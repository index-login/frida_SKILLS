/**
 * thread_monitor.js - 线程创建/销毁监控模块
 * 用途：监控应用创建了哪些线程，捕获 Frida 反检测和恶意线程行为。
 *       支持 clone() 真实入口提取（定位检测线程 so+offset）。
 * 覆盖层级：
 *   libc: pthread_create
 *   libc: clone / __clone → 可选 resolveRealEntry 提取真实线程入口（定位检测代码 so+offset）
 *   libc: syscall(__NR_clone)
 *   libc: pthread_exit / pthread_detach
 * 加载方式：frida -U -f com.app -l utils.js -l thread_monitor.js
 *   # 启用真实入口解析（推荐，默认开启）
 *   frida -U -f com.app -l utils.js -l thread_monitor.js
 *     -e 'var CONFIG_OVERRIDE={thread_monitor:{resolveRealEntry:true, entryOffset:96}}'
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] thread_monitor requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('thread_monitor', {
        showBacktrace: false,
        backtraceDepth: 8,
        includeSyscall: true,
        alertKeywords: ["frida", "gum", "inject", "debug", "trace", "hook", "xposed"],
        callerFilter: [],
        _compiledCallerFilter: [],
        alwaysShowCallerOffset: true,
        resolveRealEntry: true,
        entryOffset: 96,
    });

    // 线程去重
    var seenThreads = {};

    function compileCallerFilter() {
        CONFIG._compiledCallerFilter = U.compilePatterns(CONFIG.callerFilter);
    }

    function resolveCallerModule(returnAddress) {
        return U.resolveCallerMod(returnAddress);
    }

    function matchesCallerFilter(modName) {
        if (!modName || CONFIG._compiledCallerFilter.length === 0) return false;
        return U.matchesAnyPattern(modName, CONFIG._compiledCallerFilter);
    }

    /**
     * 从 clone() 的 arg 参数提取真实线程入口地址。
     * Android pthread_create → clone 调用链中，clone 收到的 fn 参数只指向
     * __pthread_start 包装函数，真正的业务函数指针在 arg 结构体的 entryOffset 处。
     */
    function extractRealEntry(arg) {
        if (!arg || arg.isNull()) return null;
        try {
            return arg.add(CONFIG.entryOffset).readPointer();
        } catch (e) {
            return null;
        }
    }

    /**
     * 格式化单帧调用栈为 so+offset 格式（如 "libmsaoaidsec.so + 0x1CEF8"）
     */
    function formatFrameWithOffset(addr) {
        return U.formatFrameWithOffset(addr);
    }

    function logBacktraceWithOffsets(ctx, maxDepth) {
        U.logBacktraceWithOffsets(ctx, maxDepth || CONFIG.backtraceDepth);
    }

    function describeThread(threadEntry, childStack, flags) {
        var desc = "";
        if (threadEntry && !threadEntry.isNull()) {
            var sym = DebugSymbol.fromAddress(threadEntry);
            var mod = Process.findModuleByAddress(threadEntry);
            var modName = mod ? mod.name : "???";
            desc = "entry=" + sym + " (" + modName + ")";
        } else {
            desc = "entry=<null>";
        }
        if (flags) desc += " flags=0x" + flags.toString(16);
        return desc;
    }

    function isAlertKeyword(desc) {
        for (var i = 0; i < CONFIG.alertKeywords.length; i++) {
            if (desc.toLowerCase().indexOf(CONFIG.alertKeywords[i]) !== -1) return true;
        }
        return false;
    }

    function logThreadCreated(label, threadEntry, flags) {
        var desc = describeThread(threadEntry, null, flags);
        var tid = Process.getCurrentThreadId();
        var key = threadEntry ? threadEntry.toString() : "";

        if (seenThreads[key]) return;
        seenThreads[key] = true;

        // 检查调用者是否来自目标 so（callerFilter 模式）
        var callerMod = resolveCallerModule(this.returnAddress);
        var isTargetCaller = callerMod && matchesCallerFilter(callerMod.name);

        if (isTargetCaller) {
            // 来自目标检测 so 的调用 → 打印完整信息
            U.alert("[DETECT] " + label + " called FROM " + callerMod.name +
                    " + 0x" + callerMod.offset.toString(16));
            U.timeLog("entry: " + desc + " | tid=" + tid);
            logBacktraceWithOffsets(this.context || null, CONFIG.backtraceDepth);
        } else if (isAlertKeyword(desc)) {
            U.alert(label + " " + desc + " | tid=" + tid);
            U.logBacktrace(this.context || null, CONFIG.backtraceDepth);
        } else {
            U.timeLog(label + " " + desc + " | tid=" + tid);
            if (CONFIG.alwaysShowCallerOffset && callerMod) {
                console.log("    caller: " + callerMod.name + " + 0x" + callerMod.offset.toString(16));
            }
        }
        if (CONFIG.showBacktrace && !isTargetCaller) {
            U.logBacktrace(this.context || null, CONFIG.backtraceDepth);
        }
    }

    // ========== libc 层 ==========
    function hookLibcThreads() {
        // pthread_create
        U.registerHook(U.safeHook("libc.so", "pthread_create", {
            onEnter: function (args) {
                this.threadPtr = args[0];
                this.attr = args[1];
                this.startRoutine = args[2];
                this.arg = args[3];
                if (this.startRoutine && !this.startRoutine.isNull()) {
                    logThreadCreated.call(this, "pthread_create", this.startRoutine, null);
                }
            }
        }));

        // clone (更底层，Android 最终调用的线程创建)
        // 同时用 resolveRealEntry 提取真实线程入口，定位检测代码 so+offset
        U.registerHook(U.safeHook("libc.so", "clone", {
            onEnter: function (args) {
                this.fn = args[0];
                this.childStack = args[1];
                this.flags = args[2].toInt32();
                this.arg = args[3];
                if (this.fn && !this.fn.isNull()) {
                    logThreadCreated.call(this, "clone", this.fn, this.flags);
                }
                // 提取真实线程入口（从 arg 结构体）
                if (CONFIG.resolveRealEntry) {
                    var realEntry = extractRealEntry(this.arg);
                    if (realEntry && !realEntry.isNull()) {
                        var realMod = Process.findModuleByAddress(realEntry);
                        if (realMod) {
                            var realOffset = realEntry.sub(realMod.base);
                            var realKey = realMod.name + "+0x" + realOffset.toString(16);
                            if (!seenThreads[realKey]) {
                                seenThreads[realKey] = true;
                                U.alert("[REAL_ENTRY] clone true entry: " + realKey +
                                        " | size=" + ((realMod.size / 1024).toFixed(0)) + "KB");
                                if (CONFIG.showBacktrace) {
                                    U.logBacktrace(this.context || null, CONFIG.backtraceDepth);
                                }
                            }
                        }
                    }
                }
            }
        }));

        // __clone
        U.registerHook(U.safeHook("libc.so", "__clone", {
            onEnter: function (args) {
                this.fn = args[0];
                this.childStack = args[1];
                this.flags = args[2].toInt32();
                if (this.fn && !this.fn.isNull()) {
                    logThreadCreated.call(this, "__clone", this.fn, this.flags);
                }
            }
        }));
    }

    // ========== syscall 层 ==========
    function hookSyscallClone() {
        // ARM64: __NR_clone = 220
        // ARM32: __NR_clone = 120
        // x86_64: __NR_clone = 56
        var CLONE_NR = Process.pointerSize === 8 ? 220 : 120;

        U.registerHook(U.safeHook(null, "syscall", {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                if (nr === CLONE_NR) {
                    var flags = args[1].toInt32();
                    var childStack = args[2];
                    var parentTid = args[3];
                    var childTid = args[4];
                    U.timeLog("syscall(clone) flags=0x" + flags.toString(16) +
                              " childSP=" + childStack + " | tid=" + Process.getCurrentThreadId());
                    if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));
    }

    // ========== 启动 ==========
    (function init() {
        compileCallerFilter();
        U.info("thread_monitor.js initializing...");

        Process.enumerateThreads().forEach(function (t) {
            seenThreads[t.id] = true;
        });
        U.info("baseline: " + Object.keys(seenThreads).length + " existing threads");
        if (CONFIG._compiledCallerFilter.length > 0) {
            U.info("callerFilter: " + CONFIG.callerFilter.join(", ") + " (backtrace on match)");
        }

        hookLibcThreads();
        if (CONFIG.includeSyscall) hookSyscallClone();
        U.info("thread_monitor.js ready (libc=" + true + " syscall=" + CONFIG.includeSyscall +
               " callerFilter=" + CONFIG._compiledCallerFilter.length + ")");
        console.log("");
    })();

})(this);
