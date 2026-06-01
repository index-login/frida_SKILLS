/**
 * thread_blocker.js - 检测线程阻断模块（分析 Phase 2：主动阻断线程级检测）
 *
 * 用途：通过 Interceptor.replace 选择性阻断来自指定 so 的检测线程创建，
 *       同时透传其他正常线程调用到原始函数。
 *       支持两种策略：pthread_replace（默认）和 clone_prot_none（底层暗杀）。
 *
 * 对应文章模式：爱加密（文章③）— Interceptor.replace(pthread_create) 阻挡检测线程 +
 *                  自建 dlopen 延迟加载轮询
 *              银行app 反检测 — clone() hook + PROT_NONE 暗杀检测线程入口
 *
 * 与 init_hook 互补：
 *   - init_hook  → 处理"init_array 级 SVC #0 检测"（分支 B）
 *   - thread_blocker → 处理"运行时 pthread_create/clone 检测线程"（分支 A）
 *
 * 覆盖层级：libc (pthread_create, clone)
 *
 * 加载方式：
 *   # 默认策略：阻断 pthread_create
 *   frida -U -f com.app -l utils.js -l thread_blocker.js
 *     -e 'var CONFIG_OVERRIDE={thread_blocker:{blockCallers:["libmsaoaidsec.so"]}}'
 *
 *   # clone 暗杀策略：hook clone() + PROT_NONE 废掉线程入口（当 pthread_create 被绕过时）
 *   frida -U -f com.app -l utils.js -l thread_blocker.js
 *     -e 'var CONFIG_OVERRIDE={thread_blocker:{strategy:"clone_prot_none", blockCallers:["libDetect.so"]}}'
 *
 *   # 阻断 + 轮询等待主 so 加载
 *   frida -U -f com.app -l utils.js -l thread_blocker.js
 *     -e 'var CONFIG_OVERRIDE={thread_blocker:{blockCallers:["libexec.so"],
 *       waitForModule:[{name:"libexecmain.so",intervalMs:100,timeoutMs:30000}]}}'
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] thread_blocker requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('thread_blocker', {
        strategy: "pthread_replace",
        entryOffset: 96,
        blockCallers: [],
        waitForModule: [],
        indirectHook: false,
        verbose: true,
        _originalPthreadCreate: null,
    });

    var active = false;
    var blockedCounts = {};
    var passedCount = 0;
    var pollTimers = {};
    var compiledBlockCallers = [];

    function compileBlockCallers() {
        compiledBlockCallers = U.compilePatterns(CONFIG.blockCallers);
    }

    function matchesBlockList(modName) {
        if (!modName || compiledBlockCallers.length === 0) return false;
        return U.matchesAnyPattern(modName, compiledBlockCallers);
    }

    function resolveCallerMod(returnAddr) {
        return U.resolveCallerMod(returnAddr);
    }

    // ========== pthread_create 拦截 ==========

    function hookPthreadCreate() {
        var pthreadCreateAddr = Module.findExportByName("libc.so", "pthread_create");
        if (!pthreadCreateAddr) {
            U.fail("pthread_create not found in libc.so");
            return;
        }

        CONFIG._originalPthreadCreate = new NativeFunction(pthreadCreateAddr, 'int',
            ['pointer', 'pointer', 'pointer', 'pointer']);

        Interceptor.replace(pthreadCreateAddr, new NativeCallback(
            function (threadPtr, attr, startRoutine, arg) {
                var callerMod = resolveCallerMod(this.returnAddress);

                if (callerMod && matchesBlockList(callerMod.name)) {
                    blockedCounts[callerMod.name] = (blockedCounts[callerMod.name] || 0) + 1;
                    var cnt = blockedCounts[callerMod.name];

                    if (CONFIG.verbose) {
                        U.alert("[THREAD_BLOCKER] BLOCKED pthread_create from " +
                                callerMod.name + " + 0x" + callerMod.offset.toString(16) +
                                " (count=" + cnt + ")");

                        var entryMod = null;
                        try {
                            if (startRoutine && !startRoutine.isNull()) {
                                entryMod = Process.findModuleByAddress(startRoutine);
                            }
                        } catch (e) {}
                        var entryDesc = entryMod
                            ? (entryMod.name + " + 0x" + startRoutine.sub(entryMod.base).toString(16))
                            : (startRoutine ? startRoutine.toString() : "<null>");
                        U.info("  thread entry: " + entryDesc);

                        U.logBacktrace(this.context, 8);
                    }

                    return 0;
                }

                passedCount++;
                return CONFIG._originalPthreadCreate(threadPtr, attr, startRoutine, arg);
            },
            'int', ['pointer', 'pointer', 'pointer', 'pointer']
        ));

        U.ok("pthread_create REPLACED (blocking: " + CONFIG.blockCallers.join(", ") + ")");
    }

    // ========== clone_strategy — PROT_NONE 暗杀 ==========

    /**
     * Hook clone()，从 arg 结构体中提取真实线程入口地址，
     * 对匹配的检测 so 入口设 PROT_NONE 使其崩溃。
     *
     * 注意：若目标 so 同时承担解密和检测职责（如壳的解密 so），
     * 全量暗杀会导致 app 异常。应先用 thread_monitor(resolveRealEntry:true)
     * 摸清所有 clone 真实入口，确认 SO 仅用于检测后再启用此策略。
     * 若 SO 是双重用途，改用 function_patcher 精确 NOP 单一检测函数。
     */
    function hookCloneProtNone() {
        var cloneAddr = Module.findExportByName("libc.so", "clone");
        if (!cloneAddr) {
            U.fail("clone not found in libc.so");
            return;
        }

        var seenEntries = {};

        Interceptor.attach(cloneAddr, {
            onEnter: function (args) {
                var arg = args[3];
                if (!arg || arg.isNull()) return;

                var realEntry;
                try {
                    realEntry = arg.add(CONFIG.entryOffset).readPointer();
                } catch (e) { return; }
                if (!realEntry || realEntry.isNull()) return;

                var mod = Process.findModuleByAddress(realEntry);
                if (!mod || !matchesBlockList(mod.name)) return;

                var offset = realEntry.sub(mod.base);
                var key = mod.name + "+0x" + offset.toString(16);

                if (seenEntries[key]) return;
                seenEntries[key] = true;
                blockedCounts[mod.name] = (blockedCounts[mod.name] || 0) + 1;

                if (CONFIG.verbose) {
                    U.alert("[THREAD_BLOCKER:CLONE] PROT_NONE on " + key +
                            " (" + ((mod.size / 1024).toFixed(0)) + "KB)" +
                            " count=" + blockedCounts[mod.name]);
                    U.logBacktrace(this.context, 8);
                }

                // 对齐到页边界设 PROT_NONE
                try {
                    var pageSize = 4096;
                    var aligned = realEntry.and(new NativePointer(pageSize - 1).not());
                    var size = (realEntry.sub(aligned).toInt32() + 4 > pageSize) ? pageSize * 2 : pageSize;
                    Memory.protect(aligned, size, '---');
                    U.ok("[THREAD_BLOCKER:CLONE] PROT_NONE applied to " + key);
                } catch (e) {
                    U.fail("[THREAD_BLOCKER:CLONE] prot_none failed: " + e.message);
                }

                console.log("");
            }
        });

        U.ok("clone() hooked with PROT_NONE (blocking: " + CONFIG.blockCallers.join(", ") + ")");
    }

    // ========== dlopen 轮询等待 ==========

    function startPolling() {
        if (CONFIG.waitForModule.length === 0) return;

        var dlopenAddr = Module.findExportByName(null, "dlopen");
        if (!dlopenAddr) {
            U.fail("dlopen not found — cannot poll for modules");
            return;
        }

        var RTLD_NOLOAD = 0x4;
        var dlopen = new NativeFunction(dlopenAddr, 'pointer', ['pointer', 'int']);

        CONFIG.waitForModule.forEach(function (entry) {
            var modName = entry.name;
            var intervalMs = entry.intervalMs || 500;
            var timeoutMs = entry.timeoutMs || 30000;
            var onLoaded = entry.onLoaded || null;

            U.info("polling for " + modName + " (interval=" + intervalMs +
                   "ms timeout=" + timeoutMs + "ms)");

            var startTime = Date.now();

            pollTimers[modName] = setInterval(function () {
                try {
                    var pathBuf = Memory.allocUtf8String(modName);
                    var handle = dlopen(pathBuf, RTLD_NOLOAD);

                    if (!handle.isNull()) {
                        clearInterval(pollTimers[modName]);
                        delete pollTimers[modName];

                        var mod = Process.findModuleByName(modName);
                        if (mod) {
                            U.alert("[THREAD_BLOCKER] " + modName + " loaded @ " + mod.base +
                                    " " + ((mod.size / 1024).toFixed(0)) + "KB" +
                                    " (after " + (Date.now() - startTime) + "ms)");
                        } else {
                            U.ok("[THREAD_BLOCKER] " + modName + " loaded (handle=" + handle + ")");
                        }

                        if (typeof onLoaded === 'function') {
                            try {
                                onLoaded(mod || { name: modName, base: handle, size: 0 });
                            } catch (e) {
                                U.fail("onLoaded callback failed: " + e.message);
                            }
                        }

                        if (global.FridaInit && global.FridaInit.checkNow) {
                            global.FridaInit.checkNow();
                        }
                    }
                } catch (e) {
                    U.fail("poll for " + modName + " failed: " + e.message);
                }

                if (Date.now() - startTime > timeoutMs) {
                    if (pollTimers[modName]) {
                        clearInterval(pollTimers[modName]);
                        delete pollTimers[modName];
                        U.fail("waitForModule TIMEOUT: " + modName +
                               " (" + timeoutMs + "ms)");
                    }
                }
            }, intervalMs);
        });
    }

    // ========== 导出 API ==========

    global.ThreadBlocker = {
        /**
         * 激活（配合 init_hook 使用，在 call_constructors 回调中调用）
         */
        activate: function () {
            if (active) return;
            active = true;
            U.alert("[THREAD_BLOCKER] activate() called, strategy=" + CONFIG.strategy);
            compileBlockCallers();
            if (CONFIG.strategy === "clone_prot_none") {
                hookCloneProtNone();
            } else {
                hookPthreadCreate();
            }
            startPolling();
            U.ok("[THREAD_BLOCKER] activated");
        },

        /**
         * 查询阻断统计
         */
        getStats: function () {
            return {
                active: active,
                blocked: blockedCounts,
                passed: passedCount,
                waitingModules: Object.keys(pollTimers),
            };
        },

        /**
         * 重置统计
         */
        resetStats: function () {
            blockedCounts = {};
            passedCount = 0;
        },
    };

    // ========== 启动 ==========

    (function init() {
        U.info("thread_blocker.js initializing...");

        if (CONFIG.blockCallers.length === 0 && CONFIG.waitForModule.length === 0) {
            U.info("thread_blocker.js loaded (no blockCallers or waitForModule configured — idle)");
            console.log("");
            return;
        }

        compileBlockCallers();

        U.info("strategy=" + CONFIG.strategy);
        if (CONFIG.blockCallers.length > 0) {
            U.info("blockCallers: " + CONFIG.blockCallers.join(", "));
        }
        if (CONFIG.waitForModule.length > 0) {
            U.info("waitForModule: " + CONFIG.waitForModule.map(function (e) {
                return e.name;
            }).join(", "));
        }
        U.info("indirectHook=" + CONFIG.indirectHook);

        if (CONFIG.indirectHook) {
            U.info("thread_blocker.js ready (INDIRECT mode — waiting for activate())");
        } else {
            active = true;
            if (CONFIG.strategy === "clone_prot_none") {
                hookCloneProtNone();
            } else {
                hookPthreadCreate();
            }
            startPolling();
            U.info("thread_blocker.js ready (active, strategy=" + CONFIG.strategy + ")");
        }
        console.log("");
    })();

})(this);
