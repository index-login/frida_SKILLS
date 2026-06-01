/**
 * file_monitor.js - 文件访问监控模块
 * 用途：监控应用在运行过程中打开/读取了哪些文件
 * 覆盖层级：
 *   libc: open / openat / __openat / fopen / fopen64 / open64
 *   libc: readlink / readlinkat / stat / lstat / fstat
 *   libc: syscall(__NR_openat, ...)
 * 加载方式：frida -U -f com.app -l utils.js -l file_monitor.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] file_monitor requires utils.js (load it first)");
        return;
    }

    // ========== 可配置项 ==========
    var CONFIG = U.mergeConfig('file_monitor', {
        showAllFileAccess: false,    // true = 显示所有文件访问（包括系统库）
        showBacktrace: false,        // true = 每次文件访问打印调用栈
        backtraceDepth: 10,
        filterExt: null,             // 如 [".db", ".xml", ".json", ".png"]
        filterPath: null,            // 如 ["/data/data/com.target/", "/sdcard/"]
        includeLibc: true,           // 是否 hook libc 层
        includeSyscall: true,        // 是否 hook syscall 层
        dedupCacheSize: 256,         // 去重缓存大小，防止同路径重复刷屏
    });

    // ========== Dedup (object-based, O(1) lookup) ==========
    var seenKeys = {};
    var seenQueue = [];
    var seenMax = CONFIG.dedupCacheSize;
    function isDedup(path, flags) {
        var key = path + "|" + flags + "|" + Process.getCurrentThreadId();
        if (seenKeys[key]) return true;
        seenKeys[key] = true;
        seenQueue.push(key);
        if (seenQueue.length > seenMax) {
            delete seenKeys[seenQueue.shift()];
        }
        return false;
    }

    // ========== 路径过滤器 ==========
    function shouldLog(path) {
        if (!path || path.length === 0) return false;
        if (CONFIG.showAllFileAccess) return true;

        if (CONFIG.filterPath) {
            for (var i = 0; i < CONFIG.filterPath.length; i++) {
                if (path.indexOf(CONFIG.filterPath[i]) !== -1) return true;
            }
            return false;
        }
        if (CONFIG.filterExt) {
            for (var j = 0; j < CONFIG.filterExt.length; j++) {
                if (path.endsWith(CONFIG.filterExt[j])) return true;
            }
            return false;
        }
        return U.isInteresting(path);
    }

    // ========== libc 层 hook ==========
    function hookLibcFileOps() {
        // openat (最常用)
        U.registerHook(U.safeHook("libc.so", "openat", {
            onEnter: function (args) {
                this.dirfd = args[0].toInt32();
                this.path = U.safeReadCString(args[1]);
                this.flags = args[2].toInt32();
                if (this.path && shouldLog(this.path) && !isDedup(this.path, this.flags)) {
                    U.timeLog("openat dirfd=" + this.dirfd + " flags=0x" + this.flags.toString(16) + " path=" + this.path);
                    if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));

        // open (旧版)
        U.registerHook(U.safeHook("libc.so", "open", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.flags = args[1].toInt32();
                if (this.path && shouldLog(this.path) && !isDedup(this.path, this.flags)) {
                    U.timeLog("open flags=0x" + this.flags.toString(16) + " path=" + this.path);
                    if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));

        // open64
        U.registerHook(U.safeHook("libc.so", "open64", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.flags = args[1].toInt32();
                if (this.path && shouldLog(this.path) && !isDedup(this.path, this.flags)) {
                    U.timeLog("open64 flags=0x" + this.flags.toString(16) + " path=" + this.path);
                }
            }
        }));

        // fopen (高层 C 库)
        U.registerHook(U.safeHook("libc.so", "fopen", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.mode = U.safeReadCString(args[1]);
                if (this.path && shouldLog(this.path) && !isDedup(this.path, this.mode || "")) {
                    U.timeLog("fopen mode=" + (this.mode || "?") + " path=" + this.path);
                }
            }
        }));

        // fopen64
        U.registerHook(U.safeHook("libc.so", "fopen64", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.mode = U.safeReadCString(args[1]);
                if (this.path && shouldLog(this.path) && !isDedup(this.path, this.mode || "")) {
                    U.timeLog("fopen64 mode=" + (this.mode || "?") + " path=" + this.path);
                }
            }
        }));

        // readlink (读取符号链接，常用于 /proc/self/exe)
        U.registerHook(U.safeHook("libc.so", "readlink", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                if (this.path && shouldLog(this.path) && !isDedup(this.path, "")) {
                    U.timeLog("readlink path=" + this.path);
                }
            }
        }));

        // readlinkat
        U.registerHook(U.safeHook("libc.so", "readlinkat", {
            onEnter: function (args) {
                this.dirfd = args[0].toInt32();
                this.path = U.safeReadCString(args[1]);
                if (this.path && shouldLog(this.path) && !isDedup(this.path, "")) {
                    U.timeLog("readlinkat dirfd=" + this.dirfd + " path=" + this.path);
                }
            }
        }));

        // stat / lstat (检查文件存在性，常用于反 Frida 检测)
        var statFuncs = ["stat", "lstat", "lstat64", "stat64", "__xstat", "__lxstat"];
        statFuncs.forEach(function (name) {
            U.registerHook(U.safeHook("libc.so", name, {
                onEnter: function (args) {
                    var path = U.safeReadCString(args[0]);
                    if (path && shouldLog(path) && !isDedup(path, name)) {
                        U.timeLog(name + " path=" + path + " (file existence check)");
                        if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                    }
                }
            }));
        });

        // access (检查文件可访问性)
        U.registerHook(U.safeHook("libc.so", "access", {
            onEnter: function (args) {
                var path = U.safeReadCString(args[0]);
                var mode = args[1].toInt32();
                if (path && shouldLog(path) && !isDedup(path, mode.toString())) {
                    U.timeLog("access mode=" + mode + " path=" + path);
                    if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));
    }

    // ========== syscall 层 hook ==========
    function hookSyscallLayer() {
        var SYSCALL_NUMS = {
            android: { 56: "openat", 257: "openat", 78: "readlinkat",
                       89: "readlink", 4: "stat", 195: "stat64",
                       196: "lstat", 197: "fstat", 21: "access", 33: "faccessat" },
            ios: { 5: "open", 463: "openat", 338: "openat_dprotected",
                   339: "stat", 340: "lstat", 33: "access" }
        };

        var target = (Process.platform === "darwin") ? SYSCALL_NUMS.ios : SYSCALL_NUMS.android;

        U.registerHook(U.safeHook(null, "syscall", {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                var name = target[nr];
                if (!name) return;

                this.syscallName = name;
                this.syscallNr = nr;

                if (name === "openat" || name === "openat_dprotected" || name === "open") {
                    var pathPtr = name === "open" ? args[1] : args[2];
                    var path = U.safeReadCString(pathPtr);
                    if (path && shouldLog(path) && !isDedup(path, "syscall_" + name)) {
                        U.timeLog("syscall(" + nr + "/" + name + ") path=" + path);
                        if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                    }
                } else if (name === "readlinkat" || name === "readlink") {
                    var rpathPtr = args[1];
                    var rpath = U.safeReadCString(rpathPtr);
                    if (rpath && shouldLog(rpath) && !isDedup(rpath, "syscall_" + name)) {
                        U.timeLog("syscall(" + nr + "/" + name + ") path=" + rpath);
                    }
                } else if (name.indexOf("stat") !== -1 || name === "access") {
                    var spath = U.safeReadCString(args[1]);
                    if (spath && shouldLog(spath) && !isDedup(spath, "syscall_" + name)) {
                        U.timeLog("syscall(" + nr + "/" + name + ") path=" + spath);
                        if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);
                    }
                }
            }
        }));
    }

    // ========== 启动 ==========
    (function init() {
        U.info("file_monitor.js initializing...");
        if (CONFIG.includeLibc) hookLibcFileOps();
        if (CONFIG.includeSyscall) hookSyscallLayer();
        U.info("file_monitor.js ready (libc=" + CONFIG.includeLibc + " syscall=" + CONFIG.includeSyscall + ")");
        U.info("config: showAll=" + CONFIG.showAllFileAccess +
               " filterExt=" + JSON.stringify(CONFIG.filterExt) +
               " filterPath=" + JSON.stringify(CONFIG.filterPath));
        console.log("");
    })();

})(this);
