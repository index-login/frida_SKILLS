/**
 * dl_monitor.js - 动态库加载监控模块
 * 用途：监控应用在运行时加载了哪些 .so / .dylib 库
 * 覆盖层级：
 *   libc: android_dlopen_ext / dlopen / dlsym / dlclose
 *   libart: LoadNativeLibrary (Android ART 内部)
 * 加载方式：frida -U -f com.app -l utils.js -l dl_monitor.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] dl_monitor requires utils.js (load it first)");
        return;
    }

    var CONFIG = {
        showDlsym: false,          // 是否监控 dlsym（量非常大）
        showSelfLoads: false,      // 是否显示应用自身的 so 加载
        showSystemLibs: false,     // 是否显示系统库加载
        showBacktrace: false,
        backtraceDepth: 8,
    };

    // CONFIG_OVERRIDE 注入
    if (typeof CONFIG_OVERRIDE !== 'undefined' && CONFIG_OVERRIDE['dl_monitor']) {
        var over = CONFIG_OVERRIDE['dl_monitor'];
        for (var k in over) { if (over.hasOwnProperty(k)) { CONFIG[k] = over[k]; } }
    }

    function isAppLibrary(path) {
        if (!path) return false;
        return path.indexOf("/data/") !== -1;
    }

    function isSystemLibrary(path) {
        if (!path) return false;
        return path.indexOf("/system/") !== -1 ||
               path.indexOf("/vendor/") !== -1 ||
               path.indexOf("/apex/") !== -1;
    }

    function shouldLog(path) {
        if (!path) return false;
        if (!CONFIG.showSelfLoads && isAppLibrary(path)) return false;
        if (!CONFIG.showSystemLibs && isSystemLibrary(path)) return false;
        return true;
    }

    function hookDlopen() {
        // android_dlopen_ext (Android 专用，比 dlopen 更早被调用)
        U.registerHook(U.safeHook(null, "android_dlopen_ext", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.flags = args[1].toInt32();
            },
            onLeave: function (retval) {
                if (this.path && shouldLog(this.path)) {
                    var mod = Process.findModuleByName(this.path.split("/").pop());
                    var base = mod ? mod.base : retval;
                    U.timeLog("dlopen [" + (retval.isNull() ? "FAIL" : "OK") + "] base=" + base + " path=" + this.path);
                    if (CONFIG.showBacktrace) U.logBacktrace(this.context, CONFIG.backtraceDepth);

                    if (retval.isNull()) {
                        U.fail("dlopen FAILED: " + this.path);
                    }
                }
            }
        }));

        // dlopen (POSIX 标准)
        U.registerHook(U.safeHook(null, "dlopen", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                this.flags = args[1].toInt32();
            },
            onLeave: function (retval) {
                if (this.path && this.path !== "libc.so" && shouldLog(this.path)) {
                    U.timeLog("dlopen [" + (retval.isNull() ? "FAIL" : "OK") + "] base=" + retval + " path=" + this.path);
                    if (retval.isNull()) {
                        U.fail("dlopen FAILED: " + this.path);
                    }
                }
            }
        }));

        // dlsym (符号查找)
        if (CONFIG.showDlsym) {
            U.registerHook(U.safeHook(null, "dlsym", {
                onEnter: function (args) {
                    this.handle = args[0];
                    this.name = U.safeReadCString(args[1]);
                },
                onLeave: function (retval) {
                    if (this.name && !retval.isNull()) {
                        var mod = this.handle.isNull() ? "<global>" : "<handle>";
                        U.timeLog("dlsym " + this.name + " = " + retval + " | " + mod);
                    }
                }
            }));
        }

        // dlclose
        U.registerHook(U.safeHook(null, "dlclose", {
            onEnter: function (args) {
                this.handle = args[0];
                U.timeLog("dlclose handle=" + this.handle);
            }
        }));
    }

    // Hook ART 的 LoadNativeLibrary（Java 层 System.loadLibrary 最终路径）
    function hookArtLoadLibrary() {
        var art = Process.findModuleByName("libart.so");
        if (!art) return;

        // 搜索 libart.so 中 LoadNativeLibrary 相关符号
        U.findSymbolInModule("libart.so", "LoadNativeLibrary");
        U.findSymbolInModule("libart.so", "JavaVMExt_LoadNativeLibrary");

        // 泛用方法：通过 java_vm_ext 相关符号查找
        var patterns = ["LoadNativeLibrary", "OpenNativeLibrary", "NativeLibrary"];
        patterns.forEach(function (p) {
            var addr = U.findSymbolInModule("libart.so", p);
            if (addr) {
                U.registerHook(Interceptor.attach(addr, {
                    onEnter: function (args) {
                        var path = U.safeReadCString(args[0]);
                        if (path) {
                            U.timeLog("libart LoadNativeLibrary: " + path);
                        }
                    }
                }));
            }
        });
    }

    // ========== 启动 ==========
    (function init() {
        U.info("dl_monitor.js initializing...");
        hookDlopen();
        hookArtLoadLibrary();

        // 打印已加载的模块作为基线
        U.info("Currently loaded modules:");
        Process.enumerateModules().forEach(function (m) {
            if (shouldLog(m.path)) {
                console.log("  " + m.base + " - " + (m.size / 1024).toFixed(0) + "KB - " + m.path);
            }
        });

        U.info("dl_monitor.js ready (dlsym=" + CONFIG.showDlsym +
               " self=" + CONFIG.showSelfLoads + " system=" + CONFIG.showSystemLibs + ")");
        console.log("");
    })();

})(this);
