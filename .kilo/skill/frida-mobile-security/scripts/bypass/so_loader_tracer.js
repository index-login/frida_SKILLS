/**
 * so_loader_tracer.js - SO 加载追踪（分析 Phase 1：定位检测 so）
 * 用途：追踪所有 Native 库的加载过程，用于定位哪个 so 加载后导致闪退
 * 覆盖层级：
 *   linker64: do_dlopen (内部函数，比 android_dlopen_ext 更底层)
 *   libc: android_dlopen_ext
 * 加载方式：frida -U -f com.app -l utils.js -l so_loader_tracer.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] so_loader_tracer requires utils.js"); return; }

    var CONFIG = U.mergeConfig('so_loader_tracer', {
        showDoDlopen: true,
        showAndroidDlopen: true,
        trackSize: true,
        filterPath: [],
        warnOnStripped: false,
    });

    function resolveDoDlopenAddr() {
        var linker = Process.pointerSize === 8 ? "linker64" : "linker";
        var base = Module.findBaseAddress(linker);
        if (!base) { U.fail("linker not found"); return null; }

        // 策略1: 搜索导出表
        var patterns = ["do_dlopen", "__dl__Z10do_dlopen"];
        try {
            var exports = Module.enumerateExports(linker);
            for (var i = 0; i < exports.length; i++) {
                for (var j = 0; j < patterns.length; j++) {
                    if (exports[i].name.indexOf(patterns[j]) !== -1) {
                        U.ok("do_dlopen found in exports: " + exports[i].name + " @ " + exports[i].address);
                        return exports[i].address;
                    }
                }
            }
        } catch (e) { U.fail("enumerateExports failed: " + e.message); }

        // 策略2: 常见硬编码偏移（API 30-34），逐个尝试验证
        var fallbackOffsets = [0x3ba00, 0x3b800, 0x3bc00, 0x3c000, 0x3c200];
        for (var k = 0; k < fallbackOffsets.length; k++) {
            var addr = base.add(fallbackOffsets[k]);
            try {
                var inst = Instruction.parse(addr);
                if (inst) {
                    U.info("fallback do_dlopen @ " + addr + " (offset=0x" + fallbackOffsets[k].toString(16) + ") inst=" + inst.mnemonic);
                    return addr;
                }
            } catch (e) { }
        }

        U.fail("do_dlopen NOT FOUND. Run: adb shell readelf -sW /apex/com.android.runtime/bin/" + linker + " | grep do_dlopen");
        return null;
    }

    // ========== linker do_dlopen（最底层） ==========
    function hookDoDlopen() {
        var addr = resolveDoDlopenAddr();
        if (!addr) return;

        U.registerHook(Interceptor.attach(addr, {
                onEnter: function (args) {
                    try { this.path = args[0].readCString(); } catch (e) { this.path = null; }
                    this.flags = args[1].toInt32();
                    if (this.path) {
                        U.timeLog("do_dlopen START: " + this.path + " flags=0x" + this.flags.toString(16));
                    }
                },
                onLeave: function (retval) {
                    if (!this.path) return;
                    if (retval.isNull()) {
                        U.fail("do_dlopen FAILED: " + this.path);
                        return;
                    }
                    var mod = Process.findModuleByName(this.path.split("/").pop());
                    var size = mod ? (mod.size / 1024).toFixed(1) + "KB" : "?";
                    var hasExports = false;
                    if (mod) {
                        try {
                            var exps = Module.enumerateExports(mod.name);
                            hasExports = exps.length > 0;
                        } catch (e) { }
                    }
                    var marker = "";
                    if (!hasExports && mod && mod.size > 1024) {
                        marker = " [STRIPPED]"; // 去符号 = 可能加固
                    }
        U.ok("do_dlopen OK: " + this.path + " base=" + retval + " " + size + marker);
    }
}));
U.info("do_dlopen hooked @ " + addr);
}

// ========== android_dlopen_ext（备选） ==========
    function hookAndroidDlopen() {
        U.registerHook(U.safeHook(null, "android_dlopen_ext", {
            onEnter: function (args) {
                this.path = U.safeReadCString(args[0]);
                if (this.path) {
                    U.timeLog("android_dlopen_ext: " + this.path);
                }
            },
            onLeave: function (retval) {
                if (this.path && retval.isNull()) {
                    U.fail("android_dlopen_ext FAILED: " + this.path);
                }
            }
        }));
    }

    // ========== 启动时列出已加载模块 ==========
    function listLoadedModules() {
        U.info("Already loaded modules:");
        var count = 0;
        Process.enumerateModules().forEach(function (m) {
            var path = m.path;
            if (CONFIG.filterPath.length > 0) {
                var match = false;
                for (var i = 0; i < CONFIG.filterPath.length; i++) {
                    if (path.indexOf(CONFIG.filterPath[i]) !== -1) { match = true; break; }
                }
                if (!match) return;
            }
            console.log("  " + m.base + " " + (m.size / 1024).toFixed(0) + "KB " + path);
            count++;
        });
        U.info("total: " + count + " modules");
    }

    (function init() {
        U.info("so_loader_tracer.js initializing...");
        listLoadedModules();
        if (CONFIG.showDoDlopen) hookDoDlopen();
        if (CONFIG.showAndroidDlopen) hookAndroidDlopen();
        U.info("so_loader_tracer.js ready (do_dlopen=" + CONFIG.showDoDlopen +
               " android_dlopen=" + CONFIG.showAndroidDlopen + ")");
        console.log("");
    })();
})(this);
