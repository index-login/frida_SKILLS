/**
 * dlsym_tracer.js - 动态符号解析追踪（分析 Phase 3：发现检测逻辑）
 * 用途：追踪检测代码通过 dlopen/dlsym 动态获取了哪些函数的地址
 *
 * 典型场景：
 *   检测 so 的 init_array 解密字符串 → 通过 dlopen("libc.so") + dlsym("pthread_create")
 *   获得函数地址 → 创建线程持续扫描 Frida 特征。
 *   通过 dlsym_tracer 可以快速发现检测代码使用了哪些 libc 函数。
 *
 * 覆盖层级：
 *   linker64: do_dlsym (内部函数，捕获所有动态符号解析)
 *   libc: dlsym
 * 加载方式：frida -U -f com.app -l utils.js -l dlsym_tracer.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] dlsym_tracer requires utils.js"); return; }

    var CONFIG = U.mergeConfig('dlsym_tracer', {
        showDoDlsym: true,
        showDlsym: true,
        showLookupResult: true,
        filterModule: [],
        alertKeywords: ["pthread_create", "pthread_detach", "dl_iterate_phdr",
                        "ptrace", "strstr", "strcmp", "fopen", "open",
                         "mmap", "mprotect", "syscall"],
    });

    function resolveDoDlsymAddr() {
        var linker = Process.pointerSize === 8 ? "linker64" : "linker";
        var base = Module.findBaseAddress(linker);
        if (!base) { U.fail("linker not found"); return null; }

        // 策略1: 搜索导出表
        var patterns = ["do_dlsym", "__dl__Z9do_dlsym"];
        try {
            var exports = Module.enumerateExports(linker);
            for (var i = 0; i < exports.length; i++) {
                for (var j = 0; j < patterns.length; j++) {
                    if (exports[i].name.indexOf(patterns[j]) !== -1) {
                        U.ok("do_dlsym found in exports: " + exports[i].name + " @ " + exports[i].address);
                        return exports[i].address;
                    }
                }
            }
        } catch (e) { U.fail("enumerateExports failed: " + e.message); }

        // 策略2: 常见硬编码偏移（API 30-34）
        var fallbackOffsets = [0x3c5b0, 0x3c400, 0x3c700, 0x3c800, 0x3ca00];
        for (var k = 0; k < fallbackOffsets.length; k++) {
            var addr = base.add(fallbackOffsets[k]);
            try {
                var inst = Instruction.parse(addr);
                if (inst) {
                    U.info("fallback do_dlsym @ " + addr + " (offset=0x" + fallbackOffsets[k].toString(16) + ") inst=" + inst.mnemonic);
                    return addr;
                }
            } catch (e) { }
        }

        U.fail("do_dlsym NOT FOUND. Run: adb shell readelf -sW /apex/com.android.runtime/bin/" + linker + " | grep do_dlsym");
        return null;
    }

    var seenSyms = {};

    function isAlert(sym) {
        for (var i = 0; i < CONFIG.alertKeywords.length; i++) {
            if (sym.indexOf(CONFIG.alertKeywords[i]) !== -1) return true;
        }
        return false;
    }

    // ========== linker do_dlsym（最底层，捕获全部） ==========
    function hookDoDlsym() {
        var addr = resolveDoDlsymAddr();
        if (!addr) return;

        U.registerHook(Interceptor.attach(addr, {
                onEnter: function (args) {
                    try {
                        // args[0] = handle (soinfo*)
                        // args[1] = symbol name (const char*)
                        if (!args[1] || args[1].isNull()) return;
                        this.sym = args[1].readCString();
                    } catch (e) {
                        this.sym = null;
                    }
                },
                onLeave: function (retval) {
                    if (!this.sym) return;
                    if (seenSyms[this.sym]) return;
                    seenSyms[this.sym] = true;

                    var prefix = isAlert(this.sym) ? "[!]" : "   ";
                    var result = "";
                    if (CONFIG.showLookupResult && !retval.isNull()) {
                        var mod = Process.findModuleByAddress(retval);
                        result = " = " + retval + (mod ? " (" + mod.name + ")" : "");
                    }
    U.timeLog(prefix + " do_dlsym: " + this.sym + result);
}
}));
U.info("do_dlsym hooked @ " + addr);
}

// ========== libc dlsym（备选） ==========
    function hookDlsym() {
        U.registerHook(U.safeHook(null, "dlsym", {
            onEnter: function (args) {
                this.handle = args[0];
                this.sym = U.safeReadCString(args[1]);
            },
            onLeave: function (retval) {
                if (!this.sym || retval.isNull()) return;
                if (seenSyms[this.sym]) return;
                seenSyms[this.sym] = true;

                var callerMod = Process.findModuleByAddress(this.returnAddress);
                var callerName = callerMod ? callerMod.name : "?";
                U.timeLog("dlsym: " + this.sym + " = " + retval + " (caller: " + callerName + ")");
            }
        }));
    }

    (function init() {
        U.info("dlsym_tracer.js initializing...");
        if (CONFIG.showDoDlsym) hookDoDlsym();
        if (CONFIG.showDlsym) hookDlsym();
        U.info("dlsym_tracer.js ready (alerts: " + CONFIG.alertKeywords.join(", ") + ")");
        console.log("");
    })();
})(this);
