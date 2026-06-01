/**
 * shellcode_detector.js - Shellcode 分配检测（分析 Phase 5：定位闪退代码）
 * 用途：检测小尺寸的 mmap 调用（特别是 PROT_EXEC），这是动态解密 shellcode 的特征
 *
 * 典型场景：
 *   梆梆等加固方案的检测代码通过 mmap 分配 28 字节的 PROT_READ|PROT_EXEC 内存，
 *   写入 shellcode，然后跳转执行。通过过滤 mmap 的小尺寸分配 + 调用栈，
 *   可以定位到 so 中解密 shellcode 的函数偏移。
 *
 * 覆盖层级：libc: mmap / mmap64 / mprotect
 * 加载方式：frida -U -f com.app -l utils.js -l shellcode_detector.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] shellcode_detector requires utils.js"); return; }

    var CONFIG = U.mergeConfig('shellcode_detector', {
        maxSizeThreshold: 64,
        minSizeFilter: 1,
        showOnlyExec: true,
        showBacktrace: true,
        backtraceDepth: 12,
    });

    // PROT_* 位定义
    var PROT_EXEC  = 4;
    var PROT_WRITE = 2;
    var PROT_READ  = 1;

    function protToString(prot) {
        var r = (prot & PROT_READ) ? "r" : "-";
        var w = (prot & PROT_WRITE) ? "w" : "-";
        var x = (prot & PROT_EXEC) ? "x" : "-";
        return r + w + x;
    }

    function isSuspicious(length, prot) {
        if (length < CONFIG.minSizeFilter || length > CONFIG.maxSizeThreshold) return false;
        if (CONFIG.showOnlyExec && !(prot & PROT_EXEC)) return false;
        return true;
    }

    function hookMmap(name) {
        U.registerHook(U.safeHook("libc.so", name, {
            onEnter: function (args) {
                this.addr = args[0];
                this.length = args[1].toInt32();
                this.prot = args[2].toInt32();
                this.flags = args[3].toInt32();
                this.fd = args[4].toInt32();
                this.offset = args[5].toInt32();
            },
            onLeave: function (retval) {
                if (!isSuspicious(this.length, this.prot)) return;
                if (retval.isNull() || retval.toInt32() === -1) return;

                var marker = (this.prot & PROT_EXEC) ? "[SHELLCODE]" : "[suspicious]";
                var proto = protToString(this.prot);
                var from = U.safeReadCString(this.returnAddress) || "";
                U.alert(marker + " " + name + " len=" + this.length +
                       " prot=" + proto + " addr=" + retval);
                if (CONFIG.showBacktrace) {
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));
    }

    // mprotect（修改已有内存为可执行，同样是 shellcode 特征）
    function hookMprotect() {
        U.registerHook(U.safeHook("libc.so", "mprotect", {
            onEnter: function (args) {
                this.addr = args[0];
                this.len = args[1].toInt32();
                this.prot = args[2].toInt32();
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 0) return;
                if (!(this.prot & PROT_EXEC)) return;
                if (this.len > 4096) return; // 大块 mprotect 通常是正常分配

                var proto = protToString(this.prot);
                U.alert("[mprotect->exec] addr=" + this.addr + " len=" + this.len + " prot=" + proto);
                if (CONFIG.showBacktrace) {
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));
    }

    (function init() {
        U.info("shellcode_detector.js initializing...");
        hookMmap("mmap");
        hookMmap("mmap64");
        hookMprotect();
        U.info("shellcode_detector.js ready (size<=" + CONFIG.maxSizeThreshold +
               " execOnly=" + CONFIG.showOnlyExec + ")");
        console.log("");
    })();
})(this);
