/**
 * function_patcher.js - Native 函数修补（分析 Phase 6：精确绕过）
 * 用途：在定位到闪退函数偏移后，通过 Memory.patchCode 将函数第一条指令替换为 RET
 *       支持 ARM64 / ARM / Thumb 三种架构
 * 加载方式：frida -U -f com.app -l utils.js -l init_hook.js -l function_patcher.js
 *
 * 典型用法：
 *   var FP = global.FunctionPatcher;
 *   config = [
 *     {module: "libtarget.so", offset: 0x234E0},  // 闪退函数 1
 *     {module: "libtarget.so", offset: 0x26334},  // 闪退函数 2
 *   ];
 *   FP.patchBatch(config);
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] function_patcher requires utils.js"); return; }

    var FunctionPatcher = {};
    var patched = {};
    var pendingPatches = [];  // 目标模块尚未加载时暂存

    // ========== Writer 工厂 ==========
    function getWriter(code, addr) {
        if (Process.arch === "arm64") {
            return new Arm64Writer(code, { pc: addr });
        } else if (Process.arch === "arm") {
            return new ThumbWriter(code, { pc: addr });
        } else {
            return new ArmWriter(code, { pc: addr });
        }
    }

    function writeRet(writer) {
        if (Process.arch === "arm64") {
            writer.putRet();
        } else {
            writer.putBxLr();
        }
    }

    function writeMovRet0(writer, reg, value) {
        if (Process.arch === "arm64") {
            writer.putMovRegU64(reg, value);
            writer.putRet();
        } else {
            writer.putMovRegU32(reg, value);
            writer.putBxLr();
        }
    }

    // ========== 核心操作 ==========

    /**
     * NOP 函数入口（替换为 RET）
     */
    FunctionPatcher.nop = function (addr) {
        var key = addr.toString();
        if (patched[key]) return false;

        try {
            Memory.patchCode(addr, 4, function (code) {
                var w = getWriter(code, addr);
                writeRet(w);
                w.flush();
            });
            patched[key] = true;
            U.ok("nop: " + addr + " -> RET");
            return true;
        } catch (e) {
            U.fail("nop failed: " + addr + " - " + e.message);
            return false;
        }
    };

    /**
     * 替换函数返回值为指定数字
     * @returns {boolean}
     */
    FunctionPatcher.returnValue = function (addr, value) {
        var key = addr.toString();
        if (patched[key]) return false;

        try {
            Memory.patchCode(addr, 16, function (code) {
                var w = getWriter(code, addr);
                writeMovRet0(w, Process.arch === "arm64" ? "x0" : "r0", value || 0);
                w.flush();
            });
            patched[key] = true;
            U.ok("returnValue: " + addr + " -> return " + (value || 0));
            return true;
        } catch (e) {
            U.fail("returnValue failed: " + addr + " - " + e.message);
            return false;
        }
    };

    /**
     * NOP + NOP + RET（对多条指令的入口有效）
     */
    FunctionPatcher.nopSled = function (addr, instructionCount) {
        instructionCount = instructionCount || 1;
        var key = addr.toString();
        if (patched[key]) return false;

        try {
            Memory.patchCode(addr, instructionCount * 4 + 4, function (code) {
                var w = getWriter(code, addr);
                for (var i = 0; i < instructionCount; i++) {
                    w.putNop();
                }
                writeRet(w);
                w.flush();
            });
            patched[key] = true;
            U.ok("nopSled: " + addr + " (" + instructionCount + " NOPs + RET)");
            return true;
        } catch (e) {
            U.fail("nopSled failed: " + addr + " - " + e.message);
            return false;
        }
    };

    // ========== 批量操作 ==========

    /**
     * 通过模块名 + 偏移修补
     */
    FunctionPatcher.patchOffset = function (moduleName, offset) {
        var mod = Process.findModuleByName(moduleName);
        if (!mod) {
            U.fail("patchOffset: module not loaded: " + moduleName);
            pendingPatches.push({ moduleName: moduleName, offset: offset });
            return false;
        }
        return FunctionPatcher.nop(mod.base.add(offset));
    };

    /**
     * 批量修补
     * configs: [{module: "libtarget.so", offset: 0x234E0}, ...]
     */
    FunctionPatcher.patchBatch = function (configs) {
        configs.forEach(function (cfg) {
            FunctionPatcher.patchOffset(cfg.module, cfg.offset);
        });
    };

    /**
     * 处理待修补列表（配合 init_hook 在模块加载后调用）
     */
    FunctionPatcher.processPending = function () {
        if (pendingPatches.length === 0) return;
        U.info("processing " + pendingPatches.length + " pending patches...");
        var remaining = [];
        pendingPatches.forEach(function (p) {
            if (!FunctionPatcher.patchOffset(p.moduleName, p.offset)) {
                remaining.push(p);
            }
        });
        pendingPatches = remaining;
    };

    /**
     * 重置状态
     */
    FunctionPatcher.reset = function () {
        patched = {};
        pendingPatches = [];
    };

    // 导出
    global.FunctionPatcher = FunctionPatcher;

    (function init() {
        U.info("function_patcher.js loaded (" + Process.arch + ")");
    })();
})(this);
