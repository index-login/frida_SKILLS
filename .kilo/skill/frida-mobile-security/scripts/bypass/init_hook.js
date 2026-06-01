/**
 * init_hook.js - init_array 执行时机 Hook（分析 Phase 2：抢 init_array 之前）
 * 用途：在 linker64 的 call_constructors 处获取控制权，早于 so 的 init_proc/init_array
 * 加载方式：frida -U -f com.app -l utils.js -l init_hook.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] init_hook requires utils.js"); return; }

    function hasSvc0(addr) {
        try {
            var bytes = addr.readByteArray(128);
            var arr = new Uint8Array(bytes);
            for (var b = 0; b < arr.length - 3; b++) {
                if (arr[b]===0x01 && arr[b+1]===0x00 && arr[b+2]===0x00 && arr[b+3]===0xD4) {
                    return true;
                }
            }
        } catch(e) {}
        return false;
    }

    function patchInitArray(mod) {
        var ptrSize = Process.pointerSize;
        var e_phoff = mod.base.add(ptrSize===8?32:28).readU32();
        var e_phentsize = mod.base.add(ptrSize===8?54:42).readU16();
        var e_phnum = mod.base.add(ptrSize===8?56:44).readU16();
        U.info("Patching " + mod.name + " phoff=0x"+e_phoff.toString(16)+" phentsize="+e_phentsize+" phnum="+e_phnum);
        for (var i = 0; i < e_phnum; i++) {
            var phdr = mod.base.add(e_phoff + i * e_phentsize);
            var p_type = phdr.readU32();
            if (p_type === 2) {
                var p_vaddr = phdr.add(ptrSize===8?16:8).readPointer();
                U.info("PT_DYNAMIC vaddr=" + p_vaddr);
                var dyn = mod.base.add(p_vaddr);
                var initAddr = null, initArrayAddr = null, initArraySz = 0;
                for (var j = 0; ; j++) {
                    var d_tag = dyn.add(j * ptrSize * 2).readPointer().toInt32();
                    if (d_tag === 0) break;
                    var d_val = dyn.add(j * ptrSize * 2 + ptrSize).readPointer();
                    if (d_tag === 12) { initAddr = mod.base.add(d_val.toInt32()); U.info("DT_INIT=" + initAddr); }
                    if (d_tag === 25) { initArrayAddr = mod.base.add(d_val.toInt32()); U.info("DT_INIT_ARRAY=" + initArrayAddr); }
                    if (d_tag === 27) { initArraySz = d_val.toInt32(); U.info("DT_INIT_ARRAYSZ=" + initArraySz); }
                }
                if (initAddr && !initAddr.isNull() && initAddr.toInt32() > mod.base.toInt32()) {
                    try {
                        if (hasSvc0(initAddr)) {
                            U.alert("DT_INIT has SVC #0, patching: " + initAddr);
                            Memory.patchCode(initAddr, 4, function(code) {
                                var w = Process.arch==="arm64"?new Arm64Writer(code,{pc:initAddr}):new ThumbWriter(code,{pc:initAddr});
                                w.putRet(); w.flush();
                            });
                            U.ok("DT_INIT -> RET @ " + initAddr);
                        } else {
                            U.info("DT_INIT skip (no SVC #0): " + initAddr);
                        }
                    } catch(e) { U.fail("DT_INIT patch: "+e.message); }
                }
                if (initArrayAddr && !initArrayAddr.isNull() && initArraySz > 0) {
                    var count = initArraySz / ptrSize;
                    U.alert("DT_INIT_ARRAY count=" + count);
                    for (var k = 0; k < count; k++) {
                        var funcPtr = initArrayAddr.add(k * ptrSize).readPointer();
                        if (!funcPtr.isNull()) {
                            try {
                                if (hasSvc0(funcPtr)) {
                                    Memory.patchCode(funcPtr, 4, function(code) {
                                        var w = Process.arch==="arm64"?new Arm64Writer(code,{pc:funcPtr}):new ThumbWriter(code,{pc:funcPtr});
                                        w.putRet(); w.flush();
                                    });
                                    U.info("  ["+k+"] SVC#0 -> RET");
                                } else {
                                    U.info("  ["+k+"] skip (no SVC #0)");
                                }
                            } catch(e) { U.fail("  ["+k+"] patch fail: "+e.message); }
                        }
                    }
                }
                break;
            }
        }
    }

    var CONFIG = U.mergeConfig('init_hook', {
        onModuleInit: [
            {moduleName: "libexecmain.so", callback: patchInitArray},
            {moduleName: "libexec.so", callback: patchInitArray},
        ],
        sleepBeforeInit: 0,
        logAllConstructors: false,
        probeCallers: true,
        autoHideFrida: true,
        probeBacktraceDepth: 12,
    });

    var initCallbacks = [];

    /**
     * 在 linker64 导出表中搜索 call_constructors 符号
     * 返回函数地址，找不到返回 null
     */
    function findCallConstructors() {
        var linker = Process.pointerSize === 8 ? "linker64" : "linker";
        var base = Module.findBaseAddress(linker);
        if (!base) {
            U.fail("[" + linker + "] not loaded");
            return null;
        }

        // 策略 1：搜索导出表
        var patterns = [
            "call_constructors",        // AOSP standard
            "__dl__Z16call_constructors", // some builds
            "call_constructors_recursive",
        ];
        try {
            var exports = Module.enumerateExports(linker);
            for (var i = 0; i < exports.length; i++) {
                for (var j = 0; j < patterns.length; j++) {
                    if (exports[i].name.indexOf(patterns[j]) !== -1) {
                        U.ok("call_constructors found in exports: " + exports[i].name + " @ " + exports[i].address);
                        return exports[i].address;
                    }
                }
            }
        } catch (e) {
            U.fail("enumerateExports failed: " + e.message);
        }

        // 策略 2：常见硬编码偏移（API 30-34），逐个尝试验证
        var fallbackOffsets = [0x50cf8, 0x50d00, 0x50c00, 0x4d0e0, 0x4f0e0, 0x52110];
        for (var k = 0; k < fallbackOffsets.length; k++) {
            var addr = base.add(fallbackOffsets[k]);
            try {
                var inst = Instruction.parse(addr);
                if (inst) {
                    U.info("fallback call_constructors candidate @ " + addr +
                           " (offset=0x" + fallbackOffsets[k].toString(16) + ") inst=" + inst.mnemonic);
                    return addr;
                }
            } catch (e) { }
        }

        U.fail("call_constructors NOT FOUND. Run on device:");
        U.fail("  adb shell readelf -sW /apex/com.android.runtime/bin/" + linker + " | grep call_constructors");
        U.fail("  Then update LINKER_OFFSETS in init_hook.js");
        return null;
    }

    // ========== 导出 API ==========
    var probedPthread = false;

    function resolveCallerMod(returnAddr) {
        return U.resolveCallerMod(returnAddr);
    }

    function formatFrameWithOff(addr) {
        return U.formatFrameWithOffset(addr);
    }

    function probeBacktrace(ctx, targetModName, depth) {
        U.logBacktraceWithOffsets(ctx, depth || CONFIG.probeBacktraceDepth);
        U.info("=== These offsets can be fed to function_patcher for bypass ===");
    }

    /**
     * 当目标 so 在 call_constructors 被检测到时自动触发：
     * 1. 隐藏 Frida 特征（如果 autoHideFrida 开启且 FridaFeatureHider 已加载）
     * 2. hook pthread_create 以捕获来自目标 so 的检测线程调用
     */
    function onTargetModuleFound(mod, moduleName) {
        // ① 自动隐藏 Frida 特征
        if (CONFIG.autoHideFrida && global.FridaFeatureHider && global.FridaFeatureHider.activate) {
            try {
                global.FridaFeatureHider.activate();
                U.alert("autoHideFrida: FridaFeatureHider activated for " + moduleName);
            } catch (e) {
                U.fail("autoHideFrida failed: " + e.message);
            }
        }

        // ② 自动 hook pthread_create 捕获检测线程
        if (CONFIG.probeCallers && !probedPthread) {
            probedPthread = true;
            var pthreadCreate = Module.findExportByName("libc.so", "pthread_create");
            if (!pthreadCreate) {
                U.fail("pthread_create not found for probeCallers");
                return;
            }
            Interceptor.attach(pthreadCreate, {
                onEnter: function (args) {
                    var modInfo = resolveCallerMod(this.returnAddress);
                    if (!modInfo) return;
                    if (modInfo.name !== moduleName) return;

                    U.alert("[INIT_HOOK] pthread_create called FROM " + modInfo.name +
                            " + 0x" + modInfo.offset.toString(16));
                    // 解析入口函数
                    var entryMod = Process.findModuleByAddress(args[2]);
                    var entryName = entryMod ? (entryMod.name + " + 0x" + args[2].sub(entryMod.base).toString(16)) : args[2].toString();
                    U.info("  thread entry: " + entryName);

                    probeBacktrace(this.context, modInfo.name, CONFIG.probeBacktraceDepth);
                }
            });
            U.ok("probeCallers: pthread_create hooked, filtering for " + moduleName);
        }
    }

    global.FridaInit = {
        /**
         * 注册回调：当目标模块在 call_constructors 被触发时执行
         * @param {string} moduleName - 目标 so 文件名
         * @param {Function} callback - 回调函数，参数 (moduleInfo)
         */
        onModuleInit: function (moduleName, callback) {
            initCallbacks.push({
                moduleName: moduleName,
                callback: callback,
                _triggered: false,
            });
            U.info("registered init hook for: " + moduleName);
        },

        /**
         * 手动检查目标模块是否已加载并触发回调（用于非 call_constructors 路径）
         */
        checkNow: function () {
            for (var i = 0; i < initCallbacks.length; i++) {
                var cb = initCallbacks[i];
                var mod = Process.findModuleByName(cb.moduleName);
                if (mod && !cb._triggered) {
                    cb._triggered = true;
                    U.alert("manual check: " + cb.moduleName + " found");
                    if (typeof cb.callback === 'function') {
                        try { cb.callback(mod); } catch (e) {
                            U.fail("callback failed: " + e.message);
                        }
                    }
                }
            }
        }
    };

    // ========== 调试辅助 ==========
    function sleepBeforeTarget(targetName) {
        var sleep = new NativeFunction(Module.findExportByName("libc.so", "sleep"), 'int', ['int']);
        var dlopenAddr = Module.findExportByName(null, "android_dlopen_ext");
        if (dlopenAddr) {
            Interceptor.attach(dlopenAddr, {
                onEnter: function (args) {
                    var path = U.safeReadCString(args[0]);
                    if (path && path.indexOf(targetName) !== -1) {
                        var sec = CONFIG.sleepBeforeInit || 10;
                        U.alert("sleep " + sec + "s before " + targetName);
                        sleep(sec);
                    }
                }
            });
            U.info("sleep-before-dlopen registered for: " + targetName);
        }
    }

    // ========== 启动 ==========
    (function init() {
        U.info("init_hook.js initializing...");

        var addr = findCallConstructors();
        if (!addr) {
            U.fail("init_hook.js DISABLED: call_constructors address not resolved");
            U.fail("  Phase 0: verify linker offset first (see SKILL.md Phase 0)");
            console.log("");
            return;
        }

        Interceptor.attach(addr, {
            onEnter: function (args) {
                if (CONFIG.logAllConstructors) {
                    U.timeLog("call_constructors called");
                }
                for (var i = 0; i < initCallbacks.length; i++) {
                    var cb = initCallbacks[i];
                    var mod = Process.findModuleByName(cb.moduleName);
                    if (mod && !cb._triggered) {
                        cb._triggered = true;
                        U.alert("call_constructors: " + cb.moduleName + " found @ " + mod.base + " size=" + (mod.size / 1024).toFixed(0) + "KB");
                        // 自动激活 feature hider + probe callers
                        onTargetModuleFound(mod, cb.moduleName);
                        // 执行用户回调
                        if (typeof cb.callback === 'function') {
                            try { cb.callback(mod); } catch (e) {
                                U.fail("callback failed: " + e.message);
                            }
                        }
                    }
                }
            }
        });

        // 注册用户配置的回调
        CONFIG.onModuleInit.forEach(function (entry) {
            global.FridaInit.onModuleInit(entry.moduleName, entry.callback || entry.handler);
        });

        if (CONFIG.sleepBeforeInit > 0 && CONFIG.onModuleInit.length > 0) {
            sleepBeforeTarget(CONFIG.onModuleInit[0].moduleName);
        }

        U.info("init_hook.js ready (callbacks=" + initCallbacks.length +
               " probeCallers=" + CONFIG.probeCallers +
               " autoHideFrida=" + CONFIG.autoHideFrida +
               " sleep=" + CONFIG.sleepBeforeInit + ")");
        console.log("");
    })();
})(this);
