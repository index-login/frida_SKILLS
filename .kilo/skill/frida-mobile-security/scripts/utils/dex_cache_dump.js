/**
 * dex_cache_dump.js - DEX 精确 Dump（DexCache 主动枚举）
 * 用途：从 ART 的 java.lang.DexCache 对象反向定位 DEX，不依赖 DEX magic，天然免疫假 DEX / 抹 magic 壳
 * 互补：frida-dexdump 全内存扫 magic 会被假 DEX 干扰、对抹 magic 的壳需 -d 兜底；本模块直接问 ART 拿真 DEX
 * 代价：Java.choose 堆扫描大型 App 需 10-30s，部分壳会检测 Java.choose 调用栈
 * 被动拦截变体：见 dex_defineclass_dump.js（hook ClassLinker::DefineClass）
 * 加载：frida -U -f com.app -l scripts/core/utils.js -l scripts/utils/dex_cache_dump.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] dex_cache_dump requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('dex_cache_dump', {
        // 输出目录（设备上）
        outputDir: "/data/local/tmp/dex_dump/",
        // 是否 dump（false 只打印清单）
        autoDump: true,
        // 只 dump location 匹配这些前缀的 DEX（如 ["com.target.app"]），空 = 全部
        filterPrefixes: [],
        // 是否排除系统 classLoader 的 DEX
        excludeSystemLoader: true,
    });

    var dumped = {};   // base -> size，去重
    var dexCount = 0;

    // 从 dalvik.system.DexFile Java 对象提取 native DexFile 指针和大小
    // DexFile.mCookie → OatDexFile* → +8 → DexFile*（与 dex_dump.js 一致，已验证）
    function getNativeDex(dexFileObj) {
        try {
            var DexFile = Java.use("dalvik.system.DexFile");
            var field = DexFile.class.getDeclaredField("mCookie");
            field.setAccessible(true);
            // dexFileObj 必须是 dalvik.system.DexFile 实例（Java.choose 直接枚举得到）
            var mCookie = field.get(dexFileObj);
            if (mCookie === null) return null;

            var cookieType = mCookie.getClass().getName();
            var cookies = [];
            if (cookieType === "[J") {
                var arr = Java.array('long', mCookie);
                for (var i = 0; i < arr.length; i++) cookies.push(arr[i]);
            } else if (cookieType === "java.lang.Long") {
                cookies.push(mCookie.longValue());
            } else if (cookieType === "[Ljava.lang.Long;") {
                var arr = Java.cast(mCookie, Java.use("[Ljava.lang.Long;"));
                for (var i = 0; i < arr.length; i++) {
                    if (arr[i] !== null) cookies.push(arr[i].longValue());
                }
            } else {
                return null;
            }

            for (var c = 0; c < cookies.length; c++) {
                var cookiePtr = ptr(cookies[c]);
                var offsets = [0, 8, 16, 24, 32, 40, 48, 56, 64];
                for (var oi = 0; oi < offsets.length; oi++) {
                    try {
                        var candidate = cookiePtr.add(offsets[oi]).readPointer();
                        if (candidate.isNull()) continue;
                        var magicArr = candidate.readByteArray(4);
                        var m = new Uint8Array(magicArr);
                        if (m[0] === 0x64 && m[1] === 0x65 && m[2] === 0x78) {
                            var dexSize = candidate.add(0x20).readU32();
                            return { base: candidate, size: dexSize };
                        }
                    } catch (e) {}
                }
            }
        } catch (e) {}
        return null;
    }

    function saveDex(dexPtr, dexSize, location) {
        if (!dexPtr || dexPtr.isNull() || dexSize <= 0 || dexSize > 0x40000000) return;
        if (dumped[dexPtr.toString()]) return;
        dumped[dexPtr.toString()] = dexSize;

        var clsCount = 0;
        try { clsCount = dexPtr.add(0x60).readU32(); } catch (e) {}

        U.info("[DEXCACHE] " + (location || "?") + " base=" + dexPtr + " size=" + dexSize +
            " class_defs=" + clsCount);

        if (!CONFIG.autoDump) return;

        try {
            var data = U.readDexMemory(dexPtr, dexSize);
            if (!data) { U.fail("[DEXCACHE:DUMP] " + dexPtr + " read failed"); return; }
            var baseName = ("classes" + (dexCount + 1)).replace(/\.class/, ".dex");
            var outputPath = CONFIG.outputDir + baseName;
            var f = new File(outputPath, "wb");
            f.write(data);
            f.close();
            dexCount++;
            U.ok("[DEXCACHE:DUMP] " + outputPath + " (" + (dexSize / 1024 / 1024).toFixed(2) + " MB)");
        } catch (e) {
            U.fail("[DEXCACHE:DUMP] " + dexPtr + " failed: " + e.message);
        }
    }

    function dumpAll() {
        if (!Java.available) { U.fail("Java not available"); return; }
        Java.perform(function () {
            var scanStart = Date.now();
            var total = 0;
            try {
                Java.choose("dalvik.system.DexFile", {
                    onMatch: function (instance) {
                        total++;
                        try {
                            var location = "";
                            try { location = instance.getName() || ""; } catch (e) {}

                            // classLoader 过滤独立 try/catch（getClassLoader 可能抛异常，不能中断 dump）
                            if (CONFIG.excludeSystemLoader) {
                                try {
                                    var classLoader = instance.getClassLoader();
                                    if (classLoader) {
                                        var cls = classLoader.getClass
                                            ? classLoader.getClass().getName()
                                            : "?";
                                        if (cls.indexOf("BootClassLoader") !== -1) return;
                                    }
                                } catch (e) {}
                            }

                            if (CONFIG.filterPrefixes.length > 0) {
                                var hit = false;
                                for (var i = 0; i < CONFIG.filterPrefixes.length; i++) {
                                    if (location && location.indexOf(CONFIG.filterPrefixes[i]) !== -1) { hit = true; break; }
                                }
                                if (!hit) return;
                            }

                            var nd = getNativeDex(instance);
                            if (nd) saveDex(nd.base, nd.size, location);
                        } catch (e) {}
                    },
                    onComplete: function () {
                        U.ok("[DEXCACHE] scanned " + total + " DexFile in " + ((Date.now() - scanStart) / 1000).toFixed(1) + "s, dumped " + dexCount + " unique DEX");
                    }
                });
            } catch (e) {
                U.fail("[DEXCACHE] Java.choose failed: " + e.message);
            }
        });
    }

    global.DexCacheDump = {
        dumpAll: dumpAll,
        getDumpedCount: function () { return dexCount; },
    };

    U.info("dex_cache_dump.js ready (autoDump=" + CONFIG.autoDump + " filter=" +
        (CONFIG.filterPrefixes.join(",") || "all") + ")");
    console.log("");

    // 输出目录优先 app 私有目录（/data/local/tmp 属 root，app 进程无写权限）
    // 注意：必须在 Java 就绪后解析（顶层 Java.perform 异步，currentApplication 未就绪）
    function resolveOutputDir() {
        var appDumpDir = U.getDumpDir();
        if (appDumpDir) CONFIG.outputDir = appDumpDir;
        U.ensureDir(CONFIG.outputDir);
    }

    setTimeout(function () { resolveOutputDir(); dumpAll(); }, 5000); // 等壳完成解密后自动执行

})(this);