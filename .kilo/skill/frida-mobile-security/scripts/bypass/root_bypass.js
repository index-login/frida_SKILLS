/**
 * root_bypass.js - Root 检测绕过模块
 * 用途：系统性绕过 Android 应用的 Root 检测，覆盖 Java 层和 Native 层
 * 覆盖：File.exists / Runtime.exec / SystemProperties / PackageManager / Native libc 文件访问 / 线程检测
 * 来源：整合自 Frida 学习笔记 · Root 检测绕过（KuGou / CMB 实战）
 * 加载方式：frida -U -f com.app -l utils.js -l root_bypass.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] root_bypass requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('root_bypass', {
        // Java 层: File.exists / canExecute / canRead 通配 hook
        hookFileExists: true,
        // Java 层: Runtime.exec / ProcessBuilder 拦截
        hookRuntimeExec: true,
        // Java 层: SystemProperties + Build 字段伪造
        hookSystemProperties: true,
        // Java 层: PackageManager (getPackageInfo / getInstalledPackages / getInstalledApplications)
        hookPackageManager: true,
        // Native 层: libc 文件访问 (access / faccessat / stat / fstatat / open / openat / fopen)
        hookNativeFile: true,
        // Java 层: Thread.start 拦截（观察模式）
        hookThreadBlock: true,
        // 只观察不拦截（Thread.start 场景）
        threadObserveOnly: true,

        // 可疑 Root 文件列表（大小写不敏感）
        suspiciousFiles: [
            "/su", "/su/bin/su", "/system/bin/su", "/system/xbin/su",
            "/sbin/su", "/system/sbin/su", "/vendor/bin/su",
            "/magisk", "/magisk/.core", "/magisk/mirror",
            "/data/adb", "/data/adb/magisk", "/data/adb/modules",
            "/system/app/Superuser", "/system/app/SuperSU",
            "/system/app/Kinguser", "/system/app/MagiskManager",
            "/data/local/tmp", "/system/etc/init.d",
            "/system/bin/failsafe", "/system/xbin/failsafe",
            "/system/bin/.ext", "/system/xbin/.ext",
            "/proc/self/attr", "/proc/self/attr/prev",
        ],

        // 可疑 Root 包名
        suspiciousPackages: [
            "com.noshufou.android.su", "com.noshufou.android.su.elite",
            "eu.chainfire.supersu", "com.koushikdutta.superuser",
            "com.thirdparty.superuser", "com.yellowes.su",
            "com.topjohnwu.magisk", "com.kingroot.kinguser",
            "com.kingo.root", "com.smedialink.oneclickroot",
            "com.dimonvideo.luckypatcher", "com.chelpus.lackypatch",
            "org.simsu.android", "com.aurora.root",
        ],

        // 伪装属性
        fakeBuildTags: "release-keys",
        fakeBuildType: "user",

        // 危险命令关键词
        dangerousCommands: ["su", "magisk", "root", "mount", "busybox", "chmod 777"],
    });

    var SUSPICIOUS_FILE_REGEX = CONFIG.suspiciousFiles.map(function (f) {
        return new RegExp(f.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
    });

    function isSuspiciousFile(path) {
        if (!path) return false;
        for (var i = 0; i < SUSPICIOUS_FILE_REGEX.length; i++) {
            if (SUSPICIOUS_FILE_REGEX[i].test(path)) return true;
        }
        return false;
    }

    if (!Java.available) {
        U.info("root_bypass: Java not available, native hooks only");
        // 即使 Java 不可用，Native 层 hook 仍可继续
    }

    // ==================== 1. File.exists / canExecute / canRead ====================
    if (CONFIG.hookFileExists && Java.available) {
        Java.perform(function () {
            try {
                var File = Java.use("java.io.File");

                var existMethods = ["exists", "canExecute", "canRead", "canWrite", "isFile", "isDirectory"];
                existMethods.forEach(function (method) {
                    File[method].implementation = function () {
                        var path = this.getAbsolutePath();
                        var orig = this[method]();
                        if (orig && isSuspiciousFile(path)) {
                            U.alert("[ROOT_BYPASS] Blocked File." + method + "(\"" + path + "\") → false");
                            return false;
                        }
                        return orig;
                    };
                });

                // File.list / listFiles — 如果列出的是可疑目录，返回空
                var listMethods = ["list", "listFiles"];
                listMethods.forEach(function (method) {
                    try {
                        File[method].overload().implementation = function () {
                            var path = this.getAbsolutePath();
                            var orig = this[method]();
                            if (isSuspiciousFile(path)) {
                                U.alert("[ROOT_BYPASS] Blocked File." + method + "(\"" + path + "\") → null");
                                return null;
                            }
                            return orig;
                        };
                    } catch (e) {}
                });

                U.ok("File.exists/canExecute/canRead hooks active");
            } catch (e) { U.fail("File hooks failed: " + e.message); }
        });
    }

    // ==================== 2. Runtime.exec / ProcessBuilder ====================
    if (CONFIG.hookRuntimeExec && Java.available) {
        Java.perform(function () {
            try {
                var Runtime = Java.use("java.lang.Runtime");
                var execMethods = [
                    { name: "exec", overload: ["java.lang.String"] },
                    { name: "exec", overload: ["java.lang.String", "[Ljava.lang.String;"] },
                    { name: "exec", overload: ["java.lang.String", "[Ljava.lang.String;", "java.io.File"] },
                    { name: "exec", overload: ["[Ljava.lang.String;"] },
                    { name: "exec", overload: ["[Ljava.lang.String;", "[Ljava.lang.String;"] },
                    { name: "exec", overload: ["[Ljava.lang.String;", "[Ljava.lang.String;", "java.io.File"] },
                ];

                execMethods.forEach(function (m) {
                    try {
                        Runtime[m.name].overload.apply(Runtime[m.name], m.overload).implementation = function () {
                            var cmd = arguments[0];
                            var cmdStr = Array.isArray(cmd) ? cmd.join(" ") : String(cmd);
                            for (var i = 0; i < CONFIG.dangerousCommands.length; i++) {
                                if (cmdStr.toLowerCase().indexOf(CONFIG.dangerousCommands[i].toLowerCase()) !== -1) {
                                    U.alert("[ROOT_BYPASS] Blocked Runtime.exec(\"" + cmdStr + "\") — dangerous command");
                                    throw Java.use("java.io.IOException").$new("Permission denied");
                                }
                            }
                            return this[m.name].apply(this, arguments);
                        };
                    } catch (e) {}
                });

                // ProcessBuilder
                try {
                    var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
                    ProcessBuilder.start.implementation = function () {
                        var cmd = this.command();
                        var cmdStr = cmd.toString();
                        for (var i = 0; i < CONFIG.dangerousCommands.length; i++) {
                            if (cmdStr.toLowerCase().indexOf(CONFIG.dangerousCommands[i].toLowerCase()) !== -1) {
                                U.alert("[ROOT_BYPASS] Blocked ProcessBuilder.start(\"" + cmdStr + "\")");
                                throw Java.use("java.io.IOException").$new("Permission denied");
                            }
                        }
                        return this.start();
                    };
                } catch (e) {}

                U.ok("Runtime.exec/ProcessBuilder hooks active");
            } catch (e) { U.fail("Runtime.exec hooks failed: " + e.message); }
        });
    }

    // ==================== 3. SystemProperties + Build 字段伪装 ====================
    if (CONFIG.hookSystemProperties && Java.available) {
        Java.perform(function () {
            // SystemProperties.get
            try {
                var SystemProperties = Java.use("android.os.SystemProperties");
                var spGetMethods = ["get", "getInt", "getLong", "getBoolean"];
                spGetMethods.forEach(function (method) {
                    try {
                        SystemProperties[method].overload("java.lang.String").implementation = function (key) {
                            var result = this[method](key);
                            if (key === "ro.build.tags" && result === "test-keys") {
                                U.alert("[ROOT_BYPASS] SystemProperties." + method + "(\"" + key + "\") → \"" + CONFIG.fakeBuildTags + "\"");
                                return CONFIG.fakeBuildTags;
                            }
                            if (key === "ro.build.type" && result === "userdebug") {
                                U.alert("[ROOT_BYPASS] SystemProperties." + method + "(\"" + key + "\") → \"" + CONFIG.fakeBuildType + "\"");
                                return CONFIG.fakeBuildType;
                            }
                            return result;
                        };
                    } catch (e) {}
                });
                U.ok("SystemProperties hooks active");
            } catch (e) { U.fail("SystemProperties hooks failed: " + e.message); }

            // Build 静态字段反射
            try {
                var Build = Java.use("android.os.Build");
                var Build_VERSION = Java.use("android.os.Build$VERSION");
                // 替换 TAGS
                var tagsField = Build.class.getDeclaredField("TAGS");
                tagsField.setAccessible(true);
                var origTags = tagsField.get(null);
                if (origTags === "test-keys") {
                    tagsField.set(null, CONFIG.fakeBuildTags);
                    U.ok("Build.TAGS: \"test-keys\" → \"" + CONFIG.fakeBuildTags + "\"");
                }
                U.ok("Build static fields checked");
            } catch (e) { U.fail("Build fields check failed: " + e.message); }
        });
    }

    // ==================== 4. PackageManager ====================
    if (CONFIG.hookPackageManager && Java.available) {
        Java.perform(function () {
            try {
                var PM = Java.use("android.app.ApplicationPackageManager");

                // getPackageInfo
                PM.getPackageInfo.overload("java.lang.String", "int").implementation = function (pkg, flags) {
                    for (var i = 0; i < CONFIG.suspiciousPackages.length; i++) {
                        if (pkg.indexOf(CONFIG.suspiciousPackages[i]) !== -1) {
                            U.alert("[ROOT_BYPASS] Blocked getPackageInfo(\"" + pkg + "\") → NameNotFoundException");
                            throw Java.use("android.content.pm.PackageManager$NameNotFoundException").$new();
                        }
                    }
                    return this.getPackageInfo(pkg, flags);
                };

                // getInstalledPackages
                try {
                    PM.getInstalledPackages.overload("int").implementation = function (flags) {
                        var result = this.getInstalledPackages(flags);
                        // 过滤掉可疑包
                        var filtered = Java.use("java.util.ArrayList").$new();
                        var iter = result.iterator();
                        while (iter.hasNext()) {
                            var pkg = Java.cast(iter.next(), Java.use("android.content.pm.PackageInfo"));
                            var isSuspicious = false;
                            for (var i = 0; i < CONFIG.suspiciousPackages.length; i++) {
                                if (pkg.packageName.value.indexOf(CONFIG.suspiciousPackages[i]) !== -1) {
                                    isSuspicious = true;
                                    U.alert("[ROOT_BYPASS] Filtered package: " + pkg.packageName.value);
                                    break;
                                }
                            }
                            if (!isSuspicious) filtered.add(pkg);
                        }
                        return filtered;
                    };
                } catch (e) {}

                // getInstalledApplications
                try {
                    PM.getInstalledApplications.overload("int").implementation = function (flags) {
                        var result = this.getInstalledApplications(flags);
                        var filtered = Java.use("java.util.ArrayList").$new();
                        var iter = result.iterator();
                        while (iter.hasNext()) {
                            var info = Java.cast(iter.next(), Java.use("android.content.pm.ApplicationInfo"));
                            var isSuspicious = false;
                            for (var i = 0; i < CONFIG.suspiciousPackages.length; i++) {
                                if (info.packageName.value.indexOf(CONFIG.suspiciousPackages[i]) !== -1) {
                                    isSuspicious = true;
                                    break;
                                }
                            }
                            if (!isSuspicious) filtered.add(info);
                        }
                        return filtered;
                    };
                } catch (e) {}

                U.ok("PackageManager hooks active");
            } catch (e) { U.fail("PackageManager hooks failed: " + e.message); }
        });
    }

    // ==================== 5. Native 层 libc 文件访问 ====================
    if (CONFIG.hookNativeFile) {
        var libcHookTargets = [
            { mod: "libc.so", func: "access", nArgs: 1 },
            { mod: "libc.so", func: "faccessat", nArgs: 3 },
            { mod: "libc.so", func: "stat", nArgs: 1 },
            { mod: "libc.so", func: "fstatat", nArgs: 3 },
            { mod: "libc.so", func: "open", nArgs: 2 },
            { mod: "libc.so", func: "openat", nArgs: 3 },
            { mod: "libc.so", func: "fopen", nArgs: 1 },
        ];

        libcHookTargets.forEach(function (target) {
            var addr = Module.findExportByName(target.mod, target.func);
            if (!addr) return;
            Interceptor.attach(addr, {
                onEnter: function (args) {
                    try {
                        var path = args[0].readCString();
                        if (path && isSuspiciousFile(path)) {
                            this.blocked = true;
                            this.path = path;
                            this.func = target.func;
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.blocked) {
                        U.alert("[ROOT_BYPASS:NATIVE] Blocked " + this.func + "(\"" + this.path + "\") → -1");
                        retval.replace(ptr(-1));
                    }
                }
            });
        });
        U.ok("Native libc file hooks active (" + libcHookTargets.length + " functions)");
    }

    // ==================== 6. Thread.start 拦截 ====================
    if (CONFIG.hookThreadBlock && Java.available) {
        Java.perform(function () {
            try {
                var Thread = Java.use("java.lang.Thread");
                Thread.start.implementation = function () {
                    if (CONFIG.threadObserveOnly) {
                        U.info("[ROOT_BYPASS:OBSERVE] Thread.start: " + this.getName() + " (id=" + this.getId() + ")");
                        var stack = U.javaStack ? "(use showStack)" : "";
                        U.info(stack);
                    } else {
                        U.alert("[ROOT_BYPASS] Blocked Thread.start: " + this.getName());
                        return; // 不启动线程
                    }
                    return this.start();
                };
                U.ok("Thread.start hook active (observe=" + CONFIG.threadObserveOnly + ")");
            } catch (e) { U.fail("Thread.start hook failed: " + e.message); }
        });
    }

    U.info("root_bypass.js ready");
    console.log("");

})(this);