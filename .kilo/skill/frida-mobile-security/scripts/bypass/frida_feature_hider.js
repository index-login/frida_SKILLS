/**
 * frida_feature_hider.js - Frida 特征隐藏模块
 * 用途：拦截 /proc/self/maps, /proc/self/status, /proc/self/fd 等文件访问，
 *       过滤其中包含 frida/gum/linjector 等特征的行，使反 Frida 检测失效。
 *       支持 standalone 模式或配合 init_hook 在 call_constructors 处抢先激活。
 * 覆盖层级：libc (open/openat/fopen/fopen64/read/fgets/access/faccessat/stat)
 *           + libc (strstr — 对内存中直接扫描的兜底)
 * 加载方式：
 *   # Standalone（适用于 attach 模式）
 *   frida -U -f com.app -l utils.js -l frida_feature_hider.js
 *
 *   # 配合 init_hook（spawn 模式，抢在 init_array 前生效）
 *   frida -U -f com.app -l utils.js -l init_hook.js -l frida_feature_hider.js
 *     -e 'var CONFIG_OVERRIDE={init_hook:{onModuleInit:[{moduleName:"libmsaoaidsec.so"}]},
 *          frida_feature_hider:{indirectHook:false}}'
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] frida_feature_hider requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('frida_feature_hider', {
        blockProcSelfMaps: true,
        blockProcSelfStatus: true,
        blockProcSelfFd: true,
        blockProcSelfCmdline: false,
        blockProcSelfExe: false,
        blockProcSelfMountinfo: false,
        hideViaAccess: true,
        hookStrstr: true,
        filterKeywords: [
            "frida", "gum-js-loop", "linjector", "frida-agent",
            "gmain", "gdbus", "FRIDA", "frida-server",
            "gum", "gumjs", "fridahook",
        ],
        sanitizeRead: true,
        sanitizeFgets: true,
        verbose: false,
        indirectHook: false,
    });

    var active = false;
    var blockedCounts = {};
    var procFds = {};     // fd → path
    var procFiles = {};   // FILE* ptr → path

    function normPath(path) {
        if (!path) return "";
        return path.replace(/\/\//g, "/");
    }

    function isProcSelfPath(path) {
        if (!path) return false;
        var p = normPath(path);
        if (CONFIG.blockProcSelfMaps && (p === "/proc/self/maps" || p.indexOf("/proc/self/maps") === 0)) return "maps";
        if (CONFIG.blockProcSelfStatus && (p === "/proc/self/status" || p.indexOf("/proc/self/status") === 0)) return "status";
        if (CONFIG.blockProcSelfFd && (p.indexOf("/proc/self/fd/") !== -1 || p === "/proc/self/fd")) return "fd";
        if (CONFIG.blockProcSelfCmdline && (p === "/proc/self/cmdline")) return "cmdline";
        if (CONFIG.blockProcSelfExe && (p === "/proc/self/exe")) return "exe";
        if (CONFIG.blockProcSelfMountinfo && (p === "/proc/self/mountinfo")) return "mountinfo";
        if (p.indexOf("/proc/") !== -1 && p.indexOf("self") !== -1) {
            // 泛匹配：任何 /proc/self/* 且路径或文件名包含 task/taskid
            if (p.indexOf("/task/") === -1) {
                // 不拦截 /proc/self/task/*（线程信息），除非明确配置
            }
        }
        return null;
    }

    function containsKeyword(str) {
        if (!str) return false;
        var lower = str.toLowerCase();
        for (var i = 0; i < CONFIG.filterKeywords.length; i++) {
            if (lower.indexOf(CONFIG.filterKeywords[i].toLowerCase()) !== -1) return true;
        }
        return false;
    }

    function logBlocked(label, detail) {
        blockedCounts[label] = (blockedCounts[label] || 0) + 1;
        if (CONFIG.verbose) {
            U.alert("[FEATURE_HIDER] " + label + " " + (detail || "") + " (count=" + blockedCounts[label] + ")");
        }
    }

    // ========== read 缓冲过滤 ==========
    function sanitizeReadBuffer(buf, n, fd) {
        if (!buf || buf.isNull() || n <= 0) return false;
        try {
            var content = buf.readUtf8String(n);
            if (!containsKeyword(content)) return false;

            // 逐行过滤，保留不含关键词的行
            var lines = content.split("\n");
            var filteredLines = [];
            for (var i = 0; i < lines.length; i++) {
                if (!containsKeyword(lines[i])) {
                    filteredLines.push(lines[i]);
                }
            }
            var filtered = filteredLines.join("\n");

            // 写回原始缓冲区（先清零，再写入过滤后内容）
            var zeroBuf = [];
            for (var j = 0; j < n; j++) zeroBuf.push(0);
            buf.writeByteArray(zeroBuf);
            var filteredBytes = [];
            for (var k = 0; k < Math.min(filtered.length, n); k++) {
                filteredBytes.push(filtered.charCodeAt(k));
            }
            buf.writeByteArray(filteredBytes);

            logBlocked("read_sanitize", "fd=" + fd + " orig=" + n + " bytes → filtered");
            return true;
        } catch (e) {
            if (CONFIG.verbose) U.fail("read sanitize error: " + e.message);
            return false;
        }
    }

    // ========== fgets 行过滤 ==========
    function sanitizeFgetsLine(buf, maxSize) {
        if (!buf || buf.isNull()) return false;
        try {
            var line = buf.readCString();
            if (!line) return false;
            if (!containsKeyword(line)) return false;

            // 替换为仅含换行符的空行
            buf.writeByteArray([0x0A, 0x00]); // "\n\0"

            logBlocked("fgets_sanitize", "filtered: " + line.substring(0, Math.min(line.length, 60)));
            return true;
        } catch (e) {
            return false;
        }
    }

    // ========== Hook: open / openat ==========
    function hookOpen() {
        var funcs = [
            { mod: "libc.so", name: "open", argIndex: 0 },
            { mod: "libc.so", name: "__openat", argIndex: 1 },
        ];

        // openat 在不同 Android 版本可能名称不同
        try {
            var openatAddr = Module.findExportByName("libc.so", "openat");
            if (openatAddr) funcs.push({ mod: "libc.so", name: "openat", argIndex: 1 });
        } catch (e) {}

        funcs.forEach(function (f) {
            U.registerHook(U.safeHook(f.mod, f.name, {
                onEnter: function (args) {
                    var path = U.safeReadCString(args[f.argIndex]);
                    if (!path) return;
                    var procType = isProcSelfPath(path);
                    if (procType) {
                        this._hid = true;
                        this._path = path;
                        this._procType = procType;
                        logBlocked("open:" + f.name, procType + " → " + path);
                    }
                },
                onLeave: function (retval) {
                    if (this._hid) {
                        var fd = retval.toInt32();
                        if (fd >= 0) {
                            procFds[fd] = this._path;
                            if (CONFIG.verbose) {
                                U.timeLog("[FEATURE_HIDER] tracked fd=" + fd + " for " + this._path);
                            }
                        }
                        // 不阻止 open，因为我们要在 read 层过滤
                        // 这样检测代码不会因为 open 失败而使用备用路径
                    }
                }
            }));
        });
    }

    // ========== Hook: fopen / fopen64 ==========
    function hookFopen() {
        ["fopen", "fopen64"].forEach(function (name) {
            U.registerHook(U.safeHook("libc.so", name, {
                onEnter: function (args) {
                    var path = U.safeReadCString(args[0]);
                    if (!path) return;
                    var procType = isProcSelfPath(path);
                    if (procType) {
                        this._hid = true;
                        this._path = path;
                        logBlocked("fopen", procType + " → " + path);
                    }
                },
                onLeave: function (retval) {
                    if (this._hid && !retval.isNull()) {
                        procFiles[retval.toString()] = this._path;
                        if (CONFIG.verbose) {
                            U.timeLog("[FEATURE_HIDER] tracked FILE* for " + this._path);
                        }
                    }
                }
            }));
        });
    }

    // ========== Hook: read ==========
    function hookRead() {
        U.registerHook(U.safeHook("libc.so", "read", {
            onEnter: function (args) {
                this.fd = args[0].toInt32();
                this.buf = args[1];
                this.count = args[2].toInt32();
            },
            onLeave: function (retval) {
                if (!CONFIG.sanitizeRead) return;
                var n = retval.toInt32();
                if (n <= 0) return;
                if (!procFds[this.fd]) return;
                sanitizeReadBuffer(this.buf, n, this.fd);
            }
        }));
    }

    // ========== Hook: fgets ==========
    function hookFgets() {
        if (!CONFIG.sanitizeFgets) return;
        U.registerHook(U.safeHook("libc.so", "fgets", {
            onEnter: function (args) {
                this.buf = args[0];
                this.size = args[1].toInt32();
                this.stream = args[2];
                if (this.stream && !this.stream.isNull()) {
                    this._streamKey = this.stream.toString();
                }
            },
            onLeave: function (retval) {
                if (retval.isNull()) return;
                if (!this._streamKey) return;
                if (!procFiles[this._streamKey]) return;
                sanitizeFgetsLine(this.buf, this.size);
            }
        }));
    }

    // ========== Hook: access / faccessat / stat — 隐藏文件存在 ==========
    function hookAccess() {
        if (!CONFIG.hideViaAccess) return;

        // access
        U.registerHook(U.safeHook("libc.so", "access", {
            onEnter: function (args) {
                var path = U.safeReadCString(args[0]);
                if (path && isProcSelfPath(path)) {
                    this._hid = true;
                    logBlocked("access", "→ " + path);
                }
            },
            onLeave: function (retval) {
                if (this._hid) {
                    retval.replace(ptr(-1)); // ENOENT
                }
            }
        }));

        // faccessat
        U.registerHook(U.safeHook("libc.so", "faccessat", {
            onEnter: function (args) {
                var dirfd = args[0].toInt32();
                var path = U.safeReadCString(args[1]);
                if (path && isProcSelfPath(path)) {
                    this._hid = true;
                    logBlocked("faccessat", "→ " + path);
                }
            },
            onLeave: function (retval) {
                if (this._hid) {
                    retval.replace(ptr(-1));
                }
            }
        }));

        // stat (仅拦截 /proc/self/*)
        ["stat", "lstat", "__xstat", "__lxstat"].forEach(function (name) {
            try {
                var addr = Module.findExportByName("libc.so", name);
                if (!addr) return;
                Interceptor.attach(addr, {
                    onEnter: function (args) {
                        var path = args[0];
                        if (name.indexOf("xstat") !== -1) path = args[1]; // __xstat(ver, path, buf)
                        var p = U.safeReadCString(path);
                        if (p && isProcSelfPath(p)) {
                            this._hid = true;
                            logBlocked(name, "→ " + p);
                        }
                    },
                    onLeave: function (retval) {
                        if (this._hid) {
                            retval.replace(ptr(-1));
                        }
                    }
                });
            } catch (e) {}
        });
    }

    // ========== Hook: strstr 兜底 ==========
    function hookStrstr() {
        if (!CONFIG.hookStrstr) return;

        U.registerHook(U.safeHook("libc.so", "strstr", {
            onEnter: function (args) {
                this.haystack = args[0];
                this.needle = U.safeReadCString(args[1]);
                if (!this.needle) return;
                if (containsKeyword(this.needle)) {
                    this._suspect = true;
                }
            },
            onLeave: function (retval) {
                if (!this._suspect || retval.isNull()) return;
                // 检测到匹配 — 这很可能是 Frida 检测
                // 打印调用栈帮助定位
                logBlocked("strstr", 'needle="' + this.needle + '" result=' + retval);
                U.logBacktrace(this.context, 10);

                // 注意：不修改返回值。strstr 广泛使用，修改可能导致误杀。
                // 仅记录调用栈供分析人员手动 patch。
            }
        }));
    }

    // ========== 导出 API ==========
    global.FridaFeatureHider = {
        /**
         * 激活隐藏（配合 init_hook 使用，在 call_constructors 回调中调用）
         * 因为 init_array 尚未执行，此时激活可以拦截 init_proc 中的 /proc 检测
         */
        activate: function () {
            if (active) return;
            active = true;
            U.alert("[FEATURE_HIDER] activate() called — hiding Frida features");
            hookOpen();
            hookFopen();
            hookRead();
            hookFgets();
            hookAccess();
            hookStrstr();
            U.ok("[FEATURE_HIDER] activated");
        },

        /**
         * 手动添加追踪的 fd（用于特殊情况）
         */
        trackFd: function (fd, path) {
            procFds[fd] = path;
        },

        /**
         * 查询状态
         */
        getStats: function () {
            return {
                active: active,
                blockedCounts: blockedCounts,
                trackedFds: Object.keys(procFds).length,
                trackedFiles: Object.keys(procFiles).length,
            };
        },

        /**
         * 重置统计
         */
        resetStats: function () {
            blockedCounts = {};
        },
    };

    // ========== 启动 ==========
    (function init() {
        U.info("frida_feature_hider.js initializing...");

        var hiding = [];
        if (CONFIG.blockProcSelfMaps) hiding.push("maps");
        if (CONFIG.blockProcSelfStatus) hiding.push("status");
        if (CONFIG.blockProcSelfFd) hiding.push("fd");
        U.info("hiding: " + (hiding.length > 0 ? hiding.join(", ") : "none"));
        U.info("methods: read=" + CONFIG.sanitizeRead +
               " fgets=" + CONFIG.sanitizeFgets +
               " access=" + CONFIG.hideViaAccess +
               " strstr=" + CONFIG.hookStrstr);
        U.info("indirectHook=" + CONFIG.indirectHook);

        if (CONFIG.indirectHook) {
            // 延迟激活：等待外部通过 FridaFeatureHider.activate() 触发
            U.info("frida_feature_hider.js ready (INDIRECT mode — waiting for activate())");
        } else {
            // 立即激活
            active = true;
            hookOpen();
            hookFopen();
            hookRead();
            hookFgets();
            hookAccess();
            hookStrstr();
            U.info("frida_feature_hider.js ready (active)");
        }
        console.log("");
    })();

})(this);
