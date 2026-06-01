/**
 * memory_scanner.js - 内存敏感数据扫描 + 密码输入监听
 * 用途：
 *   1. 自动扫描预设的高价值数据（AES key、JWT、私钥、API key、URL凭证）
 *   2. 实时监听密码输入框的输入内容
 *   3. 通过 Frida console 交互式搜索内存（MemoryScanner.search("pattern")）
 *
 * 加载方式：
 *   frida -U -f com.app -l utils.js -l memory_scanner.js
 *
 * 交互式命令（Frida console 中执行）：
 *   MemoryScanner.search("api_key")        搜索所有 rw- 内存区域
 *   MemoryScanner.searchJava("password")   搜索 Java 堆 String 对象
 *   MemoryScanner.searchMod("libxxx.so", "secret")  搜索指定模块
 *   MemoryScanner.dump("0x7a12345678", 256) hexdump 指定地址
 *   MemoryScanner.stats()                  查看扫描统计
 *   MemoryScanner.scanNow()                手动触发一次完整扫描
 *   MemoryScanner.startPasswordCapture()   启动密码输入监听
 *   MemoryScanner.passwordCaptureStatus()  查看密码监听状态
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] memory_scanner requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('memory_scanner', {
        // ========== 预设自动扫描（加载时立即执行一次） ==========
        autoScanOnLoad: true,
        autoScanDelay: 3000,        // 延迟 ms，等 app 初始化完成

        // AES 密钥 (128/192/256-bit hex)
        scanAesKeys: true,
        aesKeyMinLen: 32,           // 最小 hex 长度 (128-bit = 32 hex chars)
        aesKeyMaxLen: 128,          // 最大 hex 长度

        // JWT Token
        scanJwt: true,

        // PEM 私钥
        scanPemKeys: true,

        // API Key (已知格式)
        scanApiKeys: true,

        // URL 凭证 (https://user:pass@host)
        scanUrlCredentials: true,

        // ========== 密码输入监听（默认关闭，console 调用 MemoryScanner.startPasswordCapture() 启动） ==========
        passwordShowChars: 64,      // 每次展示的最大字符数
        passwordShowStack: false,   // 是否打印调用栈

        // ========== 扫描参数 ==========
        scanNativeMemory: true,     // 扫描 Native 内存 (rw- 区域)
        scanJavaHeap: true,         // 扫描 Java 堆 String 对象
        maxRangeSize: 64 * 1024 * 1024,  // 跳过大于 64MB 的内存区域
        maxResultsPerPattern: 50,   // 每种模式最多展示的结果数
        resultContextLen: 40,       // 匹配结果前后文 hex 长度

        // ========== 性能 ==========
        scanInterval: 0,            // 0 = 不重复扫描，>0 = 定时扫描间隔 ms
        memoryChunkSize: 65536,     // 每次读取的内存块大小
    });

    // ==================== 预定义模式 ====================

    var PRESETS = {};

    if (CONFIG.scanAesKeys) {
        PRESETS["AES_KEY_128"] = {
            regex: /[0-9a-fA-F]{32}/g,
            label: "AES-128 key (hex)",
            alert: true,
            dedup: true,
        };
        PRESETS["AES_KEY_192"] = {
            regex: /[0-9a-fA-F]{48}/g,
            label: "AES-192 key (hex)",
            alert: true,
            dedup: true,
        };
        PRESETS["AES_KEY_256"] = {
            regex: /[0-9a-fA-F]{64}/g,
            label: "AES-256 key (hex)",
            alert: true,
            dedup: true,
        };
    }

    if (CONFIG.scanJwt) {
        PRESETS["JWT_TOKEN"] = {
            regex: /eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g,
            label: "JWT Token",
            alert: true,
            dedup: true,
        };
    }

    if (CONFIG.scanPemKeys) {
        PRESETS["PEM_PRIVATE"] = {
            regex: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[^-]*-----END (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/gs,
            label: "PEM Private Key",
            alert: true,
            dedup: true,
        };
        PRESETS["PEM_PUBLIC"] = {
            regex: /-----BEGIN PUBLIC KEY-----[^-]*-----END PUBLIC KEY-----/gs,
            label: "PEM Public Key",
            alert: false,
            dedup: true,
        };
        PRESETS["PEM_CERT"] = {
            regex: /-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----/gs,
            label: "PEM Certificate",
            alert: false,
            dedup: true,
        };
    }

    if (CONFIG.scanApiKeys) {
        PRESETS["AWS_ACCESS_KEY"] = {
            regex: /AKIA[0-9A-Z]{16}/g,
            label: "AWS Access Key ID",
            alert: true,
            dedup: true,
        };
        PRESETS["AWS_SECRET_KEY"] = {
            regex: /[0-9a-zA-Z\/+]{40}/g,
            label: "AWS Secret Key (candidate)",
            alert: false,
            dedup: true,
            filter: function (s) {
                return /[A-Z]/.test(s) && /[a-z]/.test(s) && /[0-9]/.test(s);
            },
        };
        PRESETS["FIREBASE_URL"] = {
            regex: /https?:\/\/[a-zA-Z0-9-]+\.firebaseio\.com/g,
            label: "Firebase URL",
            alert: true,
            dedup: true,
        };
        PRESETS["GOOGLE_API_KEY"] = {
            regex: /AIza[0-9A-Za-z\-_]{35}/g,
            label: "Google API Key",
            alert: true,
            dedup: true,
        };
        PRESETS["GITHUB_TOKEN"] = {
            regex: /gh[pousr]_[A-Za-z0-9_]{36,255}/g,
            label: "GitHub Token",
            alert: true,
            dedup: true,
        };
        PRESETS["SLACK_TOKEN"] = {
            regex: /xox[baprs]-[0-9a-zA-Z\-]{10,}/g,
            label: "Slack Token",
            alert: true,
            dedup: true,
        };
        PRESETS["STRIPE_KEY"] = {
            regex: /[sr]k_(live|test)_[0-9a-zA-Z]{24,}/g,
            label: "Stripe API Key",
            alert: true,
            dedup: true,
        };
    }

    if (CONFIG.scanUrlCredentials) {
        PRESETS["URL_CREDENTIALS"] = {
            regex: /https?:\/\/[^:\s]{1,64}:[^@\s]{1,64}@[^\s]{1,256}/g,
            label: "URL with credentials",
            alert: true,
            dedup: true,
        };
    }

    // ==================== 扫描状态 ====================
    var stats = {
        scans: 0,
        totalMatches: 0,
        lastScanTime: 0,
        rangesScanned: 0,
        javaStringsScanned: 0,
        presets: {},
    };
    var seenHashes = {};  // dedup

    function hash(s) {
        var h = 0;
        for (var i = 0; i < s.length; i++) {
            h = ((h << 5) - h) + s.charCodeAt(i);
            h |= 0;
        }
        return h;
    }

    function isDedup(s) {
        var h = hash(s);
        if (seenHashes[h]) return true;
        seenHashes[h] = true;
        return false;
    }

    // ==================== 结果输出 ====================
    function reportMatch(label, value, source, alert) {
        if (alert === undefined) alert = false;
        if (CONFIG.maxResultsPerPattern > 0) {
            var key = label;
            stats.presets[key] = (stats.presets[key] || 0) + 1;
            if (stats.presets[key] > CONFIG.maxResultsPerPattern) return;
        }
        stats.totalMatches++;

        var prefix = alert ? "[!!!]" : "[ + ]";
        var msg = prefix + " [" + label + "] " + source;
        if (alert) {
            U.alert(msg);
        } else {
            U.ok(msg);
        }
        console.log("  " + (value.length > 200 ? value.substring(0, 200) + "..." : value));
        console.log("");
    }

    // ==================== Native 内存扫描 ====================
    function scanNativeMemory(patterns) {
        if (!CONFIG.scanNativeMemory) return;

        var ranges = Process.enumerateRanges({ protection: 'rw-', coalesce: true });
        stats.rangesScanned = 0;

        ranges.forEach(function (range) {
            if (range.size > CONFIG.maxRangeSize) return;
            if (range.size < 16) return;

            var mod = null;
            try {
                mod = Process.findModuleByAddress(range.base);
            } catch (e) {}

            var source = mod
                ? (mod.name + " + 0x" + range.base.sub(mod.base).toString(16) + " (" + (range.size / 1024).toFixed(0) + "KB)")
                : ("[anon:" + range.protection + "] " + range.base + " (" + (range.size / 1024).toFixed(0) + "KB)");

            stats.rangesScanned++;
            var offset = 0;
            while (offset < range.size) {
                var chunkSize = Math.min(CONFIG.memoryChunkSize, range.size - offset);
                var data;
                try {
                    data = range.base.add(offset).readByteArray(chunkSize);
                } catch (e) {
                    offset += chunkSize;
                    continue;
                }

                var str;
                try {
                    str = String.fromCharCode.apply(null, new Uint8Array(data));
                } catch (e) {
                    offset += chunkSize;
                    continue;
                }

                for (var name in patterns) {
                    var p = patterns[name];
                    var regex = new RegExp(p.regex.source, p.regex.flags);
                    var match;
                    while ((match = regex.exec(str)) !== null) {
                        var val = match[0];
                        if (p.dedup && isDedup(val)) continue;
                        if (p.filter && !p.filter(val)) continue;
                        reportMatch(p.label, val, source, p.alert);
                    }
                }
                offset += chunkSize;
            }
        });
    }

    // ==================== Java 堆扫描 ====================
    function scanJavaHeap(patterns) {
        if (!CONFIG.scanJavaHeap || !Java.available) return;

        Java.perform(function () {
            stats.javaStringsScanned = 0;
            var String = Java.use("java.lang.String");

            Java.choose("java.lang.String", {
                onMatch: function (instance) {
                    stats.javaStringsScanned++;
                    if (stats.javaStringsScanned % 1000 === 0) {
                        U.info("Scanned " + stats.javaStringsScanned + " Java Strings...");
                    }
                    var val = instance.toString();
                    if (val.length < 16 || val.length > 4096) return;

                    for (var name in patterns) {
                        var p = patterns[name];
                        var regex = new RegExp(p.regex.source, p.regex.flags);
                        regex.lastIndex = 0;
                        var match = regex.exec(val);
                        if (match) {
                            var matched = match[0];
                            if (p.dedup && isDedup(matched)) continue;
                            if (p.filter && !p.filter(matched)) continue;
                            reportMatch(p.label, matched, "Java heap", p.alert);
                        }
                    }
                },
                onComplete: function () {
                    U.info("Java heap scan complete: " + stats.javaStringsScanned + " strings");
                }
            });
        });
    }

    // ==================== 密码输入监听 ====================
    var passwordFieldSet = {};
    var passwordHooksActive = false;
    var passwordHookListeners = [];

    function setupPasswordCapture() {
        if (!Java.available) {
            console.log("[-] Java not available");
            return;
        }
        if (passwordHooksActive) {
            U.info("Password capture already active");
            return;
        }

        Java.perform(function () {
            try {
                var EditText = Java.use("android.widget.EditText");

                EditText.setInputType.implementation = function (type) {
                    var isPwd = (type & 0x80) !== 0;
                    if (isPwd) {
                        var id = this.hashCode();
                        passwordFieldSet[id] = true;
                        U.info("[PASSWORD] Field detected (inputType=0x" + type.toString(16) + ") id=" + id);
                    }
                    return this.setInputType(type);
                };

                EditText.setTransformationMethod.implementation = function (method) {
                    if (method && method.$className === "android.text.method.PasswordTransformationMethod") {
                        var id = this.hashCode();
                        passwordFieldSet[id] = true;
                        U.info("[PASSWORD] Field detected (PasswordTransformationMethod) id=" + id);
                    }
                    return this.setTransformationMethod(method);
                };

                EditText.getText.implementation = function () {
                    var result = this.getText();
                    var id = this.hashCode();
                    if (passwordFieldSet[id] && result && result.length() > 0) {
                        var text = result.toString();
                        var len = text.length;
                        var display = len > CONFIG.passwordShowChars
                            ? text.substring(0, CONFIG.passwordShowChars) + "...(" + len + " chars)"
                            : text;
                        U.alert("[PASSWORD INPUT] " + display);
                        if (CONFIG.passwordShowStack) {
                            U.javaStack();
                        }
                    }
                    return result;
                };

                passwordHooksActive = true;
                U.ok("Password input capture ACTIVE");
            } catch (e) {
                U.fail("Password capture hook failed: " + e.message);
            }
        });
    }

    // ==================== 交互式搜索 API ====================
    function searchPattern(patternStr, label) {
        if (!label) label = "search";
        var pattern;
        try {
            pattern = { regex: new RegExp(patternStr, 'g'), label: label, alert: true, dedup: false };
        } catch (e) {
            console.log("[-] Invalid regex: " + e.message);
            return;
        }
        var patterns = { "__search": pattern };
        U.info("Searching for: /" + patternStr + "/ ...");
        scanNativeMemory(patterns);
        U.info("Search complete.");
    }

    function searchJavaPattern(patternStr, label) {
        if (!Java.available) {
            console.log("[-] Java not available");
            return;
        }
        if (!label) label = "searchJava";
        var pattern;
        try {
            pattern = { regex: new RegExp(patternStr, 'g'), label: label, alert: true, dedup: false };
        } catch (e) {
            console.log("[-] Invalid regex: " + e.message);
            return;
        }
        var patterns = { "__searchJava": pattern };
        U.info("Searching Java heap for: /" + patternStr + "/ ...");
        scanJavaHeap(patterns);
    }

    function searchModulePattern(moduleName, patternStr, label) {
        if (!label) label = "searchMod";
        var mod = Process.findModuleByName(moduleName);
        if (!mod) {
            console.log("[-] Module not found: " + moduleName);
            return;
        }
        var pattern;
        try {
            pattern = new RegExp(patternStr, 'g');
        } catch (e) {
            console.log("[-] Invalid regex: " + e.message);
            return;
        }

        var data;
        try {
            data = mod.base.readByteArray(mod.size);
        } catch (e) {
            console.log("[-] Failed to read module memory: " + e.message);
            return;
        }

        var str;
        try {
            str = String.fromCharCode.apply(null, new Uint8Array(data));
        } catch (e) {
            console.log("[-] Failed to convert to string");
            return;
        }

        var match;
        var count = 0;
        while ((match = pattern.exec(str)) !== null) {
            count++;
            var offset = match.index;
            var val = match[0];
            var addr = mod.base.add(offset);
            U.ok("[" + label + "] " + moduleName + " + 0x" + offset.toString(16) + " @ " + addr);
            console.log("  " + (val.length > 200 ? val.substring(0, 200) + "..." : val));
        }
        U.info("Found " + count + " matches in " + moduleName + " (" + (mod.size / 1024).toFixed(0) + "KB)");
    }

    function dumpMemory(addrStr, size) {
        var addr;
        try {
            if (addrStr.indexOf("0x") === 0) {
                addr = ptr(addrStr);
            } else {
                addr = ptr(parseInt(addrStr));
            }
        } catch (e) {
            console.log("[-] Invalid address: " + addrStr);
            return;
        }
        size = size || 256;
        console.log(U.hexdumpSafe(addr, size));
    }

    // ==================== 导出 API ====================
    global.MemoryScanner = {
        /**
         * 搜索所有 rw- Native 内存区域
         * @param {string} pattern - 正则表达式字符串
         */
        search: function (pattern) {
            searchPattern(pattern);
        },

        /**
         * 搜索 Java 堆中的 String 对象
         * @param {string} pattern - 正则表达式字符串
         */
        searchJava: function (pattern) {
            searchJavaPattern(pattern);
        },

        /**
         * 搜索指定模块内存
         * @param {string} moduleName - 模块名，如 "libnative.so"
         * @param {string} pattern - 正则表达式字符串
         */
        searchMod: function (moduleName, pattern) {
            searchModulePattern(moduleName, pattern);
        },

        /**
         * Hexdump 指定地址
         * @param {string} addr - 地址，如 "0x7a12345678"
         * @param {number} size - 字节数，默认 256
         */
        dump: function (addr, size) {
            dumpMemory(addr, size);
        },

        /**
         * 手动触发一次完整扫描
         */
        scanNow: function () {
            U.info("Manual scan started...");
            var start = Date.now();
            scanNativeMemory(PRESETS);
            if (CONFIG.scanJavaHeap && Java.available) {
                scanJavaHeap(PRESETS);
            }
            var elapsed = ((Date.now() - start) / 1000).toFixed(1);
            stats.lastScanTime = Date.now();
            stats.scans++;
            U.info("Scan complete: " + stats.totalMatches + " matches in " + elapsed + "s");
        },

        /**
         * 查看扫描统计
         */
        stats: function () {
            console.log("========== MemoryScanner Stats ==========");
            console.log("  Scans:          " + stats.scans);
            console.log("  Total matches:  " + stats.totalMatches);
            console.log("  Ranges scanned: " + stats.rangesScanned);
            console.log("  Java strings:   " + stats.javaStringsScanned);
            console.log("  Last scan:      " + (stats.lastScanTime
                ? new Date(stats.lastScanTime).toLocaleTimeString() : "never"));
            console.log("  Pattern breakdown:");
            for (var k in stats.presets) {
                console.log("    " + k + ": " + stats.presets[k]);
            }
            console.log("=========================================");
        },

        /**
         * 添加自定义扫描模式
         * @param {string} name - 模式名称
         * @param {string} regexStr - 正则表达式字符串
         */
        addPattern: function (name, regexStr) {
            PRESETS[name] = {
                regex: new RegExp(regexStr, 'g'),
                label: name,
                alert: true,
                dedup: true,
            };
            U.info("Added pattern: " + name);
        },

        /**
         * 启动密码输入监听（Frida console 直接调用）
         * 用法: MemoryScanner.startPasswordCapture()
         */
        startPasswordCapture: function () {
            setupPasswordCapture();
        },

        /**
         * 查看密码输入监听状态
         */
        passwordCaptureStatus: function () {
            console.log("Password capture: " + (passwordHooksActive ? "ACTIVE" : "inactive"));
            console.log("Tracked fields: " + Object.keys(passwordFieldSet).length);
        },
    };

    // ==================== 启动 ====================
    (function init() {
        U.info("memory_scanner.js initializing...");

        if (CONFIG.autoScanOnLoad) {
            U.info("Auto-scan scheduled in " + (CONFIG.autoScanDelay / 1000).toFixed(1) + "s");
            setTimeout(function () {
                U.info("Auto-scan starting...");
                var start = Date.now();
                scanNativeMemory(PRESETS);
                if (CONFIG.scanJavaHeap && Java.available) {
                    scanJavaHeap(PRESETS);
                }
                var elapsed = ((Date.now() - start) / 1000).toFixed(1);
                stats.lastScanTime = Date.now();
                stats.scans++;
                U.info("Auto-scan complete: " + stats.totalMatches + " matches in " + elapsed + "s");
                U.info("MemoryScanner.search('pattern')  available for interactive use");
                U.info("MemoryScanner.searchJava('pattern')  for Java heap search");
                U.info("MemoryScanner.searchMod('lib.so', 'pattern')  for module search");
                U.info("MemoryScanner.dump('0x...', 256)  for hexdump");
                U.info("MemoryScanner.stats()  for scan statistics");
            }, CONFIG.autoScanDelay);
        } else {
            U.info("Auto-scan disabled. Use MemoryScanner.scanNow() to trigger.");
        }

        if (CONFIG.scanInterval > 0) {
            setInterval(function () {
                scanNativeMemory(PRESETS);
                if (CONFIG.scanJavaHeap && Java.available) {
                    scanJavaHeap(PRESETS);
                }
            }, CONFIG.scanInterval);
            U.info("Periodic scan enabled: every " + (CONFIG.scanInterval / 1000).toFixed(0) + "s");
        }

        U.info("memory_scanner.js ready");
        var presetCount = Object.keys(PRESETS).length;
        U.info("  presets: " + presetCount + " patterns");
        U.info("  native scan: " + CONFIG.scanNativeMemory);
        U.info("  java heap scan: " + CONFIG.scanJavaHeap);
        U.info("  MemoryScanner.startPasswordCapture()  to start password capture");
        console.log("");
    })();

})(this);