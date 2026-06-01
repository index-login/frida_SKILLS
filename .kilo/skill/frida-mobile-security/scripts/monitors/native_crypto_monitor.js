/**
 * native_crypto_monitor.js - Native 层 OpenSSL/BoringSSL 加密全自动监控
 * 用途：监控 Native 层所有加密操作，自动吐出算法、密钥、明文、密文
 * 覆盖：EVP Cipher / EVP Digest / HMAC / AES 低级 / RSA 低级 / MD5 低级 / Base64
 * 适用：使用 OpenSSL/BoringSSL 的 Android/iOS 应用
 * 加载方式：frida -U -f com.app -l utils.js -l native_crypto_monitor.js
 *
 * 视觉风格对齐 Java 版 crypto_monitor.js:
 *   - ANSI 256 色背景标签头, 按事件类型分色
 *   - 字段对齐: "    标签 │ 值",续行用等宽空白对齐
 *   - 智能 hex/text 双行:ASCII 可打印优先显 "text",其下再附 hex
 *   - 每事件用 buf 累积, 单次 console.log,多线程并发不会字段级混入
 *
 * 来源: Frida 学习笔记 — 算法自吐 · Native 层 OpenSSL/BoringSSL Hook
 */
(function (global) {
    'use strict';

    var U = global.Utils;

    var CONFIG = (U && U.mergeConfig)
        ? U.mergeConfig('native_crypto_monitor', {
            hookEvpCipher: true,
            hookEvpDigest: true,
            hookHmac: true,
            hookAesLowLevel: true,
            hookRsaLowLevel: true,
            hookMd5LowLevel: true,
            hookBase64: true,
            showBacktrace: false,
            backtraceDepth: 5,
            maxDataLength: 256,
            skipHugeUpdates: 8192,
            rateLimitPerSecond: 50,
            hideTestVectors: true,
            hideTlsNoise: true,
            useColor: true,
        })
        : {
            hookEvpCipher: true, hookEvpDigest: true, hookHmac: true,
            hookAesLowLevel: true, hookRsaLowLevel: true, hookMd5LowLevel: true,
            hookBase64: true, showBacktrace: false, backtraceDepth: 5,
            maxDataLength: 256, skipHugeUpdates: 8192, rateLimitPerSecond: 50,
            hideTestVectors: true, hideTlsNoise: true, useColor: true,
        };

    // ==================== ANSI 颜色 ====================
    var C = CONFIG.useColor ? {
        reset:    "\x1b[0m", bold:     "\x1b[1m", dim:      "\x1b[2m",
        green:    "\x1b[32m", yellow:   "\x1b[33m", gray:     "\x1b[90m",
        hCipher:    "\x1b[1;38;5;16;48;5;51m",   hHash:      "\x1b[1;38;5;15;48;5;27m",
        hHmac:      "\x1b[1;38;5;16;48;5;201m",  hSignature: "\x1b[1;38;5;16;48;5;220m",
        hKeyGen:    "\x1b[1;38;5;16;48;5;46m",
    } : {
        reset: "", bold: "", dim: "", green: "", yellow: "", gray: "",
        hCipher: "", hHash: "", hHmac: "", hSignature: "", hKeyGen: "",
    };

    function tint(color, text) { return CONFIG.useColor ? (color + text + C.reset) : text; }
    function visualLen(s) { var w = 0; for (var i = 0; i < s.length; i++) w += (s.charCodeAt(i) > 0x7f) ? 2 : 1; return w; }

    // ==================== 字节格式化 ====================
    function bytesToHex(bytes, origSize) {
        if (!bytes || bytes.length === 0) return "(empty)";
        var n = Math.min(bytes.length, CONFIG.maxDataLength);
        var hex = [];
        for (var i = 0; i < n; i++) {
            var b = (bytes[i] & 0xff).toString(16);
            hex.push(b.length === 1 ? "0" + b : b);
        }
        var out = hex.join("");
        var totalSize = origSize !== undefined ? origSize : bytes.length;
        if (totalSize > CONFIG.maxDataLength) out += "...(" + totalSize + " bytes)";
        return out;
    }

    function smartFormatBytes(bytes, origSize) {
        if (!bytes || bytes.length === 0) return ["(empty)"];
        var totalSize = origSize !== undefined ? origSize : bytes.length;
        var pc = 0;
        var cl = Math.min(bytes.length, 64);
        for (var i = 0; i < cl; i++) {
            var b = bytes[i] & 0xff;
            if ((b >= 0x20 && b <= 0x7e) || b === 0x09 || b === 0x0a || b === 0x0d) pc++;
        }
        var hex = bytesToHex(bytes, origSize);
        if (cl > 0 && pc / cl > 0.85) {
            var tmax = Math.min(bytes.length, 200);
            var s = "";
            for (var j = 0; j < tmax; j++) s += String.fromCharCode(bytes[j] & 0xff);
            if (totalSize > 200) s += "...";
            return ['"' + s + '"', hex];
        }
        return [hex];
    }

    function smartFormatPtr(ptr, size) {
        if (!ptr || ptr.isNull() || size <= 0) return ["(empty)"];
        var dumpSize = Math.min(size, CONFIG.maxDataLength);
        try {
            var bytes = new Uint8Array(ptr.readByteArray(dumpSize));
            return smartFormatBytes(bytes, size);
        } catch (e) { return ["(read failed)"]; }
    }

    function dumpPtrHex(ptr, size) {
        if (!ptr || ptr.isNull() || size <= 0) return "(empty)";
        var dumpSize = Math.min(size, CONFIG.maxDataLength);
        try {
            var bytes = new Uint8Array(ptr.readByteArray(dumpSize));
            return bytesToHex(bytes, size);
        } catch (e) { return "(read failed)"; }
    }

    function isTestVectorBytes(bytes) {
        if (!bytes || bytes.length < 16) return null;
        var n = bytes.length;
        var allZero = true, allFF = true, seq = true;
        for (var i = 0; i < n; i++) {
            if (bytes[i] !== 0) allZero = false;
            if (bytes[i] !== 0xff) allFF = false;
            if (bytes[i] !== (i & 0xff)) seq = false;
        }
        if (allZero) return "all zero";
        if (allFF) return "all FF";
        if (seq) return "NIST seq (FIPS-197)";
        if (n >= 8) { var p4 = true; for (var i = 0; i < n - 4; i++) { if (bytes[i] !== bytes[i + 4]) { p4 = false; break; } } if (p4) return "4-byte period"; }
        if (n >= 16) { var p8 = true; for (var i = 0; i < n - 8; i++) { if (bytes[i] !== bytes[i + 8]) { p8 = false; break; } } if (p8) return "8-byte period"; }
        return null;
    }

    // ==================== 输出原语 ====================
    function printHeader(type, subtitle, color, buf) {
        var label = type.toUpperCase();
        while (label.length < 9) label += " ";
        var tag = tint(color, "  " + label + "  ");
        var sub = CONFIG.useColor ? (C.bold + subtitle + C.reset) : subtitle;
        buf.push("");
        buf.push(tag + "  " + sub);
    }

    function printField(label, value, valueColor, buf) {
        if (value === null || value === undefined) return;
        var lines = (typeof value === "object" && value.length !== undefined) ? value : [value];
        if (lines.length === 0) return;
        var pad = "";
        while (visualLen(label) + pad.length < 4) pad += " ";
        var labelPart = tint(C.dim, "    " + label + pad + " │ ");
        var contPart = tint(C.dim, "         │ ");
        var paint = valueColor ? function (v) { return tint(valueColor, v); } : function (v) { return v; };
        buf.push(labelPart + paint(lines[0]));
        for (var i = 1; i < lines.length; i++) buf.push(contPart + paint(lines[i]));
    }

    function printMultiInput(label, inputsArrayOfArrays, buf) {
        var circled = ["①","②","③","④","⑤","⑥","⑦","⑧","⑨","⑩","⑪","⑫","⑬","⑭","⑮","⑯","⑰","⑱","⑲","⑳"];
        if (inputsArrayOfArrays.length === 0) return;
        if (inputsArrayOfArrays.length === 1) { printField(label, inputsArrayOfArrays[0], null, buf); return; }
        var flat = [];
        inputsArrayOfArrays.forEach(function (inpLines, idx) {
            var marker = circled[idx] || ("(" + (idx + 1) + ")");
            inpLines.forEach(function (line, j) { flat.push(j === 0 ? (marker + " " + line) : ("  " + line)); });
        });
        printField(label, flat, null, buf);
    }

    function getNativeStackLines(ctx) {
        if (!CONFIG.showBacktrace) return [];
        try {
            return Thread.backtrace(ctx, Backtracer.FUZZY).slice(0, CONFIG.backtraceDepth).map(function (addr) {
                return DebugSymbol.fromAddress(addr).toString();
            });
        } catch (e) { return []; }
    }
    function printStack(ctx, buf) {
        var lines = getNativeStackLines(ctx);
        if (lines.length === 0) return;
        printField("stack", lines, null, buf);
    }

    // 限速器
    var logBudget = CONFIG.rateLimitPerSecond || 999;
    var lastRefill = Date.now();
    function canLog() {
        if (CONFIG.rateLimitPerSecond <= 0) return true;
        var now = Date.now();
        if (now - lastRefill > 1000) { logBudget = CONFIG.rateLimitPerSecond; lastRefill = now; }
        if (logBudget > 0) { logBudget--; return true; }
        return false;
    }
    function flush(buf) { if (canLog()) console.log(buf.join("\n")); }

    // ==================== SO 解析 + Interceptor 安装 ====================
    var CRYPTO_SOS = ["libcrypto_kg.so", "libcrypto.so", "libssl_kg.so", "libssl.so"];
    function getCryptoExport(name) {
        for (var i = 0; i < CRYPTO_SOS.length; i++) {
            var mod = Process.findModuleByName(CRYPTO_SOS[i]);
            if (!mod) continue;
            var addr = mod.findExportByName(name);
            if (addr) return addr;
        }
        return null;
    }

    var installedAddrs = {};
    function safeAttach(addr, callbacks, label) {
        var success = 0;
        if (addr) {
            var key = addr.toString();
            if (!installedAddrs[key]) {
                try { Interceptor.attach(addr, callbacks); installedAddrs[key] = true; success++; }
                catch (e) { console.log("[SKIP] " + (label || addr) + " — " + e.message); }
            } else { success++; }
        }
        if (label) {
            Process.enumerateModules().forEach(function (mod) {
                if (CRYPTO_SOS.indexOf(mod.name) === -1) return;
                var a = mod.findExportByName(label);
                if (!a) return;
                var k = a.toString();
                if (installedAddrs[k]) return;
                try { Interceptor.attach(a, callbacks); installedAddrs[k] = true; success++; }
                catch (e) { console.log("[SKIP] " + label + "(" + mod.name + ") — " + e.message); }
            });
        }
        return success > 0;
    }

    // TLS 噪声过滤
    var TLS_NOISE_SOS = ["libssl.so", "libssl_kg.so"];
    var TLS_NOISE_SYMS = ["tls1_P_hash", "tls1_prf", "tls13_", "ssl3_", "SSLTranscript", "GetFinishedMAC", "HKDF_extract", "HKDF_expand", "HKDF_", "EVP_DigestFinal", "EVP_DigestSign"];
    function isTlsNoise(lr, keyLen) {
        if (!CONFIG.hideTlsNoise) return false;
        if (keyLen === 0) return true;
        if (!lr) return false;
        try {
            var mod = Process.findModuleByAddress(lr);
            if (mod && TLS_NOISE_SOS.indexOf(mod.name) !== -1) return true;
            var sym = DebugSymbol.fromAddress(lr);
            if (sym && sym.name) {
                for (var i = 0; i < TLS_NOISE_SYMS.length; i++) {
                    if (sym.name.indexOf(TLS_NOISE_SYMS[i]) !== -1) return true;
                }
            }
        } catch (e) {}
        return false;
    }

    // ==================== 状态 (跨 dlopen 重装) ====================
    var evpDigestInputs = {};
    var hmacCtxs = {};
    var md5CtxInputs = {};

    function getEvpCipherName(ctx) {
        try {
            var EVP_CIPHER_CTX_cipher = new NativeFunction(
                getCryptoExport("EVP_CIPHER_CTX_cipher") || getCryptoExport("EVP_CIPHER_CTX_get0_cipher"),
                "pointer", ["pointer"]);
            var cipherPtr = EVP_CIPHER_CTX_cipher(ctx);
            if (cipherPtr.isNull()) return "unknown";
            var EVP_CIPHER_nid = new NativeFunction(
                getCryptoExport("EVP_CIPHER_nid") || getCryptoExport("EVP_CIPHER_get_nid"),
                "int", ["pointer"]);
            var nid = EVP_CIPHER_nid(cipherPtr);
            var OBJ_nid2sn = new NativeFunction(getCryptoExport("OBJ_nid2sn"), "pointer", ["int"]);
            var namePtr = OBJ_nid2sn(nid);
            return namePtr.isNull() ? "nid:" + nid : namePtr.readUtf8String();
        } catch (e) { return "unknown"; }
    }

    // ==================== EVP 对称加密 ====================
    function installEvpCipher() {
        if (!CONFIG.hookEvpCipher) return;
        ["EVP_CipherInit_ex", "EVP_CipherInit", "EVP_EncryptInit_ex", "EVP_DecryptInit_ex", "EVP_EncryptInit", "EVP_DecryptInit"].forEach(function (funcName) {
            var addr = getCryptoExport(funcName);
            if (!addr) return;
            var isEncrypt = funcName.indexOf("Encrypt") !== -1;
            var mode = isEncrypt ? "ENCRYPT" : "DECRYPT";
            safeAttach(addr, {
                onEnter: function (args) {
                    this.ctx = args[0]; this.key = args[3]; this.iv = args[4];
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 1) return;
                    var algoName = getEvpCipherName(this.ctx);
                    var buf = [];
                    printHeader("Cipher", algoName + " · " + mode + " · init", C.hCipher, buf);
                    if (!this.key.isNull()) {
                        var keyLen = 16;
                        if (algoName.indexOf("256") !== -1) keyLen = 32;
                        else if (algoName.indexOf("192") !== -1) keyLen = 24;
                        printField("key", smartFormatPtr(this.key, keyLen), C.yellow, buf);
                    }
                    if (!this.iv.isNull()) printField("IV", dumpPtrHex(this.iv, 16), null, buf);
                    if (this.callerLr) { try { printField("caller", DebugSymbol.fromAddress(this.callerLr).toString(), null, buf); } catch (e) {} }
                    printStack(this.context, buf);
                    flush(buf);
                }
            }, funcName);
            if (U) U.ok(funcName);
            else console.log("[OK] " + funcName);
        });

        ["EVP_EncryptUpdate", "EVP_DecryptUpdate"].forEach(function (funcName) {
            var addr = getCryptoExport(funcName);
            if (!addr) return;
            var isEncrypt = funcName.indexOf("Encrypt") !== -1;
            safeAttach(addr, {
                onEnter: function (args) {
                    this.ctx = args[0]; this.outBuf = args[1]; this.outlPtr = args[2];
                    this.inBuf = args[3]; this.inLen = args[4].toInt32();
                    this.inSnapshot = null;
                    if (this.inLen > 0 && !this.inBuf.isNull()) {
                        try { this.inSnapshot = new Uint8Array(this.inBuf.readByteArray(Math.min(this.inLen, CONFIG.maxDataLength))); } catch (e) {}
                    }
                },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 1) return;
                    var outLen = this.outlPtr.readS32();
                    var algoName = getEvpCipherName(this.ctx);
                    var label = isEncrypt ? "Encrypt" : "Decrypt";
                    var buf = [];
                    printHeader("Cipher", algoName + " · " + label + "Update", C.hCipher, buf);
                    if (this.inSnapshot) printField("input", smartFormatBytes(this.inSnapshot, this.inLen), null, buf);
                    else printField("input", "(unreadable)", null, buf);
                    printField("output", smartFormatPtr(this.outBuf, outLen), C.green, buf);
                    flush(buf);
                }
            }, funcName);
            if (U) U.ok(funcName);
            else console.log("[OK] " + funcName);
        });

        ["EVP_EncryptFinal_ex", "EVP_DecryptFinal_ex", "EVP_EncryptFinal", "EVP_DecryptFinal"].forEach(function (funcName) {
            var addr = getCryptoExport(funcName);
            if (!addr) return;
            safeAttach(addr, {
                onEnter: function (args) { this.outBuf = args[1]; this.outlPtr = args[2]; },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 1) return;
                    var outLen = this.outlPtr.readS32();
                    if (outLen <= 0) return;
                    var buf = [];
                    printHeader("Cipher", "Final · " + outLen + " bytes", C.hCipher, buf);
                    printField("output", smartFormatPtr(this.outBuf, outLen), C.green, buf);
                    flush(buf);
                }
            }, funcName);
        });
    }

    // ==================== EVP Digest ====================
    function installEvpDigest() {
        if (!CONFIG.hookEvpDigest) return;
        var digestUpdate = getCryptoExport("EVP_DigestUpdate");
        if (digestUpdate) {
            safeAttach(digestUpdate, {
                onEnter: function (args) {
                    var len = args[2].toInt32();
                    if (len <= 0 || (CONFIG.skipHugeUpdates > 0 && len > CONFIG.skipHugeUpdates)) return;
                    var ctxKey = args[0].toString();
                    if (!evpDigestInputs[ctxKey]) evpDigestInputs[ctxKey] = [];
                    try { evpDigestInputs[ctxKey].push(smartFormatBytes(new Uint8Array(args[1].readByteArray(Math.min(len, CONFIG.maxDataLength))), len)); } catch (e) {}
                }
            }, "EVP_DigestUpdate");
            if (U) U.ok("EVP_DigestUpdate"); else console.log("[OK] EVP_DigestUpdate");
        }

        var digestFinal = getCryptoExport("EVP_DigestFinal_ex");
        if (digestFinal) {
            safeAttach(digestFinal, {
                onEnter: function (args) {
                    this.mdBuf = args[1]; this.sizePtr = args[2];
                    this.ctxKey = args[0].toString(); this.ctxPtr = args[0];
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 1) return;
                    if (isTlsNoise(this.callerLr, -1)) { delete evpDigestInputs[this.ctxKey]; return; }
                    var size = this.sizePtr.readU32();
                    var inputs = evpDigestInputs[this.ctxKey] || [];
                    var buf = [];
                    var algo = "Digest";
                    if (size === 16) algo = "MD5"; else if (size === 20) algo = "SHA-1";
                    else if (size === 32) algo = "SHA-256"; else if (size === 48) algo = "SHA-384";
                    else if (size === 64) algo = "SHA-512";
                    printHeader("Hash", algo + " (EVP) · " + inputs.length + " updates", C.hHash, buf);
                    if (inputs.length === 0) printField("ctx", this.ctxPtr.toString(), C.gray, buf);
                    else printMultiInput("input", inputs, buf);
                    printField("digest", dumpPtrHex(this.mdBuf, size), C.green, buf);
                    if (this.callerLr) { try { printField("caller", DebugSymbol.fromAddress(this.callerLr).toString(), null, buf); } catch (e) {} }
                    flush(buf);
                    delete evpDigestInputs[this.ctxKey];
                }
            }, "EVP_DigestFinal_ex");
            if (U) U.ok("EVP_DigestFinal_ex"); else console.log("[OK] EVP_DigestFinal_ex");
        }

        var evpDigest = getCryptoExport("EVP_Digest");
        if (evpDigest) {
            safeAttach(evpDigest, {
                onEnter: function (args) {
                    this.dataPtr = args[0]; this.dataLen = args[1].toInt32();
                    this.mdBuf = args[2]; this.sizePtr = args[3];
                    this.inSnapshot = null;
                    if (this.dataLen > 0 && !this.dataPtr.isNull()) {
                        try { this.inSnapshot = new Uint8Array(this.dataPtr.readByteArray(Math.min(this.dataLen, CONFIG.maxDataLength))); } catch (e) {}
                    }
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function (retval) {
                    if (retval.toInt32() !== 1) return;
                    var size = 32; try { size = this.sizePtr.readU32(); } catch (e) {}
                    var algo = "Digest";
                    if (size === 16) algo = "MD5"; else if (size === 20) algo = "SHA-1";
                    else if (size === 32) algo = "SHA-256"; else if (size === 48) algo = "SHA-384";
                    else if (size === 64) algo = "SHA-512";
                    var buf = [];
                    printHeader("Hash", algo + " (EVP oneshot) · " + this.dataLen + "B", C.hHash, buf);
                    if (this.inSnapshot) printField("input", smartFormatBytes(this.inSnapshot, this.dataLen), null, buf);
                    else printField("input", "(unreadable)", null, buf);
                    printField("digest", dumpPtrHex(this.mdBuf, size), C.green, buf);
                    if (this.callerLr) { try { printField("caller", DebugSymbol.fromAddress(this.callerLr).toString(), null, buf); } catch (e) {} }
                    flush(buf);
                }
            }, "EVP_Digest");
            if (U) U.ok("EVP_Digest (oneshot)"); else console.log("[OK] EVP_Digest (oneshot)");
        }
    }

    // ==================== HMAC ====================
    function installHmac() {
        if (!CONFIG.hookHmac) return;
        var hmacAddr = getCryptoExport("HMAC");
        if (hmacAddr) {
            safeAttach(hmacAddr, {
                onEnter: function (args) {
                    this.keyPtr = args[1]; this.keyLen = args[2].toInt32();
                    this.dataPtr = args[3]; this.dataLen = args[4].toInt32();
                    this.mdLenPtr = args[6];
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function (retval) {
                    if (retval.isNull()) return;
                    if (isTlsNoise(this.callerLr, this.keyLen)) return;
                    var mdLen = 32; try { mdLen = this.mdLenPtr.readU32(); } catch (e) {}
                    var buf = [];
                    printHeader("HMAC", "Native · oneshot", C.hHmac, buf);
                    printField("key", smartFormatPtr(this.keyPtr, this.keyLen), C.yellow, buf);
                    printField("data", smartFormatPtr(this.dataPtr, this.dataLen), null, buf);
                    printField("signature", dumpPtrHex(retval, mdLen), C.green, buf);
                    printStack(this.context, buf);
                    flush(buf);
                }
            }, "HMAC");
            if (U) U.ok("HMAC"); else console.log("[OK] HMAC");
        }

        var hmacInit = getCryptoExport("HMAC_Init_ex");
        if (hmacInit) {
            safeAttach(hmacInit, {
                onEnter: function (args) {
                    var ctxKey = args[0].toString();
                    var keyPtr = args[1]; var keyLen = args[2].toInt32();
                    hmacCtxs[ctxKey] = { key: keyLen > 0 ? smartFormatPtr(keyPtr, keyLen) : ["(empty)"], inputs: [], isNoise: isTlsNoise(this.context.lr, keyLen) };
                }
            }, "HMAC_Init_ex");
            if (U) U.ok("HMAC_Init_ex"); else console.log("[OK] HMAC_Init_ex");
        }

        var hmacUpdate = getCryptoExport("HMAC_Update");
        if (hmacUpdate) {
            safeAttach(hmacUpdate, {
                onEnter: function (args) {
                    var len = args[2].toInt32();
                    if (len <= 0 || (CONFIG.skipHugeUpdates > 0 && len > CONFIG.skipHugeUpdates)) return;
                    var ctxKey = args[0].toString();
                    if (!hmacCtxs[ctxKey]) hmacCtxs[ctxKey] = { key: ["(no Init caught)"], inputs: [], isNoise: false };
                    if (hmacCtxs[ctxKey].isNoise) return;
                    try { hmacCtxs[ctxKey].inputs.push(smartFormatBytes(new Uint8Array(args[1].readByteArray(Math.min(len, CONFIG.maxDataLength))), len)); } catch (e) {}
                }
            }, "HMAC_Update");
            if (U) U.ok("HMAC_Update"); else console.log("[OK] HMAC_Update");
        }

        var hmacFinal = getCryptoExport("HMAC_Final");
        if (hmacFinal) {
            safeAttach(hmacFinal, {
                onEnter: function (args) {
                    this.ctxKey = args[0].toString(); this.mdPtr = args[1]; this.mdLenPtr = args[2];
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function () {
                    var ctx = hmacCtxs[this.ctxKey];
                    var fromFallback = false;
                    if (!ctx) { ctx = { key: ["(no Init caught)"], inputs: [], isNoise: false }; fromFallback = true; }
                    if (ctx.isNoise) { delete hmacCtxs[this.ctxKey]; return; }
                    if (fromFallback && isTlsNoise(this.callerLr, -1)) { delete hmacCtxs[this.ctxKey]; return; }
                    var mdLen = 32; try { mdLen = this.mdLenPtr.readU32(); } catch (e) {}
                    var buf = [];
                    printHeader("HMAC", "Native · " + ctx.inputs.length + " updates", C.hHmac, buf);
                    printField("key", ctx.key, C.yellow, buf);
                    if (ctx.inputs.length > 0) printMultiInput("data", ctx.inputs, buf);
                    printField("signature", dumpPtrHex(this.mdPtr, mdLen), C.green, buf);
                    if (this.callerLr) { try { printField("caller", DebugSymbol.fromAddress(this.callerLr).toString(), null, buf); } catch (e) {} }
                    flush(buf);
                    delete hmacCtxs[this.ctxKey];
                }
            }, "HMAC_Final");
            if (U) U.ok("HMAC_Final"); else console.log("[OK] HMAC_Final");
        }
    }

    // ==================== AES 低级 API ====================
    function installAesLowLevel() {
        if (!CONFIG.hookAesLowLevel) return;
        var aesSetKey = getCryptoExport("AES_set_encrypt_key");
        if (aesSetKey) {
            safeAttach(aesSetKey, {
                onEnter: function (args) {
                    var keyPtr = args[0]; var bits = args[1].toInt32(); var keyLen = bits / 8;
                    var keyBytes = null;
                    try { keyBytes = new Uint8Array(keyPtr.readByteArray(keyLen)); } catch (e) {}
                    if (CONFIG.hideTestVectors && keyBytes) {
                        var tag = isTestVectorBytes(keyBytes);
                        if (tag) { console.log(tint(C.dim, "  [filter] AES set_encrypt_key · " + bits + " bits · " + tag + " (skipped)")); return; }
                    }
                    var buf = [];
                    printHeader("Cipher", "AES set_encrypt_key · " + bits + " bits", C.hCipher, buf);
                    printField("key", smartFormatBytes(keyBytes, keyLen), C.yellow, buf);
                    try { var lr = this.context.lr; if (lr) printField("caller", DebugSymbol.fromAddress(lr).toString(), null, buf); } catch (e) {}
                    printStack(this.context, buf);
                    flush(buf);
                }
            }, "AES_set_encrypt_key");
            if (U) U.ok("AES_set_encrypt_key"); else console.log("[OK] AES_set_encrypt_key");
        }

        var aesSetDecKey = getCryptoExport("AES_set_decrypt_key");
        if (aesSetDecKey) {
            safeAttach(aesSetDecKey, {
                onEnter: function (args) {
                    var keyPtr = args[0]; var bits = args[1].toInt32(); var keyLen = bits / 8;
                    var keyBytes = null;
                    try { keyBytes = new Uint8Array(keyPtr.readByteArray(keyLen)); } catch (e) {}
                    if (CONFIG.hideTestVectors && keyBytes) {
                        var tag = isTestVectorBytes(keyBytes);
                        if (tag) { console.log(tint(C.dim, "  [filter] AES set_decrypt_key · " + bits + " bits · " + tag + " (skipped)")); return; }
                    }
                    var buf = [];
                    printHeader("Cipher", "AES set_decrypt_key · " + bits + " bits", C.hCipher, buf);
                    printField("key", smartFormatBytes(keyBytes, keyLen), C.yellow, buf);
                    flush(buf);
                }
            }, "AES_set_decrypt_key");
            if (U) U.ok("AES_set_decrypt_key"); else console.log("[OK] AES_set_decrypt_key");
        }

        var aesCbc = getCryptoExport("AES_cbc_encrypt");
        if (aesCbc) {
            safeAttach(aesCbc, {
                onEnter: function (args) {
                    this.inPtr = args[0]; this.outPtr = args[1]; this.length = args[2].toInt32();
                    try { this.ivHex = dumpPtrHex(args[4], 16); } catch (e) { this.ivHex = "(read failed)"; }
                    this.enc = args[5].toInt32();
                    this.inSnapshot = null;
                    if (this.length > 0 && !this.inPtr.isNull()) {
                        try { this.inSnapshot = new Uint8Array(this.inPtr.readByteArray(Math.min(this.length, CONFIG.maxDataLength))); } catch (e) {}
                    }
                },
                onLeave: function () {
                    var mode = this.enc === 1 ? "ENCRYPT" : "DECRYPT";
                    var buf = [];
                    printHeader("Cipher", "AES_cbc_encrypt · " + mode + " · " + this.length + " bytes", C.hCipher, buf);
                    printField("IV", this.ivHex, null, buf);
                    if (this.inSnapshot) printField("input", smartFormatBytes(this.inSnapshot, this.length), null, buf);
                    else printField("input", "(unreadable)", null, buf);
                    printField("output", smartFormatPtr(this.outPtr, this.length), C.green, buf);
                    flush(buf);
                }
            }, "AES_cbc_encrypt");
            if (U) U.ok("AES_cbc_encrypt"); else console.log("[OK] AES_cbc_encrypt");
        }
    }

    // ==================== RSA 低级 API ====================
    function installRsaLowLevel() {
        if (!CONFIG.hookRsaLowLevel) return;
        function readBigNumHex(bnPtr) {
            try {
                var dPtr = bnPtr.readPointer(); var top = bnPtr.add(Process.pointerSize).readU32();
                if (top <= 0 || top > 128) return null;
                var le = new Uint8Array(dPtr.readByteArray(top * Process.pointerSize));
                var hex = [];
                for (var i = le.length - 1; i >= 0; i--) { var b = le[i].toString(16); hex.push(b.length === 1 ? "0" + b : b); }
                return hex.join("");
            } catch (e) { return null; }
        }

        var rsaEnc = getCryptoExport("RSA_public_encrypt");
        if (rsaEnc) {
            safeAttach(rsaEnc, {
                onEnter: function (args) {
                    this.flen = args[0].toInt32(); this.from = args[1]; this.to = args[2]; this.padding = args[4].toInt32();
                },
                onLeave: function (retval) {
                    var outLen = retval.toInt32();
                    var padMap = { 1: "PKCS1", 3: "NoPadding", 4: "OAEP" };
                    var buf = [];
                    printHeader("Signature", "RSA_public_encrypt · " + (padMap[this.padding] || this.padding), C.hSignature, buf);
                    printField("plaintext", smartFormatPtr(this.from, this.flen), null, buf);
                    if (outLen > 0) printField("ciphertext", dumpPtrHex(this.to, outLen), C.green, buf);
                    printStack(this.context, buf);
                    flush(buf);
                }
            }, "RSA_public_encrypt");
            if (U) U.ok("RSA_public_encrypt"); else console.log("[OK] RSA_public_encrypt");
        }

        var modExp = getCryptoExport("BN_mod_exp_mont");
        if (modExp) {
            safeAttach(modExp, {
                onEnter: function (args) {
                    this.r = args[0]; this.a = args[1]; this.p = args[2]; this.m = args[3];
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function (retval) {
                    var n = readBigNumHex(this.m);
                    if (!n) return;
                    var bits = n.length * 4;
                    if (bits < 512) return;
                    var e = readBigNumHex(this.p);
                    var a = readBigNumHex(this.a);
                    var r = readBigNumHex(this.r);
                    var buf = [];
                    printHeader("Signature", "BN_mod_exp_mont · " + bits + "-bit · r = a^p mod m", C.hSignature, buf);
                    printField("modulus m", "0x" + n, null, buf);
                    if (e) {
                        if (e.length <= 16) printField("exponent p", "0x" + e + "  (public exponent, usually 0x10001)", null, buf);
                        else printField("exponent p", "0x" + e.substring(0, 64) + "…  (private exponent, " + (e.length * 4) + " bit)", null, buf);
                    }
                    if (a) printField("input a", "0x" + a, null, buf);
                    if (r) printField("output r", "0x" + r, C.green, buf);
                    if (this.callerLr) { try { printField("caller", DebugSymbol.fromAddress(this.callerLr).toString(), null, buf); } catch (e) {} }
                    flush(buf);
                }
            }, "BN_mod_exp_mont");
            if (U) U.ok("BN_mod_exp_mont"); else console.log("[OK] BN_mod_exp_mont");
        }
    }

    // ==================== MD5 低级 API ====================
    function installMd5LowLevel() {
        if (!CONFIG.hookMd5LowLevel) return;
        var md5Update = getCryptoExport("MD5_Update");
        var md5Final = getCryptoExport("MD5_Final");
        if (md5Update && md5Final) {
            safeAttach(md5Update, {
                onEnter: function (args) {
                    var len = args[2].toInt32();
                    if (len <= 0 || (CONFIG.skipHugeUpdates > 0 && len > CONFIG.skipHugeUpdates)) return;
                    var ctxKey = args[0].toString();
                    if (!md5CtxInputs[ctxKey]) md5CtxInputs[ctxKey] = [];
                    try { md5CtxInputs[ctxKey].push(smartFormatBytes(new Uint8Array(args[1].readByteArray(Math.min(len, CONFIG.maxDataLength))), len)); } catch (e) {}
                }
            }, "MD5_Update");
            safeAttach(md5Final, {
                onEnter: function (args) {
                    this.outPtr = args[0]; this.ctxKey = args[1].toString(); this.ctxPtr = args[1];
                    try { this.callerLr = this.context.lr; } catch (e) { this.callerLr = null; }
                },
                onLeave: function () {
                    if (isTlsNoise(this.callerLr, -1)) { delete md5CtxInputs[this.ctxKey]; return; }
                    var chunks = md5CtxInputs[this.ctxKey] || [];
                    var buf = [];
                    printHeader("Hash", "MD5 · " + chunks.length + " updates", C.hHash, buf);
                    if (chunks.length === 0) printField("ctx", this.ctxPtr.toString(), C.gray, buf);
                    else printMultiInput("input", chunks, buf);
                    printField("digest", dumpPtrHex(this.outPtr, 16), C.green, buf);
                    if (this.callerLr) { try { printField("caller", DebugSymbol.fromAddress(this.callerLr).toString(), null, buf); } catch (e) {} }
                    flush(buf);
                    delete md5CtxInputs[this.ctxKey];
                }
            }, "MD5_Final");
            if (U) U.ok("MD5_Update + MD5_Final"); else console.log("[OK] MD5_Update + MD5_Final");
        }

        var md5Oneshot = getCryptoExport("MD5");
        if (md5Oneshot) {
            safeAttach(md5Oneshot, {
                onEnter: function (args) {
                    this.dataPtr = args[0]; this.dataLen = args[1].toInt32(); this.outPtr = args[2];
                    this.inSnapshot = null;
                    if (this.dataLen > 0 && !this.dataPtr.isNull()) {
                        try { this.inSnapshot = new Uint8Array(this.dataPtr.readByteArray(Math.min(this.dataLen, CONFIG.maxDataLength))); } catch (e) {}
                    }
                },
                onLeave: function () {
                    var buf = [];
                    printHeader("Hash", "MD5 · oneshot · " + this.dataLen + "B", C.hHash, buf);
                    if (this.inSnapshot) printField("input", smartFormatBytes(this.inSnapshot, this.dataLen), null, buf);
                    else printField("input", "(unreadable)", null, buf);
                    printField("digest", dumpPtrHex(this.outPtr, 16), C.green, buf);
                    try { var lr = this.context.lr; if (lr) printField("caller", DebugSymbol.fromAddress(lr).toString(), null, buf); } catch (e) {}
                    flush(buf);
                }
            }, "MD5");
            if (U) U.ok("MD5 (oneshot)"); else console.log("[OK] MD5 (oneshot)");
        }
    }

    // ==================== Base64 (BoringSSL 单步) ====================
    function installBase64() {
        if (!CONFIG.hookBase64) return;
        var encBlock = getCryptoExport("EVP_EncodeBlock");
        if (encBlock) {
            safeAttach(encBlock, {
                onEnter: function (args) {
                    this.dst = args[0]; this.src = args[1]; this.srclen = args[2].toInt32();
                    this.inSnapshot = null;
                    if (this.srclen > 0 && !this.src.isNull()) {
                        try { this.inSnapshot = new Uint8Array(this.src.readByteArray(Math.min(this.srclen, CONFIG.maxDataLength))); } catch (e) {}
                    }
                },
                onLeave: function (retval) {
                    var outLen = retval.toInt32();
                    if (outLen <= 0) return;
                    var buf = [];
                    printHeader("Base64", "EVP_EncodeBlock · " + this.srclen + "B → " + outLen + "B", C.hKeyGen, buf);
                    if (this.inSnapshot) printField("input", smartFormatBytes(this.inSnapshot, this.srclen), null, buf);
                    else printField("input", "(unreadable)", null, buf);
                    printField("output", smartFormatPtr(this.dst, outLen), C.green, buf);
                    try { var lr = this.context.lr; if (lr) printField("caller", DebugSymbol.fromAddress(lr).toString(), null, buf); } catch (e) {}
                    flush(buf);
                }
            }, "EVP_EncodeBlock");
            if (U) U.ok("EVP_EncodeBlock"); else console.log("[OK] EVP_EncodeBlock");
        }

        var decBlock = getCryptoExport("EVP_DecodeBlock");
        if (decBlock) {
            safeAttach(decBlock, {
                onEnter: function (args) {
                    this.dst = args[0]; this.src = args[1]; this.srclen = args[2].toInt32();
                    this.inSnapshot = null;
                    if (this.srclen > 0 && !this.src.isNull()) {
                        try { this.inSnapshot = new Uint8Array(this.src.readByteArray(Math.min(this.srclen, CONFIG.maxDataLength))); } catch (e) {}
                    }
                },
                onLeave: function (retval) {
                    var outLen = retval.toInt32();
                    if (outLen <= 0) return;
                    var buf = [];
                    printHeader("Base64", "EVP_DecodeBlock · " + this.srclen + "B → " + outLen + "B", C.hKeyGen, buf);
                    if (this.inSnapshot) printField("input", smartFormatBytes(this.inSnapshot, this.srclen), null, buf);
                    else printField("input", "(unreadable)", null, buf);
                    printField("output", smartFormatPtr(this.dst, outLen), C.green, buf);
                    try { var lr = this.context.lr; if (lr) printField("caller", DebugSymbol.fromAddress(lr).toString(), null, buf); } catch (e) {}
                    flush(buf);
                }
            }, "EVP_DecodeBlock");
            if (U) U.ok("EVP_DecodeBlock"); else console.log("[OK] EVP_DecodeBlock");
        }
    }

    // ==================== Spawn 兼容: dlopen 触发延迟装钩 ====================
    function installAllHooks() {
        installEvpCipher();
        installEvpDigest();
        installHmac();
        installAesLowLevel();
        installRsaLowLevel();
        installMd5LowLevel();
        installBase64();
    }

    (function setupDlopenTrigger() {
        var libdl = Process.findModuleByName("libdl.so");
        if (!libdl) return;
        var dlopen = libdl.findExportByName("android_dlopen_ext") || libdl.findExportByName("dlopen");
        if (!dlopen) return;
        Interceptor.attach(dlopen, {
            onEnter: function (args) {
                try {
                    var path = args[0].readCString();
                    if (!path) return;
                    var soName = path.split("/").pop();
                    this.shouldReinstall = (CRYPTO_SOS.indexOf(soName) !== -1);
                } catch (e) {}
            },
            onLeave: function () { if (this.shouldReinstall) installAllHooks(); }
        });
    })();

    installAllHooks();

    // ==================== Banner ====================
    console.log("");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("  native_crypto_monitor.js  v2.0");
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("  EVP Cipher | EVP Digest | HMAC | AES | RSA | MD5 | Base64");
    console.log("  Rate: " + CONFIG.rateLimitPerSecond + " ops/s  |  Stack: " + (CONFIG.showBacktrace ? "ON" : "OFF"));
    console.log("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    console.log("");

    if (U) U.info("native_crypto_monitor.js ready");
})(this);