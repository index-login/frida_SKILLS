/**
 * crypto_monitor.js - Java 层加解密自吐模块
 * 用途：监控 Java 层所有加解密操作，自动吐出算法、密钥、明文、密文
 * 覆盖：javax.crypto.Cipher / java.security.MessageDigest / javax.crypto.Mac
 *       + 密钥材料 (SecretKeySpec / IvParameterSpec / X509EncodedKeySpec / DESKeySpec / PBEKeySpec)
 * 适用：Android 应用（需要 Java.available）
 * 加载方式：frida -U -f com.app -l utils.js -l crypto_monitor.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] crypto_monitor requires utils.js (load it first)"); return; }

    var CONFIG = U.mergeConfig('crypto_monitor', {
        // Cipher (对称加密/解密)
        hookCipher: true,
        // MessageDigest (哈希)
        hookMessageDigest: true,
        // Mac (HMAC)
        hookMac: true,
        // 密钥材料
        hookKeyMaterial: true,
        // 打印 Java 调用栈（定位代码路径）
        showStack: true,
        // 输出格式：hex / base64 / utf8
        showHex: true,
        showBase64: true,
        showUtf8: true,
    });

    function formatBytes(bytes, label) {
        var parts = [];
        if (CONFIG.showHex && bytes)   parts.push(label + "_hex: " + U.bytesToHex(bytes));
        if (CONFIG.showBase64 && bytes) parts.push(label + "_base64: " + U.bytesToBase64(bytes));
        if (CONFIG.showUtf8 && bytes)  parts.push(label + "_utf8: " + U.utf8ToStr(bytes));
        parts.forEach(function (p) { U.timeLog(p); });
    }

    function logStackIfNeeded() {
        if (CONFIG.showStack) U.javaStack();
    }

    var BANNER_S = "========== [Crypto] START ==========";
    var BANNER_E = "========== [Crypto] END   ==========";

    if (!Java.available) {
        U.info("crypto_monitor requires Java (Android only)");
        return;
    }

    Java.perform(function () {

        // ==========================================
        // 1. 密钥材料捕获
        // ==========================================
        if (CONFIG.hookKeyMaterial) {
            try {
                var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
                SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function (key, algo) {
                    U.info(BANNER_S);
                    U.ok("[SecretKeySpec] algo=" + algo);
                    formatBytes(key, "key");
                    U.info(BANNER_E);
                    return this.$init(key, algo);
                };
                SecretKeySpec.$init.overload('[B', 'int', 'int', 'java.lang.String').implementation = function (key, off, len, algo) {
                    U.info(BANNER_S);
                    U.ok("[SecretKeySpec] algo=" + algo + " off=" + off + " len=" + len);
                    formatBytes(key, "key");
                    U.info(BANNER_E);
                    return this.$init(key, off, len, algo);
                };
            } catch (e) { U.fail("SecretKeySpec hook failed: " + e.message); }

            try {
                var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
                IvParameterSpec.$init.overload('[B').implementation = function (iv) {
                    U.info(BANNER_S);
                    U.ok("[IvParameterSpec] IV (hex): " + U.bytesToHex(iv));
                    U.info(BANNER_E);
                    return this.$init(iv);
                };
            } catch (e) { U.fail("IvParameterSpec hook failed: " + e.message); }

            try {
                var DESKeySpec = Java.use('javax.crypto.spec.DESKeySpec');
                DESKeySpec.$init.overload('[B').implementation = function (key) {
                    U.info(BANNER_S);
                    U.ok("[DESKeySpec]");
                    formatBytes(key, "DES_key");
                    U.info(BANNER_E);
                    return this.$init(key);
                };
            } catch (e) { U.fail("DESKeySpec hook failed: " + e.message); }

            try {
                var X509KS = Java.use('java.security.spec.X509EncodedKeySpec');
                X509KS.$init.overload('[B').implementation = function (key) {
                    U.info(BANNER_S);
                    U.ok("[X509EncodedKeySpec] RSA public key");
                    formatBytes(key, "RSA_pub");
                    U.info(BANNER_E);
                    return this.$init(key);
                };
            } catch (e) { U.fail("X509EncodedKeySpec hook failed: " + e.message); }

            try {
                var RSAPubKS = Java.use('java.security.spec.RSAPublicKeySpec');
                RSAPubKS.$init.overload('java.math.BigInteger', 'java.math.BigInteger').implementation = function (n, e) {
                    U.info(BANNER_S);
                    U.ok("[RSAPublicKeySpec] N(modulus): " + n.toString(16));
                    U.ok("[RSAPublicKeySpec] E(exponent): " + e.toString(16));
                    U.info(BANNER_E);
                    return this.$init(n, e);
                };
            } catch (e) { U.fail("RSAPublicKeySpec hook failed: " + e.message); }

            try {
                var PBEKeySpec = Java.use('javax.crypto.spec.PBEKeySpec');
                PBEKeySpec.$init.overload('[C', '[B', 'int', 'int').implementation = function (pwd, salt, iter, keyLen) {
                    U.info(BANNER_S);
                    U.ok("[PBEKeySpec] password=" + pwd + " iterations=" + iter + " keyLen=" + keyLen);
                    if (salt) formatBytes(salt, "salt");
                    U.info(BANNER_E);
                    return this.$init(pwd, salt, iter, keyLen);
                };
            } catch (e) { U.fail("PBEKeySpec hook failed: " + e.message); }

            try {
                var KeyFactory = Java.use('java.security.KeyFactory');
                KeyFactory.getInstance.overload('java.lang.String').implementation = function (algo) {
                    U.info("[KeyFactory] algo=" + algo);
                    return this.getInstance(algo);
                };
            } catch (e) { U.fail("KeyFactory hook failed: " + e.message); }
        }

        // ==========================================
        // 2. javax.crypto.Cipher (对称/非对称加解密)
        // ==========================================
        if (CONFIG.hookCipher) {
            try {
                var Cipher = Java.use('javax.crypto.Cipher');

                // getInstance
                Cipher.getInstance.overload('java.lang.String').implementation = function (algo) {
                    U.info("[Cipher.getInstance] algo=" + algo);
                    return this.getInstance(algo);
                };
                Cipher.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (algo, prov) {
                    U.info("[Cipher.getInstance] algo=" + algo + " provider=" + prov);
                    return this.getInstance(algo, prov);
                };

                // init
                Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
                    U.info(BANNER_S);
                    U.ok("[Cipher.init] mode=" + (mode === 1 ? "ENCRYPT" : "DECRYPT"));
                    return this.init(mode, key);
                };
                Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {
                    U.info(BANNER_S);
                    U.ok("[Cipher.init] mode=" + (mode === 1 ? "ENCRYPT" : "DECRYPT"));
                    return this.init(mode, key, params);
                };

                // update — 分块输入
                Cipher.update.overload('[B').implementation = function (input) {
                    U.ok("[Cipher.update] input_utf8: " + U.utf8ToStr(input));
                    return this.update(input);
                };

                // doFinal — 最终结果
                Cipher.doFinal.overload().implementation = function () {
                    var result = this.doFinal();
                    formatBytes(result, "result");
                    logStackIfNeeded();
                    U.info(BANNER_E);
                    return result;
                };

                Cipher.doFinal.overload('[B').implementation = function (input) {
                    U.ok("[Cipher.doFinal([B])]");
                    formatBytes(input, "input");
                    var result = this.doFinal(input);
                    formatBytes(result, "result");
                    logStackIfNeeded();
                    U.info(BANNER_E);
                    return result;
                };

                Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, off, len) {
                    U.ok("[Cipher.doFinal([B,int,int])] off=" + off + " len=" + len);
                    formatBytes(input, "input");
                    var result = this.doFinal(input, off, len);
                    formatBytes(result, "result");
                    logStackIfNeeded();
                    U.info(BANNER_E);
                    return result;
                };

                // Cipher.update 多参数版本
                try {
                    Cipher.update.overload('[B', 'int', 'int', '[B').implementation = function (input, off, len, output) {
                        U.ok("[Cipher.update([B,int,int,[B])] off=" + off + " len=" + len);
                        formatBytes(input, "input");
                        var result = this.update(input, off, len, output);
                        if (output) formatBytes(output, "output");
                        return result;
                    };
                } catch (e) { /* overload may not exist */ }

                try {
                    Cipher.update.overload('[B', 'int', 'int', '[B', 'int').implementation = function (input, off, len, output, outOff) {
                        U.ok("[Cipher.update([B,int,int,[B,int])] off=" + off + " len=" + len);
                        formatBytes(input, "input");
                        var result = this.update(input, off, len, output, outOff);
                        if (output) formatBytes(output, "output");
                        return result;
                    };
                } catch (e) { /* overload may not exist */ }

                U.ok("Cipher hooks active");
            } catch (e) { U.fail("Cipher hooks failed: " + e.message); }
        }

        // ==========================================
        // 3. java.security.MessageDigest (哈希)
        // ==========================================
        if (CONFIG.hookMessageDigest) {
            try {
                var Digest = Java.use('java.security.MessageDigest');

                Digest.getInstance.overload('java.lang.String').implementation = function (algo) {
                    U.info("[MessageDigest.getInstance] algo=" + algo);
                    return this.getInstance(algo);
                };
                Digest.getInstance.overload('java.lang.String', 'java.lang.String').implementation = function (algo, prov) {
                    U.info("[MessageDigest.getInstance] algo=" + algo + " provider=" + prov);
                    return this.getInstance(algo, prov);
                };

                Digest.update.overload('[B').implementation = function (input) {
                    U.info(BANNER_S);
                    U.ok("[MessageDigest.update]");
                    formatBytes(input, "input");
                    return this.update(input);
                };

                Digest.digest.overload().implementation = function () {
                    var result = this.digest();
                    formatBytes(result, "hash");
                    logStackIfNeeded();
                    U.info(BANNER_E);
                    return result;
                };

                U.ok("MessageDigest hooks active");
            } catch (e) { U.fail("MessageDigest hooks failed: " + e.message); }
        }

        // ==========================================
        // 4. javax.crypto.Mac (HMAC)
        // ==========================================
        if (CONFIG.hookMac) {
            try {
                var Mac = Java.use('javax.crypto.Mac');

                Mac.getInstance.overload('java.lang.String').implementation = function (algo) {
                    U.info("[Mac.getInstance] algo=" + algo);
                    return this.getInstance(algo);
                };

                Mac.update.overload('[B').implementation = function (input) {
                    U.info(BANNER_S);
                    U.ok("[Mac.update]");
                    formatBytes(input, "input");
                    return this.update(input);
                };

                Mac.update.overload('[B', 'int', 'int').implementation = function (input, off, len) {
                    U.info(BANNER_S);
                    U.ok("[Mac.update([B,int,int])] off=" + off + " len=" + len);
                    formatBytes(input, "input");
                    return this.update(input, off, len);
                };

                Mac.doFinal.overload().implementation = function () {
                    var result = this.doFinal();
                    formatBytes(result, "hmac");
                    logStackIfNeeded();
                    U.info(BANNER_E);
                    return result;
                };

                Mac.doFinal.overload('[B').implementation = function (input) {
                    U.ok("[Mac.doFinal([B])]");
                    formatBytes(input, "input");
                    var result = this.doFinal(input);
                    formatBytes(result, "hmac");
                    logStackIfNeeded();
                    U.info(BANNER_E);
                    return result;
                };

                U.ok("Mac hooks active");
            } catch (e) { U.fail("Mac hooks failed: " + e.message); }
        }

    });

    U.info("crypto_monitor.js ready (cipher=" + CONFIG.hookCipher +
           " digest=" + CONFIG.hookMessageDigest + " mac=" + CONFIG.hookMac +
           " keys=" + CONFIG.hookKeyMaterial + ")");
    console.log("");
})(this);
