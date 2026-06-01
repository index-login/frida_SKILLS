/**
 * ssl_plaintext.js - SSL/HTTP 明文捕获模块
 * 用途：在数据进入 TLS/SSL 加密前拦截 HTTP 层的明文请求和响应
 * 覆盖：OkHttp3 (Request/Response body) + HttpsURLConnection (I/O stream)
 *       + Retrofit2 (Converter) + java.net.HttpURLConnection (非 HTTPS 明文)
 * 加载方式：frida -U -f com.app -l utils.js -l ssl_plaintext.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] ssl_plaintext requires utils.js (load it first)");
        return;
    }

    var CONFIG = {
        hookOkHttp: true,
        hookHttpsURLConnection: true,
        hookRetrofit: true,
        hookHttpURLConnection: false,
        showHeaders: true,
        showBody: true,
        bodyMaxLen: 1024,
        showResponse: true,
        responseMaxLen: 1024,
        showStack: false,
        urlFilter: [],
    };

    if (typeof CONFIG_OVERRIDE !== 'undefined' && CONFIG_OVERRIDE['ssl_plaintext']) {
        var over = CONFIG_OVERRIDE['ssl_plaintext'];
        for (var k in over) { if (over.hasOwnProperty(k)) { CONFIG[k] = over[k]; } }
    }

    if (!Java.available) {
        U.info("ssl_plaintext requires Java (Android only)");
        return;
    }

    function urlMatches(url) {
        if (!url) return true;
        if (CONFIG.urlFilter.length === 0) return true;
        for (var i = 0; i < CONFIG.urlFilter.length; i++) {
            if (url.indexOf(CONFIG.urlFilter[i]) !== -1) return true;
        }
        return false;
    }

    function logBody(label, url, bytesArray) {
        if (!CONFIG.showBody) return;
        var len = bytesArray ? bytesArray.length : 0;
        if (len === 0) return;
        U.info("===== [SSL Plaintext] " + label + " =====");
        U.timeLog(url || "?");
        try {
            var str = U.utf8ToStr(bytesArray);
            var max = CONFIG.bodyMaxLen;
            if (label.indexOf("Resp") !== -1) max = CONFIG.responseMaxLen;
            if (str.length > max) str = str.substring(0, max) + "...(truncated, total " + len + " bytes)";
            console.log(str);
        } catch (e) {
            console.log("[binary " + len + " bytes] " + U.bytesToHex(bytesArray).substring(0, Math.min(len, 64) * 2));
        }
        U.info("===== [SSL Plaintext] END =====");
    }

    function logStack() {
        if (CONFIG.showStack) U.javaStack();
    }

    var BODY_BANNER = "===== [SSL Plaintext]";
    var BODY_END = "===== [SSL Plaintext] END";

    // ========== OkHttp3 ==========
    function hookOkHttp() {
        Java.perform(function () {
            // ---- Request Body ----
            try {
                var RequestBody = Java.use("okhttp3.RequestBody");
                // create(MediaType, String)
                try {
                    RequestBody.create.overload('okhttp3.MediaType', 'java.lang.String').implementation = function (type, content) {
                        U.info(BODY_BANNER + " Request ==");
                        U.timeLog("OkHttp RequestBody.create String, content-type: " + (type ? type.toString() : "null"));
                        if (CONFIG.showBody && content) {
                            console.log(content.toString());
                        }
                        logStack();
                        U.info(BODY_END);
                        return this.create(type, content);
                    };
                } catch (e) {}

                // create(MediaType, byte[])
                try {
                    RequestBody.create.overload('okhttp3.MediaType', '[B').implementation = function (type, content) {
                        U.info(BODY_BANNER + " Request ==");
                        U.timeLog("OkHttp RequestBody.create byte[], content-type: " + (type ? type.toString() : "null"));
                        logBody("Request Body", "OkHttp", content);
                        logStack();
                        U.info(BODY_END);
                        return this.create(type, content);
                    };
                } catch (e) {}

                // create(MediaType, byte[], int, int)
                try {
                    RequestBody.create.overload('okhttp3.MediaType', '[B', 'int', 'int').implementation = function (type, content, off, len) {
                        U.info(BODY_BANNER + " Request ==");
                        U.timeLog("OkHttp RequestBody.create byte[" + off + ":" + (off + len) + "], content-type: " + (type ? type.toString() : "null"));
                        if (CONFIG.showBody && content) {
                            var sub = Java.array('byte', []);
                            try {
                                sub = Java.array('byte', Array.prototype.slice.call(content, off, off + len));
                            } catch (e2) {}
                            logBody("Request Body", "OkHttp", sub);
                        }
                        logStack();
                        U.info(BODY_END);
                        return this.create(type, content, off, len);
                    };
                } catch (e) {}

                U.ok("OkHttp RequestBody hooks active");
            } catch (e) {
                U.fail("OkHttp RequestBody hook failed: " + e.message);
            }

            // ---- Response Body ----
            try {
                var ResponseBody = Java.use("okhttp3.ResponseBody");
                ResponseBody.string.implementation = function () {
                    var result = this.string();
                    if (CONFIG.showResponse && result) {
                        U.info(BODY_BANNER + " Response ==");
                        U.timeLog("OkHttp ResponseBody.string, content-length: " + this.contentLength());
                        var max = CONFIG.responseMaxLen;
                        var display = result.toString();
                        if (display.length > max) display = display.substring(0, max) + "...(truncated)";
                        console.log(display);
                        logStack();
                        U.info(BODY_END);
                    }
                    return result;
                };
                U.ok("OkHttp ResponseBody hooks active");
            } catch (e) {
                U.fail("OkHttp ResponseBody hook failed: " + e.message);
            }

            // ---- Request URL/Headers ----
            try {
                var Request = Java.use("okhttp3.Request");
                Request.url.implementation = function () {
                    var urlObj = this.url();
                    return urlObj;
                };

                var RealCall = Java.use("okhttp3.RealCall");
                RealCall.execute.implementation = function () {
                    var req = this.request();
                    var url = req.url().toString();
                    if (CONFIG.showHeaders && urlMatches(url)) {
                        U.timeLog("OkHttp Request: " + req.method() + " " + url);
                        var headers = req.headers();
                        for (var i = 0; i < headers.size(); i++) {
                            console.log("  " + headers.name(i) + ": " + headers.value(i));
                        }
                    }
                    return this.execute();
                };
                U.ok("OkHttp Request headers hook active");
            } catch (e) {
                U.fail("OkHttp Request headers hook failed: " + e.message);
            }
        });
    }

    // ========== HttpsURLConnection ==========
    function hookHttpsUrlConnection() {
        Java.perform(function () {
            try {
                var HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");

                // getOutputStream — 抓请求体
                HttpsURLConnection.getOutputStream.implementation = function () {
                    var url = this.getURL().toString();
                    if (!urlMatches(url)) return this.getOutputStream();

                    var origOut = this.getOutputStream();
                    var OutputStream = Java.use("java.io.OutputStream");
                    var ByteArrayOutputStream = Java.use("java.io.ByteArrayOutputStream");
                    var baos = ByteArrayOutputStream.$new();

                    var ProxyOutputStream = Java.registerClass({
                        name: "com.frida.SSLProxyOutputStream",
                        superClass: OutputStream,
                        methods: {
                            write: [
                                { retType: 'void', argumentTypes: ['int'], implementation: function (b) {
                                    baos.write(b);
                                    origOut.write(b);
                                }},
                                { retType: 'void', argumentTypes: ['[B'], implementation: function (b) {
                                    baos.write(b);
                                    origOut.write(b);
                                }},
                                { retType: 'void', argumentTypes: ['[B', 'int', 'int'], implementation: function (b, off, len) {
                                    baos.write(b, off, len);
                                    origOut.write(b, off, len);
                                }}
                            ],
                            close: { retType: 'void', argumentTypes: [], implementation: function () {
                                var body = baos.toByteArray();
                                U.info(BODY_BANNER + " Request ==");
                                U.timeLog("HttpsURLConnection: " + url);
                                logBody("Request Body", url, body);
                                logStack();
                                U.info(BODY_END);
                                origOut.close();
                            }},
                            flush: { retType: 'void', argumentTypes: [], implementation: function () {
                                origOut.flush();
                            }}
                        }
                    });
                    return ProxyOutputStream.$new();
                };

                // getInputStream — 抓响应体
                HttpsURLConnection.getInputStream.implementation = function () {
                    var url = this.getURL().toString();
                    if (!urlMatches(url) || !CONFIG.showResponse) return this.getInputStream();

                    var origIn = this.getInputStream();
                    var ByteArrayOutputStream2 = Java.use("java.io.ByteArrayOutputStream");
                    var baos2 = ByteArrayOutputStream2.$new();
                    var buf = Java.array('byte', new Array(4096).fill(0));
                    var len;
                    while ((len = origIn.read(buf)) !== -1) {
                        baos2.write(buf, 0, len);
                    }
                    var body = baos2.toByteArray();
                    var ByteArrayInputStream = Java.use("java.io.ByteArrayInputStream");
                    baos2.close();
                    origIn.close();

                    U.info(BODY_BANNER + " Response ==");
                    U.timeLog("HttpsURLConnection: " + url);
                    logBody("Response Body", url, body);
                    logStack();
                    U.info(BODY_END);

                    return ByteArrayInputStream.$new(body);
                };

                U.ok("HttpsURLConnection hooks active");
            } catch (e) {
                U.fail("HttpsURLConnection hooks failed: " + e.message);
            }
        });
    }

    // ========== Retrofit2 ==========
    function hookRetrofit() {
        Java.perform(function () {
            try {
                var Retrofit = Java.use("retrofit2.Retrofit");
                Retrofit.create.implementation = function (service) {
                    var result = this.create(service);
                    U.ok("Retrofit service created: " + service.toString());
                    return result;
                };

                // Retrofit Converter — 抓序列化后的请求体
                try {
                    var GsonRequestBodyConverter = Java.use("retrofit2.converter.gson.GsonRequestBodyConverter");
                    GsonRequestBodyConverter.convert.implementation = function (value) {
                        U.info(BODY_BANNER + " Retrofit ==");
                        U.timeLog("Retrofit request body: " + (value ? value.toString() : "null"));
                        logStack();
                        U.info(BODY_END);
                        return this.convert(value);
                    };
                } catch (e) { /* Gson converter not present */ }

                try {
                    var JacksonRequestBodyConverter = Java.use("retrofit2.converter.jackson.JacksonRequestBodyConverter");
                    JacksonRequestBodyConverter.convert.implementation = function (value) {
                        U.info(BODY_BANNER + " Retrofit ==");
                        U.timeLog("Retrofit request body: " + (value ? value.toString() : "null"));
                        logStack();
                        U.info(BODY_END);
                        return this.convert(value);
                    };
                } catch (e) { /* Jackson converter not present */ }

                U.ok("Retrofit hooks active");
            } catch (e) {
                U.fail("Retrofit hooks failed: " + e.message);
            }
        });
    }

    // ========== java.net.HttpURLConnection (非 HTTPS 明文 HTTP) ==========
    function hookHttpUrlConnection() {
        Java.perform(function () {
            try {
                var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                // Hook URL.openConnection 以捕获所有 HTTP 连接
                var URL = Java.use("java.net.URL");
                URL.openConnection.overload().implementation = function () {
                    var conn = this.openConnection();
                    var urlStr = this.toString();
                    if (urlMatches(urlStr)) {
                        U.timeLog("HttpURLConnection opened: " + urlStr);
                    }
                    return conn;
                };
                U.ok("HttpURLConnection hooks active");
            } catch (e) {
                U.fail("HttpURLConnection hooks failed: " + e.message);
            }
        });
    }

    // ========== 启动 ==========
    (function init() {
        U.info("ssl_plaintext.js initializing...");

        if (CONFIG.hookOkHttp) hookOkHttp();
        if (CONFIG.hookHttpsURLConnection) hookHttpsUrlConnection();
        if (CONFIG.hookRetrofit) hookRetrofit();
        if (CONFIG.hookHttpURLConnection) hookHttpUrlConnection();

        U.info("ssl_plaintext.js ready (okhttp=" + CONFIG.hookOkHttp +
               " https=" + CONFIG.hookHttpsURLConnection +
               " retrofit=" + CONFIG.hookRetrofit +
               " http=" + CONFIG.hookHttpURLConnection + ")");
        console.log("");
    })();

})(this);
