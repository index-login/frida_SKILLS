/**
 * custom_hook.js - App-specific custom hook template
 *
 * Usage:
 *   1. Copy this file to your project directory
 *   2. Write app-specific hook logic in the Java.perform block
 *   3. Load: frida -U -f com.app -l utils.js -l custom_hook.js
 *
 * Utils (from utils.js) is available as `U`:
 *   U.alert(msg)  U.ok(msg)  U.info(msg)  U.fail(msg)
 *   U.timeLog(msg)  U.bytesToHex(bytes)  U.safeReadCString(ptr)
 *   U.logBacktrace(ctx, depth)
 *   send({tag: "key", data: value})  // structured data to Python
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) { console.log("[-] custom_hook requires utils.js"); return; }

    // ==========================================
    // Java layer hooks (Android)
    // ==========================================
    if (Java.available) {
        Java.perform(function () {
            U.info("Executing custom Java hooks...");

            // Example: hook a method and print args
            //
            // var TargetClass = Java.use("com.example.TargetClass");
            //
            // TargetClass.method.overload("java.lang.String", "int")
            //     .implementation = function (str, num) {
            //     U.ok("TargetClass.method(" + str + ", " + num + ")");
            //     var result = this.method(str, num);
            //     U.ok("  => " + result);
            //     return result;
            // };

            // Example: hook constructor
            //
            // TargetClass.$init.overload("android.content.Context")
            //     .implementation = function (ctx) {
            //     U.ok("TargetClass.<init>(Context)");
            //     return this.$init(ctx);
            // };

            // Example: enumerate loaded classes by keyword
            //
            // Java.enumerateLoadedClasses({
            //     onMatch: function (name) {
            //         if (name.indexOf("crypto") !== -1) U.ok("Found: " + name);
            //     },
            //     onComplete: function () { U.info("Enumeration done"); }
            // });

            // Example: modify return value
            //
            // TargetClass.check.implementation = function () {
            //     U.ok("Bypassing check() -> returning true");
            //     return true;
            // };

            // Example: send structured data to Python
            //
            // TargetClass.getResult.implementation = function () {
            //     var result = this.getResult();
            //     send({tag: "result", value: result.toString(), time: Date.now()});
            //     return result;
            // };

            U.info("Custom Java hooks ready");
        });
    }

    // ==========================================
    // Native layer hooks (any platform)
    // ==========================================

    // Example: hook a native function by export name
    //
    // var addr = Module.findExportByName("libc.so", "open");
    // if (addr) {
    //     Interceptor.attach(addr, {
    //         onEnter: function (args) {
    //             var path = U.safeReadCString(args[0]);
    //             U.timeLog("open(" + path + ")");
    //         },
    //         onLeave: function (retval) {
    //             U.info("  => fd=" + retval);
    //         }
    //     });
    // }

    // Example: hook a native function by module+offset
    //
    // var mod = Process.findModuleByName("libtarget.so");
    // if (mod) {
    //     Interceptor.attach(mod.base.add(0x12345), {
    //         onEnter: function (args) {
    //             U.alert("target_func called, arg0=" + args[0]);
    //             U.logBacktrace(this.context, 10);
    //         }
    //     });
    // }

    U.info("custom_hook.js loaded");
})(this);
