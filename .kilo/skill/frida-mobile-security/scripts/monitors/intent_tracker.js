/**
 * intent_tracker.js - 跨组件 Intent 污点追踪
 * 用途：跟踪数据如何在 Activity/Service/BroadcastReceiver/ContentProvider 之间流动
 * 覆盖：
 *   Activity: Instrumentation.execStartActivity (所有 startActivity 的汇聚点)
 *   Service:  ContextImpl.startService / bindService
 *   Broadcast: ContextImpl.sendBroadcast
 *   Provider:  ContentProvider.query / insert / update / delete / call
 * 加载方式：frida -U -f com.app -l utils.js -l intent_tracker.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] intent_tracker requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('intent_tracker', {
        trackActivity: true,
        trackService: true,
        trackBroadcast: true,
        trackProvider: true,
        showExtras: true,
        extrasMaxStrLen: 200,       // 字符串类型 extra 最大展示长度
        showStack: false,            // 是否打印 Java 调用栈
        showFlags: true,
        // 过滤目标组件（空 = 全部展示）
        targetFilter: [],            // 如 ["com.app.WebViewActivity", "com.app.ExportService"]
        actionFilter: [],            // 如 ["android.intent.action.VIEW"]
    });

    var FLAG_NAMES = {
        0x10000000: "NEW_TASK",
        0x08000000: "CLEAR_TOP",
        0x04000000: "SINGLE_TOP",
        0x20000000: "CLEAR_TASK",
        0x01000000: "ACTIVITY_NEW_DOCUMENT",
        0x00008000: "EXCLUDE_STOPPED",
        0x00800000: "RECEIVER_FOREGROUND",
        0x00400000: "RECEIVER_NO_ABORT",
        0x02000000: "RECEIVER_REGISTERED_ONLY",
        0x00000001: "GRANT_READ_URI",
        0x00000002: "GRANT_WRITE_URI",
        0x00000004: "FROM_BACKGROUND",
        0x00000008: "DEBUG_LOG_RESOLUTION",
        0x00000010: "EXCLUDE_STOPPED_PACKAGES",
        0x00000020: "INCLUDE_STOPPED_PACKAGES",
        0x00010000: "RECEIVER_REPLACE_PENDING",
    };

    if (!Java.available) {
        U.info("intent_tracker requires Java (Android only)");
        return;
    }

    // ========== 工具函数 ==========

    function decodeFlags(flags) {
        var parts = [];
        for (var flag in FLAG_NAMES) {
            if (flags & parseInt(flag)) {
                parts.push(FLAG_NAMES[flag]);
            }
        }
        return parts.length > 0 ? parts.join(" | ") : "0x" + flags.toString(16);
    }

    function getTarget(intent) {
        try {
            var component = intent.getComponent();
            if (component) return component.flattenToShortString();
            var action = intent.getAction();
            var pkg = intent.getPackage();
            if (action && pkg) return pkg + " (action=" + action + ")";
            if (action) return "(action=" + action + ")";
            return "(unknown)";
        } catch (e) {
            return "(error)";
        }
    }

    function extractBundle(bundle, depth) {
        if (!bundle) return null;
        if (depth === undefined) depth = 0;
        if (depth > 2) return "<max depth>";

        var result = {};
        try {
            var keys = bundle.keySet();
            var iterator = keys.iterator();
            while (iterator.hasNext()) {
                var key = String(iterator.next());
                try {
                    var val = bundle.get(key);
                    if (val === null) {
                        result[key] = "null";
                    } else {
                        var cls = val.getClass().getName();
                        if (cls === 'java.lang.String') {
                            var s = String(val);
                            result[key] = s.length > CONFIG.extrasMaxStrLen
                                ? s.substring(0, CONFIG.extrasMaxStrLen) + "...(" + s.length + " chars)"
                                : s;
                        } else if (cls === 'java.lang.Integer' || cls === 'java.lang.Long' ||
                                   cls === 'java.lang.Float' || cls === 'java.lang.Double' ||
                                   cls === 'java.lang.Boolean' || cls === 'java.lang.Short' ||
                                   cls === 'java.lang.Byte') {
                            result[key] = String(val);
                        } else if (cls === 'android.os.Bundle') {
                            result[key] = extractBundle(val, depth + 1);
                        } else if (cls === 'java.util.ArrayList') {
                            result[key] = "<ArrayList size=" + val.size() + ">";
                        } else if (cls.indexOf('[L') === 0) {
                            result[key] = "<Array " + cls + ">";
                        } else {
                            result[key] = "<" + cls + ">";
                        }
                    }
                } catch (e) {
                    result[key] = "<error>";
                }
            }
        } catch (e) {
            return "<Bundle error: " + e.message + ">";
        }
        return result;
    }

    function formatExtras(extras) {
        if (!extras) return "  (none)";
        var lines = [];
        for (var key in extras) {
            var val = extras[key];
            if (typeof val === 'object' && val !== null) {
                lines.push("    " + key + ": " + JSON.stringify(val));
            } else {
                lines.push("    " + key + ": " + val);
            }
        }
        return lines.join("\n");
    }

    function getCaller() {
        try {
            var Exception = Java.use("java.lang.Exception");
            var stack = Exception.$new().getStackTrace();
            for (var i = 0; i < Math.min(stack.length, 15); i++) {
                var className = stack[i].getClassName();
                if (className.indexOf('android.app.ContextImpl') === -1 &&
                    className.indexOf('android.content.ContextWrapper') === -1 &&
                    className.indexOf('java.lang.reflect') === -1 &&
                    className.indexOf('dalvik.system') === -1 &&
                    className.indexOf('android.os.Handler') === -1) {
                    return className + "." + stack[i].getMethodName();
                }
            }
            return stack[3] ? stack[3].getClassName() + "." + stack[3].getMethodName() : "?";
        } catch (e) {
            return "?";
        }
    }

    function shouldLogTarget(target) {
        if (CONFIG.targetFilter.length === 0) return true;
        for (var i = 0; i < CONFIG.targetFilter.length; i++) {
            if (target.indexOf(CONFIG.targetFilter[i]) !== -1) return true;
        }
        return false;
    }

    function shouldLogAction(action) {
        if (CONFIG.actionFilter.length === 0) return true;
        if (!action) return false;
        for (var i = 0; i < CONFIG.actionFilter.length; i++) {
            if (action.indexOf(CONFIG.actionFilter[i]) !== -1) return true;
        }
        return false;
    }

    function logIpcEvent(channel, source, target, intent) {
        var action = null;
        var dataUri = null;
        var extras = null;
        var flags = 0;

        try {
            action = intent.getAction();
        } catch (e) {}
        try {
            dataUri = intent.getDataString();
        } catch (e) {}
        try {
            extras = extractBundle(intent.getExtras());
        } catch (e) {}
        try {
            flags = intent.getFlags();
        } catch (e) {}

        if (!shouldLogTarget(target)) return;
        if (!shouldLogAction(action)) return;

        console.log("");
        U.timeLog("[IPC\u2192" + channel + "] " + source + " \u2192 " + target);
        if (action) console.log("  action: " + action);
        if (dataUri) console.log("  data:   " + dataUri);
        if (CONFIG.showExtras) {
            console.log("  extras:");
            console.log(formatExtras(extras));
        }
        if (CONFIG.showFlags && flags) {
            console.log("  flags:  0x" + flags.toString(16) + " (" + decodeFlags(flags) + ")");
        }
        if (CONFIG.showStack) {
            U.javaStack();
        }
    }

    // ========== Activity 跳转 ==========
    function hookActivity() {
        Java.perform(function () {
            try {
                var Instrumentation = Java.use("android.app.Instrumentation");
                Instrumentation.execStartActivity.overload(
                    'android.content.Context',
                    'android.os.IBinder',
                    'android.os.IBinder',
                    'android.app.Activity',
                    'android.content.Intent',
                    'int',
                    'android.os.Bundle'
                ).implementation = function (who, contextThread, token, target, intent, requestCode, options) {
                    var source = who.getClass().getName();
                    var targetName = getTarget(intent);
                    logIpcEvent("Activity", source, targetName, intent);
                    return this.execStartActivity(who, contextThread, token, target, intent, requestCode, options);
                };
                U.ok("Activity IPC hook active");
            } catch (e) {
                U.fail("Activity IPC hook failed: " + e.message);
            }
        });
    }

    // ========== Service 启动 ==========
    function hookService() {
        Java.perform(function () {
            try {
                var ContextImpl = Java.use("android.app.ContextImpl");
                ContextImpl.startService.implementation = function (intent) {
                    var source = getCaller();
                    var targetName = getTarget(intent);
                    logIpcEvent("Service", source, targetName, intent);
                    return this.startService(intent);
                };
                U.ok("Service IPC hook active");
            } catch (e) {
                U.fail("Service IPC hook failed: " + e.message);
            }

            try {
                var ContextImpl = Java.use("android.app.ContextImpl");
                ContextImpl.bindService.implementation = function (intent, conn, flag) {
                    var source = getCaller();
                    var targetName = getTarget(intent);
                    logIpcEvent("Service(bind)", source, targetName, intent);
                    return this.bindService(intent, conn, flag);
                };
                U.ok("Service bind IPC hook active");
            } catch (e) {
                U.fail("Service bind IPC hook failed: " + e.message);
            }
        });
    }

    // ========== 广播发送 ==========
    function hookBroadcast() {
        Java.perform(function () {
            try {
                var ContextImpl = Java.use("android.app.ContextImpl");
                ContextImpl.sendBroadcast.overload('android.content.Intent').implementation = function (intent) {
                    var source = getCaller();
                    var targetName = getTarget(intent);
                    logIpcEvent("Broadcast", source, targetName, intent);
                    return this.sendBroadcast(intent);
                };
                U.ok("Broadcast IPC hook active");
            } catch (e) {
                U.fail("Broadcast IPC hook failed: " + e.message);
            }

            try {
                var ContextImpl = Java.use("android.app.ContextImpl");
                ContextImpl.sendOrderedBroadcast.overload(
                    'android.content.Intent', 'java.lang.String'
                ).implementation = function (intent, receiverPermission) {
                    var source = getCaller();
                    var targetName = getTarget(intent);
                    logIpcEvent("Broadcast(ordered)", source, targetName, intent);
                    return this.sendOrderedBroadcast(intent, receiverPermission);
                };
                U.ok("OrderedBroadcast IPC hook active");
            } catch (e) {
                U.fail("OrderedBroadcast IPC hook failed: " + e.message);
            }
        });
    }

    // ========== ContentProvider ==========
    function hookProvider() {
        Java.perform(function () {
            var providerClassName = null;

            try {
                var ContentProvider = Java.use("android.content.ContentProvider");

                ContentProvider.query.overload(
                    'android.net.Uri', '[Ljava.lang.String;', 'android.os.Bundle',
                    'android.os.CancellationSignal'
                ).implementation = function (uri, projection, queryArgs, signal) {
                    providerClassName = this.getClass().getName();
                    var source = "?(caller)";
                    try {
                        var Binder = Java.use("android.os.Binder");
                        var uid = Binder.getCallingUid();
                        source = "uid=" + uid;
                    } catch (e2) {}

                    console.log("");
                    U.timeLog("[IPC\u2192Provider] " + source + " \u2192 " + providerClassName + ".query");
                    console.log("  uri:  " + String(uri));
                    if (projection) {
                        var proj = [];
                        for (var i = 0; i < projection.length; i++) {
                            proj.push(String(projection[i]));
                        }
                        console.log("  proj: [" + proj.join(", ") + "]");
                    }
                    if (queryArgs) {
                        console.log("  args: " + extractBundle(queryArgs));
                    }
                    if (CONFIG.showStack) U.javaStack();
                    return this.query(uri, projection, queryArgs, signal);
                };

                ContentProvider.insert.implementation = function (uri, values, extras) {
                    providerClassName = this.getClass().getName();
                    console.log("");
                    U.timeLog("[IPC\u2192Provider] ?(caller) \u2192 " + providerClassName + ".insert");
                    console.log("  uri:    " + String(uri));
                    if (values) {
                        console.log("  values: " + JSON.stringify(extractBundle(values)));
                    }
                    if (CONFIG.showStack) U.javaStack();
                    return this.insert(uri, values, extras);
                };

                ContentProvider.update.implementation = function (uri, values, selection, selectionArgs) {
                    providerClassName = this.getClass().getName();
                    console.log("");
                    U.timeLog("[IPC\u2192Provider] ?(caller) \u2192 " + providerClassName + ".update");
                    console.log("  uri:      " + String(uri));
                    if (selection) console.log("  sel:      " + String(selection));
                    if (values) {
                        console.log("  values:   " + JSON.stringify(extractBundle(values)));
                    }
                    if (CONFIG.showStack) U.javaStack();
                    return this.update(uri, values, selection, selectionArgs);
                };

                ContentProvider.delete.implementation = function (uri, selection, selectionArgs) {
                    providerClassName = this.getClass().getName();
                    console.log("");
                    U.timeLog("[IPC\u2192Provider] ?(caller) \u2192 " + providerClassName + ".delete");
                    console.log("  uri: " + String(uri));
                    if (selection) console.log("  sel: " + String(selection));
                    if (CONFIG.showStack) U.javaStack();
                    return this.delete(uri, selection, selectionArgs);
                };

                try {
                    ContentProvider.call.overload(
                        'java.lang.String', 'java.lang.String', 'android.os.Bundle'
                    ).implementation = function (method, arg, extras) {
                        providerClassName = this.getClass().getName();
                        console.log("");
                        U.timeLog("[IPC\u2192Provider] ?(caller) \u2192 " + providerClassName + ".call");
                        console.log("  method: " + String(method));
                        if (arg) console.log("  arg:    " + String(arg));
                        if (extras) {
                            console.log("  extras: " + JSON.stringify(extractBundle(extras)));
                        }
                        if (CONFIG.showStack) U.javaStack();
                        return this.call(method, arg, extras);
                    };
                } catch (e) {
                    U.info("ContentProvider.call overload not available");
                }

                U.ok("ContentProvider IPC hook active");
            } catch (e) {
                U.fail("ContentProvider IPC hook failed: " + e.message);
            }
        });
    }

    // ========== 启动 ==========
    (function init() {
        U.info("intent_tracker.js initializing...");

        if (CONFIG.trackActivity) hookActivity();
        if (CONFIG.trackService) hookService();
        if (CONFIG.trackBroadcast) hookBroadcast();
        if (CONFIG.trackProvider) hookProvider();

        U.info("intent_tracker.js ready (activity=" + CONFIG.trackActivity +
               " service=" + CONFIG.trackService +
               " broadcast=" + CONFIG.trackBroadcast +
               " provider=" + CONFIG.trackProvider + ")");
        console.log("");
    })();

})(this);