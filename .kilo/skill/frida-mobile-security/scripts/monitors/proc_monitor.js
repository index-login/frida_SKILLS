/**
 * proc_monitor.js - Process/command execution monitor
 * Purpose: Monitor child process creation and shell command execution
 *          Common in root detection (e.g. "which su") and malicious behavior
 * Coverage:
 *   libc: system / popen / fork / execve / execvp / execle
 *   libc: syscall(__NR_execve)
 *   Java: Runtime.exec / ProcessBuilder (Android)
 * Load: frida -U -f com.app -l utils.js -l proc_monitor.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] proc_monitor requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('proc_monitor', {
        showBacktrace: true,
        backtraceDepth: 10,
        includeJava: true,
        includeSyscall: true,
    });

    // ========== libc layer ==========
    function hookLibcProc() {
        // system() - execute shell command
        U.registerHook(U.safeHook("libc.so", "system", {
            onEnter: function (args) {
                var cmd = U.safeReadCString(args[0]);
                if (cmd) {
                    U.alert("system() called: " + cmd);
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));

        // popen() - execute shell command with pipe
        U.registerHook(U.safeHook("libc.so", "popen", {
            onEnter: function (args) {
                var cmd = U.safeReadCString(args[0]);
                var mode = U.safeReadCString(args[1]);
                if (cmd) {
                    U.alert("popen() called: " + cmd + " (mode=" + (mode || "?") + ")");
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));

        // fork() - create child process
        U.registerHook(U.safeHook("libc.so", "fork", {
            onEnter: function (args) {
                U.alert("fork() called | tid=" + Process.getCurrentThreadId());
                U.logBacktrace(this.context, CONFIG.backtraceDepth);
            }
        }));

        // execve() - execute program
        U.registerHook(U.safeHook("libc.so", "execve", {
            onEnter: function (args) {
                var path = U.safeReadCString(args[0]);
                U.alert("execve() called: " + (path || "?") + " | tid=" + Process.getCurrentThreadId());
                U.logBacktrace(this.context, CONFIG.backtraceDepth);
                if (args[1] && !args[1].isNull()) {
                    try {
                        console.log("  argv:");
                        var argv = args[1];
                        var idx = 0;
                        while (true) {
                            var p = argv.add(idx * Process.pointerSize).readPointer();
                            if (p.isNull()) break;
                            var a = U.safeReadCString(p);
                            if (a) console.log("    [" + idx + "] " + a);
                            idx++;
                        }
                    } catch (e) { }
                }
            }
        }));

        // execvp
        U.registerHook(U.safeHook("libc.so", "execvp", {
            onEnter: function (args) {
                var file = U.safeReadCString(args[0]);
                U.alert("execvp() called: " + (file || "?"));
                U.logBacktrace(this.context, CONFIG.backtraceDepth);
            }
        }));
    }

    // ========== Java layer (Android) ==========
    function hookJavaProc() {
        if (!Java.available) return;

        Java.perform(function () {
            try {
                var Runtime = Java.use("java.lang.Runtime");
                Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmdArray) {
                    var cmd = "";
                    for (var i = 0; i < cmdArray.length; i++) {
                        cmd += cmdArray[i] + " ";
                    }
                    console.log("[!] Runtime.exec(String[]): " + cmd.trim());
                    U.logBacktrace(null, CONFIG.backtraceDepth);
                    return this.exec(cmdArray);
                };
                Runtime.exec.overload("[Ljava.lang.String;", "[Ljava.lang.String;").implementation = function (cmdArray, envp) {
                    var cmd = "";
                    for (var i = 0; i < cmdArray.length; i++) {
                        cmd += cmdArray[i] + " ";
                    }
                    console.log("[!] Runtime.exec(String[], String[]): " + cmd.trim());
                    U.logBacktrace(null, CONFIG.backtraceDepth);
                    return this.exec(cmdArray, envp);
                };
                Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
                    console.log("[!] Runtime.exec(String): " + cmd);
                    U.logBacktrace(null, CONFIG.backtraceDepth);
                    return this.exec(cmd);
                };
                Runtime.exec.overload("java.lang.String", "[Ljava.lang.String;").implementation = function (cmd, envp) {
                    console.log("[!] Runtime.exec(String, String[]): " + cmd);
                    U.logBacktrace(null, CONFIG.backtraceDepth);
                    return this.exec(cmd, envp);
                };
                U.ok("Java Runtime.exec hooked");
            } catch (e) {
                U.fail("Java Runtime.exec hook failed: " + e.message);
            }

            try {
                var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
                ProcessBuilder.start.implementation = function () {
                    var command = this.command();
                    var cmd = "";
                    var it = command.iterator();
                    while (it.hasNext()) {
                        cmd += it.next() + " ";
                    }
                    console.log("[!] ProcessBuilder.start(): " + cmd.trim());
                    U.logBacktrace(null, CONFIG.backtraceDepth);
                    return this.start();
                };
                U.ok("Java ProcessBuilder.start hooked");
            } catch (e) {
                U.fail("Java ProcessBuilder hook failed: " + e.message);
            }
        });
    }

    // ========== syscall layer ==========
    function hookSyscallProc() {
        // ARM64: __NR_execve = 221
        var NR_EXECVE = 221;
        U.registerHook(U.safeHook(null, "syscall", {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                if (nr === NR_EXECVE) {
                    var path = U.safeReadCString(args[1]);
                    U.alert("syscall(execve): " + (path || "?"));
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));
    }

    // ========== Startup ==========
    (function init() {
        U.info("proc_monitor.js initializing...");
        hookLibcProc();
        if (CONFIG.includeJava) hookJavaProc();
        if (CONFIG.includeSyscall) hookSyscallProc();
        U.info("proc_monitor.js ready (java=" + CONFIG.includeJava + " syscall=" + CONFIG.includeSyscall + ")");
        console.log("");
    })();

})(this);
