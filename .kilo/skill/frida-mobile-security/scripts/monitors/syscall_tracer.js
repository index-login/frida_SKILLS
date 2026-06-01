/**
 * syscall_tracer.js - System call trace module
 * Purpose: Trace syscall() invocations for detection analysis
 * Coverage: libc: syscall() function
 * Load: frida -U -f com.app -l utils.js -l syscall_tracer.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] syscall_tracer requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('syscall_tracer', {
        traceAll: false,
        showArgs: true,
        showBacktrace: false,
        backtraceDepth: 5,
        maxRatePerSec: 50,
    });

    // ARM64 syscall number -> name mapping
    var SYSCALL_MAP_ARM64 = {
        // File operations
        56:  "openat",         257: "openat2",       29:  "close",
        63:  "read",           64:  "write",         67:  "pread64",
        68:  "pwrite64",       73:  "flock",         72:  "fcntl",
        4:   "stat",           195: "fstat",         196: "lstat",
        78:  "readlinkat",     21:  "access",        33:  "faccessat",
        50:  "lseek",          35:  "link",          38:  "unlink",
        36:  "symlink",        82:  "rename",        83:  "mkdir",
        87:  "unlinkat",       49:  "chdir",         48:  "fchdir",
        20:  "getcwd",         291: "statfs",        44:  "sendfile",
        // Memory operations
        222: "mmap",           226: "mprotect",      215: "munmap",
        278: "madvise",        25:  "mremap",
        // Thread/Process
        93:  "exit",           94:  "exit_group",    220: "clone",
        98:  "futex",          131: "tgkill",        129: "kill",
        130: "tkill",          260: "wait4",         261: "prctl",
        172: "getpid",         174: "gettid",        178: "getuid",
        // Network
        198: "socket",         203: "connect",       201: "bind",
        202: "listen",         293: "accept",        206: "sendto",
        207: "recvfrom",       208: "setsockopt",
        // Debug/Trace
        101: "ptrace",         167: "getrusage",     118: "gettimeofday",
        113: "clock_gettime",  117: "nanosleep",
        62:  "lseek",
        // Other
        135: "sigaction",      117: "nanosleep",     96:  "set_tid_address",
        137: "set_robust_list",99:  "set_uid",       168: "poll",
        16:  "ioctl",          61:  "writev",        66:  "readv",
    };

    var SECURITY_RELEVANT = {
        "openat": true, "openat2": true, "read": true, "write": true,
        "stat": true, "fstat": true, "lstat": true, "readlinkat": true,
        "access": true, "faccessat": true, "getcwd": true, "statfs": true,
        "mmap": true, "mprotect": true, "munmap": true,
        "clone": true, "futex": true, "exit": true, "exit_group": true,
        "connect": true, "sendto": true, "recvfrom": true,
        "ptrace": true, "gettimeofday": true, "clock_gettime": true,
        "sigaction": true, "tgkill": true, "kill": true,
        "sendfile": true,
        "prctl": true, "unlink": true, "unlinkat": true, "symlink": true,
    };

    function getSyscallName(nr) {
        return SYSCALL_MAP_ARM64[nr] || ("sys_" + nr);
    }

    var logCount = 0;
    var lastReset = Date.now();
    function rateLimit() {
        var now = Date.now();
        if (now - lastReset >= 1000) {
            logCount = 0;
            lastReset = now;
            return false;
        }
        logCount++;
        return logCount > CONFIG.maxRatePerSec;
    }

    function hookSyscall() {
        U.registerHook(U.safeHook(null, "syscall", {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                var name = getSyscallName(nr);

                if (!CONFIG.traceAll && !SECURITY_RELEVANT[name]) return;
                if (rateLimit()) return;

                var msg = "syscall(" + nr + "/" + name + ")";
                if (CONFIG.showArgs) {
                    msg += " args=[" + args[1] + "," + args[2] + "," + args[3] + "]";
                }
                msg += " | tid=" + Process.getCurrentThreadId();
                U.timeLog(msg);

                if (name === "ptrace") U.alert("ptrace syscall detected!");
                if (name === "clone") {
                    var flags = args[1].toInt32();
                    U.info("clone flags=0x" + flags.toString(16));
                }

                if (CONFIG.showBacktrace) {
                    U.logBacktrace(this.context, CONFIG.backtraceDepth);
                }
            }
        }));
    }

    // ========== Startup ==========
    (function init() {
        U.info("syscall_tracer.js initializing...");
        hookSyscall();
        U.info("syscall_tracer.js ready (traceAll=" + CONFIG.traceAll + " rateLimit=" + CONFIG.maxRatePerSec + "/s)");
        console.log("");
    })();

})(this);
