/**
 * svc_tracer.js - SVC 指令级 syscall 追踪器
 * 用途：捕获 direct syscall（绕过 libc 的 SVC 指令），定位反调试/反Hook 的真实终止点
 * 原理：使用 Stalker 在指令级追踪 SVC #0，不依赖 libc 的 syscall() 函数
 * 特性：
 *   - 记录 SVC 指令地址 (PC)，可直接用于 IDA 定位
 *   - 显示 syscall 号、名称、参数
 *   - 显示模块名 + 偏移量（so+offset 格式）
 *   - 捕获 SIGSEGV 信号
 *   - 过滤特定 syscall 号和模块
 *   - 可配置追踪时长，到期自动停止
 * 加载方式：frida -U -f com.app -l utils.js -l svc_tracer.js
 *
 * 与 syscall_tracer.js 的区别：
 *   syscall_tracer.js → hook libc 的 syscall() 函数，对 direct SVC 盲区
 *   svc_tracer.js     → Stalker 指令级追踪，捕获所有 SVC 指令（包括匿名 RX 段）
 *
 * 注意：Stalker 有性能开销，建议用于短时诊断（30-120s），不适合长期挂载。
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] svc_tracer requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('svc_tracer', {
        targetModules: [],
        filterSyscalls: [48, 56, 93, 94, 101, 129, 131],
        showArgs: true,
        showBacktrace: false,
        backtraceDepth: 8,
        duration: 60,
        maxRatePerSec: 50,
        traceChildThreads: true,
        catchSIGSEGV: true,
        skipLibcSvc: true,
    });

    // ========== ARM64 完整 syscall 号映射 ==========
    var SYSCALL_MAP_ARM64 = {
        0: "io_setup", 1: "io_destroy", 2: "io_submit", 3: "io_cancel",
        4: "io_getevents", 5: "setxattr", 6: "lsetxattr", 7: "fsetxattr",
        8: "getxattr", 9: "lgetxattr", 10: "fgetxattr", 11: "listxattr",
        12: "llistxattr", 13: "flistxattr", 14: "removexattr", 15: "lremovexattr",
        16: "fremovexattr", 17: "getcwd",
        18: "lookup_dcookie", 19: "eventfd2", 20: "epoll_create1",
        21: "epoll_ctl", 22: "epoll_pwait", 23: "dup", 24: "dup3",
        25: "fcntl", 26: "inotify_init1", 27: "inotify_add_watch",
        28: "inotify_rm_watch", 29: "ioctl", 30: "ioprio_set",
        31: "ioprio_get", 32: "flock", 33: "mknodat", 34: "mkdirat",
        35: "unlinkat", 36: "symlinkat", 37: "linkat", 38: "renameat",
        39: "umount2", 40: "mount", 41: "pivot_root",
        42: "nfsservctl", 43: "statfs", 44: "fstatfs", 45: "truncate",
        46: "ftruncate", 47: "fallocate",
        48: "faccessat", 49: "chdir", 50: "fchdir",
        51: "chroot", 52: "fchmod", 53: "fchmodat", 54: "fchownat",
        55: "fchown", 56: "openat", 57: "close", 58: "vhangup",
        59: "pipe2", 60: "quotactl", 61: "getdents64", 62: "lseek",
        63: "read", 64: "write", 65: "readv", 66: "writev",
        67: "pread64", 68: "pwrite64", 69: "preadv", 70: "pwritev",
        71: "sendfile", 72: "pselect6", 73: "ppoll",
        74: "signalfd4", 75: "vmsplice", 76: "splice", 77: "tee",
        78: "readlinkat", 79: "fstatat", 80: "fstat",
        81: "sync", 82: "fsync", 83: "fdatasync",
        84: "sync_file_range", 85: "timerfd_create", 86: "timerfd_settime",
        87: "timerfd_gettime", 88: "utimensat", 89: "acct", 90: "capget",
        91: "capset", 92: "personality",
        93: "exit", 94: "exit_group", 95: "waitid",
        96: "set_tid_address", 97: "unshare", 98: "futex",
        99: "set_robust_list", 100: "get_robust_list",
        101: "nanosleep", 102: "getitimer", 103: "setitimer",
        104: "kexec_load", 105: "init_module", 106: "delete_module",
        107: "timer_create", 108: "timer_gettime", 109: "timer_getoverrun",
        110: "timer_settime", 111: "timer_delete",
        112: "clock_settime", 113: "clock_gettime", 114: "clock_getres",
        115: "clock_nanosleep", 116: "syslog",
        117: "ptrace", 118: "sched_setparam", 119: "sched_setscheduler",
        120: "sched_getscheduler", 121: "sched_getparam",
        122: "sched_setaffinity", 123: "sched_getaffinity",
        124: "sched_yield", 125: "sched_get_priority_max",
        126: "sched_get_priority_min", 127: "sched_rr_get_interval",
        128: "restart_syscall",
        129: "kill", 130: "tkill", 131: "tgkill",
        132: "sigaltstack", 133: "rt_sigsuspend", 134: "rt_sigaction",
        135: "rt_sigprocmask", 136: "rt_sigpending",
        137: "rt_sigtimedwait", 138: "rt_sigqueueinfo", 139: "rt_sigreturn",
        140: "setpriority", 141: "getpriority", 142: "reboot",
        143: "setregid", 144: "setgid", 145: "setreuid", 146: "setuid",
        147: "setresuid", 148: "getresuid", 149: "setresgid",
        150: "getresgid", 151: "setfsuid", 152: "setfsgid",
        153: "times", 154: "setpgid", 155: "getpgid", 156: "getsid",
        157: "setsid", 158: "getgroups", 159: "setgroups",
        160: "uname", 161: "sethostname", 162: "setdomainname",
        163: "getrlimit", 164: "setrlimit", 165: "getrusage",
        166: "umask", 167: "prctl", 168: "getcpu",
        169: "gettimeofday", 170: "settimeofday", 171: "adjtimex",
        172: "getpid", 173: "getppid", 174: "getuid", 175: "geteuid",
        176: "getgid", 177: "getegid", 178: "gettid",
        179: "sysinfo", 180: "mq_open", 181: "mq_unlink",
        182: "mq_timedsend", 183: "mq_timedreceive", 184: "mq_notify",
        185: "mq_getsetattr", 186: "msgget", 187: "msgctl",
        188: "msgrcv", 189: "msgsnd", 190: "semget", 191: "semctl",
        192: "semtimedop", 193: "semop", 194: "shmget",
        195: "shmctl", 196: "shmat", 197: "shmdt",
        198: "socket", 199: "socketpair", 200: "bind", 201: "listen",
        202: "accept", 203: "connect", 204: "getsockname",
        205: "getpeername", 206: "sendto", 207: "recvfrom",
        208: "setsockopt", 209: "getsockopt", 210: "shutdown",
        211: "sendmsg", 212: "recvmsg", 213: "readahead",
        214: "brk", 215: "munmap", 216: "mremap",
        217: "add_key", 218: "request_key", 219: "keyctl",
        220: "clone", 221: "execve", 222: "mmap",
        223: "fadvise64", 224: "swapon", 225: "swapoff",
        226: "mprotect", 227: "msync", 228: "mlock",
        229: "munlock", 230: "mlockall", 231: "munlockall",
        232: "mincore", 233: "madvise", 234: "remap_file_pages",
        235: "mbind", 236: "get_mempolicy", 237: "set_mempolicy",
        238: "migrate_pages", 239: "move_pages",
        240: "rt_tgsigqueueinfo", 241: "perf_event_open",
        242: "accept4", 243: "recvmmsg",
        244: "wait4", 260: "wait4_old", 245: "prlimit64",
        246: "fanotify_init", 247: "fanotify_mark",
        248: "name_to_handle_at", 249: "open_by_handle_at",
        250: "clock_adjtime", 251: "syncfs",
        252: "setns", 253: "sendmmsg",
        254: "process_vm_readv", 255: "process_vm_writev",
        256: "kcmp", 257: "finit_module",
        258: "sched_setattr", 259: "sched_getattr",
        260: "renameat2", 261: "seccomp", 262: "getrandom",
        263: "memfd_create", 264: "bpf", 265: "execveat",
        266: "userfaultfd", 267: "membarrier",
        268: "mlock2", 269: "copy_file_range",
        270: "preadv2", 271: "pwritev2",
        272: "pkey_mprotect", 273: "pkey_alloc", 274: "pkey_free",
        275: "statx", 276: "io_pgetevents",
        277: "rseq", 278: "kexec_file_load",
        279: "pidfd_send_signal", 280: "io_uring_setup",
        281: "io_uring_enter", 282: "io_uring_register",
        283: "open_tree", 284: "move_mount",
        285: "fsopen", 286: "fsconfig", 287: "fsmount",
        288: "fspick", 289: "pidfd_open",
        290: "clone3", 291: "close_range",
        292: "openat2", 293: "pidfd_getfd",
        294: "faccessat2", 295: "process_madvise",
        296: "epoll_pwait2", 297: "mount_setattr",
        298: "quotactl_fd", 299: "landlock_create_ruleset",
        300: "landlock_add_rule", 301: "landlock_restrict_self",
        302: "memfd_secret", 303: "process_mrelease",
        304: "futex_waitv", 305: "set_mempolicy_home_node",
        306: "cachestat", 307: "fchmodat2",
        308: "map_shadow_stack", 309: "futex_wake",
        310: "futex_wait", 311: "futex_requeue",
        424: "pidfd_send_signal", 425: "io_uring_setup",
        426: "io_uring_enter", 427: "io_uring_register",
        428: "open_tree", 429: "move_mount",
        430: "fsopen", 431: "fsconfig", 432: "fsmount",
        433: "fspick", 434: "pidfd_open",
        435: "clone3",
    };

    var SECURITY_SYSCALLS = {
        48: "faccessat(root/su probing)", 56: "openat(file probing)",
        93: "exit(process terminate)", 94: "exit_group(process terminate)",
        101: "nanosleep(timing)", 117: "ptrace(debugger detect)",
        129: "kill(SIGKILL)", 131: "tgkill(thread kill)",
        167: "prctl(anti-debug)", 220: "clone(child thread)",
        226: "mprotect(code/memory)", 222: "mmap(memory alloc)",
        215: "munmap", 78: "readlinkat(proc scan)",
        262: "getrandom", 263: "memfd_create(frida memfd detect)",
    };

    function getSyscallName(nr) {
        return SYSCALL_MAP_ARM64[nr] || ("sys_" + nr);
    }

    function getSecurityLabel(nr) {
        return SECURITY_SYSCALLS[nr] || null;
    }

    // ========== 模块范围追踪 ==========
    var moduleRanges = [];
    var libcRange = null;

    function buildModuleRanges() {
        moduleRanges = [];
        var modules = Process.enumerateModules();
        for (var i = 0; i < modules.length; i++) {
            var m = modules[i];
            moduleRanges.push({
                base: m.base,
                end: m.base.add(m.size),
                name: m.name,
            });
        }
        moduleRanges.sort(function (a, b) {
            return a.base.compare(b.base);
        });

        var libc = Process.findModuleByName("libc.so");
        if (libc) {
            libcRange = {
                base: libc.base,
                end: libc.base.add(libc.size),
            };
        }
    }

    function findModuleFast(pc) {
        var lo = 0, hi = moduleRanges.length - 1;
        while (lo <= hi) {
            var mid = Math.floor((lo + hi) / 2);
            var range = moduleRanges[mid];
            if (pc.compare(range.base) < 0) {
                hi = mid - 1;
            } else if (pc.compare(range.end) >= 0) {
                lo = mid + 1;
            } else {
                return range;
            }
        }
        return null;
    }

    function resolveModuleOffset(pc) {
        var range = findModuleFast(pc);
        if (range) {
            return range.name + "+0x" + pc.sub(range.base).toString(16);
        }
        try {
            var range2 = Process.findRangeByAddress(pc);
            if (range2) {
                var prot = range2.protection;
                if (range2.file) {
                    return "[" + range2.file.path + "+0x" + pc.sub(range2.base).toString(16) + "]";
                }
                return "[anon:" + prot + "]+0x" + pc.sub(range2.base).toString(16);
            }
        } catch (e) {}
        return "0x" + pc.toString(16);
    }

    function isInLibc(pc) {
        if (!libcRange) return false;
        return pc.compare(libcRange.base) >= 0 && pc.compare(libcRange.end) < 0;
    }

    function isInTargetModule(pc) {
        if (CONFIG.targetModules.length === 0) return true;
        var range = findModuleFast(pc);
        if (!range) return false;
        for (var i = 0; i < CONFIG.targetModules.length; i++) {
            if (range.name.indexOf(CONFIG.targetModules[i]) !== -1) return true;
        }
        return false;
    }

    // ========== 速率限制 ==========
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

    // ========== 路径读取（安全） ==========
    function tryReadPath(context, syscallNr) {
        try {
            if (syscallNr === 48 || syscallNr === 56 || syscallNr === 257 || syscallNr === 432) {
                var pathPtr = context.x1;
                if (pathPtr && !pathPtr.isNull()) {
                    var str = pathPtr.readCString(256);
                    if (str && str.length > 0) {
                        return ' path="' + str + '"';
                    }
                }
            } else if (syscallNr === 78) {
                var pathPtr = context.x1;
                if (pathPtr && !pathPtr.isNull()) {
                    var str = pathPtr.readCString(256);
                    if (str && str.length > 0) {
                        return ' path="' + str + '"';
                    }
                }
            }
        } catch (e) {}
        return "";
    }

    function formatArgs(context, syscallNr) {
        var parts = [];
        for (var i = 0; i < 6; i++) {
            var reg;
            if (i === 0) reg = context.x0;
            else if (i === 1) reg = context.x1;
            else if (i === 2) reg = context.x2;
            else if (i === 3) reg = context.x3;
            else if (i === 4) reg = context.x4;
            else reg = context.x5;

            try {
                parts.push(reg.toString());
            } catch (e) {
                parts.push("?");
            }
        }
        return parts.join(",");
    }

    // ========== Stalker 回调 ==========
    var startTime = 0;
    var svcCount = 0;
    var sigsegvCount = 0;

    function onSvcCallout(context) {
        var syscallNr = -1;
        try {
            syscallNr = context.x8.toInt32();
        } catch (e) {
            return;
        }

        if (CONFIG.filterSyscalls.length > 0 && CONFIG.filterSyscalls.indexOf(syscallNr) === -1) {
            return;
        }

        var pc;
        try {
            pc = context.pc;
        } catch (e) {
            return;
        }

        if (CONFIG.skipLibcSvc && isInLibc(pc)) {
            return;
        }

        if (!isInTargetModule(pc)) {
            return;
        }

        if (rateLimit()) {
            return;
        }

        svcCount++;
        var name = getSyscallName(syscallNr);
        var label = getSecurityLabel(syscallNr);
        var offset = resolveModuleOffset(pc);
        var tid = Process.getCurrentThreadId();

        var msg = "SVC #" + syscallNr + " (" + name + ")";
        msg += " | pc=" + pc;
        msg += " | " + offset;
        msg += " | tid=" + tid;
        if (label) {
            msg += " | " + label;
        }
        if (CONFIG.showArgs) {
            msg += " | args=[" + formatArgs(context, syscallNr) + "]";
        }
        msg += tryReadPath(context, syscallNr);

        if (syscallNr === 129 || syscallNr === 131) {
            var sig = 0;
            try {
                sig = (syscallNr === 129) ? context.x1.toInt32() : context.x3.toInt32();
            } catch (e) {}
            if (sig === 6 || sig === 9 || sig === 11 || sig === 15) {
                U.alert(msg + " <<< FATAL SIGNAL " + sig);
            } else {
                U.alert(msg);
            }
        } else if (syscallNr === 93 || syscallNr === 94) {
            U.alert(msg + " <<< PROCESS EXIT");
        } else {
            U.alert(msg);
        }

        if (CONFIG.showBacktrace) {
            try {
                U.logBacktraceWithOffsets(context, CONFIG.backtraceDepth);
            } catch (e) {}
        }
    }

    // ========== Stalker Transform ==========
    function makeTransform() {
        return function (iterator) {
            var instruction;
            while ((instruction = iterator.next()) !== null) {
                if (instruction.mnemonic === 'svc') {
                    iterator.putCallout(onSvcCallout);
                }
                iterator.keep();
            }
        };
    }

    // ========== 线程管理 ==========
    var stalkedThreads = {};
    var stalkerActive = true;

    function stalkThread(tid) {
        if (stalkedThreads[tid]) return;
        try {
            Stalker.follow(tid, {
                transform: makeTransform(),
            });
            stalkedThreads[tid] = true;
            U.info("Stalker following thread: " + tid);
        } catch (e) {
            U.fail("Stalker.follow failed for tid " + tid + ": " + e.message);
        }
    }

    function followNewThreads() {
        if (!stalkerActive) return;
        try {
            var threads = Process.enumerateThreads();
            for (var i = 0; i < threads.length; i++) {
                stalkThread(threads[i].id);
            }
        } catch (e) {}
    }

    // ========== SIGSEGV 捕获 ==========
    function setupSIGSEGVHandler() {
        Process.setExceptionHandler(function (details) {
            if (details.type === 'access-violation') {
                sigsegvCount++;
                var pc = details.context.pc;
                var offset = resolveModuleOffset(pc);
                var addr = details.address;
                var op = details.memory ? details.memory.operation : '?';
                var tid = Process.getCurrentThreadId();

                U.alert("SIGSEGV | fault=" + addr + " op=" + op + " pc=" + pc + " | " + offset + " | tid=" + tid);

                if (CONFIG.showBacktrace) {
                    try {
                        U.logBacktraceWithOffsets(details.context, CONFIG.backtraceDepth);
                    } catch (e) {}
                }
            }
            return false;
        });
        U.ok("SIGSEGV handler installed");
    }

    // ========== 清理 ==========
    function cleanup() {
        if (!stalkerActive) return;
        stalkerActive = false;
        var elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
        var msg = "svc_tracer stopped after " + elapsed + "s";
        msg += " | SVC events: " + svcCount;
        msg += " | SIGSEGV: " + sigsegvCount;
        msg += " | threads tracked: " + Object.keys(stalkedThreads).length;
        U.info(msg);

        try {
            for (var tid in stalkedThreads) {
                if (stalkedThreads.hasOwnProperty(tid)) {
                    try {
                        Stalker.unfollow(parseInt(tid));
                    } catch (e) {}
                }
            }
        } catch (e) {}
        stalkedThreads = {};
        U.info("Stalker unfollowed all threads");
    }

    function setupDurationTimer() {
        if (CONFIG.duration > 0) {
            setTimeout(function () {
                cleanup();
            }, CONFIG.duration * 1000);
            U.info("svc_tracer will auto-stop after " + CONFIG.duration + "s");
        } else {
            U.info("svc_tracer running indefinitely (Ctrl+C to stop)");
        }
    }

    // ========== 启动 ==========
    (function init() {
        U.info("svc_tracer.js initializing (Stalker-based SVC instruction tracer)...");

        if (Process.arch !== "arm64") {
            U.fail("svc_tracer only supports ARM64 (current arch: " + Process.arch + ")");
            return;
        }

        buildModuleRanges();
        Stalker.trustThreshold = -1;

        startTime = Date.now();
        followNewThreads();

        if (CONFIG.traceChildThreads) {
            var intervalId = setInterval(function () {
                if (!stalkerActive) {
                    clearInterval(intervalId);
                    return;
                }
                followNewThreads();
            }, 2000);
        }

        if (CONFIG.catchSIGSEGV) {
            setupSIGSEGVHandler();
        }

        setupDurationTimer();

        var filterNames = CONFIG.filterSyscalls.map(function (n) {
            return getSyscallName(n) + "(" + n + ")";
        }).join(", ");
        U.info("svc_tracer.js ready");
        U.info("  arch: " + Process.arch);
        U.info("  tracing: " + (CONFIG.filterSyscalls.length > 0 ? filterNames : "ALL syscalls"));
        if (CONFIG.targetModules.length > 0) {
            U.info("  target modules: " + CONFIG.targetModules.join(", "));
        }
        U.info("  duration: " + (CONFIG.duration > 0 ? CONFIG.duration + "s" : "unlimited"));
        U.info("  rate limit: " + CONFIG.maxRatePerSec + "/s");
        console.log("");
    })();

})(this);