/**
 * network_monitor.js - 网络通信监控模块
 * 用途：监控应用在运行过程中的网络通信（connect / send / recv）
 * 覆盖层级：
 *   libc: connect / sendto / recvfrom / send / recv
 *   libc: getaddrinfo (DNS 查询)
 *   libc: syscall(__NR_connect, __NR_sendto, __NR_recvfrom)
 * 加载方式：frida -U -f com.app -l utils.js -l network_monitor.js
 */
(function (global) {
    'use strict';

    var U = global.Utils;
    if (!U) {
        console.log("[-] network_monitor requires utils.js (load it first)");
        return;
    }

    var CONFIG = U.mergeConfig('network_monitor', {
        showPayload: false,       // 是否打印数据内容（hexdump）
        payloadMaxLen: 128,       // 最大打印数据字节
        showDns: true,            // 是否监控 DNS
        includeSyscall: true,
        // 关注的目标端口（0 表示全部）
        targetPorts: [],          // 如 [443, 80, 8080]
        ignoreLocalhost: false,   // 忽略 127.0.0.1 通信
    });

    // ========== 工具函数 ==========
    function parseSockaddr(addrPtr, addrLen) {
        try {
            var family = addrPtr.readU16();
            if (family === 2) { // AF_INET
                var port = ((addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8());
                var ip = addrPtr.add(4).readU8() + "." +
                         addrPtr.add(5).readU8() + "." +
                         addrPtr.add(6).readU8() + "." +
                         addrPtr.add(7).readU8();
                return { family: "IPv4", ip: ip, port: port };
            } else if (family === 10) { // AF_INET6
                var port6 = ((addrPtr.add(2).readU8() << 8) | addrPtr.add(3).readU8());
                var flowinfo = addrPtr.add(4).readU32();
                var ip6parts = [];
                for (var i = 0; i < 16; i += 2) {
                    ip6parts.push(addrPtr.add(8 + i).readU16().toString(16));
                }
                var ip6 = ip6parts.join(":");
                return { family: "IPv6", ip: ip6, port: port6, flowinfo: flowinfo };
            }
            return { family: "unknown(" + family + ")", ip: "?", port: 0 };
        } catch (e) {
            return { family: "error", ip: "?", port: 0, error: e.message };
        }
    }

    function shouldLogPort(port) {
        if (CONFIG.targetPorts.length === 0) return true;
        return CONFIG.targetPorts.indexOf(port) !== -1;
    }

    function logData(label, sockfd, addrInfo, dataLen, buf) {
        var target = addrInfo ? (addrInfo.ip + ":" + addrInfo.port) : "?";
        if (!shouldLogPort(addrInfo ? addrInfo.port : 0)) return;
        if (CONFIG.ignoreLocalhost && addrInfo && (addrInfo.ip === "127.0.0.1" || addrInfo.ip === "::1")) return;

        U.timeLog(label + " fd=" + sockfd + " -> " + target + " len=" + dataLen);

        if (CONFIG.showPayload && dataLen > 0 && buf && !buf.isNull()) {
            try {
                var dumpLen = Math.min(dataLen, CONFIG.payloadMaxLen);
                console.log(hexdump(buf, { offset: 0, length: dumpLen, header: true, ansi: false }));
            } catch (e) {
                U.fail("payload dump failed: " + e.message);
            }
        }
    }

    function logRecvData(label, sockfd, buf, dataLen) {
        if (!CONFIG.showPayload || dataLen <= 0 || !buf || buf.isNull()) return;
        try {
            var dumpLen = Math.min(dataLen, CONFIG.payloadMaxLen);
            console.log(hexdump(buf, { offset: 0, length: dumpLen, header: true, ansi: false }));
            U.timeLog(label + " fd=" + sockfd + " recv_len=" + dataLen);
        } catch (e) {
            U.fail("recv dump failed: " + e.message);
        }
    }

    // ========== libc 层 ==========
    function hookLibcNetwork() {
        // connect
        U.registerHook(U.safeHook("libc.so", "connect", {
            onEnter: function (args) {
                this.sockfd = args[0].toInt32();
                this.addrPtr = args[1];
                this.addrLen = args[2].toInt32();
                var info = parseSockaddr(this.addrPtr, this.addrLen);
                if (shouldLogPort(info.port) && CONFIG.ignoreLocalhost &&
                    (info.ip === "127.0.0.1" || info.ip === "::1")) return;
                U.timeLog("connect fd=" + this.sockfd + " -> " + info.ip + ":" + info.port + " (" + info.family + ")");
                // Frida 默认端口警告
                if (info.port === 27042 || info.port === 27043) {
                    U.alert("Frida default port detected! " + info.ip + ":" + info.port);
                    U.logBacktrace(this.context, 10);
                }
            },
            onLeave: function (retval) {
                if (retval.toInt32() !== 0) {
                    U.fail("connect failed: ret=" + retval);
                }
            }
        }));

        // sendto
        U.registerHook(U.safeHook("libc.so", "sendto", {
            onEnter: function (args) {
                this.sockfd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
                this.flags = args[3].toInt32();
                this.addrPtr = args[4];
                this.addrLen = args[5].toInt32();
                var info = this.addrPtr && !this.addrPtr.isNull()
                    ? parseSockaddr(this.addrPtr, this.addrLen) : null;
                logData("sendto", this.sockfd, info, this.len, this.buf);
            }
        }));

        // recvfrom
        U.registerHook(U.safeHook("libc.so", "recvfrom", {
            onEnter: function (args) {
                this.sockfd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                var rlen = retval.toInt32();
                if (rlen > 0) {
                    logRecvData("recvfrom", this.sockfd, this.buf, rlen);
                }
            }
        }));

        // send (TCP)
        U.registerHook(U.safeHook("libc.so", "send", {
            onEnter: function (args) {
                this.sockfd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                var slen = retval.toInt32();
                if (slen > 0) {
                    logData("send", this.sockfd, null, slen, this.buf);
                }
            }
        }));

        // recv (TCP)
        U.registerHook(U.safeHook("libc.so", "recv", {
            onEnter: function (args) {
                this.sockfd = args[0].toInt32();
                this.buf = args[1];
                this.len = args[2].toInt32();
            },
            onLeave: function (retval) {
                var rlen = retval.toInt32();
                if (rlen > 0) {
                    logRecvData("recv", this.sockfd, this.buf, rlen);
                }
            }
        }));

        // getaddrinfo (DNS)
        if (CONFIG.showDns) {
            U.registerHook(U.safeHook("libc.so", "getaddrinfo", {
                onEnter: function (args) {
                    var node = U.safeReadCString(args[0]);
                    var service = U.safeReadCString(args[1]);
                    if (node) {
                        U.timeLog("getaddrinfo host=" + node + (service ? " service=" + service : ""));
                    }
                }
            }));
        }
    }

    // ========== syscall 层 ==========
    function hookSyscallNetwork() {
        var NR = {
            connect: Process.pointerSize === 8 ? 203 : 283,
            sendto: Process.pointerSize === 8 ? 206 : 290,
            recvfrom: Process.pointerSize === 8 ? 207 : 291,
            write: Process.pointerSize === 8 ? 64 : 4,
        };

        U.registerHook(U.safeHook(null, "syscall", {
            onEnter: function (args) {
                var nr = args[0].toInt32();
                if (nr === NR.connect) {
                    var sockfd = args[1].toInt32();
                    var addrPtr = args[2];
                    var addrLen = args[3].toInt32();
                    var info = parseSockaddr(addrPtr, addrLen);
                    if (shouldLogPort(info.port)) {
                        U.timeLog("syscall(connect) fd=" + sockfd + " -> " + info.ip + ":" + info.port);
                    }
                } else if (nr === NR.sendto) {
                    var sSockfd = args[1].toInt32();
                    var sBuf = args[2];
                    var sLen = args[3].toInt32();
                    var sAddrPtr = args[4];
                    var sAddrLen = args[5].toInt32();
                    var sInfo = sAddrPtr && !sAddrPtr.isNull()
                        ? parseSockaddr(sAddrPtr, sAddrLen) : null;
                    logData("syscall(sendto)", sSockfd, sInfo, sLen, sBuf);
                } else if (nr === NR.write) {
                    var wFd = args[1].toInt32();
                    var wBuf = args[2];
                    var wLen = args[3].toInt32();
                    if (wFd > 2 && wLen > 0) {
                        logData("syscall(write)", wFd, null, wLen, wBuf);
                    }
                }
            }
        }));
    }

    // ========== 启动 ==========
    (function init() {
        U.info("network_monitor.js initializing...");
        hookLibcNetwork();
        if (CONFIG.includeSyscall) hookSyscallNetwork();
        U.info("network_monitor.js ready (dns=" + CONFIG.showDns + " syscall=" + CONFIG.includeSyscall + ")");
        console.log("");
    })();

})(this);
