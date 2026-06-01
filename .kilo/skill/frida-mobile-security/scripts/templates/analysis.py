"""
analysis.py - Frida 分析入口模板

用法：
    1. 复制此文件到 <包名>/analysis.py
    2. 修改下方「配置区域」的变量
    3. 在 CUSTOM_HOOK_SCRIPT 中写入 app 专属的 hook 逻辑
    4. 运行: python analysis.py

依赖：
    pip install frida-tools
"""

import frida
import sys
import os
import json
import time

# ==================== 配置区域（每个包改这里）====================

# --- 连接模式 ---
# "usb" = 标准 USB 连接 (frida-server 默认 27042)
# "remote" = 自定义主机端口 (Gadget / 非标端口 frida-server)
# "auto" = 先尝试 remote，失败后回退到 USB
CONNECTION_MODE = "auto"
REMOTE_HOST = "127.0.0.1:7890"    # CONNECTION_MODE = "remote" 或 "auto" 时生效

# --- 目标选择（三选一，留空的项会被跳过）---
TARGET_PACKAGE = "com.example.app"  # 模式1: 包名（优先），留空则不启用
TARGET_PID = None                   # 模式2: 直接指定 PID，如 12345
USE_FRONTMOST = False               # 模式3: 自动获取前台应用（前面两项为空时启用）

# --- 附加方式 ---
SPAWN_MODE = False                  # True=重启spawn, False=attach已有进程（模式1包名时生效）
SPAWN_GATING = ""                   # spawn 模式下的启动门控文件路径，留空跳过
GADGET_MODE = False                 # Gadget 模式不支持枚举进程，需配合 adb pidof 获取 PID

# --- 复用模块（文件名不含 .js，utils.js 自动首加载）---
# 可用模块见: .kilo/skill/frida-mobile-security/scripts/monitors/ + scripts/bypass/
LOAD_MODULES = [
    "crypto_monitor",
]

# --- 模块配置（对应 CLI 的 -e 'var CONFIG_OVERRIDE=...'）---
CONFIG_OVERRIDE = {
    "crypto_monitor": {"showStack": True},
}

# --- 自定义 Hook（app 专属逻辑）---
CUSTOM_HOOK_SCRIPT = """
// 在此处写入当前 app 专属的 hook 逻辑
// 示例：hook 特定类的方法、修改参数/返回值
// Utils 对象（来自 utils.js）可在 custom hook 中使用

Java.perform(function() {
    // var Cls = Java.use("com.example.TargetClass");
    // Cls.method.implementation = function() {
    //     var ret = this.method();
    //     console.log("[*] result:", ret);
    //     return ret;
    // };
});
"""

# --- 日志 ---
LOG_TO_FILE = True       # 同时输出到控制台和 .txt 日志文件
TIMEOUT = 10              # 秒，0=手动 Ctrl+C 停止；>0=到时自动退出（LLM 自动分析用）

# ==================== 配置区域结束 ====================

# ========== 消息处理 ==========

_log_file = None

def handle_send(payload, data):
    """结构化 send() 分发 — 按需扩展此函数

    JS 端用法:
        send("plain text")                                     → 默认：打印 + 写日志
        send({tag: "crypto", algo: "AES", key: hexstr})        → JSON，按 tag 匹配
        send({tag: "dump", path: "key.bin"}, keyBytes)         → 二进制，写文件

    按需在下方添加 elif 分支。
    """
    tag = payload.get("tag", "") if isinstance(payload, dict) else ""

    if tag == "":
        # 纯文本 / 无 tag 的 JSON → 打印 + 写日志
        line = str(payload)
        print(line)
        if _log_file:
            _log_file.write(line + "\n")
            _log_file.flush()
    elif data:
        # 带 tag 的二进制数据，默认只报长度（需要写文件时在本分支添加逻辑）
        print(f"[DATA] tag={tag} {len(data)} bytes")
    else:
        # 带 tag 的纯 JSON，默认打印
        print(str(payload))

def on_message(message, data):
    if message["type"] == "send":
        handle_send(message.get("payload", ""), data)
    elif message["type"] == "error":
        stack = message.get("stack", message.get("description", str(message)))
        print(f"[ERROR] {stack}")

# ========== 引擎（不需要改动）==========

SKILL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", ".kilo", "skill", "frida-mobile-security", "scripts")
CORE_DIR = os.path.join(SKILL_DIR, "core")
MONITORS_DIR = os.path.join(SKILL_DIR, "monitors")
BYPASS_DIR = os.path.join(SKILL_DIR, "bypass")


def resolve_device():
    """根据 CONNECTION_MODE 获取设备对象"""
    if CONNECTION_MODE in ("remote", "auto"):
        # 自动转发端口
        port = REMOTE_HOST.split(":")[-1]
        os.system(f"adb forward tcp:{port} tcp:{port} >nul 2>&1")
        try:
            mgr = frida.get_device_manager()
            dev = mgr.add_remote_device(REMOTE_HOST)
            print(f"[+] Connected to remote device: {REMOTE_HOST}")
            return dev
        except Exception as e:
            if CONNECTION_MODE == "remote":
                print(f"[-] Remote connection failed: {e}")
                sys.exit(1)
            print(f"[*] Remote connection failed ({e}), falling back to USB...")

    dev = frida.get_usb_device()
    print(f"[+] Connected via USB: {dev.name}")
    return dev


def resolve_target(device):
    """根据配置确定目标进程 (pid, name)"""
    # 模式1: 包名 spawn（先 spawn 再 attach）
    if TARGET_PACKAGE and SPAWN_MODE:
        pid = device.spawn([TARGET_PACKAGE])
        print(f"[*] Spawned {TARGET_PACKAGE} (pid={pid})")
        return pid, TARGET_PACKAGE

    # 模式2: 直接指定 PID
    if TARGET_PID:
        print(f"[*] Using specified PID: {TARGET_PID}")
        return TARGET_PID, None

    # 模式3: 包名 attach
    if TARGET_PACKAGE:
        if GADGET_MODE:
            import subprocess
            result = subprocess.run(["adb", "shell", "pidof", TARGET_PACKAGE],
                                    capture_output=True, text=True)
            pid_str = result.stdout.strip()
            if pid_str:
                pid = int(pid_str.split()[0])
                print(f"[+] Found via adb: {TARGET_PACKAGE} (pid={pid})")
                return pid, TARGET_PACKAGE
            print(f"[-] Process not found via adb: {TARGET_PACKAGE}")
            sys.exit(1)
        try:
            proc = device.get_process(TARGET_PACKAGE)
            print(f"[+] Found target: {TARGET_PACKAGE} (pid={proc.pid})")
            return proc.pid, TARGET_PACKAGE
        except frida.ProcessNotFoundError:
            print(f"[-] Process not found: {TARGET_PACKAGE}")
            print("[*] Running processes:")
            for p in device.enumerate_processes():
                print(f"    {p.pid:<8} {p.name}")
            sys.exit(1)

    # 模式4: 前台应用
    if USE_FRONTMOST:
        app = device.get_frontmost_application()
        if not app:
            print("[-] Cannot get frontmost app (screen on? app in foreground?)")
            sys.exit(1)
        print(f"[+] Frontmost app: {app.identifier} (pid={app.pid})")
        return app.pid, app.identifier

    print("[-] No target configured (set TARGET_PACKAGE, TARGET_PID, or USE_FRONTMOST)")
    sys.exit(1)


def read_script(filename):
    """Read script file, searching monitors/ → bypass/ → core/"""
    search_dirs = [MONITORS_DIR, BYPASS_DIR, CORE_DIR]
    for d in search_dirs:
        path = os.path.join(d, filename)
        if os.path.exists(path):
            return open(path, "r", encoding="utf-8").read()
    print(f"[-] Script not found in any search dir: {filename}")
    sys.exit(1)


def load_all_scripts(session):
    """拼接所有 JS 为单个脚本（模拟 frida -l a.js -l b.js 的行为）"""
    js_parts = []

    if CONFIG_OVERRIDE:
        js_parts.append(f"var CONFIG_OVERRIDE = {json.dumps(CONFIG_OVERRIDE)};")

    print("[*] Loading utils.js ...")
    js_parts.append(read_script("utils.js"))

    for module_name in LOAD_MODULES:
        filename = f"{module_name}.js"
        print(f"[*] Loading {filename} ...")
        js_parts.append(read_script(filename))

    if CUSTOM_HOOK_SCRIPT and CUSTOM_HOOK_SCRIPT.strip():
        print("[*] Loading custom hooks ...")
        js_parts.append(CUSTOM_HOOK_SCRIPT)

    combined = "\n".join(js_parts)
    script = session.create_script(combined)
    script.on("message", on_message)
    script.load()
    print("[*] All scripts loaded")


def main():
    global _log_file
    # 避免 frida 日志中的非 ASCII 字符导致 Windows 控制台编码错误
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

    device = resolve_device()
    pid, name = resolve_target(device)

    # Attach
    print(f"[*] Attaching to pid={pid} ...")
    session = device.attach(pid)
    print("[+] Attached")

    # 日志文件
    if LOG_TO_FILE:
        label = name or f"pid_{pid}"
        log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{label}.txt")
        _log_file = open(log_path, "w", encoding="utf-8")
        print(f"[+] Log file: {log_path}")

    # Spawn 模式下执行启动门控
    if TARGET_PACKAGE and SPAWN_MODE:
        if SPAWN_GATING:
            print(f"[*] Waiting for device startup ({SPAWN_GATING}) ...")
            os.system(f"adb shell 'while [ ! -f {SPAWN_GATING} ]; do sleep 0.1; done'")
        device.resume(pid)
        print(f"[*] Resumed {TARGET_PACKAGE}")

    try:
        load_all_scripts(session)
    except frida.TransportError as e:
        print(f"\n[!] Frida connection lost: {e}")
        print("[!] Diagnosis (check context above to narrow down):")
        print("    - If scripts were loading normally then died → likely app Frida detection")
        print("    - If died at 'Attaching...' → check USB cable, frida-server, port forwarding")
        print("    - If app process still alive (adb pidof) but can't reconnect → frida agent killed")
        try:
            session.detach()
        except Exception:
            pass
        sys.exit(1)
    print(f"[*] All scripts loaded. Running (TIMEOUT={TIMEOUT}s, 0=manual)...\n")

    start = time.time()
    try:
        while TIMEOUT == 0 or (time.time() - start) < TIMEOUT:
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\n[*] Stopping ...")
    finally:
        if _log_file:
            _log_file.close()
        session.detach()
        print("[*] Detached")


if __name__ == "__main__":
    main()
