# MobileRE-Skill — 综合移动端逆向分析 Agent 技能集

<div align="center">

**一个让 AI Agent（Kilo）真正"会逆向"的完整技能系统** —— 不只是 Frida 脚本，而是覆盖静态分析、动态分析、脱壳、反检测、Native 逆向、安全合规的完整逆向工作流。

[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/Version-v0.5.0-2ea44f?style=flat-square)](https://github.com/index-login/MobileRE-Skill)
[![Android](https://img.shields.io/badge/Android-3DDC84?style=flat-square&logo=android&logoColor=white)](https://developer.android.com/)
[![Frida](https://img.shields.io/badge/Frida-FF6B57?style=flat-square&logo=frida&logoColor=white)](https://frida.re/)
[![Python](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Jadx](https://img.shields.io/badge/Jadx-6C5CE7?style=flat-square&logo=java&logoColor=white)](https://github.com/skylot/jadx)
[![Ghidra](https://img.shields.io/badge/Ghidra-9B9B9B?style=flat-square&logo=github&logoColor=white)](https://ghidra-sre.org/)
[![Kilo](https://img.shields.io/badge/Agent-Kilo-orange?style=flat-square&logo=github&logoColor=white)](https://kilo.ai/docs)

**English README** · [English](README.en.md)

如果这个项目对你有帮助，欢迎 ⭐ Star 支持！

</div>

---

## 使用场景

你只需要**用一句话描述需求**，AI 按决策树自动完成整个分析流程：

| 场景 | 一句话需求示例 | AI 会做什么 |
|------|---------------|------------|
| 🎯 **加固脱壳** | "帮我脱壳这个 App" | 一键脱壳：默认回填、修复、去重、方法体标记，产物直接可分析 |
| 🔐 **加密分析** | "看下这个 App 的加密算法和密钥" | Java + Native 双层加解密自吐，给出算法/密钥/IV/明文 |
| 🛡️ **反检测绕过** | "挂上 Frida 就闪退，帮我绕过" | 6 阶段 Pipeline：定位检测 SO → 抢 init_array → 保活 → NOP 闪退函数 |
| 🔍 **行为摸底** | "这个 App 偷偷干了什么" | 文件/网络/线程/进程/Intent 全程监控，输出行为画像 |
| 🧩 **Dex2C/VMP 分析** | "这个加密是 native 的，帮我分析逻辑" | 定位 `so+offset`，hook 优先 / unidbg 复现 / Ghidra 伪代码 |
| 🧬 **静态攻击面** | "帮我审计这个 App 的攻击面" | 从 Manifest 枚举 exported 组件/Provider/WebView，source→sink 追踪 |
| 🧪 **安全合规测试** | "帮我检查这个 App 的安全合规" | 自动运行合规检测（注入/调试/WebView SSL/元数据），出具结果 |

> 所有操作由 AI 完成，你不需要手敲命令或运行脚本。

---

## 这是什么

这不是一个"Frida 脚本合集"，而是一个 **AI 逆向分析 Agent 的完整技能系统**：

- 🧠 **Agent 大脑**（`.kilo/agent/reverser.md`）— 逆向分析高级研究员的角色定义，知道怎么决策
- 📚 **领域知识**（`.kilo/skill/`）— 9 大技巧域手册：脱壳、反检测、加密分析、行为分析、静态攻击面、Native 逆向、故障诊断
- 🔧 **能力单元**（`scripts/`）— 22 个 Frida 模块 + 6 个 Python 二进制工具 + 检测清单
- 🛠️ **合规检测能力** — 针对注入、调试、WebView SSL、APK 元数据的检测项
- 🔌 **MCP 集成**（`kilo.json`）— jadx-mcp（Java 反编译）+ ghidra-mcp（二进制分析）

## 为什么做这个

市面上的逆向输出大多是**孤立的单点脚本**：一个加解密自吐、一个文件监控、一个 Root 绕过。每次新项目都要重新拼凑，遇到加固或反检测时单点工具一碰就崩。

这个 Skill 把碎片化能力整合成 **AI 可理解的模块系统**：

- **AI 按决策树自动选模块**，不靠人肉记忆
- **`-l` 参数自由组合**，场景驱动，不互相依赖
- **分层递推**：`Java → JNI → Native → libc → syscall → SVC`，上层被绕自动下钻
- **反馈闭环**：走不通的路径、崩溃模块、缺失能力自动记录到 `feedback/`

## 与传统工具箱的区别

| 维度 | 传统逆向工具箱 | 本 Skill |
|------|---------------|----------|
| 使用者 | 人类工程师 | **AI Agent**（Kilo 等） |
| 交互方式 | 手敲命令 | **一句话描述需求** |
| 核心交付 | 脚本/工具 | **Skill 文档 + Agent 定义**（`.kilo/`） |
| 决策依据 | 人的经验 | **SKILL.md 决策树** |
| 反馈闭环 | 无 | **Feedback 机制**自动记录失败路径 |
| 静态分析 | 手动开 JADX | **jadx-mcp** 让 AI 直接读类源码 |

---

## 架构

```
┌────────────────────────────────────────────────────────────┐
│                 AI Agent (Kilo)                             │
│  .kilo/agent/reverser.md  — Agent 角色定义                  │
│  .kilo/skill/.../SKILL.md — 任务路由 + 决策树 + 模块索引    │
│  feedback/FEEDBACK.md     — 分析过程反馈闭环                │
├────────────────────────────────────────────────────────────┤
│               Frida 动态 Hook 模块                          │
│  monitors/ (13 个) — 纯观察，不修改行为                     │
│  bypass/   (9 个)  — 主动干预，修改 app 行为                │
│  utils/            — 脱壳/反编译/符号分析工具               │
├────────────────────────────────────────────────────────────┤
│               Python 二进制分析工具                          │
│  find_branch_callers · find_strref · fix_elf               │
│  scan_inline_svc · patch_gadget_threadnames · so_dump      │
├────────────────────────────────────────────────────────────┤
│               MCP 集成（kilo.json 配置）                    │
│  jadx-mcp  — AI 直接读 Java 源码反编译                      │
│  ghidra-mcp — AI 直接反汇编/调试二进制                      │
├────────────────────────────────────────────────────────────┤
│              合规检测能力                                    │
│  注入检测 · 调试检测 · WebView SSL · APK 元数据             │
└────────────────────────────────────────────────────────────┘
```

## 关键技术

- **一键脱壳**：`unpack.py` 6 步线性流水线（默认回填 → 补充扫描 → 自动 pull → 修复 checksum → 去重 → 方法体标记），一代/抽取壳通吃，产物直接拖 jadx
- **反检测 Pipeline**：6 阶段自动递进（定位检测 SO → 抢 init_array → 追踪符号 → 保活 → 检测 shellcode → NOP 闪退函数）
- **分层下钻**：`Java → JNI → Native → libc → syscall → SVC`，上层 hook 被绕过自动降级到更低层
- **Dex2C/VMP 分析**：hook 优先拿数据 → unidbg 复现算法 → Ghidra 伪代码，不需要 IDA 重工具

---

## 项目结构

```
MobileRE-Skill/
├── .kilo/
│   ├── agent/
│   │   └── reverser.md              # Agent 角色定义（逆向分析研究员）
│   └── skill/
│       └── frida-mobile-security/
│           ├── SKILL.md             # 总控：任务路由 + 决策树 + 模块目录
│           ├── references/          # 9 大技巧域手册
│           │   ├── unpacking.md         # 脱壳
│           │   ├── anti-detection.md    # 环境对抗
│           │   ├── crypto-hook.md       # 加密/功能 hook
│           │   ├── behavior-analysis.md # 行为分析
│           │   ├── static-analysis.md   # 静态攻击面
│           │   ├── native-analysis.md   # SO 层分析
│           │   ├── troubleshooting.md   # 故障诊断
│           │   ├── api-reference.md     # Frida API 参考
│           │   └── articles.md          # 参考文章索引
│           ├── scripts/
│           │   ├── core/utils.js        # 公共工具（始终首个加载）
│           │   ├── monitors/            # 13 个监控模块（纯观察）
│           │   ├── bypass/              # 9 个干预模块（反检测等）
│           │   ├── utils/               # 脱壳/二进制/修复工具
│           │   │   ├── unpack.py            # 一键脱壳入口
│           │   │   ├── codeitem_dump.js     # 抽取壳回填 dump
│           │   │   ├── dex_finder.js        # 内存扫描 DEX
│           │   │   ├── dex_cache_dump.js    # ART 精确 dump
│           │   │   ├── dex_rebuilder.py     # DEX 修复（checksum/回填）
│           │   │   ├── scan_register_natives.js  # Dex2C 定位
│           │   │   └── ...                  # find_strref 等分析工具
│           │   ├── checklist/           # 合规检测项
│           │   └── templates/           # 分析模板
│           └── tools/                   # 独立检测工具（bat）
│               ├── check-anti-inject.bat    # 注入检测
│               ├── debug-gdb.bat            # 调试检测
│               └── check-janus.bat          # APK 元数据
├── feedback/FEEDBACK.md            # 分析过程反馈闭环
├── kilo.json                       # MCP 配置（jadx-mcp / ghidra-mcp）
├── AGENTS.md                       # 开发规范（AI 编码约束）
└── README.md / README.en.md        # 本文件
```

---

## 环境搭建

### 宿主机要求

| 工具 | 用途 | 下载 |
|------|------|------|
| Python 3.9+ | 运行 Python 分析脚本 | https://www.python.org/downloads/ |
| Frida CLI | Frida 命令行工具 | `pip install frida-tools` |
| ADB | Android 调试桥 | Android SDK Platform-Tools |
| Android NDK | GDB 调试客户端 | https://developer.android.com/ndk/downloads |
| Java Runtime | APK 信息提取 | https://www.oracle.com/java/technologies/downloads/ |
| JADX | Java 反编译 | https://github.com/skylot/jadx |
| Ghidra | 二进制分析 | https://ghidra-sre.org/ |

### MCP 配套（让 AI 直接读源码/反汇编）

通过 `kilo.json` 集成，AI 分析时直接调用，无需手动开 GUI：

| MCP | 作用 | 安装 |
|-----|------|------|
| **jadx-mcp** | AI 直接读 Java 类源码（`jadx_get_class_source` 等） | [jadx-ai-mcp](https://github.com/zinja-coder/jadx-ai-mcp) |
| **ghidra-mcp** | AI 直接反汇编/调试二进制（`ghidra_import_file` 等） | [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) |

### 测试机准备

```bash
# 1. 推送 frida-server
adb push frida-server-<版本>-android-arm64 /data/local/tmp/fuckserver
adb shell "chmod 755 /data/local/tmp/fuckserver"
adb shell "su -c '/data/local/tmp/fuckserver -D'"

# 2. 推送 AndKittyInjector（合规检测用）
adb push AndKittyInjector /data/local/tmp/AndKittyInjector
adb shell "chmod 755 /data/local/tmp/AndKittyInjector"

# 3. 推送 gdbserver64（调试检测用）
adb push gdbserver64 /data/local/tmp/gdbserver64
adb shell "chmod 755 /data/local/tmp/gdbserver64"
```

---

## 设计原则

- **单一职责** — 一个模块做一件事，monitors/ 只观察不修改，bypass/ 只干预不监控
- **可组合** — 模块通过 `-l` 参数自由组合，不互相依赖
- **可观测** — 所有 hook 点必须有日志输出，不静默吞掉
- **可复现** — 脚本能在其他设备上跑，不依赖特定路径硬编码
- **最小权限** — 只 hook 需要的目标，不做全量扫描

## 许可

[MIT](LICENSE) 许可。

## 免责声明

本项目仅供**教育和合法授权**的安全测试使用：

- 请勿用于任何未经授权的 App 分析、破解或逆向
- 使用者须确保拥有对目标 App 进行测试的合法授权
- 因使用本项目造成的任何法律责任由使用者自行承担
- 如侵犯了您的权益，请联系作者删除相关内容

## 支持

- ⭐ Star 本项目
- 🐛 遇到问题提交 Issue
- 🧩 有新的检测项/模块想法，欢迎讨论
