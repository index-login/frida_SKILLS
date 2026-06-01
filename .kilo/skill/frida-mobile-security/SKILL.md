# Frida Mobile Security Skill

**模块优先，决策树驱动。** `scripts/` 下的可拼接模块覆盖 95% 的常规分析需求。面对问题时，先匹配决策树 → 按树加载模块 → 根据输出信号判断下一步。硬性规则：`utils.js` **必须**作为第一个 `-l` 参数加载。

---

## 快速命令卡片

```bash
# 加解密自吐
frida -U -f com.app -l utils.js -l crypto_monitor.js

# 行为摸底
frida -U -f com.app -l utils.js -l file_monitor.js -l network_monitor.js -l thread_monitor.js

# 反检测 (Phase 1: 保活 + 定位检测 so)
frida -U -f com.app -l utils.js -l exit_blocker.js -l so_loader_tracer.js

# HTTP 明文拦截
frida -U -f com.app -l utils.js -l ssl_plaintext.js

# Native 函数发现
frida -U -f com.app -l utils.js -l native_hooker.js

# 跨组件 Intent 污点追踪
frida -U -f com.app -l utils.js -l intent_tracker.js

# 内存敏感数据扫描 + 密码输入监听
frida -U -f com.app -l utils.js -l memory_scanner.js

# 完整攻击链 (组件跳转 + 文件 + 网络)
frida -U -f com.app -l utils.js -l intent_tracker.js -l file_monitor.js -l network_monitor.js
```

运行时配置通过 `-e 'var CONFIG_OVERRIDE={...}'` 注入，详见 §5。

---

## 一、任务路由

匹配用户意图 → 跳转对应章节，不要逐章浏览。

### 1.1 前置判断：检测是否已绕过

```
用户是否已能稳定挂载 Frida？
├─ [否] "挂上就闪退" → §四 反检测 Pipeline
├─ [是] 用了 hluda/魔改 frida/已跑过 exit_blocker → 跳过 §四，直接匹配下方任务
└─ [不确定] → 快速探路：
     模块: utils + exit_blocker + so_loader_tracer
     ├─ exit_blocker 有 BLOCKED → 存在检测但已被保活 → 可继续
     └─ exit_blocker 无日志且进程正常 → 无检测 → 可继续
```

### 1.2 意图 → 路径映射

| 关键词 | 任务 | 跳转 |
|-------|------|------|
| "绕过检测" "过掉反调试" | 绕过 | §四 Pipeline |
| "检测防调试" "防调试" "ptrace" "TracerPid" "GDB" "有没有反调试" | 防调试检测 | §九 → `debug-gdb.bat` |
| "检测防注入" "防注入" "注入测试" "能否注入" "anti-injection" | 防注入检测 | §九 → `check-anti-inject.bat` |
| "APK 信息" "Janus" "签名漏洞" "APK 签名" "加固检测" "包名版本" | APK 元数据 | §九 → `check-janus.bat` |
| "找到加密明文" "明文在哪" "加密前数据" | 定位明文 | §2.1 Step 1 crypto_monitor(showStack) |
| "分析加密算法" "什么加密" "密钥是什么" | 识别算法 | §2.1 完整决策树 |
| "看网络请求" "还原协议" "抓包" | 协议分析 | §2.2 |
| "native 函数" "so 里的加密" "找不到导出" | Native 分析 | §2.1 → native_hooker |
| "全程监控" "不知道做了什么" "摸一下行为" | 行为摸底 | §2.3 |
| "分析这个类" "hook 某个方法" | 通用 Java 逆向 | §三 Java Hook 模板 |
| "hook OkHttp" "拦截请求" "SSL 明文" | HTTP 明文 | ssl_plaintext 模块 |
| "SSL 证书" "忽略 SSL" "证书校验" "TrustManager" "HostnameVerifier" "onReceivedSslError" "proceed" "WebView 安全" | SSL/TLS 忽略检测 | §十 |
| "修改参数" "伪造返回值" "替换数据" | 修改数据 | §三 — 在 implementation 中改 return 值 |
| "NOP 掉" "跳过校验" "patch 这个偏移" | 已知偏移 patch | `function_patcher.patchBatch([...])` |
| "so 加载顺序" "追踪 so" | SO 追踪 | dl_monitor 或 so_loader_tracer |
| "建分析脚本" "用 Python" | Python 入口 | §3.3 |
| "污点追踪" "跨组件" "Intent跟踪" "source to sink" "数据流" "攻击链" | 跨组件污点追踪 | §2.6 → intent_tracker |
| "Serializable" "Parcelable" "反序列化" "readObject" "createFromParcel" | 序列化攻击面扫描 | §2.7 → JADX 搜索 `readObject` / `createFromParcel` |
| "内存扫描" "敏感数据" "密钥泄露" "密码输入" "内存搜索" "AES key" "硬编码密钥" "API key" "token" "令牌" | 内存敏感数据扫描 | §2.8 → memory_scanner |

---

## 二、分析决策树

### 2.1 加密算法分析

```
Step 1: crypto_monitor（Java 层自吐）
  模块: utils + crypto_monitor
  │
  ├── [有输出] → 拿到算法、密钥(hex/base64)、IV、明文/密文
  │               配置 showStack:true 从调用栈定位业务代码 → 结束
  │
  └── [无输出] → 加密不在 Java 层，判因下钻
       ├── Java.available = false → 纯 native 进程/iOS → Step 2-Native
       ├── 自定义 ClassLoader/反射 → hook ClassLoader.loadClass 定位类名
       └── 加密在 native 层（OpenSSL/BoringSSL/自实现）→ Step 2-Native

Step 2-Native: native_hooker
  模块: utils + native_hooker(targetLibs:["libencrypt","libssl","libcrypto"])
  ├── [命中] → 自动打印参数(hexdump)/返回值/调用栈
  ├── [STRIPPED] → 追加 dlsym_tracer 看运行时解析
  ├── [没找到明显 crypto so] → 清空 targetLibs 扫描全部 /data/ so
  └── Step 3: network_monitor 字节级兜底
       模块: utils + network_monitor(showPayload:true) + syscall_tracer
       密文必经 write/sendto 发出 → backtrace → so+offset
```

### 2.2 网络协议分析

```
Step 1: network_monitor
  模块: utils + network_monitor
  ├── [明文 HTTP/JSON/Protobuf] → 结束
  └── [密文/TCP 字节流] →
       ├── 标准 TLS (端口 443) → SSL Pinning 绕过
       ├── 自定义加密 TCP → §2.1 先分析加密层
       └── 多通道（WebSocket/Binder/Unix Socket）→ proc_monitor + syscall_tracer
```

### 2.3 行为摸底

```
Step 1: 全量监控
  模块: utils + file_monitor + network_monitor + thread_monitor
  ├── [file_monitor 看到 .dat/.json/.xml] → 追加 crypto_monitor
  ├── [network_monitor 看到陌生 IP 或大量 DNS] → 追加 dl_monitor + crypto_monitor
  ├── [thread_monitor 看到周期性 pthread_create] → 追加 syscall_tracer
  └── [所有模块无输出] → 追加 syscall_tracer(traceAll:true)
```

### 2.4 反 Frida 检测（入口 → ANTI-DETECTION.md）

> **前置快速检测**（无需 Frida，独立工具，详见 §九）：
> - `debug-gdb.bat <包名>` — ptrace 反调试检测（TracerPid + 进程存活）
> - `check-anti-inject.bat <包名>` — SO 注入检测（ptrace + mem 注入）

```
Step 1: 保活 + 定位检测 so
  模块: utils + exit_blocker + so_loader_tracer
  exit_blocker: Interceptor.replace 替换 exit_group/_exit/abort/kill/tgkill
  so_loader_tracer: 记录 do_dlopen 路径+基址
  │
  ├── [exit_blocker BLOCKED + 调用栈来自 pthread_create]
  │   → 分支 A（线程检测）：thread_blocker 或 function_patcher
  │   → 详见 ANTI-DETECTION.md "分支 A"
  │
  ├── [exit_blocker BLOCKED + 调用栈来自 init_array]
  │   → 分支 B（init_array 检测）：init_hook + feature_hider
  │   → 详见 ANTI-DETECTION.md "分支 B"
  │
  └── [exit_blocker 无 BLOCKED，进程直接消失]
       → SVC #0 内联 exit_group，完全绕过 libc
       → 分支 B：llvm-objdump linker64 → init_hook + hasSvc0
```

### 2.5 症状速查

| 症状 | 模式 | 模块组合 |
|------|------|---------|
| exit_blocker BLOCKED + 调用栈来自 pthread_create | 线程检测 | `thread_blocker(blockCallers)` 或 `thread_monitor(callerFilter)` → `function_patcher` |
| 已知 IDA so+offset | 已分析目标 | `function_patcher.patchBatch([...])` |
| 加固壳延迟加载 so + 检测线程 | 壳多阶段 | `thread_blocker(blockCallers)` + `waitForModule` |
| exit_blocker 无 BLOCKED 但进程退出 | init_array SVC | `init_hook` + `hasSvc0` |

### 2.6 跨组件污点追踪（Source → Flow → Sink）

```
攻击链模型：
  Source（不可信数据入口）→ Flow（跨组件传递）→ Sink（危险操作）

Step 1: intent_tracker — 追踪数据在组件间流动
  模块: utils + intent_tracker
  │
  ├── [有输出] → 看到完整的组件跳转链 + Intent extras 内容
  │   ├── 结合 file_monitor 看是否对应文件操作
  │   ├── 结合 network_monitor 看是否对应网络请求
  │   └── 三链路对齐 → 确认完整攻击链 (source→flow→sink)
  │
  └── [无输出] → 组件通信不走标准 Intent API
       ├── 可能是 Binder 直接调用 → 下钻到 syscall_tracer
       └── 可能是 Unix Socket → proc_monitor

Step 2: 组合攻击链验证
  模块: utils + intent_tracker + file_monitor + network_monitor
  操作: 触发 deeplink / 发送 Intent → 观察三模块日志：
  │
  ├── intent_tracker: ExportedActivity → InternalActivity (extras:{url: "evil.com"})
  ├── file_monitor:   InternalActivity.openat /data/data/.../secret.db
  └── network_monitor: InternalActivity.connect evil.com:443
  │
  └── 三条日志时间戳对齐 → 攻击链确认
```

### 2.7 序列化攻击面扫描（Serializable / Parcelable）

```
Android 中所有 Serializable/Parcelable 类都可从 Intent 反序列化。
攻击者构造恶意对象塞入 Intent extras → 触发 readObject()/createFromParcel() 中的危险 sink。

Step 1: 搜索候选类（JADX）
  方法1: 搜索方法名 "readObject" → 找到所有自定义反序列化入口
  方法2: 搜索方法名 "createFromParcel" → 找到所有 Parcelable 工厂方法
  方法3: 搜索类声明 "implements Serializable" / "implements Parcelable"

Step 2: 逐个检查反序列化链
  对每个 readObject(ObjectInputStream) 方法，追踪数据流：
    ois.readObject() / readUTF() / readInt() 等  ← SOURCE
    → 赋值给 this.xxx 字段                          ← FLOW
    → 后续方法使用 this.xxx 做了什么？              ← SINK?

Step 3: 重点 sink 模式
  ├── Class.forName(字段).newInstance()       → 任意类实例化（Google Auth bug）
  ├── Class.forName(字段).getMethod().invoke() → 任意方法反射调用
  ├── new FileInputStream(字段) / new File(字段) → 路径遍历文件读取
  ├── Runtime.exec(字段) / ProcessBuilder(字段) → 命令注入
  ├── loadUrl(字段) / loadData(字段)           → WebView URL 注入
  ├── startActivity(字段) / startService(字段) → Intent 重定向
  └── SQLiteDatabase.execSQL(字段)            → SQL 注入

Step 4: 确认字段外部可控
  只要满足任一条件，字段即外部可控：
  ├── 类本身实现了 Serializable → 可直接 Intent.putExtra()
  ├── 类是某个 Intent extra 的成员字段 → 间接可控
  └── 类通过 Bundle.putSerializable() 传递 → 间接可控
```

### 2.8 内存敏感数据扫描 + 密码输入监听

```
memory_scanner.js 做三件事：
  1. 自动扫描预设高价值数据（AES key、JWT、私钥、API key、URL 凭证）
  2. 实时监听密码输入框的输入内容
  3. 通过 Frida console 提供交互式搜索 API

Step 1: 加载模块
  frida -U -f com.app -l utils.js -l memory_scanner.js
  → 3 秒后自动扫描一次，输出所有匹配

Step 2: 交互式搜索（Frida console 中执行）
  MemoryScanner.search("password")               搜索所有 rw- 内存区域
  MemoryScanner.searchJava("api_key")            搜索 Java 堆 String 对象
  MemoryScanner.searchMod("libnative.so", "secret")  搜索指定模块
  MemoryScanner.dump("0x7a12345678", 256)         hexdump 指定地址
  MemoryScanner.stats()                          查看扫描统计
  MemoryScanner.scanNow()                        手动触发一次完整扫描
  MemoryScanner.addPattern("MY_KEY", "sk-[a-z]{24}")  添加自定义模式

Step 3: 密码输入捕获（Frida console 中启动，无需 -e 参数）
  MemoryScanner.startPasswordCapture()  启动密码输入监听
  MemoryScanner.passwordCaptureStatus() 查看状态
  → 自动检测 EditText 的 password 类型字段
  → 用户输入时实时输出到 console

Step 4: 预设模式说明
  ├── AES-128/192/256 key: 32/48/64 位 hex 字符串
  ├── JWT Token: eyJ... 格式
  ├── PEM Private Key: -----BEGIN...PRIVATE KEY-----
  ├── PEM Public Key / Certificate
  ├── AWS Access Key (AKIA...), AWS Secret Key
  ├── Google API Key (AIza...)
  ├── GitHub Token (ghp_...), Slack Token (xox...)
  ├── Stripe API Key (sk_live_...)
  ├── Firebase URL
  └── URL with credentials (https://user:pass@host)
```

---

## 三、模块目录与用法

### 3.1 目录结构

```
scripts/
├── core/          utils.js                           ← 始终首个加载
├── monitors/      crypto_monitor, file_monitor,        被动观察模块
│                  network_monitor, thread_monitor,      只观测，不修改
│                  dl_monitor, proc_monitor,
│                  syscall_tracer, ssl_plaintext,
│                  native_hooker, intent_tracker,
│                  native_crypto_monitor, memory_scanner
├── bypass/        exit_blocker, thread_blocker,        主动干预模块
│                  frida_feature_hider, function_patcher, 修改 app 行为
│                  init_hook, dlsym_tracer,
│                  so_loader_tracer, shellcode_detector
├── checklist/     (Frida 动态检测脚本，预留)            按需扩展
└── templates/     analysis.py, custom_hook.js          模板文件

tools/             check-anti-inject.bat, debug-gdb.bat,  独立检测工具（详见 §九）
                   check-janus.bat, GetAPKInfo.jar        Frida 挂载前跑
```

### 3.2 Java Hook 模板

```bash
# 枚举已加载的类（按关键词过滤）
frida -U -f com.app -e 'Java.perform(function(){Java.enumerateLoadedClasses({onMatch:function(n){if(n.indexOf("keyword")!==-1)console.log(n);},onComplete:function(){}});});'

# Hook 指定方法并打印返回值
frida -U -f com.app -l utils.js \
  -e 'Java.perform(function(){var C=Java.use("com.example.Class");C.method.implementation=function(){var r=this.method();console.log("[*]",r);return r;};});'
```

详细 API 参考（Java.use / Interceptor / Stalker / Memory / ObjC）见 `API-REFERENCE.md`。

### 3.3 Python 工作流（推荐）

避免手敲超长 CLI 命令。使用 `scripts/templates/analysis.py`：

```
1. 复制 analysis.py → <包名>/analysis.py
2. 修改 TARGET_PACKAGE / LOAD_MODULES / CONFIG_OVERRIDE
3. 在 CUSTOM_HOOK_SCRIPT 中写入 app 专属逻辑
4. 运行: python analysis.py
```

模板自动处理模块加载顺序（utils.js 首加载 → monitors → bypass → 自定义脚本）。`CONFIG_OVERRIDE` 以 Python dict 形式配置，无需 CLI 字符串拼接。

**交互模式**（需要用户在 app 上点击按钮）：设 `TIMEOUT=0`（手动 Ctrl+C 停止）和 `LOG_TO_FILE=True`，详见 §七。

### 3.4 常用组合速查

| 分析目标 | 模块组合 | 说明 |
|---------|---------|------|
| 加解密自吐 | `utils + crypto_monitor` | 第一步总是 crypto_monitor；无输出则加密在 native |
| Native 加密 | `utils + native_hooker` | 默认模式: encrypt/decrypt/aes/rsa/des/sha/hmac/base64/xor |
| HTTP 明文 | `utils + ssl_plaintext` | OkHttp/Retrofit/HttpsURLConnection |
| 字节级协议 | `utils + network_monitor(showPayload:true)` | 发出/接收原始 hex 字节 |
| 行为摸底 | `utils + file_monitor + network_monitor + thread_monitor` | 三模块快速画像 |
| SO 加载追踪 | `utils + dl_monitor` | 加载/卸载/符号解析全生命周期 |
| 子进程监控 | `utils + proc_monitor` | 命令执行、进程创建 |
| 反检测 Phase 1 | `utils + exit_blocker + so_loader_tracer` | 保活 + 定位检测 so |
| 反检测 Phase 2 | `utils + frida_feature_hider(indirectHook) + init_hook(onModuleInit) + exit_blocker` | 抢时机 + 隐藏特征 |
| 反检测线程阻断 | `utils + thread_blocker(blockCallers)` | 拦截检测 so 的 pthread_create |
| 全量覆盖 | `utils + file + thread + network + syscall + dl + proc + crypto` | 盲区全覆盖，日志量大 |
| 跨组件污点追踪 | `utils + intent_tracker` | 跟踪数据在 Activity/Service/Broadcast/Provider 间的流动 |
| 完整攻击链 | `utils + intent_tracker + file_monitor + network_monitor` | web→sink 全路径：source(Intent) → flow(组件跳转) → sink(文件/网络) |
| 内存敏感数据 | `utils + memory_scanner` | 自动扫描 AES key/JWT/API key/私钥 + 密码输入监听 + 交互式搜索 |

---

## 四、分层分析原则

当上层 hook 失效时，按此递推下钻到更底层：

```
Java/ObjC → Java.use / ObjC.classes
  ↓ 被绕过时
JNI Bridge → RegisterNatives 劫持
  ↓
Native .so → Interceptor.attach(导出函数)
  ↓
libc → Interceptor.attach(libc 函数)
  ↓
syscall → Interceptor.attach(syscall)
  ↓
SVC #0 → Stalker / inline hook
```

完整调用链：`Java/ObjC → JNI/Runtime → Native .so → libc → syscall → svc`

### 常见下钻场景

| 现象 | 原因 | 下钻到 |
|------|------|--------|
| crypto_monitor 无输出 | 非 Java 层 | native_hooker |
| file_monitor 无输出 | 函数内联 | syscall_tracer |
| network_monitor 无 connect | 使用 sendto(UDP) | 检查 recvfrom |
| network_monitor 无输出 | Binder/Unix Socket | syscall_tracer(traceAll:true) |
| dl_monitor 无输出 | 自定义 linker | syscall_tracer (mmap+PROT_EXEC) |
| native_hooker 无输出 | SO 尚未加载 | spawn 模式或 dl_monitor |
| native_hooker [STRIPPED] | 去符号 | dlsym_tracer |
| ssl_plaintext 无输出 | 非标准 HTTP 库 | network_monitor(showPayload:true) |

---

## 五、运行时配置（CONFIG_OVERRIDE）

**两个修改层级**：
- **编辑模块文件**（持久生效）：直接改 `scripts/monitors/xxx.js` 或 `scripts/bypass/xxx.js` 中的 `var CONFIG = { ... }`
- **命令行注入**（临时覆盖）：使用 Frida `-e` 参数注入 `CONFIG_OVERRIDE`

所有模块都接受 `CONFIG_OVERRIDE`，通过 Frida `-e` 或 Python dict 注入：

```javascript
var CONFIG_OVERRIDE = {
    file_monitor:     { showBacktrace: true, filterPath: ["/data/data/com.target/"] },
    network_monitor:  { showPayload: true, showBacktrace: false },
    crypto_monitor:   { showStack: true },
    native_hooker:    { targetLibs: ["libencrypt.so"], hookPatterns: ["encrypt", "aes", "xor"] },
    ssl_plaintext:    { urlFilter: ["api.example.com"] },
    exit_blocker:     { showBacktrace: false },
    init_hook:        { onModuleInit: [{ moduleName: "libDetect.so" }], probeCallers: true, autoHideFrida: true },
    thread_blocker:   { blockCallers: ["libmsaoaidsec.so"] },
    frida_feature_hider: { indirectHook: true },
};
```

### 常用覆盖场景

| 场景 | CONFIG_OVERRIDE |
|------|----------------|
| 只看目标路径 | `file_monitor: { filterPath: ["/data/data/com.target/"] }` |
| 关闭调用栈（降噪） | `file_monitor: { showBacktrace:false }, network_monitor: { showBacktrace:false }` |
| 打印发出字节 | `network_monitor: { showPayload:true }` |
| 限定 native hook 库 | `native_hooker: { targetLibs:["libencrypt"] }` |
| 阻断检测线程 | `thread_blocker: { blockCallers:["libDetect.so"] }` |
| indirectHook 模式 | `frida_feature_hider: { indirectHook:true }` |
| 只看特定 URL | `ssl_plaintext: { urlFilter:["api.example.com"] }` |
| 交互模式 | `analysis.py` 中 `TIMEOUT=0`、`LOG_TO_FILE=True` |

---

## 六、故障诊断

### Hook 不生效 / 模块无输出

| 现象 | 可能原因 | 排查 |
|------|---------|------|
| crypto_monitor 无输出 | Java.available=false | §2.1 → native_hooker |
| crypto_monitor 无输出 | 自定义 ClassLoader | hook ClassLoader.loadClass |
| crypto_monitor 无输出 | 加密在 native 层 | dl_monitor 确认 crypto so |
| file_monitor 无输出 | 函数内联 | syscall_tracer |
| network_monitor 无 connect | UDP (sendto) | 检查 recvfrom |
| network_monitor 无输出 | Binder/Unix Socket | syscall_tracer(traceAll:true) |
| dl_monitor 无输出 | 自定义 linker | syscall_tracer (mmap+PROT_EXEC) |
| native_hooker 无输出 | SO 尚未加载 | spawn 模式或 dl_monitor |
| ssl_plaintext 无输出 | 非标准 HTTP 库 | network_monitor(showPayload:true) |

### 进程闪退 / 不稳定

| 现象 | 可能原因 | 排查 |
|------|---------|------|
| 加载 Frida 后闪退 | Frida 被检测 | 加载 exit_blocker → ANTI-DETECTION.md |
| exit_blocker 后仍闪退 | sigaction(SIGKILL)+raise | 额外 hook signal + kill/tgkill |
| exit_blocker 后仍闪退 | 内联 _exit() | syscall_tracer (syscall 93/94) |
| hook 后 ANR/卡死 | onEnter 耗时操作 | 改为异步 send() |
| Interceptor.replace 崩溃 | 参数签名不匹配 | 检查 NativeFunction 参数类型 |
| TypeError: not a function | replace/attach 冲突 | exit_blocker(blockSyscall:false) 或 indirectHook |
| 进程退出但无 BLOCKED | SVC #0 内联 exit_group | ANTI-DETECTION.md 分支 B |

### 环境版本

| 现象 | 原因 | 排查 |
|------|------|------|
| frida -U 连不上 | frida-server 未启动或版本不匹配 | `adb shell "frida-server -D"` |
| Java.perform 报错 | 非 JVM 进程 | `frida-ps -U` 确认进程类型 |
| ARM64 vs ARM32 符号不匹配 | 64位设备 32位 so | `file` 命令检查架构 |
| iOS arm64e PAC 崩溃 | 指针认证 | 见 API-REFERENCE.md |
| Android 高版本 linker64 符号消失 | linker 重构 | `Module.enumerateExports("linker64")` |

---

## 七、交互式协作流程

当目标行为需要用户在 app 上手动点击按钮/切换页面时才触发时，使用此流程。

**循环模式**：配置 analysis.py → 运行 → 用户操作 app → Ctrl+C 停止 → AI 读 `.txt` 日志 → 改 CUSTOM_HOOK_SCRIPT → 再运行。

**关键配置**：`TIMEOUT=0`（手动停止）、`LOG_TO_FILE=True`（日志落盘供 AI 读取）。

**日志分析**：AI 直接读日志文件，按 §八交叉分析模式关联多模块信号与时间戳，输出「已确认 → 推断 → 下一步建议」。用户只需告知操作的大致时间点（如"14:32:15 点了登录"），AI 据此锚定窗口过滤日志。

运行时也可实时读取日志（`.flush()` 确保写入），但推荐停止后再分析，日志更完整。

---

## 八、模块间交叉分析

单个模块的日志提供**纵向**信号（某种行为是否发生），多模块日志交叉分析提供**横向**关联（行为之间的因果关系）。以下模式帮助 LLM 在分析日志时做出正确路由判断。

### 8.1 配置文件解密识别

```
信号组合: file_monitor 看到 read /data/.../config.dat
         + crypto_monitor 随后出现 AES/ECB/PKCS5Padding 解密
时间窗口: file_monitor 时间戳 < crypto_monitor 时间戳 < 1ms
结论:     config.dat 是加密配置文件，算法为 AES/ECB
操作:     用 crypto_monitor 输出的密钥和 IV 离线解密 config.dat
```

### 8.2 Native 层网络初始化识别

```
信号组合: dl_monitor 看到加载 libnetwork.so
         + network_monitor 随后出现 connect(... 443)
时间窗口: dl_monitor < network_monitor < 500ms
结论:     libnetwork.so 负责网络初始化，可能在 .init_array 中执行
操作:     对该 so 追加 init_hook — 配置 onModuleInit:libnetwork.so
```

### 8.3 检测 so 定位（Phase 1 核心决策）

```
信号组合: so_loader_tracer 看到加载 libDetect.so
         + exit_blocker 随后立即 BLOCKED exit_group
时间窗口: so_loader_tracer < exit_blocker < 10ms
结论:     libDetect.so 的 init_array 触发了退出（典型反 Frida 检测）
操作:     → Phase 2: 追加 init_hook + dlsym_tracer 获取检测逻辑
         → Phase 5: 追加 shellcode_detector 定位闪退偏移
         → Phase 6: function_patcher NOP 掉闪退函数
```

### 8.4 加密函数 native 层定位

```
信号组合: network_monitor 看到 sendto(... 密文 payload, length=256)
         + syscall_tracer 看到 write(fd, len=256) 在同一线程、同一时间戳
时间窗口: |network_monitor 时间戳 - syscall_tracer 时间戳| < 2ms
结论:     write() 的调用者就是加密/发送函数
操作:     在 write() hook 中执行 Thread.backtrace() → 第2-3帧即加密函数地址
         → Process.findModuleByAddress 解析为 libxxx.so+0xoffset
```

### 8.5 其他关联模式

| 信号组合 | 结论 | 时间窗口 |
|---------|------|---------|
| file_monitor `read /data/.../config.dat` → crypto_monitor `AES/ECB` | (详见 8.1) | <1ms |
| dl_monitor `libnetwork.so` → network_monitor `connect(...443)` | (详见 8.2) | <500ms |
| so_loader_tracer `libDetect.so` → exit_blocker `BLOCKED exit_group` | (详见 8.3) | <10ms |
| network_monitor `sendto(密文,256)` + syscall_tracer `write(fd,256)` 同线程同时 | (详见 8.4) | <2ms |
| intent_tracker `ExportedActivity → WebViewActivity` + file_monitor `openat .../secret.db` | 跨组件攻击链：deeplink source → 组件跳转 flow → 文件读取 sink | <500ms |
| intent_tracker extras 含 `Serializable` + file_monitor 读到私有文件 | 反序列化攻击链：Intent 携带恶意序列化对象 → 触发路径遍历 | 看 intent_tracker 先于 file_monitor |

### 8.6 反向推断：用缺失信号做排除

当某一模块无输出但不确定原因时，用已知正常模块的状态做排除法：

```
场景: 你 hook javax.crypto.Cipher 但无输出
交叉验证: 同时加载 file_monitor
  → file_monitor 有输出 → utils.js 正常、Frida 正常、进程正常 — 问题锁定在 Java hook 层
  → file_monitor 也无输出 → 可能：
      - app 在 Frida attach 前就退出了 → 检查 exit_blocker
      - 目标进程不是 JVM 进程 → 检查 Java.available
      - Frida 没有正确注入 → 检查 frida-ps -U 确认进程可见
```

---

## 九、独立检测工具

`tools/` 目录下的自动化检测脚本，**无需 Frida 即可运行**，是 Frida 分析的前置步骤。

> **Agent 使用规则**：三个 bat 是 Windows 批处理，Agent 不能代跑，应输出完整命令让用户自行执行（方便截图）。用户提到"检测反调试"、"检测防注入"、"看 APK 信息"时，Agent 按 §1.2 路由表匹配对应工具，输出命令。

| 工具 | 检测目标 | 用法 |
|------|---------|------|
| `check-anti-inject.bat` | 防注入（ptrace + /proc/pid/mem） | `check-anti-inject.bat <包名>` |
| `debug-gdb.bat` | 防调试（ptrace / TracerPid） | `debug-gdb.bat <包名>` |
| `check-janus.bat` | APK 元数据提取 | `check-janus.bat <apk路径>` |

### 9.1 check-anti-inject.bat — 防注入检测

**原理**：通过 AndKittyInjector 向目标进程注入 `libhello64.so`（ptrace + /proc/pid/mem 方式），然后检查 `/proc/pid/maps` 确认注入是否成功。

**前置条件**：
- 设备已 root，SELinux 设为 Permissive（脚本自动执行 `setenforce 0`）
- `/data/local/tmp/AndKittyInjector` — 注入器二进制
- `/data/local/tmp/libhello64.so` — 测试用 SO

**流程**（5 步）：
1. 检查 ADB 设备连接
2. 启动目标 App 并获取 PID
3. 注入前检查 maps（确认干净）
4. 执行 AndKittyInjector 注入
5. 注入后检查 maps 验证结果

**输出判读**：
- `Injection SUCCESS` + maps 中找到 `libhello64.so` → **无防注入保护**
- `Injection FAILED` + maps 中无 `libhello64.so` → **存在防注入保护**

**局限**：仅测试 ptrace + mem 注入方式，不覆盖 LD_PRELOAD、Zygote 注入、Magisk 模块注入等。

### 9.2 debug-gdb.bat — 防调试检测（ptrace）

**原理**：通过 gdbserver64 附加到目标进程，读取寄存器/内存/线程列表，然后检查进程是否存活（反调试会杀死进程）。全程监控 TracerPid 变化。

**前置条件**：
- 设备已 root，SELinux 设为 Permissive
- `/data/local/tmp/gdbserver64` — GDB 服务端
- 本机已安装 Android NDK（`gdb-aarch64.cmd` 中配置路径，默认 NDK 21.4）

**流程**（7 步）：
1. 检查 ADB 设备连接
2. 获取目标进程 PID + 调试前 TracerPid（应为 0）
3. 启动 gdbserver64 附加（端口 5039）+ 调试中 TracerPid（应为 gdbserver PID）
4. 端口转发 `tcp:5039`
5. GDB 批量执行（`debug.gdb` 脚本）：寄存器转储 → PC 内存读取 → 线程列表 → detach
6. 反调试等待 5 秒 → 检查进程是否存活
7. 调试后 TracerPid（应恢复为 0）

**输出判读**：
- TracerPid: `0 → gdbserver PID → 0` + 进程存活 → **无 ptrace 反调试**
- 进程消失 / gdbserver 连接失败 → **存在 ptrace 反调试**

**辅助文件**：
- `gdb-aarch64.cmd` — NDK GDB 包装器，自动设置 PATH 指向 aarch64 GDB
- `debug.gdb` — GDB 批处理脚本（寄存器/内存/线程/detach）

### 9.3 check-janus.bat — APK 元数据提取

**原理**：使用 `GetAPKInfo.jar` 提取 APK 的包名、版本号、版本代码等元数据。

**前置条件**：
- 本机已安装 Java Runtime

**用法**：
```bat
check-janus.bat path/to/app.apk
```

**输出**：APK 包名、版本号、版本代码等（中文输出，GBK 编码）。

### 9.4 与 Frida 检测的配合

| 场景 | 推荐流程 |
|------|---------|
| 首次分析新 App | `check-janus.bat` 提取 APK 信息 → `debug-gdb.bat` 测 ptrace → `check-anti-inject.bat` 测注入 → Frida Phase 1 |
| Frida 挂载闪退 | `debug-gdb.bat` 确认 ptrace 反调试 → 再决定 Frida 策略（§2.4 Pipeline） |
| Frida 挂载成功但行为异常 | `check-anti-inject.bat` 确认注入能力 → 交叉验证 Frida 检测结果 |
| 需要截图证据 | 三个 bat 均有结构化输出，适合截图存档 |

> **执行注意**：`tools/` 脚本是 `.bat` 文件，需在 Windows 宿主机上双击运行或命令行执行，不能在 Kilo 内直接运行。Agent 应输出让用户自行执行的命令，方便截图取证。`debug-gdb.bat` 和 `check-anti-inject.bat` 均依赖 `su`（root 权限）。

---

## 十、SSL/TLS 忽略检测 — 全层参考

Android App 的网络通信分 5 层架构，每层 SSL 忽略的检测 API 不同。**`onReceivedSslError` 是 WebView 专属，不能用于检测 OkHttp。**

### 10.1 检测判定标准速查

| 层 | 框架 | 检测点 | 漏洞特征 |
|----|------|--------|---------|
| Java HTTP | OkHttp 3/4 | `X509TrustManager.checkServerTrusted()` | 方法体为空 |
| Java HTTP | OkHttp 3/4 | `HostnameVerifier.verify()` | `return true;` |
| Java HTTP | Retrofit | 同上（底层即 OkHttp） | 查 `OkHttpClient` 构造处 |
| Java HTTP | HttpURLConnection | `HttpsURLConnection.setDefaultSSLSocketFactory()` | 注入 TrustAll SSLSocketFactory |
| Java HTTP | HttpURLConnection | `HttpsURLConnection.setDefaultHostnameVerifier()` | `return true;` |
| Java HTTP | Volley | `HurlStack` 自定义 `SSLSocketFactory` | 查 `Volley.newRequestQueue` 的 stack 参数 |
| WebView | 系统 WebView | `WebViewClient.onReceivedSslError()` | 调用了 `handler.proceed()` |
| WebView | 腾讯 X5 | `IX5WebViewClient.onReceivedSslError()` | 同上，`com.tencent.smtt.sdk` |
| WebView | UC | `com.uc.webview.export.WebViewClient` | 同上 |
| Native | OpenSSL/BoringSSL | `SSL_CTX_set_verify(ctx, mode, ...)` | `mode` = `SSL_VERIFY_NONE` (0x00) |
| Native | OpenSSL | `SSL_set_verify(ssl, mode, ...)` | 同上 |
| Native | libcurl | `curl_easy_setopt(handle, CURLOPT_SSL_VERIFYPEER, 0L)` | 参数为 0 |
| Native | MbedTLS | `mbedtls_ssl_conf_authmode()` | 设为 `MBEDTLS_SSL_VERIFY_NONE` |
| WebSocket | OkHttp WS | 继承 OkHttp SSL 配置 | 同上 OkHttp 检测点 |
| WebSocket | Java-WebSocket | 自定义 `SSLSocketFactory` | TrustAll 工厂 |
| 全局配置 | Network Security Config | `res/xml/network_security_config.xml` | `<certificates src="user" />` 信任用户证书 |
| 全局配置 | Network Security Config | 同上 XML | `<domain-config cleartextTrafficPermitted="true">` |

### 10.2 静态检测方法 (JADX)

| 目标 | JADX 搜索关键字 |
|------|----------------|
| OkHttp TrustAll | `checkServerTrusted` → 方法体为空 |
| OkHttp HostnameVerifier | `HostnameVerifier` → `return true` |
| OkHttp Builder 注入 | `sslSocketFactory` + `hostnameVerifier` |
| WebView SSL 忽略 | `onReceivedSslError` → 含 `proceed()` |
| X5 WebView | `com.tencent.smtt` + `onReceivedSslError` |
| Native SSL_VERIFY_NONE | 搜索字符串 `SSL_VERIFY_NONE` |
| Network Security Config | `jadx_get_resource_file("res/xml/network_security_config.xml")` |

### 10.3 动态检测方法 (Frida)

| 目标 | Hook 点 | 模块 |
|------|--------|------|
| OkHttp SSLContext Init | `javax.net.ssl.SSLContext.init()` → 检查 `TrustManager[]` 是否 TrustAll | `ssl_plaintext.js` |
| OkHttp HostnameVerifier | `javax.net.ssl.HostnameVerifier.verify()` → 日志 `return true` | `ssl_plaintext.js` |
| WebView SSL 忽略 | `android.webkit.SslErrorHandler.proceed()` | 自定义 hook |
| X5 WebView SSL | `com.tencent.smtt.sdk.SslErrorHandler.proceed()` | 自定义 hook |
| Native SSL_CTX_set_verify | `libssl.so` → `SSL_CTX_set_verify` → 打印 `mode` 参数 | `native_hooker.js` |
| Native curl | `libcurl.so` → `curl_easy_setopt` → `CURLOPT_SSL_VERIFYPEER` | `native_hooker.js` |

### 10.4 检测优先级（金融 App 视角）

| 优先级 | 检测层 | 原因 |
|--------|--------|------|
| **P0** | OkHttp `X509TrustManager` + `HostnameVerifier` | 覆盖率 90%+，API 全量暴露 |
| **P0** | WebView `onReceivedSslError` → `proceed()` | H5 页面含敏感操作 |
| **P1** | X5 WebView 同等接口 | 金融 App 高占比 |
| **P1** | Native `SSL_CTX_set_verify` | 核心交易/加密常走 Native |
| **P2** | Network Security Config 信任用户证书 | 配合抓包利用 |
| **P2** | HttpURLConnection / Volley / libcurl | 老项目残留 |

### 10.5 常见误判

| 误判 | 纠正 |
|------|------|
| 在 OkHttp 层搜索 `onReceivedSslError` | 这是 WebView API，OkHttp 不适用 |
| 在 WebView 层搜索 `checkServerTrusted` | 这是 OkHttp API，WebView 不适用 |
| 看到 `SSLSocketFactory` 自定义就判漏洞 | 需确认 TrustManager 是否 TrustAll，正常自定义 TLS 协议版本是安全的 |
| 看到 `onReceivedSslError` 重写就判漏洞 | 必须确认内部调用了 `handler.proceed()`，仅 log 不调用是安全的 |

---

## 注意事项
- Frida 16.x 与 15.x/14.x 有 API 差异
- ARM64 有指针认证（PAC），iOS arm64e 需特殊处理
- Android 不同 API Level 的 libart.so 内部符号可能不同
- `tools/` 下的 `.bat` 脚本为独立检测工具，无需 Frida 即可运行，详见 §九
- `exit_blocker` 替换退出后检测线程可能空转 — 正常，阻止了退出操作
- 详细 API 用法：`API-REFERENCE.md`
- 反检测 Pipeline 详情：`ANTI-DETECTION.md`
