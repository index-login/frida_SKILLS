# AGENTS.md — 开发规范

所有脚本、模块、工具的开发规范。编码时遵循此规范，确保产出可组合、可观测、可复现。

## 编码规范

### Frida 脚本 (JavaScript)

- 语言：JavaScript（Frida QuickJS / V8），非 Node.js，无 `require`、无 npm
- 文件编码：UTF-8 无 BOM
- 缩进：2 空格，不混用 Tab
- 变量名 camelCase，常量 UPPER_SNAKE_CASE
- 函数单一职责，单个 hook 逻辑不超过 50 行
- 不写注释，除非逻辑不直观需要解释 why
- 使用 `utils.js` 提供的工具函数，不重复实现

### Python 工具

- Python 3.9+，使用 frida Python binding
- 配置通过 dict 注入，不硬编码路径/参数
- 模板：`scripts/templates/analysis.py`

### bat 检测脚本

- 放在 `tools/` 目录
- 结构化输出，方便截图取证
- 前置条件在脚本头部注释说明

## 模块结构

Skill 采用「单 skill + references 分域 + 脚本共享」结构（符合 Agent Skills 开放标准）：

```
.kilo/skill/frida-mobile-security/
├── SKILL.md              ← 总控：任务路由 + 决策树导航 + 模块目录（精华区）
├── references/           ← 技巧分域手册，按需读取（不注册为独立 skill）
│   ├── anti-detection.md    环境对抗
│   ├── unpacking.md         脱壳
│   ├── crypto-hook.md       加密/功能 hook
│   ├── behavior-analysis.md 行为分析
│   ├── static-analysis.md   静态分析（jadx-mcp）
│   ├── native-analysis.md   SO 层分析
│   ├── troubleshooting.md   故障诊断
│   ├── api-reference.md     Frida API 参考
│   └── articles.md          参考文章索引
├── scripts/              ← 脚本共享库（工具，不属于任何技巧域）
│   ├── core/utils.js        ← 始终首个加载，提供公共工具
│   ├── monitors/            ← 纯观测，不修改行为
│   ├── bypass/              ← 主动干预，修改 app 行为
│   ├── utils/               ← SO/DEX 静态工具（so_dump/dex_cache_dump/codeitem_dump 等）
│   ├── checklist/           ← 检测清单脚本
│   └── templates/           ← 模板，复制后修改使用
└── tools/                 ← 独立 bat 检测工具
```

规则：
- **脚本是工具，不属于任何技巧域**：references 按模块名引用 `scripts/`，不复制脚本
- **信息只存一份**：知识只存在于 SKILL.md 或某个 references 之一，不重复
- **新技巧域**：新增 references/<域>.md 并在 SKILL.md 路由表加一行
- **新模块**：放入对应 `scripts/` 子目录，在 SKILL.md 模块目录加一行

新模块导出标准接口：

```javascript
var CONFIG = { ... };
if (typeof CONFIG_OVERRIDE !== 'undefined') {
    Object.assign(CONFIG, CONFIG_OVERRIDE[模块名] || {});
}
```

## Frida API 约定

- **Hook 前先检查目标是否存在**：`Java.use()` 前用 `Java.available`，`Module.findExportByName()` 前用 `Module.findBaseAddress()`
- **大量数据用 `send()` 而非 `console.log()`**：`send()` 走 channel，`console.log()` 走 stdout，大数据会丢
- **Interceptor.attach 比 Interceptor.replace 安全**：replace 替换原函数，签名不匹配会崩
- **Native callback 必须持有引用**：`new NativeCallback(...)` 赋值给全局变量，否则 GC 回收后崩溃
- **Stalker 只在必要时用**：性能开销大，用 `Interceptor.attach` + `Thread.backtrace()` 能解决的不要 Stalker

## 软件工程原则

- **单一职责**：一个模块做一件事，不要把监控和绕过混在一起
- **可组合**：模块通过 `-l` 参数组合，不互相依赖
- **可观测**：所有 hook 点必须有日志输出，不能静默吞掉
- **可复现**：脚本能在其他设备上跑，不依赖特定路径硬编码
- **最小权限**：只 hook 需要的目标，不做全量扫描除非明确要求

## Karpathy 编码准则

写 Frida Agent 脚本时遵循 `karpathy-guidelines` skill 的 4 条原则：

1. **Think Before Coding** — 不假设，暴露不确定性。hook 前先确认目标类/方法存在。
2. **Simplicity First** — 最少代码解决问题。不写投机性 hook，不加未请求的功能。
3. **Surgical Changes** — 只改必须改的。修改现有模块时不顺手重构，匹配已有风格。
4. **Goal-Driven Execution** — 定义可验证的成功标准。hook 有输出 = 成功，无输出 = 需排查。

## 反馈协议

分析过程中遇到以下情况时，往 `feedback/FEEDBACK.md` **追加**一条（不改已有条目）：

- 决策树某个分支走不通或没覆盖
- 模块崩溃 / 无输出 / 逻辑错
- 发现需要但不存在的能力
- AGENTS/SKILL 说明误导了判断

字段约束：
- 类型限 5 种：`decision-tree` / `module-bug` / `missing-module` / `doc` / `tool`
- 复现**必须**给完整 `frida` 命令（开发时原样跑）
- 状态默认 `open`，不自行关闭

## 不重复造轮子

- 写新模块前先查 `scripts/` 是否已有可复用的
- `utils.js` 已有日志格式化、hexdump、backtrace 解析，直接调用
- 配置走 `CONFIG_OVERRIDE` 机制，不硬编码
- 检测类脚本放 `checklist/`，监控类放 `monitors/`，绕过类放 `bypass/`

## 集成新检测项

把新的检测能力集成到 skill 时：

1. 判断类型：Frida 脚本 → `scripts/`，Python 工具 → `tools/` 或 `templates/`，bat 脚本 → `tools/`
2. 遵循上述模块规范（CONFIG、CONFIG_OVERRIDE）
3. 沉渍到对应技巧域：更新 SKILL.md 路由表（如新技巧域则新建 references/<域>.md）
4. 更新 SKILL.md 模块目录和常用组合速查表
5. 添加反馈条目（如有）