# 模块间交叉分析

> 单模块日志提供**纵向**信号（某种行为是否发生），多模块日志交叉分析提供**横向**关联（行为之间的因果关系）。
> 模块速查：SKILL.md §3.1，故障排查：TROUBLESHOOTING.md。

---

## 1. 配置文件解密识别

```
信号组合: file_monitor 看到 read /data/.../config.dat
         + crypto_monitor 随后出现 AES/ECB/PKCS5Padding 解密
时间窗口: file_monitor 时间戳 < crypto_monitor 时间戳 < 1ms
结论:     config.dat 是加密配置文件，算法为 AES/ECB
操作:     用 crypto_monitor 输出的密钥和 IV 离线解密 config.dat
```

## 2. Native 层网络初始化识别

```
信号组合: dl_monitor 看到加载 libnetwork.so
         + network_monitor 随后出现 connect(... 443)
时间窗口: dl_monitor < network_monitor < 500ms
结论:     libnetwork.so 负责网络初始化，可能在 .init_array 中执行
操作:     对该 so 追加 init_hook — 配置 onModuleInit:libnetwork.so
```

## 3. 检测 so 定位（Phase 1 核心决策）

```
信号组合: so_loader_tracer 看到加载 libDetect.so
         + exit_blocker 随后立即 BLOCKED exit_group
时间窗口: so_loader_tracer < exit_blocker < 10ms
结论:     libDetect.so 的 init_array 触发了退出（典型反 Frida 检测）
操作:     → Phase 2: 追加 init_hook + dlsym_tracer 获取检测逻辑
         → Phase 5: 追加 shellcode_detector 定位闪退偏移
         → Phase 6: function_patcher NOP 掉闪退函数
```

## 4. 加密函数 native 层定位

```
信号组合: network_monitor 看到 sendto(... 密文 payload, length=256)
         + syscall_tracer 看到 write(fd, len=256) 在同一线程、同一时间戳
时间窗口: |network_monitor 时间戳 - syscall_tracer 时间戳| < 2ms
结论:     write() 的调用者就是加密/发送函数
操作:     在 write() hook 中执行 Thread.backtrace() → 第2-3帧即加密函数地址
         → Process.findModuleByAddress 解析为 libxxx.so+0xoffset
```

## 5. 关联模式速查

| 信号组合 | 结论 | 时间窗口 |
|---------|------|---------|
| file_monitor `read /data/.../config.dat` → crypto_monitor `AES/ECB` | (详见 §1) | <1ms |
| dl_monitor `libnetwork.so` → network_monitor `connect(...443)` | (详见 §2) | <500ms |
| so_loader_tracer `libDetect.so` → exit_blocker `BLOCKED exit_group` | (详见 §3) | <10ms |
| network_monitor `sendto(密文,256)` + syscall_tracer `write(fd,256)` 同线程同时 | (详见 §4) | <2ms |

---

## 6. 反向推断：用缺失信号做排除

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
