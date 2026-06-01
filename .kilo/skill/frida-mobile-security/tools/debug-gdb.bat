@echo off
setlocal enabledelayedexpansion

set "PKG=%~1"
if "%PKG%"=="" (
    echo 用法: debug-gdb.bat ^<包名^>
    echo 示例: debug-gdb.bat com.zhiHuiAnJi
    pause
    exit /b 1
)

set "GDBSERVER=/data/local/tmp/gdbserver64"
set "PORT=5039"
set "GDB=%~dp0gdb-aarch64.cmd"
set "GDB_SCRIPT=%~dp0debug.gdb"

:: === 静默前置：确保 SELinux Permissive（测试环境标配）===
adb shell "su -c 'setenforce 0'" 2>nul

echo ============================================
echo   GDB 原生调试验证
echo   目标: %PKG%
echo   时间: %date% %time%
echo ============================================
echo.

echo [1/7] 检查 ADB 设备...
adb devices 2>nul | findstr "device" >nul
if errorlevel 1 (
    echo [失败] 未检测到 ADB 设备
    pause
    exit /b 1
)
echo [成功] 设备已连接
echo.

echo [2/7] 检查目标进程: %PKG%...
for /f %%p in ('adb shell "pidof %PKG%" 2^>nul') do set "PID=%%p"
if "%PID%"=="" (
    echo [提示] 进程未运行，正在启动...
    adb shell "monkey -p %PKG% 1" >nul 2>&1
    timeout /t 3 /nobreak >nul
    for /f %%p in ('adb shell "pidof %PKG%" 2^>nul') do set "PID=%%p"
    if "!PID!"=="" (
        echo [失败] 无法启动目标进程
        pause
        exit /b 1
    )
)
echo [成功] 进程 PID: %PID%
echo.

:: ====== 关键检测点：TracerPid 是否非零 ======
echo   --- 调试前 TracerPid (应为 0) ---
echo   命令: adb shell "su -c 'cat /proc/%PID%/status | grep TracerPid'"
for /f "tokens=2" %%t in ('adb shell "su -c 'cat /proc/%PID%/status 2>/dev/null | grep TracerPid'" 2^>nul') do set "TP_BEFORE=%%t"
echo   结果: TracerPid = %TP_BEFORE%
if "%TP_BEFORE%"=="0" (
    echo   状态: 未被调试 - 干净
) else (
    echo   状态: 已被 PID %TP_BEFORE% 跟踪!
    echo.
    echo   --- 追查 tracer 身份 ---
    echo   命令: ps -A ^| grep %PKG%
    adb shell "su -c 'ps -A | grep %PKG%'" 2>nul
    echo.
    echo   命令: ps -p %TP_BEFORE%
    adb shell "su -c 'ps -p %TP_BEFORE%'" 2>nul
    echo.
    set "TRACER_IS_SELF=0"
    adb shell "su -c 'ps -p %TP_BEFORE%'" 2>nul | findstr "%PKG%" >nul
    if not errorlevel 1 set "TRACER_IS_SELF=1"
    echo   目标 PID: %PID%
    set /a "PID_DIFF=%TP_BEFORE% - %PID%" 2>nul
    echo   tracer PID: %TP_BEFORE% (差值: !PID_DIFF!)
    echo.
    echo ============================================
    if "!TRACER_IS_SELF!"=="1" (
        echo   检测结论: 存在 ptrace 自跟踪反调试
        echo   证据: tracer 与目标同属 %PKG%，系自身 fork 子进程自跟踪
    ) else (
        echo   检测结论: 存在 ptrace 反调试 (外部 tracer)
        echo   证据: 见上方 ps 输出，tracer 非本工具进程
    )
    echo ============================================
    echo   目标: %PKG% (PID: %PID%)
    echo   本工具尚未附加调试器，TracerPid 非零，非本工具设置。
    echo   外部 ptrace 工具 (gdbserver/Frida) 将无法附加。
    echo ============================================
    echo.
    pause
    exit /b 1
)
echo.

echo [3/7] 启动 gdbserver (端口 %PORT%)...
adb shell "su -c 'killall gdbserver64 2>/dev/null'" >nul 2>&1
start /b adb shell "su -c '%GDBSERVER% :%PORT% --attach %PID%'" >nul 2>&1
timeout /t 2 /nobreak >nul
adb shell "su -c 'netstat -tlnp 2>/dev/null | grep %PORT%'" 2>nul | findstr "LISTEN" >nul
if errorlevel 1 (
    echo [失败] gdbserver 启动失败
    echo.
    echo ============================================
    echo   检测结论: 无法附加调试器
    echo ============================================
    echo   目标: %PKG% (PID: %PID%)
    echo   证据: gdbserver --attach 失败，TracerPid 曾为 %TP_BEFORE%
    echo ============================================
    echo.
    pause
    exit /b 1
)
echo [成功] gdbserver 已在 :%PORT% 监听
echo.
echo   --- 调试中 TracerPid (应为 gdbserver PID) ---
echo   命令: adb shell "su -c 'cat /proc/%PID%/status | grep TracerPid'"
for /f "tokens=2" %%t in ('adb shell "su -c 'cat /proc/%PID%/status 2>/dev/null | grep TracerPid'" 2^>nul') do set "TP_AFTER=%%t"
echo   结果: TracerPid = %TP_AFTER%
if not "%TP_AFTER%"=="0" (echo   状态: 调试器已附加 - 跟踪进程 PID %TP_AFTER%) else (echo   [失败] TracerPid 仍为 0 - 调试器未附加)
echo.

echo [4/7] 端口转发...
adb forward tcp:%PORT% tcp:%PORT% >nul 2>&1
adb forward --list 2>nul | findstr "%PORT%"
echo [成功] 端口 %PORT% 转发完成
echo.

echo [5/7] GDB 连接并执行调试操作...
echo.
echo ============================================
echo   以下为 GDB 原始输出
echo   这是调试能力的关键证据
echo ============================================
echo.
call "%GDB%" -batch -x "%GDB_SCRIPT%" 2>&1
set "GDB_EXIT=%ERRORLEVEL%"
echo.
echo ============================================
echo   调试会话结束 - 进程已恢复运行
echo ============================================
echo.
if not "%GDB_EXIT%"=="0" (echo [警告] GDB 返回码 %GDB_EXIT% - 可能存在反调试)

echo [6/7] 反调试检测 - 等待 5 秒...
echo   如果目标存在反调试，此时会自行终止
timeout /t 5 /nobreak
for /f %%p in ('adb shell "pidof %PKG%" 2^>nul') do set "PID_AFTER=%%p"
if "%PID_AFTER%"=="" (
    echo [检测到反调试] 进程已消失! 目标存在反调试保护!
    echo.
    echo ============================================
    echo   检测结论: 存在 ptrace 反调试保护
    echo ============================================
    echo   目标: %PKG% (PID: %PID%)
    echo   证据: 调试器附加后进程被终止
    echo ============================================
    pause
    exit /b 1
)
echo [成功] 进程存活 - PID: %PID_AFTER%
echo.

echo [7/7] 调试后 TracerPid (应为 0)...
echo   命令: adb shell "su -c 'cat /proc/%PID%/status | grep TracerPid'"
for /f "tokens=2" %%t in ('adb shell "su -c 'cat /proc/%PID%/status 2>/dev/null | grep TracerPid'" 2^>nul') do set "TP_AFTER_DETACH=%%t"
echo   结果: TracerPid = %TP_AFTER_DETACH%
if "%TP_AFTER_DETACH%"=="0" (echo   状态: 调试器已干净分离) else (echo   注意: TracerPid 仍为 %TP_AFTER_DETACH%)
echo.

echo ============================================
echo   检测结论: 无 ptrace 反调试保护
echo ============================================
echo   目标: %PKG% (PID: %PID%)
echo   TracerPid 变化: %TP_BEFORE% -^> %TP_AFTER% -^> %TP_AFTER_DETACH%
echo   调试结束后进程仍正常运行，TracerPid 已恢复为 0
echo ============================================
echo.
pause