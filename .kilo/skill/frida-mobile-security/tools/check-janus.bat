@echo off
setlocal enabledelayedexpansion

set "APK=%~1"
if "%APK%"=="" (
    echo Usage: check-janus.bat ^<apk_path^>
    pause
    exit /b 1
)

set "JAR=%~dp0GetAPKInfo.jar"
java -jar "%JAR%" "%APK%"

pause