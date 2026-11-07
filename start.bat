@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title NetDiag · 网络矩阵 - 便携网络诊断工具
color 0B

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PY=%ROOT%\tools\python\python.exe"

echo.
echo  ============================================================
echo    NetDiag · 网络矩阵   便携网络诊断工具
echo    运行目录: %ROOT%
echo  ============================================================
echo.

REM ---------- 1. 管理员权限（抓包必需）----------
net session >nul 2>&1
if not errorlevel 1 goto :have_admin
echo  [*] 未获得管理员权限，正在请求提权（UAC 请点"是"）...
powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b
echo  [!] 提权被取消，以普通权限继续：实时抓包可能失败，可改用离线分析。
echo.
:have_admin

REM ---------- 2. 便携 Python ----------
if exist "%PY%" goto :have_python
echo  [X] 未找到便携 Python: %PY%
echo      请确认 tools\python\ 目录完整，或重新解压项目包。
pause
exit /b 1
:have_python

REM ---------- 3. 环境自检 + 按当前盘符生成配置 ----------
"%PY%" "%ROOT%\core\bootstrap.py"
if errorlevel 3 goto :no_tshark
goto :check_npcap

:no_tshark
echo.
echo  [X] 未找到 tshark，实时抓包与离线分析都不可用。
echo      请将 Wireshark 便携版解压到:
echo      %ROOT%\tools\WiresharkPortable\App\Wireshark\tshark.exe
echo.
pause
exit /b 1

REM ---------- 4. Npcap 驱动 ----------
:check_npcap
"%PY%" "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 goto :npcap_ready

echo.
echo  [*] Npcap 驱动未就绪，开始静默安装（需 UAC 授权，约 30 秒）...
for %%f in ("%ROOT%\tools\npcap-*.exe") do (
    echo      正在安装: %%~nxf
    start /wait "" "%%~f" /S /winpcap_mode=no /loopback_support=yes /dot11_support=yes
)
"%PY%" "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 (
    echo  [OK] Npcap 安装完成。
) else (
    echo  [!] Npcap 仍未就绪，实时抓包不可用；离线分析（上传 pcap）不受影响。
)
goto :launch

:npcap_ready
echo  [OK] Npcap 驱动就绪。

REM ---------- 5. 可选：拉起 DeepSeek Harness（Agent 底座）----------
:launch
set "HARNESS_FOUND="
if exist "%ROOT%\harness\windows.bat" set "HARNESS_FOUND=1"
for %%f in ("%ROOT%\harness\*.exe") do set "HARNESS_FOUND=1"
if not defined HARNESS_FOUND goto :start_ui

echo.
echo  [i] 检测到 DeepSeek Harness（Agent 底座）。如需同时启动请运行: start.bat ai
if /i not "%~1"=="ai" goto :start_ui

if exist "%ROOT%\harness\windows.bat" (
    start "DeepSeek Harness" /D "%ROOT%\harness" cmd.exe /c windows.bat
    goto :start_ui
)
for %%f in ("%ROOT%\harness\*.exe") do (
    echo  [*] 启动 Agent 底座: %%~nxf
    start "" /D "%ROOT%\harness" "%%~ff"
    goto :start_ui
)

:start_ui

echo.
echo  [*] 启动本地诊断服务，浏览器将自动打开...
echo      （关闭本窗口即停止服务；界面右上角「退出」也可以）
echo  [i] 日常使用建议双击 NetDiag.vbs：无控制台窗口，自动提权并打开界面
echo.
"%PY%" "%ROOT%\core\server.py"

echo.
echo  服务已退出。
pause
endlocal
