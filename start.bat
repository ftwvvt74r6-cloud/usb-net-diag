@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title NetDiag · 网络矩阵 - 网络诊断工具
color 0B

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PY=%ROOT%\tools\python\python.exe"
set "PYARGS="
set "PY_FLAVOR=portable"

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

REM ---------- 2. Python 运行时（包内优先，回退系统 Python）----------
if exist "%PY%" goto :have_python

REM 回退 1：系统 PATH 里的 python（要求 3.11+）
set "PY=python"
set "PYLABEL=python"
where python >nul 2>&1
if not errorlevel 1 (
    "%PY%" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "PY_FLAVOR=system"
        goto :have_python
    )
)

REM 回退 2：Python Launcher 的 py -3
set "PY=py"
set "PYARGS=-3"
set "PYLABEL=py -3"
where py >nul 2>&1
if not errorlevel 1 (
    "%PY%" %PYARGS% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
    if not errorlevel 1 (
        set "PY_FLAVOR=py"
        goto :have_python
    )
)

echo.
echo  [X] 未找到可用的 Python 运行时（需要 Python 3.11+）。
echo      已尝试：① 包内 tools\python\python.exe  ② 系统 python  ③ py -3
echo      请安装 Python 3.11 或更高版本（安装时勾选 "Add python.exe to PATH"）：
echo      https://www.python.org/downloads/windows/
echo      或重新解压带 tools\python\ 的完整内部离线包。
echo.
pause
exit /b 1

:have_python
if /i not "%PY_FLAVOR%"=="portable" (
    echo  [i] 未找到包内 Portable Python，回退到系统运行时：%PYLABEL%
    echo.
)

REM ---------- 3. 环境自检 + 按当前盘符生成配置 ----------
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py"
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
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 goto :npcap_ready

echo.
echo  [*] Npcap 驱动未就绪，开始静默安装（需 UAC 授权，约 30 秒）...
for %%f in ("%ROOT%\tools\npcap-*.exe") do (
    echo      正在安装: %%~nxf
    start /wait "" "%%~f" /S /winpcap_mode=no /loopback_support=yes /dot11_support=yes
)
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py" --npcap
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
"%PY%" %PYARGS% "%ROOT%\core\server.py"

echo.
echo  服务已退出。
pause
endlocal
