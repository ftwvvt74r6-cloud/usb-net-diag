@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title NetDiag · 网络矩阵 - 网络诊断工具
color 0B

REM ============================================================
REM  推荐入口：双击 NetDiag.exe（无控制台、启动不提权、自动开浏览器）
REM  本文件是 Python 回退入口：不依赖 exe，便于查看日志/排查启动问题。
REM  需要管理员权限时运行 start.bat --admin（会请求 UAC）；
REM  默认以当前权限启动，实时抓包/通信观察在界面里按需提权。
REM ============================================================

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

REM ---------- 1. 管理员权限（默认不提权；只在 --admin 时请求）----------
REM 为什么默认不提权：启动即弹 UAC 是「双击没反应 / 慢」的主因之一；
REM 需要权限的功能由界面按需请求，离线分析、链路体检不需要管理员。
net session >nul 2>&1
if not errorlevel 1 goto :have_admin
if /i not "%~1"=="--admin" goto :no_admin_tip
echo  [*] 正在请求管理员权限（UAC 请点"是"）...
powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b
echo  [!] 提权被取消，以普通权限继续：实时抓包/通信观察可能不可用。
echo.
goto :have_admin

:no_admin_tip
echo  [i] 当前以普通权限运行（启动不请求管理员权限）。
echo      分析抓包文件、连通与速度测试不受影响；
echo      实时抓包 / 通信观察需要管理员权限时，请在界面里按需提权，
echo      或关闭本窗口后运行: start.bat --admin
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
echo  [X] 未找到 tshark，实时抓包与「分析抓包文件」（离线分析）都不可用。
echo      请将 Wireshark 便携版解压到:
echo      %ROOT%\tools\WiresharkPortable\App\Wireshark\tshark.exe
echo.
pause
exit /b 1

REM ---------- 4. Npcap 驱动（只检测 + 交互式安装，不再静默安装）----------
REM 为什么去掉 /S：Npcap 免费版不支持静默安装（会弹「Silent installation is
REM only supported in Npcap OEM」），用户只看到一个看不懂的警告；改为打开向导。
:check_npcap
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 goto :npcap_ready

echo.
echo  [*] Npcap 驱动未就绪，启动交互式安装向导（需 UAC 授权）...
for %%f in ("%ROOT%\tools\npcap-*.exe") do (
    echo      正在启动安装向导: %%~nxf
    echo      请在向导里完成安装（免费版不支持 /S 静默安装）。
    start /wait "" "%%~f"
)
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 (
    echo  [OK] Npcap 安装完成。
) else (
    echo  [!] Npcap 仍未就绪，实时抓包不可用；「分析抓包文件」（离线分析，上传 pcap）不受影响。
    echo      可手动安装：https://npcap.com/#download
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
echo  [i] 日常使用建议双击 NetDiag.exe：无控制台窗口、启动不提权
echo      本文件（start.bat）是 Python 回退入口，需要管理员时用 start.bat --admin
echo.
"%PY%" %PYARGS% "%ROOT%\core\server.py"

echo.
echo  服务已退出。
pause
endlocal
