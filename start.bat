@echo off
chcp 65001 >nul 2>&1
setlocal enabledelayedexpansion
title NetDiag - portable network diagnostics
color 0B

REM ============================================================
REM  This file MUST stay pure ASCII (every byte < 0x80).
REM  Reason: after "chcp 65001" cmd keeps reading this batch by
REM  BYTE offset, so a multi-byte character on a line boundary
REM  gets split and its tail is executed as a command (the
REM  garbled "is not recognized" lines seen in a GBK console).
REM  All Chinese messages are printed by core\startmsg.py.
REM ============================================================
REM  Recommended entry: double-click NetDiag.exe (no console,
REM  no UAC at start, opens the browser automatically).
REM  This file is the Python fallback entry: no exe required,
REM  handy for reading logs / debugging startup problems.
REM  Use "start.bat --admin" when you want UAC up front;
REM  by default it starts with current rights and the UI asks
REM  for elevation only when a mode really needs it.
REM ============================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PY=%ROOT%\tools\python\python.exe"
set "PYARGS="
set "PY_FLAVOR=portable"

REM ---------- 1. Python runtime (bundled first, then system) ----------
REM Order is a hard contract: bundled -> "where python" -> "where py".
if exist "%PY%" goto :have_python

REM Fallback 1: python on PATH (requires 3.11+)
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

REM Fallback 2: Python Launcher, "py -3"
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
echo  [X] No usable Python runtime found (Python 3.11+ required).
echo      Tried: 1) bundled tools\python\python.exe  2) python  3) py -3
echo      Install Python 3.11 or newer and tick "Add python.exe to PATH":
echo      https://www.python.org/downloads/windows/
echo      Or unzip the full offline package that ships tools\python\.
echo.
pause
exit /b 1

:have_python
call :say banner "%ROOT%"
echo.
if /i not "%PY_FLAVOR%"=="portable" (
    call :say portable_fallback "%PYLABEL%"
    echo.
)

REM ---------- 2. Administrator rights (default: do NOT elevate) ----------
REM Why no UAC by default: a UAC prompt at startup is the main cause of
REM "double-click does nothing / feels slow". Modes that need admin ask
REM from the UI; offline analysis and link probing never need it.
net session >nul 2>&1
if not errorlevel 1 goto :have_admin
if /i not "%~1"=="--admin" goto :no_admin_tip
call :say admin_elevating
powershell -NoProfile -Command "try { Start-Process -FilePath '%~f0' -Verb RunAs -ErrorAction Stop; exit 0 } catch { exit 1 }"
if not errorlevel 1 exit /b
call :say admin_cancelled
echo.
goto :have_admin

:no_admin_tip
call :say no_admin
echo.
:have_admin

REM ---------- 3. Environment self-check + per-drive config ----------
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py"
if errorlevel 3 goto :no_tshark
goto :check_npcap

:no_tshark
REM A missing tshark only degrades, it never blocks: the first screen shows
REM what is missing and how to fix it, offline analysis still works. So print
REM one line and keep going (the message text lives in core\startmsg.py).
call :say no_tshark
goto :check_npcap

REM ---------- 4. Npcap driver (detect + interactive install only) ----------
REM Why /S is gone: Npcap free edition does not support silent install (it
REM pops "Silent installation is only supported in Npcap OEM"), so we open
REM the wizard instead of leaving the user with an incomprehensible warning.
:check_npcap
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 goto :npcap_ready

echo.
call :say npcap_missing
for %%f in ("%ROOT%\tools\npcap-*.exe") do (
    call :say npcap_file "%%~nxf"
    call :say npcap_hint
    start /wait "" "%%~f"
)
"%PY%" %PYARGS% "%ROOT%\core\bootstrap.py" --npcap
if not errorlevel 1 (
    call :say npcap_installed
) else (
    call :say npcap_failed
)
goto :launch

:npcap_ready
call :say npcap_ready

REM ---------- 5. Optional: start DeepSeek Harness (agent backend) ----------
:launch
set "HARNESS_FOUND="
if exist "%ROOT%\harness\windows.bat" set "HARNESS_FOUND=1"
for %%f in ("%ROOT%\harness\*.exe") do set "HARNESS_FOUND=1"
if not defined HARNESS_FOUND goto :start_ui

echo.
call :say harness_hint
if /i not "%~1"=="ai" goto :start_ui

if exist "%ROOT%\harness\windows.bat" (
    start "DeepSeek Harness" /D "%ROOT%\harness" cmd.exe /c windows.bat
    goto :start_ui
)
for %%f in ("%ROOT%\harness\*.exe") do (
    call :say harness_start "%%~nxf"
    start "" /D "%ROOT%\harness" "%%~ff"
    goto :start_ui
)

:start_ui

echo.
call :say start_ui
echo.
"%PY%" %PYARGS% "%ROOT%\core\server.py"

echo.
call :say bye
pause
endlocal
goto :eof

REM ---------- helper: print one Chinese message block ----------
REM Usage: call :say <key> [args...]
REM The text lives in core\startmsg.py so this file can stay pure ASCII.
:say
"%PY%" %PYARGS% "%ROOT%\core\startmsg.py" %*
exit /b 0
