@echo off
setlocal EnableExtensions EnableDelayedExpansion
title NetDiag Self-Check

REM ============================================================
REM  NetDiag portable self-check (ASCII only, no codepage tricks)
REM  Usage:  double-click, or pass --no-pause for an unattended run
REM  Exit :  0 = usable, 1 = not usable
REM ============================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PY=%ROOT%\tools\python\python.exe"
set "TSHARK=%ROOT%\tools\WiresharkPortable\App\Wireshark\tshark.exe"
set "PY_OK=0"
set "DEMO_OUT="
set "NPCAP_SETUP=npcap-1.79.exe"
set "PYTHONIOENCODING=utf-8"
set "PAUSE_AT_END=1"
if /i "%~1"=="--no-pause" set "PAUSE_AT_END=0"

set /a PASSES=0
set /a WARNS=0
set /a FAILS=0

set "VER=unknown"
if exist "%ROOT%\VERSION" for /f "usebackq delims=" %%v in ("%ROOT%\VERSION") do set "VER=%%v"

echo ============================================================
echo  NetDiag portable self-check
echo  Version : %VER%
echo  Folder  : %ROOT%
echo ============================================================
echo.

call :check_python
call :check_tshark
call :check_npcap
call :check_admin
call :check_demo
call :check_logs
goto :summary

REM ------------------------------------------------------------
:check_python
if not exist "%PY%" goto :cp_missing
"%PY%" -c "import sys;print(sys.version.split()[0])" > "%TEMP%\netdiag_pyver.txt" 2>&1
if errorlevel 1 goto :cp_broken
set /p PYVER=<"%TEMP%\netdiag_pyver.txt"
set "PY_OK=1"
call :pass "Python runtime" "%PY% (version %PYVER%)"
exit /b
:cp_missing
call :fail "Python runtime" "not found: %PY%  [package incomplete - re-extract the zip]"
exit /b
:cp_broken
call :fail "Python runtime" "%PY% exists but cannot run (see %TEMP%\netdiag_pyver.txt)"
exit /b

REM ------------------------------------------------------------
:check_tshark
if not exist "%TSHARK%" goto :ct_missing
"%TSHARK%" --version > "%TEMP%\netdiag_tshark_ver.txt" 2>&1
if errorlevel 1 goto :ct_broken
set /p TSHVER=<"%TEMP%\netdiag_tshark_ver.txt"
call :pass "tshark (offline analysis)" "%TSHARK%"
echo          %TSHVER%
exit /b
:ct_missing
call :fail "tshark (offline analysis)" "not found: %TSHARK%  [WiresharkPortable incomplete]"
exit /b
:ct_broken
call :fail "tshark (offline analysis)" "%TSHARK% cannot run (see %TEMP%\netdiag_tshark_ver.txt)"
exit /b

REM ------------------------------------------------------------
:check_npcap
if exist "%SystemRoot%\System32\Npcap\Packet.dll" goto :cn_yes
if exist "%SystemRoot%\System32\Packet.dll" goto :cn_yes
for %%f in ("%ROOT%\tools\npcap-*.exe") do set "NPCAP_SETUP=%%~nxf"
call :warn "Npcap driver (live capture)" "not installed - run tools\%NPCAP_SETUP% to install (offline analysis still works)"
call :echo_installer_hint
exit /b
:cn_yes
call :pass "Npcap driver (live capture)" "installed"
exit /b

:echo_installer_hint
echo          Installer: %ROOT%\tools\%NPCAP_SETUP%
echo          Note: Npcap is a third-party component - read docs\licensing.md first.
exit /b

REM ------------------------------------------------------------
:check_admin
net session >nul 2>&1
if not errorlevel 1 goto :ca_yes
fsutil dirty query %SystemDrive% >nul 2>&1
if not errorlevel 1 goto :ca_yes
call :warn "Administrator rights (live capture)" "not elevated - live capture unavailable, offline analysis still works"
exit /b
:ca_yes
call :pass "Administrator rights (live capture)" "elevated"
exit /b

REM ------------------------------------------------------------
:check_demo
if not "%PY_OK%"=="1" goto :cd_nopy
if not exist "%ROOT%\captures\faults_demo.pcap" goto :cd_nopcap
if not exist "%TSHARK%" goto :cd_notshark
set "DEMO_OUT=%TEMP%\netdiag-selfcheck-%RANDOM%%RANDOM%"
mkdir "%DEMO_OUT%" >nul 2>&1
if not exist "%DEMO_OUT%" goto :cd_noout
"%PY%" "%ROOT%\core\diagnose.py" --pcap "%ROOT%\captures\faults_demo.pcap" --report-out "%DEMO_OUT%" --json > "%DEMO_OUT%\summary.txt" 2>&1
if errorlevel 1 goto :cd_failed
"%PY%" -c "import json,sys;t=open(sys.argv[1],encoding='utf-8').read().strip().splitlines();d=json.loads(t[-1]);print('critical='+str(d.get('critical_count'))+' warning='+str(d.get('warning_count')));sys.exit(0 if d.get('critical_count')==3 and d.get('warning_count')==5 else 3)" "%DEMO_OUT%\summary.txt" > "%DEMO_OUT%\counts.txt" 2>&1
if errorlevel 1 goto :cd_badcounts
set /p COUNTS=<"%DEMO_OUT%\counts.txt"
if not "%COUNTS%"=="critical=3 warning=5" goto :cd_badcounts
call :pass "Offline analysis demo" "faults_demo.pcap: %COUNTS%"
echo          Report: %DEMO_OUT%\faults_demo.md
exit /b
:cd_nopy
call :fail "Offline analysis demo" "skipped: Python runtime is not available"
exit /b
:cd_nopcap
call :fail "Offline analysis demo" "missing captures\faults_demo.pcap"
exit /b
:cd_notshark
call :fail "Offline analysis demo" "skipped: tshark is not available"
exit /b
:cd_noout
call :fail "Offline analysis demo" "cannot create temp folder: %DEMO_OUT%"
exit /b
:cd_failed
call :fail "Offline analysis demo" "diagnose.py exited non-zero (see %DEMO_OUT%\summary.txt)"
exit /b
:cd_badcounts
call :fail "Offline analysis demo" "expected critical=3 warning=5, got: %COUNTS%  (see %DEMO_OUT%\summary.txt)"
exit /b

REM ------------------------------------------------------------
:check_logs
if not "%PY_OK%"=="1" goto :cl_nopy
if not exist "%ROOT%\logs\env.json" goto :cl_nolog
if not exist "%DEMO_OUT%\faults_demo.md" goto :cl_noreport
if not exist "%DEMO_OUT%\faults_demo.json" goto :cl_noreport
call :pass "Run logging and report output" "logs\env.json + faults_demo.md/.json written"
exit /b
:cl_nopy
call :fail "Run logging and report output" "skipped: Python runtime is not available"
exit /b
:cl_nolog
call :fail "Run logging and report output" "logs\env.json not written - logging is broken"
exit /b
:cl_noreport
call :fail "Run logging and report output" "report files missing in %DEMO_OUT%"
exit /b

REM ------------------------------------------------------------
:summary
echo.
echo ------------------------------------------------------------
echo  PASS: %PASSES%    WARN: %WARNS%    FAIL: %FAILS%
if not "%FAILS%"=="0" goto :not_usable
echo  RESULT: USABLE
if not "%WARNS%"=="0" echo  NOTE: live capture may be limited (see WARN lines); offline analysis is ready.
echo ------------------------------------------------------------
set "RC=0"
goto :finish
:not_usable
echo  RESULT: NOT USABLE
echo  Fix the FAIL lines above, then run this check again.
echo  Details: docs\build.md  and  docs\licensing.md
echo ------------------------------------------------------------
set "RC=1"
goto :finish

REM ------------------------------------------------------------
:pass
set /a PASSES+=1
echo  [PASS] %~1
echo          %~2
exit /b
:warn
set /a WARNS+=1
echo  [WARN] %~1
echo          %~2
exit /b
:fail
set /a FAILS+=1
echo  [FAIL] %~1
echo          %~2
exit /b

:finish
echo.
if "%PAUSE_AT_END%"=="1" pause
endlocal & exit /b %RC%
