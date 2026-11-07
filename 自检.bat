@echo off
setlocal EnableExtensions EnableDelayedExpansion
title NetDiag Self-Check

REM ============================================================
REM  NetDiag self-check (ASCII only, no codepage tricks)
REM  Works for both package types:
REM    - public lite package : source only, uses system Python
REM    - internal offline pkg: bundled tools\python + Wireshark
REM  Usage:  double-click, or pass --no-pause for an unattended run
REM  Exit :  0 = usable, 1 = not usable
REM ============================================================

set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "PY="
set "PYARGS="
set "PY_KIND="
set "PY_OK=0"
set "TSHARK="
set "TSHARK_OK=0"
set "NPCAP_OK=0"
set "DEMO_OK=0"
set "DEMO_OUT="
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
call :check_source
call :check_tshark
call :check_npcap
call :check_admin
call :check_demo
call :check_logs
goto :summary

REM ------------------------------------------------------------
:check_python
if exist "%ROOT%\tools\python\python.exe" (
    set "PY=%ROOT%\tools\python\python.exe"
    set "PY_KIND=packaged"
    goto :cp_probe
)
where python >nul 2>&1
if not errorlevel 1 (
    for /f "delims=" %%p in ('where python 2^>nul') do if not defined PY set "PY=%%p"
    if defined PY set "PY_KIND=system"
)
if not defined PY (
    where py >nul 2>&1
    if not errorlevel 1 (
        set "PY=py"
        set "PYARGS=-3"
        set "PY_KIND=system py launcher"
    )
)
if not defined PY goto :cp_missing

:cp_probe
"%PY%" %PYARGS% -c "import sys;print(sys.version.split()[0])" > "%TEMP%\netdiag_pyver.txt" 2>&1
if errorlevel 1 goto :cp_broken
set /p PYVER=<"%TEMP%\netdiag_pyver.txt"
set "PY_OK=1"
call :pass "Python runtime" "%PY% %PYARGS% - version %PYVER%, %PY_KIND%"
exit /b
:cp_missing
call :fail "Python runtime" "Python 3.11+ not found. Install it from https://www.python.org/downloads/windows/ and enable Add python.exe to PATH."
exit /b
:cp_broken
call :fail "Python runtime" "%PY% %PYARGS% exists but cannot run - see %TEMP%\netdiag_pyver.txt"
exit /b

REM ------------------------------------------------------------
:check_source
if not "%PY_OK%"=="1" goto :cs_nopy
"%PY%" %PYARGS% -c "import sys;sys.path.insert(0,r'%ROOT%');sys.path.insert(0,r'%ROOT%\core');import analyzer,verdict,report,diagnose;print('core modules import OK')" > "%TEMP%\netdiag_imports.txt" 2>&1
if errorlevel 1 goto :cs_fail
call :pass "Source tree" "core modules import OK - analyzer / verdict / report / diagnose"
exit /b
:cs_nopy
call :warn "Source tree" "skipped: Python runtime is not available"
exit /b
:cs_fail
call :fail "Source tree" "cannot import core modules - see %TEMP%\netdiag_imports.txt"
exit /b

REM ------------------------------------------------------------
:check_tshark
if "%PY_OK%"=="1" goto :ct_pyfind
if exist "%ROOT%\tools\WiresharkPortable\App\Wireshark\tshark.exe" (
    set "TSHARK=%ROOT%\tools\WiresharkPortable\App\Wireshark\tshark.exe"
    goto :ct_found
)
if defined TSHARK_PATH if exist "%TSHARK_PATH%" (
    set "TSHARK=%TSHARK_PATH%"
    goto :ct_found
)
where tshark >nul 2>&1
if errorlevel 1 goto :ct_missing
for /f "delims=" %%t in ('where tshark 2^>nul') do if not defined TSHARK set "TSHARK=%%t"
goto :ct_found

:ct_pyfind
"%PY%" %PYARGS% -c "import sys;sys.path.insert(0,r'%ROOT%\core');import tshark;p=tshark.find_tshark();print(str(p) if p else '')" > "%TEMP%\netdiag_tshark_path.txt" 2>&1
if errorlevel 1 goto :ct_missing
set /p TSHARK=<"%TEMP%\netdiag_tshark_path.txt"
if not defined TSHARK goto :ct_missing

:ct_found
"%TSHARK%" --version > "%TEMP%\netdiag_tshark_ver.txt" 2>&1
if errorlevel 1 goto :ct_broken
set /p TSHVER=<"%TEMP%\netdiag_tshark_ver.txt"
set "TSHARK_OK=1"
call :pass "tshark (offline analysis)" "%TSHARK%"
echo          %TSHVER%
exit /b
:ct_missing
call :warn "tshark (offline analysis)" "not found. Offline analysis needs tshark: install Wireshark from https://www.wireshark.org/download.html or set TSHARK_PATH to tshark.exe."
exit /b
:ct_broken
call :fail "tshark (offline analysis)" "%TSHARK% cannot run - see %TEMP%\netdiag_tshark_ver.txt"
exit /b

REM ------------------------------------------------------------
:check_npcap
if exist "%SystemRoot%\System32\Npcap\Packet.dll" goto :cn_yes
if exist "%SystemRoot%\System32\Packet.dll" goto :cn_yes
if exist "%SystemRoot%\System32\wpcap.dll" goto :cn_yes
if exist "%SystemRoot%\System32\drivers\npcap.sys" goto :cn_yes
set "NPCAP_SETUP="
for %%f in ("%ROOT%\tools\npcap-*.exe") do if exist "%%~ff" set "NPCAP_SETUP=%%~ff"
if defined NPCAP_SETUP goto :cn_bundled
call :warn "Npcap driver (live capture)" "not installed. Download and install it from https://npcap.com/#download - live capture only, offline analysis does not need Npcap."
exit /b
:cn_bundled
call :warn "Npcap driver (live capture)" "not installed. This internal package bundles an installer: %NPCAP_SETUP% - run it manually; internal use only."
exit /b
:cn_yes
set "NPCAP_OK=1"
call :pass "Npcap driver (live capture)" "installed"
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
if not "%TSHARK_OK%"=="1" goto :cd_notshark
if not exist "%ROOT%\captures\faults_demo.pcap" goto :cd_nopcap
set "DEMO_OUT=%TEMP%\netdiag-selfcheck-%RANDOM%%RANDOM%"
mkdir "%DEMO_OUT%" >nul 2>&1
if not exist "%DEMO_OUT%" goto :cd_noout
"%PY%" %PYARGS% "%ROOT%\core\diagnose.py" --pcap "%ROOT%\captures\faults_demo.pcap" --report-out "%DEMO_OUT%" --json > "%DEMO_OUT%\summary.txt" 2>&1
if errorlevel 1 goto :cd_failed
"%PY%" %PYARGS% -c "import json,sys;t=open(sys.argv[1],encoding='utf-8').read().strip().splitlines();d=json.loads(t[-1]);print('critical='+str(d.get('critical_count'))+' warning='+str(d.get('warning_count')));sys.exit(0 if d.get('critical_count')==3 and d.get('warning_count')==5 else 3)" "%DEMO_OUT%\summary.txt" > "%DEMO_OUT%\counts.txt" 2>&1
if errorlevel 1 goto :cd_badcounts
set /p COUNTS=<"%DEMO_OUT%\counts.txt"
if not "%COUNTS%"=="critical=3 warning=5" goto :cd_badcounts
set "DEMO_OK=1"
call :pass "Offline analysis demo" "faults_demo.pcap: %COUNTS%"
echo          Report: %DEMO_OUT%\faults_demo.md
exit /b
:cd_nopy
call :warn "Offline analysis demo" "skipped: Python runtime is not available"
exit /b
:cd_notshark
call :warn "Offline analysis demo" "skipped: tshark is not available - install Wireshark or set TSHARK_PATH"
exit /b
:cd_nopcap
call :fail "Offline analysis demo" "missing captures\faults_demo.pcap"
exit /b
:cd_noout
call :fail "Offline analysis demo" "cannot create temp folder: %DEMO_OUT%"
exit /b
:cd_failed
call :fail "Offline analysis demo" "diagnose.py exited non-zero - see %DEMO_OUT%\summary.txt"
exit /b
:cd_badcounts
call :fail "Offline analysis demo" "expected critical=3 warning=5, got: %COUNTS% - see %DEMO_OUT%\summary.txt"
exit /b

REM ------------------------------------------------------------
:check_logs
if not "%PY_OK%"=="1" goto :cl_nopy
if not "%DEMO_OK%"=="1" goto :cl_nodemo
if not exist "%ROOT%\logs\env.json" goto :cl_nolog
if not exist "%DEMO_OUT%\faults_demo.md" goto :cl_noreport
if not exist "%DEMO_OUT%\faults_demo.json" goto :cl_noreport
call :pass "Run logging and report output" "logs\env.json + faults_demo.md/.json written"
exit /b
:cl_nopy
call :warn "Run logging and report output" "skipped: Python runtime is not available"
exit /b
:cl_nodemo
call :warn "Run logging and report output" "skipped: offline demo did not run"
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
if not "%TSHARK_OK%"=="1" echo  NOTE: offline analysis needs tshark - see the WARN line above.
if not "%NPCAP_OK%"=="1" echo  NOTE: live capture needs Npcap - see the WARN line above.
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
