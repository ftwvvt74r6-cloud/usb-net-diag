@echo off
REM ============================================================
REM  NetDiag background sampling agent - installer
REM
REM  Creates exactly ONE scheduled task (logon trigger, 1 min delay,
REM  normal rights). No Windows service, no UAC prompt, nothing written
REM  outside the project folder.
REM
REM  This file MUST stay pure ASCII (every byte < 0x80). Reason: cmd
REM  keeps reading a batch file by BYTE offset after "chcp 65001", so a
REM  multi-byte character on a line boundary gets split and executed as
REM  a command. Same constraint as start.bat.
REM ============================================================
setlocal
set "TASK_NAME=NetDiag Agent"
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

if exist "%ROOT%\NetDiag-agent.exe" goto :install_exe
if exist "%ROOT%\tools\python\pythonw.exe" goto :install_py
goto :no_runner

:install_exe
REM Preferred: dedicated exe, no console window at all.
schtasks /create /tn "%TASK_NAME%" /sc onlogon /delay 0001:00 /tr "\"%ROOT%\NetDiag-agent.exe\" --daemon" /rl limited /f
goto :check

:install_py
REM Fallback: portable pythonw next to core\agent.py. pythonw has no console.
schtasks /create /tn "%TASK_NAME%" /sc onlogon /delay 0001:00 /tr "\"%ROOT%\tools\python\pythonw.exe\" \"%ROOT%\core\agent.py\" --daemon" /rl limited /f
goto :check

:no_runner
echo.
echo  [X] No runnable agent found.
echo      Expected one of:
echo        1^) %ROOT%\NetDiag-agent.exe
echo        2^) %ROOT%\tools\python\pythonw.exe  ^(portable runtime^)
echo.
exit /b 1

:check
if errorlevel 1 goto :failed
echo.
echo  [OK] Scheduled task "%TASK_NAME%" created.
echo       Trigger: at logon, 1 minute delay. Rights: limited ^(no UAC^).
echo       Start it now without logging off:
echo         schtasks /run /tn "%TASK_NAME%"
echo       Remove it later with uninstall-agent.bat
echo.
exit /b 0

:failed
echo.
echo  [X] schtasks failed. Check the message above.
echo      Run this file from a normal cmd window ^(not elevated PowerShell^).
echo      /f replaces an existing task with the same name.
echo.
exit /b 1
