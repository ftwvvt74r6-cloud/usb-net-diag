@echo off
REM ============================================================
REM  NetDiag background sampling agent - uninstaller
REM
REM  Deletes the single scheduled task created by install-agent.bat.
REM  It never touches the history data under logs\history\ - delete that
REM  folder manually if you really want the samples gone.
REM
REM  Pure ASCII only, same reason as start.bat.
REM ============================================================
setlocal
set "TASK_NAME=NetDiag Agent"

schtasks /query /tn "%TASK_NAME%" >nul 2>&1
if errorlevel 1 goto :absent

schtasks /delete /tn "%TASK_NAME%" /f
if errorlevel 1 goto :failed

echo.
echo  [OK] Scheduled task "%TASK_NAME%" deleted.
echo       An agent that is already running keeps running until logoff.
echo       Stop it now with:
echo         taskkill /f /im NetDiag-agent.exe
echo       Collected history stays in logs\history\ ^(on purpose^).
echo.
exit /b 0

:absent
echo.
echo  [i] Task "%TASK_NAME%" is not installed - nothing to do.
echo.
exit /b 0

:failed
echo.
echo  [X] Could not delete task "%TASK_NAME%".
echo      Open Task Scheduler and remove it manually.
echo.
exit /b 1
