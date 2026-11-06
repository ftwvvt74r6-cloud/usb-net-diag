@echo off
chcp 65001 >nul 2>&1
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
"%ROOT%\tools\python\python.exe" "%ROOT%\core\bootstrap.py" --check
echo.
pause
