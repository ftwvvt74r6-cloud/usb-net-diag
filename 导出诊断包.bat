@echo off
chcp 65001 >nul 2>&1
set "PYTHONIOENCODING=utf-8"
setlocal
title USB-Net-Diag - 导出诊断包
set "ROOT=%~dp0"
if not exist "%ROOT%core\diagnose.py" (
  echo [ERROR] 找不到 %ROOT%core\diagnose.py，请确认本 bat 放在工具根目录。
  pause
  exit /b 1
)
set "PY=%ROOT%tools\python\python.exe"
if not exist "%PY%" set "PY=python"
echo ============================================================
echo   正在导出诊断包（默认脱敏，不会联网、不会上传）...
echo ============================================================
"%PY%" "%ROOT%core\diagnose.py" --export-diag %*
set "RC=%ERRORLEVEL%"
echo.
if not "%RC%"=="0" (
  echo [ERROR] 导出失败，返回码 %RC%。可把上面的错误信息发给维护者。
) else (
  echo 请把上面显示的 zip 文件原样发回给维护者。
)
echo.
pause
exit /b %RC%
