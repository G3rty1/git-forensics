@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Git Forensics

git --version >nul 2>&1
if errorlevel 1 (
  echo Не найден Git. Установите его с https://git-scm.com/download/win и запустите снова.
  pause
  exit /b 1
)

where py >nul 2>&1
if %errorlevel%==0 (
  py ui_server.py
) else (
  python ui_server.py
)
if errorlevel 1 (
  echo.
  echo Не удалось запустить. Проверьте, что установлен Python 3.7 или новее ^(python.org^).
  pause
)
