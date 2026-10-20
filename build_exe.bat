@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Сборка GitForensics.exe (нужен интернет для установки PyInstaller)...
where py >nul 2>&1
if %errorlevel%==0 (set PY=py) else (set PY=python)
%PY% -m pip install --upgrade pyinstaller
if errorlevel 1 goto fail
%PY% -m PyInstaller --onefile --name GitForensics --clean ui_server.py
if errorlevel 1 goto fail
echo.
echo Готово: dist\GitForensics.exe
echo Этот один файл можно отправить другому человеку. Ему нужен только Git.
pause
exit /b 0
:fail
echo.
echo Сборка не удалась. Пришлите текст ошибки выше.
pause
exit /b 1
