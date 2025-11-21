@echo off
title Build TasksParser EXE
cd /d "%~dp0"

echo =====================================
echo        Building TasksParser Executable
echo =====================================
echo.

echo Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found in PATH!
    pause
    exit /b 1
)

echo Installing dependencies...
pip install pyinstaller pywebview pythoncom pywin32 >nul 2>&1

echo Cleaning previous builds...
if exist build rmdir /s /q build >nul 2>&1
if exist dist rmdir /s /q dist >nul 2>&1
if exist __pycache__ rmdir /s /q __pycache__ >nul 2>&1
if exist TasksParser.spec del TasksParser.spec >nul 2>&1
if exist PathsParser.spec del PathsParser.spec >nul 2>&1

echo.
echo =====================================
echo     Building Executable...
echo =====================================

REM Check if icon file exists
if exist "tasks.ico" (
    echo Using custom icon: tasks.ico
    set ICON_OPTION=--icon=tasks.ico
) else (
    echo No tasks.ico found - building without custom icon
    set ICON_OPTION=
)

python -m PyInstaller --onefile --windowed %ICON_OPTION% ^
    --name "TasksParser" ^
    --add-data "web;web" ^
    --hidden-import="webview" ^
    --hidden-import="webview.platforms.win32" ^
    --hidden-import="webview.platforms.wince" ^
    --hidden-import="pythoncom" ^
    --hidden-import="win32com" ^
    --hidden-import="win32com.client" ^
    --hidden-import="pywintypes" ^
    --hidden-import="xml.etree.ElementTree" ^
    --hidden-import="xml.etree" ^
    --hidden-import="json" ^
    --hidden-import="threading" ^
    --hidden-import="datetime" ^
    --hidden-import="pathlib" ^
    --hidden-import="re" ^
    --hidden-import="concurrent.futures" ^
    --hidden-import="winreg" ^
    --collect-all="webview" ^
    %ICON_OPTION% ^
    tasksparser.py

if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)

if exist dist\TasksParser.exe (
    echo.
    echo SUCCESS! Built: dist\TasksParser.exe
    echo.
    echo The executable is now completely standalone!
    echo No external dependencies needed - everything is built in.
) else (
    echo ERROR: EXE not created!
)

echo.
pause