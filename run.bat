@echo off
cd /d "%~dp0"

:: Check for admin using High Integrity SID (reliable on all Windows 10/11 editions)
whoami /groups 2>nul | find "S-1-16-12288" >nul 2>&1
if %errorlevel% equ 0 goto :run

:: Not admin — re-launch this file elevated using 8.3 short path (no space issues)
powershell -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c %~sdp0run.bat' -Verb RunAs -WorkingDirectory '%~sdp0'" >nul 2>&1
exit /b

:run
echo ============================================
echo  Enterprise DLP System - Starting...
echo ============================================
echo.
echo  Checking dependencies...
pip install -r requirements.txt --quiet --disable-pip-version-check
if errorlevel 1 (
    echo.
    echo  ERROR: Could not install dependencies.
    echo  Make sure Python and pip are installed.
    pause
    exit /b 1
)
echo  Dependencies OK.
echo.
echo  Dashboard : http://localhost:5000
echo  Press Ctrl+C to stop.
echo.
python backend\server.py
pause
