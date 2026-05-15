@echo off
echo ============================================
echo  DLP System - Setup
echo ============================================
echo.

where python >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

echo Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo ERROR: pip install failed. Check your internet connection.
    pause
    exit /b 1
)

echo.
echo Creating required folders...
if not exist monitor    mkdir monitor
if not exist quarantine mkdir quarantine
if not exist backend    mkdir backend
if not exist frontend   mkdir frontend

echo.
echo ============================================
echo  Setup complete!
echo.
echo  To start:  run.bat  (or: python backend/server.py)
echo  Dashboard: http://localhost:5000
echo.
echo  NOTE: For Network DLP packet inspection,
echo        install Npcap from https://npcap.com
echo        and run as Administrator.
echo ============================================
pause
