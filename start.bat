@echo off
REM Sentinel OSINT launcher (Windows)
cd /d "%~dp0"
echo Installing dependencies...
pip install -r backend\requirements.txt
echo Starting Sentinel OSINT on http://127.0.0.1:8000
echo (the first-run admin password is printed once in this window)
python run.py
pause
