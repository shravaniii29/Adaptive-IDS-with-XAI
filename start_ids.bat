@echo off
REM ===========================================================
REM  Adaptive IDS - one-click launcher
REM  Double-click to start the backend AND the dashboard, then
REM  open the dashboard in your browser.
REM
REM  If the dashboard shows NO flows, close everything and
REM  right-click this file -> "Run as administrator"
REM  (live packet capture may need admin, depending on your
REM  Npcap install).
REM ===========================================================

title Adaptive IDS launcher

REM Work from this file's own folder, wherever it is clicked from.
cd /d "%~dp0"

echo.
echo  Starting the IDS backend (http://127.0.0.1:8000) ...
start "IDS Backend" cmd /k python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

echo  Starting the dashboard (http://localhost:5173) ...
start "IDS Dashboard" cmd /k npm --prefix frontend run dev

echo  Waiting for the dashboard to come up ...
timeout /t 10 /nobreak >nul

start "" http://localhost:5173

echo.
echo  ===========================================================
echo   Backend:   http://127.0.0.1:8000
echo   Dashboard: http://localhost:5173
echo.
echo   Two windows opened: "IDS Backend" and "IDS Dashboard".
echo   Close those two windows to stop the IDS.
echo   You can close THIS window now.
echo  ===========================================================
echo.
pause
