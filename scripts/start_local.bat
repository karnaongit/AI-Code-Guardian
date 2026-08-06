@echo off
REM AI Code Guardian v3 Local Startup Script

cd /d "%~dp0\.."

echo Checking health of local services...
python scripts\healthcheck.py

echo Initializing database schema...
python scripts\seed_db.py

echo Starting FastAPI Backend (Port 8000)...
start "ACG Backend" cmd /c "uvicorn backend.app.main:app --reload --port 8000"

echo Starting React Frontend (Port 5173)...
cd frontend
start "ACG Frontend" cmd /c "npm run dev"

cd ..
echo.
echo =========================================
echo 🚀 Environment is running!
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173
echo =========================================
echo Check the newly opened terminal windows.
echo Close those windows to stop the services.
