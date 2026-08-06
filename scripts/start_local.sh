#!/bin/bash
# AI Code Guardian v3 Local Startup Script

set -e

# Change to project root
cd "$(dirname "$0")/.."

echo "Checking health of local services..."
python3 scripts/healthcheck.py || true

echo "Initializing database schema..."
python3 scripts/seed_db.py

echo "Starting FastAPI Backend (Port 8000)..."
# Start the backend in the background
if [ -d ".venv" ]; then
    .venv/bin/uvicorn backend.app.main:app --reload --port 8000 &
else
    uvicorn backend.app.main:app --reload --port 8000 &
fi
BACKEND_PID=$!

echo "Starting React Frontend (Port 5173)..."
# Start the frontend in the background
cd frontend
npm run dev &
FRONTEND_PID=$!

cd ..

echo ""
echo "🚀 Environment is running!"
echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:5173"
echo "Press Ctrl+C to stop all services."

# Trap Ctrl+C (SIGINT) to kill background processes
trap "echo '\nShutting down...'; kill $BACKEND_PID $FRONTEND_PID; exit" SIGINT SIGTERM

# Wait for background processes
wait
