# Run Script for SOC Co-Pilot POC
# This script activates the virtual environment and starts the FastAPI server.

Write-Host "=============================================" -ForegroundColor Cyan
Write-Host "         Launching SOC Co-Pilot POC          " -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Check if virtual environment exists
if (-not (Test-Path ".\venv")) {
    Write-Error "Virtual environment not found. Please create it first by running: python -m venv venv"
    exit 1
}

Write-Host "Activating virtual environment..." -ForegroundColor Yellow
. .\venv\Scripts\Activate.ps1

Write-Host "Starting FastAPI server with Uvicorn..." -ForegroundColor Yellow
Write-Host "You can access the UI dashboard at: http://127.0.0.1:8000" -ForegroundColor Green
Write-Host "Press Ctrl+C to terminate the server." -ForegroundColor Gray
Write-Host ""

uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir app --reload-dir templates --reload-dir static
