# AegisNIDS Unified Launch Script for Hackathon
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   AegisNIDS // Two-Layer Autonomous Defense System       " -ForegroundColor Yellow
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check & Launch Flask API
Write-Host "[1/2] Launching Layer 1 ML Engine (Port 5000)..." -ForegroundColor Green
$flaskDir = Join-Path $PSScriptRoot "src\flask-api"
$flaskPython = Join-Path $flaskDir ".venv\Scripts\python.exe"

if (Test-Path $flaskPython) {
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd '$flaskDir'; & '$flaskPython' run.py" -WindowStyle Minimized
} else {
    Write-Host "Virtual environment not found, creating with uv..." -ForegroundColor Yellow
    & "uv" venv "$flaskDir\.venv" --python 3.11
    & "uv" pip install -r "$flaskDir\requirements.txt" flask-cors --python "$flaskPython"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd '$flaskDir'; & '$flaskPython' run.py" -WindowStyle Minimized
}

Start-Sleep -Seconds 2

# 2. Launch React Dashboard
Write-Host "[2/2] Launching React SOC Monitoring Center (Port 3000)..." -ForegroundColor Green
$frontendDir = Join-Path $PSScriptRoot "src\frontend\my-app"
Start-Process -FilePath "powershell.exe" -ArgumentList "-NoExit", "-Command", "cd '$frontendDir'; npm start" -WindowStyle Minimized

Write-Host ""
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " System is running and active!" -ForegroundColor Green
Write-Host " Dashboard:  http://localhost:3000" -ForegroundColor White
Write-Host " ML Engine:  http://localhost:5000/health" -ForegroundColor White
Write-Host "==========================================================" -ForegroundColor Cyan
