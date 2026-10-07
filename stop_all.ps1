# AegisNIDS Stop Script
Write-Host "Stopping AegisNIDS services..." -ForegroundColor Yellow

$port5000 = Get-NetTCPConnection -LocalPort 5000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique
$port3000 = Get-NetTCPConnection -LocalPort 3000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique

if ($port5000) {
    Stop-Process -Id $port5000 -Force -ErrorAction SilentlyContinue
    Write-Host "Terminated Flask API (PID: $port5000)" -ForegroundColor Green
}

if ($port3000) {
    Stop-Process -Id $port3000 -Force -ErrorAction SilentlyContinue
    Write-Host "Terminated React Dashboard (PID: $port3000)" -ForegroundColor Green
}

Write-Host "All NIDS services stopped." -ForegroundColor Cyan
