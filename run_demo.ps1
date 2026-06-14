# ============================================================
#  Paladin - Natalie Romanoff Forensic Demo Runner
#  Usage: .\run_demo.ps1
# ============================================================

$ErrorActionPreference = "Continue"
$env:PYTHONPATH = "."
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PALADIN - Forensic Demo: win7-32-nromanoff-10.3.58.5" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

# --- Check Ollama ---
Write-Host "[1/3] Checking Ollama..." -ForegroundColor Yellow
$ollamaOk = $false
try {
    $r = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -TimeoutSec 3
    $ollamaOk = $true
} catch { }

if (-Not $ollamaOk) {
    Write-Host "  ERROR: Ollama is not running. Start Ollama app first." -ForegroundColor Red
    exit 1
}
$models = ($r.models | ForEach-Object { $_.name }) -join ", "
Write-Host "  OK - Ollama is running. Models: $models" -ForegroundColor Green

# --- Check Docker ---
Write-Host "[2/3] Checking Docker..." -ForegroundColor Yellow
docker ps 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  ERROR: Docker is not running or not accessible." -ForegroundColor Red
    exit 1
}
Write-Host "  OK - Docker is running." -ForegroundColor Green

# --- Check Evidence ---
Write-Host "[3/3] Checking evidence files..." -ForegroundColor Yellow
$evidence = "c:\Users\Lenovo\Downloads\win7-32-nromanoff-10.3.58.5"
if (-Not (Test-Path $evidence)) {
    Write-Host "  ERROR: Evidence folder not found: $evidence" -ForegroundColor Red
    exit 1
}
$fileCount = (Get-ChildItem -Recurse $evidence -File).Count
Write-Host "  OK - Found $fileCount evidence files." -ForegroundColor Green

Write-Host ""
Write-Host "  All checks passed. Starting investigation..." -ForegroundColor Green
Write-Host ""

# --- Run ---
python -X utf8 demo_nromanoff.py
