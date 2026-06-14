# ============================================================
#  Paladin v2.0 - Full Showcase Demo Runner
#  Usage: .\run_full_showcase.ps1 [Phase]
#  Examples:
#    .\run_full_showcase.ps1
#    .\run_full_showcase.ps1 all
#    .\run_full_showcase.ps1 forensic
#    .\run_full_showcase.ps1 ingestion
# ============================================================

param (
    [string]$Phase = "all"
)

$ErrorActionPreference = "Continue"
$env:PYTHONPATH = "."
$env:PYTHONUTF8 = "1"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PALADIN v2.0 - FULL SHOWCASE DEMO" -ForegroundColor Cyan
Write-Host "  Phase: $Phase" -ForegroundColor Cyan
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
    Write-Host "  WARNING: Ollama is not running on port 11434." -ForegroundColor Yellow
} else {
    $models = ($r.models | ForEach-Object { $_.name }) -join ", "
    Write-Host "  OK - Ollama is running. Models: $models" -ForegroundColor Green
}

# --- Check Docker ---
Write-Host "[2/3] Checking Docker..." -ForegroundColor Yellow
docker ps 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "  WARNING: Docker is not running or not accessible." -ForegroundColor Yellow
} else {
    Write-Host "  OK - Docker is running." -ForegroundColor Green
}

# --- Check Evidence ---
Write-Host "[3/3] Checking evidence files..." -ForegroundColor Yellow
$evidence = "c:\Users\Lenovo\Downloads\win7-32-nromanoff-10.3.58.5"
if (-Not (Test-Path $evidence)) {
    Write-Host "  WARNING: Evidence folder not found: $evidence" -ForegroundColor Yellow
    Write-Host "  Forensic phase will run without real files." -ForegroundColor Yellow
} else {
    $fileCount = (Get-ChildItem -Recurse $evidence -File).Count
    Write-Host "  OK - Found $fileCount evidence files." -ForegroundColor Green
}

Write-Host ""
Write-Host "  Starting showcase ($Phase)..." -ForegroundColor Green
Write-Host ""

# --- Run ---
python -X utf8 demo_full_showcase.py --phase $Phase --timeout 5
