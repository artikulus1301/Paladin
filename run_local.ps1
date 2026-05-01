# RAG Bot Local Runner for Windows
# This script starts the infrastructure (Neo4j, Ollama, SearXNG) via Docker
# and runs the Python bot locally.

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot


Write-Host "--- RICHTER Local Setup & Run ---" -ForegroundColor Cyan

# 1. Check Dependencies
Write-Host "[1/6] Checking dependencies..." -ForegroundColor Yellow
if (!(Get-Command python -ErrorAction SilentlyContinue)) {
    Write-Error "Python is not installed. Please install Python 3.10+ from python.org"
}
if (!(Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Error "Docker is not installed or not in PATH. Please install Docker Desktop."
}

# 1.1 Check if Docker Daemon is running
Write-Host "[1.1/6] Checking Docker status..." -ForegroundColor Yellow
try {
    docker ps > $null 2>&1
    if ($LASTEXITCODE -ne 0) { throw "Docker daemon is not responding." }
}
catch {
    Write-Host "`n[!] ERROR: Docker Desktop is not running or not accessible." -ForegroundColor Red
    Write-Host "Please start Docker Desktop and wait until it says 'Engine running'." -ForegroundColor White
    Write-Host "Then run this script again.`n" -ForegroundColor White
    exit
}

# 2. Check .env file
$EnvPath = Join-Path $PSScriptRoot ".env"
$EnvExamplePath = Join-Path $PSScriptRoot ".env.example"

Write-Host "[2/6] Checking configuration..." -ForegroundColor Yellow
if (!(Test-Path $EnvPath)) {
    Write-Host "[!] .env file not found at $EnvPath. Creating from .env.example..." -ForegroundColor Red
    if (Test-Path $EnvExamplePath) {
        Copy-Item $EnvExamplePath $EnvPath
        Write-Host "[!] Created .env. Please add your TELEGRAM_TOKEN and run again." -ForegroundColor Magenta
        exit
    }
    else {
        Write-Error ".env.example not found at $EnvExamplePath. Please create a .env file with TELEGRAM_TOKEN manually."
    }
}
else {
    Write-Host "OK: .env found." -ForegroundColor Gray
}


# 3. Start Infrastructure
Write-Host "[3/6] Starting Infrastructure (Neo4j, Ollama, SearXNG) via Docker..." -ForegroundColor Yellow
docker-compose up -d neo4j ollama searxng ollama-init
Write-Host "Services are starting in the background. Note: Ollama may take time to pull models (~5GB)." -ForegroundColor Gray

# 4. Setup Python Environment
Write-Host "[3/6] Setting up Virtual Environment..." -ForegroundColor Yellow
if (!(Test-Path venv)) {
    python -m venv venv
}

# Activate venv
$VENV_PATH = "$PSScriptRoot\venv\Scripts\Activate.ps1"
. $VENV_PATH

# 5. Install Requirements
Write-Host "[4/6] Installing Python dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip
pip install -r requirements.txt

# 6. Download SpaCy Models
Write-Host "[5/6] Downloading SpaCy models..." -ForegroundColor Yellow
python -m spacy download ru_core_news_sm
python -m spacy download en_core_web_sm
python -m spacy download xx_ent_wiki_sm

# 7. Run Bot
Write-Host "[6/6] Starting the Bot..." -ForegroundColor Green
Write-Host "Press Ctrl+C to stop." -ForegroundColor Gray
$env:PYTHONPATH = $PSScriptRoot
python app/main.py
