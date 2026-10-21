# ============================================================
#  Paladin - one-command demo launcher
#
#  .\start_demo.ps1              fresh start (empty graph)
#  .\start_demo.ps1 -KeepData    keep incidents from the previous run
#  .\start_demo.ps1 -NoBrowser   do not open the dashboard
#
#  Stops with .\stop_demo.ps1
# ============================================================
param(
    [switch]$KeepData,
    [switch]$NoBrowser
)

# Native tools (docker) write progress to stderr; under "Stop" Windows PowerShell 5.1
# turns that into a terminating error. Exit codes are checked explicitly instead,
# and cmdlets that must not fail use -ErrorAction Stop.
$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

$Python    = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
$Compose   = Join-Path $PSScriptRoot "docker-compose.demo.yml"
$LogDir    = Join-Path $PSScriptRoot "logs"
$PidFile   = Join-Path $LogDir "paladin.pid"
$LogFile   = Join-Path $LogDir "paladin.log"
$ErrFile   = Join-Path $LogDir "paladin.err.log"
$DemoHome  = Join-Path $env:LOCALAPPDATA "PaladinDemo"
$SiftImage = "paladin/sift-sandbox:latest"

function Step([string]$n, [string]$msg) { Write-Host "[$n] $msg" -ForegroundColor Yellow }
function Ok([string]$msg)   { Write-Host "      OK   $msg" -ForegroundColor Green }
function Info([string]$msg) { Write-Host "           $msg" -ForegroundColor Gray }
function Fail([string]$msg) { Write-Host "      FAIL $msg" -ForegroundColor Red; exit 1 }

function Read-DotEnv([string]$path) {
    $map = @{}
    foreach ($line in Get-Content $path) {
        if ($line -match '^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$') { $map[$Matches[1]] = $Matches[2] }
    }
    return $map
}

function Wait-Healthy([string]$container, [int]$timeoutSec) {
    $deadline = (Get-Date).AddSeconds($timeoutSec)
    while ((Get-Date) -lt $deadline) {
        $state = docker inspect --format "{{.State.Health.Status}}" $container 2>$null
        if ($state -eq "healthy") { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "  PALADIN - DEMO LAUNCHER" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# ---- 1. Pre-flight --------------------------------------------------------
Step "1/7" "Pre-flight checks"
if (Test-Path $PidFile) {
    $oldPid = Get-Content $PidFile
    if (Get-Process -Id $oldPid -ErrorAction SilentlyContinue) {
        Fail "Paladin is already running (PID $oldPid). Run .\stop_demo.ps1 first."
    }
}
if (-not (Test-Path $Python)) {
    Fail "No virtualenv. Run: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
}
if (-not (Test-Path ".env")) { Fail ".env not found (see paladin\.env.example)" }
$cfg = Read-DotEnv ".env"
foreach ($k in @("NEO4J_PASSWORD", "POSTGRES_PASSWORD", "DASHBOARD_ADMIN_PASSWORD", "OLLAMA_MODEL")) {
    if (-not $cfg[$k]) { Fail ".env is missing $k" }
}
Ok "virtualenv and .env"

# SpaCy downloads missing models at runtime - that would stall the demo without internet
foreach ($m in @("en_core_web_sm", "xx_ent_wiki_sm")) {
    & $Python -c "import spacy.util, sys; sys.exit(0 if spacy.util.is_package('$m') else 1)"
    if ($LASTEXITCODE -ne 0) {
        Info "installing SpaCy model $m..."
        & $Python -m spacy download $m *> $null
        if ($LASTEXITCODE -ne 0) { Fail "could not install SpaCy model $m (needs internet once)" }
    }
}
Ok "SpaCy models"

docker info *> $null
if ($LASTEXITCODE -ne 0) { Fail "Docker Desktop is not running. Start it and wait for 'Engine running'." }
Ok "Docker"

$ollamaUrl = if ($cfg["OLLAMA_BASE_URL"]) { $cfg["OLLAMA_BASE_URL"] } else { "http://localhost:11434" }
try { $tags = Invoke-RestMethod -Uri "$ollamaUrl/api/tags" -TimeoutSec 5 -ErrorAction Stop }
catch { Fail "Ollama is not reachable at $ollamaUrl. Start Ollama." }
$model = $cfg["OLLAMA_MODEL"]
if (-not ($tags.models | Where-Object { $_.name -eq $model })) { Fail "Model $model is not pulled. Run: ollama pull $model" }
Ok "Ollama with $model"

docker image inspect $SiftImage *> $null
if ($LASTEXITCODE -ne 0) {
    Info "SIFT sandbox image not found - building it (one-time, several minutes)..."
    docker build -t $SiftImage (Join-Path $PSScriptRoot "docker\sift-sandbox")
    if ($LASTEXITCODE -ne 0) { Fail "Could not build $SiftImage" }
}
Ok "SIFT sandbox image"

# ---- 2. Databases -----------------------------------------------------------
Step "2/7" "Starting Neo4j + PostgreSQL (docker-compose.demo.yml)"
if (-not $KeepData) {
    Info "Fresh start: removing previous demo data"
    docker compose -f $Compose down -v *> $null
}
$upLog = docker compose -f $Compose up -d 2>&1
if ($LASTEXITCODE -ne 0) { $upLog | ForEach-Object { Write-Host "           $_" }; Fail "docker compose up failed" }
if (-not (Wait-Healthy "paladin_demo_postgres" 90)) { Fail "PostgreSQL did not become healthy" }
Ok "PostgreSQL  localhost:15432"
if (-not (Wait-Healthy "paladin_demo_neo4j" 180)) { Fail "Neo4j did not become healthy (docker logs paladin_demo_neo4j)" }
Ok "Neo4j       localhost:17687  (browser: http://localhost:17474)"

# ---- 3. Evidence ------------------------------------------------------------
Step "3/7" "Preparing forensic evidence"
# Outside OneDrive so sync never locks files mounted into the sandbox
$evidence = Join-Path $DemoHome "evidence"
$output   = Join-Path $DemoHome "output"
try {
    if (Test-Path $evidence) { Remove-Item -Recurse -Force $evidence -ErrorAction Stop }
    New-Item -ItemType Directory -Force $evidence, $output -ErrorAction Stop | Out-Null
    Copy-Item -Recurse (Join-Path $PSScriptRoot "demo_evidence\files") $evidence -ErrorAction Stop
    Copy-Item -Recurse (Join-Path $PSScriptRoot "demo_evidence\net") $evidence -ErrorAction Stop
} catch { Fail "could not prepare evidence in ${DemoHome}: $($_.Exception.Message)" }
Ok "$evidence (mounted read-only into the sandbox)"

# ---- 4. Warm up the model ---------------------------------------------------
Step "4/7" "Loading $model into memory"
# Same num_ctx as paladin/llm/ollama_client.py, otherwise Ollama reloads the model on first use
$warm = @{ model = $model; prompt = "ok"; stream = $false; think = $false; keep_alive = "60m";
           options = @{ num_ctx = 4096; num_predict = 1 } } | ConvertTo-Json -Depth 4
try {
    Invoke-RestMethod -Uri "$ollamaUrl/api/generate" -Method Post -Body $warm -ContentType "application/json" -TimeoutSec 300 -ErrorAction Stop | Out-Null
    Ok "model loaded (kept for 60 min)"
} catch { Info "warm-up failed ($($_.Exception.Message)) - the first incident will be slower" }

# ---- 5. Start Paladin -------------------------------------------------------
Step "5/7" "Starting Paladin"
New-Item -ItemType Directory -Force $LogDir | Out-Null
$env:FORENSIC_EVIDENCE_BASE = $evidence
$env:FORENSIC_OUTPUT_BASE   = $output
$env:PYTHONIOENCODING       = "utf-8"
$proc = Start-Process -FilePath $Python -ArgumentList "-X", "utf8", "-m", "paladin.main" `
    -RedirectStandardOutput $LogFile -RedirectStandardError $ErrFile -WindowStyle Hidden -PassThru -ErrorAction Stop
$proc.Id | Set-Content $PidFile
Info "PID $($proc.Id), log: logs\paladin.log"

$deadline = (Get-Date).AddSeconds(120)
$ready = $false
while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { break }
    if ((Test-Path $LogFile) -and (Select-String -Path $LogFile -Pattern "paladin_ready" -Quiet)) { $ready = $true; break }
    Start-Sleep -Seconds 1
}
if (-not $ready) {
    Write-Host "----- last log lines -----" -ForegroundColor Red
    if (Test-Path $LogFile) { Get-Content $LogFile -Tail 15 }
    if (Test-Path $ErrFile) { Get-Content $ErrFile -Tail 15 }
    Fail "Paladin did not start"
}
Ok "Paladin is running"

# ---- 6. Smoke test ----------------------------------------------------------
Step "6/7" "Smoke test of the dashboard API"
$smoke = & $Python -c @"
import ssl, json, urllib.request
ctx = ssl._create_unverified_context()
req = urllib.request.Request('https://localhost:8888/api/login', method='POST',
    data=json.dumps({'username': 'admin', 'password': '$($cfg["DASHBOARD_ADMIN_PASSWORD"])'}).encode(),
    headers={'Content-Type': 'application/json'})
tok = json.load(urllib.request.urlopen(req, context=ctx, timeout=10))['access_token']
req = urllib.request.Request('https://localhost:8888/api/status', headers={'Authorization': 'Bearer ' + tok})
s = json.load(urllib.request.urlopen(req, context=ctx, timeout=10))
print('neo4j=%s forensic=%s mode=%s' % (s['neo4j'], s['forensic_enabled'], s['mode']))
"@
if ($LASTEXITCODE -ne 0 -or $smoke -notmatch "neo4j=online") { Fail "API smoke test failed: $smoke" }
Ok $smoke

# ---- 7. Done ----------------------------------------------------------------
Step "7/7" "Ready"
Write-Host ""
Write-Host "  Dashboard : https://localhost:8888" -ForegroundColor Cyan
Write-Host "  Login     : admin / $($cfg['DASHBOARD_ADMIN_PASSWORD'])" -ForegroundColor Cyan
Write-Host "  Stop      : .\stop_demo.ps1" -ForegroundColor Cyan
Write-Host "  Runbook   : DEMO.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "  The certificate is self-signed: in the browser choose Advanced -> Proceed to localhost." -ForegroundColor Gray
if (-not $NoBrowser) { Start-Process "https://localhost:8888" }
