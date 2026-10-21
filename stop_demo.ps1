# ============================================================
#  Paladin - stop the demo
#
#  .\stop_demo.ps1          stop Paladin and the databases (data is kept)
#  .\stop_demo.ps1 -Purge   also delete the demo databases
# ============================================================
param([switch]$Purge)

Set-Location $PSScriptRoot
$PidFile = Join-Path $PSScriptRoot "logs\paladin.pid"
$Compose = Join-Path $PSScriptRoot "docker-compose.demo.yml"

if (Test-Path $PidFile) {
    $procId = Get-Content $PidFile
    if (Get-Process -Id $procId -ErrorAction SilentlyContinue) {
        Stop-Process -Id $procId -Force
        Write-Host "Paladin stopped (PID $procId)" -ForegroundColor Green
    }
    Remove-Item $PidFile -Force
} else {
    Write-Host "Paladin is not running" -ForegroundColor Gray
}

# Forensic sandboxes of an interrupted investigation (labelled by SandboxManager)
$sandboxes = docker ps -aq --filter "label=paladin.sandbox=true"
if ($sandboxes) {
    docker rm -f $sandboxes | Out-Null
    Write-Host "Removed $(@($sandboxes).Count) forensic sandbox(es)" -ForegroundColor Green
}

if ($Purge) {
    docker compose -f $Compose down -v
    Write-Host "Demo databases deleted" -ForegroundColor Green
} else {
    docker compose -f $Compose stop
    Write-Host "Demo databases stopped (data kept; start with .\start_demo.ps1 -KeepData)" -ForegroundColor Green
}
