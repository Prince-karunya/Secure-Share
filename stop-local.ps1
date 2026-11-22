$ErrorActionPreference = "Stop"
$pidFile = Join-Path $PSScriptRoot ".local-server.pid"

if (-not (Test-Path $pidFile)) {
    Write-Host "No SecureShare local server PID file found."
    exit 0
}

$serverId = [int](Get-Content $pidFile -Raw)
$server = Get-CimInstance Win32_Process -Filter "ProcessId = $serverId" -ErrorAction SilentlyContinue
if (-not $server) {
    Remove-Item $pidFile
    Write-Host "SecureShare server was already stopped."
    exit 0
}

if ($server.CommandLine -notmatch 'manage\.py.*runserver 127\.0\.0\.1:8000 --noreload') {
    throw "PID $serverId is not the expected SecureShare localhost server; refusing to stop it."
}

Stop-Process -Id $serverId
Remove-Item $pidFile
Write-Host "SecureShare local server stopped."
