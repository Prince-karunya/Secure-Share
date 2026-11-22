$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$python = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    throw "Virtual environment not found. Create it and install dependencies first: py -m venv .venv; .\.venv\Scripts\python.exe -m pip install -r requirements.txt"
}

$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue
if ($listener) {
    throw "Port 8000 is already in use. Stop that server first, or update start-local.ps1 to use another port."
}

Remove-Item Env:SHARE_BASE_URL -ErrorAction SilentlyContinue
$env:DJANGO_ALLOWED_HOSTS = "127.0.0.1,localhost"

& $python manage.py migrate --noinput
if ($LASTEXITCODE -ne 0) {
    throw "Database migrations failed; the local server was not started."
}

$server = Start-Process `
    -FilePath $python `
    -ArgumentList @("manage.py", "runserver", "127.0.0.1:8000", "--noreload") `
    -WorkingDirectory $PSScriptRoot `
    -PassThru `
    -WindowStyle Hidden
Set-Content -Path (Join-Path $PSScriptRoot ".local-server.pid") -Value $server.Id

$ready = $false
for ($attempt = 0; $attempt -lt 30; $attempt++) {
    if ($server.HasExited) {
        Remove-Item (Join-Path $PSScriptRoot ".local-server.pid") -ErrorAction SilentlyContinue
        throw "Django exited before it became ready. Run .\.venv\Scripts\python.exe manage.py runserver 127.0.0.1:8000 to see its error."
    }
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/accounts/login/" -TimeoutSec 2
        if ($response.StatusCode -eq 200) {
            $ready = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

if (-not $ready) {
    Stop-Process -Id $server.Id -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $PSScriptRoot ".local-server.pid") -ErrorAction SilentlyContinue
    throw "Django did not respond on localhost:8000."
}

Start-Process "http://127.0.0.1:8000/"
Write-Host "SecureShare is running locally at http://127.0.0.1:8000/" -ForegroundColor Green
Write-Host "It works without Wi-Fi on this computer. Stop it with .\stop-local.ps1"
