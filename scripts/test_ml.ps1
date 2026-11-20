$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot

$VenvDir = Join-Path $ProjectRoot ".venv-ml"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[SETUP] Creating isolated Python environment..." -ForegroundColor Cyan
    & python -m venv $VenvDir
    if ($LASTEXITCODE -ne 0) { throw "Python virtual environment creation failed." }
}

Write-Host "[SETUP] Installing project and ML test dependencies..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
& $VenvPython -m pip install -r requirements-dev.txt
if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }

Write-Host "[TEST] Compiling Python modules..." -ForegroundColor Cyan
& $VenvPython -m compileall -q ml ml_training services scripts tests assistant_api database
if ($LASTEXITCODE -ne 0) { throw "Python compilation failed." }

Write-Host "[TEST] Running all unit tests..." -ForegroundColor Cyan
& $VenvPython -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "One or more tests failed." }

$Node = Get-Command node -ErrorAction SilentlyContinue
if ($Node) {
    Write-Host "[TEST] Checking JavaScript syntax..." -ForegroundColor Cyan
    Get-ChildItem (Join-Path $ProjectRoot "static\js") -Filter "*.js" | ForEach-Object {
        & node --check $_.FullName
        if ($LASTEXITCODE -ne 0) { throw "JavaScript syntax check failed: $($_.Name)" }
    }
} else {
    Write-Host "[SKIP] Node.js is not installed; JavaScript syntax checks were skipped." -ForegroundColor Yellow
}

Write-Host "[PASS] CTI Sentinel X tests completed successfully." -ForegroundColor Green
