$ErrorActionPreference = "Stop"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$VenvPython = Join-Path $ProjectRoot ".venv-ml\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) { throw "Training environment not found. Run scripts\train_url_model.ps1 first." }
& $VenvPython -m ml_training.verify_runtime
if ($LASTEXITCODE -ne 0) { throw "Local URL model verification failed." }
