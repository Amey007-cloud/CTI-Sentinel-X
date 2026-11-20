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

Write-Host "[SETUP] Installing URL-model training dependencies..." -ForegroundColor Cyan
& $VenvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) { throw "pip upgrade failed." }
& $VenvPython -m pip install -r requirements-ml-training.txt
if ($LASTEXITCODE -ne 0) { throw "ML dependency installation failed." }

Write-Host "[DATA] Downloading PhiUSIIL and any configured live threat feeds..." -ForegroundColor Cyan
& $VenvPython -m ml_training.download_datasets
if ($LASTEXITCODE -ne 0) { throw "Dataset download/preparation failed. Review the source response and network connectivity." }

Write-Host "[TRAIN] Comparing candidates and training the final URL model..." -ForegroundColor Cyan
& $VenvPython -m ml_training.train
if ($LASTEXITCODE -ne 0) { throw "Model training/evaluation failed." }

Write-Host "[RESULT] Review reports\evaluation.json and models\README.md before publishing." -ForegroundColor Green
