$ErrorActionPreference = "Stop"
Write-Host "`nCTI SENTINEL X — FINAL PROJECT STARTUP" -ForegroundColor Cyan
if (!(Get-Command docker -ErrorAction SilentlyContinue)) { throw "Docker CLI is not installed or not on PATH. Install/start Docker Desktop first." }
docker info | Out-Null
if ($LASTEXITCODE -ne 0) { throw "Docker Desktop engine is not ready." }
python scripts\prepare_env.py
if ($LASTEXITCODE -ne 0) { throw "Environment preparation failed." }
Write-Host "[BUILD] Building API and web containers..." -ForegroundColor Cyan
docker compose -f docker-compose.yml up -d --build
if ($LASTEXITCODE -ne 0) { throw "Docker Compose failed. Inspect docker compose logs." }
Write-Host "`n[READY] Open CTI Sentinel X at http://localhost:5000" -ForegroundColor Green
Write-Host "[API] FastAPI documentation: http://localhost:8000/docs"
Write-Host "[MONGO] MongoDB host port: 27018 (database: cti_sentinel_final)"
Write-Host "Use 'docker compose ps' to inspect service health; 'docker compose logs -f backend frontend' for logs."
Start-Process "http://localhost:5000"
