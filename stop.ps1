$ErrorActionPreference = "Stop"
docker compose -f docker-compose.yml down
Write-Host "CTI Sentinel containers stopped. Persistent MongoDB volume was preserved." -ForegroundColor Green
