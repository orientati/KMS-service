$ImageName = "kms-service"

Write-Host "==> Avvio con Docker Compose (build & up)..."
docker compose up -d --build

if ($LASTEXITCODE -ne 0) {
    Write-Host "Errore nell'avvio con Docker Compose!"
    exit 1
}

Write-Host "==> Servizio avviato in background."
Write-Host "Per vedere i log: docker compose logs -f"
