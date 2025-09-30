$ImageName = "kms-service"

Write-Host "==> Compilazione immagine Docker..."
docker build -t $ImageName .

if ($LASTEXITCODE -ne 0) {
    Write-Host "Errore nella compilazione dell'immagine!"
    exit 1
}

Write-Host "==> Avvio container..."
docker run -it --rm -p 8000:8000 $ImageName
