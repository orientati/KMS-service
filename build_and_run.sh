#!/bin/bash

IMAGE_NAME="kms-service"

echo "==> Compilazione immagine Docker..."
docker build -t $IMAGE_NAME .

if [ $? -ne 0 ]; then
  echo "Errore nella compilazione dell'immagine!"
  exit 1
fi

echo "==> Avvio container..."
docker run -it --rm -p 8000:8000 $IMAGE_NAME
