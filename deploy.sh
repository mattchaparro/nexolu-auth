#!/bin/bash
# Deploy de ESTE servicio, independiente de los otros. Corre desde el
# droplet, asumiendo la estructura de hermanos de nexolu-infra (ver su
# README.md): este repo y nexolu-infra clonados uno al lado del otro.
set -e
cd "$(dirname "$0")"

echo "==> git pull"
git pull origin main

echo "==> Reconstruyendo y reiniciando auth"
cd ../nexolu-infra
docker compose build auth

echo "==> Migrando esquema (alembic upgrade head)"
docker compose run --rm auth alembic upgrade head

docker compose up -d auth

echo "==> Listo. Verificar: curl -s https://auth.nexolu.co/health"
