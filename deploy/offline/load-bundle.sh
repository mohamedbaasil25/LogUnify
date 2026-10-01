#!/usr/bin/env bash
# On the ISOLATED host: verify the bundle, load the images, start the stack. Needs Docker + the compose plugin, no network.
#   cd logunify-<version> && bash deploy/offline/load-bundle.sh
set -euo pipefail
cd "$(dirname "$0")/../.."
echo "== verifying checksums"; sha256sum -c SHA256SUMS --quiet
echo "== loading images"; gunzip -c logunify-images.tar.gz | docker load
[ -f .env ] || { cp .env.example .env; echo "created .env from .env.example: set LOGUNIFY_JWT_SECRET (and the other secrets), then re-run"; exit 1; }
grep -q '^LOGUNIFY_JWT_SECRET=.\+' .env || { echo "LOGUNIFY_JWT_SECRET is empty in .env"; exit 1; }
export LOGUNIFY_VERSION="$(sed -n 's/.*logunify\/backend:\(.*\)/\1/p' images.txt | head -1)"
docker compose up -d --no-build --pull never
docker compose ps
