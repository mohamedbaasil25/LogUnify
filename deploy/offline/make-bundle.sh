#!/usr/bin/env bash
# Build an AIR-GAP BUNDLE on a CONNECTED host: every image LogUnify runs, a wheelhouse, checksums and an SBOM.
#   deploy/offline/make-bundle.sh [--version 1.0.0] [--out dist] [--with-flink] [--with-siem]
# Transfer dist/logunify-<version>/ to the isolated network (data diode / signed media), then run load-bundle.sh there.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=dev; OUT=dist; PROFILES=()
while [ $# -gt 0 ]; do case "$1" in
  --version) VERSION="$2"; shift 2;; --out) OUT="$2"; shift 2;;
  --with-flink) PROFILES+=(--profile flink); shift;; --with-siem) PROFILES+=(--profile siem); shift;;
  *) echo "unknown option $1"; exit 2;; esac; done

B="$OUT/logunify-$VERSION"; mkdir -p "$B/wheels"
export LOGUNIFY_VERSION="$VERSION" LOGUNIFY_JWT_SECRET="${LOGUNIFY_JWT_SECRET:-build-time-placeholder-not-a-secret}"

echo "== building images"
[ -n "${PROFILES[*]:-}" ] && [[ " ${PROFILES[*]} " == *" flink "* ]] && bash deploy/fetch-jars.sh
docker compose "${PROFILES[@]}" build
IMAGES=$(docker compose "${PROFILES[@]}" config --images | sort -u)
echo "$IMAGES"

echo "== pulling third-party images"
for i in $IMAGES; do case "$i" in logunify/*) ;; *) docker pull "$i";; esac; done

echo "== saving images (docker save)"
# shellcheck disable=SC2086
docker save $IMAGES | gzip -1 > "$B/logunify-images.tar.gz"
echo "$IMAGES" > "$B/images.txt"

echo "== wheelhouse (for non-container installs; verified against requirements.lock hashes)"
docker run --rm -v "$PWD/logunify-backend:/src:ro" -v "$PWD/$B/wheels:/out" python:3.13-slim-bookworm \
  pip download --require-hashes --no-deps -r /src/requirements.lock -d /out

echo "== SBOM"
if command -v syft >/dev/null; then for i in $(grep '^logunify/' "$B/images.txt"); do syft "$i" -o spdx-json > "$B/sbom-$(echo "$i" | tr '/:' '__').spdx.json"; done
else echo "syft not installed: SBOM skipped (install syft, or rely on the CI sbom artifacts)"; fi

echo "== deployment files"
cp compose.yaml "$B/"; cp -r deploy "$B/deploy"; cp -r parsers.d "$B/parsers.d"; cp deploy/.env.example "$B/.env.example"
mkdir -p "$B/logunify-forwarder"; for d in elasticsearch splunk wazuh retention vector; do cp -r "logunify-forwarder/$d" "$B/logunify-forwarder/$d"; done   # policy files, not tools/
( cd "$B" && find . -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > SHA256SUMS )
echo "bundle ready: $B ($(du -sh "$B" | cut -f1)); verify with: (cd $B && sha256sum -c SHA256SUMS)"
echo "Sign it before transfer (e.g. cosign sign-blob / gpg --detach-sign $B/SHA256SUMS): the checksums only prove integrity if SHA256SUMS itself is trusted."
