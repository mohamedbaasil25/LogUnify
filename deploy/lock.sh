#!/usr/bin/env bash
# Regenerate the hash-pinned, cross-platform lock files (requirements.in -> requirements.lock) with uv. Needs network, not Docker.
#   pip install uv && deploy/lock.sh
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
uv pip compile "$root/logunify-backend/requirements.in" --universal --python-version 3.13 --generate-hashes --no-header \
   -o "$root/logunify-backend/requirements.lock"
uv pip compile "$root/logunify-flink/requirements.in" --universal --python-version 3.11 --generate-hashes --no-header \
   -o "$root/logunify-flink/requirements.lock"
echo "locks written; review the diff, run the tests, commit. Install check: pip install --require-hashes -r <lock>"
