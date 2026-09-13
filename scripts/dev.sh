#!/usr/bin/env bash
# Local backend stack: Docker Compose with file watch (no local Python / npm).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ ! -f .env ]]; then
  echo "dev: missing .env — run: bash scripts/generate-env.sh" >&2
  exit 1
fi

exec docker compose --env-file .env up --build --watch
