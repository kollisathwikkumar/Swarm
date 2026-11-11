#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ROOT_DIR/.env" ]; then
  cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
  echo "Created .env from .env.example (edit .env or configure keys in Settings UI)."
fi

cleanup() {
  kill 0 2>/dev/null || true
}
trap cleanup EXIT

echo "Clearing stale Next.js dev cache..."
rm -rf "$ROOT_DIR/frontend/.next"

echo "Starting Swarm FastAPI backend on http://127.0.0.1:8000 ..."
(
  cd "$ROOT_DIR/backend"
  .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
) &

echo "Starting Swarm Next.js frontend on http://127.0.0.1:3000 ..."
(
  cd "$ROOT_DIR/frontend"
  npm run dev
) &

wait
