#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$ROOT_DIR/.env" ]; then
  cp "$ROOT_DIR/.env.example" "$ROOT_DIR/.env"
  echo "Created .env from .env.example (edit .env or configure keys in Settings UI)."
fi

# Locate Python 3.12 specifically (user may have a newer system Python such as 3.14/3.15)
PYTHON_312=""
for candidate in \
  "$(command -v python3.12 2>/dev/null || true)" \
  "/opt/homebrew/bin/python3.12" \
  "/opt/homebrew/opt/python@3.12/bin/python3.12" \
  "/usr/local/bin/python3.12"; do
  if [ -n "$candidate" ] && [ -x "$candidate" ]; then
    PYTHON_312="$candidate"
    break
  fi
done

if [ -z "$PYTHON_312" ]; then
  echo "Error: Python 3.12 is required but not found on PATH or standard Homebrew paths." >&2
  echo "Please install Python 3.12 using: brew install python@3.12" >&2
  exit 1
fi

echo "Found Python 3.12 at: $PYTHON_312 ($("$PYTHON_312" --version))"

VENV_DIR="$ROOT_DIR/backend/.venv"
RECREATE_VENV=0

if [ ! -d "$VENV_DIR" ] || [ ! -x "$VENV_DIR/bin/python" ]; then
  echo "Backend virtualenv not found. Initializing with Python 3.12..."
  RECREATE_VENV=1
else
  CURRENT_VENV_VER="$("$VENV_DIR/bin/python" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || echo "unknown")"
  if [ "$CURRENT_VENV_VER" != "3.12" ]; then
    echo "Warning: Current backend/.venv is Python $CURRENT_VENV_VER, but Swarm requires 3.12. Recreating with Python 3.12..."
    RECREATE_VENV=1
  fi
fi

if [ "$RECREATE_VENV" -eq 1 ]; then
  rm -rf "$VENV_DIR"
  "$PYTHON_312" -m venv "$VENV_DIR"
  "$VENV_DIR/bin/pip" install --upgrade pip
  "$VENV_DIR/bin/pip" install -r "$ROOT_DIR/backend/requirements.txt"
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
  .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload --reload-dir app
) &

echo "Starting Swarm Next.js frontend on http://127.0.0.1:3000 ..."
(
  cd "$ROOT_DIR/frontend"
  npm run dev
) &

wait
