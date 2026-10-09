#!/usr/bin/env bash
# AstraSec — one-command setup and launch.
#
#   ./scripts/run.sh            train (if needed), build the UI, serve on :8000
#   ./scripts/run.sh --retrain  force a fresh training run
#   ./scripts/run.sh --skip-ui  backend only (API + Swagger docs)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

RETRAIN=0
SKIP_UI=0
for arg in "$@"; do
  case "$arg" in
    --retrain) RETRAIN=1 ;;
    --skip-ui) SKIP_UI=1 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { printf '\n\033[1;34m==>\033[0m %s\n' "$1"; }

# ---------------------------------------------------------------- python
say "Checking Python environment"
PY="${PYTHON:-python3}"
"$PY" --version
if [ ! -d .venv ]; then
  say "Creating virtual environment (.venv)"
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --quiet --upgrade pip
pip install --quiet -r backend/requirements.txt

# ---------------------------------------------------------------- models
MODELVER="$(cat artifacts/models/model_version.txt 2>/dev/null || true)"
if [ "$RETRAIN" -eq 1 ] || [ ! -f artifacts/models/threat_prediction.joblib ] \
   || [ "$MODELVER" != "2026.09-assistant" ]; then
  say "Training the immune system (this takes a few minutes)"
  (cd backend && python -m astrasec.train --samples 30000)
else
  say "Trained models found — skipping training (use --retrain to force)"
fi

# ---------------------------------------------------------------- frontend
if [ "$SKIP_UI" -eq 0 ]; then
  if command -v npm >/dev/null 2>&1; then
    if [ "$RETRAIN" -eq 1 ] || [ ! -d frontend/dist ]; then
      say "Building the dashboard"
      (cd frontend && npm install --no-audit --no-fund && npm run build)
    else
      say "Dashboard bundle found — skipping build"
    fi
  else
    say "npm not found — serving the API only (install Node 18+ for the dashboard)"
  fi
fi

# ---------------------------------------------------------------- serve
say "Starting AstraSec on http://localhost:8000"
echo "    AstraBot (the chatbot)  : http://localhost:8000/bot"
echo "    Security Center (owner) : http://localhost:8000"
echo
echo "    Set your owner password under Settings in the Security Center."
echo
echo "    Something not working?  Run:  cd backend && python -m astrasec.doctor"
echo
cd backend
exec python -m uvicorn astrasec.api:app --host 0.0.0.0 --port 8000
