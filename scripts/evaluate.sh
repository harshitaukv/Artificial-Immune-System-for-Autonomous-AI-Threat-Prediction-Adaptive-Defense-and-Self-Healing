#!/usr/bin/env bash
# Regenerate every metric, table and figure used in the project report.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
[ -d .venv ] && source .venv/bin/activate
cd backend
python -m astrasec.train --samples 30000 --split disjoint --cv 3
python -m astrasec.evaluate --traffic 400
echo
echo "Artifacts written to artifacts/reports/ and artifacts/figures/"
