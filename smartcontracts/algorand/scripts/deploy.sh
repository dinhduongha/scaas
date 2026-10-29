#!/usr/bin/env bash
# Algorand deploy + hash gate (spec §4.9): deploy.sh <algod-url> [gate <role>=<app id>…]; env and steps in deploy.py's docstring.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$R/scripts/venv.sh"
exec "$R/.venv/bin/python" -I "$R/scripts/deploy.py" "$@"
