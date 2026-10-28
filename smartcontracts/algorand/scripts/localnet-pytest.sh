#!/usr/bin/env bash
# pytest against the localnet: reuses a running one, else starts it and stops it on exit.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOK=$(printf 'a%.0s' {1..64})
if ! curl -sf -H "X-Algo-API-Token: $TOK" http://127.0.0.1:4001/v2/status >/dev/null; then
  trap '"$R/scripts/devnet.sh" down >/dev/null 2>&1' EXIT
  "$R/scripts/devnet.sh" up
fi
cd "$R" && .venv/bin/python -m pytest -q -s --tb=short -p no:cacheprovider -W ignore::DeprecationWarning tests "$@"
