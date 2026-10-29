#!/usr/bin/env bash
# NEAR keyless deploy (spec §3.9): deploy.sh <rpc-url> [gate <account…>]; env and steps in deploy.py's docstring.
set -euo pipefail
exec python3 -I "$(dirname "${BASH_SOURCE[0]}")/deploy.py" "$@"
