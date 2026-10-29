#!/usr/bin/env bash
# The pinned toolchain in smartcontracts/algorand/.venv (git-ignored), created on first use.
set -euo pipefail
R="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[ -x "$R/.venv/bin/puyapy" ] && exit 0
python3 -m venv "$R/.venv" && "$R/.venv/bin/pip" install -q -r "$R/requirements.txt"
