#!/usr/bin/env bash
# scaas-node e2e_algorand on a fresh localnet (T20 review M6): up, the e2e, and the localnet down on exit — a failure or an
# interrupt included (no container is left). Extra args go to the test binary (e.g. a test name).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
D="$ROOT/smartcontracts/scripts/devnet.sh"
trap '"$D" algorand down >/dev/null 2>&1' EXIT
"$D" algorand down >/dev/null 2>&1 || true
"$ROOT/scripts/capped" "$D" algorand up
cd "$ROOT/scaas-node" && "$ROOT/scripts/capped" cargo test -j2 --test e2e_algorand -- --ignored --nocapture "$@"
