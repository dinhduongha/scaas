#!/bin/sh
# P6d-2 benchmark run: native pqz_bench (5 proves, 5 + 5 verifies) and the wasm runner (3 proves, 1 verify), each
# under scripts/capped, JSON lines into opt/runs/<label>-{native,wasm}.jsonl.
#   opt/bench.sh <label> [native binary] [wasm module]      (defaults: build/native/pqz_bench, build/wasm/pqz.wasm)
set -eu
cd "$(dirname "$0")/../../pqzl" # the PQZL core: build/, src/, test/, kat/
CAPPED=${CAPPED:-$(git rev-parse --show-toplevel)/scripts/capped}
L=$1 NB=${2:-build/native/pqz_bench} WM=${3:-build/wasm/pqz.wasm}
$CAPPED "$NB" 5 5 > "../research/opt/runs/$L-native.jsonl" 2>&1 || echo "native rc=$?"
PQZ_WASM_FILE=$WM $CAPPED node test/run_wasm.mjs 3 1 > "../research/opt/runs/$L-wasm.jsonl" 2>&1 || echo "wasm rc=$?"
grep -h -e timing -e proof_bytes -e fails "../research/opt/runs/$L-native.jsonl" "../research/opt/runs/$L-wasm.jsonl"
