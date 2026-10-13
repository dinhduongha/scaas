#!/bin/sh
# P6-SV benchmark: generic and specialised verifier, native portable (-O2), native x86-64-v3 + AES-NI (optional
# backend), wasm32 under node (no SIMD; with WASM_SIMD=1 also the -msimd128 build). Each run under scripts/capped,
# one at a time; JSON lines into sv/runs/<label>-*.jsonl.
#   sv/bench.sh <label> [n_verify_fast] [n_verify_generic]      (defaults 200, 10)
set -eu
cd "$(dirname "$0")/.."
CAPPED=${CAPPED:-$(git rev-parse --show-toplevel)/scripts/capped}
L=$1 NF=${2:-200} NG=${3:-10}
./build.sh native >/dev/null 2>&1
./build.sh native-x86v3 >/dev/null 2>&1
./build.sh wasm >/dev/null 2>&1
R=sv/runs/$L
PQZ_VERIFY=fast $CAPPED build/native/pqz_bench 2 "$NF" > "$R-native-fast.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=generic $CAPPED build/native/pqz_bench 2 "$NG" > "$R-native-generic.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=fast $CAPPED build/native-x86v3/pqz_bench 2 "$NF" > "$R-x86v3-fast.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=fast $CAPPED node test/run_wasm.mjs 2 $((NF / 2)) > "$R-wasm-fast.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=generic $CAPPED node test/run_wasm.mjs 2 3 > "$R-wasm-generic.jsonl" 2>&1 || echo "rc=$?"
if [ "${WASM_SIMD:-0}" = 1 ]; then
  mkdir -p build/wasm-simd
  WASM_SIMD=1 B=build/wasm-simd ./build.sh wasm >/dev/null 2>&1
  PQZ_WASM_FILE=build/wasm-simd/wasm/pqz.wasm PQZ_VERIFY=fast $CAPPED node test/run_wasm.mjs 2 $((NF / 2)) \
    > "$R-wasm-simd-fast.jsonl" 2>&1 || echo "rc=$?"
fi
grep -h -e timing -e fails -e init_ms "$R"-*.jsonl
