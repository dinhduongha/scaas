#!/bin/sh
# P6-ANON L3: PQZL R_TXM measurements per shape, M = 1, 2, 4, 8 (built) and 16 (oversize), auditor on / off, one
# process per shape and backend (so each arena peak is that shape's alone). One capped job:
#   scripts/capped pqz-core/rel3/txm-bench.sh <label>        JSON lines into rel3/runs/<label>-*
# Builds under build/ov with OVERSIZE=1 (bench only; the precompile build never has M = 16). Per shape:
#   native generic: NP proves (proof bytes min / max, prove p50 / p99, arena peak), NV honest + adversarial verifies
#   native / x86-64-v3 / wasm specialised verifier: NF honest + adversarial verifies
#   wasm generic: NPW proves (prove p50, arena peak), NVW verifies; wasm without the SV (the wallet's prover): 1 prove
set -eu
cd "$(dirname "$0")/.."
R=rel3/runs/$1
export PQZ_ARENA_MB=${ARENA_MB:-3072}
NP=${NP:-10} NV=${NV:-30} NF=${NF:-200} NPW=${NPW:-3} NVW=${NVW:-3}
export B=build/ov OVERSIZE=1
./build.sh native > "$R-build.txt" 2>&1
./build.sh native-x86v3 >> "$R-build.txt" 2>&1
./build.sh wasm >> "$R-build.txt" 2>&1
SV=0 B=build/ov-nosv ./build.sh wasm >> "$R-build.txt" 2>&1
wc -c build/ov/wasm/pqz.wasm build/ov-nosv/wasm/pqz.wasm >> "$R-build.txt"
for f in native-generic native-fast x86v3-fast wasm-fast wasm-generic wasm-nosv; do : > "$R-$f.jsonl"; done
for t in 0 1 2 3 4 5 6 7 8 9; do
  m=$((64 << t))
  build/ov/native/pqz_bench "$NP" "$NV" $m >> "$R-native-generic.jsonl" || echo "native generic $t rc=$?"
  PQZ_VERIFY=fast build/ov/native/pqz_bench 2 "$NF" $m >> "$R-native-fast.jsonl" || echo "native fast $t rc=$?"
  PQZ_VERIFY=fast build/ov/native-x86v3/pqz_bench 2 "$NF" $m >> "$R-x86v3-fast.jsonl" || echo "x86v3 fast $t rc=$?"
  PQZ_WASM_FILE=build/ov/wasm/pqz.wasm PQZ_VERIFY=fast node test/run_wasm.mjs 1 $((NF / 2)) $m >> "$R-wasm-fast.jsonl" \
    || echo "wasm fast $t rc=$?"
  PQZ_WASM_FILE=build/ov/wasm/pqz.wasm node test/run_wasm.mjs "$NPW" "$NVW" $m >> "$R-wasm-generic.jsonl" \
    || echo "wasm generic $t rc=$?"
  PQZ_WASM_FILE=build/ov-nosv/wasm/pqz.wasm node test/run_wasm.mjs 1 0 $m >> "$R-wasm-nosv.jsonl" \
    || echo "wasm nosv $t rc=$?"
done
grep -h -e proof_bytes -e timing -e fails "$R"-*.jsonl
