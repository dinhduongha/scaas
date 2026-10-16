#!/bin/sh
# R_BURN / R_DS / R_DR measurement (docs/research/pqz-relations-burn-disclose.md). Run the whole script under
# scripts/capped (one heavy job):   scripts/capped pqz-core/rel3/bench.sh <label>
# Builds native + wasm, checks the R_REG / R_TX proof hashes against the P6d-2 values (STATUS.md), KAT 19/19,
# then times the new relations; JSON lines into rel3/runs/<label>-*.jsonl.
set -eu
cd "$(dirname "$0")/.."
L=$1 R=rel3/runs/$1
./build.sh all > "$R-build.txt" 2>&1
build/native/kat_dump > build/native/kat-pqz.json
python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json > "$R-kat.txt"
build/native/pqz_bench 5 5 3 > "$R-fnv-native.jsonl" || echo "fnv native rc=$?"
node test/run_wasm.mjs 3 1 3 > "$R-fnv-wasm.jsonl" || echo "fnv wasm rc=$?"
build/native/pqz_bench ${NP:-10} ${NV:-100} 28 > "$R-native.jsonl" || echo "native rc=$?"
node test/run_wasm.mjs ${NPW:-5} ${NVW:-30} 28 > "$R-wasm.jsonl" || echo "wasm rc=$?"
cat "$R-kat.txt"
grep -h -e proofs_fnv "$R-fnv-native.jsonl" "$R-fnv-wasm.jsonl"
grep -h -e timing -e proof_bytes -e fails -e init "$R-native.jsonl" "$R-wasm.jsonl"
