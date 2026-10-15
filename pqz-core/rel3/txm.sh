#!/bin/sh
# P6-ANON Track L (R_TXM, op 7): build, KAT, tbox fixes, the six P6e forms' proof hashes (must equal the last run's),
# the R_TXM shapes native and wasm (honest, adversarial, txm_check variants / negatives), ASan + UBSan. One capped job:
#   scripts/capped pqz-core/rel3/txm.sh <label>        JSON lines into rel3/runs/<label>-*
# NP / NV / NPW / NVW: proves / verifies per shape native / wasm (default 2 2 1 1); ARENA_MB (default 2048).
set -eu
cd "$(dirname "$0")/.."
R=rel3/runs/$1
TXM=$((64 * 255)) # the eight built shapes
export PQZ_ARENA_MB=${ARENA_MB:-2048}
./build.sh all > "$R-build.txt" 2>&1
build/native/kat_dump > build/native/kat-pqz.json
python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json > "$R-kat.txt" || echo "kat rc=$?"
./check_tbox_fixes.sh > "$R-tbox-fixes.txt" 2>&1 || echo "check_tbox_fixes rc=$?"
build/native/pqz_bench 5 5 63 > "$R-fnv-native.jsonl" || echo "fnv native rc=$?"
node test/run_wasm.mjs 3 1 63 > "$R-fnv-wasm.jsonl" || echo "fnv wasm rc=$?"
build/native/pqz_bench ${NP:-2} ${NV:-2} $TXM 1 > "$R-txm-native.jsonl" || echo "txm native rc=$?"
node test/run_wasm.mjs ${NPW:-1} ${NVW:-1} $TXM > "$R-txm-wasm.jsonl" || echo "txm wasm rc=$?"
mkdir -p build/asan
F="-std=gnu11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPQZ_DEBUG_MALLOC -DPQZ_SV -w -Ibuild/include -Isrc -Ilazer -Iparams"
${CC:-clang} $F -o build/asan/pqz_bench src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_keys.c src/pqz_sv.c test/pqz_bench.c
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 build/asan/pqz_bench 1 1 $((64 * 2 + 64 * 128)) > "$R-asan.jsonl" 2> "$R-asan-stderr.txt" \
  || echo "asan rc=$?"
cat "$R-kat.txt"
tail -3 "$R-tbox-fixes.txt"
grep -h proofs_fnv "$R-fnv-native.jsonl" "$R-fnv-wasm.jsonl"
grep -h -e proofs_fnv -e proof_bytes -e timing -e txm_check -e fails -e rc "$R-txm-native.jsonl" "$R-txm-wasm.jsonl" "$R-asan.jsonl"
