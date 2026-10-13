#!/bin/sh
# Owner decisions 2026-10-13 on pqz-relations-burn-disclose.md §5 (branch pqz-relfix): R_TX on the §7.7 layout,
# disclosure kind word, relation keys built at first use. Run the whole script under scripts/capped (one heavy job):
#   scripts/capped pqz-core/rel3/relfix.sh <label>
# Build native + wasm, KAT, the tbox-fix regression checks (check_tbox_fixes.sh, from v2), proof hashes (f2: R_REG
# 12ec7452 native / 3bc7e9b3 wasm; proofSystemId v2 changes all five relations), arena peak of each
# relation alone (one process per relation: what a prover for that op carries), ASan + UBSan, then the timings of all
# five relations; JSON lines into rel3/runs/<label>-*.
set -eu
cd "$(dirname "$0")/.."
R=rel3/runs/$1
./build.sh all > "$R-build.txt" 2>&1
build/native/kat_dump > build/native/kat-pqz.json
python3 -I kat/check.py kat/lazer-3330e48.json build/native/kat-pqz.json > "$R-kat.txt"
./check_tbox_fixes.sh > "$R-tbox-fixes.txt" 2>&1 || echo "check_tbox_fixes rc=$?"
build/native/pqz_bench 5 5 31 > "$R-fnv-native.jsonl" || echo "fnv native rc=$?"
node test/run_wasm.mjs 3 1 31 > "$R-fnv-wasm.jsonl" || echo "fnv wasm rc=$?"
: > "$R-alone.jsonl"
for m in 1 2 4 8 16; do
  build/native/pqz_bench 1 0 $m | sed 's/^{/{"backend": "native", /' >> "$R-alone.jsonl" || echo "alone native $m rc=$?"
  node test/run_wasm.mjs 1 0 $m | sed 's/^{/{"backend": "wasm", /' >> "$R-alone.jsonl" || echo "alone wasm $m rc=$?"
done
# ASan + UBSan on the libc heap (opt/asan.sh without its own capped call)
mkdir -p build/asan
F="-std=gnu11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -DPQZ_DEBUG_MALLOC -w -Ibuild/include -Isrc -Ilazer -Iparams"
${CC:-clang} $F -o build/asan/pqz_bench src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c test/pqz_bench.c
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=print_stacktrace=1 build/asan/pqz_bench 1 1 31 > "$R-asan.jsonl" 2> "$R-asan-stderr.txt" \
  || echo "asan rc=$?"
build/native/pqz_bench ${NP:-10} ${NV:-100} 31 > "$R-native.jsonl" || echo "native rc=$?"
node test/run_wasm.mjs ${NPW:-5} ${NVW:-30} 31 > "$R-wasm.jsonl" || echo "wasm rc=$?"
cat "$R-kat.txt"
tail -6 "$R-tbox-fixes.txt"
grep -h -e proofs_fnv "$R-fnv-native.jsonl" "$R-fnv-wasm.jsonl"
grep -h -e arena_peak -e init "$R-alone.jsonl"
grep -h -e fails "$R-asan.jsonl"
grep -h -e timing -e proof_bytes -e fails -e init "$R-native.jsonl" "$R-wasm.jsonl"
