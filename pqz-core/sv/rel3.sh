#!/bin/sh
# P6-SV for R_BURN / R_DS / R_DR (and R_REG / R_TX again): the whole set under ONE scripts/capped job,
#   scripts/capped pqz-core/sv/rel3.sh <label>
# 1. differential test, portable and x86-64-v3 (pqz_sv_diff; per relation: n_reg n_tx muts seed fuzz n_burn n_ds n_dr)
# 2. bench: fast verifier native portable / x86-64-v3 / wasm32, generic for reference (pqz_bench, run_wasm.mjs)
# 3. wasm PQZ_VERIFY=both: every wasm verify with both verifiers, disagreements counted
# 4. ASan + UBSan on the libc-heap path: pqz_bench with the fast verifier, all five relations
# JSON lines into sv/runs/<label>-*.
set -eu
cd "$(dirname "$0")/.."
L=$1 R=sv/runs/$1
DIFF=${DIFF:-"4 4 2 1 10 12 12 12"} DIFF3=${DIFF3:-"2 2 2 2 10 6 6 6"} NF=${NF:-200} NG=${NG:-10}
./build.sh native > "$R-build.txt" 2>&1
./build.sh native-x86v3 >> "$R-build.txt" 2>&1
./build.sh wasm >> "$R-build.txt" 2>&1
build/native/pqz_sv_diff $DIFF > "$R-diff-portable.jsonl" || echo "diff portable rc=$?"
build/native-x86v3/pqz_sv_diff $DIFF3 > "$R-diff-x86v3.jsonl" || echo "diff x86v3 rc=$?"
PQZ_VERIFY=fast build/native/pqz_bench 2 "$NF" > "$R-native-fast.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=generic build/native/pqz_bench 2 "$NG" > "$R-native-generic.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=fast build/native-x86v3/pqz_bench 2 "$NF" > "$R-x86v3-fast.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=fast node test/run_wasm.mjs 2 $((NF / 2)) > "$R-wasm-fast.jsonl" 2>&1 || echo "rc=$?"
PQZ_VERIFY=both node test/run_wasm.mjs 2 10 > "$R-wasm-both.jsonl" 2>&1 || echo "rc=$?"
mkdir -p build/sv-san
SRC="src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c src/pqz_sv.c"
INC="-std=gnu11 -g -fno-omit-frame-pointer -w -Ibuild/include -Isrc -Ilazer -Iparams"
SAN="-fsanitize=address,undefined -fno-sanitize=vla-bound,pointer-overflow -fno-sanitize-recover=all"
${CC:-clang} -O1 $INC $SAN -DPQZ_DEBUG_MALLOC -o build/sv-san/pqz_bench $SRC test/pqz_bench.c
ASAN_OPTIONS=detect_leaks=0 PQZ_VERIFY=fast build/sv-san/pqz_bench 1 3 > "$R-asan.jsonl" 2>&1 || echo "asan rc=$?"
grep -h -e '"seed"' -e '"mismatch"' -e prg -e arena "$R-diff-portable.jsonl" "$R-diff-x86v3.jsonl"
grep -h -e timing -e fails -e init_ms -e mismatches "$R"-native-*.jsonl "$R"-x86v3-fast.jsonl "$R"-wasm-*.jsonl "$R-asan.jsonl"
