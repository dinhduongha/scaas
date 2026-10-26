#!/bin/sh
# P6-SV for R_BURN / R_DS / R_DR (and R_REG / R_TX again): the whole set under ONE scripts/capped job,
#   scripts/capped pqz-core/pqzl/sv/rel3.sh <label>
# 1. differential test, portable and x86-64-v3 (pqz_sv_diff; per relation: n_reg n_tx muts seed fuzz n_burn n_ds n_dr
#    n_tx0 n_txm; R_TX0 since P6e Task 2, every built R_TXM shape since P6-ANON L2)
# 2. bench: fast verifier native portable / x86-64-v3 / wasm32, generic for reference (pqz_bench, run_wasm.mjs)
# 3. wasm PQZ_VERIFY=both: every wasm verify with both verifiers, disagreements counted
# 4. ASan + UBSan on the libc-heap path: pqz_bench with the fast verifier, all five relations
# 5. (since v2) KAT, check_tbox_fixes.sh (generic side), sv/check_sv_fixes.sh (SV side: each fix reverted in a copy
#    of pqz_sv.c must make the differential test fail)
# 6. (since v2) memory per op alone (one process per relation, prove + one honest verify): wasm without the
#    specialised verifier (SV=0, the wallet's prover build), wasm with it (generic and fast verify), native fast
# JSON lines into sv/runs/<label>-*.
set -eu
cd "$(dirname "$0")/.."
L=$1 R=sv/runs/$1
DIFF=${DIFF:-"4 4 2 1 10 12 12 12 12 2"} DIFF3=${DIFF3:-"2 2 2 2 10 6 6 6 6 1"} NF=${NF:-200} NG=${NG:-10}
export PQZ_ARENA_MB=${PQZ_ARENA_MB:-2048} # R_TXM M = 8 (P6-ANON L2)
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
INC="-std=gnu11 -g -fno-omit-frame-pointer -w -DPQZ_SV -Ibuild/include -Isrc -Ilazer -Iparams"
SAN="-fsanitize=address,undefined -fno-sanitize=vla-bound,pointer-overflow -fno-sanitize-recover=all"
${CC:-clang} -O1 $INC $SAN -DPQZ_DEBUG_MALLOC -o build/sv-san/pqz_bench $SRC test/pqz_bench.c
ASAN_OPTIONS=detect_leaks=0 PQZ_VERIFY=fast build/sv-san/pqz_bench 1 3 > "$R-asan.jsonl" 2>&1 || echo "asan rc=$?"
build/native/kat_dump > build/native/kat-pqz.json
python3 -I kat/check.py ../params/sets/${PQZ_SET:-n2304-kmax4096}/lazer-3330e48-kat.json build/native/kat-pqz.json > "$R-kat.txt" || echo "kat rc=$?"
./check_tbox_fixes.sh > "$R-tbox-fixes.txt" 2>&1 || echo "check_tbox_fixes rc=$?"
sv/check_sv_fixes.sh > "$R-sv-fixes.txt" 2>&1 || echo "check_sv_fixes rc=$?"
cp build/svfix/tree.jsonl "$R-sv-fixes-tree.jsonl"
cp build/svfix/sz.jsonl "$R-sv-fixes-sz-reverted.jsonl"
cp build/svfix/l2.jsonl "$R-sv-fixes-l2-reverted.jsonl"
SV=0 B=build/wasm-nosv ./build.sh wasm >> "$R-build.txt" 2>&1
wc -c build/wasm/pqz.wasm build/wasm-nosv/wasm/pqz.wasm >> "$R-build.txt"
: > "$R-alone.jsonl"
for m in 1 2 4 8 16 32; do
  PQZ_WASM_FILE=build/wasm-nosv/wasm/pqz.wasm node test/run_wasm.mjs 1 0 $m | sed 's/^{/{"backend": "wasm-nosv", /' >> "$R-alone.jsonl" || echo "alone wasm-nosv $m rc=$?"
  node test/run_wasm.mjs 1 0 $m | sed 's/^{/{"backend": "wasm-generic", /' >> "$R-alone.jsonl" || echo "alone wasm $m rc=$?"
  PQZ_VERIFY=fast node test/run_wasm.mjs 1 0 $m | sed 's/^{/{"backend": "wasm-fast", /' >> "$R-alone.jsonl" || echo "alone wasm-fast $m rc=$?"
  PQZ_VERIFY=fast build/native/pqz_bench 1 0 $m | sed 's/^{/{"backend": "native-fast", /' >> "$R-alone.jsonl" || echo "alone native-fast $m rc=$?"
done
grep -h -e '"seed"' -e '"mismatch"' -e prg -e arena "$R-diff-portable.jsonl" "$R-diff-x86v3.jsonl"
grep -h -e timing -e fails -e init_ms -e mismatches "$R"-native-*.jsonl "$R"-x86v3-fast.jsonl "$R"-wasm-*.jsonl "$R-asan.jsonl"
cat "$R-kat.txt"
tail -6 "$R-tbox-fixes.txt"
cat "$R-sv-fixes.txt"
grep -h -e arena_peak -e init "$R-alone.jsonl"
