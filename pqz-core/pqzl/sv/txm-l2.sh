#!/bin/sh
# P6-ANON L2: the specialised verifier on the R_TXM shapes, in parts that each fit one capped job (4 GB, < 30 min):
#   scripts/capped pqz-core/pqzl/sv/txm-l2.sh <label> diff     build native / x86v3 / wasm, pqz_sv_diff portable
#   scripts/capped pqz-core/pqzl/sv/txm-l2.sh <label> diff3    pqz_sv_diff x86-64-v3, check_sv_fixes.sh, wasm PQZ_VERIFY=both
#   scripts/capped pqz-core/pqzl/sv/txm-l2.sh <label> zdiff    sv/review/review.sh zdiff 1 (six forms + eight R_TXM shapes)
#   scripts/capped pqz-core/pqzl/sv/txm-l2.sh <label> fuzz     sv/fuzz.sh <label> 600 (byte 0: R_TXM M = 2 on, M = 8 off)
# pqz_sv_diff args: n_reg n_tx muts seed fuzz n_burn n_ds n_dr n_tx0 n_txm (one proof per form, one per R_TXM shape).
set -eu
cd "$(dirname "$0")/.."
L=$1 R=sv/runs/$1
export PQZ_ARENA_MB=${PQZ_ARENA_MB:-2048}
case $2 in
diff)
  ./build.sh native > "$R-build.txt" 2>&1
  ./build.sh native-x86v3 >> "$R-build.txt" 2>&1
  ./build.sh wasm >> "$R-build.txt" 2>&1
  build/native/pqz_sv_diff ${DIFF:-1 1 2 1 10 1 1 1 1 1} > "$R-diff-portable.jsonl" || echo "diff portable rc=$?"
  grep -h -e '"seed"' -e '"mismatch"' -e arena "$R-diff-portable.jsonl" ;;
diff3)
  build/native-x86v3/pqz_sv_diff ${DIFF3:-1 1 2 2 10 1 1 1 1 1} > "$R-diff-x86v3.jsonl" || echo "diff x86v3 rc=$?"
  sv/check_sv_fixes.sh > "$R-sv-fixes.txt" 2>&1 || echo "check_sv_fixes rc=$?"
  PQZ_VERIFY=both node test/run_wasm.mjs 1 3 $((64 * 255)) > "$R-wasm-both.jsonl" 2>&1 || echo "wasm both rc=$?"
  grep -h -e '"seed"' -e '"mismatch"' "$R-diff-x86v3.jsonl"
  cat "$R-sv-fixes.txt"
  grep -h -e mismatches -e fails "$R-wasm-both.jsonl" ;;
zdiff)
  sv/review/review.sh zdiff 1 > "$R-z21diff.jsonl" 2> "$R-z21diff-stderr.txt" || echo "zdiff rc=$?"
  grep -h z21diff "$R-z21diff.jsonl" | tail -3 ;;
fuzz)
  CAPPED=env sv/fuzz.sh "$L" 600 ;;
*) echo "usage: $0 <label> diff|diff3|zdiff|fuzz" >&2; exit 2 ;;
esac
