#!/bin/sh
# Regression checks for the LaZer tbox soundness fixes: the two behind proofSystemId v2 (lazer/lnp-tbox.c), the
# verifier-only z21 norm check (lazer/lnp-quad.c, src/pqz_sv.c) and the Fiat-Shamir transcript binding (v3):
#   P6-SZ (lazer-crypto/lazer issue 24): sz/sz_trace, the lambda = 4 evaluation-step accumulators must get distinct
#          challenge rows (exit 1 otherwise);
#   P6-L2 (issue 25): l2dom/, proofs from the pooled-slack cheating prover (blocks above their own l2 bound, the sum
#          within the pooled budget) must be rejected by the production verifier; control: the same prover on a copy
#          with the fix undone must get every proof accepted there (so a REJECT means the fix, not a broken PoC).
#   P6-Z21 (issue 26): sv/review/review.sh norm, the z21_big proof (||z21||^2 far above Bsq, from a cheating prover)
#          must be rejected by both production verifiers (pqz_verify, pqz_verify_fast) and accepted by both in the
#          control with the z21 term removed; the honest proof must verify, z1_over / w_over must be rejected.
#   P6-FS (issue 28): sz/fs_bind, the Fiat-Shamir binding test: in pqz_verify and pqz_verify_fast the V4 / V3 seeds
#          must change when z3 or z4 changes and the mu seed when h changes (a missing seed record fails); the
#          honest proof must verify. Observation only (which bytes seed which challenge), no cheating prover.
# Needs build/native/libpqz.a (./build.sh native). Heavy: run under scripts/capped. Exit 0 = all fixes in place.
set -eu
cd "$(dirname "$0")"
O=build/l2dom/out
rm -rf "$O" build/sz/fs_bind
mkdir -p build
rc=0
sum=""
res () { [ "$2" = 0 ] && sum="$sum$1 ok; " || { sum="$sum$1 FAIL; "; rc=1; }; }
st=0
sz/build.sh > build/sz-trace.txt 2>&1 || st=1
grep VERDICT build/sz-trace.txt || echo "sz: no verdict (build/sz-trace.txt)"
res P6-SZ $st
st=0
l2dom/build.sh "$O" > build/l2dom.txt 2>&1 || st=1
for c in honest s_over_A s_over_B tx_over; do
  ctl=$(sed -n '/^== control/,/^== fixed/p' build/l2dom.txt | grep -c "in-process pqz_verify($c): ACCEPT" || true)
  prod=$(grep -c "production-lib pqz_verify($c): REJECT" build/l2dom.txt || true)
  echo "l2dom $c: control (fix undone) accepts $ctl/1, production rejects $prod/1"
  [ "$ctl" = 1 ] && [ "$prod" = 1 ] || st=1
done
res P6-L2 $st
st=0
sv/review/review.sh norm > build/z21-norm.txt 2>&1 || st=1
blk () { sed -n "/^== $1/,/^==/p" build/z21-norm.txt; }
z21=$(grep -c '^z21_big  prove rc=0' build/z21-norm.txt || true)
hon=$(blk production | grep -c '^honest   generic ACCEPT  fast ACCEPT$' || true)
prod=$(blk production | grep -c -e '^z21_big  generic REJECT  fast REJECT$' -e '^z1_over  generic REJECT  fast REJECT$' \
  -e '^w_over   generic REJECT  fast REJECT$' || true)
ctl=$(blk 'control: z21 term' | grep -c '^z21_big  generic ACCEPT  fast ACCEPT$' || true)
echo "z21 z21_big: proved $z21/1; production: honest accepted $hon/1, z21_big / z1_over / w_over rejected by both $prod/3;" \
  "control (z21 term removed) accepts z21_big $ctl/1"
grep '||z21||' build/z21-norm.txt || true
[ "$z21" = 1 ] && [ "$hon" = 1 ] && [ "$prod" = 3 ] && [ "$ctl" = 1 ] || st=1
res P6-Z21 $st
st=0
if [ -x build/sz/fs_bind ]; then
  build/sz/fs_bind > build/fs-bind.txt 2>&1 || st=1
  grep '^P6-FS' build/fs-bind.txt || true
  grep VERDICT build/fs-bind.txt || { echo "fs_bind: no verdict (build/fs-bind.txt)"; st=1; }
else
  echo "fs_bind: not built (build/sz-trace.txt)"; st=1
fi
res "P6-FS lazer#28" $st
echo "checks: $sum"
[ $rc = 0 ] && echo "check_tbox_fixes: ok" || echo "check_tbox_fixes: FAIL"
exit $rc
