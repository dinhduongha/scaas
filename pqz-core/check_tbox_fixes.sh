#!/bin/sh
# Regression checks for the LaZer tbox soundness fixes: the two behind proofSystemId v2 (lazer/lnp-tbox.c) and the
# verifier-only z21 norm check (lazer/lnp-quad.c, src/pqz_sv.c):
#   P6-SZ (lazer-crypto/lazer issue 24): sz/sz_trace, the lambda = 4 evaluation-step accumulators must get distinct
#          challenge rows (exit 1 otherwise);
#   P6-L2 (issue 25): l2dom/, proofs from the pooled-slack cheating prover (blocks above their own l2 bound, the sum
#          within the pooled budget) must be rejected by the production verifier; control: the same prover on a copy
#          with the fix undone must get every proof accepted there (so a REJECT means the fix, not a broken PoC).
#   P6-Z21 (issue 26): sv/review/review.sh norm, the z21_big proof (||z21||^2 far above Bsq, from a cheating prover)
#          must be rejected by both production verifiers (pqz_verify, pqz_verify_fast) and accepted by both in the
#          control with the z21 term removed; the honest proof must verify, z1_over / w_over must be rejected.
# Needs build/native/libpqz.a (./build.sh native). Heavy: run under scripts/capped. Exit 0 = all fixes in place.
set -eu
cd "$(dirname "$0")"
O=build/l2dom/out
rm -rf "$O"
rc=0
sz/build.sh > build/sz-trace.txt 2>&1 || rc=1
grep VERDICT build/sz-trace.txt || echo "sz: no verdict (build/sz-trace.txt)"
l2dom/build.sh "$O" > build/l2dom.txt 2>&1 || rc=1
for c in honest s_over_A s_over_B tx_over; do
  ctl=$(sed -n '/^== control/,/^== fixed/p' build/l2dom.txt | grep -c "in-process pqz_verify($c): ACCEPT" || true)
  prod=$(grep -c "production-lib pqz_verify($c): REJECT" build/l2dom.txt || true)
  echo "l2dom $c: control (fix undone) accepts $ctl/1, production rejects $prod/1"
  [ "$ctl" = 1 ] && [ "$prod" = 1 ] || rc=1
done
sv/review/review.sh norm > build/z21-norm.txt 2>&1 || rc=1
blk () { sed -n "/^== $1/,/^==/p" build/z21-norm.txt; }
z21=$(grep -c '^z21_big  prove rc=0' build/z21-norm.txt || true)
hon=$(blk production | grep -c '^honest   generic ACCEPT  fast ACCEPT$' || true)
prod=$(blk production | grep -c -e '^z21_big  generic REJECT  fast REJECT$' -e '^z1_over  generic REJECT  fast REJECT$' \
  -e '^w_over   generic REJECT  fast REJECT$' || true)
ctl=$(blk 'control: z21 term' | grep -c '^z21_big  generic ACCEPT  fast ACCEPT$' || true)
echo "z21 z21_big: proved $z21/1; production: honest accepted $hon/1, z21_big / z1_over / w_over rejected by both $prod/3;" \
  "control (z21 term removed) accepts z21_big $ctl/1"
grep '||z21||' build/z21-norm.txt || true
[ "$z21" = 1 ] && [ "$hon" = 1 ] && [ "$prod" = 3 ] && [ "$ctl" = 1 ] || rc=1
[ $rc = 0 ] && echo "check_tbox_fixes: ok" || echo "check_tbox_fixes: FAIL"
exit $rc
