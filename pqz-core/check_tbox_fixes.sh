#!/bin/sh
# Regression checks for the two LaZer tbox soundness fixes behind proofSystemId v2 (lazer/lnp-tbox.c):
#   P6-SZ (lazer-crypto/lazer issue 24): sz/sz_trace, the lambda = 4 evaluation-step accumulators must get distinct
#          challenge rows (exit 1 otherwise);
#   P6-L2 (issue 25): l2dom/, proofs from the pooled-slack cheating prover (blocks above their own l2 bound, the sum
#          within the pooled budget) must be rejected by the production verifier; control: the same prover on a copy
#          with the fix undone must get every proof accepted there (so a REJECT means the fix, not a broken PoC).
# Needs build/native/libpqz.a (./build.sh native). Heavy: run under scripts/capped. Exit 0 = both fixes in place.
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
[ $rc = 0 ] && echo "check_tbox_fixes: ok" || echo "check_tbox_fixes: FAIL"
exit $rc
