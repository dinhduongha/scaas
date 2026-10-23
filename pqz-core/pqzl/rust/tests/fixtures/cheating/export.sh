#!/bin/sh
# Exports the cheating proofs check_tbox_fixes.sh builds, with their statements, into this directory (PQZ_SET=n2048-kmax1024)
# or <set>/ (any other PQZ_SET; run once per set, under
# scripts/capped; the files are committed): the pooled-slack prover's (l2dom/, P6-L2: s_over_A, s_over_B, tx_over and
# its proof of an honest witness, which the fixed verifier also rejects), the norm PoC prover's (sv/review/review.sh norm, P6-Z21: z21_big, z1_over, w_over and its
# honest control) and this directory's z34poc.sh (a patched copy of lnp-tbox.c: z3_over, z4_over, the z3 / z4 bounds
# of _lnp_tbox_check_z34). <case>.stmt / <case>.proof; tests/vectors.rs cheating_proofs_reject and tests/sv_diff.rs
# cheating_rejected read them (tests/common cheating()). P6-SZ has no
# cheating prover (sz/sz_trace only traces an honest prove); the honest v2 vectors cover its transcript.
set -eu
F=$(cd "$(dirname "$0")" && pwd)
X=$F # the scripts (z34poc.sh)
cd "$F/../../../.." # pqz-core/pqzl
PB=build${PQZ_BUILD_TAG:+/$PQZ_BUILD_TAG} # the C build root; gate.sh sets PQZ_BUILD_TAG = the set (concurrent gates: build/<set>/)
# the parameter set (owner 2026-10-21: one per build): the v3 set's fixtures here, another set's in <set>/
PQZ_SET=${PQZ_SET:-n2304-kmax4096}
export PQZ_SET
[ "$PQZ_SET" = n2048-kmax1024 ] || { F=$F/$PQZ_SET; mkdir -p "$F"; }
./build.sh native > /dev/null
O=$PB/l2dom/out
rm -rf "$O"
l2dom/build.sh "$O"
for c in honest s_over_A s_over_B; do
  cp "$O/$c.stmt" "$F/l2dom_$c.stmt"
  cp "$O/$c.proof" "$F/l2dom_$c.proof"
done
cp "$O/tx_over.stmt" "$O/tx_over.proof" "$F/"
sv/review/review.sh norm
for c in honest z21_big z1_over w_over; do
  cp "$PB/review/norm-out/$c.stmt" "$F/norm_$c.stmt"
  cp "$PB/review/norm-out/$c.proof" "$F/norm_$c.proof"
done
"$X/z34poc.sh"
for c in z3_over z4_over; do
  cp "$PB/z34poc/out/$c.stmt" "$F/norm_$c.stmt"
  cp "$PB/z34poc/out/$c.proof" "$F/norm_$c.proof"
done
ls -l "$F"
