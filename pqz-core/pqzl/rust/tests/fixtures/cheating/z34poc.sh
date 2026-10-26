#!/bin/sh
# Cheating R_REG provers past the final hash for the z3 / z4 norm checks of _lnp_tbox_check_z34 (and of pqz_sv.c's
# verify_body / the Rust verifiers): a patched copy of lazer/lnp-tbox.c (under build/z34poc, never in a production
# build; the core stays untouched) whose prover inflates y3 (<< 2: ||z3||^2 ~ 6 Bz3sqr) or y4 (<< 4: ||z4||_inf ~
# 3 Bz4) and skips that rejection test, so the proof is consistent with its commitments and passes the final hash.
# Only the norm check after the hash can reject it. Mutation testing never reaches these checks (a mutated proof fails
# the hash first). Run from export.sh (under scripts/capped); prints the C core's verdicts (both verifiers reject)
# and writes build/z34poc/out/<case>.{stmt,proof}, case = honest (control), z3_over, z4_over.
set -eu
F=$(cd "$(dirname "$0")" && pwd)
cd "$F/../../../.." # pqz-core/pqzl
PB=build${PQZ_BUILD_TAG:+/$PQZ_BUILD_TAG} # the C build root; gate.sh sets PQZ_BUILD_TAG = the set (concurrent gates: build/<set>/)
[ -f $PB/native/libpqz.a ] || ./build.sh native > /dev/null
B=$PB/z34poc
rm -rf $B/out # never a previous run's (another parameter set's) proofs
mkdir -p $B/out
CC=${CC:-clang}
FL="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off -w -I$PB/include -Isrc -Ilazer -Iparams"
sed -e '3a\
int pqz_z34_mode; /* z34poc: 0 honest, 1 y3 << 2 and no z3 rejection, 2 y4 << 4 and no z4 rejection */' \
  -e 's|^          polyvec_grandom (y3, params->log2stdev3, seed_tbox, dom++);$|&\n          if (pqz_z34_mode == 1) polyvec_lshift (y3, y3, 2);|' \
  -e 's|^          polyvec_grandom (y4, params->log2stdev4, seed_tbox, dom++);$|&\n          if (pqz_z34_mode == 2) polyvec_lshift (y4, y4, 4);|' \
  -e 's|if (nex > 0 \&\& params->rej3)$|if (nex > 0 \&\& params->rej3 \&\& pqz_z34_mode != 1)|' \
  -e 's|if (nprime > 0 \&\& params->rej4)$|if (nprime > 0 \&\& params->rej4 \&\& pqz_z34_mode != 2)|' \
  lazer/lnp-tbox.c > $B/lnp-tbox.c
n=$(diff lazer/lnp-tbox.c $B/lnp-tbox.c | grep -c '^>' || true)
[ "$n" = 5 ] || { echo "z34poc: prover patch did not apply ($n lines)"; exit 1; }
$CC -I$B $FL -DPQZ_SV -c src/pqz_lazer.c -o $B/pqz_lazer.o
for f in pqz_ntt pqz_arena pqz_rel pqz_keys pqz_sv; do $CC $FL -DPQZ_SV -c src/$f.c -o $B/$f.o; done
rm -f $B/libpqz.a
ar rcs $B/libpqz.a $B/*.o
$CC -std=gnu11 -O2 -w -DPQZ_Z34_POC -I$PB/include -Isrc -o $B/z34poc_prove "$F/z34poc.c" $B/libpqz.a
$CC -std=gnu11 -O2 -w -I$PB/include -Isrc -o $B/z34poc_verify "$F/z34poc.c" $PB/native/libpqz.a
echo "== cheating prover (patched lnp-tbox.c, $n lines)"
$B/z34poc_prove prove $B/out
echo "== production verifiers ($PB/native/libpqz.a)"
$B/z34poc_verify verify $B/out
