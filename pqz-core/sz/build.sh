#!/bin/sh
# P6-SZ trace harness build (defensive review; see sz/README.md).
#   sz/build.sh            builds build/sz/sz_trace and runs it
# Compiles the kept LaZer protocol code + the rewritten layers with -DPQZ_SZ_TRACE so lnp-tbox.c calls the
# trace hook, then links the harness. Production builds (build.sh) never define PQZ_SZ_TRACE, so this is inert
# there. Run under scripts/capped like the other heavy builds.
set -eu
cd "$(dirname "$0")/.."
B=build
mkdir -p "$B/include" "$B/sz"
CC=${CC:-clang}
# lazer.h, as build.sh assembles it
{ cat lazer/lazer-in1.h; echo; echo "#ifndef LAZER_CONFIG_H"; echo "#define LAZER_CONFIG_H"
  cat lazer/config.h; echo "#endif"; echo; cat lazer/lazer-in2.h; echo
  echo "#define moduli_d64 ((const modulus_srcptr *)0)"
  echo "#define moduli_d128 ((const modulus_srcptr *)0)"; } > "$B/include/lazer.h"

CFLAGS="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off -DPQZ_SZ_TRACE \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare -I$B/include -Isrc -Ilazer -Iparams"

objs=""
for f in src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c; do
  o="$B/sz/$(basename "$f" .c).o"
  $CC $CFLAGS -c "$f" -o "$o"
  objs="$objs $o"
done
$CC -std=gnu11 -O2 -I"$B/include" -Isrc -o "$B/sz/sz_trace" sz/sz_trace.c $objs
echo "built $B/sz/sz_trace"
"$B/sz/sz_trace"
