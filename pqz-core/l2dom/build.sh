#!/bin/sh
# l2dom PoC (private review). Run under scripts/capped. Needs build/native/libpqz.a from ./build.sh native
# (the production verifier). Usage: l2dom/build.sh OUTDIR
set -eu
cd "$(dirname "$0")/.."
B=build
O=${1:?outdir}
mkdir -p "$B/l2dom" "$O"
CC=${CC:-clang}
CFLAGS="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off -DPQZ_L2DOM_POC \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare -I$B/include -Isrc -Ilazer -Iparams"
objs=""
for f in src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c; do
  o="$B/l2dom/$(basename "$f" .c).o"
  $CC $CFLAGS -c "$f" -o "$o"
  objs="$objs $o"
done
$CC -std=gnu11 -O2 -DPQZ_L2DOM_POC -Isrc -o "$B/l2dom/l2dom_prove" l2dom/l2dom_poc.c $objs
$CC -std=gnu11 -O2 -Isrc -o "$B/l2dom/l2dom_verify" l2dom/l2dom_poc.c "$B/native/libpqz.a"
$CC -std=gnu11 -O2 -DPQZ_L2DOM_POC -Isrc -o "$B/l2dom/l2dom_tx_prove" l2dom/l2dom_tx.c $objs -lm
$CC -std=gnu11 -O2 -Isrc -o "$B/l2dom/l2dom_tx_verify" l2dom/l2dom_tx.c "$B/native/libpqz.a" -lm
"$B/l2dom/l2dom_prove" prove "$O"
"$B/l2dom/l2dom_verify" verify "$O"
"$B/l2dom/l2dom_tx_prove" prove "$O"
"$B/l2dom/l2dom_tx_verify" verify "$O"
