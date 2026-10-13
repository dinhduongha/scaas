#!/bin/sh
# l2dom PoC (P6-L2, https://github.com/lazer-crypto/lazer/issues/25): the pooled-slack cheating prover
# (pqz_rel.c set_upsilon under -DPQZ_L2DOM_POC). Run under scripts/capped. Needs build/native/libpqz.a from
# ./build.sh native (the production verifier). Usage: l2dom/build.sh OUTDIR
#   control: the PoC built on a copy of lnp-tbox.c with the P6-L2 fix undone (one shared domain, as upstream);
#            its in-process verifier must ACCEPT every PoC proof (the attack works there);
#   fixed:   the PoC built on the tree as is; the production library must REJECT every PoC proof.
set -eu
cd "$(dirname "$0")/.."
B=build
O=${1:?outdir}
U=$B/l2dom/unfixed
mkdir -p "$U" "$O/control"
CC=${CC:-clang}
sed '/PQZ (P6-L2)/,/seed, dom + i,/ s/seed, dom + i,/seed, dom,/' lazer/lnp-tbox.c > "$U/lnp-tbox.c"
[ "$(diff lazer/lnp-tbox.c "$U/lnp-tbox.c" | grep -c '^>')" = 1 ] || echo "l2dom: control patch did not apply (control = tree)"
CFLAGS="-std=gnu11 -O2 -fno-builtin -fno-math-errno -ffp-contract=off -DPQZ_L2DOM_POC \
  -Wall -Wextra -Wno-unused-parameter -Wno-unused-function -Wno-sign-compare -I$B/include -Isrc -Ilazer -Iparams"
for v in fixed unfixed; do
  inc=""
  [ $v = unfixed ] && inc="-I$U"
  objs=""
  for f in src/pqz_lazer.c src/pqz_ntt.c src/pqz_arena.c src/pqz_rel.c; do
    o="$B/l2dom/$v-$(basename "$f" .c).o"
    $CC $inc $CFLAGS -c "$f" -o "$o"
    objs="$objs $o"
  done
  $CC -std=gnu11 -O2 -DPQZ_L2DOM_POC -Isrc -o "$B/l2dom/l2dom_prove_$v" l2dom/l2dom_poc.c $objs
  $CC -std=gnu11 -O2 -DPQZ_L2DOM_POC -Isrc -o "$B/l2dom/l2dom_tx_prove_$v" l2dom/l2dom_tx.c $objs -lm
done
$CC -std=gnu11 -O2 -Isrc -o "$B/l2dom/l2dom_verify" l2dom/l2dom_poc.c "$B/native/libpqz.a"
$CC -std=gnu11 -O2 -Isrc -o "$B/l2dom/l2dom_tx_verify" l2dom/l2dom_tx.c "$B/native/libpqz.a" -lm
echo "== control (P6-L2 fix undone)"
"$B/l2dom/l2dom_prove_unfixed" prove "$O/control"
"$B/l2dom/l2dom_tx_prove_unfixed" prove "$O/control"
echo "== fixed tree, production verifier"
"$B/l2dom/l2dom_prove_fixed" prove "$O"
"$B/l2dom/l2dom_verify" verify "$O"
"$B/l2dom/l2dom_tx_prove_fixed" prove "$O"
"$B/l2dom/l2dom_tx_verify" verify "$O"
