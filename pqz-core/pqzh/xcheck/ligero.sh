#!/bin/sh
# PQZH-Ligero cross-check: the statement and witness bytes of the Ligero crate's client::setup() (Rust) against
# pqz-core's test/pqz_bench.c setup() (C) for all six forms (R_TX0 = op 1 by length), the C statements patched to PQZH statements
# (dump_setup.c `pqzh`: opTag, the D3 id, auditorOn); byte-identical or exit 1. Then pqz_kat.py parses each statement
# (PQZH id only) and rebuilds it byte for byte (kat_stmt.py).
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/xcheck/ligero.sh  (output: ligero/runs/<tag>-xcheck.txt)
set -eu
cd "$(dirname "$0")/.."
out=ligero/target/xcheck
mkdir -p $out/c $out/rust
(cd .. && ./build.sh native > /dev/null)
${CC:-clang} -std=gnu11 -O2 -I../src -o $out/dump_setup xcheck/dump_setup.c ../build/native/libpqz.a
$out/dump_setup $out/c pqzh
(cd ligero && cargo run --release --offline --quiet --example dump_setup -- target/xcheck/rust)
rc=0
for r in reg tx burn ds dr tx0; do
  for f in ${r}_stmt ${r}_wit; do
    if cmp -s $out/c/$f.bin $out/rust/$f.bin; then x=equal; else x=DIFFERENT; rc=1; fi
    echo "$f $(wc -c < $out/c/$f.bin) B c=$(sha256sum < $out/c/$f.bin | cut -c1-16) rust=$(sha256sum < $out/rust/$f.bin | cut -c1-16) $x"
  done
done
python3 -I xcheck/kat_stmt.py $out/rust || rc=1
exit $rc
