#!/bin/sh
# PQZH-Ligero cross-check: the statement and witness bytes of the Ligero crate's client::setup() (Rust) against
# pqz-core's test/pqz_bench.c setup() (C) for all five relations; byte-identical or exit 1.
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/xcheck/ligero.sh  (output: ligero/runs/<tag>-xcheck.txt)
set -eu
cd "$(dirname "$0")/.."
out=ligero/target/xcheck
mkdir -p $out/c $out/rust
(cd .. && ./build.sh native > /dev/null)
${CC:-clang} -std=gnu11 -O2 -I../src -o $out/dump_setup xcheck/dump_setup.c ../build/native/libpqz.a
$out/dump_setup $out/c
(cd ligero && cargo run --release --offline --quiet --example dump_setup -- target/xcheck/rust)
rc=0
for r in reg tx burn ds dr; do
  for f in ${r}_stmt ${r}_wit; do
    if cmp -s $out/c/$f.bin $out/rust/$f.bin; then x=equal; else x=DIFFERENT; rc=1; fi
    echo "$f $(wc -c < $out/c/$f.bin) B c=$(sha256sum < $out/c/$f.bin | cut -c1-16) rust=$(sha256sum < $out/rust/$f.bin | cut -c1-16) $x"
  done
done
exit $rc
