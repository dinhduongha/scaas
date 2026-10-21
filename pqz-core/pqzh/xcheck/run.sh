#!/bin/sh
# PQZH cross-check: the statement and witness bytes of client::setup() (Rust) against pqz-core's
# test/pqz_bench.c setup() (C) for the same inputs; byte-identical or exit 1.
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/xcheck/run.sh  (output: runs/s5-xcheck.txt)
set -eu
cd "$(dirname "$0")/../stark-backup" # the STARK backup crate (dump_setup example)
out=target/xcheck
mkdir -p $out/c $out/rust
(cd ../../pqzl && PQZ_SET=n2048-kmax1024 ./build.sh native > /dev/null) # PQZH: the v3 set only (until plan 5h Task 8c)
${CC:-clang} -std=gnu11 -O2 -I../../pqzl/src -I../../pqzl/build/include -o $out/dump_setup ../xcheck/dump_setup.c ../../pqzl/build/native/libpqz.a
$out/dump_setup $out/c
cargo run --release --offline --quiet --example dump_setup -- $out/rust
rc=0
for f in reg_stmt reg_wit tx_stmt tx_wit; do
  if cmp -s $out/c/$f.bin $out/rust/$f.bin; then r=equal; else r=DIFFERENT; rc=1; fi
  echo "$f $(wc -c < $out/c/$f.bin) B c=$(sha256sum < $out/c/$f.bin | cut -c1-16) rust=$(sha256sum < $out/rust/$f.bin | cut -c1-16) $r"
done
exit $rc
