#!/bin/sh
# P6-ANON S4, LH-2 (plan Task H1 / pqzh-ligero.md §15.5): op 7 R_TXM statements across the C core, pqz-stmt, Ligero and
# pqz_kat.py, one job under scripts/capped:
#   scripts/capped pqz-core/ffi/vectors/lh2.sh <label>      -> ffi/vectors/runs/<label>-lh2.txt
# 1. pqz_bench.c's op 7 statements and witnesses (C, every TXB shape; xcheck/dump_setup.c mode txm);
# 2. the Ligero crate's (client::setup_multi, examples/dump_setup: default, fee 0 all decoys, two real legs);
# 3. examples/lh2.rs: the C ones with the op 7 opTag and recipientsHash set, under each id that builds M: pqz-stmt
#    parse + encode byte-equal, prove (PQZL: C core, PQZH: Ligero), precompile …01 (PQZL: generic verifier agrees),
#    recipientsHash flipped …00; the Ligero ones the same under both ids (PQZL: C proves Ligero's statements);
# 4. xcheck/kat_multi.py on the C statements (PQZH id): pqz_kat.py parses and rebuilds them and re-encrypts every
#    ciphertext from the C witness. Exit 1 if any step fails.
set -u
cd "$(dirname "$0")/.."
X=$(pwd)/target/lh2 R=vectors/runs/$1-lh2.txt
rm -rf "$X" && mkdir -p "$X/c" "$X/ligero" "$X/out" vectors/runs
fail=0
step() { name=$1; shift; echo "\$ $*"; "$@" || { echo "FAILED: $name (rc=$?)"; fail=1; }; }
{
  step build-c sh -c "cd ../pqzl && PQZ_SET=n2048-kmax1024 ./build.sh native > /dev/null"
  step dump-c sh -c "${CC:-clang} -std=gnu11 -O2 -I../pqzl/src -I../pqzl/build/include -o $X/dump_setup ../pqzh/xcheck/dump_setup.c ../pqzl/build/native/libpqz.a && $X/dump_setup $X/c txm"
  step dump-ligero sh -c "cd ../pqzh/ligero && cargo run -j2 --release --offline --quiet --example dump_setup -- $X/ligero"
  step lh2 cargo run -j2 --release --offline --quiet --features prove --example lh2 -- "$X/c" "$X/ligero" "$X/out"
  step kat_multi python3 -I ../pqzh/xcheck/kat_multi.py "$X/out"
  echo "lh2.sh $1: $([ $fail = 0 ] && echo ok || echo FAILED)"
} > "$R" 2>&1
tail -1 "$R"
exit $fail
