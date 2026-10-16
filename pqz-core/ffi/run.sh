#!/bin/sh
# pqz-ffi (P6e Task 7): every check in one job under scripts/capped:
#   scripts/capped pqz-core/ffi/run.sh <label>           -> ffi/runs/<label>-*.txt / .jsonl
# tests (native, release, feature prove; the crate's unit tests without it), the verify-only cdylib and its symbol
# scans, the C smoke test against pqz_ffi.h, the wasm32 builds and the native = wasm32 digest diff, the bench.
set -u
cd "$(dirname "$0")"
L=runs/$1 X=$(pwd)/target/run
mkdir -p runs "$X"
OUT() { echo "\$ $*"; "$@"; echo "[rc=$?]"; }

{
  OUT cargo test --release --offline --lib
  PQZ_FFI_DIGESTS=$X/native.jsonl PQZ_FFI_FILL_OUT=$X/fill.txt OUT cargo test --release --offline --features prove,test-hooks -- --nocapture --test-threads 4
} > "$L-test.txt" 2>&1
cp "$X/fill.txt" "$L-fill.txt" 2>/dev/null

{
  echo "# verify-only build (default features): libpqz_ffi.so, and the C core archive build.rs compiled"
  OUT cargo build --release --offline
  echo "test hooks in the production cdylib (must be 0): $(strings -a target/release/libpqz_ffi.so | grep -c TEST_ARENA)"
  A=$(pwd)/$(ls -t target/release/build/pqz-ffi-*/out/libpqz.a | head -1)
  OUT ../pqzl/check_symbols.sh "$A"
  SO=target/release/libpqz_ffi.so
  OUT sha256sum "$SO"
  echo "\$ readelf -d $SO | grep NEEDED"; readelf -d "$SO" | grep NEEDED
  echo "\$ nm -D --undefined-only $SO"; nm -D --undefined-only "$SO"
  echo "\$ nm -D --defined-only $SO | grep ' T '"; nm -D --defined-only "$SO" | grep ' T '
  echo "# GMP / MPFR / HEXL names or strings (glic/absence.sh's pattern), libm and float imports"
  echo "symbols /gmp|mpfr|hexl/i: $(nm -A "$SO" 2>/dev/null | grep -ciE 'gmp|mpfr|hexl')"
  echo "strings /gmp|mpfr|hexl/i: $(strings -a "$SO" | grep -ciE 'gmp|mpfr|hexl')"
  echo "libm-style imports: $(nm -D --undefined-only "$SO" | awk '{print $2}' | grep -cE '^(sin|cos|tan|exp|exp2|log|log2|log10|pow|sqrt|floor|ceil|round|fmod|ldexp|frexp)f?(@|$)')"
  echo "# C smoke test against pqz_ffi.h"
  OUT clang -std=c11 -Wall -Wextra -o "$X/c_abi" tests/c_abi.c -Ltarget/release -lpqz_ffi -Wl,-rpath,"$(pwd)/target/release"
  OUT "$X/c_abi"
  echo "# clippy (stable toolchain: 1.97.1 has no clippy): no float arithmetic in the crate"
  OUT cargo +stable clippy --release --offline --features prove,test-hooks --lib -- -D clippy::float_arithmetic
} > "$L-native.txt" 2>&1

{
  echo "# wasm32: the verify-only lib, then the prove harness (wasm/) and the digest diff against native"
  OUT cargo build --release --offline --lib --target wasm32-unknown-unknown
  (cd wasm && OUT cargo build --release --offline --target wasm32-unknown-unknown)
  W=wasm/target/wasm32-unknown-unknown/release/pqz_ffi_wasm.wasm
  OUT sha256sum "$W"
  ls -l "$W" | awk '{print "wasm bytes", $5}'
  echo "\$ llvm-nm-18 --undefined-only $W (imports)"; llvm-nm-18 --undefined-only "$W"
  echo "strings /gmp|mpfr|hexl/i: $(strings -a "$W" | grep -ciE 'gmp|mpfr|hexl')"
  /usr/bin/time -v node wasm/run_wasm.mjs "$W" 3 > "$X/wasm.jsonl" 2> "$X/wasm-time.txt"
  echo "node rc=$?"; grep -E "wasm run|wasm PQZL|Maximum resident|Elapsed" "$X/wasm-time.txt"
  cp "$X/native.jsonl" "$L-digests-native.jsonl"; cp "$X/wasm.jsonl" "$L-digests-wasm.jsonl"
  if diff "$X/native.jsonl" "$X/wasm.jsonl"; then echo "native = wasm32: $(wc -l < "$X/wasm.jsonl") lines equal"; else echo "native != wasm32"; fi
} > "$L-wasm.txt" 2>&1

/usr/bin/time -v cargo run --release --offline --features prove,test-hooks --example ffi_bench "${N:-200}" > "$L-bench.jsonl" 2> "$L-bench-time.txt"
echo "bench rc=$?" >> "$L-bench-time.txt"

grep -hE "^test result|FAILED|panicked|^test .* (ok|FAILED)$|rejection cases|differential:|op 7 largest|abort-freedom:|selftest hash|node faults:|verify-only |fill determinism:" "$L-test.txt"
grep -hE "^c_abi|symbols ok|forbidden|NEEDED|/gmp|libm-style|\[rc=[1-9]" "$L-native.txt"
grep -hE "native|wasm bytes|wasm run|\[rc=[1-9]" "$L-wasm.txt"
tail -2 "$L-bench.jsonl"; grep -E "bench rc|Maximum resident" "$L-bench-time.txt"
