#!/bin/sh
# Builds the libFuzzer targets (P6e plan Task 10, D12) into pqz-core/build/fuzz/<target>, under scripts/capped:
#   scripts/capped pqz-core/fuzz/build.sh
# Stable Rust (1.97.1), no nightly / cargo-fuzz: this crate (the oracles, src/lib.rs) with pqz-ffi, pqz-stmt and the
# Ligero crate instrumented by rustc's sanitizer-coverage pass (stable -C flags; overflow checks and debug assertions
# on, panics abort through the panic hook), the C core with ASan + UBSan + coverage (pqz-ffi feature `fuzz`), linked
# with targets/<target>.c by clang 18 (-fsanitize=fuzzer,address,undefined). --target keeps the flags off build scripts.
set -eu
cd "$(dirname "$0")"
B=$(cd .. && pwd)/build/fuzz
TRIPLE=x86_64-unknown-linux-gnu
mkdir -p "$B"
export CC=clang-18 CARGO_TARGET_DIR="$B/target"
export RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=4 \
-C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table \
-C llvm-args=-sanitizer-coverage-trace-compares"
cargo build --release --offline --target $TRIPLE
LIB=$B/target/$TRIPLE/release/libpqz_fuzz.a
for t in precompile mutate codec; do
  clang-18 -g -O1 -fsanitize=fuzzer,address,undefined -o "$B/$t" "targets/$t.c" "$LIB" -lpthread -ldl -lm -lrt -lgcc_s
done
rm -f "$B/honest.bin" # the cached honest proofs: re-proved by the first run (the prover may have changed)
ls -l "$B/precompile" "$B/mutate" "$B/codec"
