#!/bin/sh
# Builds the libFuzzer targets (P6e plan Task 10, D12) into pqz-core/build/fuzz/<target>, under scripts/capped:
#   scripts/capped pqz-core/fuzz/build.sh
#   PQZ_FUZZ_MODE=pqzl-diff scripts/capped pqz-core/fuzz/build.sh     -> pqz-core/build/fuzz/<target>-pqzl-diff
# (mode pqzl-diff: the C core too, compared with the Rust core on every input; src/lib.rs, README.md)
# Stable Rust (1.97.1), no nightly / cargo-fuzz: this crate (the oracles, src/lib.rs) with pqz-ffi, pqz-stmt and the
# Ligero crate and the Rust PQZL core instrumented by rustc's sanitizer-coverage pass (stable -C flags; overflow checks
# and debug assertions on, panics abort through the panic hook), in mode pqzl-diff the C core with ASan + UBSan +
# coverage (pqz-ffi features `fuzz`, `pqzl-c`), linked
# with targets/<target>.c by clang 18 (-fsanitize=fuzzer,address,undefined). --target keeps the flags off build scripts.
set -eu
cd "$(dirname "$0")"
B=$(cd .. && pwd)/build/fuzz
TRIPLE=x86_64-unknown-linux-gnu
case ${PQZ_FUZZ_MODE:-} in
  "") S= F= ;;
  pqzl-diff) S=-pqzl-diff F="--features pqzl-diff" ;;
  *) echo "PQZ_FUZZ_MODE=$PQZ_FUZZ_MODE: unset or pqzl-diff" >&2; exit 2 ;;
esac
mkdir -p "$B"
export CC=clang-18 CARGO_TARGET_DIR="$B/target$S"
export RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=4 \
-C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table \
-C llvm-args=-sanitizer-coverage-trace-compares"
cargo build --release --offline --target $TRIPLE $F
LIB=$CARGO_TARGET_DIR/$TRIPLE/release/libpqz_fuzz.a
for t in precompile mutate codec; do
  clang-18 -g -O1 -fsanitize=fuzzer,address,undefined -o "$B/$t$S" "targets/$t.c" "$LIB" -lpthread -ldl -lm -lrt -lgcc_s
done
ls -l "$B/precompile$S" "$B/mutate$S" "$B/codec$S"
