#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Builds ua-rs's libFuzzer binary (ua-rs-sign T11) into clients/ua-rs/target/fuzz/ua-fuzz, under scripts/capped:
#   scripts/capped clients/ua-rs/fuzz/build.sh
# pqz-core/fuzz's pattern: stable Rust (1.97.1, the root rust-toolchain.toml), no nightly / cargo-fuzz; this crate (the
# oracles, src/lib.rs, which exports LLVMFuzzerTestOneInput) with scaas-ua instrumented by rustc's sanitizer-coverage pass
# (stable -C flags; overflow checks and debug assertions on, panic = abort), linked by clang 18 with libFuzzer
# (-fsanitize=fuzzer,address,undefined). --target keeps the flags off build scripts. One binary for every target: run.sh
# names it in UA_FUZZ_TARGET.
set -eu
cd "$(dirname "$0")"
B=$(cd .. && pwd)/target/fuzz${UA_FUZZ_TAG:+-$UA_FUZZ_TAG} # UA_FUZZ_TAG: a build of its own (the mutant harness)
TRIPLE=x86_64-unknown-linux-gnu
mkdir -p "$B"
export CC=clang-18 CARGO_TARGET_DIR="$B/target"
export RUSTFLAGS="-C passes=sancov-module -C llvm-args=-sanitizer-coverage-level=4 \
-C llvm-args=-sanitizer-coverage-inline-8bit-counters -C llvm-args=-sanitizer-coverage-pc-table \
-C llvm-args=-sanitizer-coverage-trace-compares"
cargo build -j2 --release --locked --offline --target $TRIPLE
clang-18 -g -O1 -fsanitize=fuzzer,address,undefined -o "$B/ua-fuzz" "$CARGO_TARGET_DIR/$TRIPLE/release/libscaas_ua_fuzz.a" \
  -lpthread -ldl -lm -lrt -lgcc_s
ls -l "$B/ua-fuzz"
