#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# tests/smoke.c under AddressSanitizer (ua-rs-sign T12): the staticlib's Rust code instrumented too, so a child handle that
# read its freed wallet would be reported. From clients/ua-c, under scripts/capped:
#   scripts/capped tests/asan-smoke.sh
# -Zsanitizer needs the unstable flag: RUSTC_BOOTSTRAP=1 on the stable 1.97.1 toolchain, test builds only (target/asan, never a
# release artefact). std is not rebuilt (no -Zbuild-std): its own code is not instrumented, ours and every dependency's is.
# RUSTC_BOOTSTRAP=1 is accepted by the owner (2026-11-06) for this test-only ASan build in target/asan; nothing else here sets it.
set -eu
cd "$(dirname "$0")/.."
TRIPLE=x86_64-unknown-linux-gnu
export RUSTC_BOOTSTRAP=1 RUSTFLAGS="-Zsanitizer=address" CARGO_TARGET_DIR=target/asan
cargo build -j2 --locked --offline --target $TRIPLE
# clang-18 where the host has it (the version this was written for), else the first newer clang on PATH (CI runner images move)
CLANG=$(command -v clang-18 || command -v clang-19 || command -v clang-20 || command -v clang-21 || command -v clang) || { echo "no clang found" >&2; exit 1; }
"$CLANG" -std=c99 -g -O1 -fsanitize=address -fno-omit-frame-pointer -Wall -Wextra -Werror -Iinclude tests/smoke.c \
  "target/asan/$TRIPLE/debug/libscaas_ua_c.a" -lpthread -ldl -lm -o target/asan/smoke
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 target/asan/smoke
