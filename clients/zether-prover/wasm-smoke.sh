#!/bin/bash
# Build the wasm package (wasm32-unknown-unknown + wasm-bindgen 0.2.129, nodejs target) and
# run the headless Node smoke test. Needs: rustup target wasm32-unknown-unknown,
# `cargo install wasm-bindgen-cli --version 0.2.129`, node >= 18. ZETHER_HAZMAT=1 builds both with the test-only feature
# `hazmat` (ARCH-POS-13: the raw decrypt / prove commands) and runs the prover checks; without it the smoke checks the refusal.
set -euo pipefail
cd "$(dirname "$0")"
F=()
[ "${ZETHER_HAZMAT:-}" = 1 ] && F=(--features hazmat)
cargo build --release "${F[@]}" --bin zether-cli
cargo build --release "${F[@]}" --lib --target wasm32-unknown-unknown
"${WASM_BINDGEN:-$HOME/.cargo/bin/wasm-bindgen}" --target nodejs --out-dir pkg \
  target/wasm32-unknown-unknown/release/zether_prover.wasm
"${NODE:-node}" smoke/smoke.cjs
