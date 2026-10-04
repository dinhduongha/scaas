#!/bin/bash
# Build the wasm package (wasm32-unknown-unknown + wasm-bindgen 0.2.129, nodejs target) and
# run the headless Node smoke test. Needs: rustup target wasm32-unknown-unknown,
# `cargo install wasm-bindgen-cli --version 0.2.129`, node >= 18.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --bin zether-cli
cargo build --release --lib --target wasm32-unknown-unknown
"${WASM_BINDGEN:-$HOME/.cargo/bin/wasm-bindgen}" --target nodejs --out-dir pkg \
  target/wasm32-unknown-unknown/release/zether_prover.wasm
"${NODE:-node}" smoke/smoke.cjs
