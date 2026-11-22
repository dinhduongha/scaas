#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# scaas-sdk plan T20g: the JS / TS binding's smoke test (gate `bind-js`, CI cell `scaas-sdk-bindings` [js]), from this directory: builds
# this crate (the SDK with feature `wasm`) for wasm32-unknown-unknown, runs the wasm-bindgen CLI (WASM_BINDGEN, else
# `wasm-bindgen` on PATH; the crate's pin 0.2.130 exactly) into git-ignored pkg/ for Node, and runs test/ under `node --test`.
# The .wasm and its glue are build output, never committed. Through scripts/capped, in the foreground (on CI, which sets `CI`,
# directly).
set -euo pipefail
cd "$(dirname "$0")"
W=$(git rev-parse --show-toplevel)
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
want=0.2.130
have=$("${WASM_BINDGEN:-wasm-bindgen}" --version | awk '{print $2}')
[ "$have" = "$want" ] || { echo "[js] FAIL wasm-bindgen CLI $have, the crate's pin is $want" >&2 && exit 2; }
echo "[js] start: cargo build (wasm32)"
"${cap[@]}" cargo build --locked ${J:--j2} --release --target wasm32-unknown-unknown
echo "[js] ok: cargo build"
rm -rf pkg
"${WASM_BINDGEN:-wasm-bindgen}" --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/scaas_sdk_js.wasm
echo "[js] ok: wasm-bindgen"
"${cap[@]}" node --test test/
