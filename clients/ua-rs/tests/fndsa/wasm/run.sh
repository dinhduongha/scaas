#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# CLI-UAL-66: the Falcon gate in wasm32, from this directory: builds this crate (ua-rs, `vectors`, falcon-rs) for
# wasm32-unknown-unknown in release, runs the wasm-bindgen CLI (WASM_BINDGEN, else `wasm-bindgen` on PATH; the pin 0.2.130
# exactly) into git-ignored pkg/ for Node and runs run.cjs: every FN-DSA row and the wallet's Falcon keys and signatures,
# against PQClean's digest. Through scripts/capped, in the foreground (on CI, which sets `CI`, directly).
set -euo pipefail
cd "$(dirname "$0")"
W=$(git rev-parse --show-toplevel)
cap=("$W/scripts/capped")
[ -n "${CI:-}" ] && cap=()
want=0.2.130
have=$("${WASM_BINDGEN:-wasm-bindgen}" --version | awk '{print $2}')
[ "$have" = "$want" ] || { echo "[fndsa-wasm] FAIL wasm-bindgen CLI $have, the crate's pin is $want" >&2 && exit 2; }
echo "[fndsa-wasm] start: cargo build (wasm32)"
"${cap[@]}" cargo build --locked ${J:--j2} --release --target wasm32-unknown-unknown
echo "[fndsa-wasm] ok: cargo build"
rm -rf pkg
"${WASM_BINDGEN:-wasm-bindgen}" --target nodejs --out-dir pkg target/wasm32-unknown-unknown/release/scaas_ua_fndsa_wasm.wasm
echo "[fndsa-wasm] ok: wasm-bindgen"
"${cap[@]}" node run.cjs
