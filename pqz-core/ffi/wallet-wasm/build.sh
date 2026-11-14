#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The wallet module of one parameter set (TODO 3zf; run under scripts/capped):
#   PQZ_SET=<set> pqz-core/ffi/wallet-wasm/build.sh [out-dir]   -> <out-dir>/pqz_wallet_<set>.wasm (default target/out)
# cargo for wasm32-unknown-unknown, then strip-exports.mjs (only lib.rs's exports). No built .wasm is committed.
set -eu
cd "$(dirname "$0")"
S=${PQZ_SET:-n2304-kmax4096}
O=${1:-target/out}
export CARGO_TARGET_DIR=${CARGO_TARGET_DIR:-$(pwd)/target/$S}
mkdir -p "$O"
cargo build --release --offline --no-default-features --features "set-$S" --target wasm32-unknown-unknown
node strip-exports.mjs "$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/pqz_wallet_wasm.wasm" "$O/pqz_wallet_$S.wasm"
