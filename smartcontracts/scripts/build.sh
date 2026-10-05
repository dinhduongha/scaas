#!/usr/bin/env bash
# Build one on-chain family (or all) with its native tool. Heavy: the caller wraps it in scripts/capped.
# usage: build.sh <evm|aptos|sui|soroban|cosmos|ton|solana|all>
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILIES="evm aptos sui soroban cosmos ton solana"
build() {
  echo "== build $1"
  case "$1" in
    evm)     (cd "$SC/evm" && forge build) ;;
    aptos)   aptos move compile --package-dir "$SC/move/aptos" --dev --skip-fetch-latest-git-deps ;;
    sui)     sui move build --path "$SC/move/sui" ;;
    soroban) (cd "$SC/soroban" && cargo build --target wasm32v1-none --release) ;;
    cosmos)  "$SC/cosmos/build-wasm.sh" ;;
    ton)     (cd "$SC/ton" && { [ -d node_modules ] || npm ci; } && npm run build) ;;
    solana)  (export PATH="$HOME/.local/share/solana/install/active_release/bin:$PATH"; cd "$SC/solana" && cargo build-sbf) ;;
    *) echo "unknown family '$1' (one of: $FAMILIES all)" >&2; exit 2 ;;
  esac
}
[ "${1:-}" = all ] && set -- $FAMILIES
[ $# -gt 0 ] || { echo "usage: $0 <$FAMILIES|all>" >&2; exit 2; }
for f in "$@"; do build "$f"; done
