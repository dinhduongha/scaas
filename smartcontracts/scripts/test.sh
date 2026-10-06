#!/usr/bin/env bash
# Run one on-chain family's local test suite (or all) with its native tool. Heavy: wrap in scripts/capped.
# usage: test.sh <evm|aptos|sui|soroban|cosmos|ton|solana|all>
# Localnet e2e tests live in scaas-node (cargo test --test e2e_<family> -- --ignored), not here.
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILIES="evm aptos sui soroban cosmos ton solana"
run() {
  echo "== test $1"
  case "$1" in
    evm)     (cd "$SC/evm" && forge test) ;;
    aptos)   aptos move test --package-dir "$SC/move/aptos" --dev --skip-fetch-latest-git-deps \
               && "$SC/move/aptos/scripts/check_entry_visibility.sh" ;;
    sui)     sui move test --path "$SC/move/sui" ;;
    soroban) (cd "$SC/soroban" && cargo test) ;;
    cosmos)  (cd "$SC/cosmos" && cargo test) ;;
    ton)     (cd "$SC/ton" && { [ -d node_modules ] || npm ci; } && npm test) ;;
    # LiteSVM loads target/deploy/scaas.so, so the SBF build comes first.
    solana)  "$SC/scripts/build.sh" solana && (cd "$SC/solana" && cargo test) ;;
    *) echo "unknown family '$1' (one of: $FAMILIES all)" >&2; exit 2 ;;
  esac
}
[ "${1:-}" = all ] && set -- $FAMILIES
[ $# -gt 0 ] || { echo "usage: $0 <$FAMILIES|all>" >&2; exit 2; }
for f in "$@"; do run "$f"; done
