#!/usr/bin/env bash
# Local networks for the bamboo-node e2e tests. Run under scripts/capped together with the e2e, then `down`.
# usage: devnet.sh <family> up|down|… [args…]   (dispatches to <family>/scripts/devnet.sh)
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILY="${1:?usage: $0 <aptos|solana> up|down|…}"; shift
case "$FAMILY" in
  aptos)  exec "$SC/move/aptos/scripts/devnet.sh" "$@" ;;
  solana) exec "$SC/solana/scripts/devnet.sh" "$@" ;;
  evm|sui|cosmos) echo "$FAMILY: the e2e test starts its own node (anvil / sui start / wasmd container)" >&2; exit 2 ;;
  soroban) echo "soroban: docker run -d --rm --name bamboo-stellar -p 127.0.0.1:31980:8000 stellar/quickstart --local --enable core,rpc,horizon (e2e_soroban: STELLAR_URL, STELLAR_BIN = stellar CLI >= 23)" >&2; exit 2 ;;
  ton)    echo "ton: e2e_ton runs the sandbox shim itself (npm ci there first)" >&2; exit 2 ;;
  *) echo "unknown family '$FAMILY'" >&2; exit 2 ;;
esac
