#!/usr/bin/env bash
# Local networks for the scaas-node e2e tests. Run under scripts/capped together with the e2e, then `down`.
# usage: devnet.sh <family> up|down|… [args…]   (dispatches to <family>/scripts/devnet.sh)
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILY="${1:?usage: $0 <aptos|solana|algorand|near|soroban> up|down|…}"; shift
case "$FAMILY" in
  aptos)  exec "$SC/move/aptos/scripts/devnet.sh" "$@" ;;
  solana) exec "$SC/solana/scripts/devnet.sh" "$@" ;;
  algorand) exec "$SC/algorand/scripts/devnet.sh" "$@" ;;
  near)   exec "$SC/near/scripts/devnet.sh" "$@" ;;   # near-sandbox (no docker); e2e_near starts it itself
  evm|sui|cosmos) echo "$FAMILY: the e2e test starts its own node (anvil / sui start / wasmd container)" >&2; exit 2 ;;
  soroban) exec "$SC/soroban/scripts/quickstart.sh" "$@" ;;   # pinned quickstart at Protocol 30 (up|down|wait|cli)
  ton)    echo "ton: e2e_ton runs the sandbox shim itself (npm ci there first)" >&2; exit 2 ;;
  *) echo "unknown family '$FAMILY'" >&2; exit 2 ;;
esac
