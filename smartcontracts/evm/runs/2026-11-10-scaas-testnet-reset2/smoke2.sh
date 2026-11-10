#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 2: Step 5's smoke 1 and 2 (runs/2026-11-09-ua-mtx-merge-t66b-build/Smoke.s.sol) on the new deploy:
# the payer is the deployer (index 0 of SCAAS_TESTNET_MNEMONIC_FILE, it signs only), the relayer test key 0x…03 sends.
# Keys only in this process's environment, never printed.
#   sh runs/2026-11-10-scaas-testnet-reset2/smoke2.sh > runs/2026-11-10-scaas-testnet-reset2/smoke.log 2>&1
set -eu
cd "$(dirname "$0")/../.."
RPC=${RPC_7622:-http://127.0.0.1:8545}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "${SCAAS_TESTNET_MNEMONIC_FILE:?}" > "$T/m")
[ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
SMOKE_PAYER_KEY=$(cast wallet private-key --mnemonic "$T/m" --mnemonic-index 0)
rm -f "$T/m"
SMOKE_RELAYER_KEY=$(printf '0x%064x' 3)
export SMOKE_PAYER_KEY SMOKE_RELAYER_KEY
CAPPED_SLOTS=3 ../../scripts/capped env FOUNDRY_OUT=out/reset2-smoke FOUNDRY_CACHE_PATH=cache/reset2-smoke \
  DEPLOY_JSON=deployments/7622.json forge script runs/2026-11-09-ua-mtx-merge-t66b-build/Smoke.s.sol \
  --rpc-url "$RPC" --broadcast --slow --sender "$(cast wallet address --private-key "$SMOKE_RELAYER_KEY")"
