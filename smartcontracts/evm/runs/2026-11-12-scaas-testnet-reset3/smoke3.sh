#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 3: Step 5's smoke 1 and 2 (runs/2026-11-09-ua-mtx-merge-t66b-build/Smoke.s.sol) on the new deploy:
# the payer is the deployer (index 0 of SCAAS_TESTNET_MNEMONIC_FILE, it signs only), the relayer test key 0x…03 sends.
# Keys only in this process's environment, never printed.
#   sh runs/2026-11-12-scaas-testnet-reset3/smoke3.sh > runs/2026-11-12-scaas-testnet-reset3/smoke.log 2>&1
set -eu
cd "$(dirname "$0")/../.."
command -v forge > /dev/null || PATH=$HOME/.foundry/bin:$PATH
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
(umask 077; sed -n 's/^mnemonic:[[:space:]]*//p' "${SCAAS_TESTNET_MNEMONIC_FILE:?}" > "$T/m")
[ -s "$T/m" ] || (umask 077; grep -v '^#' "$SCAAS_TESTNET_MNEMONIC_FILE" > "$T/m")
SMOKE_PAYER_KEY=$(cast wallet private-key --mnemonic "$T/m" --mnemonic-index 0)
rm -f "$T/m"
SMOKE_RELAYER_KEY=$(printf '0x%064x' 3)
export SMOKE_PAYER_KEY SMOKE_RELAYER_KEY
S=runs/2026-11-09-ua-mtx-merge-t66b-build/Smoke.s.sol
# compile under scripts/capped, then the broadcast outside capped in a 1G scope with no slot (owner 2026-11-10); forge
# must not recompile there. The compile is forge script itself without --broadcast (a simulation, nothing sent): forge
# build "$S" compiled 40 files, forge script then 172, and that recompile in the 1G scope was killed (first try)
SENDER=$(cast wallet address --private-key "$SMOKE_RELAYER_KEY")
CAPPED_SLOTS=3 ../../scripts/capped env FOUNDRY_OUT=out/reset3-smoke FOUNDRY_CACHE_PATH=cache/reset3-smoke \
  DEPLOY_JSON=deployments/scaas-testnet.json forge script "$S" --rpc-url "$RPC" --sender "$SENDER" > "$T/sim" 2>&1 ||
  { cat "$T/sim"; exit 1; }
echo "compile and simulation under scripts/capped: ok"
# smoke 2's gas given explicitly: reset 2's RelayFeeRouter.relay ran out of gas at forge's estimate x 1.30 (336,779 asked,
# the node's eth_estimateGas 357,758, EIP-8037 state gas); here forge's estimate x 2.00
systemd-run --user --scope --quiet -p MemoryMax=1G -p MemorySwapMax=0 -- env FOUNDRY_OUT=out/reset3-smoke \
  FOUNDRY_CACHE_PATH=cache/reset3-smoke DEPLOY_JSON=deployments/scaas-testnet.json forge script "$S" \
  --rpc-url "$RPC" --broadcast --slow --gas-estimate-multiplier 200 \
  --sender "$SENDER" > "$T/out" 2>&1 || { cat "$T/out"; exit 1; }
cat "$T/out"
! grep -qE 'Compiling [0-9]+ files' "$T/out" || { echo "FAIL: forge recompiled inside the scope"; exit 1; }
