#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group `rescue` (CTR-GOV-25, spec 2026-11-12-rescue-vault.md), from smartcontracts/evm (matrix.sh runs it), two targets:
#   local: the RescueVault by script/DeployRescueVault.s.sol (the committed rescue-vault-init.hex through the CREATE2
#     deployer; it refuses bytes whose address is not RescueLib.SCAAS_DEV_RESCUE), then its admin and rescuer moved to the
#     test keys 1 and 2 by anvil_setStorageAt (slot 0 admin; slot 1 rescuer, seq 0 above it);
#   scaas-testnet: the vault of its genesis alloc (NET-EVM-14: admin test key 0x…01, rescuer 0x…02, seq 0); its code must be
#     the vector's (vectors/governance/rescue_vault_testnet_alloc.json). One run per chain: the run leaves seq 3, and
#     Rescue.s.sol refuses any start but seq 0.
# The real admin's key is never used: every admin row signs with the test keys. Then script/onchain/Rescue.s.sol by run.sh.
#   ONCHAIN_RPC=<rpc> PRIVATE_KEY=<funded test key> ONCHAIN_K1=.. ONCHAIN_K2=.. sh script/onchain/rescue.sh <local | scaas-testnet>
set -eu
net=${1:?target}
shift
RPC=${ONCHAIN_RPC:?ONCHAIN_RPC}
V=0xd33d17991f57BefB4CcBb3E57c477c10BdE5B465
case $net in
local) ;;
scaas-testnet)
  want=$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1]))["account"]["code"].lower())' \
    ../vectors/governance/rescue_vault_testnet_alloc.json)
  [ "$(cast code --rpc-url "$RPC" "$V" | tr 'A-F' 'a-f')" = "$want" ] ||
    { echo "[$net/rescue] FAIL the code at $V is not the genesis alloc's (NET-EVM-14)"; exit 1; }
  echo "[$net/rescue] vault $V from the genesis alloc: code = the vector's"
  exec sh script/onchain/run.sh "$net" Rescue --tc Rescue "$@" ;;
*) echo "[$net/rescue] FAIL local and scaas-testnet only (elsewhere the vault's admin is the real dev admin, NET-EVM-14)"; exit 1 ;;
esac
OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-matrix}
mkdir -p "$OUTD"
L=$OUTD/rescue-deploy-$net.log
echo "[$net/rescue] DeployRescueVault.s.sol …"
forge script script/DeployRescueVault.s.sol --rpc-url "$RPC" --broadcast --slow --private-key "$PRIVATE_KEY" \
  --out out/onchain-rescue --cache-path cache/onchain-rescue > "$L" 2>&1 ||
  { echo "[$net/rescue] FAIL DeployRescueVault: $(grep -E 'Error|revert' "$L" | tail -1 | cut -c1-160)"; exit 1; }
[ "$(cast code --rpc-url "$RPC" "$V")" != 0x ] || { echo "[$net/rescue] FAIL no code at $V"; exit 1; }
w1=$(cast abi-encode "f(address)" "$(cast wallet address --private-key "$ONCHAIN_K1")")
w2=$(cast abi-encode "f(address)" "$(cast wallet address --private-key "$ONCHAIN_K2")")
cast rpc --rpc-url "$RPC" anvil_setStorageAt "$V" 0x0 "$w1" > /dev/null
cast rpc --rpc-url "$RPC" anvil_setStorageAt "$V" 0x1 "$w2" > /dev/null
echo "[$net/rescue] vault $V: admin key 1, rescuer key 2 (anvil_setStorageAt)"
exec sh script/onchain/run.sh "$net" Rescue --tc Rescue "$@"
