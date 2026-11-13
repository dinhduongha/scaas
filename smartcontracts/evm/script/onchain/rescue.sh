#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group `rescue` (CTR-GOV-25, spec 2026-11-12-rescue-vault.md), local only, from smartcontracts/evm (matrix.sh runs it under
# scripts/capped): the RescueVault by script/DeployRescueVault.s.sol (the committed rescue-vault-init.hex through the CREATE2
# deployer; it refuses bytes whose address is not RescueLib.SCAAS_DEV_RESCUE), then its admin and rescuer moved to the
# test keys 1 and 2 by anvil_setStorageAt (slot 0 admin; slot 1 rescuer, seq 0 above it): the real admin's key is never
# used. Then script/onchain/Rescue.s.sol through run.sh.
#   ONCHAIN_RPC=<anvil> PRIVATE_KEY=<funded test key> ONCHAIN_K1=.. ONCHAIN_K2=.. sh script/onchain/rescue.sh local [forge args]
set -eu
net=${1:?target}
shift
[ "$net" = local ] || { echo "[$net/rescue] FAIL local only (the test admin is set by anvil_setStorageAt)"; exit 1; }
RPC=${ONCHAIN_RPC:?ONCHAIN_RPC}
V=0xd33d17991f57BefB4CcBb3E57c477c10BdE5B465
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
