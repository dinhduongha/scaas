#!/usr/bin/env bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet reset 1 (2026-11-04): a governance smoke on the deploy JSON's GovernanceRouter (CTR-GOV-15 Change): one owner
# op through the router at fee 0, relayed by another key. The owner (test key 0x…04, the registrar) creates a DEX from the
# factory's latest DEX release with itself (its native id, the padded address, CTR-GOV-01 Change) as owner; it signs the typed
# `SetListedOnly` (EIP-712, the router's domain); test key 0x…03 sends `mtxSetListedOnly` (fee 0, no relayer bound);
# `listedOnly()` must turn from false to true. Keys come from the environment and are never printed.
#   OWNER_KEY=<0x…04> RELAYER_KEY=<0x…03> [RPC=…] [J=deployments/7622.json] runs/2026-11-04-gov-smoke-7622.sh
set -euo pipefail
cd "$(dirname "$0")/.."
RPC=${RPC:-http://127.0.0.1:8545}
J=${J:-deployments/7622.json}
: "${OWNER_KEY:?}" "${RELAYER_KEY:?}"
FAC=$(jq -r .token_factory "$J"); ROUTER=$(jq -r .governance_router "$J")
OWNER=$(cast wallet address --private-key "$OWNER_KEY"); RELAYER=$(cast wallet address --private-key "$RELAYER_KEY")
O32=$(cast to-uint256 "$OWNER")   # the native id: the address as a word
Z=0x0000000000000000000000000000000000000000
echo "factory $FAC router $ROUTER owner $OWNER (native id $O32) relayer $RELAYER"
echo "router chainUid $(cast call "$ROUTER" 'chainUid()(bytes32)' --rpc-url "$RPC"), registry $(cast call "$ROUTER" 'registry()(address)' --rpc-url "$RPC" 2>/dev/null || echo '?')"
V=$(cast call "$FAC" 'latestDexVersion()(uint64)' --rpc-url "$RPC")
INIT=$(cast abi-encode 'f((bytes32,uint32,address,bool,uint64,address))' "($O32,0,$OWNER,false,0,$OWNER)")
SALT=$(cast keccak "gov-smoke-$(date +%s)")
DEX=$(cast call "$FAC" 'createDex(uint64,bytes,bytes32)(address)' "$V" "$INIT" "$SALT" --from "$OWNER" --rpc-url "$RPC")
cast send "$FAC" 'createDex(uint64,bytes,bytes32)' "$V" "$INIT" "$SALT" --private-key "$OWNER_KEY" --rpc-url "$RPC" --json \
  | jq -r '"createDex: tx \(.transactionHash) status \(.status) block \(.blockNumber) gasUsed \(.gasUsed)"'
echo "DEX v$V at $DEX: owner $(cast call "$DEX" 'owner()(bytes32)' --rpc-url "$RPC"), govRouter $(cast call "$DEX" 'govRouter()(address)' --rpc-url "$RPC" 2>/dev/null || echo '?'), listedOnly $(cast call "$DEX" 'listedOnly()(bool)' --rpc-url "$RPC")"
# the digest: SetListedOnly(from, target, on, batch, nonce, validUntil, mode, relayer, fee, feeRecipient) in the router's domain
N=$(cast call "$ROUTER" 'uaNonce(bytes32,uint256)(uint256)' "$O32" 0 --rpc-url "$RPC")
VU=$(( $(date +%s) + 3600 ))
D=$(cast call "$ROUTER" 'eip712Domain()(bytes1,string,string,uint256,address,bytes32,uint256[])' --rpc-url "$RPC")
NAME=$(sed -n 2p <<< "$D" | tr -d '"'); VER=$(sed -n 3p <<< "$D" | tr -d '"'); CID=$(sed -n 4p <<< "$D" | cut -d' ' -f1)
VC=$(sed -n 5p <<< "$D"); DS=$(sed -n 6p <<< "$D")
echo "domain: name \"$NAME\" version \"$VER\" chainId $CID verifyingContract $VC salt $DS; nonce $N validUntil $VU"
DSEP=$(cast keccak "$(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address,bytes32)' \
  "$(cast keccak 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)')" \
  "$(cast keccak "$NAME")" "$(cast keccak "$VER")" "$CID" "$VC" "$DS")")
TH=$(cast keccak 'SetListedOnly(address from,address target,bool on,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)')
SH=$(cast keccak "$(cast abi-encode 'f(bytes32,address,address,bool,uint256,uint256,uint256,uint32,address,uint256,address)' \
  "$TH" "$OWNER" "$DEX" true 0 "$N" "$VU" 0 "$Z" 0 "$Z")")
DIG=$(cast keccak "$(cast concat-hex 0x1901 "$DSEP" "$SH")")
SIG=$(cast wallet sign --no-hash "$DIG" --private-key "$OWNER_KEY")
echo "digest $DIG"
cast send "$ROUTER" 'mtxSetListedOnly((address,uint256,uint256,uint256,uint32,address,uint256,address),address,bool,bytes)' \
  "($OWNER,0,$N,$VU,0,$Z,0,$Z)" "$DEX" true "$SIG" --private-key "$RELAYER_KEY" --rpc-url "$RPC" --json \
  | jq -r '"mtxSetListedOnly (sent by the relayer, fee 0): tx \(.transactionHash) status \(.status) block \(.blockNumber) gasUsed \(.gasUsed) logs \(.logs | length)"'
L=$(cast call "$DEX" 'listedOnly()(bool)' --rpc-url "$RPC")
echo "listedOnly after: $L; router nonce now $(cast call "$ROUTER" 'uaNonce(bytes32,uint256)(uint256)' "$O32" 0 --rpc-url "$RPC")"
[ "$L" = true ] && echo "gov-smoke: ok" || { echo "gov-smoke: FAIL"; exit 1; }
