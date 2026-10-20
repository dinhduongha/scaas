#!/usr/bin/env bash
# UA-3 e2e on a dev chain (accounts.md CTR-UA-22; T-ZET): a fresh anvil (chain 31337, osaka, 64 KiB code), `deploy.sh
# evm` with DEPLOY_ZETHER=1 (the UA registry with its verifiers, the precompile probe through eth_call, the Zether
# stack), then on that chain:
#   1. a self `zether-bn254` UA: clientkeys makes the PoP against the deployed registry, a relayer submits it;
#   2. a `zether-bn254` UA whose `authRef` is the deployer EOA, co-signed with the EOA's EIP-712 UAAuth (cast);
#   3. a NONE_ZETHER token from the deployed factory shields to UA 1 (script/ZetherE2E.s.sol).
# Needs anvil, forge, cast, jq, node (clients/clientkeys with its node_modules). PORT (default 18545) for the anvil.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PORT="${PORT:-18545}"
RPC="http://127.0.0.1:$PORT"
anvil --chain-id 31337 --hardfork osaka --gas-limit 16777216 --code-size-limit 65536 --port "$PORT" --silent &
ANVIL=$!
trap 'kill "$ANVIL" 2>/dev/null || true' EXIT
for _ in $(seq 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
# anvil's dev accounts 0 (deployer) and 1 (a relayer that holds no UA key)
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
RELAYER=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
DEPLOYER="$(cast wallet address --private-key "$PRIVATE_KEY")"
DEPLOY_ZETHER=1 "$ROOT/smartcontracts/scripts/deploy.sh" evm "$RPC" --silent >/dev/null
J="$ROOT/smartcontracts/evm/deployments/31337.json"
REG="$(jq -r .ua_registry "$J")"
CUID="$(jq -r .chain_uid "$J")"
ZERO="0x$(printf '%064d' 0)"
call() { cast call "$REG" "$@" --rpc-url "$RPC"; }
register() { cast send "$REG" 'register(uint16,bytes,bytes,bytes32,bytes)' 0x0140 "$@" --private-key "$RELAYER" --rpc-url "$RPC" >/dev/null; }
# clientkeys: Y, UA and the registry PoP of the bn254 key x (hex) for authRef
pop() {
  node --input-type=module -e "
    import { zetherPop } from '$ROOT/clients/clientkeys/src/zether.js';
    import { fromHex } from '$ROOT/clients/clientkeys/src/bytes.js';
    const p = zetherPop('bn254', fromHex('$1'), { chainId: 31337, chainUid: '$CUID', registry: '$REG', authRef: '$2' });
    console.log(p.Y, p.UA, p.pop);"
}
# 1. self
read -r Y1 UA1 POP1 < <(pop "0x$(printf '%064x' 0x5eed1)" "$ZERO")
[ "$(call 'uaOf(uint16,bytes)(bytes32)' 0x0140 "$Y1")" = "$UA1" ]
register "$Y1" "$POP1" "$ZERO" 0x
[ "$(call 'kindOf(bytes32)(uint16)' "$UA1")" = 320 ]
[ "$(call 'keyOf(bytes32)(bytes)' "$UA1")" = "$Y1" ]
echo "1/3 self Zether UA registered (clientkeys PoP, relayed)"
# 2. authRef = the deployer EOA: UAAuth(authRef, PURPOSE_AUTHREF, popDigest(ua, authRef)) signed by the EOA
AUTH="$(cast abi-encode 'f(address)' "$DEPLOYER")"
read -r Y2 UA2 POP2 < <(pop "0x$(printf '%064x' 0x5eed2)" "$AUTH")
PD="$(call 'popDigest(bytes32,bytes32)(bytes32)' "$UA2" "$AUTH")"
H="$(call 'uaAuthDigest(bytes32,bytes32,bytes32)(bytes32)' "$AUTH" "$(cast keccak scaas.ua.purpose.authref.v1)" "$PD")"
register "$Y2" "$POP2" "$AUTH" "$(cast wallet sign --no-hash --private-key "$PRIVATE_KEY" "$H")"
[ "$(call 'recordOf(bytes32)((uint16,uint40,address),bytes32)' "$UA2" | tail -1)" = "$AUTH" ]
echo "2/3 Zether UA with a native authRef registered (EOA co-sign)"
# 3. the token side
cd "$ROOT/smartcontracts/evm"
ZETHER_Y="$Y1" forge script script/ZetherE2E.s.sol --rpc-url "$RPC" --broadcast --code-size-limit 65536 \
  --sender "$DEPLOYER" --silent >/dev/null
echo "3/3 NONE_ZETHER token shielded to UA 1 (registered by kindOf)"
echo "e2e-zether: 3/3 passed"
