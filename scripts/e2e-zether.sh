#!/usr/bin/env bash
# UA-3 e2e on a dev chain (accounts.md CTR-UA-22; T-ZET; UA-6: BLS12-381 only, no `authRef`): a fresh anvil (chain
# 31337, osaka, 64 KiB code), `deploy.sh evm` with DEPLOY_ZETHER=1 (the UA registry with its verifiers, the precompile
# probe through eth_call, the Zether stack), then on that chain:
#   1. a `zether-bls12381` UA: clientkeys makes the PoP against the deployed registry, a relayer submits it;
#   2. a NONE_ZETHER token from the deployed factory shields to it (script/ZetherE2E.s.sol).
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
call() { cast call "$REG" "$@" --rpc-url "$RPC"; }
# clientkeys: Y, UA and the registry PoP of the BLS12-381 key x (hex), over popDigest(ua, 0)
pop() {
  node --input-type=module -e "
    import { zetherPop } from '$ROOT/clients/clientkeys/src/zether.js';
    import { fromHex } from '$ROOT/clients/clientkeys/src/bytes.js';
    const p = zetherPop('bls12381', fromHex('$1'), { chainId: 31337, chainUid: '$CUID', registry: '$REG' });
    console.log(p.Y, p.UA, p.pop);"
}
# 1. the Zether UA (register(kind, keyData, pop, pqzKey, pqzProof): no PQZ key)
read -r Y1 UA1 POP1 < <(pop "0x$(printf '%064x' 0x5eed1)")
[ "$(call 'uaOf(uint16,bytes)(bytes32)' 0x0141 "$Y1")" = "$UA1" ]
cast send "$REG" 'register(uint16,bytes,bytes,bytes,bytes)' 0x0141 "$Y1" "$POP1" 0x 0x --private-key "$RELAYER" \
  --rpc-url "$RPC" >/dev/null
[ "$(call 'kindOf(bytes32)(uint16)' "$UA1")" = 321 ]
[ "$(call 'keyOf(bytes32)(bytes)' "$UA1")" = "$Y1" ]
echo "1/2 Zether UA registered (clientkeys PoP, relayed)"
# 2. the token side
cd "$ROOT/smartcontracts/evm"
ZETHER_Y="$Y1" forge script script/ZetherE2E.s.sol --rpc-url "$RPC" --broadcast --code-size-limit 65536 \
  --sender "$DEPLOYER" --silent >/dev/null
echo "2/2 NONE_ZETHER token shielded to the Zether UA (registered by kindOf)"
echo "e2e-zether: 2/2 passed"
