#!/usr/bin/env bash
# Deploy one family's contracts with its native tool. Keys/credentials come from the tool's own config or env.
# usage: deploy.sh <family> <network> [args…]   (args go to the native tool)
#   evm     <rpc-url>        forge script script/Deploy.s.sol --broadcast; env PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?,
#                            DEMO_HOLDER?, CHAIN_UID? (genesis hash from evm/chain-uids.json; defaults to blockhash(0),
#                            which is 0 past block 256, so a long-running chain needs it), DEPLOY_SALT? (CREATE2 salt);
#                            FOUNDRY_PROFILE=private7622|gnosis|celo|bsc|polygon|base (all osaka). Needs the deterministic
#                            CREATE2 deployer on the chain (NET-EVM-05). Writes evm/deployments/<chainid>.json (the
#                            previous file is put back if the broadcast fails). DEPLOY_ZETHER=1 (dev chains only) adds
#                            the Zether stack and the forge flags it needs: --code-size-limit 65536
#                            --gas-estimate-multiplier 105 (the anvil needs --code-size-limit 65536 too).
#   hedera  <relay-url>      same, script/hedera/DeployHedera.s.sol --slow (writes deployments/hedera-<chainid>.json)
#   aptos   <cli-profile>    aptos move deploy-object --address-name scaas
#   sui     <client-env>     sui client --client.env <env> publish
#   soroban <network> <contract>   stellar contract deploy of scaas_<contract>.wasm (build.sh soroban first); STELLAR_BIN overrides the CLI
#   solana  <cluster-url> <program-keypair> <upgrade-authority-keypair>   solana/scripts/deploy.sh
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILY="${1:?usage: $0 <family> <network> [args…]}"; NET="${2:?network}"; shift 2
case "$FAMILY" in
  evm)     cd "$SC/evm"; Z=()
           case "${DEPLOY_ZETHER:-}" in 1|true|TRUE|True) Z=(--code-size-limit 65536 --gas-estimate-multiplier 105) ;; esac
           # forge writes the JSON in the simulation, before the broadcast: keep the previous one until it succeeds
           J="deployments/$(cast chain-id --rpc-url "$NET").json"; [ -f "$J" ] && cp "$J" "$J.prev"
           if forge script script/Deploy.s.sol --rpc-url "$NET" --broadcast "${Z[@]}" \
               --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@"; then rm -f "$J.prev"
           else [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"; exit 1; fi ;;
  hedera)  cd "$SC/evm" && exec forge script script/hedera/DeployHedera.s.sol --rpc-url "$NET" --broadcast --slow \
             --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@" ;;
  aptos)   exec aptos move deploy-object --package-dir "$SC/move/aptos" --address-name scaas --profile "$NET" "$@" ;;
  sui)     exec sui client --client.env "$NET" publish "$@" "$SC/move/sui" ;;
  soroban) C="${1:?contract (token|mandate|dex|account)}"; shift
           exec "${STELLAR_BIN:-stellar}" contract deploy --network "$NET" --wasm "$SC/soroban/target/wasm32v1-none/release/scaas_$C.wasm" "$@" ;;
  solana)  exec "$SC/solana/scripts/deploy.sh" "$NET" "$@" ;;
  cosmos|ton) echo "$FAMILY: no deploy tooling in this repo yet (build artifacts: build.sh $FAMILY)" >&2; exit 2 ;;
  *) echo "unknown family '$FAMILY'" >&2; exit 2 ;;
esac
