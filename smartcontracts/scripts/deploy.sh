#!/usr/bin/env bash
# Deploy one family's contracts with its native tool. Keys/credentials come from the tool's own config or env.
# usage: deploy.sh <family> <network> [args…]   (args go to the native tool)
#   evm     <rpc-url>        forge script script/Deploy.s.sol --broadcast; env PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?,
#                            DEMO_HOLDER?, CHAIN_UID? (genesis hash from evm/chain-uids.json; defaults to blockhash(0),
#                            which is 0 past block 256, so a long-running chain needs it), DEPLOY_SALT? (CREATE2 salt);
#                            FOUNDRY_PROFILE=private7622|gnosis|celo|bsc|polygon|base (all osaka). Needs the deterministic
#                            CREATE2 deployer on the chain (NET-EVM-05). Writes evm/deployments/<chainid>.json (the
#                            previous file is put back if the broadcast fails). Every chain gets the UA registry
#                            (`ua_registry`; its EIP-2537 / bn254-G2 kinds by an eth_call precompile probe, the Zether
#                            kinds on dev chains only, the PQ kinds on the dev chains and 7622 only: unaudited, P6c).
#                            Always --disable-code-size-limit (forge 1.8.5 also applies EIP-3860 to the script contract itself); every token implementation
#                            exceeds EIP-170 since the UA ledger (UA-4; owner: wait for Glamsterdam), so the chain needs
#                            64 KiB code (anvil --code-size-limit 65536, chain 7622 maxCodeSize 0x10000); a chain at
#                            24,576 refuses the deploy. Always --gas-estimate-multiplier 105: forge's default x1.30 on
#                            the BLS inner-product verifier (~14 M, DEPLOY_ZETHER) exceeds the 2^24 per-transaction cap
#                            (EIP-7825); the largest implementation, UnderlyingPqzToken (13,319,335 gas measured), is
#                            deployed by script/pqz/e2e.py, not here. DEPLOY_ZETHER=1 (dev chains only) adds the Zether
#                            stack. --slow always (one tx per block: anvil automine can strand a large tx).
#   hedera  <relay-url>      same, script/hedera/DeployHedera.s.sol --slow (writes deployments/hedera-<chainid>.json)
#   aptos   <cli-profile>    aptos move deploy-object --address-name scaas; Move.toml upgrade_policy = "immutable"
#                            (NET-APT-20, owner ruling 2026-10-28): check the package registry reports policy 2
#   sui     <client-env>     sui client --client.env <env> publish, then in the same run
#                            0x2::package::make_immutable(UpgradeCap) (NET-SUI-15, owner ruling 2026-10-28): the cap
#                            object is gone afterwards; the script stops if it cannot find or destroy it
#   soroban <network> <contract>   stellar contract deploy of scaas_<contract>.wasm (build.sh soroban first); STELLAR_BIN overrides the CLI
#   solana  <cluster-url> <program-keypair> <upgrade-authority-keypair>   solana/scripts/deploy.sh
#   near    <rpc-url> [gate <account…>]   near/scripts/deploy.sh: token(s), dex, relayfee, relayexec as sub-accounts of
#                            the funding account, initialised, every lane registered on every token, then every access
#                            key deleted (spec §3.9); fails unless view_access_key_list is empty for each; writes
#                            near/deployments/<genesis-hash>.json. env NEAR_ACCOUNT_ID + NEAR_PRIVATE_KEY (or
#                            NEAR_KEY_FILE), NEAR_TOKENS, NEAR_ADMIN, NEAR_LANES, NEAR_FUND (near/scripts/deploy.py)
set -euo pipefail
SC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FAMILY="${1:?usage: $0 <family> <network> [args…]}"; NET="${2:?network}"; shift 2
case "$FAMILY" in
  evm)     cd "$SC/evm"; Z=(--disable-code-size-limit) # forge 1.8.5: EIP-3860 on the script contract itself (Deploy.s.sol initcode > 48 KiB); the chain enforces 64 KiB
           Z+=(--gas-estimate-multiplier 105) # the BLS inner-product verifier (~14 M) must stay under the 2^24 tx cap
           # forge writes the JSON in the simulation, before the broadcast: keep the previous one until it succeeds
           J="deployments/$(cast chain-id --rpc-url "$NET").json"; [ -f "$J" ] && cp "$J" "$J.prev"
           if forge script script/Deploy.s.sol --rpc-url "$NET" --broadcast --slow "${Z[@]}" \
               --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@"; then rm -f "$J.prev"
           else [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"; exit 1; fi ;;
  hedera)  cd "$SC/evm" && exec forge script script/hedera/DeployHedera.s.sol --rpc-url "$NET" --broadcast --slow --disable-code-size-limit \
             --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@" ;;
  aptos)   exec aptos move deploy-object --package-dir "$SC/move/aptos" --address-name scaas --profile "$NET" "$@" ;;
  sui)     out="$(sui client --client.env "$NET" publish --json "$@" "$SC/move/sui")" || { echo "$out"; exit 1; }
           echo "$out"
           cap="$(python3 -c 'import json,sys; print(next(c["objectId"] for c in json.loads(sys.stdin.read())["objectChanges"]
                  if c.get("type") == "created" and c.get("objectType") == "0x2::package::UpgradeCap"))' <<< "$out")" \
             || { echo "no UpgradeCap in the publish output: make the package immutable by hand" >&2; exit 1; }
           # --gas-budget: older Sui CLIs require it (SUI_GAS_BUDGET, MIST)
           exec sui client --client.env "$NET" call --package 0x2 --module package --function make_immutable --args "$cap" \
             --gas-budget "${SUI_GAS_BUDGET:-50000000}" ;;
  soroban) C="${1:?contract (token|mandate|dex|smart_key_account)}"; shift
           exec "${STELLAR_BIN:-stellar}" contract deploy --network "$NET" --wasm "$SC/soroban/target/wasm32v1-none/release/scaas_$C.wasm" "$@" ;;
  solana)  exec "$SC/solana/scripts/deploy.sh" "$NET" "$@" ;;
  near)    exec "$SC/near/scripts/deploy.sh" "$NET" "$@" ;;
  cosmos|ton) echo "$FAMILY: no deploy tooling in this repo yet (build artifacts: build.sh $FAMILY)" >&2; exit 2 ;;
  *) echo "unknown family '$FAMILY'" >&2; exit 2 ;;
esac
