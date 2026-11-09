#!/usr/bin/env bash
# Deploy one family's contracts with its native tool. Keys/credentials come from the tool's own config or env.
# usage: deploy.sh <family> <network> [args…]   (args go to the native tool)
#   evm     <rpc-url>        forge script script/Deploy.s.sol --broadcast; env PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?,
#                            DEMO_HOLDER?, CHAIN_UID? (genesis hash from evm/chain-uids.json; defaults to blockhash(0),
#                            which is 0 past block 256, so a long-running chain needs it), DEPLOY_SALT? (CREATE2 salt);
#                            FOUNDRY_PROFILE=scaas-testnet|gnosis|celo|bsc|polygon|base (all osaka). Needs the deterministic
#                            CREATE2 deployer on the chain (NET-EVM-05). Writes evm/deployments/<chainid>.json (the
#                            previous file is put back if the broadcast fails). Every chain gets the UA registry
#                            (`ua_registry`; its EIP-2537 / bn254-G2 kinds by an eth_call precompile probe, the Zether
#                            kind on every chain with EIP-2537, the PQ kinds
#                            wherever their cap fits half the verify budget: unaudited, P6c; no chain-id lock).
#                            Always --disable-code-size-limit (forge 1.8.5 also applies EIP-3860 to the script contract itself); every token implementation
#                            exceeds EIP-170 since the UA ledger (UA-4; owner: wait for Glamsterdam), so the chain needs
#                            64 KiB code (anvil --code-size-limit 65536, chain 7622 maxCodeSize 0x10000 until the next reset);
#                            a chain at 24,576 refuses the deploy. CHAIN_CODE_LIMIT? (default 65,536, EIP-7954): the chain's
#                            declared code limit, a release above it refused by name before anything is sent (CTR-GOV-19,
#                            GD-4); the SCaaS testnet after the reset of pqz-core/nethermind/chain/RUNBOOK.md ("Code size
#                            128 KiB"): 131072. DEPLOY_WRAPPED=1 adds the WRAPPED release (GD-12); DEPLOY_REGULATED=1 the regulated releases 8, 9, enabled (10, 11 come with
#                            DEPLOY_ZETHER, 12, 13 with script/pqz/e2e.py) and the canonical ComplianceRegistry by CREATE2, its
#                            admin COMPLIANCE_ADMIN (an address with code, CTR-AS-07; none or an EOA refused AdminNotContract):
#                            JSON compliance_registry, compliance_registry_codehash (every regulated release's REGISTRY_CODEHASH).
#                            The admin then attests each DEX venue (createDex) and its puller() ELIGIBLE_CONTRACT, validUntil
#                            2^64-1, before an ALLOWLIST token trades there: its own call, this script holds no admin key.
#                            Always --gas-estimate-multiplier 105: forge's default x1.30 on
#                            the BLS inner-product verifier (~14 M, DEPLOY_ZETHER) exceeds the 2^24 per-transaction cap
#                            (EIP-7825); the largest implementation, WrappedPqzToken (13,319,335 gas measured), is
#                            deployed by script/pqz/e2e.py, not here. DEPLOY_ZETHER=1 (any chain but Hedera) adds the Zether
#                            stack. --slow always (one tx per block: anvil automine can strand a large tx).
#                            T66b: each token release and the DEX come with their body modules (P, T, A, W, Z, Q; the
#                            DEX's D), each its own CREATE2 transaction through the deterministic deployer with DEPLOY_SALT
#                            (the same address on every chain) and its own gate, pinned in the release's env after the
#                            libraries and named in its implArgs; releases.json gets a row per module (class 0, its kind).
#                            RELEASE_GAS_GATE? (Q4 of CTR-MTX-30, NET-EVM-06; declared, never derived from a chain id):
#                            testnet (default, the SCaaS testnet's gate: runtime x 1,530 + 2^24 within the block gas
#                            limit) or public (a public chain: each release transaction, the UA registry and its library
#                            run once in the simulation on the RPC's fork, (regular + state) x 1.05 within the block gas
#                            limit and regular x 1.05 < 2^24, refused by name before anything is sent; the figures are the
#                            script's "release gas |" log lines). Any other value refuses.
#   hedera  <relay-url>      same, script/hedera/DeployHedera.s.sol --slow (writes deployments/hedera-<chainid>.json)
#   aptos   <cli-profile>    aptos move deploy-object --address-name scaas; Move.toml upgrade_policy = "immutable"
#                            (NET-APT-20, owner ruling 2026-10-28): check the package registry reports policy 2
#   sui     <client-env>     sui client --client.env <env> publish, then in the same run
#                            0x2::package::make_immutable(UpgradeCap) (NET-SUI-15, owner ruling 2026-10-28): the cap
#                            object is gone afterwards; the script stops if it cannot find or destroy it
#   soroban <network> <contract>   stellar contract deploy of scaas_<contract>.wasm (build.sh soroban first); STELLAR_BIN overrides the CLI
#                            constructor args after `--`; the token: --admin --decimals --name --symbol [--registry '"C…"']
#                            (--registry omitted = None: the UA ledger is off, UaLedgerOff)
#                            relay_fee: deploys the executor and the router, each constructor naming the other (the
#                            router's id derived first from a salt, SOROBAN_SALT = 64 hex or random); "$@" = tx options
#                            only (--source <acct>); prints the router id (controller ruling 2026-10-31, T8 review)
#                            every deployed contract is warmed: instance + code extended to the 60-day TTL target by the
#                            deployer (no relayed job pays a first-call rent; controller ruling 2026-10-31, T10 review)
#   solana  <cluster-url> <program-keypair> <upgrade-authority-keypair>   solana/scripts/deploy.sh
#   near    <rpc-url> [gate <account…>]   near/scripts/deploy.sh: token(s), dex, relayfee, relayexec as sub-accounts of
#                            the funding account, initialised, every lane registered on every token, then every access
#                            key deleted (spec §3.9); fails unless view_access_key_list is empty for each; writes
#                            near/deployments/<genesis-hash>.json. env NEAR_ACCOUNT_ID + NEAR_PRIVATE_KEY (or
#                            NEAR_KEY_FILE), NEAR_TOKENS, NEAR_ADMIN, NEAR_LANES, NEAR_FUND (near/scripts/deploy.py)
#   algorand <algod-url> [gate <role>=<app id>…]   algorand/scripts/deploy.sh: account, relayfee (its off-curve executor
#                            salt), token(s), mandate, dex in that order, each app address funded with its base minimum;
#                            fails unless each app's approval / clear sha512_256 equals artifacts.json (programs that reject
#                            update and delete), the links (account_app, router_app) and the executor hold; resumable;
#                            writes algorand/deployments/<genesis-hash, URL-safe base64>.json. env ALGORAND_MNEMONIC (or
#                            ALGORAND_PRIVATE_KEY), ALGOD_TOKEN, ALGORAND_TOKENS, ALGORAND_ADMIN (algorand/scripts/deploy.py)
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
  soroban) C="${1:?contract (token|mandate|dex|smart_key_account|relay_fee|ua_registry)}"; shift
           ST="${STELLAR_BIN:-stellar}"; W="$SC/soroban/target/wasm32v1-none/release"
           # `contract id wasm` / `contract extend` take only the source / RPC / config options: pass those of "$@" before
           # `--` (a deploy-only option such as --alias or --inclusion-fee would make them fail)
           I=(); A=("$@")
           for ((i = 0; i < ${#A[@]}; i++)); do
             case "${A[i]}" in
               --) break ;;
               -s|--source|--source-account|--rpc-url|--rpc-header|--network-passphrase|--config-dir|--hd-path)
                 I+=("${A[i]}" "${A[i + 1]-}"); i=$((i + 1)) ;;
               --source=*|--source-account=*|--rpc-url=*|--rpc-header=*|--network-passphrase=*|--config-dir=*|--hd-path=*)
                 I+=("${A[i]}") ;;
             esac
           done
           # Warm (controller ruling 2026-10-31, T10 review): the instance and its code extended to the contracts' 60-day
           # TTL target (S11: extend_ttl(30 days, 60 days)) by the deployer, so no relayed job pays a first-call rent.
           warm() {
             "$ST" contract extend --network "$NET" --id "$1" --ledgers-to-extend 1036800 "${I[@]}" >&2
             "$ST" contract extend --network "$NET" --wasm "$2" --ledgers-to-extend 1036800 "${I[@]}" >&2
           }
           if [ "$C" = relay_fee ]; then
             S="${SOROBAN_SALT:-$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')}"
             R="$("$ST" contract id wasm --network "$NET" --salt "$S" "${I[@]}")"
             X="$("$ST" contract deploy --network "$NET" --wasm "$W/scaas_relay_executor.wasm" "$@" -- --router "$R")"
             got="$("$ST" contract deploy --network "$NET" --wasm "$W/scaas_relay_fee.wasm" --salt "$S" "$@" -- --executor "$X")"
             [ "$got" = "$R" ] || { echo "router id $got != derived $R (executor $X is bound to $R)" >&2; exit 1; }
             warm "$X" "$W/scaas_relay_executor.wasm"; warm "$R" "$W/scaas_relay_fee.wasm"
             echo "$R"; exit 0
           fi
           id="$("$ST" contract deploy --network "$NET" --wasm "$W/scaas_$C.wasm" "$@")"
           warm "$id" "$W/scaas_$C.wasm"
           echo "$id" ;;
  solana)  exec "$SC/solana/scripts/deploy.sh" "$NET" "$@" ;;
  near)    exec "$SC/near/scripts/deploy.sh" "$NET" "$@" ;;
  algorand) exec "$SC/algorand/scripts/deploy.sh" "$NET" "$@" ;;
  cosmos|ton) echo "$FAMILY: no deploy tooling in this repo yet (build artifacts: build.sh $FAMILY)" >&2; exit 2 ;;
  *) echo "unknown family '$FAMILY'" >&2; exit 2 ;;
esac
