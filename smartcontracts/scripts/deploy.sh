#!/usr/bin/env bash
# Deploy one family's contracts with its native tool. Keys/credentials come from the tool's own config or env.
# usage: deploy.sh <family> <network> [args…]   (args go to the native tool)
#   evm     <rpc-url>        forge script script/Deploy.s.sol --broadcast; env PRIVATE_KEY, REGISTRAR?, DEMO_SUPPLY?,
#                            DEMO_HOLDER?, CHAIN_UID? (genesis hash from evm/chain-uids.json; defaults to blockhash(0),
#                            which is 0 past block 256, so a long-running chain needs it), DEPLOY_SALT? (CREATE2 salt);
#                            FOUNDRY_PROFILE=scaas-testnet|gnosis|celo|bsc|polygon|base (all osaka). Needs the deterministic
#                            CREATE2 deployer on the chain (NET-EVM-05). Writes evm/deployments/<key>.json (NET-EVM-13:
#                            the key from evm/chain-uids.json by (chain id, genesis hash); a chain not in it needs
#                            DEPLOY_NAME=<name>-testnet | <name>-mainnet, else DEPLOY_NAME_REQUIRED before anything is
#                            sent; the book's header first; the previous file is put back if the broadcast fails). Every chain gets the UA registry
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
#                            admin COMPLIANCE_ADMIN (a UA id, bytes32, required; 0 refused AdminZero), its router the
#                            chain's: JSON compliance_registry, compliance_registry_codehash (every regulated release's
#                            COMPLIANCE_REGISTRY_CODEHASH). The admin then writes each DEX venue (createDex) and its puller()
#                            ELIGIBLE_CONTRACT (setCompliance), validUntil
#                            2^64-1, before an ALLOWLIST token trades there: its own call, this script holds no admin key.
#                            Two forge runs (NET-EVM-11): Deploy.s.sol simulated on the RPC's fork, nothing sent, then
#                            script/DeploySend.s.sol sends its plan (forge's dry-run file, the linked libraries first)
#                            in order, each transaction with an explicit gas limit, (regular + state) x 1.05 measured on
#                            the fork, capped at the RPC's block gas limit; one that needs more than that limit refuses
#                            the plan by name (TxGasOverBlockLimit) before anything is sent. No forge estimate, no
#                            multiplier. First (owner 2026-11-15) script/pq_verifiers.py deploys on the real chain the
#                            verifiers whose constructors probe its own precompiles (PqzKeyVerifier for pqz-mlwe 0x0142,
#                            MldsaVerifier(0x0134) for mldsa87; forge's EVM has neither precompile), by CREATE2 with
#                            DEPLOY_SALT after each probe passes, and hands them to Deploy.s.sol (PQZ_KEY_VERIFIER,
#                            MLDSA87_VERIFIER): the gen-1 registry lists both kinds, and its gate refuses a registry that
#                            misses a kind whose precompile the chain answers; a chain without them (anvil): skipped by
#                            name. DEPLOY_PQZ=1 publishes the PQZ releases 4, 5, 12, 13 on this factory (on for the SCaaS
#                            testnet; script/pqz/e2e.py keeps its own factory for its harness runs).
#                            Progress (owner 2026-11-15, runs never silent): short [deploy] lines on stdout: simulate
#                            start / ok <N> txs, est gas; one line per transaction as its receipt lands (send <i>/<N>
#                            <phase> <contract> gas <used> <address> tx <hash>; the phase from the plan: libraries,
#                            verifiers, registry, router, factory, configureChain, releases, pqchat, zether, …); a 30 s
#                            heartbeat; ok <N> txs <s>s book <path>; FAIL <phase> tx <i>/<N> <contract> rc <rc> <address>
#                            tx <hash> (the transaction without a good receipt; the hash when forge recorded one). Forge's
#                            full output in DEPLOY_LOG (default runs/<date>-deploy-<key>.log, git-ignored). Never a key.
#                            DEPLOY_ZETHER=1 (any chain but Hedera) adds the Zether stack. DEPLOY_PQCHAT=1 adds PqChat
#                            (plan 3c T92: its body module PqChatTopics by CREATE2, class env (3, 0) with the module in libs,
#                            release 1, the switch on; one instance when NOTICE_PERIOD=0; JSON pqchat_topics,
#                            pqchat_implementation, pqchat_instance), replayed by DeploySend.s.sol like every other transaction. --slow always (one tx per
#                            block: anvil automine can strand a large tx).
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
#   hedera  <relay-url>      same, script/hedera/DeployHedera.s.sol --slow (writes deployments/<key>.json: a Hedera chain's only deploy)
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
           C="$(cast chain-id --rpc-url "$NET")"; S="$(cast wallet address --private-key "$PRIVATE_KEY")"
           # NET-EVM-13: the book by the chain's key (DEPLOY_NAME for a chain not in chain-uids.json), a named fail first
           K="$(python3 -I script/deploybook.py key "$C" "$(cast block 0 --field hash --rpc-url "$NET")")"
           # forge writes the JSON in the simulation, before the broadcast: keep the previous one until it succeeds
           J="deployments/$K.json"; [ -f "$J" ] && cp "$J" "$J.prev"
           # NET-EVM-11: Deploy.s.sol simulated on the RPC's fork, nothing sent (the JSON, the release list, the plan in
           # forge's dry-run file), then DeploySend.s.sol sends that plan, each transaction with an explicit gas limit
           P="broadcast/Deploy.s.sol/$C/dry-run/run-latest.json" B="broadcast/DeploySend.s.sol/$C/run-latest.json"
           rm -f "$P" "$B" # never a stale plan, never a previous run's receipts
           DL="${DEPLOY_LOG:-runs/$(date -u +%F)-deploy-$K.log}"; mkdir -p "$(dirname "$DL")"; : > "$DL"
           W="$(mktemp)"; trap 'rm -f "$W"' EXIT
           say() { echo "[deploy] $*"; }
           fail() { say "FAIL $1 rc $2 (forge's output: $DL)"; [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"; exit 1; }
           # prog <plan> <receipts> <state> [fail <rc>]: one line per receipt not yet seen; with fail, the line of the
           # transaction that failed (the first status 0, else the next one)
           prog() { python3 -I - "$@" 2>> "$DL" <<'PY2'
import json, os, sys, time
plan, rec, state = sys.argv[1:4]
t = json.load(open(plan))["transactions"]
def phase(x):
    n, f = x.get("contractName") or "", (x.get("function") or "").split("(")[0]
    if f == "configureChain": return "configureChain"
    if f == "setChainEntries": return "directory entries"
    if f in ("createToken", "transfer"): return "demo tokens"
    if f in ("publishClassEnv", "deployImplementation", "setClassKindEnabled", "createInstance") or n.startswith("PqChat"): return "pqchat"
    if f or "Token" in n or n.startswith("SCaaSDex"):
        z = "Zether" in n or any("Zether" in (a.get("contractName") or "") for a in x.get("additionalContracts") or [])
        if not z and f and phase.last in ("releases", "zether releases"):
            return phase.last  # publishTokenEnv / setTokenKindEnabled: the release they belong to
        return "zether releases" if z else "releases"
    if n.endswith("Lib"): return "libraries"
    if n.endswith("Verifier"): return "verifiers"  # the UA kind verifiers, ZetherSchnorrBls12381Verifier included
    if n.startswith("Zether"): return "zether"
    return {"SmartKeyAccountFactory": "SKA factory", "RelayFeeRouter": "relay fee router", "UARegistry": "registry",
            "GovernanceRouter": "router", "ComplianceRegistry": "compliance registry", "OpenFactory": "factory"}.get(n, n or "other")
phase.last = None
ph = []
for x in t:
    ph.append(phase(x)); phase.last = ph[-1]
st = json.load(open(state)) if os.path.getsize(state) else {"n": 0, "t": time.time(), "gas": 0}
try:
    r = json.load(open(rec)).get("receipts", []) if os.path.exists(rec) else []
except ValueError:  # forge is writing it
    r = []
by = {x.get("hash"): x for x in t}
for i in range(st["n"], len(r)):
    x, tx = r[i], by.get(r[i]["transactionHash"], t[i] if i < len(t) else {})
    a = x.get("contractAddress") or tx.get("contractAddress") or tx.get("transaction", {}).get("to")
    name = tx.get("contractName") or (tx.get("function") or "call").split("(")[0]
    bad = "" if x.get("status") == "0x1" else f" STATUS {x.get('status')}"
    print(f"[deploy] send {i + 1}/{len(t)} {ph[i]} {name} gas {int(x['gasUsed'], 16)}{bad} {a} tx {x['transactionHash']}")
    st["n"] = i + 1
if len(sys.argv) > 5:
    i = next((j for j, x in enumerate(r) if x.get("status") != "0x1"), len(r))
    tx = t[i] if i < len(t) else {}
    a = (r[i].get("contractAddress") if i < len(r) else None) or tx.get("contractAddress") or tx.get("transaction", {}).get("to") or ""
    h = r[i]["transactionHash"] if i < len(r) else tx.get("hash")
    name = tx.get("contractName") or (tx.get("function") or "?").split("(")[0]
    print(f"[deploy] FAIL {ph[i] if i < len(t) else 'send'} tx {i + 1}/{len(t)} {name} rc {sys.argv[5]} {a}" + (f" tx {h}" if h else ""))
else:
    print(f"#{st['n']}/{len(t)}")
json.dump(st, open(state, "w"))
PY2
           }
           # follow <pid> [plan]: wait for forge, a heartbeat every 30 s; with the plan, a line per receipt as it lands
           follow() {
             local t0=$SECONDS h=$SECONDS c=
             while kill -0 "$1" 2> /dev/null; do
               sleep 2
               [ -z "${2:-}" ] || { c="$(DL="$DL" prog "$P" "$B" "$W")"; printf '%s\n' "$c" | grep -v '^#' | grep . || true; }
               [ $((SECONDS - h)) -lt 30 ] || { h=$SECONDS; say "… ${c:+$(printf '%s\n' "$c" | sed -n 's/^#//p'), }$((SECONDS - t0))s"; }
             done
             wait "$1"
           }
           T0=$SECONDS
           # owner 2026-11-15: the verifiers whose constructors probe the chain's own precompiles (PqzKeyVerifier 0x0142, the
           # mldsa87 MldsaVerifier 0x0134), on the real chain before the simulation (forge's EVM has no such precompile),
           # by CREATE2 with DEPLOY_SALT (script/pq_verifiers.py, e2e.py's builders); their addresses reach Deploy.s.sol by
           # env. A precompile the chain lacks: that verifier is skipped by name (DeployBase's gate then requires nothing).
           say "pq-verifiers start"
           forge build src/pqz/PqzKeyVerifier.sol src/ua/MlDsa.sol >> "$DL" 2>&1 || fail pq-verifiers $?
           PV="$(python3 -I script/pq_verifiers.py "$NET" 2>> "$DL")" || { printf '%s\n' "$PV" | grep '^\[deploy\]'; fail pq-verifiers 1; }
           printf '%s\n' "$PV" | grep '^\[deploy\]' || true
           for kv in $(printf '%s\n' "$PV" | grep -E '^(PQZ_KEY_VERIFIER|MLDSA87_VERIFIER)=0x[0-9a-fA-F]{40}$'); do export "${kv?}"; done
           say "simulate start chain $C $K"
           forge script script/Deploy.s.sol --rpc-url "$NET" "${Z[@]}" --sender "$S" "$@" >> "$DL" 2>&1 &
           follow $! || fail simulate $?
           [ -f "$P" ] || fail simulate "1 (no plan $P)"
           say "simulate ok $(python3 -I -c 'import json,sys; t=json.load(open(sys.argv[1]))["transactions"]; print(len(t), "txs, est gas", format(sum(int(x["transaction"].get("gas") or "0x0", 16) for x in t), ","))' "$P")"
           forge script script/DeploySend.s.sol --sig 'run(string)' "$P" \
             --rpc-url "$NET" --broadcast --slow "${Z[@]}" --sender "$S" "$@" >> "$DL" 2>&1 &
           rc=0; follow $! plan || rc=$?
           if [ "$rc" != 0 ]; then
             DL="$DL" prog "$P" "$B" "$W" fail $rc | grep -v '^#'
             [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"; say "forge's output: $DL"; exit 1
           fi
           DL="$DL" prog "$P" "$B" "$W" | grep -v '^#' || true
           rm -f "$J.prev"
           say "ok $(python3 -I -c 'import json,sys; print(len(json.load(open(sys.argv[1]))["receipts"]))' "$B") txs $((SECONDS - T0))s book $J"
           # NET-EVM-12: a remote deploy is source-verified on the chain's explorer, VERIFY_TARGET naming its config
           # (scaas-testnet, or VERIFY_EXPLORER / VERIFY_URL / VERIFY_API_KEY_ENV); chain 31337 or VERIFY_TARGET=local
           # is local; VERIFY=none needs VERIFY_REASON; an unconfigured target fails VERIFY_NOT_CONFIGURED (exit 1)
           if [ "$C" = 31337 ] || [ "${VERIFY_TARGET:-}" = local ]; then echo "[local/verify] local, not verified (no explorer)"
           else VERIFY_RPC="$NET" sh script/onchain/verify.sh "${VERIFY_TARGET:-chain-$C}"; fi ;;
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
