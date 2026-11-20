#!/usr/bin/env bash
# Deploy one family's contracts with its native tool. Keys/credentials come from the tool's own config or env.
# usage: deploy.sh <family> <network> [args…]   (args go to the native tool)
#   evm     <rpc-url>        forge script script/Deploy.s.sol --broadcast; env PRIVATE_KEY, TX_GAS_CAP? (the chain's per-transaction
#                            gas cap, the registry's txGasCap, owner X1: probed first by script/tx_gas_cap.py through TX_CAP_NODES?
#                            (default the RPC); TX_GAS_CAP is the book's owner-set value, used only where no cap is found, else
#                            it must equal the probe's), UA_GEN_BOOK? (a later UARegistry generation over that book's
#                            registry, script/DeployUAGen.s.sol, SMART_KEY_ACCOUNT_IMPL), REGISTRAR?, DEMO_SUPPLY?,
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
#                            and with MLDSA_PRECOMPILE=on, the default, MldsaVerifier 0x0130 / 0x0131 / 0x0134; forge's EVM
#                            has none of these precompiles), by CREATE2 with DEPLOY_SALT after each probe passes, and hands
#                            them to Deploy.s.sol (PQZ_KEY_VERIFIER, MLDSA44_VERIFIER, MLDSA65_VERIFIER, MLDSA87_VERIFIER):
#                            the gen-1 registry lists the kinds on them, and its gate refuses a registry that misses a
#                            precompile the chain answers; a chain without them (anvil): skipped by name, the ML-DSA kinds
#                            on the registry's expanded-key cache. MLDSA_PRECOMPILE=off (owner 2026-11-15): every ML-DSA kind
#                            on the cache, as a chain without a precompile (the deploy JSON's mldsa<x>_path says which). DEPLOY_PQZ=1 publishes the PQZ releases 4, 5, 12, 13 on this factory (on for the SCaaS
#                            testnet; script/pqz/e2e.py keeps its own factory for its harness runs).
#                            Batches (NET-EVM-11 Change, owner 2026-11-15): DeploySend sends the plan in batches of
#                            DEPLOY_BATCH (default 16) transactions, one forge run each without --slow
#                            (`run(string,uint256,uint256)`: each transaction measured on the fork of the chain as the
#                            batches before left it), receipts awaited up to DEPLOY_TX_TIMEOUT (600 s), the batch bounded by
#                            DEPLOY_BATCH_LIMIT (1800 s: forge is stopped past it, a named fail); after each batch
#                            every receipt is read (script/deploy_batch.py check) and the next batch starts only if every
#                            transaction forge sent has a receipt with status 1, else a named stop at the first failure;
#                            a release already there is skipped (DeploySend's release-done check, a `skip` line). Fees:
#                            before each batch (and before the pq-verifiers step) script/onchain/fee.sh's fee (tip
#                            ONCHAIN_TIP, default 1 gwei; max fee ONCHAIN_MAXFEE, default 2 x base fee + tip) and the fee
#                            gate MAX_FEE_GWEI (default 0.1 on a mainnet, the chain key's -mainnet; none on a testnet unless
#                            set): a max fee above it stops by name before the batch (FEE_OVER_MAX); a re-run skips the
#                            releases already there. DEPLOY_SET? (owner 2026-11-16, "ok, option 2, one chain, two deploy
#                            sets"): this deploy's set label, mldsa-off (MLDSA_PRECOMPILE=off) or mldsa-on (on), its own
#                            DEPLOY_SALT and RELEASES_JSON; an unknown label or one that is not the deploy's mode refused
#                            by name before anything is sent (DEPLOY_SET_UNKNOWN, DEPLOY_SET_MISMATCH); the book then holds
#                            every set of the chain under sets.<label>, its top level the default set mldsa-off
#                            (deploybook.py set-merge); unset: one deploy, one book, as before.
#                            Progress (owner 2026-11-15, runs never silent): short [deploy] lines on stdout: simulate
#                            start / ok <N> txs, est gas; after each batch one line per transaction from its receipts (send
#                            <i>/<N> <phase> <contract> gas <used> <address> tx <hash>; the phase from the plan: libraries,
#                            verifiers, registry, router, factory, configureChain, releases, pqchat, zether, …) and batch
#                            <k>/<n> ok; a 30 s heartbeat with the sender's nonce count; ok <N> txs <s>s book <path>; FAIL
#                            <phase> tx <i>/<N> <contract> <why> <address> tx <hash> (the transaction without a good
#                            receipt; the hash when forge recorded one). Every batch's transactions and receipts in
#                            broadcast/DeploySend.s.sol/<chain>/run-batches.json. Forge's full output in DEPLOY_LOG (default
#                            runs/<date>-deploy-<key>.log, git-ignored). Never a key.
#                            DEPLOY_ZETHER=1 (any chain but Hedera) adds the Zether stack. DEPLOY_PQCHAT=1 adds PqChat
#                            (plan 3c T92: its body module PqChatTopics by CREATE2, class env (3, 0) with the module in libs,
#                            release 1, the switch on; one instance when NOTICE_PERIOD=0; JSON pqchat_topics,
#                            pqchat_implementation, pqchat_instance), replayed by DeploySend.s.sol like every other transaction.
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
FAMILY="${1:?usage: $0 <family> <network> [args…]}"
NET="${2:?network}"
shift 2
case "$FAMILY" in
    evm)
        cd "$SC/evm"
        # owner X1, P18 (spec 2026-11-19-registry-verify-only-kinds §9): the chain's per-transaction gas cap probed through the node
        # list (TX_CAP_NODES, comma-separated, default the RPC) under strict majority, before anything else; TX_GAS_CAP, when
        # set, is the book's owner-set value: taken where no cap is found, else it must equal the probe's (GEN_TX_CAP_MISMATCH)
        TXR="$(mktemp)"
        TX_GAS_CAP="$(python3 -I script/tx_gas_cap.py "${TX_CAP_NODES:-$NET}" ${TX_GAS_CAP:+--owner-set "$TX_GAS_CAP"} --rows-out "$TXR")" || exit 1
        export TX_GAS_CAP
        # UA_GEN_BOOK (the predecessor's book): a later UARegistry generation (script/DeployUAGen.s.sol), not the gen-1 deploy
        DSCRIPT=Deploy.s.sol
        [ -z "${UA_GEN_BOOK:-}" ] || DSCRIPT=DeployUAGen.s.sol
        Z=(--disable-code-size-limit) # forge 1.8.5: EIP-3860 on the script contract itself (Deploy.s.sol initcode > 48 KiB); the chain enforces 64 KiB
        # The scripts' own gas budget (forge's gas_limit, foundry.toml 2^33), not a chain figure: the simulations run every
        # transaction twice (DeploySend: measured, then sent; Deploy.s.sol's public gate: each release measured, then
        # deployed) and a snapshot's revert returns no gas; at reset 4b (153 transactions) DeploySend spent 2^33 by tx
        # 108 and its call ran short of gas. block.gaslimit stays the chain's (the fork's block).
        export FOUNDRY_GAS_LIMIT="${FOUNDRY_GAS_LIMIT:-68719476736}"
        C="$(cast chain-id --rpc-url "$NET")"
        S="$(cast wallet address --private-key "$PRIVATE_KEY")"
        # NET-EVM-13: the book by the chain's key (DEPLOY_NAME for a chain not in chain-uids.json), a named fail first
        G0="$(cast block 0 --field hash --rpc-url "$NET")"
        K="$(python3 -I script/deploybook.py key "$C" "$G0")"
        # deploy sets (owner 2026-11-16, "ok, option 2, one chain, two deploy sets"): DEPLOY_SET names this deploy's set
        # (mldsa-off with MLDSA_PRECOMPILE=off, mldsa-on with on), refused by name before anything is sent; the book then
        # keeps every set of this chain (deploybook.py set-merge)
        DS="${DEPLOY_SET:-}"
        [ -z "$DS" ] || python3 -I script/deploybook.py set-check "$DS" "${MLDSA_PRECOMPILE:-}" >/dev/null ||
            {
                echo "[deploy] FAIL DEPLOY_SET $DS refused, nothing sent"
                exit 1
            }
        # forge writes the JSON in the simulation, before the broadcast: keep the previous one until it succeeds
        J="deployments/$K.json"
        [ -f "$J" ] && cp "$J" "$J.prev"
        # NET-EVM-11: Deploy.s.sol simulated on the RPC's fork, nothing sent (the JSON, the release list, the plan in
        # forge's dry-run file), then DeploySend.s.sol sends that plan, each transaction with an explicit gas limit
        P="broadcast/$DSCRIPT/$C/dry-run/run-latest.json" B="broadcast/DeploySend.s.sol/$C/run-latest.json"
        Q="broadcast/$DSCRIPT/$C/dry-run/send-plan.json" # DeploySend.plan's arrays, written from $P
        rm -f "$P" "$Q" "$B"                                 # never a stale plan, never a previous run's receipts
        DL="${DEPLOY_LOG:-runs/$(date -u +%F)-deploy-$K${DS:+-$DS}.log}"
        mkdir -p "$(dirname "$DL")"
        : >"$DL"
        say() { echo "[deploy] $*"; }
        fail() {
            say "FAIL $1 rc $2 (forge's output: $DL)"
            [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"
            exit 1
        }
        # follow <pid> [batch label]: wait for forge, a heartbeat every 30 s; for a batch, the sender's nonce count and a
        # wall bound (DEPLOY_BATCH_LIMIT, default 1800 s: forge waits on a receipt that never comes past its --timeout),
        # past it forge is stopped and the batch fails (rc 124)
        follow() {
            local t0=$SECONDS h=$SECONDS
            while kill -0 "$1" 2>/dev/null; do
                sleep 2
                [ $((SECONDS - h)) -lt 30 ] || {
                    h=$SECONDS
                    say "… ${2:+$2, nonce +$(($(cast nonce --rpc-url "$NET" "$S" 2>/dev/null || echo "$N0") - N0)), }$((SECONDS - t0))s"
                }
                if [ -n "${2:-}" ] && [ $((SECONDS - t0)) -ge "${DEPLOY_BATCH_LIMIT:-1800}" ]; then
                    say "$2: forge still running after $((SECONDS - t0))s (DEPLOY_BATCH_LIMIT), stopped"
                    kill "$1" 2>/dev/null
                    wait "$1" 2>/dev/null
                    return 124
                fi
            done
            wait "$1"
        }
        # the fee of every transaction forge signs (fee.sh: tip ONCHAIN_TIP, default 1 gwei; max fee 2 x base fee + tip),
        # read before each batch; the fee gate (owner 2026-11-15): MAX_FEE_GWEI, default 0.1 on a mainnet (the key's
        # -mainnet), none on a testnet; above it a named stop before the batch (a re-run skips the releases already there)
        . script/onchain/fee.sh
        case "$K" in *-mainnet) MF="${MAX_FEE_GWEI-0.1}" ;; *) MF="${MAX_FEE_GWEI:-}" ;; esac
        feegate() {
            ONCHAIN_REMOTE=1 remote_fee "$NET"
            [ -z "$MF" ] || python3 -I script/deploy_batch.py fee "$MF" "$ETH_GAS_PRICE" | sed "s/fee gate/fee gate $1/" ||
                {
                    [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"
                    exit 1
                }
        }
        T0=$SECONDS
        # owner 2026-11-15: the verifiers whose constructors probe the chain's own precompiles (PqzKeyVerifier 0x0142, the
        # MldsaVerifiers 0x0130 / 0x0131 / 0x0134 with MLDSA_PRECOMPILE=on), on the real chain before the simulation (forge's EVM has no such precompile),
        # by CREATE2 with DEPLOY_SALT (script/pq_verifiers.py, e2e.py's builders); their addresses reach Deploy.s.sol by
        # env. A precompile the chain lacks: that verifier is skipped by name (DeployBase's gate then requires nothing).
        feegate pq-verifiers
        say "pq-verifiers start"
        forge build src/pqz/PqzKeyVerifier.sol src/ua/MlDsa.sol >>"$DL" 2>&1 || fail pq-verifiers $?
        PV="$(python3 -I script/pq_verifiers.py "$NET" 2>>"$DL")" || {
            printf '%s\n' "$PV" | grep '^\[deploy\]' || true
            tail -n 3 "$DL" | sed 's/^/[deploy] pq-verifiers: /'
            fail pq-verifiers 1
        }
        printf '%s\n' "$PV" | grep '^\[deploy\]' || true
        for kv in $(printf '%s\n' "$PV" | grep -E '^(PQZ_KEY_VERIFIER|MLDSA44_VERIFIER|MLDSA65_VERIFIER|MLDSA87_VERIFIER)=0x[0-9a-fA-F]{40}$'); do export "${kv?}"; done
        say "simulate start chain $C $K"
        forge script "script/$DSCRIPT" --rpc-url "$NET" "${Z[@]}" --sender "$S" "$@" >>"$DL" 2>&1 &
        follow $! || fail simulate $?
        [ -f "$P" ] || fail simulate "1 (no plan $P)"
        say "simulate ok $(python3 -I -c 'import json,sys; t=json.load(open(sys.argv[1]))["transactions"]; print(len(t), "txs, est gas", format(sum(int(x["transaction"].get("gas") or "0x0", 16) for x in t), ","))' "$P")"
        # one array per field (DeploySend.plan: four cheatcode calls, not five per transaction); a CREATE's `to` is the
        # zero address and a missing value 0, both checked there; nothing else is changed or dropped
        python3 -I -c 'import json, sys
t = [x["transaction"] for x in json.load(open(sys.argv[1]))["transactions"]]
json.dump({"from": [x["from"] for x in t], "to": [x.get("to") or "0x" + "00" * 20 for x in t],
           "value": [x.get("value") or "0x0" for x in t], "input": [x.get("input") or "0x" for x in t]}, open(sys.argv[2], "w"))' "$P" "$Q" ||
            fail plan $?
        # NET-EVM-11 Change (owner 2026-11-15): the plan in batches of DEPLOY_BATCH (16) without --slow, one forge run each
        # (DeploySend.run(string,uint256,uint256): measured on the fork of the chain as the batches before left it, then
        # sent at once); after each batch one line per transaction from its receipts, every status 1 checked before the
        # next batch, a named stop at the first failure
        N="$(python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["to"]))' "$Q")" BS="${DEPLOY_BATCH:-16}"
        NB=$(((N + BS - 1) / BS)) AL="broadcast/DeploySend.s.sol/$C/run-batches${DS:+-$DS}.json"
        rm -f "$AL"
        for ((k = 1; k <= NB; k++)); do
            lo=$(((k - 1) * BS)) hi=$((k * BS < N ? k * BS : N))
            feegate "batch $k/$NB"
            rm -f "$B"
            N0="$(cast nonce --rpc-url "$NET" "$S")"
            tb=$SECONDS
            forge script script/DeploySend.s.sol --sig 'run(string,uint256,uint256)' "$Q" "$lo" "$hi" \
                --rpc-url "$NET" --broadcast --timeout "${DEPLOY_TX_TIMEOUT:-600}" "${Z[@]}" --sender "$S" "$@" >>"$DL" 2>&1 &
            rc=0
            follow $! "batch $k/$NB" || rc=$?
            if [ "$rc" != 0 ]; then
                python3 -I script/deploy_batch.py check "$P" "$Q" "$B" "$lo" "$hi" "$AL" fail "$rc" 2>>"$DL" || true
                [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"
                say "forge's output: $DL"
                exit 1
            fi
            python3 -I script/deploy_batch.py check "$P" "$Q" "$B" "$lo" "$hi" "$AL" 2>>"$DL" ||
                {
                    [ -f "$J.prev" ] && mv "$J.prev" "$J" || rm -f "$J"
                    say "forge's output: $DL"
                    exit 1
                }
            say "batch $k/$NB ok: txs $((lo + 1))-$hi/$N, nonce +$(($(cast nonce --rpc-url "$NET" "$S") - N0)), $((SECONDS - tb))s"
        done
        if [ -n "$DS" ]; then # this set beside the chain's other sets (a previous book of another chain is not kept)
            PB=-
            [ -f "$J.prev" ] && [ "$(python3 -I -c 'import json, sys; print(json.load(open(sys.argv[1])).get("chainUid", ""))' "$J.prev")" = "$(echo "$G0" | tr A-F a-f)" ] && PB="$J.prev"
            python3 -I script/deploybook.py set-merge "$J" "$PB" "$DS" "${RELEASES_JSON:-}" ||
                {
                    say "FAIL set-merge: $J stays this deploy's book alone, the previous one in $J.prev"
                    exit 1
                }
            say "set $DS in $J (sets: $(python3 -I -c 'import json, sys; b = json.load(open(sys.argv[1])); print(", ".join(b["sets"]), "default", b["default_set"])' "$J"))"
        fi
        # the tx-cap probe's rows into the book this run wrote (the chain's, or the later generation's companion)
        JW="$J"
        [ -z "${UA_GEN_BOOK:-}" ] || JW="$(ls -t "deployments/$K-ua-gen"*.json | head -n 1)"
        python3 -I script/deploybook.py add "$JW" "$TXR" && rm -f "$TXR"
        rm -f "$J.prev"
        say "ok $(python3 -I -c 'import json, sys; print(len(json.load(open(sys.argv[1]))["receipts"]))' "$AL" 2>/dev/null || echo 0) txs $((SECONDS - T0))s book $J"
        # NET-EVM-12: a remote deploy is source-verified on the chain's explorer, VERIFY_TARGET naming its config
        # (scaas-testnet, or VERIFY_EXPLORER / VERIFY_URL / VERIFY_API_KEY_ENV); chain 31337 or VERIFY_TARGET=local
        # is local; VERIFY=none needs VERIFY_REASON; an unconfigured target fails VERIFY_NOT_CONFIGURED (exit 1)
        if [ "$C" = 31337 ] || [ "${VERIFY_TARGET:-}" = local ]; then
            echo "[local/verify] local, not verified (no explorer)"
        else VERIFY_RPC="$NET" sh script/onchain/verify.sh "${VERIFY_TARGET:-chain-$C}"; fi
        ;;
    hedera) : "${TX_GAS_CAP:?TX_GAS_CAP: the per-transaction gas cap of the chain, from the deploy book (owner X1)}"
        cd "$SC/evm" && exec forge script script/hedera/DeployHedera.s.sol --rpc-url "$NET" --broadcast --slow --disable-code-size-limit \
        --sender "$(cast wallet address --private-key "$PRIVATE_KEY")" "$@" ;;
    aptos) exec aptos move deploy-object --package-dir "$SC/move/aptos" --address-name scaas --profile "$NET" "$@" ;;
    sui)
        out="$(sui client --client.env "$NET" publish --json "$@" "$SC/move/sui")" || {
            echo "$out"
            exit 1
        }
        echo "$out"
        cap="$(python3 -c 'import json,sys; print(next(c["objectId"] for c in json.loads(sys.stdin.read())["objectChanges"]
                  if c.get("type") == "created" and c.get("objectType") == "0x2::package::UpgradeCap"))' <<<"$out")" ||
            {
                echo "no UpgradeCap in the publish output: make the package immutable by hand" >&2
                exit 1
            }
        # --gas-budget: older Sui CLIs require it (SUI_GAS_BUDGET, MIST)
        exec sui client --client.env "$NET" call --package 0x2 --module package --function make_immutable --args "$cap" \
            --gas-budget "${SUI_GAS_BUDGET:-50000000}"
        ;;
    soroban)
        C="${1:?contract (token|mandate|dex|smart_key_account|relay_fee|ua_registry)}"
        shift
        ST="${STELLAR_BIN:-stellar}"
        W="$SC/soroban/target/wasm32v1-none/release"
        # `contract id wasm` / `contract extend` take only the source / RPC / config options: pass those of "$@" before
        # `--` (a deploy-only option such as --alias or --inclusion-fee would make them fail)
        I=()
        A=("$@")
        for ((i = 0; i < ${#A[@]}; i++)); do
            case "${A[i]}" in
                --) break ;;
                -s | --source | --source-account | --rpc-url | --rpc-header | --network-passphrase | --config-dir | --hd-path)
                    I+=("${A[i]}" "${A[i + 1]-}")
                    i=$((i + 1))
                    ;;
                --source=* | --source-account=* | --rpc-url=* | --rpc-header=* | --network-passphrase=* | --config-dir=* | --hd-path=*)
                    I+=("${A[i]}")
                    ;;
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
            [ "$got" = "$R" ] || {
                echo "router id $got != derived $R (executor $X is bound to $R)" >&2
                exit 1
            }
            warm "$X" "$W/scaas_relay_executor.wasm"
            warm "$R" "$W/scaas_relay_fee.wasm"
            echo "$R"
            exit 0
        fi
        id="$("$ST" contract deploy --network "$NET" --wasm "$W/scaas_$C.wasm" "$@")"
        warm "$id" "$W/scaas_$C.wasm"
        echo "$id"
        ;;
    solana) exec "$SC/solana/scripts/deploy.sh" "$NET" "$@" ;;
    near) exec "$SC/near/scripts/deploy.sh" "$NET" "$@" ;;
    algorand) exec "$SC/algorand/scripts/deploy.sh" "$NET" "$@" ;;
    cosmos | ton)
        echo "$FAMILY: no deploy tooling in this repo yet (build artifacts: build.sh $FAMILY)" >&2
        exit 2
        ;;
    *)
        echo "unknown family '$FAMILY'" >&2
        exit 2
        ;;
esac
