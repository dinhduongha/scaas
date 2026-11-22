#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Merged-tree review M20 (owner 2026-11-20): the SDK's per-transaction cap rule (EIP-7825 under EIP-8037) against a node
# that enforces it. From the worktree root:   clients/scaas-sdk/runs/2026-11-20-m20-nethermind.sh
# A throwaway copy of the SCaaS testnet's chain (pqz-core/nethermind/chain/copy.sh, RUNBOOK "The copy"): its own compose
# project `pqzcopy`, network and port 127.0.0.1:18545, a data dir from mktemp, the image of the reset-5 engine
# (scaas/nethermind-pqz:2.2.0-pqz11) with Amsterdam from block 1 (copygen.py), chain id 31990; the live stack,
# its containers, volumes and port are never touched. The signer alone (2,500 MiB, 2 CPUs) behind an unthrottled proxy;
# the copy is stopped and its data removed on exit. Steps: the contracts' Deploy.s.sol, then the SDK's ignored test
# `e2e_bls_multi_group_limit_on_a_node` (register_bls_multi self-relayed: 64 members refused, the largest group that fits
# lands; SCAAS_M20_BLS_FIND=1 measures that count again), then the negative control (a call whose
# regular gas exceeds 2^24). Progress on stdout; the full output in 2026-11-20-m20-nethermind.log (git-ignored).
set -euo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W"
export PATH="$HOME/.foundry/bin:$PATH"
CH=$W/pqz-core/nethermind/chain
LOG=$W/clients/scaas-sdk/runs/2026-11-20-m20-nethermind.log
IMAGE=scaas/nethermind-pqz:2.2.0-pqz11
ENGINE=$W/pqz-core/nethermind/runs/2026-11-16-testnet-reset5-engine-pqz.json
RPC=http://127.0.0.1:18545
COPY=$(mktemp -d)
export COPY
DC=(docker compose -p pqzcopy -f "$CH/docker-compose.copy.yml" -f "$COPY/caps.yml")
: >"$LOG"
say() { echo "[m20] $*" | tee -a "$LOG"; }
done_() {
    say "stopping the copy"
    IMAGE=x GENESIS=x "${DC[@]}" down --timeout 60 >>"$LOG" 2>&1 || true
    docker run --rm --memory 256m -v "$COPY:/c" alpine:3 sh -c 'rm -rf /c/*' >>"$LOG" 2>&1 || true
    rm -rf "$COPY"
}
trap done_ EXIT
[ -z "$(docker ps -aq --filter name=pqzcopy-)" ] || {
    say "FAIL pqzcopy containers exist: another copy is up"
    exit 1
}
sh "$CH/copy.sh" init >>"$LOG" 2>&1
sh "$CH/copy.sh" genesis0 "$ENGINE" >>"$LOG" 2>&1
# the testnet's Amsterdam transitions from timestamp 1 (genesis0's chainspec lacks them: without them the copy caps a
# transaction at 2^24 and charges no EIP-8037 state gas), the CREATE2 deployer (script/onchain/copygen.py); then chain id
# 31990, a local test chain (31900-31999) chain-uids.json does not list, so the copy is never taken for the SCaaS testnet
python3 -I smartcontracts/evm/script/onchain/copygen.py "$COPY" >>"$LOG" 2>&1
python3 -I - "$COPY/genesis.pqz0.json" <<'PY' >>"$LOG" 2>&1
import json, sys
g = json.load(open(sys.argv[1]))
g["params"]["chainId"] = g["params"]["networkID"] = hex(31990)
json.dump(g, open(sys.argv[1], "w"), indent=1)
print("chain id 31990")
PY
# the block gas limit held at 200 M, as the SCaaS testnet's config (RUNBOOK 2026-10-21): the copy's own configs aim at 80 M,
# and the limit falling from the genesis 200 M by 1/1024 a block left a large deploy transaction above it (the second run)
python3 -I - "$COPY/config.signer.json" "$COPY/config.follower.json" <<'PY' >>"$LOG" 2>&1
import json, sys
for p in sys.argv[1:]:
    c = json.load(open(p))
    c.setdefault("Blocks", {})["TargetBlockGasLimit"] = 200_000_000
    json.dump(c, open(p, "w"), indent=1)
print("TargetBlockGasLimit 200 M")
PY
# the proxy straight to the signer, the block producer, without the copy's rate limits (10 r/s, burst 20, 8 connections:
# a deploy batch of 16 transactions and its receipt polls got 429s, sends lost and nonce reads of 0 in the third run);
# the follower is not started (its gossip is not what this run measures)
cat >"$COPY/nginx-m20.conf" <<'EOF'
server {
    listen 8545;
    client_max_body_size 2m;
    location / {
        proxy_pass http://10.76.22.10:8545;
        proxy_http_version 1.1;
        proxy_read_timeout 120s;
    }
}
EOF
cat >"$COPY/caps.yml" <<EOF
services:
  signer:
    mem_limit: 2500m
    cpus: 2
  rpc:
    volumes: !override
      - $COPY/nginx-m20.conf:/etc/nginx/conf.d/default.conf:ro
EOF
say "starting $IMAGE (copy, Amsterdam from block 1; the signer and its proxy)"
IMAGE=$IMAGE GENESIS=genesis.pqz0.json "${DC[@]}" up -d signer rpc >>"$LOG" 2>&1
ok=
for _ in $(seq 1 60); do
    if n=$(cast block-number --rpc-url "$RPC" 2>/dev/null) && [ "$n" -ge 2 ]; then
        ok=1
        break
    fi
    sleep 5
done
[ -n "$ok" ] || {
    say "FAIL the copy never answered"
    exit 1
}
CHAIN_ID=$(cast chain-id --rpc-url "$RPC")
say "copy up: chain $CHAIN_ID, block $(cast block-number --rpc-url "$RPC"), gas limit $(cast block latest --field gasLimit --rpc-url "$RPC")"
PK=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d["data"] if "data" in d else d)[0]["private_key"])' "$COPY/signer.json")
REPO="bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better"
HOLDER=$(cast wallet address --mnemonic "$REPO")
cast send --private-key "$PK" --rpc-url "$RPC" "$HOLDER" --value 100ether >>"$LOG" 2>&1
say "the seed's EVM key 0 funded ($HOLDER)"
NAME=local-31990-testnet
# the chain's deploy as every chain gets it (smartcontracts/scripts/deploy.sh evm: the PQ verifiers probed on the copy's
# precompiles first, then Deploy.s.sol simulated and DeploySend.s.sol sending each transaction with its measured gas),
# the PQZ releases included (DEPLOY_PQZ); its book and logs moved out of the tree after. TX_GAS_CAP is the book's owner-set
# value deploy.sh's probe takes where it finds no cap (smartcontracts/evm/script/tx_gas_cap.py): the copy accepts an empty
# eth_call up to its block limit, so the copy's book names EIP-7825's 2^24, its Amsterdam rule (plan T39, 2026-11-22)
(cd smartcontracts && PRIVATE_KEY=$PK TX_GAS_CAP=16777216 FOUNDRY_PROFILE=scaas-testnet DEPLOY_NAME=$NAME CHAIN_CODE_LIMIT=131072 DEPLOY_PQZ=1 VERIFY=none VERIFY_REASON="a throwaway local copy" \
    DEPLOY_LOG=$COPY/deploy.log "$W/scripts/capped" bash scripts/deploy.sh evm "$RPC") >>"$LOG" 2>&1
BOOK=$W/smartcontracts/evm/deployments/$NAME.json
cp "$BOOK" "$COPY/book.json"
rm -f "$W"/smartcontracts/evm/deployments/$NAME*.json
say "deployed: registry $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["ua_registry"])' "$COPY/book.json")"
F=vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots
e2e() { # one ignored e2e test of the SDK against the copy
    (cd clients/scaas-sdk && SCAAS_M20_RPC=$RPC SCAAS_M20_BOOK=$COPY/book.json SCAAS_M20_CHAIN_ID=$CHAIN_ID \
        SCAAS_M20_TOKEN=${TOKEN:-} "$W/scripts/capped" cargo test --locked --offline -j2 --features $F --test e2e -- \
        --ignored --exact "$1" --nocapture) >>"$LOG" 2>&1
}
rc=0
PARTS=${M20_PARTS:-bls,pqz,control}
if [[ ,$PARTS, == *,bls,* ]]; then
    e2e e2e_bls_multi_group_limit_on_a_node && r=0 || r=$?
    say "register_bls_multi: 64 refused, the largest group lands: rc=$r"
    rc=$((rc | r))
fi
if [[ ,$PARTS, == *,pqz,* ]]; then
    # a NORMAL_PQZ token of the deploy's factory (PRECOMPILE mode), its public units minted to the payer
    FACTORY=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["token_factory"])' "$COPY/book.json")
    CD=$(cd smartcontracts/evm && MINTER=$(cast wallet address --private-key "$PK") FOUNDRY_PROFILE=scaas-testnet \
    FOUNDRY_OUT=out/m20 FOUNDRY_CACHE_PATH=cache/m20 "$W/scripts/capped" forge script script/SdkM20PqzToken.s.sol 2>>"$LOG" |
        grep -A1 'M20 calldata' | tail -1 | tr -d ' ')
    rm -rf smartcontracts/evm/out/m20 smartcontracts/evm/cache/m20
    # the token's address by an eth_call on the node (its precompile runs the token's self-test), then the same call sent
    T=$(cast call --from "$(cast wallet address --private-key "$PK")" "$FACTORY" "$CD" --rpc-url "$RPC")
    cast send --private-key "$PK" --rpc-url "$RPC" --gas-limit 30000000 "$FACTORY" "$CD" >>"$LOG" 2>&1
    UID_=$(cast call "$FACTORY" "chainUid()(bytes32)" --rpc-url "$RPC")
    echo "M20 token 0x${T: -40}" >>"$LOG"
    cast send --private-key "$PK" --rpc-url "$RPC" "0x${T: -40}" "mint(address,uint256,bytes32)" "$HOLDER" 1000000000000 "$UID_" >>"$LOG" 2>&1
    TOKEN=$(grep -m1 'M20 token' "$LOG" | awk '{print $NF}')
    say "PQZ token $TOKEN"
    e2e e2e_pqz_debit_on_a_node && r=0 || r=$?
    say "PQZ debit (mtxConfidentialTransferSingle): rc=$r"
    rc=$((rc | r))
fi
grep '^M20 ' "$LOG" | sed 's/^/[m20] /' || true
[[ ,$PARTS, == *,control,* ]] || exit "$rc"
# no `M20 tx` line when the BLS part failed: the control still runs
TX=$(grep '^M20 tx ' "$LOG" | awk '{print $3}' || true)
[ -n "$TX" ] && say "receipt: $(cast receipt "$TX" --rpc-url "$RPC" --json | python3 -I -c 'import json,sys; r=json.load(sys.stdin); print({k: r.get(k) for k in ("status","gasUsed","blockNumber","blockGasUsed","gasUsedRegular","gasUsedState")})')"
# the negative control: initcode that loops for ever (JUMPDEST PUSH1 0 JUMP). Its regular gas has no bound but the cap:
# the estimate is refused, and a transaction with a gas limit of 30 M, above 2^24, stops at the cap (status 0)
say "control estimate: $(cast estimate --rpc-url "$RPC" --from "$HOLDER" --create 0x5b600056 2>&1 | tail -1 | cut -c1-160)"
KEY0=$(cast wallet private-key --mnemonic "$REPO")
CTX=$(cast send --private-key "$KEY0" --rpc-url "$RPC" --gas-limit 30000000 --create 0x5b600056 --json 2>>"$LOG" |
    python3 -I -c 'import json,sys; print(json.load(sys.stdin)["transactionHash"])' || true)
if [ -n "$CTX" ]; then
    say "control 30 M gas limit: $(cast receipt "$CTX" --rpc-url "$RPC" --json | python3 -I -c 'import json,sys; r=json.load(sys.stdin); print({k: r.get(k) for k in ("status","gasUsed","blockNumber")})')"
else
    say "control 30 M gas limit: refused at the send ($(grep -i 'error' "$LOG" | tail -1 | cut -c1-160))"
fi
exit "$rc"
