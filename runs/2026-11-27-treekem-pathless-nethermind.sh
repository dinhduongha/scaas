#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# The path-less delta P8 and P8b (docs/superpowers/specs/2026-11-25-treekem-pathless-add.md §14) on a node that enforces
# EIP-7825 under EIP-8037: the gas rows of §9 as the node counts them, and pqchat-core's chain tests on it. From the worktree
# root:   runs/2026-11-27-treekem-pathless-nethermind.sh
# A throwaway copy of the SCaaS testnet's chain (pqz-core/nethermind/chain/copy.sh, RUNBOOK "The copy"), set up as
# clients/scaas-sdk/runs/2026-11-20-m20-nethermind.sh sets it up: its own compose project `pqzcopy`, port 127.0.0.1:18545,
# a data dir from mktemp, the reset-5 engine's image, Amsterdam from block 1 (copygen.py), the block gas limit held at
# 200 M; chain id 31337 (pqchat-core's chain harness names it; a local test id). The live stack, its containers, volumes and
# port are never touched. The signer alone (Docker mem_limit 2,500 MiB, 2 CPUs) behind an unthrottled proxy; the copy is
# stopped and its data removed on exit. Steps: the chain's deploy (smartcontracts/scripts/deploy.sh evm with PqChat), then
# pqchat-core's ignored chain tests on it (`PQCHAT_CHAIN_RPC`, the book, the signer key as the funder, `PQCHAT_GAS_ROWS`).
# A gas count, no timing. Progress on stdout; the full output in 2026-11-27-treekem-pathless-nethermind.log (git-ignored);
# the rows in 2026-11-27-treekem-pathless-nethermind-rows.txt.
set -euo pipefail
W=$(git rev-parse --show-toplevel)
cd "$W"
export PATH="$HOME/.foundry/bin:$PATH"
CH=$W/pqz-core/nethermind/chain
LOG=$W/runs/2026-11-27-treekem-pathless-nethermind.log
ROWS=$W/runs/2026-11-27-treekem-pathless-nethermind-rows.txt
IMAGE=scaas/nethermind-pqz:2.2.0-pqz11
ENGINE=$W/pqz-core/nethermind/runs/2026-11-16-testnet-reset5-engine-pqz.json
RPC=http://127.0.0.1:18545
COPY=$(mktemp -d)
export COPY
DC=(docker compose -p pqzcopy -f "$CH/docker-compose.copy.yml" -f "$COPY/caps.yml")
: >"$LOG"
say() { echo "[p8] $*" | tee -a "$LOG"; }
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
python3 -I smartcontracts/evm/script/onchain/copygen.py "$COPY" >>"$LOG" 2>&1
python3 -I - "$COPY/genesis.pqz0.json" <<'PY' >>"$LOG" 2>&1
import json, sys
g = json.load(open(sys.argv[1]))
g["params"]["chainId"] = g["params"]["networkID"] = hex(31337)
json.dump(g, open(sys.argv[1], "w"), indent=1)
print("chain id 31337")
PY
python3 -I - "$COPY/config.signer.json" "$COPY/config.follower.json" <<'PY' >>"$LOG" 2>&1
import json, sys
for p in sys.argv[1:]:
    c = json.load(open(p))
    c.setdefault("Blocks", {})["TargetBlockGasLimit"] = 200_000_000
    json.dump(c, open(p, "w"), indent=1)
print("TargetBlockGasLimit 200 M")
PY
cat >"$COPY/nginx-p8.conf" <<'EOF'
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
    mem_limit: 128m
    volumes: !override
      - $COPY/nginx-p8.conf:/etc/nginx/conf.d/default.conf:ro
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
say "copy up: chain $(cast chain-id --rpc-url "$RPC"), block $(cast block-number --rpc-url "$RPC"), gas limit $(cast block latest --field gasLimit --rpc-url "$RPC")"
PK=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d["data"] if "data" in d else d)[0]["private_key"])' "$COPY/signer.json")
NAME=local-31337-p8-testnet
(cd smartcontracts && PRIVATE_KEY=$PK TX_GAS_CAP=16777216 FOUNDRY_PROFILE=scaas-testnet DEPLOY_NAME=$NAME CHAIN_CODE_LIMIT=131072 DEPLOY_PQCHAT=1 VERIFY=none VERIFY_REASON="a throwaway local copy" \
    DEPLOY_LOG=$COPY/deploy.log "$W/scripts/capped" bash scripts/deploy.sh evm "$RPC") >>"$LOG" 2>&1
BOOK=$W/smartcontracts/evm/deployments/$NAME.json
cp "$BOOK" "$COPY/book.json"
rm -f "$W"/smartcontracts/evm/deployments/$NAME*.json
say "deployed: PqChat $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["pqchat_instance"])' "$COPY/book.json")"
rc=0
for t in ${P8_TESTS:-chain_tree_pathless_rows chain_tree_bound chain_tree_session}; do
    (cd clients/pqchat-core && PQCHAT_CHAIN_RPC=$RPC PQCHAT_CHAIN_BOOK=$COPY/book.json PQCHAT_CHAIN_FUNDER=$PK PQCHAT_GAS_ROWS=1 \
        CARGO_INCREMENTAL=0 CARGO_TARGET_DIR=../scaas-sdk/target "$W/scripts/capped" cargo test --locked --offline -j2 \
        --test chain_tree -- --ignored --exact "$t" --nocapture) >>"$LOG" 2>&1 && r=0 || r=$?
    say "$t on the copy: rc=$r"
    rc=$((rc | r))
done
# the rows: each landed transaction's receipt (the node's count), its entry by selector (forge's method identifiers)
python3 -I - "$LOG" smartcontracts/evm/out/IPqChat.sol/IPqChat.json >"$ROWS" <<'PY'
import json, re, sys
ids = {"0x" + v: k.split("(")[0] for k, v in json.load(open(sys.argv[2]))["methodIdentifiers"].items()}
print("# the path-less delta P8 on the local copy of the SCaaS testnet's chain (runs/2026-11-27-treekem-pathless-nethermind.sh)")
print("# entry | gasUsed | regular | state | gas limit; [rows] lines name the row the transactions after them belong to")
for line in open(sys.argv[1]):
    if line.startswith("[rows]") or line.startswith("[tree]") or line.startswith("[chain]"):
        print(line.rstrip())
    m = re.match(r"\[gas\] (0x[0-9a-f]{8}) gasUsed (\S+) regular (\S+) state (\S+) gasLimit (\d+)", line)
    if m:
        print(" | ".join([ids.get(m[1], m[1])] + [str(int(x, 16)) if x.startswith("0x") else x for x in m.groups()[1:]]))
PY
say "rows: $ROWS ($(grep -c ' | ' "$ROWS") transactions)"
exit "$rc"
