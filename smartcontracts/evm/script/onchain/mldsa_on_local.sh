#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# mldsa_on.py on a local anvil (README-mldsa-on.md "Tests without the testnet"): a fresh anvil (as matrix.sh local), a deploy
# with MLDSA_PRECOMPILE=off (anvil has no ML-DSA precompile: the cache path runs instead), then `mldsa_on.py --set mldsa-off`.
# Under scripts/capped, foreground, from smartcontracts/evm:
#   ../../scripts/capped sh script/onchain/mldsa_on_local.sh [groups]
# MLDSA_ON_STATE=<file>: the first run deploys, keeps the chain there (anvil --dump-state) and stops; the next ones load it
# (no second deploy, each from the deployed state). anvil's dev keys only. Short lines on stdout; the deploy's and anvil's output in the git-ignored log.
set -eu
PORT=${PORT:-18630}
RPC=http://127.0.0.1:$PORT
OUTD=${MATRIX_OUT:-runs/$(date +%Y-%m-%d)-mldsa-on-local}
mkdir -p "$OUTD"
L=$OUTD/mldsa-on-local.log
: >"$L"
ST=${MLDSA_ON_STATE:-}
fresh=1
set -- "${1:-mldsa,tokens}"
if [ -n "$ST" ] && [ -s "$ST" ]; then
    fresh=0
    anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 131072 --port "$PORT" \
        --load-state "$ST" >>"$L" 2>&1 &
else
    anvil --chain-id 31337 --hardfork amsterdam --gas-limit 200000000 --code-size-limit 131072 --port "$PORT" \
        ${ST:+--dump-state "$ST"} >>"$L" 2>&1 &
fi
A=$!
trap 'kill -INT $A 2> /dev/null || true; wait $A 2> /dev/null || true' EXIT INT TERM
for i in $(seq 60); do
    cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
    [ "$i" -lt 60 ] || {
        echo "[local] FAIL anvil did not start"
        exit 1
    }
    sleep 1
done
echo "[local] anvil up (port $PORT, $([ $fresh = 1 ] && echo fresh || echo "state $ST"))"
# anvil's dev keys 0-3 (matrix.sh local)
export PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
export ONCHAIN_K1=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
export ONCHAIN_K2=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
export ONCHAIN_K3=0x7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6
export DEPLOY_NAME=local-31337-testnet
if [ $fresh = 1 ]; then
    echo "[local] deploy (MLDSA_PRECOMPILE=off, DEPLOY_PQCHAT=1) …"
    t0=$(date +%s)
    env FOUNDRY_OUT=out/onchain-deploy FOUNDRY_CACHE_PATH=cache/onchain-deploy RELEASE_GAS_GATE=public CHAIN_CODE_LIMIT=131072 \
        RELEASES_WRITE=true RELEASES_JSON=deployments/local-31337-testnet-releases.json DEPLOY_WRAPPED=1 DEPLOY_REGULATED=1 \
        DEPLOY_ZETHER=1 DEPLOY_PQCHAT=1 NOTICE_PERIOD=0 \
        DEMO_SUPPLY=1000000000000 MLDSA_PRECOMPILE=off DEPLOY_SALT="$(cast keccak scaas.deploy.mldsa-on.local)" \
        COMPLIANCE_ADMIN=0x0000000000000000000000004e59b44847b379578588920ca78fbf26c0b4956c \
        ../scripts/deploy.sh evm "$RPC" >>"$L" 2>&1 || {
        echo "[local] FAIL deploy: $(grep -E 'Error|FAIL|refus' "$L" | tail -1 | cut -c1-160)"
        exit 1
    }
    echo "[local] deploy ok ($(($(date +%s) - t0))s)"
    if [ -n "$ST" ]; then
        cp deployments/local-31337-testnet.json "$ST.book.json"
        echo "[local] state kept in $ST: run again for the groups"
        exit 0
    fi
fi
B=deployments/local-31337-testnet.json
[ -z "$ST" ] || [ $fresh = 1 ] || B=$ST.book.json
MATRIX_OUT=$OUTD EVM_OUT=${EVM_OUT:-out/t66b-e2e} python3 -I script/onchain/mldsa_on.py --set mldsa-off --net local --rpc "$RPC" \
    --groups "$1" --book "$B"
