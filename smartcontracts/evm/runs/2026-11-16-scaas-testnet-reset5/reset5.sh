#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet (chain id 7622) reset 5 (owner 2026-11-16 "Ok, reset 5 before PR #18"): reset 4's procedure (reset4.sh, the
# T-20 drill left out) with a new image and chainspec: image scaas/nethermind-pqz:2.2.0-pqz11 (build-image.sh on the reset5
# tree, the reviewed library pins of SelfTest.cs); chainspec = the live genesis.json through patch-chainspec.py
# --testnet-reset --rescue-vault-alloc (NET-EVM-14) with the calibrated chain/engine-pqz.json (26 rows, 2026-11-15, the
# three-key ids of pqz-core v6), then add-schedule.py --mldsa (schedule 1: ML-DSA-44 / -65 / -87 = 59,000 / 100,000 /
# 135,000). No chain-data backup (owner 2026-10-24): data dirs renamed *.pre-reset5-<D>, never deleted; genesis.json,
# docker-compose.yml, config.json, config.rpc.json get .bak-pre-reset5-<D> copies.
#   NEW=<chainspec> SCAAS_TESTNET_DIR=<stack> RPC_7622=<rpc> sh reset5.sh reset   stop, back up, install, rename, start
#   ... sh reset5.sh check | explorer
# Log: reset5.log beside this file (git-ignored).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$HERE/../../../.." && pwd)
N=$R/pqz-core/nethermind
C=$N/chain
L=${SCAAS_TESTNET_DIR:?set SCAAS_TESTNET_DIR to the SCaaS testnet stack directory}
IMG=scaas/nethermind-pqz:2.2.0-pqz11
OLD=scaas/nethermind-pqz:2.2.0-pqz9
E=$N/runs/2026-11-16-testnet-reset5-engine-pqz.json
D=${RESET_D:-20261116}
TAG=${RESET_TAG:-pre-reset5}
LOG=$HERE/reset5.log
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
A="docker run --rm --memory 256m --cpus 1 -v $L/data:/d alpine:3"
say() {
    echo "[reset5] $*"
    echo "# $*" >>"$LOG"
}
side() {
    docker run --rm --memory 64m --cpus 0.5 --network "container:$1" curlimages/curl:8.21.0 -s --retry 60 --retry-delay 2 \
        --retry-all-errors --retry-max-time 150 -H 'content-type: application/json' \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" http://127.0.0.1:8550
    echo
}
run() {
    echo "\$ $*" >>"$LOG"
    "$@" >>"$LOG" 2>&1
    rc=$?
    echo "[rc=$rc]" >>"$LOG"
    echo "[reset5] $(echo "$*" | cut -c1-90) rc=$rc"
    return $rc
}
logs() {
    echo "\$ docker logs $1 | grep PQZ / errors" >>"$LOG"
    docker logs "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'PQZ-START|PQZ-REFUSE|PQZ-NODE-FAULT|Invalid configuration|ERROR|Exception' | cut -c1-400 | head -20 >>"$LOG"
}
state() { echo "$1: $(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} started={{.State.StartedAt}}' "$1")"; }

case "${1:?reset | check | explorer}" in
    reset)
        NEW=${NEW:?NEW = the prepared chainspec}
        say "reset $(date -u +%FT%TZ), image $IMG $(docker image inspect $IMG --format '{{.Id}}')"
        cd "$L"
        for f in genesis.json docker-compose.yml config.json config.rpc.json; do [ -e "$f.bak-$TAG-$D" ] || cp -p "$f" "$f.bak-$TAG-$D"; done
        run sha256sum genesis.json "$NEW"
        cp "$NEW" genesis.json
        sed -i "s#image: $OLD#image: $IMG#" docker-compose.yml
        [ "$(grep -c "image: $IMG" docker-compose.yml)" = 2 ] || {
            say "FAIL compose: not two services on $IMG"
            exit 1
        }
        echo "\$ head before stop" >>"$LOG"
        python3 -I "$C/e2e.py" head --rpc $RPC >>"$LOG" 2>&1 || true
        run docker compose stop -t 120 explorer-frontend explorer-backend explorer-db rpc sealer
        run $A sh -c "for d in nethermind_data nethermind_rpc_data explorer_db_data explorer_app_data; do mv /d/\$d /d/\$d.$TAG-$D && mkdir /d/\$d; done; mkdir /d/explorer_app_data/logs /d/explorer_app_data/dets; ls /d"
        run docker compose up -d sealer
        echo "\$ sealer eth_blockNumber (sidecar)" >>"$LOG"
        side mba_chain_sealer eth_blockNumber >>"$LOG" 2>&1
        run docker compose up -d rpc
        curl -s --retry 60 --retry-delay 2 --retry-all-errors --retry-max-time 150 -o /dev/null -H 'content-type: application/json' \
            --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' $RPC
        logs mba_chain_sealer
        logs mba_chain_rpc
        ;;
    check)
        say "check $(date -u +%FT%TZ)"
        run "$C/watch.sh" mba_chain_sealer $RPC 10m
        run "$C/watch.sh" mba_chain_rpc $RPC 10m
        logs mba_chain_sealer
        logs mba_chain_rpc
        echo "\$ eth_blockNumber sealer / rpc sidecars" >>"$LOG"
        side mba_chain_sealer eth_blockNumber >>"$LOG" 2>&1
        side mba_chain_rpc eth_blockNumber >>"$LOG" 2>&1
        run python3 -I -c "import json, urllib.request as u; r = lambda n: json.load(u.urlopen(u.Request('$RPC', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': [n, False]}).encode(), {'content-type': 'application/json'})))['result']; [print('block', int(b['number'], 16), b['hash'], 'gasLimit', int(b['gasLimit'], 16), 'ts', int(b['timestamp'], 16)) for b in (r('0x0'), r('0x1'))]"
        G=$(python3 -I -c "import json, urllib.request as u; print(json.load(u.urlopen(u.Request('$RPC', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': ['0x0', False]}).encode(), {'content-type': 'application/json'})))['result']['hash'])")
        run python3 -I "$C/e2e.py" probe --engine "$E" --rpc $RPC --genesis-hash "$G" --corpus "${CORPUS:-$N/bin/corpus.jsonl}"
        run python3 -I "$N/runs/2026-11-16-mldsa-probe-reset5.py" $RPC
        ;;
    explorer)
        say "explorer $(date -u +%FT%TZ)"
        cd "$L"
        run docker compose up -d sc-verifier explorer-db explorer-backend explorer-frontend
        ;;
esac
