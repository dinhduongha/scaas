#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet (chain id 7622) reset 4 (TODO 3zd; owner standing go 2026-11-14): reset 1's procedure
# (pqz-core/nethermind/runs/2026-11-04-testnet-reset1.sh) with a new image and chainspec: image
# scaas/nethermind-pqz:2.2.0-pqz9 (the ExpectedLibrarySha256 pin 29c351ec..., the three-key library); chainspec = the live
# genesis.json through patch-chainspec.py --testnet-reset --rescue-vault-alloc (NET-EVM-14: the RescueVault at
# SCAAS_DEV_RESCUE, test-key admin and rescuer) with engine-pqz-provisional-n2304.json (the three-key ids), then
# add-schedule.py --mldsa (schedule 1: ML-DSA-44 / -65 / -87 = 59,000 / 68,000 / 135,000). No chain-data backup (owner
# 2026-10-31): data dirs renamed *.pre-reset4-<D>, never deleted; genesis.json, docker-compose.yml, config.json,
# config.rpc.json get .bak-pre-reset4-<D> copies. Also the T-20 exit-120 drill (owner 2026-11-15 "Lam vao testnet luon"):
# the drill's compose override lives outside the stack directory (DRILL_DIR) and is removed by `restore`.
#   NEW=<chainspec> SCAAS_TESTNET_DIR=<stack> RPC_7622=<rpc> sh reset4.sh reset   stop, back up, install, rename, start
#   ... sh reset4.sh check | explorer
#   DRILL_DIR=<private dir> ... sh reset4.sh drill-hooks | drill-byte | restore
# Log: reset4.log beside this file (git-ignored).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$HERE/../../../.." && pwd)
N=$R/pqz-core/nethermind
C=$N/chain
L=${SCAAS_TESTNET_DIR:?set SCAAS_TESTNET_DIR to the SCaaS testnet stack directory}
IMG=scaas/nethermind-pqz:2.2.0-pqz9
OLD=scaas/nethermind-pqz:2.2.0-pqz7
E=$N/runs/2026-11-15-testnet-reset4-engine-pqz.json
D=${RESET_D:-20261115}
TAG=${RESET_TAG:-pre-reset4}  # reset 4b (owner 2026-11-15, the deploy fixed): RESET_TAG=pre-reset4b, same image and chainspec
LOG=$HERE/reset4.log
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
A="docker run --rm --memory 256m --cpus 1 -v $L/data:/d alpine:3"
say() { echo "[reset4] $*"; echo "# $*" >> "$LOG"; }
side() {
  docker run --rm --memory 64m --cpus 0.5 --network "container:$1" curlimages/curl:8.21.0 -s --retry 60 --retry-delay 2 \
    --retry-all-errors --retry-max-time 150 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" http://127.0.0.1:8550; echo
}
run() { echo "\$ $*" >> "$LOG"; "$@" >> "$LOG" 2>&1; rc=$?; echo "[rc=$rc]" >> "$LOG"; echo "[reset4] $(echo "$*" | cut -c1-90) rc=$rc"; return $rc; }
logs() { echo "\$ docker logs $1 | grep PQZ / errors" >> "$LOG"
  docker logs "$1" 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'PQZ-START|PQZ-REFUSE|PQZ-NODE-FAULT|Invalid configuration|ERROR|Exception' | cut -c1-400 | head -20 >> "$LOG"; }
state() { echo "$1: $(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} restarts={{.RestartCount}} started={{.State.StartedAt}}' "$1")"; }
OVR=${DRILL_DIR:-}/drill-compose.yml

case "${1:?reset | check | explorer | drill-hooks | drill-byte | restore}" in
reset)
  NEW=${NEW:?NEW = the prepared chainspec}
  say "reset $(date -u +%FT%TZ), image $IMG $(docker image inspect $IMG --format '{{.Id}}')"
  cd "$L"
  for f in genesis.json docker-compose.yml config.json config.rpc.json; do [ -e "$f.bak-$TAG-$D" ] || cp -p "$f" "$f.bak-$TAG-$D"; done
  run sha256sum genesis.json "$NEW"
  cp "$NEW" genesis.json
  sed -i "s#image: $OLD#image: $IMG#" docker-compose.yml
  [ "$(grep -c "image: $IMG" docker-compose.yml)" = 2 ] || { say "FAIL compose: not two services on $IMG"; exit 1; }
  echo "\$ head before stop" >> "$LOG"; python3 -I "$C/e2e.py" head --rpc $RPC >> "$LOG" 2>&1 || true
  run docker compose stop -t 120 explorer-frontend explorer-backend explorer-db rpc sealer
  run $A sh -c "for d in nethermind_data nethermind_rpc_data explorer_db_data explorer_app_data; do mv /d/\$d /d/\$d.$TAG-$D && mkdir /d/\$d; done; mkdir /d/explorer_app_data/logs /d/explorer_app_data/dets; ls /d"
  run docker compose up -d sealer
  echo "\$ sealer eth_blockNumber (sidecar)" >> "$LOG"; side mba_chain_sealer eth_blockNumber >> "$LOG" 2>&1
  run docker compose up -d rpc
  curl -s --retry 60 --retry-delay 2 --retry-all-errors --retry-max-time 150 -o /dev/null -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' $RPC
  logs mba_chain_sealer; logs mba_chain_rpc
  ;;
check)
  say "check $(date -u +%FT%TZ)"
  run "$C/watch.sh" mba_chain_sealer $RPC 10m
  run "$C/watch.sh" mba_chain_rpc $RPC 10m
  logs mba_chain_sealer; logs mba_chain_rpc
  echo "\$ eth_blockNumber sealer / rpc sidecars" >> "$LOG"
  side mba_chain_sealer eth_blockNumber >> "$LOG" 2>&1; side mba_chain_rpc eth_blockNumber >> "$LOG" 2>&1
  run python3 -I -c "import json, urllib.request as u; r = lambda n: json.load(u.urlopen(u.Request('$RPC', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': [n, False]}).encode(), {'content-type': 'application/json'})))['result']; [print('block', int(b['number'], 16), b['hash'], 'gasLimit', int(b['gasLimit'], 16), 'ts', int(b['timestamp'], 16)) for b in (r('0x0'), r('0x1'))]"
  G=$(python3 -I -c "import json, urllib.request as u; print(json.load(u.urlopen(u.Request('$RPC', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': ['0x0', False]}).encode(), {'content-type': 'application/json'})))['result']['hash'])")
  run python3 -I "$C/e2e.py" probe --engine "$E" --rpc $RPC --genesis-hash "$G" --corpus "${CORPUS:-$N/bin/corpus.jsonl}"
  run python3 -I "$N/runs/2026-11-15-mldsa-probe-reset4.py" $RPC
  ;;
explorer)
  say "explorer $(date -u +%FT%TZ)"
  cd "$L"
  run docker compose up -d sc-verifier explorer-db explorer-backend explorer-frontend
  ;;
drill-hooks|drill-byte)  # T-20: the rpc node on a test library mounted over the image's; watch it ~90 s
  [ -n "${DRILL_DIR:-}" ] || { say "FAIL DRILL_DIR"; exit 1; }
  case $1 in
  drill-hooks) LIB=$N/bin/test-hooks/libpqz_ffi.so ;;
  drill-byte)
    docker run --rm --entrypoint cat $IMG /nethermind/plugins/libpqz_ffi.so > "$DRILL_DIR/libpqz_ffi.so.byte"
    printf '\000' >> "$DRILL_DIR/libpqz_ffi.so.byte"
    LIB=$DRILL_DIR/libpqz_ffi.so.byte ;;
  esac
  printf 'services:\n  rpc:\n    volumes:\n      - %s:/nethermind/plugins/libpqz_ffi.so:ro\n' "$LIB" > "$OVR"
  say "$1: library sha256 $(sha256sum "$LIB" | cut -c1-16)…, image's 29c351ec…; head before $(side mba_chain_sealer eth_blockNumber | cut -c1-80)"
  cd "$L"
  run docker compose -f docker-compose.yml -f "$OVR" up -d rpc
  for i in 1 2 3; do sleep 30; say "$(state mba_chain_rpc); $(state mba_chain_sealer); sealer head $(side mba_chain_sealer eth_blockNumber | cut -c1-80)"; done
  say "rpc log tags:"; docker logs mba_chain_rpc 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'PQZ-REFUSE|PQZ-NODE-FAULT|PQZ-START' | cut -c1-260 | sort | uniq -c | head -6 | tee -a "$LOG"
  ;;
restore)  # the image's own library back: the plain compose file, no override
  cd "$L"
  run docker compose up -d --force-recreate rpc
  [ -z "${DRILL_DIR:-}" ] || rm -f "$OVR" "$DRILL_DIR/libpqz_ffi.so.byte"
  sleep 30
  say "$(state mba_chain_rpc); $(state mba_chain_sealer)"
  logs mba_chain_rpc
  grep -c fault-hooks docker-compose.yml config.json config.rpc.json | tee -a "$LOG"
  ;;
esac
