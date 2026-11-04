#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet (chain id 7622) reset 1, owner 2026-11-04 ("Làm reset: mục 2, reset lần 1"; TODO pre-freeze work order
# item 2): image scaas/nethermind-pqz:2.2.0-pqz7 (the MLDSA87 plugin), chainspec of RUNBOOK "Code size 128 KiB"
# (patch-chainspec.py --testnet-reset: maxCodeSize 0x20000, eip7954TransitionTimestamp removed) plus a second engine.Pqz
# schedule from add-schedule.py --mldsa87 (= schedule 0 + mldsa87Gas 102,000, PROVISIONAL, not calibrated). No chain-data
# backup (owner 2026-10-31): the data dirs of both nodes and of Blockscout are renamed *.pre-reset1-20261104, not deleted;
# genesis.json, docker-compose.yml, config.json and config.rpc.json get .bak-pre-reset1-20261104 copies (the rollback).
# Rehearsed first on a throwaway copy (2026-11-04-testnet-reset1-throwaway.txt).
#   NEW=<prepared chainspec> sh runs/2026-11-04-testnet-reset1.sh reset    stop, back up, install, rename data, start nodes
#   sh runs/2026-11-04-testnet-reset1.sh check                              health, block 0, probes, node e2e, codesize
#   sh runs/2026-11-04-testnet-reset1.sh explorer                           start Blockscout on its fresh DB
#   sh runs/2026-11-04-testnet-reset1.sh rollback                           the .bak files back, old data dirs back, start
# Log: runs/2026-11-04-testnet-reset1.txt (each step appends). 22776 is never touched (patch-chainspec refuses it).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
N=$(cd "$HERE/.." && pwd)
C=$N/chain
L=${SCAAS_TESTNET_DIR:?set SCAAS_TESTNET_DIR to the SCaaS testnet stack directory}
IMG=scaas/nethermind-pqz:2.2.0-pqz7
OLD=scaas/nethermind-pqz:2.2.0-pqz6
G=0xf1f491abec46eb7c1784b7fc75a0174171b41831530e510c46b7178c02d63164  # predicted by the throwaway run (live genesis, mining off)
KEY=0x0000000000000000000000000000000000000000000000000000000000000004 # test key 0x…04, funded in genesis
E=$HERE/2026-11-04-testnet-reset1-engine-pqz.json   # = engine.Pqz of the new chainspec (two schedules)
D=20261104
LOG=$HERE/2026-11-04-testnet-reset1.txt
RPC=http://127.0.0.1:8545
A="docker run --rm --memory 256m --cpus 1 -v $L/data:/d alpine:3"
side() {  # one JSON-RPC call on a node's container-loopback admin endpoint (RUNBOOK § Node split), bounded retries
  docker run --rm --memory 64m --cpus 0.5 --network "container:$1" curlimages/curl:8.21.0 -s --retry 60 --retry-delay 2 \
    --retry-all-errors --retry-max-time 150 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" http://127.0.0.1:8550; echo
}
run() { echo "\$ $*" >> "$LOG"; "$@" >> "$LOG" 2>&1; rc=$?; echo "[rc=$rc]" >> "$LOG"; return $rc; }
logs() { echo "\$ docker logs $1 | grep PQZ / errors" >> "$LOG"
  docker logs "$1" 2>&1 | grep -E 'PQZ-START|PQZ-REFUSE|PQZ-NODE-FAULT|Invalid configuration|ERROR|Exception' | cut -c1-400 | head -20 >> "$LOG"; }

case "${1:?reset | check | explorer | rollback}" in
reset)
  NEW=${NEW:?NEW = the prepared chainspec}
  echo "# reset $(date -u +%FT%TZ), image $IMG $(docker image inspect $IMG --format '{{.Id}}')" >> "$LOG"
  cd "$L"
  # the prepared chainspec against the live one: exactly these changes, nothing else (header, alloc, engine.Clique)
  echo "\$ semantic diff genesis.json -> NEW" >> "$LOG"
  python3 -I - genesis.json "$NEW" >> "$LOG" 2>&1 <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
assert set(a) == set(b) and a["genesis"] == b["genesis"] and a["accounts"] == b["accounts"], "header / alloc / keys"
assert {k: v for k, v in a["engine"].items() if k != "Pqz"} == {k: v for k, v in b["engine"].items() if k != "Pqz"}
p = {k: (a["params"].get(k), b["params"].get(k)) for k in set(a["params"]) | set(b["params"]) if a["params"].get(k) != b["params"].get(k)}
assert p == {"maxCodeSize": ("0x10000", "0x20000"), "eip7954TransitionTimestamp": (1, None)}, p
sa, sb = a["engine"]["Pqz"]["schedules"], b["engine"]["Pqz"]["schedules"]
assert len(sa) == 1 and len(sb) == 2 and sa[0] == sb[0], "schedule 0 unchanged"
s0, s1 = dict(sb[0]), dict(sb[1])
key = lambda r: json.dumps(r, sort_keys=True)
assert sorted(map(key, s1.pop("pqz"))) == sorted(map(key, s0.pop("pqz"))), "schedule 1 rows = schedule 0 rows"
ts, g87 = s1.pop("timestamp"), s1.pop("mldsa87Gas")
s0.pop("timestamp")
assert s1 == s0 and g87 == 102000, (s1, s0, g87)
print(f"params {p}; schedule 1 at {int(ts, 16)} = schedule 0 + mldsa87Gas {g87} (PROVISIONAL); header, alloc, Clique unchanged")
PY
  run docker compose stop -t 120 explorer-frontend explorer-backend explorer-db rpc sealer
  for f in genesis.json docker-compose.yml config.json config.rpc.json; do
    [ -e "$f.bak-pre-reset1-$D" ] || cp -p "$f" "$f.bak-pre-reset1-$D"
  done
  run sha256sum genesis.json.bak-pre-reset1-$D docker-compose.yml.bak-pre-reset1-$D config.json.bak-pre-reset1-$D config.rpc.json.bak-pre-reset1-$D
  cp "$NEW" genesis.json
  sed -i "s#image: $OLD#image: $IMG#" docker-compose.yml
  [ "$(grep -c "image: $IMG" docker-compose.yml)" = 2 ] || { echo "FAIL compose: not two services on $IMG" >> "$LOG"; exit 1; }
  echo "\$ diff docker-compose.yml.bak-pre-reset1-$D docker-compose.yml" >> "$LOG"
  diff "docker-compose.yml.bak-pre-reset1-$D" docker-compose.yml >> "$LOG" 2>&1 || true
  # fresh chain and a fresh Blockscout index: the old dirs are renamed, not deleted
  run $A sh -c "for d in nethermind_data nethermind_rpc_data explorer_db_data explorer_app_data; do mv /d/\$d /d/\$d.pre-reset1-$D && mkdir /d/\$d; done; mkdir /d/explorer_app_data/logs /d/explorer_app_data/dets; ls -la /d"
  run docker compose up -d sealer
  echo "\$ sealer eth_blockNumber (sidecar)" >> "$LOG"; side mba_chain_sealer eth_blockNumber >> "$LOG" 2>&1
  run docker compose up -d rpc
  curl -s --retry 60 --retry-delay 2 --retry-all-errors --retry-max-time 150 -o /dev/null -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' $RPC
  logs mba_chain_sealer; logs mba_chain_rpc
  ;;
check)
  echo "# check $(date -u +%FT%TZ)" >> "$LOG"
  run "$C/watch.sh" mba_chain_sealer $RPC 10m
  run "$C/watch.sh" mba_chain_rpc $RPC 10m
  echo "\$ eth_blockNumber sealer / rpc sidecars, admin_peers" >> "$LOG"
  side mba_chain_sealer eth_blockNumber >> "$LOG" 2>&1; side mba_chain_rpc eth_blockNumber >> "$LOG" 2>&1
  side mba_chain_sealer admin_peers | python3 -I -c 'import json,sys; print("sealer peers", [p.get("enode","")[:30] for p in json.load(sys.stdin)["result"]])' >> "$LOG" 2>&1
  side mba_chain_rpc admin_peers | python3 -I -c 'import json,sys; print("rpc peers", [p.get("enode","")[:30] for p in json.load(sys.stdin)["result"]])' >> "$LOG" 2>&1
  run python3 -I "$C/e2e.py" head --rpc $RPC
  run python3 -I -c "import json, urllib.request as u; r = lambda n: json.load(u.urlopen(u.Request('$RPC', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': [n, False]}).encode(), {'content-type': 'application/json'})))['result']; [print('block', int(b['number'], 16), b['hash'], 'gasLimit', int(b['gasLimit'], 16), 'ts', int(b['timestamp'], 16)) for b in (r('0x0'), r('0x1'))]"
  run python3 -I "$C/e2e.py" probe --engine "$E" --rpc $RPC --genesis-hash $G
  run python3 -I "$HERE/2026-11-04-mldsa87-probe.py" $RPC
  run python3 -I "$C/e2e.py" e2e --engine "$E" --rpc $RPC --key $KEY --no-ua
  run python3 -I "$C/e2e.py" codesize --rpc $RPC --key $KEY --sizes 65537:ok,119800:ok --gas 199900000
  ;;
explorer)
  echo "# explorer $(date -u +%FT%TZ)" >> "$LOG"
  cd "$L"
  run docker compose up -d sc-verifier explorer-db explorer-backend explorer-frontend
  ;;
rollback)
  echo "# rollback $(date -u +%FT%TZ)" >> "$LOG"
  cd "$L"
  run docker compose stop -t 120 explorer-frontend explorer-backend explorer-db rpc sealer
  for f in genesis.json docker-compose.yml config.json config.rpc.json; do cp -p "$f.bak-pre-reset1-$D" "$f"; done
  run $A sh -c "for d in nethermind_data nethermind_rpc_data explorer_db_data explorer_app_data; do mv /d/\$d /d/\$d.failed-reset1-$D && mv /d/\$d.pre-reset1-$D /d/\$d; done; ls -la /d"
  run docker compose up -d sealer
  run docker compose up -d rpc
  run docker compose up -d sc-verifier explorer-db explorer-backend explorer-frontend
  ;;
esac
