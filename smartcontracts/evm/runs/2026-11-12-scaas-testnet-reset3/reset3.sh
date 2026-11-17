#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# SCaaS testnet (chain id 7622) reset 3 (owner 2026-11-10 "tự động làm, không cần hỏi nữa": reset 3 by the same procedure as reset 2): reset 1's procedure
# (pqz-core/nethermind/runs/2026-11-04-testnet-reset1.sh) without its chainspec and image changes: genesis.json,
# docker-compose.yml, config.json, config.rpc.json, keystores and .env stay as reset 1 left them (sha256 before and
# after), the image stays scaas/nethermind-pqz:2.2.0-pqz7. No chain-data backup (owner 2026-10-31): the data dirs of
# both nodes and of Blockscout are renamed *.pre-reset3-20261112, not deleted (as reset 1).
#   SCAAS_TESTNET_DIR=<stack> sh reset3.sh reset     stop, rename data, start sealer then rpc
#   SCAAS_TESTNET_DIR=<stack> sh reset3.sh check     health, block 0 / 1, PQZ probe, MLDSA87 probe (read-only)
#   SCAAS_TESTNET_DIR=<stack> sh reset3.sh explorer  Blockscout on its fresh DB
# Log: reset3.log beside this file (git-ignored).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
R=$(cd "$HERE/../../../.." && pwd)
N=$R/pqz-core/nethermind
C=$N/chain
L=${SCAAS_TESTNET_DIR:?set SCAAS_TESTNET_DIR to the SCaaS testnet stack directory}
IMG=scaas/nethermind-pqz:2.2.0-pqz7
G=0xf1f491abec46eb7c1784b7fc75a0174171b41831530e510c46b7178c02d63164  # reset 1's genesis; same genesis.json
E=$N/runs/2026-11-04-testnet-reset1-engine-pqz.json                     # = engine.Pqz of genesis.json (checked)
D=20261112
LOG=$HERE/reset3.log
RPC=${RPC_7622:?set RPC_7622 to the SCaaS testnet RPC (no default)}
A="docker run --rm --memory 256m --cpus 1 -v $L/data:/d alpine:3"
side() {
  docker run --rm --memory 64m --cpus 0.5 --network "container:$1" curlimages/curl:8.21.0 -s --retry 60 --retry-delay 2 \
    --retry-all-errors --retry-max-time 150 -H 'content-type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$2\",\"params\":${3:-[]}}" http://127.0.0.1:8550; echo
}
run() { echo "\$ $*" >> "$LOG"; "$@" >> "$LOG" 2>&1; rc=$?; echo "[rc=$rc]" >> "$LOG"; echo "[reset3] $(echo "$*" | cut -c1-90) rc=$rc"; return $rc; }
logs() { echo "\$ docker logs $1 | grep PQZ / errors" >> "$LOG"
  docker logs "$1" 2>&1 | grep -E 'PQZ-START|PQZ-REFUSE|PQZ-NODE-FAULT|Invalid configuration|ERROR|Exception' | cut -c1-400 | head -20 >> "$LOG"; }
files() { (cd "$L" && sha256sum genesis.json docker-compose.yml config.json config.rpc.json .env jsonrpc.filter) >> "$LOG"; }

case "${1:?reset | check | explorer}" in
reset)
  echo "# reset $(date -u +%FT%TZ), image $IMG $(docker image inspect $IMG --format '{{.Id}}')" >> "$LOG"
  cd "$L"
  [ "$(grep -c "image: $IMG" docker-compose.yml)" = 2 ] || { echo "FAIL compose: not two services on $IMG" >> "$LOG"; exit 1; }
  python3 -I - genesis.json "$E" >> "$LOG" 2>&1 <<'PY'
import json, sys
g, e = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
p = g["params"]
assert g["engine"]["Pqz"] == e, "engine.Pqz differs from reset 1's"
assert p["maxCodeSize"] == "0x20000" and not any("7702" in k or "7954" in k for k in p), "7702 / 7954 / code size"
ams = sorted(k for k in p if k.endswith("TransitionTimestamp") and int(str(p[k]), 0) == 1)
assert g["genesis"]["gasLimit"] == "0xbebc200", g["genesis"]["gasLimit"]
assert any(a.lower() == "0x4e59b44847b379578588920ca78fbf26c0b4956c" and v.get("code") for a, v in g["accounts"].items())
print("genesis.json: engine.Pqz = reset 1's; maxCodeSize 0x20000, no 7702 / 7954 key, gasLimit 200 M, CREATE2 deployer 0x4e59 with code; ts-1 transitions", ams)
PY
  echo "\$ sha256 of the kept files (before)" >> "$LOG"; files
  echo "\$ head before stop" >> "$LOG"; python3 -I "$C/e2e.py" head --rpc $RPC >> "$LOG" 2>&1 || true
  run docker compose stop -t 120 explorer-frontend explorer-backend explorer-db rpc sealer
  run $A sh -c "for d in nethermind_data nethermind_rpc_data explorer_db_data explorer_app_data; do mv /d/\$d /d/\$d.pre-reset3-$D && mkdir /d/\$d; done; mkdir /d/explorer_app_data/logs /d/explorer_app_data/dets; ls -la /d"
  run docker compose up -d sealer
  echo "\$ sealer eth_blockNumber (sidecar)" >> "$LOG"; side mba_chain_sealer eth_blockNumber >> "$LOG" 2>&1
  run docker compose up -d rpc
  curl -s --retry 60 --retry-delay 2 --retry-all-errors --retry-max-time 150 -o /dev/null -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' $RPC
  logs mba_chain_sealer; logs mba_chain_rpc
  echo "\$ sha256 of the kept files (after)" >> "$LOG"; files
  ;;
check)  # CORPUS=<a checkout>/pqz-core/nethermind/bin/corpus.jsonl when this one has no build
  echo "# check $(date -u +%FT%TZ)" >> "$LOG"
  run "$C/watch.sh" mba_chain_sealer $RPC 10m
  run "$C/watch.sh" mba_chain_rpc $RPC 10m
  echo "\$ eth_blockNumber sealer / rpc sidecars, admin_peers" >> "$LOG"
  side mba_chain_sealer eth_blockNumber >> "$LOG" 2>&1; side mba_chain_rpc eth_blockNumber >> "$LOG" 2>&1
  side mba_chain_sealer admin_peers | python3 -I -c 'import json,sys; print("sealer peers", [p.get("enode","")[:30] for p in json.load(sys.stdin)["result"]])' >> "$LOG" 2>&1
  side mba_chain_rpc admin_peers | python3 -I -c 'import json,sys; print("rpc peers", [p.get("enode","")[:30] for p in json.load(sys.stdin)["result"]])' >> "$LOG" 2>&1
  run python3 -I "$C/e2e.py" head --rpc $RPC
  run python3 -I -c "import json, urllib.request as u; r = lambda n: json.load(u.urlopen(u.Request('$RPC', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': [n, False]}).encode(), {'content-type': 'application/json'})))['result']; [print('block', int(b['number'], 16), b['hash'], 'gasLimit', int(b['gasLimit'], 16), 'ts', int(b['timestamp'], 16)) for b in (r('0x0'), r('0x1'))]"
  run python3 -I "$C/e2e.py" probe --engine "$E" --rpc $RPC --genesis-hash $G --corpus "${CORPUS:-$N/bin/corpus.jsonl}"  # CORPUS: a checkout that holds the built corpus
  run python3 -I "$N/runs/2026-11-04-mldsa87-probe.py" $RPC
  ;;
explorer)
  echo "# explorer $(date -u +%FT%TZ)" >> "$LOG"
  cd "$L"
  run docker compose up -d sc-verifier explorer-db explorer-backend explorer-frontend
  ;;
esac
