#!/bin/sh
# SCaaS testnet (chain id 7622) reset with genesis gasLimit 200,000,000 (0xbebc200), owner 2026-10-22 ("Reset ngay để
# có 200 M sớm, không cần chạy tải"). Everything else as on 2026-10-21: image scaas/nethermind-pqz:2.2.0-pqz3, the same
# engine.Pqz and params (Amsterdam from timestamp 1), config.json (TargetBlockGasLimit 200 M already) and compose
# unchanged, same ports and keys. No chain-data backup (owner 2026-10-21); the old data dir is renamed, not deleted, and
# genesis.json gets a .bak copy. Prepared and rehearsed on throwaway chains (2026-10-22-genesis-200m-throwaway.txt).
# Run by the controller on 2026-10-22 (log 2026-10-22-testnet-200m.txt): genesis 0xa17faef4…2ac2 as predicted. Review
# amsterdam-node L3 (after that run): the patched chainspec is written to genesis.json.new, checked, then moved, so a
# failed check leaves genesis.json untouched; reuse it at plan fs3 Task 13 with that task's engine file and checks.
#   sh runs/2026-10-22-testnet-reset-200m.sh reset     stop, back up genesis.json, patch, rename the data dir, start
#   sh runs/2026-10-22-testnet-reset-200m.sh check     head, probe (with the eth_estimateGas row), e2e smoke, 64 KiB deploy
# Log: runs/2026-10-22-testnet-200m.txt (each step appends). No load rehearsal, no burst / fill, no calibration.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
N=$(cd "$HERE/.." && pwd)
C=$N/chain
L=/home/dockers/mba-chain-nethermind
IMG=scaas/nethermind-pqz:2.2.0-pqz3
G=0xa17faef497fa29ec90603969dad0176ea18fd1cc2eaf0f9f4fa2dacc9c952ac2  # predicted (throwaway run with the live genesis)
KEY=0x0000000000000000000000000000000000000000000000000000000000000004 # test key 0x…04, funded in genesis
E=$HERE/2026-10-21-testnet-engine-pqz.json   # = the live engine.Pqz (two schedules, PQZL v2 rows)
# the corpus of the image's library (pqz3 = FFI_REV 1adbd563, PQZL v2); main's bin/corpus.jsonl is v3. Rebuild it with
# bin/ffi-src/.../corpus.py as the 2026-10-21 check step did, or point K at the nethermind-2.2 worktree's copy.
K=${K:-$N/bin/corpus-ffi-1adbd563.jsonl}
D=20261022
LOG=$HERE/2026-10-22-testnet-200m.txt
run() { echo "\$ $*" >> "$LOG"; "$@" >> "$LOG" 2>&1; rc=$?; echo "[rc=$rc]" >> "$LOG"; return $rc; }

case "${1:?reset | check}" in
reset)
  echo "# reset $(date -u +%FT%TZ), image $IMG $(docker image inspect $IMG --format '{{.Id}}')" >> "$LOG"
  cd "$L"
  [ "$(docker inspect -f '{{.State.Status}}' mba_chain_node_nethermind)" = exited ] || docker compose stop blockchain-node
  [ -e "genesis.json.bak-pre-200m-$D" ] || cp -p genesis.json "genesis.json.bak-pre-200m-$D"
  # the same chainspec apart from the genesis gasLimit: --testnet-reset replaces engine.Pqz by the same rows (the
  # extracted live copy), keeps the params (the three reset params are already set) and sets gasLimit 0xbebc200
  run python3 -I "$C/patch-chainspec.py" "genesis.json.bak-pre-200m-$D" "$E" 0 genesis.json.new --testnet-reset
  echo "\$ diff genesis.json.bak-pre-200m-$D genesis.json.new (semantic)" >> "$LOG"
  python3 -I - "genesis.json.bak-pre-200m-$D" genesis.json.new >> "$LOG" 2>&1 <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:3])
def flat(x, p=""):
    return {k2: v2 for k, v in x.items() for k2, v2 in (flat(v, f"{p}{k}.") if isinstance(v, dict) else {f"{p}{k}": v}).items()}
fa, fb = flat(a), flat(b)
d = {k: (fa.get(k), fb.get(k)) for k in set(fa) | set(fb) if fa.get(k) != fb.get(k)}
print(d)
assert set(d) == {"genesis.gasLimit"}, d
PY
  mv genesis.json.new genesis.json
  grep -q '"TargetBlockGasLimit": 200000000' config.json || { echo "FAIL config.json TargetBlockGasLimit is not 200 M" >> "$LOG"; exit 1; }
  # the fresh chain: the old data dir is renamed, not deleted
  run docker run --rm --memory 256m --cpus 1 -v "$L/data:/d" alpine:3 sh -c "mv /d/nethermind_data /d/nethermind_data.pre-200m-$D && mkdir /d/nethermind_data && ls -la /d"
  run docker compose up -d blockchain-node
  sleep 40
  echo "\$ docker logs mba_chain_node_nethermind | grep PQZ / Error" >> "$LOG"
  docker logs mba_chain_node_nethermind 2>&1 | grep -E 'PQZ-START|PQZ-REFUSE|Invalid configuration|ERROR|Exception' | head -20 >> "$LOG"
  ;;
check)
  echo "# check $(date -u +%FT%TZ)" >> "$LOG"
  run "$C/watch.sh" mba_chain_node_nethermind http://127.0.0.1:8545 2m
  run python3 -I "$C/e2e.py" head --rpc http://127.0.0.1:8545
  run python3 -I -c "import json, urllib.request as u; r = lambda n: json.load(u.urlopen(u.Request('http://127.0.0.1:8545', json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'eth_getBlockByNumber', 'params': [n, False]}).encode(), {'content-type': 'application/json'})))['result']; [print('block', int(b['number'], 16), b['hash'], 'gasLimit', int(b['gasLimit'], 16)) for b in (r('0x0'), r('0x1'))]"
  run python3 -I "$C/e2e.py" probe --engine "$E" --corpus "$K" --rpc http://127.0.0.1:8545 --genesis-hash $G
  run python3 -I "$C/e2e.py" e2e --engine "$E" --corpus "$K" --rpc http://127.0.0.1:8545 --key $KEY --no-ua
  run python3 -I "$C/e2e.py" codesize --rpc http://127.0.0.1:8545 --key $KEY   # no ramp to wait for: 200 M from block 0
  ;;
esac
