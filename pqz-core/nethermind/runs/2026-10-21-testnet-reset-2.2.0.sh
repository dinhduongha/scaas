#!/bin/sh
# SCaaS testnet (chain id 7622) reset onto Nethermind 2.2.0 + Amsterdam (Glamsterdam), 2026-10-21.
# Owner 2026-10-21: reset directly with the new image and Amsterdam active, no backup. Nothing is deleted: the old data
# dir is renamed next to itself and the three edited files get a .bak-1.39.0-<date> copy (the directory's convention).
#   sh runs/2026-10-21-testnet-reset-2.2.0.sh reset     edit chainspec / config / compose, rename the data dir, start
#   sh runs/2026-10-21-testnet-reset-2.2.0.sh check     health, probe (eth_call) and e2e (transactions)
# Log: runs/2026-10-21-testnet-2.2.0.txt (each step appends).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
N=$(cd "$HERE/.." && pwd)
C=$N/chain
L=/home/dockers/mba-chain-nethermind
IMG=scaas/nethermind-pqz:2.2.0-pqz3
G=0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464   # genesis hash: unchanged (Amsterdam from ts 1)
KEY=0x0000000000000000000000000000000000000000000000000000000000000004 # test key 0x…04, funded in genesis
D=20261021
LOG=$HERE/2026-10-21-testnet-2.2.0.txt
run() { echo "\$ $*" >> "$LOG"; "$@" >> "$LOG" 2>&1; rc=$?; echo "[rc=$rc]" >> "$LOG"; return $rc; }

case "${1:?reset | check}" in
reset)
  echo "# reset $(date -u +%FT%TZ), image $IMG $(docker image inspect $IMG --format '{{.Id}}')" >> "$LOG"
  [ "$(docker inspect -f '{{.State.Status}}' mba_chain_node_nethermind)" = exited ] || { echo "FAIL: the node is not stopped" >> "$LOG"; exit 1; }
  cd "$L"
  for f in genesis.json config.json docker-compose.yml; do [ -e "$f.bak-1.39.0-$D" ] || cp -p "$f" "$f.bak-1.39.0-$D"; done
  # Amsterdam per EIP at timestamp 1 (genesis is at 0, so the genesis header and hash stay; every later block is
  # Amsterdam). Not EIP-7843 (SLOTNUM: the header's slot number comes from a consensus layer; the Clique producer
  # sets none and 2.2.0's header validator rejects a block without one) and not EIP-8282 (builder deposit / exit
  # requests: system calls into CL predeploys that a Clique chain does not have), as 4788 / 6110 / 7002 / 7251 today.
  python3 -I - genesis.json <<'PY'
import json, sys
p = sys.argv[1]
g = json.load(open(p))
eips = [2780, 7708, 7778, 7928, 7954, 7976, 7981, 8024, 8037, 8038, 8246]
for e in eips:
    k = f"eip{e}TransitionTimestamp"
    assert k not in g["params"], k
    g["params"][k] = 1
json.dump(g, open(p, "w"), indent=2)
print("amsterdam keys:", ", ".join(f"eip{e}TransitionTimestamp=1" for e in eips))
PY
  # 64 KiB code needs ~100 M state gas (EIP-8037: 1,530 per byte), and EIP-8037 reserves tx.gas in the block's state
  # dimension: raise the target to 200 M (Glamsterdam's block size, 2.2.0 notes)
  python3 -I - config.json <<'PY'
import json, sys
p = sys.argv[1]
c = json.load(open(p))
c["Blocks"]["TargetBlockGasLimit"] = 200000000
c["Init"].pop("IsMining", None)  # 2.2.0: "Invalid configuration settings" (done by hand at the restart; Mining.Enabled stays)
json.dump(c, open(p, "w"), indent=2)
PY
  sed -i "s#image: scaas/nethermind-pqz:1.39.0-pqz2#image: $IMG#" docker-compose.yml
  for f in genesis.json config.json docker-compose.yml; do echo "\$ diff $f.bak-1.39.0-$D $f" >> "$LOG"; diff "$f.bak-1.39.0-$D" "$f" >> "$LOG" 2>&1 || true; done
  # the fresh chain: the 1.39.0 data dir is renamed, not deleted
  run docker run --rm --memory 256m -v "$L/data:/d" alpine:3 sh -c "mv /d/nethermind_data /d/nethermind_data.pre-2.2.0-$D && mkdir /d/nethermind_data && ls -la /d"
  run docker compose up -d blockchain-node
  sleep 40
  echo "\$ docker logs mba_chain_node_nethermind | grep PQZ / Nethermind / Invalid / Error" >> "$LOG"
  docker logs mba_chain_node_nethermind 2>&1 | grep -E 'PQZ-START|PQZ-REFUSE|Nethermind 2\.|Version|Invalid configuration|ERROR|Error|Exception|Amsterdam|Sealed|Produced' | head -40 >> "$LOG"
  ;;
check)
  echo "# check $(date -u +%FT%TZ)" >> "$LOG"
  run "$C/watch.sh" mba_chain_node_nethermind http://127.0.0.1:8545 2h
  run python3 -I "$C/e2e.py" head --rpc http://127.0.0.1:8545
  run python3 -I -c "import json; json.dump(json.load(open('$L/genesis.json'))['engine']['Pqz'], open('$HERE/2026-10-21-testnet-engine-pqz.json', 'w'), indent=2)"
  # the live rows (PQZL v2 id) and the vectors of the library's own commit (FFI_REV of build-image.sh): main's
  # chain/engine-pqz.json and bin/corpus.jsonl carry the v3 id the reviewed library does not verify
  run python3 -I "$N/bin/ffi-src/pqz-core/nethermind/corpus.py" "$N/bin/corpus-ffi-1adbd563.jsonl"
  E=$HERE/2026-10-21-testnet-engine-pqz.json; K=$N/bin/corpus-ffi-1adbd563.jsonl
  run python3 -I "$C/e2e.py" probe --engine "$E" --corpus "$K" --rpc http://127.0.0.1:8545 --genesis-hash $G
  run python3 -I "$C/e2e.py" e2e --engine "$E" --corpus "$K" --rpc http://127.0.0.1:8545 --key $KEY --no-ua
  run python3 -I "$C/e2e.py" codesize --rpc http://127.0.0.1:8545 --key $KEY   # waits for the 1/1024 gas-limit ramp
  ;;
esac
