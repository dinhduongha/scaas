#!/bin/sh
# Rust PQZL roll-out on chain 7622 (2026-10-19), path A as the op 7 section of chain/RUNBOOK.md. PREPARED, NEVER RUN:
# the owner stopped the roll-out before the live step ("Dừng và rollback", PQZL Fiat–Shamir finding). Kept as the
# prepared procedure for the next roll-out (the rows file and the image will change with the new proofSystemId).
#   sh runs/2026-10-19-rust-live.sh before   stop, back up, third schedule at T, image pqz2 -> pqz3, start, probe before T
#   sh runs/2026-10-19-rust-live.sh after    after T: probe and e2e (writes nothing on the chain host)
# Log: runs/2026-10-19-rust-live.txt (+ -probe-before-T, -probe-after-T, -e2e). Any failed check: stop, RUNBOOK rollback.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
N=$(cd "$HERE/.." && pwd)
C=$N/chain
L=/home/dockers/mba-chain-nethermind
G=0x24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464
KEY=0x0000000000000000000000000000000000000000000000000000000000000004   # test key 0x…04, funded in genesis
LOG=$HERE/2026-10-19-rust-live.txt
fail() { echo "FAIL: $*"; exit 1; }
count() { echo "$1 rc=$2 ($(grep -c '^ok' "$3") ok, $(grep -c '^FAIL' "$3") FAIL): $(tail -1 "$3")"; }
exec >> "$LOG" 2>&1
case ${1:?before or after} in
before)
  TS=$(date +%Y%m%d-%H%M%S); B=/home/dockers/mba-chain-nethermind-backups/rust-$TS
  A="docker run --rm --memory 512m -v $L:/l -v $(dirname "$B"):/b alpine:3"
  echo "# Rust PQZL roll-out on chain 7622 (path A: a third engine.Pqz schedule, image pqz2 -> pqz3, data kept), $(date -u +%FT%TZ), commit $(git -C "$N" rev-parse --short HEAD)"
  echo "## 0. before"
  python3 -I "$C/e2e.py" head --rpc http://127.0.0.1:8545 | head -1
  echo "pqz3 image $(docker image inspect scaas/nethermind-pqz:1.39.0-pqz3 --format '{{.Id}}') label ffi $(docker image inspect scaas/nethermind-pqz:1.39.0-pqz3 --format '{{index .Config.Labels "scaas.pqz.ffi.sha256"}}')"
  echo "## 1. stop + backup -> $B"
  cd $L && docker compose stop -t 120 blockchain-node
  echo "state $(docker inspect -f '{{.State.Status}}' mba_chain_node_nethermind)"
  [ "$(docker inspect -f '{{.State.Status}}' mba_chain_node_nethermind)" = exited ] || fail "node not stopped"
  mkdir -p "$B" && cp -p genesis.json config.json docker-compose.yml password.txt "$B/" || fail "config backup"
  $A sh -c "cp -a /l/keystore /l/data/nethermind_data /b/rust-$TS/" || fail "data backup"
  $A sh -c "cd /l/data/nethermind_data && find . -type f | sort | xargs sha256sum" > "$B.live-data.sha256"
  $A sh -c "cd /b/rust-$TS/nethermind_data && find . -type f | sort | xargs sha256sum" > "$B.backup-data.sha256"
  cmp "$B.live-data.sha256" "$B.backup-data.sha256" && echo "data backup identical: $(wc -l < "$B.live-data.sha256") files" || fail "data manifests differ"
  $A sh -c "cd /l/keystore && find . -type f | sort | xargs sha256sum" > "$B.live-keystore.sha256"
  $A sh -c "cd /b/rust-$TS/keystore && find . -type f | sort | xargs sha256sum" > "$B.backup-keystore.sha256"
  cmp "$B.live-keystore.sha256" "$B.backup-keystore.sha256" && echo "keystore backup identical: $(wc -l < "$B.live-keystore.sha256") files" || fail "keystore manifests differ"
  F="genesis.json config.json docker-compose.yml password.txt"
  [ "$(cd $L && sha256sum $F)" = "$(cd "$B" && sha256sum $F)" ] && echo "config files identical" || fail "config files differ"
  $A du -s /l/data/nethermind_data /b/rust-$TS/nethermind_data
  T=$(( $(date +%s) + 960 ))
  echo "## 2. edits (T = $T = $(date -u -d @$T +%FT%TZ))"
  python3 -I "$C/add-schedule.py" "$B/genesis.json" "$HERE/2026-10-19-pqzl-rows-engine-pqz.json" $T $L/genesis.json \
    --ops 1,2,3,4,5,7 --id pqzl --selftest || fail "add-schedule"
  sed -i 's#scaas/nethermind-pqz:1.39.0-pqz2#scaas/nethermind-pqz:1.39.0-pqz3#' docker-compose.yml
  diff "$B/docker-compose.yml" docker-compose.yml
  python3 -I - "$B/genesis.json" $L/genesis.json <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:])
sa, sb = a["engine"]["Pqz"]["schedules"], b["engine"]["Pqz"]["schedules"]
b["engine"]["Pqz"]["schedules"] = sb[:len(sa)]
print("genesis: only engine.Pqz.schedules grew:", a == b and len(sb) == len(sa) + 1)
PY
  echo "## 3. start"
  docker compose up -d blockchain-node
  sleep 30
  S=$(docker logs mba_chain_node_nethermind 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'PQZ-START|PQZ-REFUSE' | tail -1)
  echo "$S" | cut -c1-400
  echo "$S" | grep -q "PQZ-START sha256=16dd99ce77d05a9bea9f54142979bc21511240aeff6d4442d784470a428c9caf selftest=ed910a2cf4c8f7845efe524151f68f91074a40ab8f59df687e233ce91333d205" || fail "PQZ-START"
  echo "schedules in PQZ-START: $(echo "$S" | grep -o '{ts [0-9]*, rows [0-9]*' | tr '\n' ' ')/ selftest $(echo "$S" | grep -o 'selftest [0-9]*' | tr '\n' ' ')"
  python3 -I "$C/e2e.py" head --rpc http://127.0.0.1:8545 | head -1
  python3 -I -c "import json; json.dump(json.load(open('$L/genesis.json'))['engine']['Pqz'], open('$C/engine-pqz.json', 'w'), indent=2)"
  echo "## 4. probe before T (schedule 1), genesis hash pinned"
  P=$HERE/2026-10-19-rust-live-probe-before-T.txt
  python3 -I "$C/e2e.py" probe --engine "$C/engine-pqz.json" --schedule 1 --rpc http://127.0.0.1:8545 --genesis-hash $G > "$P" 2>&1
  count probe $? "$P"
  echo "T=$T B=$B"
  ;;
after)
  echo "## 5. after T"
  python3 -I "$C/e2e.py" head --rpc http://127.0.0.1:8545 | head -1
  P=$HERE/2026-10-19-rust-live-probe-after-T.txt
  python3 -I "$C/e2e.py" probe --engine "$C/engine-pqz.json" --rpc http://127.0.0.1:8545 --genesis-hash $G > "$P" 2>&1
  count probe $? "$P"
  P=$HERE/2026-10-19-rust-live-e2e.txt
  python3 -I "$C/e2e.py" e2e --engine "$C/engine-pqz.json" --rpc http://127.0.0.1:8545 --key $KEY --no-ua > "$P" 2>&1
  count e2e $? "$P"
  echo "fault / panic / refuse lines: $(docker logs mba_chain_node_nethermind 2>&1 | grep -cE 'PQZ-NODE-FAULT|PQZ-INPUT-PANIC|PQZ-REFUSE')"
  python3 -I "$C/e2e.py" head --rpc http://127.0.0.1:8545 | head -1
  ;;
esac
