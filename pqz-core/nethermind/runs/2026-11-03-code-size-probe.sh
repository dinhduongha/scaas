#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Governance plan T0 (CTR-GOV-19): does a contract above 64 KiB deploy under Amsterdam's EIP-7954 with maxCodeSize 0x20000?
#   sh runs/2026-11-03-code-size-probe.sh <0 | A | B | C | D> [image]     one arm, foreground; default image 2.2.0-pqz6
# Arm D (plan T0b): as C (EIP-7954 out), gasLimit and target 300 M: the code ceiling at 0x20000 and the init code limit.
# A throwaway copy under $COPY (default <repo>/scratchpad/gov-probe), project pqzcopy, 127.0.0.1:18545. The live directory
# is never read. One node container at a time (1700m): the signer makes the blocks, then a second node, signer stopped, imports them
# from RLP through Nethermind's Hive plugin, so a block another node refuses shows. Per-arm log <this name>-<arm>-<tag>.log
# (git-ignored), first line "# <arm> at commit <sha>", last "rc=<n>"; an arm that ended rc=0 at this commit is skipped.
set -eu
ARM=${1:?0 | A | B | C | D}
IMAGE=${2:-scaas/nethermind-pqz:2.2.0-pqz6}
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../chain" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
COPY=${COPY:-$ROOT/scratchpad/gov-probe}
export COPY
SHA=$(git -C "$ROOT" rev-parse --short HEAD)
LOG=$HERE/2026-11-03-code-size-probe-$ARM-${IMAGE##*:}.log

if [ -z "${PROBE_INNER:-}" ]; then
  if [ -f "$LOG" ] && [ "$(head -1 "$LOG")" = "# $ARM at commit $SHA" ] && [ "$(tail -1 "$LOG")" = "rc=0" ]; then
    echo "arm $ARM: done at $SHA, skipped"; exit 0
  fi
  echo "# $ARM at commit $SHA" > "$LOG"
  rc=0
  PROBE_INNER=1 sh "$0" "$@" >> "$LOG" 2>&1 || rc=$?
  echo "rc=$rc" >> "$LOG"
  grep -E '^(ok|FAIL) |params:|PROBE-' "$LOG" || true
  echo "arm $ARM: rc=$rc"
  exit "$rc"
fi

# signer | follower: one service of the copy's compose file, on the port the file gives only to nginx
node_up() {
  IMAGE=$IMAGE GENESIS=genesis.arm.json docker compose -f "$C/docker-compose.copy.yml" -f - up -d "$1" <<'YML'
services:
  signer:
    ports: ["127.0.0.1:18545:8545"]
  follower:
    ports: ["127.0.0.1:18545:8545"]
    environment: {NETHERMIND_HIVE_ENABLED: "true"}
    volumes: ["${COPY}/rows.jsonl.rlp:/chain.rlp:ro"]
YML
  curl -s --retry 90 --retry-delay 2 --retry-all-errors --retry-max-time 240 -o /dev/null -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' http://127.0.0.1:18545
}
node_log() { docker logs "pqzcopy-$1" 2>&1 | grep -E 'PQZ-START|PQZ-REFUSE|Invalid|Rejected|[Ii]nvalid block|Exception|Nethermind 2\.|Hive' | head -40 || true; }
e2e() { python3 -I "$C/e2e.py" "$@"; }
rows() { e2e codesize --key "$KEY" --record "$COPY/rows.jsonl" --sizes "$1" --gas "$2"; }
clean() { rc=$?; trap - EXIT; "$C/copy.sh" down || true; "$C/copy.sh" wipe || true; exit "$rc"; }

[ -z "$(docker ps -q --filter name=pqzcopy-)" ]
awk '/MemAvailable/ {exit !($2 >= 4194304)}' /proc/meminfo
trap clean EXIT
"$C/copy.sh" init
"$C/copy.sh" genesis0 "$C/engine-pqz.json"
python3 -I - "$COPY" "$ARM" <<'PY'
import json, sys
copy, arm = sys.argv[1:]
g = json.load(open(f"{copy}/genesis.pqz0.json"))
p = g["params"]
# runs/2026-10-21-testnet-reset-2.2.0.sh: the Amsterdam transitions, timestamp 1
for e in (2780, 7708, 7778, 7928, 7954, 7976, 7981, 8024, 8037, 8038, 8246):
    p[f"eip{e}TransitionTimestamp"] = 1
target = 200_000_000
if arm != "0":
    p["maxCodeSize"] = "0x20000"
if arm in ("B", "D"):
    target = 300_000_000
    g["genesis"]["gasLimit"] = hex(target)
if arm in ("C", "D"):
    del p["eip7954TransitionTimestamp"]
json.dump(g, open(f"{copy}/genesis.arm.json", "w"), indent=1)
print(f"params: arm {arm} maxCodeSize {p['maxCodeSize']} maxCodeSizeTransition {p['maxCodeSizeTransition']} "
      f"eip7954TransitionTimestamp {p.get('eip7954TransitionTimestamp', 'removed')} genesis gasLimit {g['genesis']['gasLimit']} "
      f"TargetBlockGasLimit {target}")
for n in ("signer", "follower"):
    f = f"{copy}/config.{n}.json"
    c = json.load(open(f))
    c["Init"].pop("IsMining", None)  # 2.2.0 refuses the key (RUNBOOK)
    c["Blocks"]["TargetBlockGasLimit"] = target
    c["JsonRpc"]["GasCap"] = target  # e2e.py replays a refused create by eth_call for its error; the default cap is 100 M
    c["JsonRpc"]["EnabledModules"].append("debug")
    if n == "follower":
        c["Hive"] = {"Enabled": True}  # Nethermind warns "Invalid configuration settings: Hive.Enabled", and needs it
    json.dump(c, open(f, "w"), indent=2)
PY
KEY=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print((d["data"] if "data" in d else d)[0]["private_key"])' "$COPY/signer.json")
echo "PROBE-image $IMAGE $(docker image inspect "$IMAGE" --format '{{.Id}}')"

node_up signer
: > "$COPY/rows.jsonl"
fail=0
case $ARM in
0) rows 65536:ok,65537:fail 110000000 || fail=1 ;;
A|C)
  rows 65536:ok,65537:ok,70000:jump 130000000 || fail=1
  rows 119000:ok 198900000 || fail=1
  rows 119800:any 199900000 || fail=1          # not in T0: the same size at a tx.gas that fits the block
  rows 119800:out 200100000 || fail=1 ;;       # T0: formula tx.gas above the block; last, it may stay pending
B)
  rows 131072:ok,131073:fail 290000000 || fail=1
  rows 131073:init,140000:init 30000000 || fail=1 ;;
D)
  rows 131072:ok,131073:fail 290000000 || fail=1
  # init code rows, accepted or refused, ascending: a refusal at the pool takes no nonce. The largest .init row of
  # size-baseline.json (WrappedPqzToken's) first.
  INIT=$(python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); print(max(v for k, v in d.items() if k.endswith(".init")))' \
    "$ROOT/smartcontracts/evm/size-baseline.json")
  echo "PROBE-largest-init size-baseline.json $INIT B"
  rows "$INIT:init,131072:init,131073:init,262144:init,262145:init" 290000000 || fail=1 ;;
esac
e2e codedump --record "$COPY/rows.jsonl" || fail=1
node_log signer
"$C/copy.sh" down

node_up follower
e2e codeverify --record "$COPY/rows.jsonl" || fail=1
node_log follower
exit "$fail"
