#!/bin/sh
# P6f D14: one look at a PQZ node — head height / age, gasLimit, the container's state and last exit code, and the
# PQZ log tags since <since> (default 1h). Run by the operator or cron; changes nothing.
#   watch.sh <container> <rpc> [since]
set -u
C=${1:?container}; RPC=${2:?rpc}; S=${3:-1h}
H=$(curl -s -m 10 -H 'content-type: application/json' --data '{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["latest",false]}' "$RPC")
python3 -I -c '
import json, sys, time
try:
    b = json.loads(sys.argv[1])["result"]
    n, ts, gl, gu = (int(b[k], 16) for k in ("number", "timestamp", "gasLimit", "gasUsed"))
    h = b["hash"]
    print(f"head {n} age {int(time.time()) - ts}s gasLimit {gl:,} gasUsed {gu:,} hash {h}")
except Exception as e:
    print(f"head: no answer from the RPC ({e})")
' "$H"
echo "container $C: $(docker inspect -f '{{.State.Status}} exit={{.State.ExitCode}} started={{.State.StartedAt}} restarts={{.RestartCount}}' "$C" 2>&1)"
R=$(docker inspect -f '{{.RestartCount}}' "$C" 2>/dev/null)
[ "${R:-0}" -gt 0 ] && echo "WARN $C restarted $R times (restart: unless-stopped): check for a crash loop"
L=$(docker logs --since "$S" "$C" 2>&1)
for t in PQZ-START PQZ-INPUT-PANIC PQZ-NODE-FAULT PQZ-REFUSE; do
  echo "$t since $S: $(printf '%s\n' "$L" | grep -c "$t")"
done
printf '%s\n' "$L" | grep -E "PQZ-NODE-FAULT|PQZ-REFUSE|PQZ-INPUT-PANIC" | tail -3
