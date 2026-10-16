#!/bin/sh
# ZK + Goldilocks^5 at 128 bits (proven / conjectured, p3-security, 16 grinding bits, arity 8): sizes, prove time,
# peak heap, one proof each. Run alone: scripts/capped runs/t5-probe.sh
set -u
cd "$(dirname "$0")/.."
for c in "3 75 proven" "4 57 proven" "5 45 proven" "3 38 conj" "4 29 conj" "5 23 conj"; do
  set -- $c
  /usr/bin/time -f "maxrss_kb %M elapsed %e" target/release/pqzh_bench --zk --ext5 --blowup $1 --queries $2 --np 1 --sizes-only --max-proof 4000000 \
    > runs/t5-probe-b$1-q$2.jsonl 2> runs/t5-probe-b$1-q$2-time.txt
  echo "$3 b$1 q$2 rc=$? $(tail -1 runs/t5-probe-b$1-q$2-time.txt)"
done
