#!/bin/sh
# ZK + Goldilocks^5 at 128 bits with 24 grinding bits (fewer queries, p3-security runs/t4-model-ext5-zk-pow24.jsonl):
# one proof each, sizes / prove time / peak heap. Run alone: scripts/capped runs/t8-pow24.sh
set -u
cd "$(dirname "$0")/.."
for c in "3 70 proven" "4 53 proven" "3 35 conj" "4 27 conj"; do
  set -- $c
  /usr/bin/time -f "maxrss_kb %M elapsed %e" target/release/pqzh_bench --zk --ext5 --pow 24 --blowup $1 --queries $2 --np 1 \
    --sizes-only --max-proof 4000000 > runs/t8-pow24-$3-b$1-q$2.jsonl 2> runs/t8-pow24-$3-b$1-q$2-time.txt
  echo "$3 b$1 q$2 rc=$? $(tail -1 runs/t8-pow24-$3-b$1-q$2-time.txt)"
done
