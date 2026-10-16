#!/bin/sh
# ZK WHIR, Goldilocks^2 at its reachable per-term targets (owner 2026-10-14: 96-100 bits only; 128 is refused by
# WHIR's grinding budget, pqzh-zk-ext5.md §7): starting rate 3, fold 4, mask code rate 1/16; target 96 with 16
# grinding bits and target 100 with 20. n = 3 proofs, 100 honest verifies, 12 mutation kinds x 10 per relation.
# Run alone: scripts/capped runs/w3-zkwhir2.sh > runs/w3-zkwhir2.log
set -eu
cd "$(dirname "$0")/.."
cargo build --release --offline --bin pqzh_bench --bin pqzh_security 2>/dev/null
for c in "96 16" "100 20"; do
  set -- $c
  tag=w3-zkwhir2-r3-t$1-pow$2
  /usr/bin/time -v target/release/pqzh_bench --whir-rate 3 --whir-target $1 --whir-pow $2 --np 3 --nv 100 --nadv 10 \
    --max-proof 100000000 > runs/$tag.jsonl 2> runs/$tag-time.txt || echo "$tag failed: $?"
  echo "$tag $(grep -E 'Maximum resident|Elapsed' runs/$tag-time.txt | tr -s ' ')"
  target/release/pqzh_security --whir --ext 2 --rate 3 --target $1 --pow $2 > runs/$tag-bits.jsonl 2>&1 || echo "$tag bits failed"
done
