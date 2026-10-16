#!/bin/sh
# PROBE (one proof each, sizes / prove time / peak heap only): ZK WHIR Goldilocks^5, Johnson 128, starting rate 2 and 4
# (blowup 4 / 16) around the w2 setting (rate 3). Run alone: scripts/capped runs/w4-rate-probe.sh > runs/w4-rate-probe.log
set -eu
cd "$(dirname "$0")/.."
cargo build --release --offline --bin pqzh_bench 2>/dev/null
for r in 2 4; do
  tag=w4-probe-zkwhir5-r$r
  /usr/bin/time -v target/release/pqzh_bench --ext5 --whir-rate $r --np 1 --sizes-only --max-proof 100000000 \
    > runs/$tag.jsonl 2> runs/$tag-time.txt || echo "$tag failed: $?"
  echo "$tag $(grep -o '"proof_bytes": [0-9]*' runs/$tag.jsonl | tr '\n' ' ') $(grep -E 'Maximum resident|Elapsed' runs/$tag-time.txt | tr -s ' ')"
done
