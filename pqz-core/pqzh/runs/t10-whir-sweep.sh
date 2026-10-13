#!/bin/sh
# Non-hiding WHIR (p3-whir 0.9.0-rc.1, Johnson bound) through p3-multi-stark: sweep over challenge field,
# starting rate, folding factor and the per-term target (the composed bound sums the PCS terms). One proof each,
# 3 honest + 12 mutated verifies. Not zero-knowledge (pqzh-zk-ext5.md §7). Run alone: scripts/capped runs/t10-whir-sweep.sh
set -u
cd "$(dirname "$0")/.."
for ext in 2 5; do
  for rate in 1 2 3 4; do
    for fold in 4; do
      for tgt in 128 130; do
        target/release/pqzh_whir --ext $ext --rate $rate --fold $fold --target $tgt --np 1 --nv 3 --nadv 1 \
          >> runs/t10-whir-sweep.jsonl 2>> runs/t10-whir-sweep.err || echo "ext $ext rate $rate fold $fold target $tgt rc=$?" >> runs/t10-whir-sweep.err
      done
    done
  done
done
