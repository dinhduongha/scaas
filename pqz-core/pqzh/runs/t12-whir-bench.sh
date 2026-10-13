#!/bin/sh
# Non-hiding WHIR benches (Johnson bound, fold 4): Goldilocks^5 at the 128-bit per-term target (rates 2-4) and
# Goldilocks^2 at the highest target 16-18 grinding bits allow (128 needs 42 bits: runs/t10-whir-sweep.err).
# n = 3 proofs, 100 honest + 120 mutated verifies. Run alone: scripts/capped runs/t12-whir-bench.sh
set -u
cd "$(dirname "$0")/.."
run() { tag=$1; shift; /usr/bin/time -v target/release/pqzh_whir "$@" --np 3 --nv 100 --nadv 10 > runs/t12-whir-$tag.jsonl \
  2> runs/t12-whir-$tag-time.txt; echo "$tag rc=$?"; }
run ext5-r2 --ext 5 --rate 2 --target 128
run ext5-r3 --ext 5 --rate 3 --target 128
run ext5-r4 --ext 5 --rate 4 --target 128
run ext2-r3-t98 --ext 2 --rate 3 --target 98 --pow 16
run ext2-r3-t100-pow18 --ext 2 --rate 3 --target 100 --pow 18
