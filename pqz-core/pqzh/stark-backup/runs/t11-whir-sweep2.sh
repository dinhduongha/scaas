#!/bin/sh
# WHIR sweep, part 2: Goldilocks^2 at lower per-term targets (128 needs 42-50 grinding bits, runs/t10-whir-sweep.err),
# Goldilocks^5 with larger folding factors and rate 5. Run alone: scripts/capped runs/t11-whir-sweep2.sh
set -u
cd "$(dirname "$0")/.."
run() { target/release/pqzh_whir "$@" --np 1 --nv 3 --nadv 1 >> runs/t11-whir-sweep2.jsonl 2>> runs/t11-whir-sweep2.err \
  || echo "args $* rc=$?" >> runs/t11-whir-sweep2.err; }
for tgt in 100 110 115 120; do run --ext 2 --rate 3 --fold 4 --target $tgt; done
for f in 6 8; do run --ext 5 --rate 3 --fold $f --target 128; run --ext 5 --rate 4 --fold $f --target 128; done
run --ext 5 --rate 5 --fold 4 --target 128
