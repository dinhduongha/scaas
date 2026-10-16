#!/bin/sh
# PROBE (single proofs, sizes only): HVZK-WHIR mask code rate / length vs proof bytes, R_REG, Goldilocks^5, rate 3,
# Johnson 128. Run alone: scripts/capped runs/w0-mask-probe.sh > runs/w0-mask-probe.log
set -eu
cd "$(dirname "$0")/.."
cargo build --release --offline --bin pqzh_bench --bin pqzh_security 2>/dev/null
for m in 1 2 3 4 6; do
  for l in 4; do
    tag=w0-probe-mask$m-ell$l
    /usr/bin/time -v target/release/pqzh_bench --rel reg --np 1 --sizes-only --ext5 --whir-rate 3 --whir-mask-rate $m \
      --whir-ell $l --max-proof 100000000 > runs/$tag.jsonl 2> runs/$tag-time.txt
    target/release/pqzh_security --whir --ext 5 --rate 3 --mask-rate $m --ell $l | head -1 > runs/$tag-bits.jsonl
    echo "$tag $(grep -o '"proof_bytes": [0-9]*' runs/$tag.jsonl) $(grep -o '"bits_composed": [0-9.]*' runs/$tag-bits.jsonl)"
  done
done
