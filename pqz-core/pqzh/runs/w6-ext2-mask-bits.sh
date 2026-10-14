#!/bin/sh
# MODEL (no proofs): bits of one HVZK-WHIR opening of the R_TX main-round shape (22 variables, 24 claims), Goldilocks^2
# and Goldilocks^5, per-term target / grinding, mask code rate 1..6: the masked base case's gamma round over the
# 2^128 field (runs/w3-*-bits.jsonl: vacuous at mask rate 1/16). Run alone under scripts/capped.
set -eu
cd "$(dirname "$0")/.."
cargo build --release --offline --bin pqzh_security 2>&1 >/dev/null | grep -E "^error" -A5 >&2 || true
for e in 2 5; do
  for t in "96 16" "100 20" "128 16"; do
    set -- $t
    for m in 1 2 3 4 5 6; do
      target/release/pqzh_security --whir --ext $e --rate 3 --target $1 --pow $2 --mask-rate $m --vars 22 --claims 24
    done
  done
done
