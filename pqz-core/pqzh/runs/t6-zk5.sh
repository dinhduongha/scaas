#!/bin/sh
# ZK + Goldilocks^5 at 128 bits (p3-security: proven = Johnson / unique decoding, conjectured = random words;
# 16 grinding bits, FRI arity 8): full native bench (prove, honest + adversarial verify), wasm32 verify of the
# natively made proofs, then the Merkle cap sweep (sizes). Blowup 32 needs > 4 GB (runs/t5-probe-b5-*): left out.
# Run alone: scripts/capped runs/t6-zk5.sh
set -eu
cd "$(dirname "$0")/.."
cargo build --release --offline --bin pqzh_bench 2>/dev/null
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2>/dev/null)
for c in "3 75 proven" "4 57 proven" "3 38 conj" "4 29 conj"; do
  set -- $c
  tag=t6-zk5-$3-b$1-q$2
  mkdir -p target/proofs/$tag
  /usr/bin/time -v target/release/pqzh_bench --zk --ext5 --blowup $1 --queries $2 --np 3 --nv 100 --nadv 10 \
    --max-proof 4000000 --dump target/proofs/$tag > runs/$tag.jsonl 2> runs/$tag-time.txt
  PQZH_PROOFS=target/proofs/$tag node wasm/run_wasm.mjs 0 100 10 $1 $2 1 4000000 1 > runs/$tag-wasm.jsonl
  echo "$tag $(grep -E 'Maximum resident' runs/$tag-time.txt)"
done
for c in "3 75" "4 57" "3 38" "4 29"; do
  set -- $c
  for cap in 0 4 6 8; do
    target/release/pqzh_bench --zk --ext5 --blowup $1 --queries $2 --cap $cap --np 1 --sizes-only --max-proof 4000000 \
      > runs/t7-cap-zk5-b$1-q$2-cap$cap.jsonl
  done
done
