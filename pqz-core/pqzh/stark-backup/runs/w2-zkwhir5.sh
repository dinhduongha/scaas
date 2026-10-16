#!/bin/sh
# ZK WHIR (src/whirpcs.rs), Goldilocks^5, Johnson bound, 128-bit per-term target, fold 4, 16 grinding bits, mask code
# rate 1/16, starting rate 3 (blowup 8): native bench (n = 3 proofs, 100 honest verifies, 12 mutation kinds x 40 per
# relation = 960 mutated inputs), bits per term, then wasm32 verify of the natively made proofs.
# Run alone: scripts/capped runs/w2-zkwhir5.sh > runs/w2-zkwhir5.log
set -eu
cd "$(dirname "$0")/.."
tag=w2-zkwhir5-r3
cargo build --release --offline --bin pqzh_bench --bin pqzh_security 2> runs/$tag-build.txt
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown) 2> runs/$tag-wasm-build.txt
mkdir -p target/proofs/$tag
/usr/bin/time -v target/release/pqzh_bench --ext5 --whir-rate 3 --np 3 --nv 100 --nadv 40 --max-proof 100000000 \
  --dump target/proofs/$tag > runs/$tag.jsonl 2> runs/$tag-time.txt
echo "$tag $(grep -E 'Maximum resident|Elapsed' runs/$tag-time.txt | tr -s ' ')"
target/release/pqzh_security --whir --ext 5 --rate 3 --mask-rate 4 > runs/$tag-bits.jsonl
PQZH_WHIR=3,4,16,128 PQZH_PROOFS=target/proofs/$tag node wasm/run_wasm.mjs 0 100 10 0 0 1 100000000 1 > runs/$tag-wasm.jsonl || echo "wasm failed: $?"
echo done
