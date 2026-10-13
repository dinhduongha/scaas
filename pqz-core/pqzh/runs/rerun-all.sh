#!/bin/sh
# Every measurement of docs/research/pqzh-prototype.md, in order; run alone: scripts/capped pqz-core/pqzh/runs/rerun-all.sh
set -eu
cd "$(dirname "$0")/.."
cargo test --release --offline -- --test-threads 2 > runs/s1-all-tests.txt 2>&1
runs/bench.sh s2-native --np 10 --nv 200 --nadv 20
target/release/pqzh_bench --np 2 --sizes-only --blowup 3 --queries 38 > runs/s3-native-b8q38.jsonl
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/s3-wasm-build.txt)
node wasm/run_wasm.mjs 5 100 10 > runs/s3-wasm.jsonl
node wasm/run_wasm.mjs 2 20 2 3 38 0 1000000 > runs/s3-wasm-b8q38.jsonl
runs/bench.sh s4-native-zk --zk --np 10 --nv 200 --nadv 20 --max-proof 1000000
node wasm/run_wasm.mjs 3 50 4 0 0 1 1000000 > runs/s4-wasm-zk.jsonl
xcheck/run.sh > runs/s5-xcheck.txt
for e in 2 5; do
  target/release/pqzh_security --ext $e > runs/s6-model-ext$e.jsonl
  target/release/pqzh_security --ext $e --zk > runs/s6-model-ext$e-zk.jsonl
done
target/release/pqzh_security --batch-pow 24 --ood-pow 24 --lookup-pow 24 > runs/s6-model-ext2-grind24.jsonl
target/release/pqzh_security --ext 5 --measure > runs/s6-measure-ext5.jsonl
target/release/pqzh_security --ext 2 --target 100 --measure > runs/s6-measure-ext2-t100.jsonl
target/release/pqzh_security --ext 5 --pow 24 --measure > runs/s6-measure-ext5-pow24.jsonl
runs/bench.sh s7-ext5-b32-q21-pow24 --ext5 --blowup 5 --queries 21 --pow 24 --np 5 --nv 100 --nadv 10
