#!/bin/sh
# Plonky3 0.9.0-rc.1 (upgrade commit): tests, default bench, ZK + Goldilocks^5 conjectured blowup 16 bench, xcheck.
# Run alone: scripts/capped runs/t9-p3-0.9.sh
set -u
cd "$(dirname "$0")/.."
cargo test --release -- --test-threads 2 > runs/t9-p3-0.9-tests.txt 2>&1; echo "tests rc=$?"
runs/bench.sh t9-p3-0.9-default --np 5 --nv 100 --nadv 10
/usr/bin/time -v target/release/pqzh_bench --zk --ext5 --blowup 4 --queries 29 --np 3 --nv 100 --nadv 10 --max-proof 4000000 \
  > runs/t9-p3-0.9-zk5-conj-b4-q29.jsonl 2> runs/t9-p3-0.9-zk5-conj-b4-q29-time.txt; echo "zk5 rc=$?"
target/release/pqzh_security --ext 5 --zk > runs/t9-p3-0.9-model-ext5-zk.jsonl 2>&1; echo "security rc=$?"
