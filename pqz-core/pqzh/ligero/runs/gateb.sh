#!/bin/sh
# Gate-B round (P6e review of p6e-b1; docs/research/pqzh-ligero.md §12): run alone under the machine lock (so no other
# heavy job runs during the timings): scripts/capped pqz-core/pqzh/ligero/runs/gateb.sh <tag>      (e.g. l8)
# 1. cargo test (default features)  2. the production build: --no-default-features lib + unit tests
# 3. native seed-1 proofs of all five relations (fnv_last, to compare with the wasm32 run's: byte-identical proofs)
# 4. wasm32 build, proven preset, all five relations, 2 proofs, 1,000 honest verifies, 12 x 4 mutations each
# (controller decision: gate-B wasm32 p99 over >= 1,000 verifies per relation, under scripts/capped).
set -u
cd "$(dirname "$0")/.."
tag=${1:-l8}
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
cargo test --release --offline --no-default-features --lib > runs/$tag-nobench.txt 2>&1 || exit 1
runs/bench.sh $tag-native-fnv --rel all --regime proven --r431 1 --np 2 --nv 1 --nadv 1 || exit 1
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt) || exit 1
/usr/bin/time -v node wasm/run_wasm.mjs 2 1000 4 1 1 0,1,2,3,4 > runs/$tag-proven-wasm.jsonl 2> runs/$tag-proven-wasm-time.txt
