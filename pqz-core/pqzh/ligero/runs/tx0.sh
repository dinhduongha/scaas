#!/bin/sh
# P6e Task 8 round (docs/research/pqzh-ligero.md §14): R_TX0, the transfer without the auditor (op 1, 66,560 B).
# Run alone under the machine lock (so no other heavy job runs during the timings):
#   scripts/capped pqz-core/pqzh/ligero/runs/tx0.sh <tag>      (e.g. l14-tx0)
# 1. EVM fixtures re-exported (adds tx0-proven.*)  2. cargo test (6 x 960 mutations, negative witnesses, cross-form)
# 3. the production build: --no-default-features lib + unit tests  4. native bench, THE preset, all six forms: 5 proofs,
# 1,000 honest verifies, 12 x 80 mutations each  5. wasm32 build and run, all six forms (gate-B method): 2 proofs,
# 1,000 honest verifies, 12 x 4 mutations each  6. xcheck (six forms, bytes vs C, then pqz_kat.py)  7. forge test.
set -u
cd "$(dirname "$0")/.."
tag=${1:-l14-tx0}
cargo run --release --offline --quiet --bin ligero_export -- ../../../smartcontracts/evm/test/vectors/pqzh-ligero proven conj johnson \
  > runs/$tag-export.jsonl || exit 1
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
cargo test --release --offline --no-default-features --lib > runs/$tag-nobench.txt 2>&1 || exit 1
runs/bench.sh $tag-proven --rel all --regime proven --r431 1 --np 5 --nv 1000 --nadv 80 || exit 1
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt) || exit 1
/usr/bin/time -v node wasm/run_wasm.mjs 2 1000 4 1 1 0,1,2,3,4,5 > runs/$tag-proven-wasm.jsonl 2> runs/$tag-proven-wasm-time.txt || exit 1
../xcheck/ligero.sh > runs/$tag-xcheck.txt 2>&1 || exit 1
runs/forge.sh $tag
