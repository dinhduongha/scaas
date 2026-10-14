#!/bin/sh
# P6e Task 9 round (D3 id, exact length bound, prover retry, D5 limits; docs/research/pqzh-ligero.md §13).
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/ligero/runs/limits.sh <tag>      (e.g. l11; l10 failed: the bound capped at 262,144 B broke the proven-without-radix-431 reference preset)
# 1. re-export the EVM fixtures (statements now carry the D3 id)  2. cargo test (incl. the fixtures)
# 3. the production build: --no-default-features lib + unit tests  4. native bench, proven, 5 proofs per relation
# (sizes vs the bound)  5. xcheck (all five, bytes vs C, then pqz_kat.py)  6. forge test of the Solidity verifier.
# No wasm32 run: the verifier changed by an O(1) length gate and a 32-byte id compare only.
set -u
cd "$(dirname "$0")/.."
tag=${1:-l11}
cargo run --release --offline --quiet --bin ligero_export -- ../../../smartcontracts/evm/test/vectors/pqzh-ligero proven conj johnson \
  > runs/$tag-export.jsonl || exit 1
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
cargo test --release --offline --no-default-features --lib > runs/$tag-nobench.txt 2>&1 || exit 1
runs/bench.sh $tag-proven --rel all --regime proven --r431 1 --np 5 --nv 10 --nadv 4 || exit 1
../xcheck/ligero.sh > runs/$tag-xcheck.txt 2>&1 || exit 1
runs/forge.sh $tag
