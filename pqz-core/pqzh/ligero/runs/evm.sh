#!/bin/sh
# EVM-verifier round (docs/research/pqzh-ligero.md §11), run alone: scripts/capped pqz-core/pqzh/ligero/runs/evm.sh <tag>
# 1. Rust tests (with the Johnson preset)  2. Johnson preset native bench + wasm32 (reference, owner 2026-10-14 (b))
# 3. fixtures for the forge test          4. forge test of the Solidity verifier (gas, mutations, negative witnesses)
set -u
cd "$(dirname "$0")/.."
tag=${1:-l4}
VEC=../../../smartcontracts/evm/test/vectors/pqzh-ligero
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
runs/bench.sh $tag-johnson --regime johnson --np 3 --nv 100 --nadv 40 || exit 1
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt) || exit 1
/usr/bin/time -v node wasm/run_wasm.mjs 2 50 4 2 1 > runs/$tag-johnson-wasm.jsonl 2> runs/$tag-johnson-wasm-time.txt
mkdir -p $VEC
cargo run --release --offline --quiet --bin ligero_export -- $VEC proven conj johnson > runs/$tag-export.jsonl || exit 1
cd ../../../smartcontracts/evm
FOUNDRY_CODE_SIZE_LIMIT=65536 /usr/bin/time -v forge test --match-contract LigeroTest -vv --gas-limit 9000000000000000000 \
  > ../../pqz-core/pqzh/ligero/runs/$tag-forge.txt 2>&1
echo forge rc=$?
