#!/bin/sh
# P6e Task 8 round (docs/research/pqzh-ligero.md §12): all five relations, hedged prover (D6), no Plonky3 dependency.
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/ligero/runs/rel5.sh <tag>      (e.g. l7)
# 1. cargo test (incl. 5 x 960 mutations, negative witnesses, the old EVM fixtures)  2. native bench, proven and
# conjectured (radix 431), 5 proofs, 100 honest verifies, 12 x 80 mutations per relation  3. wasm32 build, both
# presets, 2 proofs, 100 honest verifies, 12 x 4 mutations per relation  4. xcheck (all five, bytes vs C)
# 5. re-export the EVM fixtures (hedged proofs) and run the forge test.
set -u
cd "$(dirname "$0")/.."
tag=${1:-l7}
/usr/bin/time -v cargo test --release --offline -- --nocapture --test-threads 1 > runs/$tag-tests.txt 2>&1 || exit 1
for reg in proven conj; do
  runs/bench.sh $tag-$reg --rel all --regime $reg --r431 1 --np 5 --nv 100 --nadv 80 || exit 1
done
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt) || exit 1
for reg in 1 0; do
  nm=$( [ $reg = 1 ] && echo proven || echo conj )
  /usr/bin/time -v node wasm/run_wasm.mjs 2 100 4 $reg 1 0,1,2,3,4 > runs/$tag-$nm-wasm.jsonl 2> runs/$tag-$nm-wasm-time.txt || exit 1
done
../xcheck/ligero.sh > runs/$tag-xcheck.txt 2>&1 || exit 1
cargo run --release --offline --quiet --bin ligero_export -- ../../../smartcontracts/evm/test/vectors/pqzh-ligero proven conj johnson \
  > runs/$tag-export.jsonl || exit 1
runs/forge.sh $tag
