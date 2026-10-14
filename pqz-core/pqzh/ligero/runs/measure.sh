#!/bin/sh
# Every measurement of docs/research/pqzh-ligero.md §8, in order; run alone:
#   scripts/capped pqz-core/pqzh/ligero/runs/measure.sh <tag>      (e.g. l2)
# Native: 4 presets (proven / conjectured x radices with / without 431), 3 proofs, 100 honest verifies, 12 mutation
# kinds x 40 per relation (960 per preset). wasm32: build, then prove (2) / verify (50) / 12 x 4 mutations per
# relation. xcheck: statement / witness bytes against pqz-core's C setup (unchanged pqzh client).
set -eu
cd "$(dirname "$0")/.."
tag=${1:-l2}
for reg in proven conj; do
  for r in 1 0; do
    n=$tag-$reg-r431-$r
    runs/bench.sh $n --regime $reg --r431 $r --np 3 --nv 100 --nadv 40
  done
done
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown 2> ../runs/$tag-wasm-build.txt)
for reg in 1 0; do
  for r in 1 0; do
    nm=$( [ $reg = 1 ] && echo proven || echo conj )
    /usr/bin/time -v node wasm/run_wasm.mjs 2 50 4 $reg $r > runs/$tag-$nm-r431-$r-wasm.jsonl 2> runs/$tag-$nm-r431-$r-wasm-time.txt
  done
done
../xcheck/run.sh > runs/$tag-xcheck.txt 2>&1
