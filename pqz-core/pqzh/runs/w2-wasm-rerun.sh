#!/bin/sh
# wasm32 verify of the w2 proofs (target/proofs/w2-zkwhir5-r3, made by runs/w2-zkwhir5.sh), rerun after the 32-bit
# fix of whirpcs::claims (the first attempt trapped: runs/w2-zkwhir5.log). Run alone under scripts/capped.
set -eu
cd "$(dirname "$0")/.."
tag=w2-zkwhir5-r3
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown) 2> runs/$tag-wasm-build.txt
PQZH_WHIR=3,4,16,128 PQZH_PROOFS=target/proofs/$tag node wasm/run_wasm.mjs 0 100 10 0 0 1 100000000 1 > runs/$tag-wasm.jsonl
tail -1 runs/$tag-wasm.jsonl
