#!/bin/sh
# PROBE (pqzh-zk-whir.md §10.3): R_TX again after WhirUniPcs overrides build_periodic_lde_table (DFT, as p3-fri),
# with the deterministic masks of runs/wr-probe.sh ([1; 32]); proof bytes and verification must be unchanged.
# Run alone: scripts/capped runs/wr-probe3.sh
set -eu
cd "$(dirname "$0")/wr-probe"
export CARGO_TARGET_DIR="$PWD/../../target"
cargo build --release --offline > ../wr-probe3-build.txt 2>&1
/usr/bin/time -v $CARGO_TARGET_DIR/release/wr-probe tx > ../wr-tx3.jsonl 2> ../wr-tx3-spans.txt
(cd ../.. && cargo test --release --offline --lib whirpcs) > ../wr-probe3-tests.txt 2>&1
echo done
