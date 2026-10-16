#!/bin/sh
# PROBE (pqzh-zk-whir.md §10): build runs/wr-probe, then (1) p3-whir's hiding base-case security report, (2) one ZK WHIR
# R_TX proof with tracing span timings and a field-by-field byte breakdown, (3) HidingWhirPcs micro-timings on a random
# 2^22 / 2^21 polynomial. Run alone: scripts/capped runs/wr-probe.sh
set -eu
cd "$(dirname "$0")/wr-probe"
export CARGO_TARGET_DIR="$PWD/../../target"
cargo build --release --offline > ../wr-probe-build.txt 2>&1
B=$CARGO_TARGET_DIR/release/wr-probe
$B report > ../wr-report.txt
/usr/bin/time -v $B tx > ../wr-tx.jsonl 2> ../wr-tx-spans.txt
$B micro 22 1 24 60 > ../wr-micro.jsonl
$B micro 21 24 >> ../wr-micro.jsonl
echo done
