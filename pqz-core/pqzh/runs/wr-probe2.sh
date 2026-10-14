#!/bin/sh
# PROBE (pqzh-zk-whir.md §10.3): the R_TX proof of runs/wr-probe.sh again with debug-level tracing spans, to split the
# 164 s "compute quotient" span (raw log 255 MB, kept only as its summary). Run alone: scripts/capped runs/wr-probe2.sh
set -eu
cd "$(dirname "$0")/wr-probe"
export CARGO_TARGET_DIR="$PWD/../../target"
cargo build --release --offline >> ../wr-probe-build.txt 2>&1
WR_LEVEL=debug $CARGO_TARGET_DIR/release/wr-probe tx > ../wr-tx2.jsonl 2> ../wr-tx2-debug-spans.txt
python3 ../wr-spans.py ../wr-tx2-debug-spans.txt > ../wr-tx2-debug-summary.txt && rm ../wr-tx2-debug-spans.txt  # 255 MB raw
echo done
