#!/bin/sh
# Native PQZH-Ligero bench: runs/bench.sh <tag> [ligero_bench args]  ->  runs/<tag>.jsonl, runs/<tag>-time.txt (max RSS)
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/ligero/runs/bench.sh l1-proven --regime proven
set -eu
cd "$(dirname "$0")/.."
tag=$1
shift
cargo build --release --offline --bin ligero_bench 2> runs/$tag-build.txt
/usr/bin/time -v target/release/ligero_bench "$@" > runs/$tag.jsonl 2> runs/$tag-time.txt
grep -E "Maximum resident|Elapsed" runs/$tag-time.txt
