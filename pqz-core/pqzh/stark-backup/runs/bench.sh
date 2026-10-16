#!/bin/sh
# Native PQZH bench: runs/bench.sh <tag> [pqzh_bench args]  ->  runs/<tag>.jsonl, runs/<tag>-time.txt (max RSS)
# Run alone under the machine lock: scripts/capped pqz-core/pqzh/runs/bench.sh f1 --np 10 --nv 200 --nadv 20
set -eu
cd "$(dirname "$0")/.."
tag=$1
shift
cargo build --release --offline --bin pqzh_bench 2> runs/$tag-build.txt
/usr/bin/time -v target/release/pqzh_bench "$@" > runs/$tag.jsonl 2> runs/$tag-time.txt
grep -E "Maximum resident|Elapsed" runs/$tag-time.txt
