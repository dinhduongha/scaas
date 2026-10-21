#!/bin/sh
# Plan 5h Task 8c part 1b (owner 2026-10-22: set (a) preset B, fallback A): every round, no timing. Run under the lock:
#   scripts/capped pqz-core/pqzh/ligero/runs/c8b.sh
set -u
cd "$(dirname "$0")/.."
runs/c8.sh c8b-v3 n2048-kmax1024 && runs/c8-wasm.sh c8b-v3 n2048-kmax1024
runs/c8.sh c8b-a n2304-kmax4096 && runs/c8-wasm.sh c8b-a n2304-kmax4096
target/release/ligero_kat sizes > runs/c8b-a-sizes.jsonl
cargo test --release --offline --no-fail-fast --features set-n2304-kmax4096,fallback-retry -- --test-threads 1 > runs/c8b-fallback-tests.txt 2>&1 || echo "fallback tests FAILED"
grep -E '^test result|fallback_retry' runs/c8b-fallback-tests.txt
cargo build --release --offline --features spike-count,set-n2304-kmax4096 --bin spike_count 2> runs/c8b-count-build.txt && target/release/spike_count > runs/c8b-a-count.jsonl
cargo build --release --offline --features spike-count,set-n2304-kmax4096,fallback-retry --bin spike_count 2>> runs/c8b-count-build.txt && target/release/spike_count > runs/c8b-fallback-count.jsonl
runs/ct.sh c8b-a 4095 1 n2304-kmax4096
