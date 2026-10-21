#!/bin/sh
# Research spike A (plan 5h Task 8c spike, 2026-10-22): retries under a prover limit of MAX_PROOF_PQZH at set (a).
#   scripts/capped pqz-core/pqzh/ligero/runs/spike-a.sh <tag> <N per form> <threads> <monte carlo samples>
# -> runs/<tag>.jsonl (src/bin/spike_retry.rs; no timing: prover runs are counted)
set -u
cd "$(dirname "$0")/.."
echo "# $1: HEAD $(git rev-parse HEAD), diff sha256 $(git diff HEAD -- . | sha256sum | cut -c1-16)" > runs/$1.jsonl
cargo build --release --offline --features set-n2304-kmax4096 --bin spike_retry 2> runs/$1-build.txt || exit 1
target/release/spike_retry $2 $3 $4 >> runs/$1.jsonl
