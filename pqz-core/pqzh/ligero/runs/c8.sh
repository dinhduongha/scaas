#!/bin/sh
# Plan 5h Task 8c (PQZH at the parameter set's q): per-set test round, no timing. Run under the machine lock:
#   scripts/capped pqz-core/pqzh/ligero/runs/c8.sh <tag> <set>        (set: n2048-kmax1024 | n2304-kmax4096)
# 1. cargo test --release (bench, the set)  2. the production lib + unit tests (--no-default-features)
# 3. ligero_kat setup (proof keccak / FNV of every relation, seeds 0 and 1)  4. v3 only: the vectors replay and the
# comparison with the baseline runs/c8-base-kat.jsonl (byte identity)
set -u
cd "$(dirname "$0")/.."
tag=$1
set=$2
f="--features set-$set"
cargo test --release --offline $f -- --test-threads 1 > runs/$tag-tests.txt 2>&1 || { echo "tests FAILED: runs/$tag-tests.txt"; exit 1; }
cargo test --release --offline --no-default-features $f --lib > runs/$tag-nobench.txt 2>&1 || { echo "nobench FAILED"; exit 1; }
cargo build --release --offline $f --bin ligero_kat 2> runs/$tag-kat-build.txt || exit 1
target/release/ligero_kat setup > runs/$tag-kat.jsonl || exit 1
grep -c '"verify": true' runs/$tag-kat.jsonl
if [ "$set" = n2048-kmax1024 ]; then
  python3 -I runs/replay_vectors.py target/release/ligero_kat > runs/$tag-replay.txt || { echo "replay FAILED"; exit 1; }
  tail -1 runs/$tag-replay.txt
  python3 -I -c "
import json, sys
a = [json.loads(l) for l in open('runs/c8-base-kat.jsonl')]
b = [json.loads(l) for l in open('runs/$tag-kat.jsonl')]
k = lambda x: (x['rel'], x['seed'], x['proof_bytes'], x['keccak'], x['fnv'], x['verify'])
d = [x['rel'] for x, y in zip(a, b, strict=True) if k(x) != k(y)]
print('kat vs baseline:', 'identical (%d proofs)' % len(a) if not d else 'DIFF %s' % d)
sys.exit(1 if d else 0)" > runs/$tag-kat-vs-base.txt; cat runs/$tag-kat-vs-base.txt
fi
grep -E '^test result' runs/$tag-tests.txt runs/$tag-nobench.txt
