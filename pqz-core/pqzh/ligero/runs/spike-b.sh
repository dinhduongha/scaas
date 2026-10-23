#!/bin/sh
# SUPERSEDED (owner 2026-10-22): preset B (t = 120) is set (a)'s production preset and the feature spike-b is gone; this
# script is the record of the spike's t = 119 run (runs/spike-b-*). A set (a) round today: runs/c8.sh <tag> n2304-kmax4096.
# Research spike B (plan 5h Task 8c spike, 2026-10-22): set (a) with the radices 7 / 17 and the preset n 45,752,
# k 952, t 119 (feature spike-b). No timing. scripts/capped pqz-core/pqzh/ligero/runs/spike-b.sh <tag>
# 1. tests 2. production lib tests 3. ligero_kat setup / sizes 4. native = wasm32 (wasm/fnv_wasm.mjs) 5. base-field
# product counts at this preset and at THE preset (src/bin/spike_count.rs)
set -u
cd "$(dirname "$0")/.."
t=$1
F=set-n2304-kmax4096,spike-b
echo "# $t: HEAD $(git rev-parse HEAD), diff sha256 $(git diff HEAD -- . | sha256sum | cut -c1-16)" > runs/$t-head.txt
cargo test --release --offline --features $F -- --test-threads 1 > runs/$t-tests.txt 2>&1 || echo "tests FAILED"
cargo test --release --offline --no-default-features --features $F --lib > runs/$t-nobench.txt 2>&1 || echo "nobench FAILED"
grep -E '^test result' runs/$t-tests.txt runs/$t-nobench.txt
cargo build --release --offline --features $F --bin ligero_kat 2> runs/$t-kat-build.txt || exit 1
target/release/ligero_kat setup > runs/$t-kat.jsonl
target/release/ligero_kat sizes > runs/$t-sizes.jsonl
echo "honest proofs verified: $(grep -c '"verify": true' runs/$t-kat.jsonl) / $(grep -c . runs/$t-kat.jsonl)"
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown --features set-n2304-kmax4096,spike-b 2> ../runs/$t-wasm-build.txt) || { echo "wasm build FAILED"; exit 1; }
node wasm/fnv_wasm.mjs n2304-kmax4096 > runs/$t-wasm.jsonl
python3 -I -c "
import json
n = [json.loads(l) for l in open('runs/$t-kat.jsonl')]
w = [json.loads(l) for l in open('runs/$t-wasm.jsonl')]
wp = [x for x in w if 'seed' in x]
k = lambda x: (x['seed'], x['proof_bytes'], x['fnv'], x['verify'])
d = [a['rel'] for a, b in zip(n, wp, strict=True) if k(a) != k(b)]
mut = [x for x in w if 'mutations' in x]
print('native = wasm32 (spike b):', 'identical (%d proofs)' % len(n) if not d else 'DIFF %s' % d,
      '; mutations rejected %d / %d' % (sum(x['mutations'] - x['accepted'] for x in mut), sum(x['mutations'] for x in mut)))" | tee runs/$t-native-vs-wasm.txt
cargo build --release --offline --features spike-count,$F --bin spike_count 2>> runs/$t-kat-build.txt && target/release/spike_count > runs/$t-count.jsonl
cargo build --release --offline --features spike-count,set-n2304-kmax4096 --bin spike_count 2>> runs/$t-kat-build.txt && target/release/spike_count > runs/$t-count-thepreset.jsonl
echo done
