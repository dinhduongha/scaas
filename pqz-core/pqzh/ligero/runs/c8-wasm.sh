#!/bin/sh
# Plan 5h Task 8c: native = wasm32 per set, no timing. scripts/capped pqz-core/pqzh/ligero/runs/c8-wasm.sh <tag> <set>
# (after runs/c8.sh <tag> <set>, which wrote runs/<tag>-kat.jsonl): builds the wasm32 module of the set, proves every
# relation with seeds 0 and 1 in node (wasm/fnv_wasm.mjs), verifies, rejects 12 mutations each, and compares the proof
# bytes / FNV / verdicts with the native lines.
set -u
cd "$(dirname "$0")/.."
tag=$1
set=$2
(cd wasm && cargo build --release --offline --target wasm32-unknown-unknown --features set-$set 2> ../runs/$tag-wasm-build.txt) || { echo "wasm build FAILED"; exit 1; }
node wasm/fnv_wasm.mjs $set > runs/$tag-wasm.jsonl || { echo "wasm run FAILED: runs/$tag-wasm.jsonl"; exit 1; }
python3 -I -c "
import json, sys
n = [json.loads(l) for l in open('runs/$tag-kat.jsonl')]
w = [json.loads(l) for l in open('runs/$tag-wasm.jsonl')]
wp = [x for x in w if 'seed' in x]
k = lambda x: (x['seed'], x['proof_bytes'], x['fnv'], x['verify'])
d = [a['rel'] for a, b in zip(n, wp, strict=True) if k(a) != k(b)]
mut = [x for x in w if 'mutations' in x]
print('native = wasm32 (%s):' % '$set', 'identical (%d proofs, all verify)' % len(n) if not d else 'DIFF %s' % d,
      '; mutations rejected %d / %d' % (sum(x['mutations'] - x['accepted'] for x in mut), sum(x['mutations'] for x in mut)))
sys.exit(1 if d or any(x['accepted'] for x in mut) else 0)" | tee runs/$tag-native-vs-wasm.txt
