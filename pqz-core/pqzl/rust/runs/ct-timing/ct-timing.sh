#!/bin/sh
# Fix E timing: the Rust crate before (BASE, 0dc869d) and after (NEW, pqzl-fs3 with fix E), same machine, same
# session, steps interleaved base / new so drift hits both. Relations: the six forms (63) and two R_TXM shapes.
# Usage (one capped job, idle host): scripts/capped sh ct-timing.sh <BASE rust dir> <NEW rust dir> <out dir>
set -u
BASE=$1 NEW=$2 OUT=$3
mkdir -p "$OUT"
M=${M:-$((63 | (64 << 3) | (64 << 7)))}
NP=${NP:-10} NV=${NV:-50} NF=${NF:-200} NPW=${NPW:-3} NVW=${NVW:-10} NFW=${NFW:-50}
{
  echo "base $(git -C "$BASE" rev-parse --short HEAD)  new $(git -C "$NEW" rev-parse --short HEAD) $(git -C "$NEW" diff --quiet || echo +dirty)"
  echo "rust $(rustc --version); node $(node --version); samples NP=$NP NV=$NV NF=$NF NPW=$NPW NVW=$NVW NFW=$NFW M=$M"
  uptime
} > "$OUT/env.txt"
for side in base new; do : > "$OUT/$side-native-generic.jsonl"; : > "$OUT/$side-native-fast.jsonl"
  : > "$OUT/$side-wasm-generic.jsonl"; : > "$OUT/$side-wasm-fast.jsonl"; done
for round in 1 2; do
  for side in base new; do
    d=$BASE; [ $side = new ] && d=$NEW
    (cd "$d" && ./target/release/bench $NP $NV $M) >> "$OUT/$side-native-generic.jsonl"
    (cd "$d" && PQZ_VERIFY=fast ./target/release/bench 2 $NF $M) >> "$OUT/$side-native-fast.jsonl"
  done
  for side in base new; do
    d=$BASE; [ $side = new ] && d=$NEW
    (cd "$d" && node wasm/run_wasm.mjs $NPW $NVW $M) >> "$OUT/$side-wasm-generic.jsonl"
    (cd "$d" && PQZ_VERIFY=fast node wasm/run_wasm.mjs 1 $NFW $M) >> "$OUT/$side-wasm-fast.jsonl"
  done
done
uptime >> "$OUT/env.txt"
