#!/bin/sh
# (a) non-hiding WHIR over Goldilocks^2 at targets its grinding allows (98 bits needs 17, runs/t12-whir-ext2-*-time.txt);
# (b) the same-regime non-ZK FRI over Goldilocks^5 in this configuration, for the WHIR comparison (one proof each).
# Run alone: scripts/capped runs/t13-whir-ext2-fri-plain.sh
set -u
cd "$(dirname "$0")/.."
run() { tag=$1; shift; /usr/bin/time -v target/release/pqzh_whir "$@" --np 3 --nv 100 --nadv 10 > runs/t13-whir-$tag.jsonl \
  2> runs/t13-whir-$tag-time.txt; echo "$tag rc=$?"; }
run ext2-r3-t96 --ext 2 --rate 3 --target 96 --pow 16
run ext2-r3-t100-pow20 --ext 2 --rate 3 --target 100 --pow 20
for c in "4 57 proven" "5 45 proven" "4 29 conj" "5 23 conj"; do
  set -- $c
  /usr/bin/time -v target/release/pqzh_bench --ext5 --blowup $1 --queries $2 --np 1 --sizes-only --max-proof 4000000 \
    > runs/t13-fri-plain5-$3-b$1-q$2.jsonl 2> runs/t13-fri-plain5-$3-b$1-q$2-time.txt; echo "fri plain5 $3 b$1 q$2 rc=$?"
done
