#!/bin/sh
# Plan 5h Task 7: enc16k.sage in the pinned Sage image:
#   scripts/capped pqz-core/pqzl/params/p16k/run_enc16k.sh <lattice-estimator 53da598> > pqz-core/pqzl/params/p16k/enc-16k.txt
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LE=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(git -C "$LE" rev-parse HEAD)" = 53da5982597709ba0fdf94ea37a84d822310fd84 ] || { echo "estimator must be at 53da598" >&2; exit 1; }
exec docker run --rm --network none --memory 3g --cpus 2 -e LE_COMMIT=53da598 -v "$LE":/le:ro -v "$HERE":/p:ro \
  --entrypoint /bin/sh "$IMG" -c "mkdir -p /tmp/w && cp /p/enc16k.sage /tmp/w/ && cd /le && sage /tmp/w/enc16k.sage"
