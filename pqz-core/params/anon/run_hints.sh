#!/bin/sh
# P6-ANON Task S1: DDGR20 perfect hints on R_TXM's shared (r, e1), per M and leg grouping (hints.sage):
#   git clone https://github.com/lducas/leaky-LWE-Estimator <lk> && git -C <lk> checkout 0a9caf8
#   scripts/capped pqz-core/params/anon/run_hints.sh <lk> <lattice-estimator 53da598> > pqz-core/params/anon/hints-anon.txt
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LK_PIN=0a9caf8bf0f80097724e0c6147194c52c6b90f86
LE_PIN=53da5982597709ba0fdf94ea37a84d822310fd84
LK=$(cd "$1" && pwd)
LE=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(git -C "$LK" rev-parse HEAD)" = $LK_PIN ] || { echo "leaky-LWE-Estimator must be at $LK_PIN" >&2; exit 1; }
[ "$(git -C "$LE" rev-parse HEAD)" = $LE_PIN ] || { echo "lattice-estimator must be at $LE_PIN" >&2; exit 1; }
exec docker run --rm --network none -e PYTHONPATH=/le -e LE_COMMIT=$LE_PIN -e LK_COMMIT=$LK_PIN -e SMOKE="${SMOKE:-}" \
  -v "$LK":/lk:ro -v "$LE":/le:ro -v "$HERE":/p:ro --entrypoint /bin/sh "$IMG" -c \
  "mkdir -p /tmp/w && cp /p/hints.sage /tmp/w/ && cd /lk/framework && sage /tmp/w/hints.sage"
