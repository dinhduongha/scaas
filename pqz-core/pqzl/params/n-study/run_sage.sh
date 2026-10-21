#!/bin/sh
# Plan 5h Task 7c: run one n-study Sage script in the pinned image with the pinned tools mounted read-only
# (/lk leaky-LWE-Estimator 0a9caf8, /le lattice-estimator 53da598, /lz/third_party LaZer 3330e48, /p this directory,
# /params the parent params/ directory for LaZer's codegen):
#   scripts/capped pqz-core/pqzl/params/n-study/run_sage.sh <tools dir with lk, le, lz> <script> [args] > <log>
#   e.g. ... run_sage.sh $T screen.sage > screen.txt;  ROWS=0,1 ... (env ROWS, MEM, CPUS pass through)
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LK_PIN=0a9caf8bf0f80097724e0c6147194c52c6b90f86
LE_PIN=53da5982597709ba0fdf94ea37a84d822310fd84
LZ_PIN=3330e487228f633eceb322807b13a596b516770f
T=$(cd "$1" && pwd)
S=$2
shift 2
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(git -C "$T/lk" rev-parse HEAD)" = $LK_PIN ] || { echo "lk must be at $LK_PIN" >&2; exit 1; }
[ "$(git -C "$T/le" rev-parse HEAD)" = $LE_PIN ] || { echo "le must be at $LE_PIN" >&2; exit 1; }
[ "$(git -C "$T/lz" rev-parse HEAD)" = $LZ_PIN ] || { echo "lz must be at $LZ_PIN" >&2; exit 1; }
exec docker run --rm --network none --memory "${MEM:-5g}" --cpus "${CPUS:-2}" -e PYTHONPATH=/le -e LE_COMMIT=$LE_PIN \
  -e LK_COMMIT=$LK_PIN -e PYTHONUNBUFFERED=1 -e ROWS="${ROWS:-}" -v "$T/lk":/lk:ro -v "$T/le":/le:ro -v "$T/lz/third_party":/lz/third_party:ro \
  -v "$HERE":/p:ro -v "$HERE/..":/params:ro --entrypoint /bin/sh "$IMG" -c \
  "mkdir -p /tmp/w && cp -r /params/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cp /p/*.sage /tmp/w/ &&
   cd /tmp/w/codegen && sage /tmp/w/$S $*"
