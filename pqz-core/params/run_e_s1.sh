#!/bin/sh
# Size the tbox ranks against the pinned estimator:
#   ./run_e_s1.sh <LaZer 3330e48 checkout> <lattice-estimator 53da598 checkout> > estimator-e-s1.txt
#   ./run_e_s1.sh <LaZer> <estimator> burn ds dr > estimator-e-s1-rel3.txt      (other specs: <name>_params.sage)
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LZ=$(cd "$1" && pwd)
LE=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
shift 2
[ $# -gt 0 ] || set -- reg tx
SPECS=$(for r in "$@"; do printf ' /tmp/w/%s_params.sage' "$r"; done)
[ "$(git -C "$LZ" rev-parse HEAD)" = 3330e487228f633eceb322807b13a596b516770f ] || { echo "LaZer must be at 3330e48" >&2; exit 1; }
[ "$(git -C "$LE" rev-parse HEAD)" = 53da5982597709ba0fdf94ea37a84d822310fd84 ] || { echo "estimator must be at 53da598" >&2; exit 1; }
exec docker run --rm --network none -e LE_COMMIT=53da598 -v "$LZ/third_party":/lz/third_party:ro -v "$LE":/le:ro \
  -v "$HERE":/p:ro --entrypoint /bin/sh "$IMG" -c \
  "mkdir -p /tmp/w && cp -r /p/codegen /p/*.sage /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cd /tmp/w/codegen &&
   sage /tmp/w/e_s1_proof.sage$SPECS 2>/dev/null"
