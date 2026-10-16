#!/bin/sh
# P6-ANON: size the R_TXM sketches with the pinned lattice-estimator through ../e_s1_proof.sage (as ../run_e_s1.sh,
# which reads specs from params/ only): MSIS / MLWE beta >= 450 floors, codegen proof bytes, per spec.
#   scripts/capped pqz-core/pqzl/params/anon/run_sizing.sh <LaZer 3330e48> <lattice-estimator 53da598> [specs] > pqz-core/pqzl/params/anon/sizing-anon.txt
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LZ=$(cd "$1" && pwd)
LE=$(cd "$2" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
shift 2
[ $# -gt 0 ] || set -- txm1 txm2 txm4 txm8 txm16 txm8g2 txm16g4
SPECS=$(for r in "$@"; do printf ' /tmp/w/%s_params.sage' "$r"; done)
[ "$(git -C "$LZ" rev-parse HEAD)" = 3330e487228f633eceb322807b13a596b516770f ] || { echo "LaZer must be at 3330e48" >&2; exit 1; }
[ "$(git -C "$LE" rev-parse HEAD)" = 53da5982597709ba0fdf94ea37a84d822310fd84 ] || { echo "estimator must be at 53da598" >&2; exit 1; }
exec docker run --rm --network none -e LE_COMMIT=53da598 -v "$LZ/third_party":/lz/third_party:ro -v "$LE":/le:ro \
  -v "$HERE/..":/p:ro --entrypoint /bin/sh "$IMG" -c \
  "mkdir -p /tmp/w && cp -r /p/codegen /p/e_s1_proof.sage /p/anon/*.sage /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cd /tmp/w/codegen &&
   sage /tmp/w/e_s1_proof.sage$SPECS 2>/dev/null"
