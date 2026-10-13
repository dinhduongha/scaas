#!/bin/sh
# Generate a tbox params header: ./run.sh <LaZer 3330e48 checkout> <params.sage> > <header.h>
# Runs the pinned Sage image with no network; LaZer's third_party/estimator.py (the old
# lwe-estimator the codegen loads for its MLWE root-Hermite check) comes from the checkout.
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
LZ=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
P=$(cd "$(dirname "$2")" && pwd)/$(basename "$2")
[ "$(git -C "$LZ" rev-parse HEAD)" = 3330e487228f633eceb322807b13a596b516770f ] || { echo "LaZer must be at 3330e48" >&2; exit 1; }
exec docker run --rm --network none -v "$LZ/third_party":/lz/third_party:ro -v "$HERE":/lz/codegen:ro \
  -v "$P":/lz/params.sage:ro --entrypoint /bin/sh "$IMG" -c \
  'mkdir -p /tmp/w && cp -r /lz/codegen /tmp/w/ && ln -s /lz/third_party /tmp/w/third_party && cd /tmp/w/codegen && sage lnp-tbox-codegen.sage /lz/params.sage'
