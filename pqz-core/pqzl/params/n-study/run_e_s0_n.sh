#!/bin/sh
# Plan 5h Task 7c: e_s0_n.py (../p16k/e_s0_16k.py for one cell) in the pinned Sage image (numpy pinned with it):
#   N=<n> K_MAX=<K> Q=<q> scripts/capped pqz-core/pqzl/params/n-study/run_e_s0_n.sh >> pqz-core/pqzl/params/n-study/e-s0-n.txt
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
HERE=$(cd "$(dirname "$0")" && pwd)
exec docker run --rm --network none --memory 1g --cpus 1 -e N="$N" -e K_MAX="$K_MAX" -e Q="$Q" -v "$HERE":/p:ro \
  --entrypoint sage "$IMG" -python -u -I /p/e_s0_n.py
