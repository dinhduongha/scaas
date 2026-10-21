#!/bin/sh
# Plan 5h Task 8b: e_s0_set.py (e_s0 per relation of one parameter set) in the pinned Sage image (numpy pinned with it):
#   SET=<set> scripts/capped pqz-core/params/sets/run_e_s0_set.sh > pqz-core/params/sets/<set>/e-s0.txt
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
HERE=$(cd "$(dirname "$0")" && pwd)
exec docker run --rm --network none --memory 1g --cpus 1 -e SET="$SET" -v "$HERE":/p:ro \
  --entrypoint sage "$IMG" -python -u -I /p/e_s0_set.py
