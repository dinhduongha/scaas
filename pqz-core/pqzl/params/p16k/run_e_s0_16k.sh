#!/bin/sh
# Plan 5h Task 7: e_s0_16k.py in the pinned Sage image (numpy pinned with it):
#   scripts/capped pqz-core/pqzl/params/p16k/run_e_s0_16k.sh > pqz-core/pqzl/params/p16k/e-s0-16k.txt
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
HERE=$(cd "$(dirname "$0")" && pwd)
exec docker run --rm --network none --memory 1g --cpus 1 -v "$HERE":/p:ro --entrypoint sage "$IMG" -python -u /p/e_s0_16k.py
