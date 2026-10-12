#!/bin/sh
# Rerun the PQZ E-S0 estimates: ./run.sh <lattice-estimator checkout> > estimator.txt   (then diff against git)
set -eu
IMG=sagemath/sagemath@sha256:4f5589eb6c565949a006f8665de2876b8414410daf5ac554f4434a15d4f3d528   # tag 10.7
PIN=53da5982597709ba0fdf94ea37a84d822310fd84
LE=$(cd "$1" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
[ "$(git -C "$LE" rev-parse HEAD)" = "$PIN" ] || { echo "lattice-estimator must be checked out at $PIN" >&2; exit 1; }
exec docker run --rm --network none -e PYTHONPATH=/le -e LE_COMMIT=$PIN \
  -v "$LE":/le:ro -v "$HERE":/p:ro -w /le "$IMG" sage -python -u /p/e_s0.py
