#!/bin/sh
# fs3 Task 13 phase B: one slice of a calibration run. The shell tool moves a command to the background after 3 minutes
# and the controller wants foreground steps only, so each run of calibrate.sh is split into row slices (Calibrate
# --keys a-b, same method, n = 1000 per set) plus --cold-only slices (no row):
#   scripts/capped pqz-core/nethermind/runs/2026-10-30-fs3-t13-calib-step.sh <run> <a-b> [<cold processes>]
# Outputs runs/fs3-t13-calib/run<run>-k<a-b>[-cold<n>].{txt,json} (calibrate.sh's log, with its host-load line, and its
# engine json); a slice whose log exists is skipped (resume). runs/2026-10-30-fs3-t13-rows.py merges the slices.
# CALIB_LABEL=pqz6c (option (c), 2026-10-31): the calib image with the stable ecMul baseline; default pqz6.
set -eu
cd "$(dirname "$0")/.."
R=$1 K=$2 C=${3:-0}
O=runs/fs3-t13-calib/run$R-k$K$([ "$C" = 0 ] || echo "-cold$C")
[ ! -f "$O.txt" ] || { echo "skip $O (done)"; exit 0; }
mkdir -p runs/fs3-t13-calib
S=$(echo "--keys $K --cold $C" | tr -cd 0-9)   # calibrate.sh names its files <date>-calib-ops<the digits of its args>
sh calibrate.sh "${CALIB_LABEL:-pqz6}" --keys "$K" --cold "$C" > /dev/null
F=$(ls runs/*-calib-ops"$S".txt)
mv "${F%.txt}-engine-pqz.json" "$O.json" && mv "$F" "$O.txt"
echo "$O: $(grep -c '^| [0-9]' "$O.txt") rows; $(tail -1 "$O.txt")"
