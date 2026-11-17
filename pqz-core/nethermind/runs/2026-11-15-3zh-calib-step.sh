#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# 3zh-core gas calibration (owner 2026-11-15 "Calibration: ok", before group 2): one slice of a calibration run of the
# 26 n2304-kmax4096 rows (three-key ids PQZL v6 / PQZH v4) in the calib image pqz10, the fs3 Task 13 method
# (runs/2026-10-30-fs3-t13-calib-step.sh: calibrate.sh --keys a-b, n = 1000, --cold-only slice without rows).
#   scripts/capped pqz-core/nethermind/runs/2026-11-15-3zh-calib-step.sh <run> <a-b> [<cold processes>]
# Output runs/3zh-calib/run<run>-k<a-b>[-cold<n>].{log,json.log} (calibrate.sh's log with its host-load line and its
# engine json; git-ignored, like every full output since B9); a slice whose log exists is skipped (resume).
set -eu
cd "$(dirname "$0")/.."
R=$1 K=$2 C=${3:-0}
O=runs/3zh-calib/run$R-k$K$([ "$C" = 0 ] || echo "-cold$C")
[ ! -f "$O.log" ] || { echo "skip $O (done)"; exit 0; }
mkdir -p runs/3zh-calib
S=$(echo "--keys $K --cold $C" | tr -cd 0-9)
echo "$O: start $(date -u +%T)Z, load $(cut -d' ' -f1-3 /proc/loadavg)"
sh calibrate.sh "${CALIB_LABEL:-pqz10}" --keys "$K" --cold "$C" > /dev/null
F=$(ls runs/*-calib-ops"$S".txt)
mv "${F%.txt}-engine-pqz.json" "$O.json.log" && mv "$F" "$O.log"
echo "$O: done $(date -u +%T)Z, $(grep -c '^| [0-9]' "$O.log") rows; $(tail -1 "$O.log")"
