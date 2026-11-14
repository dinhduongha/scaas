#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# TODO 3zd: one pass of the ML-DSA-87 gas calibration (owner 2026-11-15). The method of every earlier run: calibrate.sh in
# the calib image (docker --cpus 4 --memory 4g, n = 1000, t_ecMul = smallest of 5 medians after 2 s warm-up,
# gas = 1000 * ceil(6000 * p99 / t_ecMul / 1000), max with EIP-8355's base), with no PQZ row (--keys 1-0, as the
# fs3 Task 13 cold-only slices) and no cold self-test: the ML-DSA-44 / -65 / -87 lines only.
#   scripts/capped pqz-core/nethermind/runs/2026-11-15-mldsa87-calib-step.sh <pass>
# Output runs/mldsa87-calib/pass<pass>.log (calibrate.sh's log with its host-load line) and pass<pass>-engine-pqz.log
# (its engine json; git-ignored, like every full output since B9); a pass whose log exists is skipped (resume).
set -eu
cd "$(dirname "$0")/.."
P=${1:?pass number}
O=runs/mldsa87-calib/pass$P
[ ! -f "$O.log" ] || { echo "skip $O (done)"; exit 0; }
mkdir -p runs/mldsa87-calib
echo "pass $P: start $(date -u +%T)Z, load $(cut -d' ' -f1-3 /proc/loadavg)"
sh calibrate.sh "${CALIB_LABEL:-mldsa87}" --keys 1-0 --cold 0 > /dev/null
F=runs/$(date +%F)-calib-ops100
mv "$F-engine-pqz.json" "$O-engine-pqz.log" && mv "$F.txt" "$O.log"
grep -E '^t_ecMul|^ML-DSA-' "$O.log"
echo "pass $P: done $(date -u +%T)Z; $(tail -1 "$O.log")"
