#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# 3zh-core calibration: both runs, every slice of runs/2026-11-15-3zh-calib-step.sh in order (the fs3 Task 13 slices);
# each slice under scripts/capped; resumes (done slices skipped).
set -eu
cd "$(dirname "$0")/../../.."
for R in 1 2; do
  for K in 0-1 2-3 4-11 12-17 18-20 21-23 24-25; do scripts/capped sh pqz-core/nethermind/runs/2026-11-15-3zh-calib-step.sh $R $K; done
  scripts/capped sh pqz-core/nethermind/runs/2026-11-15-3zh-calib-step.sh $R 1-0 200
done
echo "3zh-calib: all slices done $(date -u +%T)Z"
