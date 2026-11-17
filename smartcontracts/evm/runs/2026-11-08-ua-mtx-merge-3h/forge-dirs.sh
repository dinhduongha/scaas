#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan 3h (T58-T61) gate step, copied from T66a's: `forge test` one test directory at a time (FOUNDRY_TEST=<dir>, its own out/ and cache/), so no single solc run
# holds the whole tree (a whole-tree compile was OOM-killed at the 4 GB `scripts/capped` cap on 2026-11-08). Per-step logs and resume:
# a directory whose log ends with a pass line is skipped (RERUN=1 runs it again).
#   scripts/capped sh smartcontracts/evm/runs/2026-11-08-ua-mtx-merge-3h/forge-dirs.sh <label> <dir> [<dir> ...]
# `<dir>` is relative to smartcontracts/evm (test/ua, test/pqz, ...); "top" = the files directly in test/ (sparse: their own imports).
# Logs: runs/2026-11-08-ua-mtx-merge-3h-<label>-<dir with / as ->.log (git-ignored). Extra forge args: FORGE_ARGS.
set -u
EVM=$(cd "$(dirname "$0")/../.." && pwd)
cd "$EVM"
L=$1
shift
rc_all=0
for d in "$@"; do
  n=$(echo "$d" | tr '/' '-')
  log=runs/2026-11-08-ua-mtx-merge-3h-$L-$n.log
  if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && grep -q "^Ran .* 0 failed" "$log"; then
    echo "$d: done ($(grep '^Ran ' "$log" | tail -1))"
    continue
  fi
  if [ "$d" = top ]; then
    # the files directly in test/ from a copy in the git-ignored dist/ (their imports are ../src and forge-std only): sparse
    # mode with --match-path 'test/*.t.sol' compiled 460 files and was OOM-killed at the 4 GB cap (3h T58, 2026-11-08)
    rm -rf dist && mkdir dist && cp test/*.t.sol dist/
    FOUNDRY_TEST=dist FOUNDRY_OUT=out/3h-$n FOUNDRY_CACHE_PATH=cache/3h-$n \
      ~/.foundry/bin/forge test -j 2 ${FORGE_ARGS:-} > "$log" 2>&1
    rc=$?
    rm -rf dist
    [ $rc -eq 0 ] || rc_all=1
    echo "$d: rc $rc | $(grep '^Ran ' "$log" | tail -1)"
    continue
  else
    FOUNDRY_TEST=$d FOUNDRY_OUT=out/3h-$n FOUNDRY_CACHE_PATH=cache/3h-$n \
      ~/.foundry/bin/forge test -j 2 ${FORGE_ARGS:-} > "$log" 2>&1
  fi
  rc=$?
  [ $rc -eq 0 ] || rc_all=1
  echo "$d: rc $rc | $(grep '^Ran ' "$log" | tail -1)"
done
exit $rc_all
