#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Plan 3h gate step: `script/pqz/at-set.sh <set> test` at the four sets, one test directory per forge run (FOUNDRY_TEST: test/pqz,
# test/ua, test/as/confidential; the plan's --match-path 'test/{ua,pqz,as/confidential}/*' split, no whole-tree compile under the
# 4 GB cap). at-set.sh rewrites src/pqz/PqzSet.sol and restores it: run in a work tree of its own, at a commit, one run at a time.
# Per-step logs and resume: a step whose log ends with a pass line is skipped (RERUN=1 runs it again).
#   scripts/capped sh smartcontracts/evm/runs/2026-11-08-ua-mtx-merge-3h/four-sets.sh <label> <log dir> [<set> ...]
# Logs: <log dir>/2026-11-08-ua-mtx-merge-3h-<label>-<set>-<dir with / as ->.log (git-ignored). Extra forge args: FORGE_ARGS.
set -u
EVM=$(cd "$(dirname "$0")/../.." && pwd)
L=$1
D=$2
shift 2
[ $# -gt 0 ] || set -- n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536
rc_all=0
for s in "$@"; do
  for d in test/pqz test/ua test/as/confidential; do
    n=$(echo "$d" | tr '/' '-')
    log=$D/2026-11-08-ua-mtx-merge-3h-$L-$s-$n.log
    if [ "${RERUN:-0}" != 1 ] && [ -f "$log" ] && grep -q "^Ran .* 0 failed" "$log"; then
      echo "$s $d: done ($(grep '^Ran ' "$log" | tail -1))"
      continue
    fi
    FOUNDRY_TEST=$d sh "$EVM/script/pqz/at-set.sh" "$s" test -j 2 ${FORGE_ARGS:-} > "$log" 2>&1
    rc=$?
    [ $rc -eq 0 ] || rc_all=1
    git -C "$EVM" diff --quiet HEAD -- src/pqz/PqzSet.sol || { echo "$s $d: PqzSet.sol not restored" >&2; exit 3; }
    echo "$s $d: rc $rc | $(grep '^Ran ' "$log" | tail -1)"
  done
done
exit $rc_all
