#!/bin/sh
# Per-directory forge gate, resumable: a step with a .done marker is skipped. Logs git-ignored (*.log).
# usage (from smartcontracts/evm): sh runs/2026-11-13-fix3-chainuid/gate.sh <dir-or-glob>...
R=${R:-runs/2026-11-13-fix3-chainuid}; mkdir -p "$R"
for d in "$@"; do
  n=$(echo "$d" | tr '/*{},' '_____')
  [ -f "$R/gate-$n.done.log" ] && { echo "skip $d"; continue; }
  echo "start $d"
  CAPPED_SLOTS=3 ../../scripts/capped forge test -j 1 --match-path "$d" > "$R/gate-$n.log" 2>&1
  rc=$?
  res=$(grep -E "^Ran [0-9]+ test suites" "$R/gate-$n.log" | tail -1)
  echo "$d | rc $rc | $res"
  [ $rc = 0 ] && echo "$d | $res" > "$R/gate-$n.done.log"
done
