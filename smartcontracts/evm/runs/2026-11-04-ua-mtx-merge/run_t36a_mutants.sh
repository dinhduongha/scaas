#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T36a (CTR-PQZ-23 change): the plan's two mutants of `PqzCore.SEALED`, one at a time, PqzCore.sol restored
# from a copy after each (the task's change may be uncommitted). From smartcontracts/evm, foreground:
#   runs/2026-11-04-ua-mtx-merge/run_t36a_mutants.sh
# Full output in git-ignored runs/2026-11-04-ua-mtx-merge-t36a-mutant-<name>.log; the table in ...-t36a-mutants.txt.
set -u
export PATH="$HOME/.foundry/bin:$PATH"
S=$(mktemp -d)
F=src/pqz/PqzCore.sol
cp "$F" "$S/PqzCore.sol.t36a"
T=runs/2026-11-04-ua-mtx-merge-t36a-mutants.txt
echo "mutant | test that went red | rc" > "$T"
run() { # name, python replacement
  local n=$1 new=$2
  python3 - "$F" "$new" <<'PY' || { echo "$n | anchor missing | 99" >> "$T"; return; }
import sys
p, new = sys.argv[1], sys.argv[2]
s = open(p).read()
old = '    uint256 internal constant SEALED = 2 + 40 * 1;'
assert s.count(old) == 1 and old != new
open(p, 'w').write(s.replace(old, new))
PY
  local L=runs/2026-11-04-ua-mtx-merge-t36a-mutant-$n.log
  ../../scripts/capped forge test --match-path 'test/{pqz/PqzTyped,pqz/PqzNormal,pqz/PqzShared,as/confidential/PqzReg*}.t.sol' > "$L" 2>&1
  local rc=$?
  cp "$S/PqzCore.sol.t36a" "$F"
  local red
  red=$(grep -oE '^\[FAIL[^]]*\] (test|invariant)[A-Za-z0-9_]+' "$L" | sed -E 's/.*\] //' | sort -u | paste -sd, - | sed 's/,/, /g')
  grep -q 'Compiler run failed' "$L" && red='COMPILE ERROR'
  echo "$n | ${red:-NONE (a finding)} | $rc" >> "$T"
}
run old-length-kept '    uint256 internal constant SEALED = 41;'
run op7-rule-m0 '    uint256 internal constant SEALED = 2 + 40 * 0;'
cmp "$F" "$S/PqzCore.sol.t36a" && echo restored && rm -r "$S"
cat "$T"
