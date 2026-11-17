#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge, owner ruling 2026-11-06 (admin-written registry slot): each mutant of adminslot_mutants.py, one at a time on a clean
# src, the registry suites run (test/as/Registry*), src restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_adminslot_mutants.sh
# The fix is not yet committed when this runs: the registry source is copied aside and copied back (no git checkout).
# ONLY="<names>" reruns a subset. Writes ../2026-11-04-ua-mtx-merge-adminslot-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-adminslot-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
src=src/regulated/ComplianceRegistry.sol
cp "$src" "$here/.adminslot.orig"
trap 'cp "$here/.adminslot.orig" "$src"; rm -f "$here/.adminslot.orig"' EXIT
# ONLY="a b" runs those mutants alone; the table is written from every mutant's last log.
for m in ${ONLY:-$(python3 "$here/adminslot_mutants.py" --list)}; do
  python3 "$here/adminslot_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-adminslot-$m.rc.log"; continue; }
  ../../scripts/capped forge test --match-path 'test/as/Registry*.t.sol' \
    > "$here/mutant-adminslot-$m.log" 2>&1
  echo $? > "$here/mutant-adminslot-$m.rc.log"
  cp "$here/.adminslot.orig" "$src"
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/adminslot_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-adminslot-%s.log' % m)).read()
    # a FAIL reason may hold raw revert bytes, newlines included
    red = sorted({x for x in re.findall(r'^\[FAIL.*?\] (test\w+)\(\)', log, re.M | re.S)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-adminslot-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-adminslot-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
