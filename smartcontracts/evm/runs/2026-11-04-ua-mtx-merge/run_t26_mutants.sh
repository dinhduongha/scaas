#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T26: each mutant of t26_mutants.py, one at a time on a clean src, test/governance/PlusZero.t run, src restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t26_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t26-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t26-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- src || { echo "src is not clean" >&2; exit 2; }
for m in $(python3 "$here/t26_mutants.py" --list); do
  python3 "$here/t26_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t26-$m.rc.log"; continue; }
  ../../scripts/capped forge test --match-path test/governance/PlusZero.t.sol > "$here/mutant-t26-$m.log" 2>&1
  echo $? > "$here/mutant-t26-$m.rc.log"
  git checkout -- src
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t26_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t26-%s.log' % m)).read()
    red = sorted({x for x in re.findall(r'^\[FAIL[^\n]*?\] (\w+)\(\)', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t26-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t26-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
