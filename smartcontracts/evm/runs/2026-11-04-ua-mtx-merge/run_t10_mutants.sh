#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T10: each mutant of t10_mutants.py, one at a time on a clean script, the deploy suites run, script restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t10_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t10-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t10-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- script || { echo "script is not clean" >&2; exit 2; }
for m in $(python3 "$here/t10_mutants.py" --list); do
  python3 "$here/t10_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t10-$m.rc.log"; continue; }
  ../../scripts/capped forge test --match-path 'test/{governance/GovDeploy,ua/UADeploy,zether/ZetherDeploy,governance/CodeCeiling}.t.sol' > "$here/mutant-t10-$m.log" 2>&1
  echo $? > "$here/mutant-t10-$m.rc.log"
  git checkout -- script
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t10_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t10-%s.log' % m)).read()
    red = sorted({x for x in re.findall(r'^\[FAIL[^\n]*?\] (\w+)\(\)', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t10-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t10-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
