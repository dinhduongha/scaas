#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T1: each mutant of t1_mutants.py, one at a time on a clean src, test/merge run, src restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t1_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t1-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t1-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- src || { echo "src is not clean" >&2; exit 2; }
for m in $(python3 "$here/t1_mutants.py" --list); do
  python3 "$here/t1_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t1-$m.rc.log"; continue; }
  FOUNDRY_TEST=test/merge ../../scripts/capped forge test --match-path 'test/merge/*.t.sol' > "$here/mutant-t1-$m.log" 2>&1
  echo $? > "$here/mutant-t1-$m.rc.log"
  git checkout -- src
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t1_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t1-%s.log' % m)).read()
    red = sorted({x for x in re.findall(r'^\[FAIL[^\n]*?\] (\w+)\(\)', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t1-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t1-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
