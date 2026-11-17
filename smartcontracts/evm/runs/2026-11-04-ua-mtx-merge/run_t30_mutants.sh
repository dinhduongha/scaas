#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T30: each mutant of t30_mutants.py, one at a time on a clean src and script, the regulated Zether suites run
# (test/as/confidential/Zether*, GovDeploy), src and script restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t30_mutants.sh
# ONLY="<names>" reruns a subset. Writes ../2026-11-04-ua-mtx-merge-t30-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t30-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- src script || { echo "src or script is not clean" >&2; exit 2; }
# ONLY="a b" runs those mutants alone; the table is written from every mutant's last log.
for m in ${ONLY:-$(python3 "$here/t30_mutants.py" --list)}; do
  python3 "$here/t30_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t30-$m.rc.log"; continue; }
  ../../scripts/capped forge test --match-path 'test/{as/confidential/Zether*,governance/GovDeploy}.t.sol' \
    > "$here/mutant-t30-$m.log" 2>&1
  echo $? > "$here/mutant-t30-$m.rc.log"
  git checkout -- src script
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t30_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t30-%s.log' % m)).read()
    # a FAIL reason may hold raw revert bytes, newlines included
    red = sorted({x for x in re.findall(r'^\[FAIL.*?\] (test\w+)\(\)', log, re.M | re.S)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t30-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t30-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
