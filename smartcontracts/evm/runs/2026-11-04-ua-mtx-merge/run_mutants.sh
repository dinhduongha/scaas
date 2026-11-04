#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T0 of the ua*/mtx* merge plan: each mutant of mutants.py on M, one at a time, test/merge/MergedEntry.t.sol run, src
# restored from the M commit after each. From smartcontracts/evm on the scratch tree at M:
#   runs/2026-11-04-ua-mtx-merge/run_mutants.sh <M commit>
# Writes mutants.txt (mutant | the tests that went red | rc); full output in git-ignored mutant-<name>.log.
set -uo pipefail
m_commit=$1
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
for m in $(python3 "$here/mutants.py" --list); do
  python3 "$here/mutants.py" "$m" || { echo "$m: anchor missing" >&2; continue; }
  FOUNDRY_TEST=test/merge FOUNDRY_SCRIPT=test/merge ../../scripts/capped forge test \
    --match-path test/merge/MergedEntry.t.sol > "$here/mutant-$m.log" 2>&1
  echo $? > "$here/mutant-$m.rc"
  git checkout "$m_commit" -- src
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-%s.log' % m)).read()
    red = sorted({x for x in re.findall(r'^\[FAIL[^\n]*?\] (\w+)\(\)', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-%s.rc' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, 'mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
