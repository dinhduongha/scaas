#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T6: each mutant of t6_mutants.py, one at a time on a clean src, test/merge then the DEX and trade suites run, src restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t6_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t6-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t6-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- src || { echo "src is not clean" >&2; exit 2; }
for m in $(python3 "$here/t6_mutants.py" --list); do
  python3 "$here/t6_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t6-$m.rc.log"; continue; }
  FOUNDRY_TEST=test/merge ../../scripts/capped forge test --match-path 'test/merge/*.t.sol' > "$here/mutant-t6-$m.log" 2>&1
  rc=$?
  ../../scripts/capped forge test --match-path 'test/{v2/Dex*,v2/Trade,v2/MtxWrap,ua/UADex*,ua/UATrade*,metatx/TradeKat}.t.sol' >> "$here/mutant-t6-$m.log" 2>&1
  r2=$?
  echo "$rc$r2" > "$here/mutant-t6-$m.rc.log"
  git checkout -- src
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t6_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t6-%s.log' % m)).read()
    red = sorted({x for x in re.findall(r'^\[FAIL[^\n]*?\] (\w+)\(\)', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t6-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t6-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
