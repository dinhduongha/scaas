#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T11: each mutant of t11_mutants.py, one at a time on a clean src/evm.js, clientkeys' typed-ops.test.js and
# evm.test.js run (vectors fixed), src/evm.js restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t11_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t11-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t11-<name>.log beside this script. A mutant whose test file fails to load is reported LOAD ERROR (it kills nothing).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
ck="$here/../../../../clients/clientkeys"
capped="$here/../../../../scripts/capped"
cd "$ck" || exit 2
git diff --quiet -- src/evm.js || { echo "src/evm.js is not clean" >&2; exit 2; }
for m in $(python3 "$here/t11_mutants.py" --list); do
  python3 "$here/t11_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t11-$m.rc.log"; git checkout -- src/evm.js; continue; }
  "$capped" node --test test/typed-ops.test.js test/evm.test.js > "$here/mutant-t11-$m.log" 2>&1
  echo $? > "$here/mutant-t11-$m.rc.log"
  git checkout -- src/evm.js
done
git diff --quiet -- src/evm.js || { echo "src/evm.js not restored" >&2; exit 3; }
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t11_mutants.py --list' % here).read().split()
rows = ['mutant | tests that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t11-%s.log' % m)).read()
    red = sorted({x.strip() for x in re.findall(r'^\s*✖ (.*?) \([\d.]+m?s\)$', log, re.M)})
    if any(r.startswith('test/') for r in red) or 'SyntaxError' in log:
        red = ['LOAD ERROR']
    rc = open(os.path.join(here, 'mutant-t11-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, '; '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t11-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
