#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T8: each mutant of t8_mutants.py, one at a time on a clean src, the Hedera suites and the other HIP-632 readers run, src restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t8_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t8-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t8-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- src || { echo "src is not clean" >&2; exit 2; }
for m in $(python3 "$here/t8_mutants.py" --list); do
  python3 "$here/t8_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t8-$m.rc.log"; continue; }
  ../../scripts/capped forge test --match-path 'test/{hedera/*,v2/Features,metatx/MtxCtx,wallet/MandateWalletMerged}.t.sol' > "$here/mutant-t8-$m.log" 2>&1
  echo $? > "$here/mutant-t8-$m.rc.log"
  git checkout -- src
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t8_mutants.py --list' % here).read().split()
rows = ['mutant | test that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t8-%s.log' % m)).read()
    red = sorted({x for x in re.findall(r'^\[FAIL[^\n]*?\] (\w+)\(\)', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t8-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t8-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
