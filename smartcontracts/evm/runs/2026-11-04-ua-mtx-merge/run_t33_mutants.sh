#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T33: each mutant of t33_mutants.py, one at a time on a clean script/, the T33 forge suites run (GovDeploy,
# LinkClosure) or, for an e2e-* mutant, `python3 -I script/pqz/e2e.py --self-test`; script/ restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t33_mutants.sh
# ONLY="<names>" reruns a subset. Writes ../2026-11-04-ua-mtx-merge-t33-mutants.txt (mutant | tests that went red | rc);
# full output in git-ignored mutant-t33-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
git diff --quiet -- src script || { echo "src or script is not clean (commit first)" >&2; exit 2; }
suites='test/{governance/GovDeploy,v2/LinkClosure}.t.sol'
for m in ${ONLY:-$(python3 "$here/t33_mutants.py" --list)}; do
  python3 "$here/t33_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t33-$m.rc.log"; continue; }
  case "$m" in
    e2e-*) python3 -I script/pqz/e2e.py --self-test > "$here/mutant-t33-$m.log" 2>&1 ;;
    *) ../../scripts/capped forge test --match-path "$suites" > "$here/mutant-t33-$m.log" 2>&1 ;;
  esac
  echo $? > "$here/mutant-t33-$m.rc.log"
  git checkout -- script
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
rows = ['mutant | test that went red | rc']
for m in os.popen('python3 %s/t33_mutants.py --list' % here).read().split():
    p = os.path.join(here, 'mutant-t33-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = open(p).read()
    red = sorted(set(re.findall(r'^\[FAIL.*?\] (test\w+)\(\)', log, re.M | re.S))
                 | {'self-test: ' + x.strip()[:70] for x in re.findall(r'^FAIL +(.*)$', log, re.M)})
    if 'Compiler run failed' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t33-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t33-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
