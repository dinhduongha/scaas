#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T36: each mutant of mutants.py (t36-*, port-*), one at a time on a clean src and script, against the regulated
# suites, the relaxation and +0 suites and the invariant suite I1-I13 (test/as/** holds test/as/invariant), then src and
# script restored with git. Then, with RERUN=1, the earlier harnesses of T24-T35 as they are (their own suites), each
# table copied to rerun-t<NN>.txt here and the committed one restored (a changed row is a finding, never hidden).
# From smartcontracts/evm, foreground, nothing else running in this work tree:
#   runs/2026-11-04-ua-mtx-merge-regulated/run_mutants.sh                 # the T36 table, mutants.txt
#   ONLY="<names>" runs/2026-11-04-ua-mtx-merge-regulated/run_mutants.sh  # a subset (the table keeps every row run)
#   RERUN=1 SKIP_T36=1 RERUN_ONLY="24 25" runs/2026-11-04-ua-mtx-merge-regulated/run_mutants.sh
# T35's harness raises CAPPED_MEM to 6G (the node's lib tests): it is skipped while another cargo runs on the machine.
# Full output in git-ignored mutant-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
evm=$(cd "$here/../.." && pwd)
cd "$evm" || exit 2
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
suites='test/{as/*,governance/GovRelax,governance/PlusZero,governance/GovDeploy,v2/LinkClosure}.t.sol'
git diff --quiet -- src script || { echo "src or script is not clean" >&2; exit 2; }

if [ "${SKIP_T36:-0}" != 1 ]; then
  for m in ${ONLY:-$(python3 "$here/mutants.py" --list)}; do
    python3 "$here/mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-$m.rc.log"; continue; }
    ../../scripts/capped forge test --match-path "$suites" > "$here/mutant-$m.log" 2>&1
    echo $? > "$here/mutant-$m.rc.log"
    git checkout -- src script
  done
  python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
rows = ['mutant | test that went red | red in | rc']
for m in os.popen('python3 %s/mutants.py --list' % here).read().split():
    p = os.path.join(here, 'mutant-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = open(p).read()
    red, where = set(), set()
    # forge prints `Ran N tests for <path>:<Contract>` before each suite's results
    for block in re.split(r'^Ran \d+ tests? for ', log, flags=re.M)[1:]:
        head = block.split('\n', 1)[0]
        for t in re.findall(r'^\[FAIL.*?\] ((?:test|invariant)\w+)', block, re.M | re.S):
            red.add(t)
            where.add('T36 invariant suite' if 'test/as/invariant/' in head else 'earlier suites')
    if 'Compiler run failed' in log:
        red, where = {'COMPILE ERROR'}, set()
    rc = open(os.path.join(here, 'mutant-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s | %s' % (m, ', '.join(sorted(red)) or 'NONE (a finding)', ' + '.join(sorted(where)) or '-', rc))
open(os.path.join(here, 'mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
fi

if [ "${RERUN:-0}" = 1 ]; then
  old="$evm/runs/2026-11-04-ua-mtx-merge"
  for t in ${RERUN_ONLY:-24 25 26 27 28 29 30 31 32 33 34 35}; do
    table="runs/2026-11-04-ua-mtx-merge-t$t-mutants.txt"
    if [ "$t" = 35 ] && pgrep -x cargo > /dev/null; then
      echo "t35: another cargo runs on the machine; its harness needs CAPPED_MEM=6G alone: skipped" >&2
      continue
    fi
    "$old/run_t${t}_mutants.sh" > "$here/rerun-t$t.log" 2>&1
    echo "t$t: rc $?" >&2
    cd "$evm" || exit 2
    cp "$table" "$here/rerun-t$t.txt"
    git diff --quiet -- "$table" || echo "t$t: the re-run's table differs from the committed one (see rerun-t$t.txt)" >&2
    git checkout -- "$table"
  done
fi
