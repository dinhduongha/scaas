#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T17: each mutant of t17_mutants.py (or those named as arguments), one at a time on a clean scaas-node, the lib
# tests of dex (book and venue) run, the two files restored after each by git checkout.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t17_mutants.sh [name ...]
# Writes ../2026-11-04-ua-mtx-merge-t17-mutants.txt (mutant | tests that went red | rc) over every mutant with a log; full
# output in git-ignored mutant-t17-<name>.log beside this script. A mutant that fails to compile is reported COMPILE ERROR
# (it kills nothing). CARGO_TARGET_DIR is the caller's.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
node="$here/../../../../scaas-node"
capped="$here/../../../../scripts/capped"
files="src/dex.rs src/dex/venue.rs"
cd "$node" || exit 2
git diff --quiet -- $files || { echo "scaas-node is not clean" >&2; exit 2; }
names=${*:-$(python3 "$here/t17_mutants.py" --list)}
for m in $names; do
  python3 "$here/t17_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t17-$m.rc.log"; git checkout -- $files; continue; }
  "$capped" cargo test -j2 --no-fail-fast --lib -- dex:: > "$here/mutant-t17-$m.log" 2>&1
  echo $? > "$here/mutant-t17-$m.rc.log"
  git checkout -- $files
done
git diff --quiet -- $files || { echo "scaas-node not restored" >&2; exit 3; }
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t17_mutants.py --list' % here).read().split()
rows = ['mutant | tests that went red | rc']
for m in names:
    p = os.path.join(here, 'mutant-t17-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = open(p).read()
    red = sorted(set(re.findall(r'^test (\S+) \.\.\. FAILED$', log, re.M)))
    if re.search(r'^error(\[E\d+\])?:', log, re.M) and 'could not compile' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t17-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t17-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
