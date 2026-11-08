#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T18: each mutant of t18_mutants.py (or those named as arguments), one at a time on a clean scaas-node, its anvil
# e2e run (scripts/capped, foreground, each test its own anvil, killed on drop), the files restored by git checkout after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t18_mutants.sh [name ...]. Needs anvil and forge in PATH.
# Writes ../2026-11-04-ua-mtx-merge-t18-mutants.txt (mutant | tests that went red | rc) over every mutant with a log; full
# output in git-ignored mutant-t18-<name>.log beside this script. A mutant that fails to compile is reported COMPILE ERROR
# (it kills nothing). CARGO_TARGET_DIR is the caller's.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
node="$here/../../../../scaas-node"
capped="$here/../../../../scripts/capped"
cd "$node" || exit 2
files=$(python3 "$here/t18_mutants.py" --files)
git diff --quiet -- $files || { echo "scaas-node is not clean" >&2; exit 2; }
names=${*:-$(python3 "$here/t18_mutants.py" --list)}
for m in $names; do
  python3 "$here/t18_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t18-$m.rc.log"; git checkout -- $files; continue; }
  : > "$here/mutant-t18-$m.log"
  rc=0
  while read -r args; do
    "$capped" cargo test -j2 $args < /dev/null >> "$here/mutant-t18-$m.log" 2>&1 || rc=$?
  done < <(python3 "$here/t18_mutants.py" --tests "$m")
  echo $rc > "$here/mutant-t18-$m.rc.log"
  git checkout -- $files
done
git diff --quiet -- $files || { echo "scaas-node not restored" >&2; exit 3; }
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t18_mutants.py --list' % here).read().split()
rows = ['mutant | tests that went red | rc']
for m in names:
    p = os.path.join(here, 'mutant-t18-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = re.sub(r'\x1b\[[0-9;]*m', '', open(p).read())
    red = sorted(set(re.findall(r'^test (\S+) \.\.\. FAILED$', log, re.M)) | set(re.findall(r"^thread '(\S+)' \(\d+\) panicked", log, re.M)))
    if re.search(r'^error(\[E\d+\])?:', log, re.M) and 'could not compile' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t18-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t18-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
