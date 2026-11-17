#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T12: each mutant of t12_mutants.py, one at a time on a clean src/envelope.rs, zether-prover's
# tests/typed_ops.rs and tests/envelope_disclosure.rs run (vectors and cast references fixed), src/envelope.rs restored after each.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t12_mutants.sh
# Writes ../2026-11-04-ua-mtx-merge-t12-mutants.txt (mutant | tests that went red | rc); full output in git-ignored
# mutant-t12-<name>.log beside this script. A mutant that fails to compile is reported COMPILE ERROR (it kills nothing).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
zp="$here/../../../../clients/zether-prover"
capped="$here/../../../../scripts/capped"
cd "$zp" || exit 2
git diff --quiet -- src/envelope.rs || { echo "src/envelope.rs is not clean" >&2; exit 2; }
for m in $(python3 "$here/t12_mutants.py" --list); do
  python3 "$here/t12_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t12-$m.rc.log"; git checkout -- src/envelope.rs; continue; }
  "$capped" cargo test -j2 --no-fail-fast --test typed_ops --test envelope_disclosure > "$here/mutant-t12-$m.log" 2>&1
  echo $? > "$here/mutant-t12-$m.rc.log"
  git checkout -- src/envelope.rs
done
git diff --quiet -- src/envelope.rs || { echo "src/envelope.rs not restored" >&2; exit 3; }
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t12_mutants.py --list' % here).read().split()
rows = ['mutant | tests that went red | rc']
for m in names:
    log = open(os.path.join(here, 'mutant-t12-%s.log' % m)).read()
    red = sorted(set(re.findall(r'^test (\w+) \.\.\. FAILED$', log, re.M)))
    if re.search(r'^error(\[E\d+\])?:', log, re.M) and 'could not compile' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t12-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t12-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
