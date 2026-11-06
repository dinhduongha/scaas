#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T34: each mutant of t34_mutants.py, one at a time on a clean tree, then the reader its prefix names:
#   ck-  clientkeys: node --test test/{regulated,typed-ops,governance-bits}.test.js
#   gen- node scripts/typed-ops-vectors.mjs, then the same clientkeys tests
#   rs-  ua-rs: cargo test --test regulated --test vectors
#   sol- forge test --match-path 'test/{as/RegulatedKat,governance/{GovBitsVector,GovRouterTypehash},metatx/TypedOps}.t.sol'
# The mutated paths and the vectors are restored with `git checkout` after each.
# From the repository root: smartcontracts/evm/runs/2026-11-04-ua-mtx-merge/run_t34_mutants.sh
# ONLY="<names>" reruns a subset. Writes ../2026-11-04-ua-mtx-merge-t34-mutants.txt (mutant | tests that went red | rc);
# full output in git-ignored mutant-t34-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
cd "$root" || exit 2
export PATH="$HOME/.foundry/bin:$PATH"
paths='clients/clientkeys clients/ua-rs/src smartcontracts/evm/src smartcontracts/vectors'
git diff --quiet -- $paths || { echo "$paths: not clean (commit first)" >&2; exit 2; }
for m in ${ONLY:-$(python3 "$here/t34_mutants.py" --list)}; do
  log="$here/mutant-t34-$m.log"
  python3 "$here/t34_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t34-$m.rc.log"; continue; }
  case "$m" in
    ck-*) (cd clients/clientkeys && ../../scripts/capped node --test test/regulated.test.js test/typed-ops.test.js test/governance-bits.test.js) > "$log" 2>&1 ;;
    gen-*) (cd clients/clientkeys && node scripts/typed-ops-vectors.mjs && ../../scripts/capped node --test test/regulated.test.js test/typed-ops.test.js) > "$log" 2>&1 ;;
    rs-*) (cd clients/ua-rs && ../../scripts/capped cargo test --test regulated --test vectors) > "$log" 2>&1 ;;
    sol-*) (cd smartcontracts/evm && ../../scripts/capped forge test --match-path 'test/{as/RegulatedKat,governance/{GovBitsVector,GovRouterTypehash},metatx/TypedOps}.t.sol') > "$log" 2>&1 ;;
  esac
  echo $? > "$here/mutant-t34-$m.rc.log"
  git checkout -- $paths
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
rows = ['mutant | test that went red | rc']
for m in os.popen('python3 %s/t34_mutants.py --list' % here).read().split():
    p = os.path.join(here, 'mutant-t34-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = open(p).read()
    red = set(re.findall(r'^\[FAIL.*?\] (test\w+)\(\)', log, re.M | re.S))       # forge
    red |= {x.strip() for x in re.findall(r'^test (\w+) \.\.\. FAILED', log, re.M)}  # cargo
    red |= {x.strip()[:90] for x in re.findall(r'^✖ (.*?) \(\d', log, re.M) if not x.startswith('test/')}  # node --test
    if 'Compiler run failed' in log or 'error[E' in log:
        red = {'COMPILE ERROR'}
    rc = open(os.path.join(here, 'mutant-t34-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(sorted(red)) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t34-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
