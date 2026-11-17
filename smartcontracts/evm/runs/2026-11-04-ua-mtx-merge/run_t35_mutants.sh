#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T35: each mutant of t35_mutants.py, one at a time on a clean tree, then:
#   e2e-  cargo test --test e2e -- --ignored --test-threads=1 regulated_transfer_refused_frozen (local anvil, dropped after)
#   else  cargo test --lib (the node's 648 lib tests: the T35 rows, refusals, venue, indexer, config and their neighbours)
# Both through scripts/capped (CAPPED_MEM=6G: run alone). The mutated paths are restored with `git checkout` after each.
# From the repository root: smartcontracts/evm/runs/2026-11-04-ua-mtx-merge/run_t35_mutants.sh
# ONLY="<names>" reruns a subset. Writes ../2026-11-04-ua-mtx-merge-t35-mutants.txt (mutant | tests that went red | rc);
# full output in git-ignored mutant-t35-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../../../.." && pwd)
cd "$root" || exit 2
export PATH="$HOME/.foundry/bin:$PATH"
paths='scaas-node/src smartcontracts/evm/src smartcontracts/evm/test/vectors'
git diff --quiet -- $paths || { echo "$paths: not clean (commit first)" >&2; exit 2; }
for m in ${ONLY:-$(python3 "$here/t35_mutants.py" --list)}; do
  log="$here/mutant-t35-$m.log"
  python3 "$here/t35_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t35-$m.rc.log"; continue; }
  case "$m" in
    e2e-*) (cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --test e2e -- --ignored --test-threads=1 regulated_transfer_refused_frozen) > "$log" 2>&1 ;;
    *) (cd scaas-node && CAPPED_MEM=6G ../scripts/capped cargo test --lib) > "$log" 2>&1 ;;
  esac
  echo $? > "$here/mutant-t35-$m.rc.log"
  git checkout -- $paths
done
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
rows = ['mutant | test that went red | rc']
for m in os.popen('python3 %s/t35_mutants.py --list' % here).read().split():
    p = os.path.join(here, 'mutant-t35-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = open(p).read()
    red = {x.strip() for x in re.findall(r'^test ([\w:]+) \.\.\. FAILED', log, re.M)}
    if 'error[E' in log:
        red = {'COMPILE ERROR'}
    rc = open(os.path.join(here, 'mutant-t35-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(sorted(red)) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t35-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
