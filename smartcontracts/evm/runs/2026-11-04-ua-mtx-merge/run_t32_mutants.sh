#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T32: each mutant of t32_mutants.py, one at a time on a clean src, the T32 suites run, src restored after
# each; then the node mutant (a router row on the token domain: `UAOperatorTransfer` on the token kinds in
# scaas-node/src/typed.rs) against the two node tests that read the rows, typed.rs restored.
# From smartcontracts/evm: runs/2026-11-04-ua-mtx-merge/run_t32_mutants.sh
# ONLY="<names>" reruns a subset (NODE=0 skips the node row). Writes ../2026-11-04-ua-mtx-merge-t32-mutants.txt
# (mutant | tests that went red | rc); full output in git-ignored mutant-t32-<name>.log beside this script.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$HOME/.cargo/bin:$PATH"
git diff --quiet -- src ../../scaas-node/src || { echo "src or scaas-node/src is not clean" >&2; exit 2; }
suites='test/{as/OperatorTransfer,as/RegulatedSkeleton,as/confidential/ZetherOperator,as/confidential/PqzOperator,governance/GovRouter,governance/GovRouterTypehash,governance/GovRegulatedBits,governance/SelectorAudit}.t.sol'
for m in ${ONLY:-$(python3 "$here/t32_mutants.py" --list)}; do
  python3 "$here/t32_mutants.py" "$m" || { echo "$m: anchor missing" >&2; echo 99 > "$here/mutant-t32-$m.rc.log"; continue; }
  ../../scripts/capped forge test --match-path "$suites" > "$here/mutant-t32-$m.log" 2>&1
  echo $? > "$here/mutant-t32-$m.rc.log"
  git checkout -- src
done
if [ "${NODE:-1}" = 1 ]; then
  m=router-row-on-token-domain
  f=../../scaas-node/src/typed.rs
  old='("UAOperatorTransfer", "mtxOperatorTransfer", GR,'
  new='("UAOperatorTransfer", "mtxOperatorTransfer", T,'
  [ "$(grep -cF "$old" "$f")" = 1 ] || { echo "$m: anchor missing" >&2; exit 3; }
  sed -i "s/(\"UAOperatorTransfer\", \"mtxOperatorTransfer\", GR,/(\"UAOperatorTransfer\", \"mtxOperatorTransfer\", T,/" "$f"
  (cd ../../scaas-node && ../scripts/capped cargo test --lib -- guard::tests::allow_lists_equal_the_selector_audit_both_directions \
    typed::tests::router_ops_are_named_and_refuse_hex) > "$here/mutant-t32-$m.log" 2>&1
  echo $? > "$here/mutant-t32-$m.rc.log"
  git checkout -- ../../scaas-node/src/typed.rs
fi
python3 - "$here" <<'PY'
import os, re, sys
here = sys.argv[1]
names = os.popen('python3 %s/t32_mutants.py --list' % here).read().split() + ['router-row-on-token-domain']
rows = ['mutant | test that went red | rc']
for m in names:
    p = os.path.join(here, 'mutant-t32-%s.log' % m)
    if not os.path.exists(p):
        continue
    log = open(p).read()
    # a FAIL reason may hold raw revert bytes, newlines included; cargo prints `test <path> ... FAILED`
    red = sorted({x for x in re.findall(r'^\[FAIL.*?\] (test\w+)\(\)', log, re.M | re.S)}
                 | {x for x in re.findall(r'^test (\S+) \.\.\. FAILED', log, re.M)})
    if 'Compiler run failed' in log or 'error[E' in log:
        red = ['COMPILE ERROR']
    rc = open(os.path.join(here, 'mutant-t32-%s.rc.log' % m)).read().strip()
    rows.append('%s | %s | %s' % (m, ', '.join(red) or 'NONE (a finding)', rc))
open(os.path.join(here, '..', '2026-11-04-ua-mtx-merge-t32-mutants.txt'), 'w').write('\n'.join(rows) + '\n')
print('\n'.join(rows))
PY
