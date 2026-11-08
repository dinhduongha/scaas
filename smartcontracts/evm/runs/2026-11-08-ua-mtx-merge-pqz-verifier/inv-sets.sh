#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3f T49 step 2: the invariant suite I1-I6 at the four sets (`script/pqz/at-set.sh`, only test/pqz compiled), and at
# n2048-kmax1024 (the PQZH value-token set) the PQZH fit rows again. Resume per step; PqzSet.sol restored by at-set.sh.
#   cd smartcontracts/evm && sh runs/2026-11-08-ua-mtx-merge-pqz-verifier/inv-sets.sh [set ...]
set -u
cd "$(dirname "$0")/../.."
SETS=${*:-n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536}
step() { # name, forge args...
  L=runs/2026-11-08-ua-mtx-merge-t49-$1.log; shift
  if [ -f "$L" ] && grep -qE "^Ran [0-9]+ test suites?" "$L"; then echo "skip $L"; return; fi
  FOUNDRY_TEST=test/pqz FOUNDRY_SCRIPT=test/pqz ../../scripts/capped script/pqz/at-set.sh "$@" > "$L" 2>&1
  echo "$L rc=$? $(grep -E '^Ran [0-9]+ test suites?' "$L" | tail -1)"
  git diff --quiet HEAD -- src/pqz/PqzSet.sol || { echo "PqzSet.sol not restored"; exit 1; }
}
for S in $SETS; do
  step "inv-$S" "$S" test --match-path test/pqz/invariant/PqzVerdictInvariants.t.sol
  [ "$S" = n2048-kmax1024 ] && step "pqzh-fit-$S" "$S" test --match-test test_pqzhN2048FitsBothPaths
done
