#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3f (plan T44, T45, T49): `script/pqz/at-set.sh <set> test` at the four sets over test/{ua,pqz,as/confidential}, one
# step per (set, directory): FOUNDRY_TEST is the directory, so only it and src are compiled (a whole-tree compile at another
# set does not fit the 4 GB cap). A step whose log ends with the forge summary is skipped on a re-run (resume per step).
# at-set.sh restores src/pqz/PqzSet.sol itself (its trap). One run per work tree. Logs: runs/<date>-ua-mtx-merge-t44-at-<set>-<dir>.log
#   cd smartcontracts/evm && sh runs/2026-11-08-ua-mtx-merge-pqz-verifier/at-sets.sh [set ...]
set -u
cd "$(dirname "$0")/../.."
SETS=${*:-n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536}
for S in $SETS; do
  for D in pqz ua as; do
    L=runs/2026-11-08-ua-mtx-merge-t44-at-$S-$D.log
    if [ -f "$L" ] && grep -qE "^Ran [0-9]+ test suites?" "$L"; then echo "skip $S $D (done)"; continue; fi
    M="test/$D/*"; [ "$D" = as ] && M="test/as/confidential/*"
    FOUNDRY_TEST=test/$D FOUNDRY_SCRIPT=test/$D ../../scripts/capped script/pqz/at-set.sh "$S" test --match-path "$M" > "$L" 2>&1
    echo "$S $D rc=$? $(grep -E '^Ran [0-9]+ test suites?' "$L" | tail -1)"
    git diff --quiet HEAD -- src/pqz/PqzSet.sol || { echo "PqzSet.sol not restored"; exit 1; }
  done
done
