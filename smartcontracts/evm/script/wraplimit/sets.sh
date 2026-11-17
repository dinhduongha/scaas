#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3l, plan T99: the wrap-limit tests (kinds 5 and 13 among them) at the four PQZ sets, one at a time
# (script/pqz/at-set.sh rewrites src/pqz/PqzSet.sol and restores it), each through scripts/capped in the foreground.
# Per step a git-ignored log <runs>/sets/<set>.log and one line `<set> | rc | passed failed` in <runs>/sets.txt; a set
# already in sets.txt is skipped (resume). From smartcontracts/evm:  sh script/wraplimit/sets.sh <runs dir>   UNAUDITED.
set -u
PATH="$HOME/.foundry/bin:$PATH"; export PATH
R=$1
mkdir -p "$R/sets"
touch "$R/sets.txt"
for s in n2048-kmax1024 n2304-kmax4096 n2560-kmax16384 n2816-kmax65536; do
  grep -q "^$s |" "$R/sets.txt" && continue
  # slot fairness (controller 2026-11-10): yield to a waiting capped job of another work tree; rerun to resume
  python3 -c "import sys; sys.path.insert(0, 'script/wraplimit'); import mutants; sys.exit(mutants.others_waiting())" \
    || { echo "yield before $s"; exit 0; }
  CAPPED_SLOTS=${CAPPED_SLOTS:-3} FOUNDRY_TEST=test/wrap ../../scripts/capped sh script/pqz/at-set.sh "$s" test \
    --match-path 'test/wrap/*' > "$R/sets/$s.log" 2>&1
  rc=$?
  n=$(grep -E '^Ran [0-9]+ test suites' "$R/sets/$s.log" | tail -1 | sed -E 's/.*: ([0-9]+) tests passed, ([0-9]+) failed.*/\1 \2/')
  echo "$s | $rc | ${n:-compile-or-run-error}" >> "$R/sets.txt"
  git diff --quiet -- src/pqz/PqzSet.sol || { echo "PqzSet.sol not restored" >&2; exit 2; }
done
