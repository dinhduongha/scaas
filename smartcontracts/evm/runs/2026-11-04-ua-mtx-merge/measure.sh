#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# T0 of the ua*/mtx* merge plan: one run's sizes, deploy gas and gas. From smartcontracts/evm, foreground, one at a time:
#   runs/2026-11-04-ua-mtx-merge/measure.sh <run>          (run = base | M | ML | MD | MLD | ...)
#   T0_SKIP="test/merge/MergedEntry.t.sol test/merge/T0GasReg.t.sol" on the D runs: they (and the PQZ fixture) read
#   views D moves off the token, and no module is built.
# Needs test/merge/{T0Gas.t.sol,T0Deploy.t.sol,T0Digest.sol,T0Sel.sol} in the tree (adapters/; T0Sel.sol = the tree's
# form). Writes sizes-<run>.json and t0-<run>.txt (the T0DEPLOY / T0GAS lines) beside this script; full forge output in
# git-ignored .log files. Forge gas is deterministic; this is not a timing calibration.
set -euo pipefail
run=$1
here=$(cd "$(dirname "$0")" && pwd)
export PATH="$HOME/.foundry/bin:$PATH"
../../scripts/capped forge build src --sizes --json > "$here/build-$run.log" 2> "$here/build-$run.err.log" || true
python3 "$here/sizes.py" "$here/build-$run.log" "$run" > /dev/null
FOUNDRY_TEST=test/merge FOUNDRY_SCRIPT=test/merge ../../scripts/capped forge test -vv ${T0_SKIP:+--skip $T0_SKIP} > "$here/test-$run.log" 2>&1 || true
grep -E "T0DEPLOY|T0GAS" "$here/test-$run.log" | sed 's/^ *//' | sort -u > "$here/t0-$run.txt" || true
grep -E "Suite result|FAIL" "$here/test-$run.log" | sed 's/finished in.*//' | sort | uniq -c > "$here/suites-$run.txt" || true
echo "$run: $(wc -l < "$here/t0-$run.txt") rows; $(grep -c FAIL "$here/suites-$run.txt" || true) FAIL lines"
