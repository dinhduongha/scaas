#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T10: the deploy-gas summary's rows by T0's method on the merged tree (t10/T10DeployGas.t.sol), then the
# table (t10_deploy_gas.py). From smartcontracts/evm, foreground, one at a time:
#   runs/2026-11-04-ua-mtx-merge/t10_deploy_gas.sh <out dir for forge's out/ and cache/, outside the tree's own>
# FOUNDRY_TEST / FOUNDRY_SCRIPT = t10/, so the suite never compiles the harness and this run leaves out/ and cache/ alone.
# Writes t10-deploy.txt (the T0DEPLOY lines) beside this script; full forge output in git-ignored t10-deploy-gas.log.
# Forge gas is deterministic; this is a measurement of gas used, not a timing calibration.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
out=${1:?out dir}
export PATH="$HOME/.foundry/bin:$PATH"
FOUNDRY_TEST=runs/2026-11-04-ua-mtx-merge/t10 FOUNDRY_SCRIPT=runs/2026-11-04-ua-mtx-merge/t10 FOUNDRY_OUT="$out/out" \
  FOUNDRY_CACHE_PATH="$out/cache" ../../scripts/capped forge test -vv > "$here/t10-deploy-gas.log" 2>&1
grep -E "T0DEPLOY" "$here/t10-deploy-gas.log" | sed 's/^ *//' | sort -u > "$here/t10-deploy.txt"
echo "$(wc -l < "$here/t10-deploy.txt") rows"
