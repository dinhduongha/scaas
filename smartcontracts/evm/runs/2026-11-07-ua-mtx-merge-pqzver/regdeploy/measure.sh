#!/bin/bash
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# ua-mtx-merge T51: the registry's deploy gas (RegistryDeployGas.t.sol) at one set. From smartcontracts/evm of the tree to
# measure (this tree, or a copy of an older commit with this directory copied in), foreground:
#   runs/2026-11-07-ua-mtx-merge-pqzver/regdeploy/measure.sh <set> <out dir outside the tree's own out/>
# The set's PqzSet.sol is put in place by at-set.sh's own rule (pqz-core/params/sets/<set>/PqzSet.sol) and restored after.
# Forge gas is deterministic: a measurement of gas used, not a timing calibration. Prints the REGDEPLOY lines.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
set_name=${1:?set}
out=${2:?out dir}
root=$(cd ../.. && pwd)
cp src/pqz/PqzSet.sol "$out/PqzSet.sol.keep"
trap 'cp "$out/PqzSet.sol.keep" src/pqz/PqzSet.sol' EXIT
cp "$root/pqz-core/params/sets/$set_name/PqzSet.sol" src/pqz/PqzSet.sol
FOUNDRY_TEST=runs/2026-11-07-ua-mtx-merge-pqzver/regdeploy FOUNDRY_OUT="$out/out-$set_name" FOUNDRY_CACHE_PATH="$out/cache-$set_name" \
  "$root/scripts/capped" "$HOME/.foundry/bin/forge" test -vv > "$out/regdeploy-$set_name.log" 2>&1
grep -E "REGDEPLOY" "$out/regdeploy-$set_name.log" | sed "s/^ */$set_name | /"
