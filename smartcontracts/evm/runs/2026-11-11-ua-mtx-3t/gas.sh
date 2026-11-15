#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Round 3t T9 figures: PqzVerifierFeeGas.t.sol (log only) at the default set, copied into test/pqz for the run and removed.
#   cd smartcontracts/evm && CAPPED_SLOTS=3 sh runs/2026-11-11-ua-mtx-3t/gas.sh
set -u
cd "$(dirname "$0")/../.."
H=runs/2026-11-11-ua-mtx-3t
cp $H/PqzVerifierFeeGas.t.sol test/pqz/PqzVerifierFeeGasProbe.t.sol
FOUNDRY_SPARSE_MODE=true FOUNDRY_TEST=test/pqz FOUNDRY_SCRIPT=test/pqz FOUNDRY_OUT=out/t66a-test-pqz FOUNDRY_CACHE_PATH=cache/t66a-test-pqz \
  ../../scripts/capped "$HOME/.foundry/bin/forge" test -j 2 --match-path test/pqz/PqzVerifierFeeGasProbe.t.sol -vv > $H/gas.log 2>&1
rc=$?
rm -f test/pqz/PqzVerifierFeeGasProbe.t.sol
echo "rc=$rc" >> $H/gas.log
echo "rc=$rc"; grep -E "GAS3T|DIAG3T|Suite result|FAIL" $H/gas.log
