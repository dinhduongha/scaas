#!/bin/sh
# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
# Group 3f T50 figures: PqzOffchainGas.t.sol (log only) at the default set, copied into test/pqz for the run and removed.
#   cd smartcontracts/evm && sh runs/2026-11-08-ua-mtx-merge-pqz-verifier/gas.sh
set -u
cd "$(dirname "$0")/../.."
cp runs/2026-11-08-ua-mtx-merge-pqz-verifier/PqzOffchainGas.t.sol test/pqz/PqzOffchainGasProbe.t.sol
FOUNDRY_TEST=test/pqz FOUNDRY_SCRIPT=test/pqz FOUNDRY_OUT=out/focus FOUNDRY_CACHE_PATH=cache/focus ../../scripts/capped forge test \
  --match-path test/pqz/PqzOffchainGasProbe.t.sol -vv > runs/2026-11-08-ua-mtx-merge-t50-gas.log 2>&1
rc=$?
rm -f test/pqz/PqzOffchainGasProbe.t.sol
echo "rc=$rc"; grep -E "GAS3F|VERDICT calldata|Suite result" runs/2026-11-08-ua-mtx-merge-t50-gas.log
