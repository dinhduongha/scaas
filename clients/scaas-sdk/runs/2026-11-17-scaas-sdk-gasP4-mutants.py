# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""SDK gas-table harness mutants of the owner's ruling P4 of 2026-11-19 ("approved"): a counted row's line is the chord from
the first to the last measured point when that chord is at or above every point, else the worst slope's line; a line below a
point fails (`SdkGasOps._sgLine`, `_sgChord`):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasP4-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

O = "smartcontracts/evm/test/gas/SdkGasOps.sol"
FORGE = "cd smartcontracts/evm && ../../scripts/capped forge test --match-path "
ROLL = FORGE + "test/gas/SdkGasConfPqz.t.sol --match-test '^test_sdkGas_pqzConfRoll\\('"
MULTI = FORGE + "test/gas/SdkGasConfZether.t.sol --match-test '^test_sdkGas_zetherConfCounted\\('"
MUTANTS = [
    (
        "the chord taken below a point",
        [(O, "ok = g[w][0] + c * (counts[i] - counts[0]) >= g[w][i];", "ok = true;")],
        ROLL,
    ),
    (
        "the chord's slope rounded down",
        [(O, "uint256 r = (g[w][n - 1] - g[w][0] + span - 1) / span;", "uint256 r = (g[w][n - 1] - g[w][0]) / span;")],
        MULTI,
    ),
]

if __name__ == "__main__":
    main("gasP4", MUTANTS)
