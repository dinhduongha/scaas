# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The chains-arweave merge into pqvault-v: NET-ALL-25's shared-genesis gate for `PqVault` (`DeployBase._requireHomeKindsHere`),
python3 runs/2026-11-21-avax-dot-arweave-merge-pqvault-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

S = "smartcontracts/evm/script/DeployBase.sol"
T = "test_pqVaultRefusedOnSharedGenesis"
TS = f"cd smartcontracts/evm && ../../scripts/capped forge test --match-path test/governance/GovDeploy.t.sol --match-test {T}"
LINE = '        if (deployPqVault) _requireKindHere("PqVault", uid);\n'
MUTANTS = [
    ("sol: the PqVault line dropped", [(S, LINE, "")], TS, T),
    ("sol: the PqVault line keyed to DEPLOY_PQCHAT", [(S, LINE, LINE.replace("deployPqVault", "deployPqChat"))], TS, T),
]

if __name__ == "__main__":
    main("merge-pqvault", MUTANTS)
