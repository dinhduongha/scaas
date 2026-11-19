# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's ruling I2 of 2026-11-19: a base row priced by a stand-in (the PQZ debits)
carries its `stand_in`, keyed by kind and entry:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasI2-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

P = "clients/scaas-sdk/gas/generate.py"
GEN = "python3 clients/scaas-sdk/gas/test_generate.py"
K = 'if f"{kind}:{entry}" in inputs.get("base_stand_in", {}):'
MUTANTS = [
    ("no base stand_in", [(P, K, 'if False and f"{kind}:{entry}" in inputs.get("base_stand_in", {}):')], GEN),
    (
        "stand_in keyed by entry only",
        [
            (P, K, 'if entry in [k.split(":")[1] for k in inputs.get("base_stand_in", {})]:'),
            (
                P,
                'row["stand_in"] = inputs["base_stand_in"][f"{kind}:{entry}"]',
                'row["stand_in"] = next(iter(inputs["base_stand_in"].values()))',
            ),
        ],
        GEN,
    ),
]

if __name__ == "__main__":
    main("gasI2", MUTANTS)
