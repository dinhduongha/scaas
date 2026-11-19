# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's ruling I3 of 2026-11-19: `mtxSetAuditorUA`'s new auditor's consent is an
attached signature (ruling 4), its kind read from the consent's key data and `newAuditor`, unknown: the worst kind:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasI3-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F + " --lib "
KIND = T + "attached_signature_kind"
MUTANTS = [
    (
        "the consent not attached",
        [(G, '        (None, Some(s)) => (s, message.get("newAuditor")),', "        (None, Some(_)) => return None,")],
        KIND,
    ),
    (
        "the consent read against the envelope's from",
        [
            (
                G,
                '        (None, Some(s)) => (s, message.get("newAuditor")),',
                '        (None, Some(s)) => (s, message.get("from")),',
            )
        ],
        KIND,
    ),
]

if __name__ == "__main__":
    main("gasI3", MUTANTS)
