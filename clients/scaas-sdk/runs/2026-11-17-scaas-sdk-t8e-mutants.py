# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8e mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8e-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/entries/mod.rs"
K = "clients/ua-rs/src/wallet/entries/account.rs"
F = "clients/ua-rs/src/factory.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxRotateKey", [(K, '"address from,uint256 index,uint8 kind,', '"address from,uint8 kind,uint256 index,')], UA + "entries_account"),
    ("a wrong selector on mtxSetGuardian", [(K, '"SetGuardian", "mtxSetGuardian",', '"SetGuardian", "mtxSetGuardians",')], UA + "entries_account"),
    ("the account's own entries signed as bytes (no AccountSig)", [(M, "} else if *kinds == A {", "} else if kinds.is_empty() {")], UA + "entries_account"),
    ("the guardian left-aligned in the salt", [(F, "g[12..].copy_from_slice(guardian);", "g[..20].copy_from_slice(guardian);")], UA + "smart_key_account_address"),
    ("another EIP-1167 head", [(F, "0x3d, 0x60, 0x2d, 0x80,", "0x3d, 0x60, 0x2c, 0x80,")], UA + "smart_key_account_address"),
]

if __name__ == "__main__":
    main("t8e", MUTANTS)
