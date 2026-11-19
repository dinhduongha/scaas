# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8b mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8b-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/entries/mod.rs"
K = "clients/ua-rs/src/wallet/entries/zether.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxUnshield (Zether)", [(K, "ZetherBurn args,uint256 amount,bytes32 recipient,bytes proof", "ZetherBurn args,bytes32 recipient,uint256 amount,bytes proof")], UA + "entries_zether"),
    ("a wrong selector on mtxRollOverBatch", [(K, '"UARollOverBatch", "mtxRollOverBatch",', '"UARollOverBatch", "mtxRollOverAll",')], UA + "entries_zether"),
    ("drop the unsigned ownerSig of mtxRollOverSigned", [(K, 'validUntilBlock ownerSig:UASig @";\nconst OWNER_MODE', 'validUntilBlock @";\nconst OWNER_MODE')], UA + "entries_zether"),
    ("an owner statement signed as bytes", [(M, '"@ua" => return Tok::Sign(Sig::Ua),', '"@ua" => return Tok::Sign(Sig::Bytes),')], UA + "entries_zether"),
]

if __name__ == "__main__":
    main("t8b", MUTANTS)
