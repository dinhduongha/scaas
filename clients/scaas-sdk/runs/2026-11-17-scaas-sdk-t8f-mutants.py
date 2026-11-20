# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8f mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8f-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

K = "clients/ua-rs/src/wallet/entries/dex.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxInvalidateNonces", [(K, '"from batch minNonce @"', '"from minNonce batch @"')], UA + "entries_dex"),
    ("a wrong selector on mtxCancelOrders", [(K, "\"CancelDexOrder\",\n        \"mtxCancelOrders\",", "\"CancelDexOrder\",\n        \"mtxCancelOrder\",")], UA + "entries_dex"),
    ("the signature out of its one-element list", [(K, '"[order] [@]"', '"[order] @"')], UA + "entries_dex"),
]

if __name__ == "__main__":
    main("t8f", MUTANTS)
