# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8d mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8d-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

K = "clients/ua-rs/src/wallet/entries/wallet.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxPayUnderMandate", [(K, '"E token payee amount entryRef epoch @ meta:PayMeta"', '"E token amount payee entryRef epoch @ meta:PayMeta"')], UA + "entries_wallet"),
    ("a wrong selector on mtxRevokeMandate", [(K, '"UARevokeMandate", "mtxRevokeMandate",', '"UARevokeMandate", "mtxRevoke",')], UA + "entries_wallet"),
    ("drop the unsigned meta of mtxPayUnderMandate", [(K, '"E token payee amount entryRef epoch @ meta:PayMeta"', '"E token payee amount entryRef epoch @"')], UA + "entries_wallet"),
]

if __name__ == "__main__":
    main("t8d", MUTANTS)
