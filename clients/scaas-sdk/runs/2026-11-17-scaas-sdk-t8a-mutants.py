# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk plan T8a mutants: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t8a-mutants.py check | run"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

M = "clients/ua-rs/src/wallet/entries/mod.rs"
K = "clients/ua-rs/src/wallet/entries/token.rs"
UA = "cd clients/ua-rs && ../../scripts/capped cargo test --locked --offline -j2 --test entries "
MUTANTS = [
    ("swap two arguments of mtxPayWithTax", [(K, '"payment taxMode tax @ meta:PayMeta"', '"payment tax taxMode @ meta:PayMeta"')], UA + "entries_token"),
    ("a wrong selector on mtxBurn", [(K, '"UABurn", "mtxBurn",', '"UABurn", "mtxBurnUA",')], UA + "entries_token"),
    ("drop the unsigned meta of mtxPayWithPayeeFee", [(K, 'feeRecipient validUntil @ meta:PayMeta"', 'feeRecipient validUntil @"')], UA + "entries_token"),
    ("an unbound relayer sent as given", [(M, "if mode & 1 == 0 {", "if mode & 1 == 2 {")], UA + "entries_token"),
    ("an unbound fee recipient sent as given", [(M, "if mode & 2 == 0 {", "if mode & 2 == 1 {")], UA + "entries_token"),
    ("a dynamic offset past the heads only", [(M, "head.extend(word(head_len + tail.len()));", "head.extend(word(tail.len()));")], UA + "entries_token"),
    ("relayRef without the chain id", [(M, "    b.extend(word(chain_id as usize));\n", "")], UA + "entries_token"),
    ("a relay fee's call on another target", [(M, "if target.as_str() != Some(field(&inner, \"token\").as_str())\n        || hash", "if hash")], UA + "entries_token"),
]

if __name__ == "__main__":
    main("t8a", MUTANTS)
