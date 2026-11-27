# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the split sampled check (owner 2026-11-19): the composition check
at a worst-case-class signature (both bounds) and the safety check of the data-dependent kinds (lower bound only), each
mutant a moved measurement or a dropped part of the composition: python3
clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasC-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
M = "smartcontracts/evm/test/vectors/sdk_gas.json"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib sampled_end_to_end_check"
MUTANTS = [
    ("an ordinary ed25519 signature above the table (safety)",
     [(M, "\"sample_0102_mtxPay_used_normal_safety\": 367358,", "\"sample_0102_mtxPay_used_normal_safety\": 371000,")], U),
    ("the worst-case ed25519 cell above the composition (lower bound)",
     [(M, "\"sample_0102_mtxCancelNonce_fresh_normal\": 428734,", "\"sample_0102_mtxCancelNonce_fresh_normal\": 432264,")], U),
    ("the worst-case ed25519 cell 3,000 below the composition (upper bound)",
     [(M, "\"sample_0102_mtxCancelNonce_fresh_normal\": 428734,", "\"sample_0102_mtxCancelNonce_fresh_normal\": 428000,")], U),
    ("an FN-DSA-512 salt above the row with its margin (safety)",
     [(M, '"verify_0x0132_safety_extra": 1741,', '"verify_0x0132_safety_extra": 2900,')], U),
    ("ua_extra not added: the composition under", [(G, "g = g.saturating_add(b.ua_extra.unwrap_or(0));", "g = g.saturating_add(0);")],
     U),
]

if __name__ == "__main__":
    main("gasC", MUTANTS)
