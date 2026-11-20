# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the sampled check's rulings of 2026-11-19 ("approved both", "OK, as proposed"): the upper
bound of 3,000, the verify rows at their worst case (ed25519 forced, FN-DSA the most of 64 salts plus `margin`), the
`margin` field: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasB-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
R = "clients/scaas-sdk/gas/reference.json"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
MUTANTS = [
    ("margin not added", [(G, "                .saturating_add(v.margin)\n", "")], U + "gas_verify_margin"),
    ("parse: margin dropped", [(C, 'margin: match r.get("margin") {', "margin: match None::<&serde_json::Value> {")],
     U + "gas_verify_margin"),
    ("parse: margin unbounded", [(C, "Some(m) => m.as_u64().filter(|m| (1..=GAS_MARGIN_MAX).contains(m))?,", "Some(m) => m.as_u64()?,")],
     U + "gas_verify_margin"),
    ("reference: FN-DSA-512's margin dropped", [(R, '"sig_bytes": 672,\n      "margin": 1000\n', '"sig_bytes": 672\n')],
     U + "reference_rows_hold_their_sources"),
    ("reference: ed25519's row at the vector, not the forced worst case",
     [(R, "\"signer\": 258,\n      \"gas\": 179000,\n      \"measured\": 178955,", "\"signer\": 258,\n      \"gas\": 177000,\n      \"measured\": 176079,")],
     U + "reference_rows_hold_their_sources"),
    ("reference: FN-DSA-1024's row at the vector, not the worst salt",
     [(R, "\"measured\": 4823338,", "\"measured\": 4751603,")], U + "reference_rows_hold_their_sources"),
]

if __name__ == "__main__":
    main("gasB", MUTANTS)
