# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's ruling W3 of 2026-11-19 ("approved"): the gas table's parse bound is 1 MiB, still
a bounded decode: a table of exactly 1 MiB parses, one byte more is refused:
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasW3-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

C = "clients/scaas-sdk/src/config.rs"
PARSE = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib gas_table_parse_checks"
B = "const GAS_TABLE_MAX_BYTES: usize = 1024 * 1024;"
MUTANTS = [
    ("the old 256 KiB bound", [(C, B, "const GAS_TABLE_MAX_BYTES: usize = 256 * 1024;")], PARSE),
    (
        "the bound off by one",
        [(C, "        if text.len() > GAS_TABLE_MAX_BYTES {", "        if text.len() >= GAS_TABLE_MAX_BYTES {")],
        PARSE,
    ),
    (
        "no bound",
        [
            (
                C,
                "        if text.len() > GAS_TABLE_MAX_BYTES {",
                "        if false && text.len() > GAS_TABLE_MAX_BYTES {",
            )
        ],
        PARSE,
    ),
    ("one byte more allowed", [(C, B, "const GAS_TABLE_MAX_BYTES: usize = 1024 * 1024 + 1;")], PARSE),
]

if __name__ == "__main__":
    main("gasW3", MUTANTS)
