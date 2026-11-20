# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""The registry-write margin lowered (owner 2026-11-20): a fixed-cost row, the intrinsic cost and the calldata quoted as
measured, the margin kept on a data-dependent kind's register row and on a slot's verify row of one, the regular bound the
same way, and the quote never below the gas a node used (M20):
python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-r20margin-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
T = f"cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features {F} --lib "
RT = T + "account::register::tests::"
MARGIN = RT + "registry_margin_on_the_data_dependent_parts_only"
M20 = RT + "registry_quote_never_below_the_m20_receipts"
MUTANTS = [
    (
        "no register row data-dependent",
        [(G, "        .is_some_and(|k| DATA_DEPENDENT.contains(&k))\n}", "        .is_some_and(|_| false)\n}")],
        MARGIN,
    ),
    (
        "every register row data-dependent",
        [(G, "        .is_some_and(|k| DATA_DEPENDENT.contains(&k))\n}", "        .is_some_and(|_| true)\n}")],
        MARGIN,
    ),
    (
        "FN-DSA-512 not data-dependent",
        [
            (
                G,
                "pub(crate) const DATA_DEPENDENT: [u16; 3] = [0x0102, 0x0132, 0x0135];",
                "pub(crate) const DATA_DEPENDENT: [u16; 3] = [0x0102, 0x0135, 0x0135];",
            )
        ],
        MARGIN,
    ),
    (
        "a slot's verify row never data-dependent",
        [(G, "add(DATA_DEPENDENT.contains(s), v, v);", "add(false, v, v);")],
        MARGIN,
    ),
    (
        "the fixed-cost parts with the margin (the old rule)",
        [
            (
                G,
                "        f.saturating_add(INTRINSIC)\n            .saturating_add(bytes)\n            .saturating_add(with_margin(d))",
                "        with_margin(f.saturating_add(INTRINSIC).saturating_add(bytes))\n            .saturating_add(with_margin(d))",
            )
        ],
        M20,
    ),
    (
        "the data-dependent parts without the margin",
        [(G, "            .saturating_add(with_margin(d))", "            .saturating_add(d)")],
        MARGIN,
    ),
    (
        "the calldata not counted",
        [
            (
                G,
                "        f.saturating_add(INTRINSIC)\n            .saturating_add(bytes)\n",
                "        f.saturating_add(INTRINSIC)\n            .saturating_add(0 * bytes)\n",
            )
        ],
        M20,
    ),
    (
        "the regular bound the whole",
        [(G, "        regular: total(fixed.1, data.1).min(gas),", "        regular: gas,")],
        MARGIN,
    ),
]

if __name__ == "__main__":
    main("r20margin", MUTANTS)
