# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's rulings I1 part 2, K2 and P1 of 2026-11-19 ("approved"): the counts the SDK
reads (`mtxCreateToken`'s `extra.config.legs`, a rollover's skip marks added to n, an env's four arrays, a DEX cancel's one
order), the new items and the per-item bound in the parse, and the generator's kind-qualified per-item keys, new items and
stated overshoot: python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasI1b-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
P = "clients/scaas-sdk/gas/generate.py"
F = "vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots"
SDK = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --features " + F + " --lib "
COUNT = SDK + "item_count_reads_the_operations_counts"
PARSE = SDK + "gas_table_per_item_parse"
GEN = "python3 clients/scaas-sdk/gas/test_generate.py"
MUTANTS = [
    (
        "TokenConfig.legs not read from extra",
        [(G, '            .or_else(|| len(extra.get("config").and_then(|c| c.get("legs"))))?,', "            ?,")],
        COUNT,
    ),
    (
        "skip marks not added",
        [(G, "checked_add(u64::try_from(skip).ok()?)", "checked_add(u64::try_from(skip).ok()? * 0)")],
        COUNT,
    ),
    (
        "an env array left out",
        [(G, '["deps", "params", "libs", "libCodeHashes"]', '["deps", "params", "libs"]')],
        COUNT,
    ),
    (
        "the one order counted 0",
        [(G, ".filter(|o| o.is_object()).map(|_| 1))?,", ".filter(|o| o.is_object()).map(|_| 0))?,")],
        COUNT,
    ),
    ("env_items not an item", [(C, '"members", "env_items", "orders"]', '"members", "orders", "orders"]')], PARSE),
    (
        "the old per-item bound",
        [(C, "const GAS_PER_ITEM_MAX: u64 = 1 << 24;", "const GAS_PER_ITEM_MAX: u64 = 1_000_000;")],
        PARSE,
    ),
    (
        "the per-item bound one above",
        [(C, "const GAS_PER_ITEM_MAX: u64 = 1 << 24;", "const GAS_PER_ITEM_MAX: u64 = (1 << 24) + 1;")],
        PARSE,
    ),
    (
        "per-item keys not kind-qualified",
        [(P, 'per_item(inputs, m, src, f"{kind}:{entry}",', "per_item(inputs, m, src, entry,")],
        GEN,
    ),
    ("orders not an item", [(P, '"env_items", "orders")', '"env_items")')], GEN),
    (
        "the overshoot not stated",
        [(P, "        if keys:\n            src = ", "        if False:\n            src = ")],
        GEN,
    ),
]

if __name__ == "__main__":
    main("gasI1b", MUTANTS)
