# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the owner's ruling I1 of 2026-11-19, part 1 ("Approved all 4 as proposed"): a base or
verify row's `per_item` adds its gas times the count the operation names; a count the SDK cannot read, or above the bound,
refuses the operation by name (`GasCountUnknown`); the parse refuses an unpaired `item` / `per_item` (`GasItemUnpaired`) and
an unknown `item` (`GasItemUnknown`): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gasI1-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
Q = "clients/scaas-sdk/src/op/quote.rs"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
ADD = U + "gas_per_item_adds_gas_times_its_count"
COUNT = U + "item_count_reads_the_operations_counts"
PARSE = U + "gas_table_per_item_parse"
QUOTE = U + "a_counted_row_quotes_its_count_or_refuses"
MUTANTS = [
    # the quote: gas + per_item × count
    ("base per_item not added", [(G, "        g = g.saturating_add(own(&b.per_item)?);\n", "")], ADD),
    ("verify per_item not added", [(G, "                .saturating_add(items(&v.per_item)?),\n", ",\n")], ADD),
    ("the signer's verify row reads no count", [(G, "signer, true, &own);", "signer, true, &attached);")], ADD),
    ("an attached signature's count read as the operation's",
     [(G, "    let attached = |p: &Option<GasPerItem>| items(p, &|_| None);", "    let attached = |p: &Option<GasPerItem>| items(p, op.count);")],
     ADD),
    ("not saturating", [(G, "        Some(p.gas.saturating_mul(n?))", "        Some(p.gas.wrapping_mul(n?))")], ADD),
    # fail closed: a count unknown or above the bound
    ("an unknown count falls through (no refusal)", [(G, "    if uncounted.get() {\n", "    if false && uncounted.get() {\n")], ADD),
    ("an unknown count read as 0",
     [(G, "        let n = count(&p.item).filter(|n| *n <= COUNT_MAX);", "        let n = Some(count(&p.item).unwrap_or(0));")], ADD),
    ("the count unbounded", [(G, "        let n = count(&p.item).filter(|n| *n <= COUNT_MAX);", "        let n = count(&p.item);")], ADD),
    ("the bound off by one", [(G, "filter(|n| *n <= COUNT_MAX);", "filter(|n| *n < COUNT_MAX);")], ADD),
    # the count read from the operation
    ("legs: args.legs not read", [(G, '        "legs" => len(message.get("args").and_then(|a| a.get("legs")))\n',
                                   '        "legs" => len(message.get("legs"))\n')], COUNT),
    ("accounts: uas not read",
     [(G, '        "accounts" => len(message.get("uas")).or_else(|| len(message.get("accounts")))?,',
       '        "accounts" => len(message.get("accounts"))?,')], COUNT),
    ("entries: a decimal n not read", [(G, "            return n.as_u64().or_else(|| n.as_str()?.parse().ok());",
                                        "            return n.as_u64();")], COUNT),
    ("the quote reads no count", [(Q, "                        count: &|item| super::gas::item_count(message, item),",
                                   "                        count: &|_| None,")], QUOTE),
    ("the quote drops the refusal", [(Q, "                        &op,\n                    )?\n",
                                      "                        &op,\n                    )\n                    .ok()\n                    .flatten()\n")],
     QUOTE),
    # the parse
    ("an unpaired item / per_item accepted",
     [(C, "            named.get_or_insert(crate::SdkError::GasItemUnpaired);\n", "")], PARSE),
    ("an unknown item accepted",
     [(C, "        named.get_or_insert(crate::SdkError::GasItemUnknown);\n        return Some(None);\n", "")], PARSE),
    ("an unknown item refused as Argument",
     [(C, "        named.get_or_insert(crate::SdkError::GasItemUnknown);\n        return Some(None);\n", "        return None;\n")],
     PARSE),
    ("base_count not enforced", [(C, '    (p.get("base_count")?.as_u64()? == 0).then_some(())?;\n', "")], PARSE),
    ("the per-item gas unbounded", [(C, "(1..=GAS_PER_ITEM_MAX).contains(g)", "(1..=u64::MAX).contains(g)")], PARSE),
    ("an unpaired part not checked", [(C, "            if let Some(p) = p {\n                per_item_gas(p)?;\n            }\n", "")],
     PARSE),
]

if __name__ == "__main__":
    main("gasI1", MUTANTS)
