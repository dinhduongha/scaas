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
    ("base per_item not added", [(G, "        g = g.saturating_add(items(&b.per_item, reg, op.count)?);\n", "")], ADD),
    ("verify per_item not added", [(G, "                .saturating_add(items(&v.per_item)?),\n", ",\n")], ADD),
    ("the signer's verify row reads no count", [(G, "signer, op.registry, true, &own);", "signer, op.registry, true, &attached);")], ADD),
    ("an attached signature's count read as the operation's",
     [(G, "    let attached = |p: &Option<GasPerItem>| items(p, false, &|_| None);", "    let attached = |p: &Option<GasPerItem>| items(p, false, op.count);")],
     ADD),
    ("not saturating", [(G, "        Some(per.saturating_mul(n?))", "        Some(per.wrapping_mul(n?))")], ADD),
    # fail closed: a count unknown or above the bound
    ("an unknown count falls through (no refusal)", [(G, "    if uncounted.get() {\n        return Err(SdkError::GasCountUnknown);\n    }\n    let execute", "    if false && uncounted.get() {\n        return Err(SdkError::GasCountUnknown);\n    }\n    let execute")], ADD),
    ("an unknown count read as 0",
     [(G, "count(&p.item).filter(|n| *n <= COUNT_MAX && p.measured_max.is_none_or(|m| *n <= m));", "Some(count(&p.item).unwrap_or(0));")], ADD),
    ("the count unbounded", [(G, "count(&p.item).filter(|n| *n <= COUNT_MAX && p.measured_max.is_none_or(|m| *n <= m));", "count(&p.item);")], ADD),
    ("the bound off by one", [(G, "filter(|n| *n <= COUNT_MAX && p.measured_max", "filter(|n| *n < COUNT_MAX && p.measured_max")], ADD),
    # the count read from the operation
    ("legs: args.legs not read", [(G, '        "legs" => len(message.get("args").and_then(|a| a.get("legs")))\n',
                                   '        "legs" => len(message.get("legs"))\n')], COUNT),
    ("accounts: uas not read",
     [(G, '        "accounts" => len(message.get("uas")).or_else(|| len(message.get("accounts")))?,',
       '        "accounts" => len(message.get("accounts"))?,')], COUNT),
    ("entries: a decimal n not read", [(G, "let n = super::dec(message.get(\"n\")?).ok()?;",
                                        "let n = alloy::primitives::U256::from(message.get(\"n\")?.as_u64()?);")], COUNT),
    ("the quote reads no count", [(Q, "            _ => super::gas::item_count(extra, message, item),",
                                   "            _ => None,")], QUOTE),
    ("the quote drops the refusal", [(Q, "                    unsigned.calldata.len(),\n                    members,\n                )?;",
                                      "                    unsigned.calldata.len(),\n                    members,\n                )\n                .ok()\n                .flatten();")],
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
