# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants (owner 2026-11-19, the gas-table rulings and part 3b's split table: sources, opt-in, order of
each part, base + verify, the app's total, the relayed path, the file's checks): python3
clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gas-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Q = "clients/scaas-sdk/src/op/quote.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
L = "clients/scaas-sdk/src/lib.rs"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
I = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --test config "
MUTANTS = [
    # the order of each part (one `part` serves base and verify)
    (
        "the chain's rows not first",
        [(G, "    if let Some(g) = find(chain) {\n        return Some((g, GasFrom::Chain));\n    }\n", "")],
        U + "gas_lookup_order_and_opt_in",
    ),
    (
        "the chain's rows named as reference",
        [(G, "        return Some((g, GasFrom::Chain));", "        return Some((g, GasFrom::Reference));")],
        U + "quote_names_its_gas_source_in_order",
    ),
    (
        "module tables read without opt-in",
        [
            (
                G,
                "    for name in opt_in.iter().filter(|n| *n != REFERENCE) {\n        if let Some(g) = table(name)",
                "    for name in tables.iter().map(|t| &t.name).filter(|n| *n != REFERENCE) {\n        if let Some(g) = table(name)",
            )
        ],
        U + "gas_lookup_order_and_opt_in",
    ),
    (
        "the reference read as a module (before the other modules)",
        [(G, "opt_in.iter().filter(|n| *n != REFERENCE)", "opt_in.iter().filter(|_| true)")],
        U + "gas_lookup_order_and_opt_in",
    ),
    (
        "the reference read without opt-in",
        [(G, "    if opt_in.iter().any(|n| n == REFERENCE) {", "    if true {")],
        U + "an_operation_without_a_gas_row_is_gas_unquoted",
    ),
    # each part's key and the sum
    (
        "the base row's lane state ignored",
        [
            (
                G,
                ".find(|b| b.key() == (entry, kind, fresh))",
                ".find(|b| (b.entry.as_str(), b.kind.as_str()) == (entry, kind))",
            )
        ],
        U + "an_operation_without_a_gas_row_is_gas_unquoted",
    ),
    (
        "the base row's domain kind ignored",
        [(G, ".find(|b| b.key() == (entry, kind, fresh))", ".find(|b| (b.entry.as_str(), b.fresh) == (entry, fresh))")],
        U + "gas_parts_are_looked_up_independently",
    ),
    (
        "the verify row's signer ignored",
        [(G, "r.verify.iter().find(|v| v.signer == signer)", "r.verify.iter().find(|_| true)")],
        U + "an_operation_without_a_gas_row_is_gas_unquoted",
    ),
    (
        "the verify part not added",
        [
            (
                G,
                "Some((b.saturating_add(v), GasSources { base, verify }))",
                "Some((b.saturating_add(v - v), GasSources { base, verify }))",
            )
        ],
        U + "gas_lookup_order_and_opt_in",
    ),
    (
        "the verify part read with the base part's order (base source for both)",
        [
            (
                G,
                "Some((b.saturating_add(v), GasSources { base, verify }))",
                "Some((b.saturating_add(v), GasSources { verify: base.clone(), base }))",
            )
        ],
        U + "quote_names_its_gas_source_in_order",
    ),
    (
        "the base part read as the verify part's (verify source for both)",
        [
            (
                G,
                "Some((b.saturating_add(v), GasSources { base, verify }))",
                "Some((b.saturating_add(v), GasSources { base: verify.clone(), verify }))",
            )
        ],
        U + "gas_parts_are_looked_up_independently",
    ),
    # the app's total
    (
        "the app's figure ignored",
        [(G, "        _ => app.map(|g| (g, GasSources::both(GasFrom::App))),", "        _ => app.and(None),")],
        U + "quote_names_its_gas_source_in_order",
    ),
    (
        "the app's figure added to a part found",
        [
            (
                G,
                "        _ => app.map(|g| (g, GasSources::both(GasFrom::App))),",
                "        (Some((b, _)), None) => app.map(|g| (g + b, GasSources::both(GasFrom::App))),\n"
                "        _ => app.map(|g| (g, GasSources::both(GasFrom::App))),",
            )
        ],
        U + "gas_parts_are_looked_up_independently",
    ),
    (
        "the app's figure before the tables",
        [
            (
                G,
                "    let (entry, kind, signer, fresh) = key;\n",
                "    let (entry, kind, signer, fresh) = key;\n    if let Some(g) = app {\n        return Some((g, GasSources::both(GasFrom::App)));\n    }\n",
            )
        ],
        U + "gas_lookup_order_and_opt_in",
    ),
    (
        "an app figure above max_gas accepted",
        [(Q, "        if gas > self.sdk.limits.max_gas {", "        if false {")],
        U + "quote_names_its_gas_source_in_order",
    ),
    # the paths
    (
        "the gateway quote drops the gas",
        [(Q, "                    gas: figure.as_ref().map(|f| f.0),", "                    gas: None,")],
        U + "gateway_quote_carries_gas_or_reports_it_unquoted",
    ),
    (
        "a relayed quote without a figure refused",
        [
            (
                Q,
                "                        return Ok(gateway());",
                "                        if figure.is_none() {\n                            return Err(SdkError::GasUnquoted);\n                        }\n                        return Ok(gateway());",
            )
        ],
        U + "gateway_quote_carries_gas_or_reports_it_unquoted",
    ),
    (
        "a self-relay without a figure estimated",
        [
            (
                Q,
                "    } else if relayed {\n        return Err(SdkError::GasUnquoted);",
                "    } else if false {\n        return Err(SdkError::GasUnquoted);",
            )
        ],
        U + "an_operation_without_a_gas_row_is_gas_unquoted",
    ),
    # the file
    (
        "the file: a figure not a multiple of 1,000",
        [(C, "    gas.is_multiple_of(1_000) && measured", "    measured")],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: 1,000 above the measurement accepted",
        [(C, "gas - measured < 1_000", "gas - measured <= 1_000")],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: measured above the table accepted",
        [(C, " && measured <= gas && ", " && gas >= 0 && ")],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: a base figure of zero accepted",
        [(C, "                gas: figure(r).filter(|g| *g > 0)?,", "                gas: figure(r)?,")],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: one base key twice",
        [(C, "            if rows.base.iter().any(|o| o.key() == row.key()) {", "            if false {")],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: one signer twice",
        [(C, "            if rows.verify.iter().any(|o| o.signer == row.signer) {", "            if false {")],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: version 1 accepted",
        [(C, 'v.get("v")?.as_u64()? != 2', 'v.get("v")?.as_u64()? > 2')],
        U + "gas_table_parse_checks",
    ),
    (
        "the file: the row bound on base rows only",
        [(C, "if base.len().saturating_add(verify.len()) > GAS_TABLE_MAX_ROWS", "if base.len() > GAS_TABLE_MAX_ROWS")],
        U + "gas_table_parse_checks",
    ),
    (
        "a reference row away from its source",
        [("clients/scaas-sdk/gas/reference.json", '"measured": 151958,', '"measured": 151000,')],  # part 3b's table
        U + "reference_rows_hold_their_sources",
    ),
    (
        "open: an opt-in naming no table",
        [(L, " && gas_tables.iter().any(|t| &t.name == n))", ")")],
        I + "open_checks_gas_tables_and_opt_ins",
    ),
    (
        "open: a module table named reference",
        [(L, 'if t.name == "reference" || t.family', "if t.family")],
        I + "open_checks_gas_tables_and_opt_ins",
    ),
]

if __name__ == "__main__":
    main("gas", MUTANTS)
