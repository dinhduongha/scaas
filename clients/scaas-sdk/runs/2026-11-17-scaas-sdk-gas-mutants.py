# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants (owner 2026-11-19, the gas-table rulings: sources, opt-in, order, app figure, the relayed
path, the file's checks): python3 clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gas-mutants.py check | run"""
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
    ("the chain's rows not first",
     [(G, "    if let Some(g) = find(measured) {\n        return Some((g, GasFrom::Chain));\n    }\n", "")],
     U + "gas_lookup_order_and_opt_in"),
    ("the chain's rows named as reference",
     [(G, "        return Some((g, GasFrom::Chain));", "        return Some((g, GasFrom::Reference));")],
     U + "quote_names_its_gas_source_in_order"),
    ("module tables read without opt-in",
     [(G, "    for name in opt_in.iter().filter(|n| *n != REFERENCE) {\n        if let Some(g) = table(name)",
       "    for name in tables.iter().map(|t| &t.name).filter(|n| *n != REFERENCE) {\n        if let Some(g) = table(name)")],
     U + "gas_lookup_order_and_opt_in"),
    ("the reference read as a module (before the other modules)",
     [(G, "opt_in.iter().filter(|n| *n != REFERENCE)", "opt_in.iter().filter(|_| true)")],
     U + "gas_lookup_order_and_opt_in"),
    ("the reference read without opt-in",
     [(G, "    if opt_in.iter().any(|n| n == REFERENCE) {", "    if true {")],
     U + "an_operation_without_a_gas_row_is_gas_unquoted"),
    ("the app's figure ignored", [(G, "    app.map(|g| (g, GasFrom::App))", "    app.and(None)")],
     U + "quote_names_its_gas_source_in_order"),
    ("an app figure above max_gas accepted", [(Q, "        if gas > self.sdk.limits.max_gas {", "        if false {")],
     U + "quote_names_its_gas_source_in_order"),
    ("the gateway quote drops the gas", [(Q, "                    gas: figure.as_ref().map(|f| f.0),", "                    gas: None,")],
     U + "gateway_quote_carries_gas_or_reports_it_unquoted"),
    ("a relayed quote without a figure refused",
     [(Q, "                        return Ok(gateway());",
       "                        if figure.is_none() {\n                            return Err(SdkError::GasUnquoted);\n                        }\n                        return Ok(gateway());")],
     U + "gateway_quote_carries_gas_or_reports_it_unquoted"),
    ("a self-relay without a figure estimated",
     [(Q, "    } else if relayed {\n        return Err(SdkError::GasUnquoted);", "    } else if false {\n        return Err(SdkError::GasUnquoted);")],
     U + "an_operation_without_a_gas_row_is_gas_unquoted"),
    ("the file: a figure not a multiple of 1,000", [(C, "                || !row.gas.is_multiple_of(1_000)\n", "")],
     U + "gas_table_parse_checks"),
    ("the file: 1,000 above the measurement accepted",
     [(C, "                || row.gas - measured >= 1_000", "                || row.gas - measured > 1_000")], U + "gas_table_parse_checks"),
    ("the file: measured above the table accepted", [(C, "                || measured > row.gas\n", "")],
     U + "gas_table_parse_checks"),
    ("the file: one key twice", [(C, "            if out.iter().any(|o| o.key() == row.key()) {", "            if false {")],
     U + "gas_table_parse_checks"),
    ("a reference row away from its source",
     [("clients/scaas-sdk/gas/reference.json", '"measured": 72665,', '"measured": 72600,')],
     U + "reference_rows_hold_their_sources"),
    ("open: an opt-in naming no table", [(L, " && gas_tables.iter().any(|t| &t.name == n))", ")")],
     I + "open_checks_gas_tables_and_opt_ins"),
    ("open: a module table named reference", [(L, 'if t.name == "reference" || t.family', "if t.family")],
     I + "open_checks_gas_tables_and_opt_ins"),
]

if __name__ == "__main__":
    main("gas", MUTANTS)
