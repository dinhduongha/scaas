# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of the rulings of 2026-11-19 ("approved all five": a saved record's `save`, `sig_bytes`,
`fee_extra`, the payee-fee entry's second signature, `mtxExecute`'s inner call) and the PQ verify rows: python3
clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gas3c-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Q = "clients/scaas-sdk/src/op/quote.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
R = "clients/scaas-sdk/gas/reference.json"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
W = (
    "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 "
    "--features vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin,classical-roots --test wallet_ops "
)
SAVE_PARSE = 'save: match r.get("save") {\n                    None => None,\n                    Some(x) => Some(figure(x).filter(|g| *g > 0)?),'
MUTANTS = [
    # ruling 1: save
    ("save not added", [(G, "            g = g.saturating_add(b.save?);\n", "            b.save?;\n")], U + "gas_save_fee"),
    ("a saving operation on a row without save answers", [(G, "b.save?);", "b.save.unwrap_or(0));")], U + "gas_save_fee"),
    ("the quote never saves", [(Q, ".is_ok_and(|m| m.save)", ".is_ok_and(|_| false)")], W + "pay_with_paymeta_v3"),
    ("parse: save dropped", [(C, 'save: match r.get("save") {', "save: match None::<&serde_json::Value> {")],
     U + "gas_table_extra_fields_parse"),
    ("parse: save not held to its measurement",
     [(C, SAVE_PARSE, SAVE_PARSE.replace("figure(x).filter(|g| *g > 0)?", 'x.get("gas")?.as_u64()?'))],
     U + "gas_table_extra_fields_parse"),
    # ruling 2: sig_bytes
    ("sig_bytes not added",
     [(G, ".saturating_add(b.saturating_mul(PER_BYTE))", ".saturating_add(0)")],
     U + "gas_save_fee"),
    ("sig_bytes at 16 gas a byte", [(G, "b.saturating_mul(PER_BYTE)", "b.saturating_mul(16)")],
     U + "gas_save_fee"),
    ("parse: sig_bytes unbounded",
     [(C, "Some(b) => b.as_u64().filter(|b| *b <= GAS_SIG_BYTES_MAX)?,", "Some(b) => b.as_u64()?,")],
     U + "gas_table_extra_fields_parse"),
    ("parse: sig_bytes dropped", [(C, 'sig_bytes: match r.get("sig_bytes") {', "sig_bytes: match None::<&serde_json::Value> {")],
     U + "gas_table_extra_fields_parse"),
    ("reference: a sig_bytes away from its measurement", [(R, '"sig_bytes": 7872', '"sig_bytes": 7871')],
     U + "reference_rows_hold_their_sources"),
    # ruling 3: fee_extra
    ("fee_extra not added", [(G, "g = g.saturating_add(b.fee_extra.unwrap_or(0));", "g = g.saturating_add(0);")],
     U + "gas_save_fee"),
    ("fee_extra added without a fee", [(G, "        if op.fee {\n", "        if true {\n")], U + "gas_save_fee"),
    ("the quote reads no fee", [(Q, "fee: fee.bytes().any(|b| b != b'0'),", "fee: false,")], W + "pay_with_paymeta_v3"),
    ("parse: fee_extra dropped",
     [(C, 'fee_extra: match r.get("fee_extra") {', "fee_extra: match None::<&serde_json::Value> {")],
     U + "gas_table_extra_fields_parse"),
    # ruling 4: the second signature
    ("a known second signature ignored",
     [(G, "Some(Some(k)) => verify_part(chain, opt_in, tables, k, false, &attached).map(|v| v.0),", "Some(Some(_)) => Some(0),")],
     U + "gas_second_signature"),
    ("an unknown second signature: the cheapest",
     [(G, ".try_fold(0, |m, v| v.map(|v| m.max(v))),", ".try_fold(u64::MAX, |m, v| v.map(|v| m.min(v))),")],
     U + "gas_second_signature"),
    ("an unknown second signature: a kind without a row skipped",
     [(G, ".try_fold(0, |m, v| v.map(|v| m.max(v))),", ".try_fold(0, |m, v| Some(m.max(v.unwrap_or(0)))),")],
     U + "gas_second_signature"),
    ("attached: empty key data native on any id",
     [(G, "return scaas_ua::in_native_space(&from).then_some(NATIVE_EVM);", "return Some(NATIVE_EVM);")],
     U + "attached_signature_kind"),
    ("attached: members ignored",
     [(G, '        if !sig.get("members")?.as_array()?.is_empty() {\n            return None;\n        }\n', "")],
     U + "attached_signature_kind"),
    ("attached: the first accepted kind", [(G, ".find(|k| scaas_ua::ua_of(*k, &kd).ok() == Some(from))", ".find(|_| true)")],
     U + "attached_signature_kind"),
    ("the quote attaches nothing", [(Q, "attached: super::gas::attached_kind(extra, message),", "attached: None,")],
     W + "payee_fee_quotes_the_attached_signature"),
    # ruling 5: mtxExecute's inner call
    ("execute: the app figure not added", [(G, "let inner = if execute { app } else { Some(0) };", "let inner = Some(0);")],
     U + "gas_execute_inner_call"),
    ("execute: the inner figure optional", [(G, "if execute { app } else { Some(0) }", "if execute { Some(app.unwrap_or(0)) } else { Some(0) }")],
     U + "gas_execute_inner_call"),
    ("execute: the app figure as a total", [(G, "        _ if execute => None,\n", "")], U + "gas_execute_inner_call"),
    # item 6: the PQ verify rows
    ("reference: a PQ verify row away from its measurement", [(R, "\"measured\": 4823423", "\"measured\": 4822985")],
     U + "reference_rows_hold_their_sources"),
]

if __name__ == "__main__":
    main("gas3c", MUTANTS)
