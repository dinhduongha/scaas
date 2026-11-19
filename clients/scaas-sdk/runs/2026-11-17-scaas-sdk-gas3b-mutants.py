# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""scaas-sdk gas-table mutants of part 3b's measurement round (owner 2026-11-19, rulings A-C: the per-byte part, its parse,
the operation's input length, the generated reference table and its coverage): python3
clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gas3b-mutants.py check | run"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from mutants_lib import main

Q = "clients/scaas-sdk/src/op/quote.rs"
G = "clients/scaas-sdk/src/op/gas.rs"
C = "clients/scaas-sdk/src/config.rs"
R = "clients/scaas-sdk/gas/reference.json"
P = "clients/scaas-sdk/src/op/prepared.rs"
U = "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 --lib "
W = (
    "cd clients/scaas-sdk && ../../scripts/capped cargo test --locked --offline -j2 "
    "--features vault,account,wallet,zether,pqz,pqz-set-n2304-kmax4096,dex,admin --test wallet_ops "
)
MUTANTS = [
    (
        "the per-byte part ignored",
        [
            (
                G,
                "Some(p) => Some(b.gas.saturating_add(p.gas.saturating_mul(len(&p.input)?))),",
                "Some(_) => Some(b.gas),",
            )
        ],
        U + "gas_per_byte_part_adds_the_inputs_length",
    ),
    (
        "a missing input answers as 0",
        [(G, "p.gas.saturating_mul(len(&p.input)?)", "p.gas.saturating_mul(len(&p.input).unwrap_or(0))")],
        U + "gas_per_byte_part_adds_the_inputs_length",
    ),
    ("data counted in hex digits", [(G, "            h.len() / 2\n", "            h.len()\n")], U + "gas_per_byte"),
    (
        "odd hex data accepted",
        [(G, "            if h.len() % 2 != 0 {\n                return None;\n            }\n", "")],
        U + "gas_per_byte",
    ),
    (
        "the body's length read as 0",
        [(G, "            .body\n            .len(),", "            .body\n            .len() * 0,")],
        U + "gas_per_byte",
    ),
    (
        "the quote passes no input length",
        [(Q, "&|input| super::gas::input_len(&prepared.t.extra, &prepared.t.message, input),", "&|_| Some(0),")],
        W + "pay_with_paymeta_v3",
    ),
    (
        "parse: any per-byte input",
        [(C, "                                .filter(|i| GAS_PER_BYTE_INPUTS.contains(&i.as_str()))?,", "?,")],
        U + "gas_table_per_byte_parse",
    ),
    (
        "parse: a per-byte gas of 0",
        [(C, ".filter(|g| (1..=GAS_PER_BYTE_MAX).contains(g))?,", ".filter(|g| *g <= GAS_PER_BYTE_MAX)?,")],
        U + "gas_table_per_byte_parse",
    ),
    (
        "parse: no per-byte bound",
        [(C, ".filter(|g| (1..=GAS_PER_BYTE_MAX).contains(g))?,", ".filter(|g| *g >= 1)?,")],
        U + "gas_table_per_byte_parse",
    ),
    (
        "parse: a per-byte part without source",
        [(C, '                        p.get("source")?.as_str().filter(|s| !s.is_empty())?;\n', "")],
        U + "gas_table_per_byte_parse",
    ),
    (
        "parse: the per-byte part dropped",
        [(C, 'per_byte: match r.get("per_byte") {', "per_byte: match None::<&serde_json::Value> {")],
        U + "gas_table_per_byte_parse",
    ),
    (
        "a reference row away from its source",
        [(R, '"measured": 151937,', '"measured": 151000,')],
        U + "reference_rows_hold_their_sources",
    ),
    (
        "a reference per-byte part away from its source",
        [
            (
                R,
                'used_mandate",\n      "per_byte": {\n        "input": "data",\n        "gas": 1,',
                'used_mandate",\n      "per_byte": {\n        "input": "data",\n        "gas": 2,',
            )
        ],
        U + "reference_rows_hold_their_sources",
    ),
    (
        "a quotable key without its row",
        [(P, '    ("mtxDelegateRevoke", &["wallet"]),\n', "")],
        U + "reference_table_covers_every_quotable_key",
    ),
    (
        "a measured key left as unmeasured",
        [
            (
                P,
                '    ("mtxAcceptAdmin", &["gov_router"]),',
                '    ("mtxAcceptAdmin", &["gov_router"]),\n    ("mtxBurn", &["token"]),',
            )
        ],
        U + "reference_table_covers_every_quotable_key",
    ),
    (
        "a verify kind unmeasured but listed as measured",
        [(P, "&[0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135]", "&[0x0130, 0x0131, 0x0132, 0x0133, 0x0134]")],
        U + "reference_table_covers_every_quotable_key",
    ),
]

if __name__ == "__main__":
    main("gas3b", MUTANTS)
