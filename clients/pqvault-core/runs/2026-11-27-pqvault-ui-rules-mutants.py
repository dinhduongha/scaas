# SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
"""CLI-SDK-36 and CLI-PQV-16 H1-H3 in pqvault-core (branch pqvault-ui-rules): a mutant of each new check, the scaas-sdk plan's
`mutants_lib` with this crate's record: python3 clients/pqvault-core/runs/2026-11-27-pqvault-ui-rules-mutants.py check | run
[name...]. Each test command goes through scripts/capped, foreground (mutant_guard's deadline and restore)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "scaas-sdk" / "runs"))
import mutants_lib as L  # noqa: E402

R = "clients/pqvault-core/runs"
L.OUT = Path(__file__).parent
L.PREFIX = "2026-11-27-pqvault-"
L.RUNS = R
L.NOT_CODE = [f":!{R}/*-mutants.txt", f":!{R}/2026-11-22-pqvault-core-summary.txt"]

I = "clients/pqvault-core/src/item.rs"
C = "clients/pqvault-core/src/content.rs"
V = "clients/pqvault-core/src/vault.rs"
AC = "clients/scaas-sdk/src/app_core.rs"
CD = "cd clients/pqvault-core && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
LIB = CD + "--lib "
DEV = CD + "--test devices "
VEC = CD + "--features vectors --test vectors "
SDK = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 "
       "--features app-core --test app_core ")

MUTANTS = [
    # CLI-SDK-36: nothing signed before the confirm, one signing call on it
    (
        "a write signed when it is prepared",
        [(V, "        let (entry, args) = call_args(&r, &wraps, &UaSig::default())?;",
          "        let _ = self.net.sign(&at.chain, signer, path_of(mode, at), typed.clone()).await;\n"
          "        let (entry, args) = call_args(&r, &wraps, &UaSig::default())?;")],
        DEV + "nothing_is_signed_before_the_confirm",
    ),
    (
        "the confirm makes no signing call",
        [(V, """        let s = self
            .net
            .sign(&p.at.chain, &p.signer, p.path, p.typed)
            .await?;
        let sig = sig_of_signed(s);""", "        let sig = UaSig::default();")],
        DEV + "nothing_is_signed_before_the_confirm",
    ),
    (
        "the quote reads a fresh row (never the entry's)",
        [(AC, '            (&f.name, "app", kind, false),', '            (&f.name, "app", kind, true),')],
        SDK + "quote_app_call_reads_the_gas_rows_before_the_signature",
    ),
    # CLI-PQV-16 H1-H3: the table, the kinds, the history, Debug, the canonical read
    (
        "a card number not secret",
        [(I, '        &["number", "code", "pin"],', '        &["code", "pin"],')],
        LIB + "item::tests::the_secret_table",
    ),
    (
        "hideBody ignored",
        [(I, '    if secret.contains(&name) || (ty == "note" && name == "body" && hide) {',
          "    if secret.contains(&name) {")],
        LIB + "item::tests::the_secret_table",
    ),
    (
        "a custom field's secret flag ignored",
        [(I, "                let value = if x.secret {", "                let value = if false && x.secret {")],
        LIB + "item::tests::custom_fields_declare_secret",
    ),
    (
        "a field of the wrong kind written",
        [(I, '            if !v.of(self.class(k)) || k == "type" || k == "history" {',
          '            if k == "type" || k == "history" {')],
        LIB + "item::tests::a_field_of_the_wrong_kind_is_refused",
    ),
    (
        "the losing secret kept as plain text",
        [(I, "                value: tv.cloned().unwrap_or(Field::Plain(Value::Null)),",
          "                value: match tv.cloned() {\n"
          "                    Some(Field::Secret(x)) => Field::Plain(Value::String(\n"
          "                        x.with(|b| String::from_utf8_lossy(b).into_owned()),\n"
          "                    )),\n"
          "                    x => x.unwrap_or(Field::Plain(Value::Null)),\n"
          "                },")],
        LIB + "item::tests::merge_keeps_the_losing_secret_secret",
    ),
    (
        "a history value read as plain",
        [(I, "                        let value = read_field(class(&ty, &h.field, hide), h.value)?;",
          "                        let value = read_field(Class::Plain, h.value)?;")],
        LIB + "item::tests::merge_keeps_the_losing_secret_secret",
    ),
    (
        "Debug prints a secret",
        [(I, "        f.write_str(self.kind())",
          "        match self {\n"
          "            Field::Secret(s) => s.with(|b| f.write_str(&String::from_utf8_lossy(b))),\n"
          "            _ => f.write_str(self.kind()),\n"
          "        }")],
        LIB + "item::tests::canonical_round_trip_and_silent_debug",
    ),
    (
        "an item's canonical form not compared on read",
        [(I, "        if again.bytes() != b {", "        if again.bytes() != b && false {")],
        LIB + "item::tests::canonical_round_trip_and_silent_debug",
    ),
    (
        "a newline escaped another way than serde_json's",
        [(C, '            10 => out.put(b"\\\\n")?,', "")],
        VEC + "item_versions_and_refusals",
    ),
]

if __name__ == "__main__":
    L.main("ui-rules", MUTANTS)
