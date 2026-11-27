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

JS = "cd clients/clientkeys && node --test --test-name-pattern 'integer-like' test/pqchat.test.js"

# the review's fixes (scratchpad review 2026-11-27, STATUS.md): one mutant per new check
MUTANTS2 = [
    (
        "a kept part not checked canonical on read",
        [(I, "    opaque_ok(b, d)?;\n", "")],
        LIB + "item::tests::a_kept_part_is_canonical",
    ),
    (
        "a kept part's depth from the document's top",
        [(I, "content::write_value_at(&v, d, &mut again)", "content::write_value_at(&v, 0, &mut again)")],
        LIB + "item::tests::a_kept_part_is_canonical",
    ),
    (
        "a kept part refused under a table class",
        [(I, "                | (Field::Opaque(_), _)", "                | (Field::Opaque(_), Class::Opaque)")],
        LIB + "item::tests::what_is_kept_is_written_back",
    ),
    (
        "a null refused under a table class",
        [(I, "                | (Field::Plain(Value::Null), _)\n", "")],
        LIB + "item::tests::what_is_kept_is_written_back",
    ),
    (
        "an empty history read as a history",
        [(I, "Ok(hs) if !hs.is_empty() && hs.iter()", "Ok(hs) if hs.iter()")],
        LIB + "item::tests::what_is_kept_is_written_back",
    ),
    (
        "the history not typed on write",
        [(I, "if h.field.is_empty() || !h.value.of(self.class(&h.field)) {", "if h.field.is_empty() {")],
        LIB + "item::tests::history_is_checked",
    ),
    (
        "values compared by kind, not by text",
        [(I, "(Ok(()), Ok(())) => a.bytes() == b.bytes(),",
          "(Ok(()), Ok(())) => {\n                a.bytes() == b.bytes() && std::mem::discriminant(self) == std::mem::discriminant(o)\n            }")],
        LIB + "item::tests::merge_retypes_by_the_merged_table",
    ),
    (
        "merged fields not retyped",
        [(I, "v.retyped(item.class(k))", "v.clone()")],
        LIB + "item::tests::merge_retypes_by_the_merged_table",
    ),
    (
        "merged history not retyped",
        [(I, "value: h.value.retyped(item.class(&h.field)),", "value: h.value.clone(),")],
        LIB + "item::tests::merge_retypes_by_the_merged_table",
    ),
    (
        "a tombstone against an edit merged field by field",
        [(I, 'if (ours.ty == "deleted") != (theirs.ty == "deleted") && base.ty != "deleted" {',
          'if false && (ours.ty == "deleted") != (theirs.ty == "deleted") && base.ty != "deleted" {')],
        LIB + "item::tests::merge_retypes_by_the_merged_table",
    ),
    (
        "a type in history read as kept",
        [(I, 'if name == "type" || COMMON.contains(&name)', "if COMMON.contains(&name)")],
        LIB + "item::tests::merge_retypes_by_the_merged_table",
    ),
    (
        "no bound on the secrets per item",
        [(I, "    if *n > SECRETS_MAX {", "    if false {")],
        LIB + "item::tests::secrets_per_item_are_bounded",
    ),
    (
        "Debug prints the fields",
        [(I, '"Item({} fields, {} history)",\n            self.fields.len(),',
          '"Item({:?} fields, {} history)",\n            self.fields,')],
        LIB + "item::tests::canonical_round_trip_and_silent_debug",
    ),
    (
        "the quote made over a signature",
        [(V, "        let (entry, args) = call_args(&r, &wraps, &UaSig::default())?;",
          "        let (entry, args) = call_args(&r, &wraps, &UaSig { signature: vec![1], ..UaSig::default() })?;")],
        DEV + "nothing_is_signed_before_the_confirm",
    ),
    (
        "the confirm signs other typed data than the review's",
        [(V, ".sign(&p.at.chain, &p.signer, p.path, p.typed)", ".sign(&p.at.chain, &p.signer, p.path, p.typed + \" \")")],
        DEV + "nothing_is_signed_before_the_confirm",
    ),
    (
        "a failed call after the signature loses the signed record",
        [(V, "        Ok(Confirmed {", "        if call.is_err() {\n            return Err(Error::Shape);\n        }\n        Ok(Confirmed {")],
        DEV + "nothing_is_signed_before_the_confirm",
    ),
    (
        "the payer checked only with rows",
        [(AC, "        crate::op::quote::payer_address(&self.sdk, &payer)?;\n", "")],
        SDK + "quote_app_call_reads_the_gas_rows_before_the_signature",
    ),
    (
        "two arrays of a row's count taken as one",
        [(AC, "        (Some(a), None) => Some(a.len() as u64),", "        (Some(a), _) => Some(a.len() as u64),")],
        "cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 --features app-core "
        "--lib app_core::tests::an_app_rows_count_is_an_arguments_array",
    ),
    (
        "clientkeys' canonical JSON rebuilt as an object",
        [("clients/clientkeys/src/pqchat.js", "      return `{${keys.map((k) => `${JSON.stringify(k)}:${w(x[k])}`).join(\",\")}}`;",
          "      return JSON.stringify(Object.fromEntries(keys.map((k) => [k, JSON.parse(w(x[k]))])));")],
        JS,
        "integer-like",
    ),
]

# the re-check's fixes (scratchpad re-check 2026-11-27, R-1 to R-8) and the owner's D-6 ruling (CLI-PQV-18)
SDKLIB = ("cd clients/scaas-sdk && CARGO_INCREMENTAL=0 ../../scripts/capped cargo test --locked --offline -j2 --features app-core "
          "--lib app_core::tests::an_app_rows_count_is_an_arguments_array")
MUTANTS3 = [
    ("the record's signature counted", [(AC, '.filter(|(k, _)| *k != "sig")', '.filter(|_| true)')], SDKLIB),
    (
        "the writer not held to the secrets bound",
        [(I, "if self.secrets() > SECRETS_MAX {", "if false {")],
        LIB + "item::tests::the_writer_holds_the_secrets_bound",
    ),
    (
        "the merge not trimmed to the secrets bound",
        [(I, "while item.secrets() > SECRETS_MAX && !item.history.is_empty() {", "while false {")],
        LIB + "item::tests::the_writer_holds_the_secrets_bound",
    ),
    (
        "a kept null bounded as a value",
        [(I, "Field::Plain(Value::Null) => {}", "Field::Plain(Value::Null) if false => {}")],
        LIB + "item::tests::kept_nulls_and_misplaced_kept_parts",
    ),
    (
        "a kept part taken where no reader keeps one",
        [(I, "kept_as_read(v, self.class(k))?;", "let _ = kept_as_read;")],
        LIB + "item::tests::kept_nulls_and_misplaced_kept_parts",
    ),
    (
        "a merge un-hides a body",
        [(I, 'if ty == "note" && (ours.hide() || theirs.hide()) {', "if false {")],
        LIB + "item::tests::merge_never_unhides_and_stays_writable",
    ),
    (
        "a losing value too deep recorded",
        [(I, ".filter(|h| check_value(&h.value, 3).is_ok())", ".filter(|_| true)")],
        LIB + "item::tests::merge_never_unhides_and_stays_writable",
    ),
    (
        "typed history beside a kept one",
        [(I, "history.clear();", "let _ = &history;")],
        LIB + "item::tests::merge_never_unhides_and_stays_writable",
    ),
    (
        "a kept custom list's secrets counted",
        [(I, "secret_of(x.value, &mut m)?", "secret_of(x.value, n)?")],
        LIB + "item::tests::kept_custom_lists_count_no_secret_and_merge_debug_is_silent",
    ),
    (
        "a merge's Debug names its fields",
        [(I, 'Merge::Conflict(i, c) => write!(f, "Conflict({i:?}, {} fields)", c.len()),',
          'Merge::Conflict(i, c) => write!(f, "Conflict({i:?}, {c:?})"),')],
        LIB + "item::tests::kept_custom_lists_count_no_secret_and_merge_debug_is_silent",
    ),
    (
        "a higher fresh cost sent on the first confirm",
        [(V, "if f <= r", "if f >= r")],
        DEV + "a_fresh_quote_within_the_review_needs_no_second_confirm",
    ),
    (
        "another payer sent on the first confirm",
        [(V, "&& fresh.payer == r.payer", "")],
        DEV + "a_fresh_quote_within_the_review_needs_no_second_confirm",
    ),
]

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ("--r2", "--r3"):
        flag = sys.argv.pop(1)
        L.main(*(("ui-rules-r2", MUTANTS2) if flag == "--r2" else ("ui-rules-r3", MUTANTS3)))
    else:
        L.main("ui-rules", MUTANTS)
