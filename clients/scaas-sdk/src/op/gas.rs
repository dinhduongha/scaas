// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The gas of an operation's quote (owner 2026-11-18, ruling 1; owner 2026-11-19, ruling B and the gas-table rulings; spec
//! §13.3). A quote never makes or sends a signature, so its gas comes from tables keyed by what changes the cost: the entry,
//! the domain kind, the signer's kind and whether the lane is used for the first time. The SDK carries no gas figure in code.
//! Lookup order: the chain's measured rows ([`crate::ChainProfile::gas`]) → the module tables the profile opts in to, in its
//! order → the SCaaS reference table (`gas/reference.json`, data beside the SDK) if the profile opts in → the figure the app
//! passes on the call (at most `Limits::max_gas`) → none. The quote names the source ([`GasFrom`]). Without a figure a
//! self-relay is `GasUnquoted`; a relayed (gateway) quote reports the gas as unquoted and is not refused for it. EVM only
//! today; every family follows the same principle with its own row shape (spec §13.3).
use crate::{GasRow, GasTable};

/// A native EVM key's signer kind in the table.
pub const NATIVE_EVM: u16 = 0;

/// The name a profile opts in to for the SCaaS reference table.
pub const REFERENCE: &str = "reference";

/// The SCaaS reference table's file, generated from the forge measurement; data, not code.
pub(crate) const REFERENCE_FILE: &str = include_str!("../../gas/reference.json");

/// Where a quote's gas figure came from (owner 2026-11-19), so the app and the operator see a figure not measured on the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GasFrom {
    /// a row of the chain profile, measured on that chain
    Chain,
    /// a row of the named module table, the profile having opted in
    Module(String),
    /// a row of the SCaaS reference table, the profile having opted in; not measured on this chain
    Reference,
    /// the figure the app passed on the call
    App,
    /// a native send's own estimate (or 21,000 for a plain transfer to an account without code)
    Estimate,
}

/// The transaction's base cost and calldata at the highest price per byte (EIP-7976's floor, 64 gas a byte).
const INTRINSIC: u64 = 21_000;
const PER_BYTE: u64 = 64;

/// The stated margin: the figure plus half of it.
pub(crate) fn with_margin(g: u64) -> u64 {
    g.saturating_add(g / 2)
}

/// The execution gas of the key and its source, in the lookup order; `None`: no figure anywhere.
pub(crate) fn lookup(
    measured: &[GasRow],
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
) -> Option<(u64, GasFrom)> {
    let find = |rows: &[GasRow]| rows.iter().find(|r| r.key() == key).map(|r| r.gas);
    let table = |name: &str| tables.iter().find(|t| t.name == name);
    if let Some(g) = find(measured) {
        return Some((g, GasFrom::Chain));
    }
    for name in opt_in.iter().filter(|n| *n != REFERENCE) {
        if let Some(g) = table(name).and_then(|t| find(&t.rows)) {
            return Some((g, GasFrom::Module(name.clone())));
        }
    }
    if opt_in.iter().any(|n| n == REFERENCE) {
        if let Some(g) = table(REFERENCE).and_then(|t| find(&t.rows)) {
            return Some((g, GasFrom::Reference));
        }
    }
    app.map(|g| (g, GasFrom::App))
}

/// The quote's gas of a key whose unsigned calldata is `len` bytes: the figure plus the intrinsic cost and the calldata, with
/// the margin, and its source; `None`: unquoted.
pub(crate) fn quoted(
    measured: &[GasRow],
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
    len: usize,
) -> Option<(u64, GasFrom)> {
    let (g, from) = lookup(measured, opt_in, tables, app, key)?;
    let bytes = u64::try_from(len)
        .unwrap_or(u64::MAX)
        .saturating_mul(PER_BYTE);
    Some((
        with_margin(g.saturating_add(INTRINSIC).saturating_add(bytes)),
        from,
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn row(entry: &str, gas: u64) -> GasRow {
        GasRow {
            entry: entry.into(),
            kind: "token".into(),
            signer: 0x0101,
            fresh: false,
            gas,
        }
    }

    fn table(name: &str, rows: Vec<GasRow>) -> GasTable {
        GasTable {
            name: name.into(),
            family: "evm".into(),
            rows,
        }
    }

    const K: (&str, &str, u16, bool) = ("mtxPay", "token", 0x0101, false);

    /// The order: chain → module (opted in, in the profile's order) → reference (opted in) → app → none; each step only when
    /// the earlier ones have no row, and a table not opted in is never read.
    #[test]
    fn gas_lookup_order_and_opt_in() {
        let tables = vec![
            table("vault", vec![row("mtxPay", 2_000)]),
            table("other", vec![row("mtxPay", 3_000)]),
            table(REFERENCE, vec![row("mtxPay", 4_000)]),
        ];
        let all = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let chain = vec![row("mtxPay", 1_000)];
        let l = |m: &[GasRow], o: &[String], app| lookup(m, o, &tables, app, K);
        assert_eq!(
            l(&chain, &all(&["vault", REFERENCE]), Some(9)),
            Some((1_000, GasFrom::Chain))
        );
        assert_eq!(
            l(&[], &all(&[REFERENCE, "vault"]), Some(9)),
            Some((2_000, GasFrom::Module("vault".into()))),
            "a module before the reference, whatever the list's order"
        );
        assert_eq!(
            l(&[], &all(&["other", "vault"]), None),
            Some((3_000, GasFrom::Module("other".into()))),
            "modules in the profile's order"
        );
        assert_eq!(
            l(&[], &all(&[REFERENCE]), Some(9)),
            Some((4_000, GasFrom::Reference))
        );
        assert_eq!(
            l(&[], &[], Some(9)),
            Some((9, GasFrom::App)),
            "nothing opted in: the app's figure"
        );
        assert_eq!(
            l(&[], &[], None),
            None,
            "no opt-in and no app figure: unquoted"
        );
        // another key's rows never answer
        let other = vec![GasRow {
            fresh: true,
            ..row("mtxPay", 1_000)
        }];
        assert_eq!(
            l(&other, &all(&["vault"]), None),
            Some((2_000, GasFrom::Module("vault".into())))
        );
        assert_eq!(
            quoted(&chain, &[], &tables, None, K, 10),
            Some(((1_000 + 21_000 + 640) * 3 / 2, GasFrom::Chain))
        );
    }

    fn file(rows: &str) -> String {
        format!(
            r#"{{"format":"scaas.gas-table","v":1,"name":"m","family":"evm","assumptions":[],"rows":[{rows}]}}"#
        )
    }
    fn r(gas: u64, measured: u64) -> String {
        format!(
            r#"{{"entry":"mtxPay","kind":"token","signer":257,"fresh":false,"gas":{gas},"measured":{measured},"source":"s"}}"#
        )
    }

    /// The table file's checks: the rounding (a multiple of 1,000, `measured <= gas < measured + 1000`), the format, the
    /// bounds, no key twice; each refusal beside its control.
    #[test]
    fn gas_table_parse_checks() {
        let ok = GasTable::parse(&file(&r(98_000, 97_947))).unwrap();
        assert_eq!(ok.rows, vec![row("mtxPay", 98_000)]);
        assert!(
            GasTable::parse(&file(&r(98_000, 98_000))).is_ok(),
            "an exact multiple stays"
        );
        for bad in [
            file(&r(98_000, 98_001)), // measured above the table
            file(&r(99_000, 97_947)), // 1,000 or more above the measurement
            file(&r(98_000, 97_000)), // exactly 1,000 above
            file(&r(98_500, 97_947)), // not a multiple of 1,000
            file(&r(0, 0)),           // zero
            file(&format!("{},{}", r(98_000, 97_947), r(98_000, 97_900))), // one key twice
            file(&r(98_000, 97_947)).replace("scaas.gas-table", "other"),
            file(&r(98_000, 97_947)).replace(r#""v":1"#, r#""v":2"#),
            file(&r(98_000, 97_947)).replace(r#","source":"s""#, ""),
            file(&r(98_000, 97_947)).replace(r#""signer":257"#, r#""signer":65536"#),
            file(&r(98_000, 97_947)).replace(r#""entry":"mtxPay""#, r#""entry":"a b""#),
        ] {
            assert!(GasTable::parse(&bad).is_err(), "{bad}");
        }
        let many = vec![r(98_000, 97_947); 1_025].join(",");
        assert!(
            GasTable::parse(&file(&many)).is_err(),
            "more than 1,024 rows"
        );
        assert!(
            GasTable::parse(&" ".repeat(256 * 1024 + 1)).is_err(),
            "above 256 KiB"
        );
    }

    /// The SCaaS reference table parses, is named `reference`, and is EVM.
    #[test]
    fn reference_file_parses() {
        let t = GasTable::parse(REFERENCE_FILE).unwrap();
        assert_eq!((t.name.as_str(), t.family.as_str()), (REFERENCE, "evm"));
        assert!(!t.rows.is_empty());
    }

    /// Each reference row holds to its source: `source` = `<repo path>#<key>[,<key>…]` of a measurement file (`{key: gas}`),
    /// `measured` the worst of the named keys, and the two bounds (`measured <= gas`, `gas - measured < 1000`) held by the parse.
    #[test]
    fn reference_rows_hold_their_sources() {
        let v: serde_json::Value = serde_json::from_str(REFERENCE_FILE).unwrap();
        for r in v["rows"].as_array().unwrap() {
            let (path, keys) = r["source"].as_str().unwrap().split_once('#').unwrap();
            let file = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
            let m: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            let worst = keys
                .split(',')
                .map(|k| m[k].as_u64().unwrap())
                .max()
                .unwrap();
            assert_eq!(worst, r["measured"].as_u64().unwrap(), "{r}");
        }
    }
}
