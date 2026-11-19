// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The gas of an operation's quote (owner 2026-11-18, ruling 1; owner 2026-11-19, ruling B and the gas-table rulings, part 3b;
//! spec §13.3). A quote never makes or sends a signature, so its gas comes from tables. Each table splits in two (format v2):
//! base rows keyed by the entry, the domain kind and whether the lane is used for the first time, measured with the reference
//! signer (a native EVM key); verify rows keyed by the signer's kind, what it adds over the reference. The figure is base +
//! verify. The SDK carries no gas figure in code. Base and verify are looked up independently, each in the order: the
//! chain's measured rows ([`crate::ChainProfile::gas`]) → the module tables the profile opts in to, in its order → the SCaaS
//! reference table (`gas/reference.json`, data beside the SDK) if the profile opts in. Without both, the figure the app passes
//! on the call (one total, at most `Limits::max_gas`) → none. The quote names both sources ([`GasSources`]). Without a figure
//! a self-relay is `GasUnquoted`; a relayed (gateway) quote reports the gas as unquoted and is not refused for it. EVM only
//! today; every family follows the same principle with its own row shape (spec §13.3).
use crate::{GasRows, GasTable};

/// A native EVM key's signer kind in the table: the reference signer.
pub const NATIVE_EVM: u16 = 0;

/// The name a profile opts in to for the SCaaS reference table.
pub const REFERENCE: &str = "reference";

/// The SCaaS reference table's file, generated from the forge measurement; data, not code.
pub(crate) const REFERENCE_FILE: &str = include_str!("../../gas/reference.json");

/// Where a part of a quote's gas figure came from (owner 2026-11-19), so the app and the operator see a figure not measured on
/// the chain.
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

/// The sources of a quote's figure: its base row's and its verify row's (owner 2026-11-19, part 3b). An app's figure, one
/// total, is `App` for both; a native send's estimate `Estimate` for both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GasSources {
    pub base: GasFrom,
    pub verify: GasFrom,
}

impl GasSources {
    pub(crate) fn both(f: GasFrom) -> Self {
        GasSources {
            base: f.clone(),
            verify: f,
        }
    }
}

/// The transaction's base cost and calldata at the highest price per byte (EIP-7976's floor, 64 gas a byte).
const INTRINSIC: u64 = 21_000;
const PER_BYTE: u64 = 64;

/// The stated margin: the figure plus half of it.
pub(crate) fn with_margin(g: u64) -> u64 {
    g.saturating_add(g / 2)
}

/// One part's figure and source, in the lookup order: the chain's rows → the module tables opted in (profile order) → the
/// reference table if opted in; `find` reads the part's row of a table.
fn part(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    find: impl Fn(&GasRows) -> Option<u64>,
) -> Option<(u64, GasFrom)> {
    let table = |name: &str| tables.iter().find(|t| t.name == name);
    if let Some(g) = find(chain) {
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
    None
}

/// The execution gas of the key `(entry, kind, signer, fresh)` and its sources: base + verify, each looked up on its own;
/// without both, the app's figure (one total); `None`: no figure.
pub(crate) fn lookup(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
) -> Option<(u64, GasSources)> {
    let (entry, kind, signer, fresh) = key;
    let base = part(chain, opt_in, tables, |r| {
        r.base
            .iter()
            .find(|b| b.key() == (entry, kind, fresh))
            .map(|b| b.gas)
    });
    let verify = part(chain, opt_in, tables, |r| {
        r.verify.iter().find(|v| v.signer == signer).map(|v| v.gas)
    });
    match (base, verify) {
        (Some((b, base)), Some((v, verify))) => {
            Some((b.saturating_add(v), GasSources { base, verify }))
        }
        _ => app.map(|g| (g, GasSources::both(GasFrom::App))),
    }
}

/// The quote's gas of a key whose unsigned calldata is `len` bytes: the figure plus the intrinsic cost and the calldata, with
/// the margin, and its sources; `None`: unquoted.
pub(crate) fn quoted(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
    len: usize,
) -> Option<(u64, GasSources)> {
    let (g, from) = lookup(chain, opt_in, tables, app, key)?;
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
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::{GasBase, GasVerify};

    fn rows(base: u64, verify: u64) -> GasRows {
        GasRows {
            base: vec![GasBase {
                entry: "mtxPay".into(),
                kind: "token".into(),
                fresh: false,
                gas: base,
            }],
            verify: vec![GasVerify {
                signer: 0x0101,
                gas: verify,
            }],
        }
    }
    fn base_only(g: u64) -> GasRows {
        GasRows {
            verify: vec![],
            ..rows(g, 0)
        }
    }
    fn verify_only(g: u64) -> GasRows {
        GasRows {
            base: vec![],
            ..rows(0, g)
        }
    }

    fn table(name: &str, rows: GasRows) -> GasTable {
        GasTable {
            name: name.into(),
            family: "evm".into(),
            rows,
        }
    }

    const K: (&str, &str, u16, bool) = ("mtxPay", "token", 0x0101, false);

    fn all(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }
    fn src(base: GasFrom, verify: GasFrom) -> GasSources {
        GasSources { base, verify }
    }
    fn module(n: &str) -> GasFrom {
        GasFrom::Module(n.into())
    }

    /// Each part's order: chain → module (opted in, in the profile's order) → reference (opted in); each step only when the
    /// earlier ones have no row of that part, and a table not opted in is never read. The figure is base + verify.
    #[test]
    fn gas_lookup_order_and_opt_in() {
        let tables = vec![
            table("vault", rows(2_000, 20)),
            table("other", rows(3_000, 30)),
            table(REFERENCE, rows(4_000, 40)),
        ];
        let l = |m: &GasRows, o: &[String], app| lookup(m, o, &tables, app, K);
        let none = GasRows::default();
        assert_eq!(
            l(&rows(1_000, 10), &all(&["vault", REFERENCE]), Some(9)),
            Some((1_010, src(GasFrom::Chain, GasFrom::Chain)))
        );
        assert_eq!(
            l(&none, &all(&[REFERENCE, "vault"]), Some(9)),
            Some((2_020, src(module("vault"), module("vault")))),
            "a module before the reference, whatever the list's order"
        );
        assert_eq!(
            l(&none, &all(&["other", "vault"]), None),
            Some((3_030, src(module("other"), module("other")))),
            "modules in the profile's order"
        );
        assert_eq!(
            l(&none, &all(&[REFERENCE]), Some(9)),
            Some((4_040, src(GasFrom::Reference, GasFrom::Reference)))
        );
        assert_eq!(
            l(&none, &[], Some(9)),
            Some((9, GasSources::both(GasFrom::App))),
            "nothing opted in: the app's figure"
        );
        assert_eq!(
            l(&none, &[], None),
            None,
            "no opt-in and no app figure: unquoted"
        );
        assert_eq!(
            quoted(&rows(1_000, 10), &[], &tables, None, K, 10),
            Some((
                (1_010 + 21_000 + 640) * 3 / 2,
                src(GasFrom::Chain, GasFrom::Chain)
            ))
        );
    }

    /// Base and verify are looked up independently (owner 2026-11-19, part 3b), each through its own order; `gas_from` names
    /// both sources; the app's figure is one total, used only when a part has no row anywhere, overriding both.
    #[test]
    fn gas_parts_are_looked_up_independently() {
        let ref_only = |t: GasRows| vec![table(REFERENCE, t)];
        let mods = vec![
            table("vault", verify_only(20)),
            table("other", base_only(3_000)),
            table(REFERENCE, rows(4_000, 40)),
        ];
        let opt = all(&["vault", "other", REFERENCE]);
        // the chain's base, a module's verify
        assert_eq!(
            lookup(&base_only(1_000), &opt, &mods, Some(9), K),
            Some((1_020, src(GasFrom::Chain, module("vault"))))
        );
        // the chain's verify, a later module's base (the first module opted in has none)
        assert_eq!(
            lookup(&verify_only(10), &opt, &mods, None, K),
            Some((3_010, src(module("other"), GasFrom::Chain)))
        );
        // a module's base, the reference's verify (no module verify opted in)
        assert_eq!(
            lookup(
                &GasRows::default(),
                &all(&["other", REFERENCE]),
                &mods,
                None,
                K
            ),
            Some((3_040, src(module("other"), GasFrom::Reference)))
        );
        // the reference's base, the chain's verify
        assert_eq!(
            lookup(&verify_only(10), &all(&[REFERENCE]), &mods, None, K),
            Some((4_010, src(GasFrom::Reference, GasFrom::Chain)))
        );
        // a part missing everywhere: the app's total for both, never a part plus the app
        for (chain, tables) in [
            (base_only(1_000), ref_only(base_only(4_000))),
            (verify_only(10), ref_only(verify_only(40))),
        ] {
            assert_eq!(
                lookup(&chain, &all(&[REFERENCE]), &tables, Some(500), K),
                Some((500, GasSources::both(GasFrom::App)))
            );
            assert_eq!(lookup(&chain, &all(&[REFERENCE]), &tables, None, K), None);
        }
        // another key's rows never answer: another entry, kind, lane state or signer kind
        for key in [
            ("mtxBurn", "token", 0x0101, false),
            ("mtxPay", "zether", 0x0101, false),
            ("mtxPay", "token", 0x0101, true),
            ("mtxPay", "token", 0x0131, false),
        ] {
            assert_eq!(
                lookup(&rows(1_000, 10), &[], &[], None, key),
                None,
                "{key:?}"
            );
        }
    }

    fn file(base: &str, verify: &str) -> String {
        format!(
            r#"{{"format":"scaas.gas-table","v":2,"name":"m","family":"evm","assumptions":[],"base":[{base}],"verify":[{verify}]}}"#
        )
    }
    fn b(gas: u64, measured: u64) -> String {
        format!(
            r#"{{"entry":"mtxPay","kind":"token","fresh":false,"gas":{gas},"measured":{measured},"source":"s"}}"#
        )
    }
    fn v(signer: u64, gas: u64, measured: u64) -> String {
        format!(r#"{{"signer":{signer},"gas":{gas},"measured":{measured},"source":"s"}}"#)
    }

    /// The table file's checks, on base and verify rows alike: the rounding (a multiple of 1,000, at least the measurement and
    /// less than 1,000 above it), the format and version 2, the bounds, no key twice; a base figure positive, a verify figure may be 0 (the
    /// reference signer's); each refusal beside its control.
    #[test]
    fn gas_table_parse_checks() {
        let ok = GasTable::parse(&file(&b(98_000, 97_947), &v(257, 3_000, 2_100))).unwrap();
        assert_eq!(ok.rows, rows(98_000, 3_000));
        for good in [
            file(&b(98_000, 98_000), ""), // an exact multiple stays
            file("", &v(0, 0, 0)),        // the reference signer's 0
            file(&b(98_000, 97_947), &v(257, 1_000, 1)),
        ] {
            assert!(GasTable::parse(&good).is_ok(), "{good}");
        }
        let bad_rounding = |g: u64, m: u64| [file(&b(g, m), ""), file("", &v(257, g, m))];
        let mut bad: Vec<String> = [
            (98_000, 98_001), // measured above the table
            (99_000, 97_947), // 1,000 or more above the measurement
            (98_000, 97_000), // exactly 1,000 above
            (98_500, 97_947), // not a multiple of 1,000
        ]
        .into_iter()
        .flat_map(|(g, m)| bad_rounding(g, m))
        .collect();
        bad.extend([
            file(&b(0, 0), ""), // a base figure of zero
            file(&format!("{},{}", b(98_000, 97_947), b(98_000, 97_900)), ""), // one base key twice
            file(
                "",
                &format!("{},{}", v(257, 1_000, 900), v(257, 2_000, 1_900)),
            ), // one signer twice
            file(&b(98_000, 97_947), "").replace("scaas.gas-table", "other"),
            file(&b(98_000, 97_947), "").replace(r#""v":2"#, r#""v":1"#),
            file(&b(98_000, 97_947), "").replace(r#","source":"s""#, ""),
            file("", &v(257, 1_000, 900)).replace(r#","source":"s""#, ""),
            file("", &v(65_536, 1_000, 900)),
            file(&b(98_000, 97_947), "").replace(r#""entry":"mtxPay""#, r#""entry":"a b""#),
            file(&b(98_000, 97_947), "").replace(r#","verify":[]"#, ""),
            file(&b(98_000, 97_947), "").replace(r#""base":["#, r#""rows":["#),
        ]);
        for bad in bad {
            assert!(GasTable::parse(&bad).is_err(), "{bad}");
        }
        // 1,000 distinct base rows and 24 or 25 verify rows: the bound counts both (control: 1,024 parse)
        let many = (0..1_000)
            .map(|i| b(98_000, 97_947).replace("mtxPay", &format!("e{i}")))
            .collect::<Vec<_>>()
            .join(",");
        let verify = |n: u64| {
            (0..n)
                .map(|i| v(i, 1_000, 900))
                .collect::<Vec<_>>()
                .join(",")
        };
        assert!(GasTable::parse(&file(&many, &verify(24))).is_ok());
        assert!(
            GasTable::parse(&file(&many, &verify(25))).is_err(),
            "more than 1,024 rows, base and verify together"
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
        assert!(!t.rows.base.is_empty() && !t.rows.verify.is_empty());
    }

    /// Each reference row holds to its source: `source` = `<repo path>#<key>[,<key>…]` of a measurement file (`{key: gas}`),
    /// `measured` the worst of the named keys' execution gas: the value itself, or, for a row naming `calldata_gas` (a pin of
    /// whole transactions), each key's total less 15,000 (the Amsterdam intrinsic cost) and its standard calldata gas. The
    /// reference signer's verify row (signer 0) is 0 by definition (the base rows are measured with it) and names no file.
    /// The two bounds (`measured <= gas`, `gas - measured < 1000`) are held by the parse.
    #[test]
    fn reference_rows_hold_their_sources() {
        let t: serde_json::Value = serde_json::from_str(REFERENCE_FILE).unwrap();
        let rows = t["base"]
            .as_array()
            .unwrap()
            .iter()
            .chain(t["verify"].as_array().unwrap());
        for r in rows {
            let Some((path, keys)) = r["source"].as_str().unwrap().split_once('#') else {
                assert_eq!(
                    (&r["signer"], &r["measured"]),
                    (&0.into(), &0.into()),
                    "{r}"
                );
                continue;
            };
            let file = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
            let m: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
            let worst = keys
                .split(',')
                .map(|k| {
                    let g = m[k].as_u64().unwrap_or_else(|| panic!("{k}"));
                    match r["calldata_gas"][k].as_u64() {
                        Some(cd) => g - 15_000 - cd,
                        None => g,
                    }
                })
                .max()
                .unwrap();
            assert_eq!(worst, r["measured"].as_u64().unwrap(), "{r}");
        }
    }
}
