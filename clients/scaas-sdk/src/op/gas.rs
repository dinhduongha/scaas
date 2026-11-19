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

/// The signer kinds the SDK accepts (spec §13.3: each UA kind `ua_key` derives that can sign alone, and the native key): the
/// verify rows the reference table carries, and the kinds an attached signature of unknown kind may be (owner 2026-11-19,
/// ruling 4).
pub(crate) const ACCEPTED_SIGNERS: [u16; 15] = [
    NATIVE_EVM, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0130, 0x0131,
    0x0132, 0x0133, 0x0134, 0x0135,
];

/// The entry whose inner call the app prices (owner 2026-11-19, ruling 5).
pub(crate) const EXECUTE: &str = "mtxExecute";

/// What a quote reads of the operation besides its key (owner 2026-11-19, ruling B and rulings 1-4).
pub(crate) struct OpGas<'a> {
    /// the length of a per-byte part's input (ruling B); `None`: the operation has none
    pub len: &'a dyn Fn(&str) -> Option<u64>,
    /// the operation saves its `PayMeta` record (ruling 1)
    pub saves: bool,
    /// the operation's fee is > 0 (ruling 3)
    pub fee: bool,
    /// a second signature the operation carries besides its signer's (ruling 4: `mtxPayWithPayeeFee`): `Some(kind)`, or
    /// `Some(None)` when its kind cannot be determined
    pub attached: Option<Option<u16>>,
}

impl OpGas<'_> {
    /// An operation without a variable-length input, a saved record, a fee or a second signature.
    #[cfg(test)]
    pub(crate) const PLAIN: OpGas<'static> = OpGas {
        len: &|_| Some(0),
        saves: false,
        fee: false,
        attached: None,
    };
}

/// A verify part of signer kind `signer`: its row's gas plus 64 gas a byte of its `sig_bytes` (owner 2026-11-19, ruling 2:
/// the quote's calldata is that of the operation built with an empty signature), and its source.
fn verify_part(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    signer: u16,
) -> Option<(u64, GasFrom)> {
    part(chain, opt_in, tables, |r| {
        let v = r.verify.iter().find(|v| v.signer == signer)?;
        Some(
            v.gas
                .saturating_add(v.sig_bytes.unwrap_or(0).saturating_mul(PER_BYTE)),
        )
    })
}

/// The execution gas of the key `(entry, kind, signer, fresh)` and its sources: base + verify, each looked up on its own;
/// without both, the app's figure (one total); `None`: no figure. The base row adds (owner 2026-11-19) its per-byte part
/// times the input's length (ruling B; an input the operation lacks: the row does not answer), its `save` when the operation
/// saves its record (ruling 1; a row without one does not answer: fail closed), its `fee_extra` when the fee is > 0 (ruling
/// 3; a row without one adds nothing: the entry's fee is its own payment); the verify part adds 64 gas a byte of its
/// `sig_bytes` (ruling 2); a second signature adds its kind's verify part, or when its kind is unknown the most expensive
/// of [`ACCEPTED_SIGNERS`] (ruling 4; a kind without a row: no answer). `mtxExecute` (ruling 5): the app's figure is its
/// inner call's, added to the rows, never a total; without it, or without the rows, no figure.
pub(crate) fn lookup_by(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
    op: &OpGas,
) -> Option<(u64, GasSources)> {
    let (entry, kind, signer, fresh) = key;
    let base = part(chain, opt_in, tables, |r| {
        let b = r.base.iter().find(|b| b.key() == (entry, kind, fresh))?;
        let mut g = b.gas;
        if let Some(p) = &b.per_byte {
            g = g.saturating_add(p.gas.saturating_mul((op.len)(&p.input)?));
        }
        if op.saves {
            g = g.saturating_add(b.save?);
        }
        if op.fee {
            g = g.saturating_add(b.fee_extra.unwrap_or(0));
        }
        Some(g)
    });
    let verify = verify_part(chain, opt_in, tables, signer);
    let second = match op.attached {
        None => Some(0),
        Some(Some(k)) => verify_part(chain, opt_in, tables, k).map(|v| v.0),
        Some(None) => ACCEPTED_SIGNERS
            .iter()
            .map(|k| verify_part(chain, opt_in, tables, *k).map(|v| v.0))
            .try_fold(0, |m, v| v.map(|v| m.max(v))),
    };
    let execute = entry == EXECUTE;
    match (base, verify, second) {
        (Some((b, base)), Some((v, verify)), Some(s)) => {
            let inner = if execute { app? } else { 0 };
            Some((
                b.saturating_add(v).saturating_add(s).saturating_add(inner),
                GasSources { base, verify },
            ))
        }
        _ if execute => None,
        _ => app.map(|g| (g, GasSources::both(GasFrom::App))),
    }
}

/// [`lookup_by`] of an operation without a variable-length input, a saved record, a fee or a second signature.
#[cfg(test)]
pub(crate) fn lookup(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
) -> Option<(u64, GasSources)> {
    lookup_by(chain, opt_in, tables, app, key, &OpGas::PLAIN)
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
    op: &OpGas,
) -> Option<(u64, GasSources)> {
    let (g, from) = lookup_by(chain, opt_in, tables, app, key, op)?;
    let bytes = u64::try_from(len)
        .unwrap_or(u64::MAX)
        .saturating_mul(PER_BYTE);
    Some((
        with_margin(g.saturating_add(INTRINSIC).saturating_add(bytes)),
        from,
    ))
}

/// The length in bytes of an operation's variable-length input a per-byte part names (`extra`, `message`: the prepared
/// operation's unsigned arguments and message): `meta.body`, the `PayMeta` body as the contract receives it (`scaas-ua`'s
/// encoding); `data`, the message's `data` (hex). `None`: the operation has none.
pub(crate) fn input_len(
    extra: &serde_json::Value,
    message: &serde_json::Value,
    input: &str,
) -> Option<u64> {
    let n = match input {
        "meta.body" => scaas_ua::wallet::entries::pay_meta_of(extra.get("meta")?)
            .ok()?
            .body
            .len(),
        "data" => {
            let h = message.get("data")?.as_str()?;
            let h = h.strip_prefix("0x").unwrap_or(h);
            if h.len() % 2 != 0 {
                return None;
            }
            h.len() / 2
        }
        _ => return None,
    };
    u64::try_from(n).ok()
}

/// The kind of the second signature an operation attaches (owner 2026-11-19, ruling 4): `mtxPayWithPayeeFee`'s payer
/// `UASig` (`extra.payerSig`) over the payment (`message.payment`, whose `from` it signs for); `None`: the operation attaches
/// none. Within: the native key for an empty key data on a native id; else the accepted kind whose id of the key data is
/// the payment's `from`; `None` when it cannot be determined (members, a stored kind's empty key data, no kind matches).
pub(crate) fn attached_kind(
    extra: &serde_json::Value,
    message: &serde_json::Value,
) -> Option<Option<u16>> {
    let sig = extra.get("payerSig")?;
    let kind = || -> Option<u16> {
        if !sig.get("members")?.as_array()?.is_empty() {
            return None;
        }
        let kd = super::unhex(sig.get("keyData")?.as_str()?).ok()?;
        let from: [u8; 32] =
            super::unhex(super::prepared::envelope(message)?.get("from")?.as_str()?)
                .ok()?
                .try_into()
                .ok()?;
        if kd.is_empty() {
            return scaas_ua::in_native_space(&from).then_some(NATIVE_EVM);
        }
        ACCEPTED_SIGNERS
            .into_iter()
            .filter(|k| *k != NATIVE_EVM)
            .find(|k| scaas_ua::ua_of(*k, &kd).ok() == Some(from))
    };
    Some(kind())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::{GasBase, GasPerByte, GasVerify};

    fn rows(base: u64, verify: u64) -> GasRows {
        GasRows {
            base: vec![GasBase {
                entry: "mtxPay".into(),
                kind: "token".into(),
                fresh: false,
                gas: base,
                per_byte: None,
                save: None,
                fee_extra: None,
            }],
            verify: vec![GasVerify {
                signer: 0x0101,
                gas: verify,
                sig_bytes: None,
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
            quoted(&rows(1_000, 10), &[], &tables, None, K, 10, &OpGas::PLAIN),
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
        let native_sig = t["verify"][0]["sig_bytes"].as_u64();
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
            let key = |k: &str| m[k].as_u64().unwrap_or_else(|| panic!("{k}"));
            let worst = keys
                .split(',')
                .map(|k| match r["calldata_gas"][k].as_u64() {
                    Some(cd) => key(k) - 15_000 - cd,
                    None => key(k),
                })
                .max()
                .unwrap();
            assert_eq!(worst, r["measured"].as_u64().unwrap(), "{r}");
            // rulings 1 and 3: `save` and `fee_extra`, each the worst difference `a-b` of its source's key pairs
            for f in ["save", "fee_extra"] {
                let Some(x) = r.get(f) else { continue };
                let (p, pairs) = x["source"].as_str().unwrap().split_once('#').unwrap();
                assert_eq!(p, path, "{r}");
                let worst = pairs
                    .split(',')
                    .map(|ab| {
                        let (a, b) = ab.split_once('-').unwrap();
                        key(a) - key(b)
                    })
                    .max()
                    .unwrap();
                assert_eq!(worst, x["measured"].as_u64().unwrap(), "{f} {r}");
            }
            // ruling 2: a verify row's `sig_bytes`, measured beside its delta
            if let Some(n) = r.get("sig_bytes") {
                let k = keys.strip_suffix("_delta").unwrap();
                assert_eq!(key(&format!("{k}_sig_bytes")), n.as_u64().unwrap(), "{r}");
                assert_eq!(
                    native_sig,
                    Some(key("verify_native_sig_bytes")),
                    "the reference signer's sig_bytes"
                );
            }
            // a per-byte part: the worst of its source keys (each a whole-gas slope), its input one the SDK measures
            if let Some(p) = r.get("per_byte") {
                let (path, keys) = p["source"].as_str().unwrap().split_once('#').unwrap();
                let file = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
                let m: serde_json::Value =
                    serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
                let worst = keys
                    .split(',')
                    .map(|k| m[k].as_u64().unwrap())
                    .max()
                    .unwrap();
                assert_eq!(worst, p["gas"].as_u64().unwrap(), "{r}");
            }
        }
    }

    /// Owner 2026-11-19, ruling B: a base row's per-byte part adds its gas times the input's length, the input read from
    /// the operation (`meta.body` encoded by `scaas-ua`, `data` hex); without the input the row does not answer.
    #[test]
    fn gas_per_byte_part_adds_the_inputs_length() {
        let mut r = rows(1_000, 10);
        r.base[0].per_byte = Some(GasPerByte {
            input: "meta.body".into(),
            gas: 9,
        });
        let by = |n: Option<u64>| {
            let len = move |i: &str| (i == "meta.body").then_some(n).flatten();
            lookup_by(
                &r,
                &[],
                &[],
                None,
                K,
                &OpGas {
                    len: &len,
                    ..OpGas::PLAIN
                },
            )
        };
        assert_eq!(by(Some(100)).map(|f| f.0), Some(1_000 + 9 * 100 + 10));
        assert_eq!(by(Some(0)).map(|f| f.0), Some(1_010));
        assert_eq!(by(None), None);
        let (empty, msg) = (
            serde_json::json!({}),
            serde_json::json!({"data": "0x0102ab"}),
        );
        assert_eq!(input_len(&empty, &msg, "data"), Some(3));
        assert_eq!(
            input_len(&empty, &serde_json::json!({"data": "0x012"}), "data"),
            None
        );
        assert_eq!(input_len(&empty, &msg, "meta.body"), None);
        assert_eq!(input_len(&empty, &msg, "other"), None);
        let salt = format!("0x{}", "11".repeat(32));
        let meta = |body: serde_json::Value| serde_json::json!({"meta": {"salt": salt, "schema": 1, "body": body}});
        let note = |n: &str| {
            input_len(&meta(serde_json::json!({"note": n})), &empty, "meta.body").unwrap()
        };
        assert_eq!(
            note("abcd") - note("ab"),
            2,
            "the body's encoding grows a byte a character"
        );
        assert!(note("ab") > 0);
    }

    /// Owner 2026-11-19, rulings 1-3: a saving operation adds the row's `save` (a row without one does not answer); a fee > 0
    /// adds its `fee_extra` (a row without one adds nothing); the verify part adds 64 gas a byte of `sig_bytes`. Each beside
    /// its control.
    #[test]
    fn gas_save_fee_and_sig_bytes() {
        let mut r = rows(1_000, 10);
        let by = |r: &GasRows, saves: bool, fee: bool| {
            lookup_by(
                r,
                &[],
                &[],
                None,
                K,
                &OpGas {
                    saves,
                    fee,
                    ..OpGas::PLAIN
                },
            )
            .map(|f| f.0)
        };
        assert_eq!(
            by(&r, false, true),
            Some(1_010),
            "no fee_extra: nothing added"
        );
        assert_eq!(
            by(&r, true, false),
            None,
            "a saving operation on a row without save"
        );
        r.base[0].save = Some(331_000);
        r.base[0].fee_extra = Some(126_000);
        assert_eq!(by(&r, false, false), Some(1_010));
        assert_eq!(by(&r, true, false), Some(1_010 + 331_000));
        assert_eq!(by(&r, false, true), Some(1_010 + 126_000));
        assert_eq!(by(&r, true, true), Some(1_010 + 331_000 + 126_000));
        r.verify[0].sig_bytes = Some(128);
        assert_eq!(by(&r, false, false), Some(1_010 + 64 * 128));
    }

    /// Owner 2026-11-19, ruling 4: a second signature adds its kind's verify part (with its `sig_bytes`); of an unknown kind,
    /// the most expensive of the accepted kinds, and no answer when one of them has no row.
    #[test]
    fn gas_second_signature() {
        let mut r = rows(1_000, 10);
        r.verify = ACCEPTED_SIGNERS
            .iter()
            .map(|s| GasVerify {
                signer: *s,
                gas: u64::from(*s),
                sig_bytes: Some(1),
            })
            .collect();
        let by = |r: &GasRows, attached| {
            lookup_by(
                r,
                &[],
                &[],
                None,
                K,
                &OpGas {
                    attached,
                    ..OpGas::PLAIN
                },
            )
            .map(|f| f.0)
        };
        let own = 1_000 + 0x0101 + 64;
        assert_eq!(by(&r, None), Some(own));
        assert_eq!(by(&r, Some(Some(0x0102))), Some(own + 0x0102 + 64));
        assert_eq!(by(&r, Some(Some(0))), Some(own + 64));
        assert_eq!(
            by(&r, Some(None)),
            Some(own + 0x0135 + 64),
            "unknown: the most expensive"
        );
        r.verify[3].gas = 1_000_000;
        assert_eq!(by(&r, Some(None)), Some(own + 1_000_000 + 64));
        assert_eq!(by(&r, Some(Some(0x0120))), None, "a kind without a row");
        r.verify.retain(|v| v.signer != 0x0133);
        assert_eq!(by(&r, Some(None)), None, "an accepted kind without a row");
    }

    /// Owner 2026-11-19, ruling 5: `mtxExecute`'s app figure is its inner call's, added to the rows; without it, or without
    /// the rows, no figure (never the app's as a total); another entry keeps the app figure as one total.
    #[test]
    fn gas_execute_inner_call() {
        let mut r = rows(1_000, 10);
        r.base[0].entry = EXECUTE.into();
        let ex = (EXECUTE, "token", 0x0101, false);
        assert_eq!(
            lookup(&r, &[], &[], Some(500), ex).map(|f| f.0),
            Some(1_510)
        );
        assert_eq!(lookup(&r, &[], &[], None, ex), None);
        assert_eq!(lookup(&GasRows::default(), &[], &[], Some(500), ex), None);
        assert_eq!(
            lookup(&GasRows::default(), &[], &[], Some(500), K),
            Some((500, GasSources::both(GasFrom::App)))
        );
        assert_eq!(
            lookup(&r, &[], &[], Some(500), K),
            Some((500, GasSources::both(GasFrom::App)))
        );
    }

    /// Ruling 4: the attached signature's kind, read from `payerSig` and the payment's `from`.
    #[test]
    fn attached_signature_kind() {
        let kd = vec![7u8; 64];
        let ua = scaas_ua::ua_of(0x0101, &kd).unwrap();
        let native = format!("0x{}{}", "00".repeat(12), "ab".repeat(20));
        let msg = |from: &str| serde_json::json!({"payment": {"from": from, "batch": "1", "validUntil": "9"}});
        let sig = |kd: &str, members: serde_json::Value| serde_json::json!({"payerSig": {"keyData": kd, "signature": "0x01", "members": members}});
        let none = serde_json::json!([]);
        assert_eq!(attached_kind(&serde_json::json!({}), &msg(&native)), None);
        assert_eq!(
            attached_kind(&sig("0x", none.clone()), &msg(&native)),
            Some(Some(0))
        );
        assert_eq!(
            attached_kind(
                &sig(&super::super::hex(&kd), none.clone()),
                &msg(&super::super::hex(&ua))
            ),
            Some(Some(0x0101))
        );
        assert_eq!(
            attached_kind(&sig("0x", none.clone()), &msg(&super::super::hex(&ua))),
            Some(None),
            "a stored kind's empty key data"
        );
        assert_eq!(
            attached_kind(&sig(&super::super::hex(&kd), none), &msg(&native)),
            Some(None),
            "no kind's id"
        );
        assert_eq!(
            attached_kind(&sig("0x", serde_json::json!([{}])), &msg(&native)),
            Some(None),
            "members"
        );
    }

    /// The new optional fields' parse: `save` and `fee_extra` held like a figure and positive, `sig_bytes` bounded.
    #[test]
    fn gas_table_extra_fields_parse() {
        let base = |f: &str| {
            file(
                &b(98_000, 97_947).replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
                "",
            )
        };
        let ok = GasTable::parse(&base(
            r#""save":{"gas":331000,"measured":330657,"source":"s"},"fee_extra":{"gas":126000,"measured":125468,"source":"s"}"#,
        ))
        .unwrap();
        assert_eq!(
            (ok.rows.base[0].save, ok.rows.base[0].fee_extra),
            (Some(331_000), Some(126_000))
        );
        for bad in [
            r#""save":{"gas":330000,"measured":330657,"source":"s"}"#,
            r#""save":{"gas":331500,"measured":330657,"source":"s"}"#,
            r#""save":{"gas":331000,"measured":330657}"#,
            r#""save":{"gas":0,"measured":0,"source":"s"}"#,
            r#""fee_extra":{"gas":127000,"measured":125468,"source":"s"}"#,
            r#""fee_extra":1000"#,
        ] {
            assert!(GasTable::parse(&base(bad)).is_err(), "{bad}");
        }
        let verify = |f: &str| {
            file(
                "",
                &v(257, 1_000, 900).replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
            )
        };
        assert_eq!(
            GasTable::parse(&verify(r#""sig_bytes":65536"#))
                .unwrap()
                .rows
                .verify[0]
                .sig_bytes,
            Some(65_536)
        );
        for bad in [
            r#""sig_bytes":65537"#,
            r#""sig_bytes":-1"#,
            r#""sig_bytes":"96""#,
        ] {
            assert!(GasTable::parse(&verify(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn gas_table_per_byte_parse() {
        let with = |p: &str| {
            file(
                &b(98_000, 97_947).replace(
                    r#""source":"s""#,
                    &format!(r#""source":"s","per_byte":{p}"#),
                ),
                "",
            )
        };
        let ok = GasTable::parse(&with(r#"{"input":"meta.body","gas":9,"source":"s"}"#)).unwrap();
        assert_eq!(
            ok.rows.base[0].per_byte,
            Some(GasPerByte {
                input: "meta.body".into(),
                gas: 9
            })
        );
        assert!(GasTable::parse(&with(r#"{"input":"data","gas":1000,"source":"s"}"#)).is_ok());
        for bad in [
            r#"{"input":"other","gas":9,"source":"s"}"#,
            r#"{"input":"data","gas":0,"source":"s"}"#,
            r#"{"input":"data","gas":1001,"source":"s"}"#,
            r#"{"input":"data","gas":9}"#,
            r#"{"input":"data","gas":9,"source":""}"#,
            r#"{"gas":9,"source":"s"}"#,
        ] {
            assert!(GasTable::parse(&with(bad)).is_err(), "{bad}");
        }
    }

    /// Owner 2026-11-19 (part 3b, ruling 6): every entry the SDK prepares is either quotable from the reference table (a
    /// base row on both lane states, `QUOTABLE`) or listed as not measured yet (`UNMEASURED`), never both, none missing; the
    /// verify rows cover every accepted signer kind (the native key, 0x0101-0x0108, 0x0130-0x0135), each with its
    /// `sig_bytes` (ruling 2).
    #[test]
    fn reference_table_covers_every_quotable_key() {
        use super::super::prepared::{QUOTABLE, UNMEASURED};
        use scaas_ua::wallet::entries::entry_rows;
        let t = GasTable::parse(REFERENCE_FILE).unwrap();
        let mut preparable: Vec<(String, String)> = entry_rows()
            .iter()
            .filter(|r| !r.entry.is_empty()) // a struct without an entry of its own
            .flat_map(|r| r.kinds.iter().map(|k| (r.entry.to_string(), k.to_string())))
            .chain(
                ["token", "zether", "pqz"]
                    .map(|k| ("mtxExecuteTransfer".to_string(), k.to_string())),
            )
            .collect();
        preparable.sort();
        preparable.dedup();
        let pairs = |l: &[(&str, &[&str])]| -> Vec<(String, String)> {
            l.iter()
                .flat_map(|(e, ks)| ks.iter().map(|k| (e.to_string(), k.to_string())))
                .collect()
        };
        let (q, u) = (pairs(QUOTABLE), pairs(UNMEASURED));
        let mut both: Vec<_> = q.iter().chain(&u).cloned().collect();
        both.sort();
        let n = both.len();
        both.dedup();
        assert_eq!(both.len(), n, "a key in both lists or twice");
        assert_eq!(
            both, preparable,
            "the two lists are every entry the SDK prepares"
        );
        for (e, k) in &q {
            for fresh in [true, false] {
                assert!(
                    t.rows
                        .base
                        .iter()
                        .any(|b| b.key() == (e.as_str(), k.as_str(), fresh)),
                    "{e} {k} {fresh}"
                );
            }
        }
        for (e, k) in &u {
            assert!(
                !t.rows.base.iter().any(|b| b.entry == *e && b.kind == *k),
                "{e} {k} measured: move it"
            );
        }
        for s in ACCEPTED_SIGNERS {
            let v = t.rows.verify.iter().find(|v| v.signer == s);
            assert!(
                v.is_some_and(|v| v.sig_bytes.is_some()),
                "signer {s:#06x}: a row with sig_bytes"
            );
        }
    }
}
