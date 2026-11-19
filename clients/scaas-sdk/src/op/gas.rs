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
use crate::{GasPerItem, GasRows, GasTable, SdkError};

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

/// The largest count a per-item part is quoted at (owner 2026-11-19, I1: a bounded count); above it the operation is
/// refused as `GasCountUnknown`.
pub(crate) const COUNT_MAX: u64 = 65_536;

/// The contracts' `ROLL_MAX` of each PQZ set (`PqzSet.ROLL_MAX`, `pqz-core/params/sets/<set>/set.toml` `roll_max`), in the
/// order of `scaas_ua::build::PQZ_SETS`; a test holds them equal to each set's generated `PqzSet.sol` (owner 2026-11-19, K1).
const ROLL_MAX: [u64; 4] = [80, 64, 48, 32];

/// This build's set's `ROLL_MAX`; `None` without a `pqz-set-*` feature.
pub(crate) fn roll_max() -> Option<u64> {
    scaas_ua::build::PQZ_SETS
        .iter()
        .zip(ROLL_MAX)
        .find(|(on, _)| **on)
        .map(|(_, m)| m)
}

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
    /// the count a per-item part names (I1: [`item_count`]); `None`: the SDK cannot read it from the operation
    pub count: &'a dyn Fn(&str) -> Option<u64>,
    /// the operation saves its `PayMeta` record (ruling 1)
    pub saves: bool,
    /// the operation's fee is > 0 (ruling 3)
    pub fee: bool,
    /// a second signature the operation carries besides its signer's (ruling 4: `mtxPayWithPayeeFee`): `Some(kind)`, or
    /// `Some(None)` when its kind cannot be determined
    pub attached: Option<Option<u16>>,
    /// a third party the entry debits besides its signer and the attached signature's owner (PR A review, finding 4:
    /// [`holder_derived`]) is, or may be, a derived UA
    pub holder: bool,
}

impl OpGas<'_> {
    /// An operation without a variable-length input, a saved record, a fee or a second signature.
    #[cfg(test)]
    pub(crate) const PLAIN: OpGas<'static> = OpGas {
        len: &|_| Some(0),
        count: &|_| None,
        saves: false,
        fee: false,
        attached: None,
        holder: false,
    };
}

/// A verify part of signer kind `signer`: its row's gas and `margin` (owner 2026-11-19, ruling 2 (b) of the sampled check),
/// plus 64 gas a byte of its `sig_bytes` when `bytes` (owner 2026-11-19,
/// ruling 2: the quote's calldata is that of the operation built with an empty signature; A3: an attached signature's bytes
/// are in that calldata already, so only its verify gas), and its source.
fn verify_part(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    signer: u16,
    bytes: bool,
    items: &dyn Fn(&Option<GasPerItem>) -> Option<u64>,
) -> Option<(u64, GasFrom)> {
    part(chain, opt_in, tables, |r| {
        let v = r.verify.iter().find(|v| v.signer == signer)?;
        let b = if bytes { v.sig_bytes } else { 0 };
        Some(
            v.gas
                .saturating_add(v.margin)
                .saturating_add(b.saturating_mul(PER_BYTE))
                .saturating_add(items(&v.per_item)?),
        )
    })
}

/// The execution gas of the key `(entry, kind, signer, fresh)` and its sources: base + verify, each looked up on its own;
/// without both, the app's figure (one total); `None`: no figure. The base row adds (owner 2026-11-19) its per-byte part
/// times the input's length (ruling B; an input the operation lacks: the row does not answer), its `save` when the operation
/// saves its record (ruling 1; a row without one does not answer: fail closed), its `fee_extra` when the fee is > 0 (ruling
/// 3; a row without one adds nothing: the entry's fee is its own payment), its `ua_extra` once when either party the entry
/// debits is a derived UA, the signer or an attached signature's owner (A1, G1; a row without one adds nothing); the verify
/// part adds 64 gas a byte of its `sig_bytes` (ruling 2); a second signature, the one attached (ruling 4 as A2 reads it), adds its kind's verify gas without its bytes (A3), or when its kind
/// is unknown the most expensive of [`ACCEPTED_SIGNERS`] (a kind without a row: no answer). `mtxExecute` (ruling 5): the
/// app's figure is its inner call's, added to the rows, never a total; without it, or without the rows, no figure. A base
/// or verify row's `per_item` (I1) adds its gas times the count it names, read by `op.count` (the signer's verify row) and
/// at most [`COUNT_MAX`]; a row read whose count is unknown or above it refuses the operation, `GasCountUnknown` (fail
/// closed: never quoted from a later table or the app's figure instead), an attached signature's verify row with one too
/// (its count is not read).
pub(crate) fn lookup_by(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
    op: &OpGas,
) -> Result<Option<(u64, GasSources)>, SdkError> {
    let (entry, kind, signer, fresh) = key;
    let uncounted = std::cell::Cell::new(false);
    let items = |p: &Option<GasPerItem>, count: &dyn Fn(&str) -> Option<u64>| {
        let Some(p) = p else { return Some(0) };
        let n = count(&p.item).filter(|n| *n <= COUNT_MAX);
        if n.is_none() {
            uncounted.set(true);
        }
        Some(p.gas.saturating_mul(n?))
    };
    let own = |p: &Option<GasPerItem>| items(p, op.count);
    let attached = |p: &Option<GasPerItem>| items(p, &|_| None);
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
        // G1: any party the entry debits a derived UA, the signer, the attached signature's owner (an attached signature of
        // unknown kind counts as derived: fail closed) or a third party's holder (PR A review, finding 4); added once
        if signer != NATIVE_EVM || op.attached.is_some_and(|k| k != Some(NATIVE_EVM)) || op.holder {
            g = g.saturating_add(b.ua_extra.unwrap_or(0));
        }
        g = g.saturating_add(own(&b.per_item)?);
        Some(g)
    });
    let verify = verify_part(chain, opt_in, tables, signer, true, &own);
    let second = match op.attached {
        None => Some(0),
        Some(Some(k)) => verify_part(chain, opt_in, tables, k, false, &attached).map(|v| v.0),
        Some(None) => ACCEPTED_SIGNERS
            .iter()
            .map(|k| verify_part(chain, opt_in, tables, *k, false, &attached).map(|v| v.0))
            .try_fold(0, |m, v| v.map(|v| m.max(v))),
    };
    if uncounted.get() {
        return Err(SdkError::GasCountUnknown);
    }
    let execute = entry == EXECUTE;
    Ok(match (base, verify, second) {
        (Some((b, base)), Some((v, verify)), Some(s)) => {
            let inner = if execute { app } else { Some(0) };
            inner.map(|inner| {
                (
                    b.saturating_add(v).saturating_add(s).saturating_add(inner),
                    GasSources { base, verify },
                )
            })
        }
        _ if execute => None,
        _ => app.map(|g| (g, GasSources::both(GasFrom::App))),
    })
}

/// [`lookup_by`] of an operation without a variable-length input, a saved record, a fee, a second signature or a count
/// (a row with a per-item part: no figure).
#[cfg(test)]
pub(crate) fn lookup(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
) -> Option<(u64, GasSources)> {
    lookup_by(chain, opt_in, tables, app, key, &OpGas::PLAIN)
        .ok()
        .flatten()
}

/// The quote's gas of a key whose unsigned calldata is `len` bytes: the figure plus the intrinsic cost and the calldata, with
/// the margin, and its sources; `None`: unquoted; `GasCountUnknown` as [`lookup_by`].
pub(crate) fn quoted(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    app: Option<u64>,
    key: (&str, &str, u16, bool),
    len: usize,
    op: &OpGas,
) -> Result<Option<(u64, GasSources)>, SdkError> {
    let bytes = u64::try_from(len)
        .unwrap_or(u64::MAX)
        .saturating_mul(PER_BYTE);
    Ok(
        lookup_by(chain, opt_in, tables, app, key, op)?.map(|(g, from)| {
            (
                with_margin(g.saturating_add(INTRINSIC).saturating_add(bytes)),
                from,
            )
        }),
    )
}

/// The calldata bytes a quote of signer kind `signer` counted (owner 2026-11-19, G3): the unsigned calldata (`unsigned`) plus
/// the verify row's `sig_bytes` when the verify part came from a row (looked up in the same order, so from the same row); an
/// app's figure, an estimate or no source counted the unsigned calldata only.
pub(crate) fn counted_bytes(
    chain: &GasRows,
    opt_in: &[String],
    tables: &[GasTable],
    signer: u16,
    from: Option<&GasSources>,
    unsigned: usize,
) -> u64 {
    let unsigned = u64::try_from(unsigned).unwrap_or(u64::MAX);
    let sig = match from.map(|f| &f.verify) {
        Some(GasFrom::Chain | GasFrom::Module(_) | GasFrom::Reference) => {
            part(chain, opt_in, tables, |r| {
                r.verify
                    .iter()
                    .find(|v| v.signer == signer)
                    .map(|v| v.sig_bytes)
            })
            .map_or(0, |v| v.0)
        }
        _ => 0,
    };
    unsigned.saturating_add(sig)
}

/// The gas of a quoted operation once signed (owner 2026-11-19, G3): the calldata part recomputed from the signed calldata
/// (`signed` bytes, the real signature's length) where it exceeds what the quote counted (`counted`), with the margin; never
/// below the quote's figure (`quoted`).
pub(crate) fn signed_gas(quoted: u64, counted: u64, signed: usize) -> u64 {
    let signed = u64::try_from(signed).unwrap_or(u64::MAX);
    match signed.saturating_sub(counted) {
        0 => quoted,
        more => quoted.saturating_add(with_margin(more.saturating_mul(PER_BYTE))),
    }
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

/// The count a per-item part names (owner 2026-11-19, I1), read from the operation's signed message (and its `extra`):
/// `legs`, the length of `args.legs` (a Zether or PQZ multi-recipient transfer, `mtxConfidentialTransfer[Compact]`), of a
/// list parameter `legs` (`mtxSetWrapLimits`) or of `extra.config.legs` (`mtxCreateToken`'s `TokenConfig`, K2); `accounts`,
/// the length of `uas` (`mtxRollOverBatch`) or of a list parameter `accounts` (`mtxSetAllowed`, `mtxSetDenied`,
/// `mtxSetCompliance`); `entries`, a rollover's `n` (PQZ `mtxRollOver`, `mtxRollOverSigned`), any `uint256` held to the
/// set's [`roll_max`] (owner 2026-11-19, K1: the contract's own bound, so an app's huge `n` meaning "all" is quoted at
/// `ROLL_MAX`), plus the length of its `skip` marks where it has them (P1, "approved": min(n, ROLL_MAX) + len(skip));
/// `env_items` (P1, K2), the elements of an env publish's four `Env` arrays (`env.deps`, `env.params`, `env.libs`,
/// `env.libCodeHashes`) together; `orders` (K2), a DEX cancel's orders, 1 for its one `order`; `members` is not read (no
/// `0x0121` signer in the SDK yet). `None`: the operation has no such count.
pub(crate) fn item_count(
    extra: &serde_json::Value,
    message: &serde_json::Value,
    item: &str,
) -> Option<u64> {
    let len = |v: Option<&serde_json::Value>| v?.as_array().map(Vec::len);
    let n = match item {
        "legs" => len(message.get("args").and_then(|a| a.get("legs")))
            .or_else(|| len(message.get("legs")))
            .or_else(|| len(extra.get("config").and_then(|c| c.get("legs"))))?,
        "accounts" => len(message.get("uas")).or_else(|| len(message.get("accounts")))?,
        "entries" => {
            let n = super::dec(message.get("n")?).ok()?;
            let n = roll_max().map_or(n, |m| n.min(alloy::primitives::U256::from(m)));
            let skip = match message.get("skip") {
                Some(s) => s.as_array()?.len(),
                None => 0,
            };
            return u64::try_from(n)
                .ok()?
                .checked_add(u64::try_from(skip).ok()?);
        }
        "env_items" => {
            let env = message.get("env")?;
            let mut t = 0;
            for a in ["deps", "params", "libs", "libCodeHashes"] {
                t += len(env.get(a))?;
            }
            t
        }
        "orders" => len(message.get("orders"))
            .or_else(|| message.get("order").filter(|o| o.is_object()).map(|_| 1))?,
        _ => return None,
    };
    u64::try_from(n).ok()
}

/// The kind of the second signature an operation attaches (owner 2026-11-19, ruling 4): `mtxPayWithPayeeFee`'s payer
/// `UASig` (`extra.payerSig`) over the payment (`message.payment`, whose `from` it signs for), or (I3) `mtxSetAuditorUA`'s
/// new auditor's consent (`extra.consent`, signed by `message.newAuditor`; the row is measured without its verify);
/// `None`: the operation attaches none. Within: the native key for an empty key data on a native id; else the accepted kind whose id of the key data is
/// the payment's `from`; `None` when it cannot be determined (members, a stored kind's empty key data, no kind matches).
pub(crate) fn attached_kind(
    extra: &serde_json::Value,
    message: &serde_json::Value,
) -> Option<Option<u16>> {
    let (sig, owner) = match (extra.get("payerSig"), extra.get("consent")) {
        (Some(s), _) => (
            s,
            super::prepared::envelope(message).and_then(|e| e.get("from")),
        ),
        (None, Some(s)) => (s, message.get("newAuditor")),
        (None, None) => return None,
    };
    let kind = || -> Option<u16> {
        if !sig.get("members")?.as_array()?.is_empty() {
            return None;
        }
        let kd = super::unhex(sig.get("keyData")?.as_str()?).ok()?;
        let from: [u8; 32] = super::unhex(owner?.as_str()?).ok()?.try_into().ok()?;
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

/// Whether an entry debits a third party besides its signer that is, or may be, a derived UA (PR A review, finding 4; G1's
/// "either debited party" read on the holder): `mtxOperatorTransfer` moves the message's `account` (derived unless a native
/// id); `mtxForceTransfer` the holder of its court-order record, which the message names only by `recordId`, so it counts as
/// derived (fail closed, as an attached signature of unknown kind). No other entry debits a third party: every other debit
/// is the signer's (`from`) or the attached signature's owner (`mtxPayWithPayeeFee`'s payer); `mtxMintToUA` credits.
pub(crate) fn holder_derived(entry: &str, message: &serde_json::Value) -> bool {
    match entry {
        "mtxOperatorTransfer" => {
            let id = message
                .get("account")
                .and_then(|a| a.as_str())
                .and_then(|a| super::unhex(a).ok())
                .and_then(|b| <[u8; 32]>::try_from(b).ok());
            id.is_none_or(|id| !scaas_ua::in_native_space(&id))
        }
        "mtxForceTransfer" => true,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::{GasBase, GasPerByte, GasPerItem, GasVerify};

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
                ua_extra: None,
                per_item: None,
            }],
            verify: vec![GasVerify {
                signer: 0x0101,
                gas: verify,
                sig_bytes: 0,
                margin: 0,
                per_item: None,
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
            quoted(&rows(1_000, 10), &[], &tables, None, K, 10, &OpGas::PLAIN).unwrap(),
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
        format!(
            r#"{{"signer":{signer},"gas":{gas},"measured":{measured},"source":"s","sig_bytes":0}}"#
        )
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
        // W3: a sound table padded to exactly 1 MiB parses; one byte more is refused
        let one = file(&b(98_000, 97_947), "");
        let at = format!("{one}{}", " ".repeat(1024 * 1024 - one.len()));
        assert!(GasTable::parse(&at).is_ok(), "a table of exactly 1 MiB");
        assert!(GasTable::parse(&format!("{at} ")).is_err(), "above 1 MiB");
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
        let inputs: serde_json::Value =
            serde_json::from_str(include_str!("../../gas/inputs.json")).unwrap();
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
            // rulings 1 and 3, A1: `save`, `fee_extra` and `ua_extra`, each the worst `a-b[-c]` of its source's items (the
            // first key less the others)
            for f in ["save", "fee_extra", "ua_extra"] {
                let Some(x) = r.get(f) else { continue };
                let (p, pairs) = x["source"].as_str().unwrap().split_once('#').unwrap();
                assert_eq!(p, path, "{r}");
                let worst = pairs
                    .split(',')
                    .map(|ab| {
                        let mut ks = ab.split('-');
                        let a = key(ks.next().unwrap());
                        ks.fold(a, |g, k| g - key(k))
                    })
                    .max()
                    .unwrap();
                assert_eq!(worst, x["measured"].as_u64().unwrap(), "{f} {r}");
            }
            // the sampled check's ruling 2 (b): a verify row's `margin` is the input list's for its kind, and only there
            if let Some(sg) = r.get("signer").and_then(|s| s.as_u64()) {
                assert_eq!(
                    &r["margin"],
                    &inputs["margin"][sg.to_string()],
                    "margin {r}"
                );
            }
            // ruling 2 (A4: every verify row): a verify row's `sig_bytes`, measured beside its delta
            if let Some(n) = r.get("sig_bytes").filter(|_| r.get("signer").is_some()) {
                let k = keys.strip_suffix("_delta").unwrap();
                assert_eq!(key(&format!("{k}_sig_bytes")), n.as_u64().unwrap(), "{r}");
                assert_eq!(
                    native_sig,
                    Some(key("verify_native_sig_bytes")),
                    "the reference signer's sig_bytes"
                );
            }
            // a per-byte or per-item part (I1): the worst of its source keys (each a whole-gas slope)
            for p in r.get("per_byte").into_iter().chain(r.get("per_item")) {
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

    /// G2 (owner 2026-11-19, "approved"): a base row's `ua_extra` covers every variant a derived signer can sign. Its own figure
    /// is the worst of the variants measured with the derived reference signer (`reference_rows_hold_their_sources`), the
    /// variants measured without it listed `unmeasured` (theirs is the largest measured on another variant); a row none of
    /// whose variants was measured takes the largest `ua_extra` measured for the same entry and lane state on another kind
    /// (`from_kind`, every variant `unmeasured`), never none; an entry a derived signer cannot sign (`ua_native` of the input
    /// list: its kind or its entry) has none and no derived measurement.
    #[test]
    fn reference_ua_extra_covers_every_variant() {
        use std::collections::BTreeSet;
        let t: serde_json::Value = serde_json::from_str(REFERENCE_FILE).unwrap();
        let inputs: serde_json::Value =
            serde_json::from_str(include_str!("../../gas/inputs.json")).unwrap();
        let file = format!(
            "{}/../../{}",
            env!("CARGO_MANIFEST_DIR"),
            inputs["measurements"].as_str().unwrap()
        );
        let m: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        let keys: Vec<&str> = m
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .filter(|k| !k.ends_with("_regular") && !k.ends_with("_state"))
            .collect();
        let vars = |pre: &str| -> BTreeSet<String> {
            keys.iter()
                .filter_map(|k| k.strip_prefix(pre))
                .map(str::to_string)
                .collect()
        };
        let native = |list: &str, x: &str| {
            inputs["ua_native"][list]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v == x)
        };
        let base = t["base"].as_array().unwrap();
        for r in base {
            let (kind, entry) = (r["kind"].as_str().unwrap(), r["entry"].as_str().unwrap());
            let fresh = vars(&format!("{kind}_{entry}_fresh_"));
            let ua = vars(&format!("{kind}_{entry}_ua_"));
            let x = r.get("ua_extra");
            if native("kinds", kind) || native("entries", entry) {
                assert!(x.is_none() && ua.is_empty(), "native-only {r}");
                continue;
            }
            let listed: BTreeSet<String> = x
                .and_then(|x| x.get("unmeasured"))
                .map(|u| {
                    u.as_array()
                        .unwrap()
                        .iter()
                        .map(|v| v.as_str().unwrap().to_string())
                        .collect()
                })
                .unwrap_or_default();
            if ua.is_empty() {
                let x = x.unwrap_or_else(|| panic!("no ua_extra and none measured: {r}"));
                let own = |o: &&serde_json::Value| {
                    o["entry"] == r["entry"]
                        && o["fresh"] == r["fresh"]
                        && o["kind"] != r["kind"]
                        && o.get("ua_extra")
                            .is_some_and(|u| u.get("from_kind").is_none())
                };
                let best = base
                    .iter()
                    .filter(own)
                    .map(|o| o["ua_extra"]["measured"].as_u64().unwrap())
                    .max()
                    .unwrap_or_else(|| panic!("no donor: {r}"));
                assert_eq!(
                    x["measured"].as_u64(),
                    Some(best),
                    "the largest on another kind: {r}"
                );
                assert!(
                    base.iter().filter(own).any(|o| o["kind"] == x["from_kind"]
                        && o["ua_extra"]["measured"] == x["measured"]),
                    "from_kind names it: {r}"
                );
                assert_eq!(listed, fresh, "every variant unmeasured: {r}");
            } else {
                // its own: present exactly when a variant's derived run cost more than the native one and its verify row
                let worst = ua
                    .iter()
                    .map(|v| {
                        let k = |w: &str| m[format!("{kind}_{entry}_{w}_{v}")].as_i64().unwrap();
                        k("ua") - k("fresh") - m["verify_0x0108_delta"].as_i64().unwrap()
                    })
                    .max()
                    .unwrap();
                assert_eq!(
                    x.is_some(),
                    worst > 0,
                    "ua_extra where the derived run costs more: {r}"
                );
                if let Some(x) = x {
                    assert!(x.get("from_kind").is_none(), "{r}");
                    assert_eq!(
                        listed,
                        &fresh - &ua,
                        "the variants without a derived run: {r}"
                    );
                }
            }
        }
    }

    /// The kinds whose verify gas depends on the data (owner 2026-11-19, "approved, as proposed"): ed25519 (its row the forced
    /// worst case), FN-DSA-512 / -1024 (the most of 64 salts plus `margin`). Each is checked twice: its composition at a
    /// signature of its row's worst-case class (both bounds) and many ordinary ones (the lower bound only).
    const DATA_DEPENDENT: [u16; 3] = [0x0102, 0x0132, 0x0135];

    /// The sampled end-to-end check (spec §13.3; owner 2026-11-19, item 7, A1 and the two rulings on the check): the `token`
    /// entries `SdkGasSample.t.sol` signs end to end on `NormalToken` by the native key, P-256, ed25519 and secp256k1, both
    /// lanes, held to the SDK's own composition (`lookup`: base + verify (with `margin`) + `ua_extra`, the verify part's
    /// calldata bytes left out, the run being execution gas) with the base row at that variant's own figure (the table's is
    /// the worst of the variants, regulated included): measured <= composed < measured + 3,000 (three parts each rounded up
    /// to 1,000; it was 2,000). A data-dependent kind's cell is signed by a signature of its row's worst-case class
    /// (ed25519: every window of `S` and `k` nonzero), and its `_safety` key, the most expensive of 32 ordinary signatures, is
    /// held to the lower bound only; FN-DSA (not forge-signable) is held at its verify row: the delta less the measured extra
    /// plus the 64 further salts' extra (`verify_<kind>_safety_extra`) never above the row with its margin. The sampled
    /// signature's bytes are the verify row's `sig_bytes`.
    #[test]
    fn sampled_end_to_end_check() {
        let file = format!(
            "{}/../../smartcontracts/evm/test/vectors/sdk_gas.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let m: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
        let key = |k: &str| m[k].as_u64().unwrap_or_else(|| panic!("{k}"));
        let t = GasTable::parse(REFERENCE_FILE).unwrap();
        let mut out = vec![];
        for signer in [NATIVE_EVM, 0x0101, 0x0102, 0x0108] {
            let s = format!("sample_{signer:04x}");
            let v = t.rows.verify.iter().find(|v| v.signer == signer).unwrap();
            assert_eq!(key(&format!("{s}_sig_bytes")), v.sig_bytes, "{s}");
            for entry in ["mtxExecuteTransfer", "mtxPay", "mtxCancelNonce", "mtxBurn"] {
                for (fresh, lane) in [(true, "fresh"), (false, "used")] {
                    let mut rows = t.rows.clone();
                    let own = key(&format!("token_{entry}_{lane}_normal")).div_ceil(1_000) * 1_000;
                    for b in rows
                        .base
                        .iter_mut()
                        .filter(|b| b.key() == (entry, "token", fresh))
                    {
                        b.gas = own;
                    }
                    let (g, _) =
                        lookup(&rows, &[], &[], None, (entry, "token", signer, fresh)).unwrap();
                    let composed = g - PER_BYTE * v.sig_bytes;
                    let measured = key(&format!("{s}_{entry}_{lane}_normal"));
                    out.push((
                        s.clone(),
                        entry,
                        lane,
                        composed.cast_signed() - measured.cast_signed(),
                    ));
                    if DATA_DEPENDENT.contains(&signer) {
                        let most = key(&format!("{s}_{entry}_{lane}_normal_safety"));
                        assert!(
                            composed >= most,
                            "{s} {entry} {lane}: safety {most} > {composed}"
                        );
                    }
                }
            }
        }
        for k in [0x0132u16, 0x0135] {
            let v = t.rows.verify.iter().find(|v| v.signer == k).unwrap();
            let h = format!("verify_{k:#06x}");
            let safe = key(&format!("{h}_delta")) - key(&format!("{h}_varied_extra"))
                + key(&format!("{h}_safety_extra"));
            assert!(
                v.gas + v.margin >= safe,
                "{h}: safety {safe} > {}",
                v.gas + v.margin
            );
        }
        let bad: Vec<_> = out.iter().filter(|x| !(0..3_000).contains(&x.3)).collect();
        assert!(
            bad.is_empty(),
            "measured <= base + verify + ua_extra < measured + 3,000; slack out of bounds: {bad:?}"
        );
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
            .unwrap()
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

    fn per_item(item: &str, gas: u64) -> Option<GasPerItem> {
        Some(GasPerItem {
            item: item.into(),
            gas,
        })
    }

    /// Owner 2026-11-19, I1: a base row's and a verify row's `per_item` add their gas times the count each names, read from
    /// the operation (`gas + per_item × count`, the row's figure being at a count of 0), on top of the other parts; a row
    /// without one reads no count and quotes as before; a count the SDK cannot read, or above `COUNT_MAX`, refuses the
    /// operation as `GasCountUnknown`, never a figure from a later table or the app's; an attached signature's row with one
    /// too. Each beside its control.
    #[test]
    fn gas_per_item_adds_gas_times_its_count() {
        let by = |r: &GasRows, counts: &[(&str, u64)], app: Option<u64>, attached| {
            let count = |i: &str| counts.iter().find(|c| c.0 == i).map(|c| c.1);
            lookup_by(
                r,
                &[],
                &[],
                app,
                K,
                &OpGas {
                    count: &count,
                    attached,
                    ..OpGas::PLAIN
                },
            )
            .map(|f| f.map(|f| f.0))
            .map_err(|e| e.code())
        };
        let mut r = rows(1_000, 10);
        let both = [("legs", 3), ("members", 5)];
        assert_eq!(
            by(&r, &[], None, None),
            Ok(Some(1_010)),
            "absent: unchanged, no count read"
        );
        assert_eq!(
            by(&r, &both, None, None),
            Ok(Some(1_010)),
            "absent: a count adds nothing"
        );
        r.base[0].per_item = per_item("legs", 30_000);
        r.base[0].save = Some(331_000);
        assert_eq!(
            by(&r, &both, None, None),
            Ok(Some(1_010 + 90_000)),
            "base: gas + per_item × 3"
        );
        assert_eq!(
            by(&r, &[("legs", 0)], None, None),
            Ok(Some(1_010)),
            "a count of 0: the row's figure"
        );
        r.verify[0].per_item = per_item("members", 450);
        assert_eq!(
            by(&r, &both, None, None),
            Ok(Some(1_010 + 90_000 + 2_250)),
            "verify: gas + per_item × 5, on top of the base's"
        );
        for counts in [
            &[("legs", 3)][..],
            &[("members", 5)],
            &[("legs", 3), ("members", COUNT_MAX + 1)],
        ] {
            assert_eq!(
                by(&r, counts, Some(9), None),
                Err("GasCountUnknown"),
                "{counts:?}"
            );
        }
        assert_eq!(
            by(&r, &[("legs", COUNT_MAX), ("members", 0)], None, None),
            Ok(Some(1_010 + 30_000 * COUNT_MAX)),
            "the bound itself"
        );
        // a count unknown on the chain's row refuses, though a later table's row would answer without one (fail closed)
        let mut chain = rows(1_000, 10);
        chain.base[0].per_item = per_item("legs", 30_000);
        let later = vec![table(REFERENCE, rows(4_000, 40))];
        let opt = all(&[REFERENCE]);
        let plain = lookup_by(&chain, &opt, &later, None, K, &OpGas::PLAIN);
        assert_eq!(plain.map_err(|e| e.code()), Err("GasCountUnknown"));
        chain.base[0].per_item = None;
        assert_eq!(
            lookup_by(&chain, &opt, &later, None, K, &OpGas::PLAIN)
                .unwrap()
                .map(|f| f.0),
            Some(1_010),
            "control"
        );
        // overflow-safe: a figure past u64 saturates (2^63 × 2 wraps to 0)
        r.base[0].per_item = per_item("legs", 1 << 63);
        assert_eq!(
            by(&r, &[("legs", 2), ("members", 0)], None, None),
            Ok(Some(u64::MAX))
        );
        // an attached signature's verify row with a per-item part: its count is not read, refused
        let mut r = rows(1_000, 10);
        r.verify.push(GasVerify {
            signer: 0x0102,
            gas: 5,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        });
        assert_eq!(by(&r, &both, None, Some(Some(0x0102))), Ok(Some(1_015)));
        r.verify[1].per_item = per_item("members", 450);
        assert_eq!(
            by(&r, &both, None, Some(Some(0x0102))),
            Err("GasCountUnknown")
        );
    }

    /// I1: the counts read from the operation's signed message, each item from its own field; `None` where it has none.
    #[test]
    fn item_count_reads_the_operations_counts() {
        use serde_json::json as j;
        let none = j!({});
        let item_count = |m: &serde_json::Value, i: &str| item_count(&none, m, i);
        let multi = j!({"from": "0x01", "args": {"legs": [{}, {}, {}], "u": [1]}});
        assert_eq!(
            item_count(&multi, "legs"),
            Some(3),
            "a multi-recipient transfer's legs"
        );
        assert_eq!(
            item_count(&j!({"legs": [{}, {}]}), "legs"),
            Some(2),
            "mtxSetWrapLimits' legs"
        );
        assert_eq!(
            item_count(&j!({"uas": ["0x01", "0x02"]}), "accounts"),
            Some(2),
            "mtxRollOverBatch"
        );
        assert_eq!(
            item_count(&j!({"accounts": ["0x01"], "flags": [1, 2]}), "accounts"),
            Some(1)
        );
        assert_eq!(
            item_count(&j!({"n": "7"}), "entries"),
            Some(7),
            "a rollover's n, decimal"
        );
        assert_eq!(item_count(&j!({"n": 9}), "entries"), Some(9));
        assert_eq!(item_count(&j!({"legs": []}), "legs"), Some(0));
        // K2: mtxCreateToken's TokenConfig.legs, in the op's extra (the message carries only its hash)
        let cfg = j!({"config": {"name": "W", "legs": [{}, {}, {}, {}]}});
        assert_eq!(
            super::item_count(&cfg, &j!({"initHash": "0x01"}), "legs"),
            Some(4),
            "TokenConfig.legs"
        );
        assert_eq!(
            super::item_count(&j!({"config": {"legs": []}}), &none, "legs"),
            Some(0)
        );
        assert_eq!(
            super::item_count(&cfg, &j!({"legs": [{}]}), "legs"),
            Some(1),
            "the message's own first"
        );
        // P1: a signed rollover's skip marks added to n; none without the field
        assert_eq!(
            item_count(&j!({"n": 3, "skip": [5, 9]}), "entries"),
            Some(5),
            "n + len(skip)"
        );
        assert_eq!(
            item_count(&j!({"n": 0, "skip": [5]}), "entries"),
            Some(1),
            "marks only"
        );
        assert_eq!(
            item_count(&j!({"n": 2, "skip": "x"}), "entries"),
            None,
            "a skip not a list"
        );
        // P1, K2: an env publish's four arrays together
        let env = j!({"env": {"deps": ["0x01"], "params": ["0x02", "0x03"], "libs": ["0x04"], "libCodeHashes": ["0x05"]}});
        assert_eq!(
            item_count(&env, "env_items"),
            Some(5),
            "every element of the four arrays"
        );
        let empty = j!({"env": {"deps": [], "params": [], "libs": [], "libCodeHashes": []}});
        assert_eq!(item_count(&empty, "env_items"), Some(0));
        assert_eq!(
            item_count(&j!({"env": {"deps": []}}), "env_items"),
            None,
            "an array missing"
        );
        // K2: the DEX cancel's one order; a list of them counted
        assert_eq!(
            item_count(&j!({"order": {"nonce": "1"}}), "orders"),
            Some(1),
            "the SDK's one order"
        );
        assert_eq!(item_count(&j!({"orders": [{}, {}]}), "orders"), Some(2));
        assert_eq!(item_count(&j!({"order": "0x01"}), "orders"), None);
        // K1: a rollover's n held to the set's ROLL_MAX (control: n at ROLL_MAX itself); every other count unclamped; a
        // build without a set (no PQZ entry) reads n as given
        let huge = alloy::primitives::U256::MAX.to_string();
        if let Some(m) = roll_max() {
            assert_eq!(item_count(&j!({"n": m.to_string()}), "entries"), Some(m));
            for n in [j!(m + 1), j!(huge), j!(u64::MAX)] {
                assert_eq!(item_count(&j!({"n": n}), "entries"), Some(m), "{n}");
            }
            // P1: n clamped first, then the skip marks added
            assert_eq!(
                item_count(&j!({"n": huge, "skip": [1, 2]}), "entries"),
                Some(m + 2)
            );
        } else {
            assert_eq!(item_count(&j!({"n": 1_000}), "entries"), Some(1_000));
            assert_eq!(item_count(&j!({"n": huge}), "entries"), None);
        }
        let legs = vec![j!({}); (COUNT_MAX + 1) as usize];
        assert_eq!(
            item_count(&j!({"legs": legs}), "legs"),
            Some(COUNT_MAX + 1),
            "not clamped"
        );
        for (m, item) in [
            (j!({"n": "0x07"}), "entries"),
            (j!({"n": "-1"}), "entries"),
            (j!({"uas": "0x01"}), "accounts"),
            (j!({"legs": [{}]}), "accounts"),
            (multi.clone(), "members"),
            (multi.clone(), "u"),
            (j!({}), "legs"),
        ] {
            assert_eq!(item_count(&m, item), None, "{m} {item}");
        }
    }

    /// K1: a rollover whose `n` is far above the contract's bound is quoted at `ROLL_MAX` entries, not refused; a count of
    /// another item above `COUNT_MAX` is still `GasCountUnknown` (each read by `item_count` from the operation's message).
    #[test]
    fn a_huge_rollover_is_quoted_at_roll_max() {
        use serde_json::json as j;
        let quote = |item: &str, message: serde_json::Value| {
            let mut r = rows(1_000, 10);
            r.base[0].per_item = per_item(item, 30_000);
            let count = |i: &str| item_count(&serde_json::Value::Null, &message, i);
            lookup_by(
                &r,
                &[],
                &[],
                None,
                K,
                &OpGas {
                    count: &count,
                    ..OpGas::PLAIN
                },
            )
            .map(|f| f.map(|f| f.0))
            .map_err(|e| e.code())
        };
        let huge = j!({"n": alloy::primitives::U256::MAX.to_string()});
        match roll_max() {
            Some(m) => assert_eq!(quote("entries", huge), Ok(Some(1_010 + 30_000 * m))),
            None => assert_eq!(
                quote("entries", huge),
                Err("GasCountUnknown"),
                "no set: no bound to hold it to"
            ),
        }
        assert_eq!(
            quote("entries", j!({"n": 3})),
            Ok(Some(1_010 + 90_000)),
            "control: below the bound"
        );
        let legs = |n: u64| j!({"legs": vec![j!(0); n as usize]});
        assert_eq!(
            quote("legs", legs(COUNT_MAX)),
            Ok(Some(1_010 + 30_000 * COUNT_MAX)),
            "control: the cap"
        );
        assert_eq!(quote("legs", legs(COUNT_MAX + 1)), Err("GasCountUnknown"));
    }

    /// K1: `ROLL_MAX` per set equals the generated `PqzSet.sol` of that set, in the order of `scaas_ua::build::PQZ_SETS`.
    #[test]
    fn roll_max_is_the_sets_own() {
        for (set, want) in [
            "n2048-kmax1024",
            "n2304-kmax4096",
            "n2560-kmax16384",
            "n2816-kmax65536",
        ]
        .iter()
        .zip(ROLL_MAX)
        {
            let path = format!(
                "{}/../../pqz-core/params/sets/{set}/PqzSet.sol",
                env!("CARGO_MANIFEST_DIR")
            );
            let src = std::fs::read_to_string(path).unwrap();
            let line = src
                .lines()
                .find(|l| l.contains("uint256 internal constant ROLL_MAX = "))
                .unwrap();
            let got: u64 = line
                .split("= ")
                .nth(1)
                .unwrap()
                .trim_end_matches(';')
                .trim()
                .parse()
                .unwrap();
            assert_eq!(got, want, "{set}");
        }
        // the build's set picks its own figure
        let pinned = [
            (cfg!(feature = "pqz-set-n2048-kmax1024"), 80),
            (cfg!(feature = "pqz-set-n2304-kmax4096"), 64),
            (cfg!(feature = "pqz-set-n2560-kmax16384"), 48),
            (cfg!(feature = "pqz-set-n2816-kmax65536"), 32),
        ];
        assert_eq!(roll_max(), pinned.iter().find(|p| p.0).map(|p| p.1));
    }

    /// I1, the parse: `item` and `per_item` together on base and verify rows (`GasItemUnpaired` otherwise), `item` one the SDK
    /// reads (`GasItemUnknown` otherwise), `per_item` `{gas 1–2^24, base_count 0, source}` (`Argument` otherwise); a
    /// file without them reads unchanged. Each refusal beside its control.
    #[test]
    fn gas_table_per_item_parse() {
        let part =
            |g: u64, at: u64| format!(r#""per_item":{{"gas":{g},"base_count":{at},"source":"s"}}"#);
        let base = |f: &str| {
            file(
                &b(98_000, 97_947).replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
                "",
            )
        };
        let verify = |f: &str| {
            file(
                "",
                &v(289, 1_000, 900).replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
            )
        };
        let ok = format!(r#""item":"legs",{}"#, part(31_000, 0));
        assert_eq!(
            GasTable::parse(&base(&ok)).unwrap().rows.base[0].per_item,
            per_item("legs", 31_000)
        );
        let members = format!(r#""item":"members",{}"#, part(450, 0));
        assert_eq!(
            GasTable::parse(&verify(&members)).unwrap().rows.verify[0].per_item,
            per_item("members", 450)
        );
        assert_eq!(
            GasTable::parse(&file(&b(98_000, 97_947), ""))
                .unwrap()
                .rows
                .base[0]
                .per_item,
            None,
            "absent"
        );
        assert!(
            GasTable::parse(&base(&format!(r#""item":"entries",{}"#, part(1 << 24, 0)))).is_ok()
        );
        for item in ["env_items", "orders"] {
            let f = format!(r#""item":"{item}",{}"#, part(450, 0));
            assert_eq!(
                GasTable::parse(&base(&f)).unwrap().rows.base[0].per_item,
                per_item(item, 450),
                "{item}"
            );
        }
        for row in [base, verify] {
            for (f, code) in [
                (part(450, 0), "GasItemUnpaired"),
                (r#""item":"legs""#.to_string(), "GasItemUnpaired"),
                (
                    format!(r#""item":"uas",{}"#, part(450, 0)),
                    "GasItemUnknown",
                ),
                (
                    format!(r#""item":"Legs",{}"#, part(450, 0)),
                    "GasItemUnknown",
                ),
                (format!(r#""item":"legs",{}"#, part(450, 1)), "Argument"),
                (format!(r#""item":"legs",{}"#, part(0, 0)), "Argument"),
                (
                    format!(r#""item":"legs",{}"#, part((1 << 24) + 1, 0)),
                    "Argument",
                ),
                (
                    format!(r#""item":"env",{}"#, part(450, 0)),
                    "GasItemUnknown",
                ),
                (
                    format!(
                        r#""item":"legs",{}"#,
                        part(450, 0).replace(r#","source":"s""#, "")
                    ),
                    "Argument",
                ),
                (
                    format!(
                        r#""item":"legs",{}"#,
                        part(450, 0).replace(r#""base_count":0,"#, "")
                    ),
                    "Argument",
                ),
                (format!(r#""item":7,{}"#, part(450, 0)), "Argument"),
                (r#""item":"legs","per_item":450"#.to_string(), "Argument"),
                // the part checked even when unpaired: a broken file stays `Argument`
                (part(0, 0), "Argument"),
            ] {
                assert_eq!(GasTable::parse(&row(&f)).unwrap_err().code(), code, "{f}");
            }
        }
    }

    /// PR A review, finding 1: a key outside the format, at the top, on a base or verify row, or inside a row's `per_byte`,
    /// `per_item`, `save`, `fee_extra`, `ua_extra` or its `second_party`, is refused by name, `GasFieldUnknown`, never dropped
    /// from a quote; every key the format and the generator write is read (control: each part with all its keys, `calldata_gas`
    /// with its source keys, `stand_in`, `assumptions`, and the reference table).
    #[test]
    fn gas_table_unknown_key_refused() {
        let fig = r#"{"gas":1000,"measured":900,"source":"s"}"#;
        let full = format!(
            r#""calldata_gas":{{"k1":10}},"stand_in":"t","per_byte":{{"input":"data","gas":16,"source":"s"}},"save":{fig},"fee_extra":{fig},"ua_extra":{{"gas":1000,"measured":900,"source":"s","second_party":{{"measured":-5,"source":"s"}},"unmeasured":[],"from_kind":"token"}},"item":"legs","per_item":{{"gas":450,"base_count":0,"source":"s"}}"#
        );
        let base = |f: &str| {
            file(
                &b(98_000, 97_947).replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
                "",
            )
        };
        let verify = |f: &str| {
            file(
                "",
                &v(289, 1_000, 900).replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
            )
        };
        let top = |f: &str| file(&b(98_000, 97_947), "").replace(r#""assumptions":[]"#, f);
        let vfull = r#""margin":1000,"stand_in":"t","item":"members","per_item":{"gas":450,"base_count":0,"source":"s"}"#;
        for (t, what) in [
            (base(&full), "base"),
            (verify(vfull), "verify"),
            (top(r#""assumptions":["a"]"#), "top"),
        ] {
            assert!(GasTable::parse(&t).is_ok(), "control: {what}");
        }
        assert!(
            GasTable::parse(REFERENCE_FILE).is_ok(),
            "control: the reference table"
        );
        for t in [
            top(r#""assumptions":[],"comment":"x""#),
            base(&format!(r#"{full},"per_iten":1"#)),
            base(&full.replace(r#""fee_extra""#, r#""fee_xtra""#)),
            base(&full.replace(r#""stand_in""#, r#""ua_extra ""#)),
            base(&full.replace(r#""input":"data""#, r#""input":"data","inptu":1"#)),
            base(&full.replace(r#""base_count":0"#, r#""base_count":0,"slope":1"#)),
            base(&full.replace(r#""save":{"gas":1000"#, r#""save":{"gas":1000,"extra":1"#)),
            base(&full.replace(
                r#""fee_extra":{"gas":1000"#,
                r#""fee_extra":{"gas":1000,"extra":1"#,
            )),
            base(&full.replace(r#""from_kind""#, r#""from_knd""#)),
            base(&full.replace(r#""measured":-5"#, r#""measured":-5,"gas":1"#)),
            verify(&format!(r#"{vfull},"margn":1"#)),
            verify(&vfull.replace(r#""base_count":0"#, r#""base_count":0,"x":1"#)),
            // a part of `ua_extra` only, never of a row
            base(&format!(
                r#"{full},"second_party":{{"measured":1,"source":"s"}}"#
            )),
        ] {
            assert_eq!(
                GasTable::parse(&t).unwrap_err().code(),
                "GasFieldUnknown",
                "{t}"
            );
        }
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
            .unwrap()
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
        r.verify[0].sig_bytes = 128;
        assert_eq!(by(&r, false, false), Some(1_010 + 64 * 128));
    }

    /// Owner 2026-11-19 (the sampled check's ruling 2 (b)): a verify row's `margin` is added with its gas, for the signer and
    /// for an attached signature of that kind alike; parsed 1–100,000, absent 0.
    #[test]
    fn gas_verify_margin() {
        let mut r = rows(1_000, 10);
        r.verify[0].margin = 1_000;
        assert_eq!(lookup(&r, &[], &[], None, K).map(|f| f.0), Some(2_010));
        r.verify.push(GasVerify {
            signer: 0x0102,
            gas: 5,
            sig_bytes: 0,
            margin: 2_000,
            per_item: None,
        });
        let op = OpGas {
            attached: Some(Some(0x0102)),
            ..OpGas::PLAIN
        };
        assert_eq!(
            lookup_by(&r, &[], &[], None, K, &op).unwrap().map(|f| f.0),
            Some(2_010 + 2_005),
            "the attached kind's margin too"
        );
        let with = |m: &str| {
            file(
                "",
                &v(306, 3_000, 2_100).replace(r#""sig_bytes":0"#, &format!(r#""sig_bytes":0,{m}"#)),
            )
        };
        assert_eq!(
            GasTable::parse(&with(r#""margin":1000"#))
                .unwrap()
                .rows
                .verify[0]
                .margin,
            1_000
        );
        // no `margin`: 0 (the control's filler key `"x"` is refused since the PR A review's finding 1)
        assert_eq!(
            GasTable::parse(&file("", &v(306, 3_000, 2_100)))
                .unwrap()
                .rows
                .verify[0]
                .margin,
            0
        );
        assert_eq!(
            GasTable::parse(&with(r#""x":0"#)).unwrap_err().code(),
            "GasFieldUnknown"
        );
        for bad in [r#""margin":0"#, r#""margin":100001"#, r#""margin":"1000""#] {
            assert!(GasTable::parse(&with(bad)).is_err(), "{bad}");
        }
    }

    /// Owner 2026-11-19, A1 and G1: a derived-UA signer, or an attached signature's derived owner, adds the row's `ua_extra`
    /// once, the native key nothing; a row without one adds nothing. Each beside its control.
    #[test]
    fn gas_ua_extra_for_a_derived_signer() {
        let mut r = rows(1_000, 10);
        r.verify = ACCEPTED_SIGNERS
            .iter()
            .map(|s| GasVerify {
                signer: *s,
                gas: if *s == 0x0101 { 10 } else { 0 },
                sig_bytes: 0,
                margin: 0,
                per_item: None,
            })
            .collect();
        let by = |r: &GasRows, signer: u16| {
            lookup(r, &[], &[], None, ("mtxPay", "token", signer, false)).map(|f| f.0)
        };
        assert_eq!(by(&r, 0x0101), Some(1_010), "no ua_extra: nothing added");
        r.base[0].ua_extra = Some(14_000);
        assert_eq!(by(&r, 0x0101), Some(1_010 + 14_000), "a derived signer");
        assert_eq!(by(&r, NATIVE_EVM), Some(1_000), "the native key");
        // G1: the attached signature's owner is debited too (`mtxPayWithPayeeFee`'s payer under the signing payee): a derived
        // payer (or one of unknown kind) under a native payee adds it; native both: not; derived both: once
        let with = |signer: u16, attached| {
            let op = OpGas {
                attached: Some(attached),
                ..OpGas::PLAIN
            };
            lookup_by(&r, &[], &[], None, ("mtxPay", "token", signer, false), &op)
                .unwrap()
                .map(|f| f.0)
        };
        assert_eq!(
            with(NATIVE_EVM, Some(0x0101)),
            Some(1_000 + 10 + 14_000),
            "a derived payer, a native payee"
        );
        assert_eq!(
            with(NATIVE_EVM, None),
            Some(1_000 + 10 + 14_000),
            "a payer of unknown kind (the dearest verify: 0x0101's 10 here)"
        );
        assert_eq!(
            with(NATIVE_EVM, Some(NATIVE_EVM)),
            Some(1_000),
            "native both"
        );
        assert_eq!(
            with(0x0101, Some(0x0101)),
            Some(1_010 + 14_000 + 10),
            "derived both: once"
        );
    }

    /// PR A review, finding 4: an entry that debits a third party adds the row's `ua_extra` when that holder is (or may be) a
    /// derived UA, under a native signer too, once; a native holder adds nothing. `holder_derived` reads it:
    /// `mtxOperatorTransfer`'s `account`, `mtxForceTransfer`'s record holder (not in the message: derived), no other entry.
    #[test]
    fn gas_ua_extra_for_a_derived_holder() {
        let mut r = rows(1_000, 10);
        r.base[0].entry = "mtxOperatorTransfer".into();
        r.base[0].kind = "gov_router".into();
        r.base[0].ua_extra = Some(15_000);
        r.verify.push(GasVerify {
            signer: NATIVE_EVM,
            gas: 0,
            sig_bytes: 0,
            margin: 0,
            per_item: None,
        });
        let by = |signer: u16, holder: bool| {
            let op = OpGas {
                holder,
                ..OpGas::PLAIN
            };
            let key = ("mtxOperatorTransfer", "gov_router", signer, false);
            lookup_by(&r, &[], &[], None, key, &op)
                .unwrap()
                .map(|f| f.0)
        };
        assert_eq!(
            by(NATIVE_EVM, false),
            Some(1_000),
            "native signer, native holder"
        );
        assert_eq!(
            by(NATIVE_EVM, true),
            Some(1_000 + 15_000),
            "native signer, derived holder"
        );
        assert_eq!(by(0x0101, true), Some(1_010 + 15_000), "derived both: once");
        let native = format!("0x{}{}", "00".repeat(12), "ab".repeat(20));
        let derived = format!("0x{}", "5c".repeat(32));
        assert!(scaas_ua::in_native_space(
            &super::super::unhex(&native).unwrap().try_into().unwrap()
        ));
        let msg = |a: &str| serde_json::json!({"from": native, "account": a, "to": native});
        assert!(
            !holder_derived("mtxOperatorTransfer", &msg(&native)),
            "a native holder"
        );
        assert!(
            holder_derived("mtxOperatorTransfer", &msg(&derived)),
            "a derived holder"
        );
        assert!(
            holder_derived("mtxOperatorTransfer", &serde_json::json!({})),
            "unreadable: derived"
        );
        assert!(
            holder_derived("mtxForceTransfer", &msg(&native)),
            "the record's holder: derived"
        );
        for e in ["mtxPay", "mtxFreeze", "mtxMintToUA", "mtxGrantRole"] {
            assert!(
                !holder_derived(e, &msg(&derived)),
                "{e}: no third-party debit"
            );
        }
    }

    /// Owner 2026-11-19, ruling 4 (A2: the attached signature): a second signature adds its kind's verify gas, not its
    /// `sig_bytes` (A3: its bytes are in the unsigned calldata already); of an unknown kind, the most expensive of the accepted
    /// kinds, and no answer when one of them has no row.
    #[test]
    fn gas_second_signature() {
        let mut r = rows(1_000, 10);
        r.verify = ACCEPTED_SIGNERS
            .iter()
            .map(|s| GasVerify {
                signer: *s,
                gas: u64::from(*s),
                sig_bytes: 1,
                margin: 0,
                per_item: None,
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
            .unwrap()
            .map(|f| f.0)
        };
        let own = 1_000 + 0x0101 + 64;
        assert_eq!(by(&r, None), Some(own));
        assert_eq!(
            by(&r, Some(Some(0x0102))),
            Some(own + 0x0102),
            "the attached kind's verify gas, not its bytes"
        );
        assert_eq!(by(&r, Some(Some(0))), Some(own));
        assert_eq!(
            by(&r, Some(None)),
            Some(own + 0x0135),
            "unknown: the most expensive"
        );
        r.verify[3].gas = 1_000_000;
        assert_eq!(by(&r, Some(None)), Some(own + 1_000_000));
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

    /// Owner 2026-11-19, G3: a quote counted the unsigned calldata plus its verify row's `sig_bytes` when the verify part
    /// came from a row (the same row, by the same order), the unsigned calldata only for an app's figure, an estimate or no
    /// source; once signed, the bytes beyond that at 64 gas a byte with the margin, never below the quote.
    #[test]
    fn signed_gas_counts_the_real_signature() {
        let mut r = rows(1_000, 10);
        r.verify[0].sig_bytes = 128;
        let mut m = rows(1_000, 10);
        m.verify[0].sig_bytes = 200;
        let tables = vec![table("vault", m)];
        let opt = all(&["vault"]);
        let c = |chain: &GasRows, from: Option<GasSources>| {
            counted_bytes(chain, &opt, &tables, 0x0101, from.as_ref(), 500)
        };
        assert_eq!(c(&r, Some(GasSources::both(GasFrom::Chain))), 628);
        assert_eq!(
            c(
                &GasRows::default(),
                Some(src(GasFrom::Chain, module("vault")))
            ),
            700,
            "the module's row, as the quote found it"
        );
        for f in [
            Some(GasSources::both(GasFrom::App)),
            Some(GasSources::both(GasFrom::Estimate)),
            None,
        ] {
            assert_eq!(c(&r, f.clone()), 500, "{f:?}");
        }
        assert_eq!(signed_gas(90_000, 628, 628), 90_000);
        assert_eq!(signed_gas(90_000, 628, 600), 90_000, "never lowered");
        assert_eq!(signed_gas(90_000, 628, 629), 90_000 + 96);
        assert_eq!(signed_gas(90_000, 500, 628), 90_000 + 12_288);
    }

    /// Ruling 4: the attached signature's kind, read from `payerSig` and the payment's `from`; I3: from `consent` and
    /// `newAuditor`.
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
        // I3: mtxSetAuditorUA's consent, signed by the new auditor (`message.newAuditor`)
        let consent = |kd: &str| serde_json::json!({"consent": {"keyData": kd, "signature": "0x01", "members": []}});
        let aud = |a: &str| serde_json::json!({"from": native, "target": "0x01", "newAuditor": a, "epoch": 1});
        assert_eq!(
            attached_kind(
                &consent(&super::super::hex(&kd)),
                &aud(&super::super::hex(&ua))
            ),
            Some(Some(0x0101)),
            "the auditor's kind"
        );
        assert_eq!(
            attached_kind(&consent("0x"), &aud(&super::super::hex(&ua))),
            Some(None),
            "a stored kind's consent: the worst kind"
        );
        assert_eq!(
            attached_kind(&consent(&super::super::hex(&kd)), &aud(&native)),
            Some(None),
            "the consent's key is not the auditor's"
        );
        assert_eq!(
            attached_kind(&serde_json::json!({}), &aud(&native)),
            None,
            "none attached"
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
            r#""ua_extra":{"gas":15000,"measured":13475,"source":"s"}"#,
            r#""ua_extra":{"gas":0,"measured":0,"source":"s"}"#,
            r#""ua_extra":14000"#,
        ] {
            assert!(GasTable::parse(&base(bad)).is_err(), "{bad}");
        }
        assert_eq!(
            GasTable::parse(&base(
                r#""ua_extra":{"gas":14000,"measured":13475,"source":"s"}"#
            ))
            .unwrap()
            .rows
            .base[0]
                .ua_extra,
            Some(14_000)
        );
        let verify = |f: &str| {
            file(
                "",
                &v(257, 1_000, 900)
                    .replace(r#","sig_bytes":0"#, "")
                    .replace(r#""source":"s""#, &format!(r#""source":"s",{f}"#)),
            )
        };
        assert_eq!(
            GasTable::parse(&verify(r#""sig_bytes":65536"#))
                .unwrap()
                .rows
                .verify[0]
                .sig_bytes,
            65_536
        );
        for bad in [
            r#""sig_bytes":65537"#,
            r#""sig_bytes":-1"#,
            r#""sig_bytes":"96""#,
        ] {
            assert!(GasTable::parse(&verify(bad)).is_err(), "{bad}");
        }
    }

    /// Owner 2026-11-19, A4: a verify row without `sig_bytes` is refused by name (`GasSigBytesMissing`), the reference
    /// signer's row too; the same file with it parses; a file broken otherwise stays `Argument`.
    #[test]
    fn gas_verify_row_without_sig_bytes_is_refused() {
        let without = |r: String| r.replace(r#","sig_bytes":0"#, "");
        for row in [v(257, 1_000, 900), v(0, 0, 0)] {
            assert!(GasTable::parse(&file("", &row)).is_ok(), "{row}");
            let e = GasTable::parse(&file("", &without(row.clone()))).unwrap_err();
            assert_eq!(e.code(), "GasSigBytesMissing", "{row}");
        }
        let broken = file("", &without(v(257, 1_000, 900))).replace(r#""v":2"#, r#""v":1"#);
        assert_eq!(GasTable::parse(&broken).unwrap_err().code(), "Argument");
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
                v.is_some_and(|v| v.sig_bytes > 0),
                "signer {s:#06x}: a row with sig_bytes"
            );
        }
    }
}
