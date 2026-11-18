// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T8 (spec §23.1 item 6): the named entries of the EVM contracts, by domain kind. For a `(struct, kind)` row this
//! builds, from one parse of the signed message, what goes to the chain (the entry's calldata) and what goes to a node (the job
//! `op` object of `docs/node/job-api.md` §5.3, `{entry, contract, struct, token, envelope, args, auth | signature}`), so what is
//! hashed is what is sent. The table is a copy of the node's (`scaas-node/src/typed.rs` `TYPED` and `NESTED`, one row per
//! entry, the same plan mini-language); `tests/entries.rs` reads the node's source and holds the two equal both ways, and every
//! row against `smartcontracts/vectors/typed/typed_ops.json`. Values are explicit named JSON (the node's forms); the output is
//! canonical (an unbound `relayer` / `feeRecipient` is 0, as `MetaTxLib.canon`; `uint` of at most 32 bits a JSON number, wider
//! ones decimal strings; hex lowercase). No packed bytes: a nested struct is an object, a list an array. UNAUDITED.
use super::eip712::{abi_atom, to_hex, u256_to_dec, Abi};
use super::{Error, Result};
use crate::keccak256;
use serde_json::{json, Map, Value};

mod account;
mod dex;
mod pqz;
mod router;
mod token;
mod wallet;
mod zether;

/// A row: `(struct, entry, kinds, fields, plan)` as the node's `TYPED` (`E` = the envelope; an empty plan = `E`, the fields
/// between `from` and the envelope, the signature).
pub(crate) type Def = (&'static str, &'static str, &'static [&'static str], &'static str, &'static str);

/// The account's kind (its own entries sign `AccountSig`); the other kind lists are in their files, by the node's names.
const A: &[&str] = &["account"];

const ENV: [&str; 7] = ["batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"];
const E_FIELDS: &str = "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient";
/// Bounds of an untrusted list: an `msig` level holds at most 16 slots (CTR-UA-09), anything else at most 256.
const MSIG_MAX_SLOTS: usize = 16;
const MAX_LIST: usize = 256;
/// A `bytes` / `string` value, and a `PayMeta` body, at most this long.
const MAX_BYTES: usize = 64 * 1024;

/// Every struct a row nests, by the node's names (`NESTED`); `Unwrap` is an unshield-unwrap's payout.
const NESTED: &[(&str, &str)] = &[
    ("G1", "bytes32 x0,bytes32 x1,bytes32 y0,bytes32 y1"),
    ("ZetherSingle", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,G1 yFrom,G1 yTo,G1 cOut,G1 dOut,G1 cDeb,G1 cAud"),
    ("ZetherLeg", "G1 yTo,G1 cOut,G1 cAud,G1 dAud"),
    ("ZetherMulti", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes16 salt,bytes32 beneficiaryUA,uint256 decoyFee,G1 yFrom,G1 dOut,G1 cDeb,ZetherLeg[] legs,bytes sealedMemo"),
    ("ZetherBurn", "uint64 accSeq,uint64 sendCounter,uint256 validUntilBlock,bytes32 beneficiaryUA,G1 yFrom"),
    ("PqzTransferArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 toUA,bytes32 beneficiaryUA,bytes16 salt,bytes32 ownTag,bytes u,bytes vTo,bytes vFrom,bytes vAuditor,bytes uFrom,bytes sealedMemo,PqzOpening openingTo,PqzOpening openingAuditor"),
    ("PqzOpening", "bytes mlkemCt,bytes32 x25519Eph,bytes sealedSeed"),
    ("PqzLeg", "bytes32 ua,bytes v,bytes vAuditor"),
    ("PqzMultiArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,uint256 decoyFee,bytes16 salt,bytes32 ownTag,bytes[] u,PqzLeg[] legs,bytes vFrom,bytes sealedMemo"),
    ("PqzBurnArgs", "uint64 p,uint256 validUntilBlock,uint256 shieldIn,bytes32 fromUA,uint64 keyVersion,bytes32 beneficiaryUA,bytes32 ownTag,bytes u,bytes vFrom"),
    ("Unwrap", "address underlying,bytes32 recipient,uint256 amount,uint256 minOut"),
    ("PqzVerdict", "address token,uint256 chainId,bytes32 proofSystemId,bytes32 statementHash,bytes32 proofHash,uint32 pqzVerifierEpoch,uint64 validUntil"),
    ("PqzSignedVerdict", "PqzVerdict pqzVerdict,UASig sig"),
    ("UAMetaTransfer", "bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient"),
    ("TradeOrder", "address from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,address destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("UATradeOrder", "bytes32 from,address receiveToken,uint256 amount,uint256 receiveAmount,uint256 minFill,uint256 fee,address relayer,address dex,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("UAWrapOrder", "bytes32 from,address wrappedToken,uint256 amount,uint256 minMinted,uint256 minFill,uint256 fee,address relayer,bytes32 destination,uint8 flags,uint256 batch,uint256 nonce,uint256 validUntil"),
    ("DexOrder", "address sellToken,TradeOrder order"),
    ("InnerSig", "uint16 index,bytes sig"),
    ("MemberSig", "uint16 index,InnerSig[] members,bytes sig"),
    ("UASig", "bytes keyData,bytes signature,MemberSig[] members"),
    ("AccountSig", "uint256 keyIndex,bytes32[] proof,bytes signature"),
    ("GrantTerms", "uint128 min,uint128 max,uint128 total,uint128 perWindow,uint32 window,uint64 validUntil,uint32 maxUses,bool delegable,bytes32 scope"),
    ("WrapLimit", "uint24 perUser,uint64 tokenWide,uint32 period"),
    ("WrapLegLimits", "address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong"),
    ("TokenRoles", "bytes32 minter,bytes32 rateAdmin,bytes32 guardian,bytes32 issuer,bytes32 compliance,bytes32 burner"),
    ("TokenLeg", "address underlying,uint256 num,uint256 den"),
    ("TokenRate", "uint32 rateDelay,uint16 maxRateStepBps"),
    ("ConfidentialConfig", "bytes auditorKey,uint256 shieldScale,uint256 maxShielded,uint256 confidentialFee,uint8 disclosureMode,uint8 auditorMode,uint256 minDecoyFee,uint8 pqzVerifyMode,bytes32 pqzVerifierUA,bool pqzVerifierFixed,uint8 proofStore,uint64 verifierFee,uint64 verifierFeeMax,bool pqzOwnKey,bool pqzOpening"),
    ("RegulatedParams", "address complianceRegistry,uint64 requiredFlags,uint64 deniedFlags,bytes32 termsHash,bytes32 taxRecipient"),
    ("TokenConfig", "string name,string symbol,uint8 decimals,uint256 features,uint256 lockedFeatures,bytes32 admin,TokenRoles roles,uint256 initialSupply,address initialHolder,TokenLeg[] legs,TokenRate rate,ConfidentialConfig conf,uint64 grantDelay,address rescueTo,uint256 maxSupply,uint256 maxWrapSupply,RegulatedParams reg"),
    ("DexConfig", "bytes32 admin,uint32 relayerSharePpm,address treasury,bool listedOnly,uint64 grantDelay,address rescueTo,uint256 features,uint256 lockedFeatures"),
    ("Env", "address registry,address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params,address[] libs,bytes32[] libCodeHashes"),
    ("ChainEntries", "address relayFeeRouter,bytes32 relayFeeRouterCodeHash,bytes32 relayFeeExecutorCodeHash,address complianceRegistry,bytes32 complianceRegistryCodeHash,address smartKeyAccountFactory,bytes32 smartKeyAccountFactoryCodeHash,address zetherStatements,bytes32 zetherStatementsCodeHash"),
];

/// The rows, every kind's file in turn.
fn defs() -> impl Iterator<Item = (&'static Def, bool)> {
    let node = [token::ROWS, zether::ROWS, pqz::ROWS, wallet::ROWS, account::ROWS, dex::ROWS, router::ROWS];
    node.into_iter().flatten().map(|d| (d, true)).chain(router::NO_NODE_ROW.iter().map(|d| (d, false)))
}

/// One row of the table as the tests and the SDK read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryRow {
    /// The struct (`typed_ops.json`'s key).
    pub name: &'static str,
    /// The contract function.
    pub entry: &'static str,
    /// The domain kinds it is signed in.
    pub kinds: &'static [&'static str],
    /// `type name` pairs, the envelope expanded, comma-joined.
    pub fields: String,
    /// The plan as written (empty = the default).
    pub plan: &'static str,
    /// A node row: a job may carry it (false: the release approvals, self-relay only, release management is no node job).
    pub node: bool,
}

/// Every row (the copy of the node's `TYPED`, then the rows the node does not take).
pub fn entry_rows() -> Vec<EntryRow> {
    defs().map(|((name, entry, kinds, f, plan), node)| EntryRow { name, entry, kinds, fields: expand(f), plan, node }).collect()
}

/// The structs a row nests, `(name, fields)` (the copy of the node's `NESTED`).
pub fn entry_structs() -> &'static [(&'static str, &'static str)] {
    NESTED
}

fn expand(f: &str) -> String {
    f.strip_suffix(",E").map_or_else(|| f.to_string(), |h| format!("{h},{E_FIELDS}"))
}

fn fields_of(f: &str) -> Result<Vec<(String, String)>> {
    expand(f).split(',').map(|x| x.split_once(' ').map(|(t, n)| (t.to_string(), n.to_string())).ok_or(Error::Argument)).collect()
}

fn nested(ty: &str) -> Option<&'static str> {
    NESTED.iter().find(|(n, _)| *n == ty).map(|(_, f)| *f)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sig {
    Bytes,
    Ua,
    Account,
}
impl Sig {
    fn ty(self) -> &'static str {
        match self {
            Sig::Bytes => "bytes",
            Sig::Ua => "UASig",
            Sig::Account => "AccountSig",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Env,
    Field(String),
    Extra(String, String),
    Group(Vec<String>),
    List(Box<Tok>),
    Whole,
    WrapAsTrade(String),
    Sign(Sig),
    Verdict,
    Init(String, String),
    InitCall,
}

fn tok(t: &str, sig: Sig) -> Tok {
    match t {
        "E" => return Tok::Env,
        "$" => return Tok::Whole,
        "verdict" => return Tok::Verdict,
        "initcall!" => return Tok::InitCall,
        "@" => return Tok::Sign(sig),
        "@bytes" => return Tok::Sign(Sig::Bytes),
        "@ua" => return Tok::Sign(Sig::Ua),
        _ => {}
    }
    if let Some(n) = t.strip_prefix("wrap!") {
        return Tok::WrapAsTrade(n.into());
    }
    if let Some((n, ty)) = t.strip_prefix("init!").and_then(|x| x.split_once(':')) {
        return Tok::Init(n.into(), ty.into());
    }
    if let Some(l) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
        return Tok::List(Box::new(tok(l, sig)));
    }
    if let Some(g) = t.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
        return Tok::Group(g.split(',').map(str::to_string).collect());
    }
    match t.split_once(':') {
        Some((n, ty)) => Tok::Extra(n.into(), ty.into()),
        None => Tok::Field(t.into()),
    }
}

struct Row {
    name: &'static str,
    entry: &'static str,
    node: bool,
    fields: Vec<(String, String)>,
    enveloped: bool,
    plan: Vec<Tok>,
    sig: Option<Sig>,
}

fn row(name: &str, kind: &str) -> Result<Row> {
    let (d, node) = defs().find(|((n, _, k, _, _), _)| *n == name && k.contains(&kind)).ok_or(Error::Argument)?;
    row_of(d, node)
}

fn row_of((name, entry, kinds, f, plan): &'static Def, node: bool) -> Result<Row> {
    let fields = fields_of(f)?;
    let enveloped = fields.len() > ENV.len()
        && fields.iter().rev().take(ENV.len()).map(|x| x.1.as_str()).eq(ENV.iter().rev().copied());
    let sig = if name.starts_with("UA") || name.starts_with("CancelUA") {
        Sig::Ua
    } else if *kinds == A {
        Sig::Account
    } else {
        Sig::Bytes
    };
    let plan: Vec<Tok> = if entry.is_empty() {
        vec![]
    } else if plan.is_empty() {
        let mid = fields.iter().skip(1).take(fields.len().saturating_sub(1 + ENV.len())).map(|x| Tok::Field(x.1.clone()));
        std::iter::once(Tok::Env).chain(mid).chain([Tok::Sign(sig)]).collect()
    } else {
        plan.split(' ').map(|t| tok(t, sig)).collect()
    };
    let sig = plan.iter().find_map(|t| match t {
        Tok::Sign(s) => Some(*s),
        Tok::List(x) => match **x {
            Tok::Sign(s) => Some(s),
            _ => None,
        },
        _ => None,
    });
    Ok(Row { name, entry, node, fields, enveloped, plan, sig })
}

// --- values ---

/// A parsed value: a head word, the raw bytes of a `bytes` / `string`, a tuple, a list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Val {
    Word([u8; 32]),
    Raw(Vec<u8>),
    Tuple(Vec<Val>),
    List(Vec<Val>),
}

/// The component types of a tuple type: a `(a,b,…)` list, a nested struct's fields, `PayMeta`'s five; `None` for an atom or a list.
fn components(ty: &str) -> Result<Option<Vec<String>>> {
    if ty.ends_with("[]") {
        return Ok(None);
    }
    if ty == "PayMeta" {
        return Ok(Some(["bytes32", "bytes32", "bool", "uint16", "bytes"].map(String::from).to_vec()));
    }
    if let Some(inner) = ty.strip_prefix('(').and_then(|x| x.strip_suffix(')')) {
        let (mut out, mut cur, mut depth) = (Vec::new(), String::new(), 0usize);
        for c in inner.chars() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.checked_sub(1).ok_or(Error::Argument)?,
                ',' if depth == 0 => {
                    out.push(std::mem::take(&mut cur));
                    continue;
                }
                _ => {}
            }
            cur.push(c);
        }
        out.push(cur);
        return Ok(Some(out));
    }
    match nested(ty) {
        Some(f) => Ok(Some(fields_of(f)?.into_iter().map(|x| x.0).collect())),
        None => Ok(None),
    }
}

/// The canonical ABI type (struct names as tuples), for a selector.
fn abi_type(ty: &str) -> Result<String> {
    if let Some(el) = ty.strip_suffix("[]") {
        return Ok(format!("{}[]", abi_type(el)?));
    }
    match components(ty)? {
        Some(c) => Ok(format!("({})", c.iter().map(|x| abi_type(x)).collect::<Result<Vec<_>>>()?.join(","))),
        None => Ok(ty.to_string()),
    }
}

fn dynamic(ty: &str) -> bool {
    if ty.ends_with("[]") || ty == "bytes" || ty == "string" {
        return true;
    }
    components(ty).ok().flatten().is_some_and(|c| c.iter().any(|x| dynamic(x)))
}

/// One JSON value as its type, strictly: present, every field of a struct and no other, lists bounded.
fn parse(ty: &str, j: &Value) -> Result<Val> {
    if j.is_null() {
        return Err(Error::Argument);
    }
    if let Some(el) = ty.strip_suffix("[]") {
        let a = j.as_array().ok_or(Error::Argument)?;
        let max = if matches!(el, "MemberSig" | "InnerSig") { MSIG_MAX_SLOTS } else { MAX_LIST };
        if a.len() > max {
            return Err(Error::Argument);
        }
        return Ok(Val::List(a.iter().map(|x| parse(el, x)).collect::<Result<_>>()?));
    }
    if ty == "PayMeta" {
        return pay_meta(j);
    }
    if let Some(f) = nested(ty) {
        let o = j.as_object().ok_or(Error::Argument)?;
        return Ok(Val::Tuple(take(&fields_of(f)?, o)?));
    }
    match abi_atom(ty, Some(j))? {
        Abi::Word(w) => Ok(Val::Word(w)),
        Abi::Raw(b) if b.len() <= MAX_BYTES => Ok(Val::Raw(b)),
        Abi::Raw(_) => Err(Error::Argument),
    }
}

fn take(fields: &[(String, String)], o: &Map<String, Value>) -> Result<Vec<Val>> {
    if o.keys().any(|k| !fields.iter().any(|f| f.1 == *k)) {
        return Err(Error::Argument);
    }
    fields.iter().map(|(t, n)| parse(t, o.get(n).ok_or(Error::Argument)?)).collect()
}

/// A pay entry's `meta` (pay-meta-tax spec §7.1): `{salt, payNo?, save?, schema?, body?}`, the body named per schema (0 none,
/// 1 `{note}`, 2 `{creditorRef, dueDate}`, 3 `{chainId, target, callHash}`, 4 `{ciphertext}`); the bytes built here, a hex body
/// refused (the node's `HEX_ARGS_REFUSED`).
fn pay_meta(j: &Value) -> Result<Val> {
    let o = j.as_object().ok_or(Error::Argument)?;
    if o.keys().any(|k| !matches!(k.as_str(), "salt" | "payNo" | "save" | "schema" | "body")) {
        return Err(Error::Argument);
    }
    let salt = parse("bytes32", o.get("salt").ok_or(Error::Argument)?)?;
    let pay_no = o.get("payNo").map_or(Ok(Val::Word([0; 32])), |v| parse("bytes32", v))?;
    let save = o.get("save").map_or(Ok(Val::Word([0; 32])), |v| parse("bool", v))?;
    let schema = o.get("schema").map_or(Ok(0), |v| v.as_u64().filter(|n| *n <= 4).ok_or(Error::Argument))?;
    let body = o.get("body").filter(|b| !b.is_null());
    let named = |keys: &[(&str, &str)]| -> Result<Vec<Val>> {
        let b = body.and_then(Value::as_object).ok_or(Error::Argument)?;
        let f: Vec<(String, String)> = keys.iter().map(|(t, n)| (t.to_string(), n.to_string())).collect();
        take(&f, b)
    };
    let bytes = match schema {
        0 if body.is_none() => Vec::new(),
        1 => match named(&[("string", "note")])?.pop() {
            Some(Val::Raw(b)) => b,
            _ => return Err(Error::Argument),
        },
        2 => seq(&["string".into(), "uint64".into()], &named(&[("string", "creditorRef"), ("uint64", "dueDate")])?)?,
        3 => seq(
            &["uint256".into(), "bytes32".into(), "bytes32".into()],
            &named(&[("uint256", "chainId"), ("bytes32", "target"), ("bytes32", "callHash")])?,
        )?,
        4 => match named(&[("bytes", "ciphertext")])?.pop() {
            Some(Val::Raw(b)) => b,
            _ => return Err(Error::Argument),
        },
        _ => return Err(Error::Argument),
    };
    if bytes.len() > MAX_BYTES {
        return Err(Error::Argument);
    }
    let mut s = [0u8; 32];
    if let Some(w) = s.last_mut() {
        *w = schema as u8;
    }
    Ok(Val::Tuple(vec![salt, pay_no, save, Val::Word(s), Val::Raw(bytes)]))
}

// --- ABI encoding (head / tail) ---

fn word(n: usize) -> [u8; 32] {
    let mut w = [0u8; 32];
    for (o, b) in w.iter_mut().rev().zip((n as u64).to_le_bytes()) {
        *o = b;
    }
    w
}

fn enc(ty: &str, v: &Val) -> Result<Vec<u8>> {
    match (v, ty.strip_suffix("[]")) {
        (Val::List(a), Some(el)) => {
            let mut out = word(a.len()).to_vec();
            out.extend(seq(&vec![el.to_string(); a.len()], a)?);
            Ok(out)
        }
        (Val::Word(w), None) => Ok(w.to_vec()),
        (Val::Raw(b), None) => {
            let mut out = word(b.len()).to_vec();
            out.extend_from_slice(b);
            out.resize(32 + b.len().div_ceil(32) * 32, 0);
            Ok(out)
        }
        (Val::Tuple(t), None) => seq(&components(ty)?.ok_or(Error::Argument)?, t),
        _ => Err(Error::Argument),
    }
}

/// `abi.encode` of a sequence: the heads (a static value in place, a dynamic one's offset), then the tails.
fn seq(tys: &[String], vals: &[Val]) -> Result<Vec<u8>> {
    if tys.len() != vals.len() {
        return Err(Error::Argument);
    }
    let parts: Vec<(bool, Vec<u8>)> = tys.iter().zip(vals).map(|(t, v)| Ok((dynamic(t), enc(t, v)?))).collect::<Result<_>>()?;
    let head_len: usize = parts.iter().map(|(d, b)| if *d { 32 } else { b.len() }).sum();
    let (mut head, mut tail) = (Vec::new(), Vec::new());
    for (d, b) in parts {
        if d {
            head.extend(word(head_len + tail.len()));
            tail.extend(b);
        } else {
            head.extend(b);
        }
    }
    head.extend(tail);
    Ok(head)
}

// --- canonical JSON (the node's `to_json`) ---

fn to_json(ty: &str, v: &Val) -> Result<Value> {
    if ty == "PayMeta" {
        return Err(Error::Argument); // kept as the canonical named form instead (`Built::meta`)
    }
    if let (Some(el), Val::List(a)) = (ty.strip_suffix("[]"), v) {
        return Ok(Value::Array(a.iter().map(|x| to_json(el, x)).collect::<Result<_>>()?));
    }
    if let (Some(f), Val::Tuple(t)) = (nested(ty), v) {
        let f = fields_of(f)?;
        return Ok(Value::Object(f.iter().zip(t).map(|((ty, n), x)| Ok((n.clone(), to_json(ty, x)?))).collect::<Result<_>>()?));
    }
    Ok(match (ty, v) {
        ("string", Val::Raw(b)) => json!(String::from_utf8(b.clone()).map_err(|_| Error::Argument)?),
        ("bytes", Val::Raw(b)) => json!(to_hex(b)),
        ("address", Val::Word(w)) => json!(to_hex(w.get(12..).ok_or(Error::Argument)?)),
        ("bool", Val::Word(w)) => json!(w.last() == Some(&1)),
        (t, Val::Word(w)) if t.starts_with("bytes") => {
            let n: usize = t.get(5..).and_then(|x| x.parse().ok()).ok_or(Error::Argument)?;
            json!(to_hex(w.get(..n).ok_or(Error::Argument)?))
        }
        (t, Val::Word(w)) if t.starts_with("uint") => {
            let bits: usize = t.get(4..).and_then(|x| x.parse().ok()).ok_or(Error::Argument)?;
            match bits {
                ..=32 => json!(u64::from_be_bytes(w.get(24..).and_then(|x| x.try_into().ok()).ok_or(Error::Argument)?)),
                _ => json!(u256_to_dec(w)),
            }
        }
        (t, Val::Word(w)) if t.starts_with("int") => {
            json!(i64::from_be_bytes(w.get(24..).and_then(|x| x.try_into().ok()).ok_or(Error::Argument)?))
        }
        _ => return Err(Error::Argument),
    })
}

// --- the build ---

/// One entry built from one parse: what goes to the chain and what goes to a node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The entry's calldata (a `UARelayFee`: the direct `mtxRelayFee`; the router's call is [`relay_fee_router_calldata`]).
    pub calldata: Vec<u8>,
    /// The job `op` object (`None`: no node row, a release approval).
    pub op: Option<Value>,
    /// The signed message in its canonical form (unbound `relayer` / `feeRecipient` 0; a creation's `initHash` filled).
    pub message: Value,
}

/// The named entry of struct `name` in domain kind `kind` on `contract` (the call's target; a wrap order's wrapper; a relay
/// fee's fee token). `message`: the signed struct, every field by name (a creation's `initHash` may be left out: it is the
/// keccak of `extra.config` / `extra.init_call`). `extra`: what the entry takes unsigned, by the plan's names (`meta`, `pqzAuth`,
/// `payerSig`, `ownerSig`, `underlying`, `config`, `init_call`), a PQZ debit's `pqzVerdict` (the `PqzSignedVerdict` it takes
/// last, the empty one of a `PRECOMPILE` token) and optional `pqz_fee`, and the job's optional `validUntil`; nothing else.
/// `sig`: the signature in the row's form, `0x`-hex `bytes`, a `UASig` `{keyData, signature, members}` or an `AccountSig`
/// `{keyIndex, proof, signature}`. `Argument`: no such row, a field missing or unknown, a value its type refuses.
pub fn entry(name: &str, kind: &str, contract: &[u8; 20], message: &Value, extra: &Value, sig: &Value) -> Result<Built> {
    build(row(name, kind)?, kind, contract, message, extra, sig)
}

/// The transfer on ids (owner 2026-11-18, ruling 6; ua-mtx-merge R44, Q7): a `UAMetaTransfer` on a token kind sent as
/// `mtxExecuteTransfer(UAMetaTransfer, UASig)`, not as a pay (`mtxPay` takes the `PayMeta` its `entryRef` commits to). Its node
/// form is the body of `POST /v1/ua-metatx` without `chain`: `{token, contract, struct: "transfer", m, auth}` (`scaas-node`
/// `gateway.rs`, the `ua_metatx` struct job), `m` the canonical message, `auth` the `UASig`. `Argument` as [`entry`].
pub fn transfer_on_ids(kind: &str, contract: &[u8; 20], message: &Value, sig: &Value) -> Result<Built> {
    if !token::IDS.2.contains(&kind) {
        return Err(Error::Argument);
    }
    let mut b = build(row_of(&token::IDS, false)?, kind, contract, message, &json!({}), sig)?;
    let auth = to_json("UASig", &parse("UASig", sig)?)?;
    b.op = Some(json!({"token": to_hex(contract), "contract": kind, "struct": "transfer", "m": b.message, "auth": auth}));
    Ok(b)
}

/// A pay entry's `meta` (its named form, as [`entry`]'s `extra.meta`) as the [`crate::pay::PayMeta`] whose `metaPayId` the
/// signed `entryRef` commits to: the body bytes built from the named body. `Argument` as the calldata refuses it.
pub fn pay_meta_of(meta: &Value) -> Result<crate::pay::PayMeta> {
    let Val::Tuple(t) = pay_meta(meta)? else { return Err(Error::Argument) };
    let word = |i: usize| match t.get(i) {
        Some(Val::Word(w)) => Ok(*w),
        _ => Err(Error::Argument),
    };
    let body = match t.get(4) {
        Some(Val::Raw(b)) => b.clone(),
        _ => return Err(Error::Argument),
    };
    let schema = word(3)?;
    Ok(crate::pay::PayMeta {
        salt: word(0)?,
        pay_no: word(1)?,
        save: word(2)?[31] != 0,
        schema: u16::from_be_bytes([schema[30], schema[31]]),
        body,
    })
}

fn build(r: Row, kind: &str, contract: &[u8; 20], message: &Value, extra: &Value, sig: &Value) -> Result<Built> {
    if r.entry.is_empty() {
        return Err(Error::Argument); // `PqzAuth`: attached by the PQZ facade, no entry of its own
    }
    let m = message.as_object().ok_or(Error::Argument)?;
    let x = extra.as_object().ok_or(Error::Argument)?;
    // what the extra may name: the plan's unsigned arguments, a creation's input, the verdict, the job's fields
    let named = |k: &str| {
        r.plan.iter().any(|t| match t {
            Tok::Extra(n, _) | Tok::Init(n, _) => n == k,
            Tok::InitCall => k == "init_call",
            Tok::Verdict => k == "pqzVerdict" || k == "pqz_fee",
            _ => false,
        }) || k == "validUntil"
    };
    if x.keys().any(|k| !named(k)) {
        return Err(Error::Argument);
    }
    // a creation's `initHash`: the keccak of the encoded config or of the initializer call
    let init = init_bytes(&r, x)?;
    let mut msg = m.clone();
    if let Some(b) = &init {
        let h = json!(to_hex(&keccak256(b)));
        if msg.get("initHash").is_some_and(|v| v.as_str().map(str::to_ascii_lowercase) != h.as_str().map(String::from)) {
            return Err(Error::Argument);
        }
        msg.insert("initHash".into(), h);
    }
    let mut vals = take(&r.fields, &msg)?;
    canon(&r.fields, &mut vals)?;
    let get = |n: &str| -> Result<Val> {
        if let Some(i) = r.fields.iter().position(|f| f.1 == n) {
            return vals.get(i).cloned().ok_or(Error::Argument);
        }
        let ty = r.plan.iter().find_map(|t| match t {
            Tok::Extra(k, ty) if k == n => Some(ty.as_str()),
            _ => None,
        });
        parse(ty.ok_or(Error::Argument)?, x.get(n).ok_or(Error::Argument)?)
    };
    let s = match r.sig {
        Some(k) => Some(parse(k.ty(), sig)?),
        None if sig.is_null() => None,
        None => return Err(Error::Argument),
    };
    let verdict = match x.get("pqzVerdict") {
        Some(v) => Some(parse("PqzSignedVerdict", v)?),
        None => None,
    };
    let ty_of = |n: &str| r.fields.iter().find(|f| f.1 == n).map(|f| f.0.clone()).ok_or(Error::Argument);
    let mut tys = Vec::new();
    let mut args = Vec::new();
    for t in &r.plan {
        let (ty, v) = match t {
            Tok::Env => {
                let mut e = vec![get("from")?];
                for n in ENV {
                    e.push(get(n)?);
                }
                let ft = r.fields.first().map(|f| f.0.as_str()).ok_or(Error::Argument)?;
                (format!("({ft},uint256,uint256,uint256,uint32,address,uint256,address)"), Val::Tuple(e))
            }
            Tok::Field(n) => (ty_of(n)?, get(n)?),
            Tok::Extra(n, ty) => (ty.clone(), get(n)?),
            Tok::Group(g) => {
                let t: Vec<String> = g.iter().map(|n| ty_of(n)).collect::<Result<_>>()?;
                (format!("({})", t.join(",")), Val::Tuple(g.iter().map(|n| get(n)).collect::<Result<_>>()?))
            }
            Tok::List(b) => match &**b {
                Tok::Field(n) => (format!("{}[]", ty_of(n)?), Val::List(vec![get(n)?])),
                Tok::Sign(k) => (format!("{}[]", k.ty()), Val::List(vec![s.clone().ok_or(Error::Argument)?])),
                _ => return Err(Error::Argument),
            },
            Tok::Whole => (
                format!("({})", r.fields.iter().map(|f| f.0.as_str()).collect::<Vec<_>>().join(",")),
                Val::Tuple(vals.clone()),
            ),
            Tok::WrapAsTrade(n) => {
                // a `UAWrapOrder` cancelled as the `UATradeOrder` it trades through: `dex` = the wrapper (the order's
                // `wrappedToken`), 13 words
                let Val::Tuple(mut w) = get(n)? else { return Err(Error::Argument) };
                let wrapper = w.get(1).cloned().ok_or(Error::Argument)?;
                if w.len() < 7 {
                    return Err(Error::Argument);
                }
                w.insert(7, wrapper);
                ("UATradeOrder".to_string(), Val::Tuple(w))
            }
            Tok::Sign(k) => (k.ty().to_string(), s.clone().ok_or(Error::Argument)?),
            Tok::Verdict => ("PqzSignedVerdict".to_string(), verdict.clone().ok_or(Error::Argument)?),
            Tok::Init(..) | Tok::InitCall => ("bytes".into(), Val::Raw(init.clone().ok_or(Error::Argument)?)),
        };
        tys.push(ty);
        args.push(v);
    }
    let abi: Vec<String> = tys.iter().map(|t| abi_type(t)).collect::<Result<_>>()?;
    let sel = keccak256(format!("{}({})", r.entry, abi.join(",")).as_bytes());
    let mut calldata = sel.get(..4).ok_or(Error::Argument)?.to_vec();
    calldata.extend(seq(&tys, &args)?);
    let message =
        Value::Object(r.fields.iter().zip(&vals).map(|((ty, n), v)| Ok((n.clone(), to_json(ty, v)?))).collect::<Result<_>>()?);
    let op = if r.node { Some(op_json(&r, kind, contract, &message, x, s.as_ref(), verdict.as_ref())?) } else { None };
    Ok(Built { calldata, op, message })
}

/// `MetaTxLib.canon`, on the struct and on each nested struct: an unbound `relayer` / `feeRecipient` is 0.
fn canon(fields: &[(String, String)], vals: &mut [Val]) -> Result<()> {
    let at = |n: &str| fields.iter().position(|f| f.1 == n);
    if let (Some(m), Some(r), Some(f)) = (at("mode"), at("relayer"), at("feeRecipient")) {
        let mode = match vals.get(m) {
            Some(Val::Word(w)) => w.last().copied().unwrap_or(0),
            _ => return Err(Error::Argument),
        };
        if mode & 1 == 0 {
            *vals.get_mut(r).ok_or(Error::Argument)? = Val::Word([0; 32]);
        }
        if mode & 2 == 0 {
            *vals.get_mut(f).ok_or(Error::Argument)? = Val::Word([0; 32]);
        }
    }
    for ((ty, _), v) in fields.iter().zip(vals.iter_mut()) {
        if let (Some(nf), Val::Tuple(t)) = (nested(ty), v) {
            canon(&fields_of(nf)?, t)?;
        }
    }
    Ok(())
}

fn init_bytes(r: &Row, x: &Map<String, Value>) -> Result<Option<Vec<u8>>> {
    for t in &r.plan {
        match t {
            Tok::Init(n, ty) => return Ok(Some(seq(std::slice::from_ref(ty), &[parse(ty, x.get(n).ok_or(Error::Argument)?)?])?)), // `abi.encode(config)`
            Tok::InitCall => {
                return match parse("bytes", x.get("init_call").ok_or(Error::Argument)?)? {
                    Val::Raw(b) if b.len() <= 4096 => Ok(Some(b)),
                    _ => Err(Error::Argument),
                };
            }
            _ => {}
        }
    }
    Ok(None)
}

/// The creation's `initHash` (`UACreateToken`, `UACreateDex`: the keccak of `abi.encode(config)`; `UACreateInstance`: of
/// `init_call`), what the signed message carries; `None` for any other row.
pub fn init_hash(name: &str, kind: &str, extra: &Value) -> Result<Option<[u8; 32]>> {
    let r = row(name, kind)?;
    Ok(init_bytes(&r, extra.as_object().ok_or(Error::Argument)?)?.map(|b| keccak256(&b)))
}

fn op_json(
    r: &Row, kind: &str, contract: &[u8; 20], message: &Value, x: &Map<String, Value>, s: Option<&Val>, verdict: Option<&Val>,
) -> Result<Value> {
    let m = message.as_object().ok_or(Error::Argument)?;
    let in_env = |n: &str| r.enveloped && (n == "from" || ENV.contains(&n));
    let init = r.plan.iter().any(|t| matches!(t, Tok::Init(..) | Tok::InitCall));
    let mut args: Map<String, Value> =
        m.iter().filter(|(k, _)| !in_env(k) && !(init && *k == "initHash")).map(|(k, v)| (k.clone(), v.clone())).collect();
    for t in &r.plan {
        match t {
            Tok::Extra(n, ty) if ty == "PayMeta" => {
                let v = x.get(n).ok_or(Error::Argument)?;
                args.insert(n.clone(), pay_meta_json(v)?);
            }
            Tok::Extra(n, ty) => {
                args.insert(n.clone(), to_json(ty, &parse(ty, x.get(n).ok_or(Error::Argument)?)?)?);
            }
            Tok::Init(n, ty) => {
                args.insert(n.clone(), to_json(ty, &parse(ty, x.get(n).ok_or(Error::Argument)?)?)?);
            }
            Tok::InitCall => {
                args.insert("init_call".into(), to_json("bytes", &parse("bytes", x.get("init_call").ok_or(Error::Argument)?)?)?);
            }
            _ => {}
        }
    }
    // group 3f: the node rebuilds the `PqzVerdict` itself and takes the verifier's part by name; none for an empty verdict
    if let Some(Val::Tuple(v)) = verdict {
        if let (Some(Val::Tuple(pv)), Some(auth @ Val::Tuple(a))) = (v.first(), v.get(1)) {
            if a.iter().any(|f| f != &Val::Raw(vec![]) && f != &Val::List(vec![])) {
                let epoch = to_json("uint32", pv.get(5).ok_or(Error::Argument)?)?;
                let until = to_json("uint256", pv.get(6).ok_or(Error::Argument)?)?;
                args.insert("pqz_verdict".into(), json!({"pqzVerifierEpoch": epoch, "validUntil": until, "auth": to_json("UASig", auth)?}));
            }
        }
    }
    if let Some(f) = x.get("pqz_fee") {
        args.insert("pqz_fee".into(), to_json("uint256", &parse("uint64", f)?)?);
    }
    let mut op = json!({"entry": r.entry, "contract": kind, "struct": r.name, "token": to_hex(contract), "args": args});
    if r.enveloped {
        let e: Map<String, Value> =
            ["from"].iter().chain(ENV.iter()).map(|k| Ok((k.to_string(), m.get(*k).cloned().ok_or(Error::Argument)?))).collect::<Result<_>>()?;
        set(&mut op, "envelope", Value::Object(e))?;
    }
    if let (Some(k), Some(v)) = (r.sig, s) {
        set(&mut op, if k == Sig::Bytes { "signature" } else { "auth" }, to_json(k.ty(), v)?)?;
    }
    if let Some(v) = x.get("validUntil") {
        set(&mut op, "validUntil", to_json("uint256", &parse("uint256", v)?)?)?;
    }
    Ok(op)
}

/// A `meta` in its canonical named form (the node's `pay_meta_json`): `payNo` and `save` always, `body` when the schema has one.
fn pay_meta_json(v: &Value) -> Result<Value> {
    pay_meta(v)?; // refused as the calldata refuses it
    let o = v.as_object().ok_or(Error::Argument)?;
    let w = |k: &str, ty: &str, d: Val| -> Result<Value> { to_json(ty, &o.get(k).map_or(Ok(d), |x| parse(ty, x))?) };
    let schema = o.get("schema").and_then(Value::as_u64).unwrap_or(0);
    let mut out = json!({"salt": w("salt", "bytes32", Val::Word([0; 32]))?, "payNo": w("payNo", "bytes32", Val::Word([0; 32]))?,
        "save": w("save", "bool", Val::Word([0; 32]))?, "schema": schema});
    let body = o.get("body").and_then(Value::as_object);
    let keys: &[(&str, &str)] = match schema {
        1 => &[("string", "note")],
        2 => &[("string", "creditorRef"), ("uint64", "dueDate")],
        3 => &[("uint256", "chainId"), ("bytes32", "target"), ("bytes32", "callHash")],
        4 => &[("bytes", "ciphertext")],
        _ => &[],
    };
    if let Some(b) = body.filter(|_| !keys.is_empty()) {
        let nb: Map<String, Value> =
            keys.iter().map(|(t, n)| Ok((n.to_string(), to_json(t, &parse(t, b.get(*n).ok_or(Error::Argument)?)?)?))).collect::<Result<_>>()?;
        set(&mut out, "body", Value::Object(nb))?;
    }
    Ok(out)
}

// --- the relay fee (CTR-MTX-27; pay-meta-tax spec §4) ---

/// `RelayFeeRouter.relayRef(target, callData) = keccak256("scaas.relayfee" ‖ uint256 chainId ‖ target ‖ keccak256(callData))`.
pub fn relay_ref(chain_id: u64, target: &[u8; 20], call_data: &[u8]) -> [u8; 32] {
    let mut b = b"scaas.relayfee".to_vec();
    b.extend(word(chain_id as usize));
    b.extend_from_slice(target);
    b.extend(keccak256(call_data));
    keccak256(&b)
}

/// The router's `relay(target, callData, token, from, payee, value, batch, nonce, validUntil, UASig auth)` of a signed
/// `UARelayFee` `message` on fee token `token` (`callData` the call it pays for: its keccak must be the signed
/// `callDataHash`). The node sends this to the message's `relayer` (the router); the payer's lane is `batch`.
pub fn relay_fee_router_calldata(message: &Value, token: &[u8; 20], call_data: &[u8], auth: &Value) -> Result<Vec<u8>> {
    let r = row("UARelayFee", "token")?;
    let vals = take(&r.fields, message.as_object().ok_or(Error::Argument)?)?;
    let get = |n: &str| r.fields.iter().position(|f| f.1 == n).and_then(|i| vals.get(i).cloned()).ok_or(Error::Argument);
    if get("callDataHash")? != Val::Word(keccak256(call_data)) {
        return Err(Error::Argument);
    }
    let mut tok = [0u8; 32];
    tok.get_mut(12..).ok_or(Error::Argument)?.copy_from_slice(token);
    let tys: Vec<String> = ["address", "bytes", "address", "bytes32", "bytes32", "uint256", "uint256", "uint256", "uint256"]
        .iter()
        .map(|s| s.to_string())
        .chain(["UASig".to_string()])
        .collect();
    let vals = vec![get("target")?, Val::Raw(call_data.to_vec()), Val::Word(tok), get("from")?, get("payee")?, get("value")?,
        get("batch")?, get("nonce")?, get("validUntil")?, parse("UASig", auth)?];
    let abi: Vec<String> = tys.iter().map(|t| abi_type(t)).collect::<Result<_>>()?;
    let sel = keccak256(format!("relay({})", abi.join(",")).as_bytes());
    let mut out = sel.get(..4).ok_or(Error::Argument)?.to_vec();
    out.extend(seq(&tys, &vals)?);
    Ok(out)
}

/// A relay-fee job (job-api §5.3, "Pay-meta and relay-fee jobs"): the `UARelayFee` op `fee` with the paid call `call` (its op
/// and calldata, [`entry`]): `target` and `callDataHash` leave `args` (the node takes them from `call`), `call` joins. `Argument`:
/// a `call` not on the signed target, its calldata not the signed hash, a relay fee or a PQZ debit (whose verdict the node
/// rebuilds after the payer hashed the call) as the call.
pub fn relay_fee_op(fee: &Built, call: &Built) -> Result<Value> {
    let mut op = fee.op.clone().ok_or(Error::Argument)?;
    let inner = call.op.clone().ok_or(Error::Argument)?;
    let field = |v: &Value, k: &str| v.get(k).and_then(Value::as_str).map(str::to_string).unwrap_or_default();
    if field(&op, "struct") != "UARelayFee" || field(&inner, "struct") == "UARelayFee" || call.calldata.is_empty() {
        return Err(Error::Argument);
    }
    let debit = row(&field(&inner, "struct"), &field(&inner, "contract"))?;
    if debit.plan.contains(&Tok::Verdict) {
        return Err(Error::Argument);
    }
    let args = op.get_mut("args").and_then(Value::as_object_mut).ok_or(Error::Argument)?;
    let target = args.remove("target").ok_or(Error::Argument)?;
    let hash = args.remove("callDataHash").ok_or(Error::Argument)?;
    if target.as_str() != Some(field(&inner, "token").as_str()) || hash != json!(to_hex(&keccak256(&call.calldata))) {
        return Err(Error::Argument);
    }
    set(&mut op, "call", inner)?;
    Ok(op)
}

fn set(v: &mut Value, k: &str, x: Value) -> Result<()> {
    v.as_object_mut().ok_or(Error::Argument)?.insert(k.to_string(), x);
    Ok(())
}
