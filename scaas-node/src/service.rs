// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The contract kind `service` (proposed NODE-JOB-25; spec docs/superpowers/specs/2026-11-09-service-pull.md §3, §8, owner
//! Q1 B): a third-party contract whose entries take a payer's signed pull (`UAMetaTransfer`, `to` = `relayer` = the service,
//! `MODE_RESTRICT_RELAYER`, fee `NONE`, `entryRef` = the EIP-712 digest of the operation in the service's domain). Its entries
//! come from config (`[[chains.services]]`) and must equal the contract's `servicePullEntries()`, both directions, at
//! startup; the node builds the calldata from named fields by the declared `encodeType` under the bounds of C3 (atomic
//! fields, `bytes`, `string`, at most 16, no array, no nested struct) and `max_service_op_bytes`; it reads the pulled token
//! from the contract; it checks §3.3 steps 1-4 before any simulation. No service is named in code. UNAUDITED.
use std::collections::{HashMap, HashSet};

use alloy::dyn_abi::{DynSolType, DynSolValue as Val};
use alloy::primitives::{keccak256, Address, Bytes, B256, U256};
use alloy::sol_types::{Eip712Domain, SolValue};
use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::abi::{UAMetaTransfer, UASig};
use crate::metatx::{native, UaMtx};
use crate::typed::{self, Op, Typed};

/// At most 32 entries per service and 1,024 bytes per `op_type` (spec §8): more is a startup error.
pub const MAX_ENTRIES: usize = 32;
pub const MAX_OP_TYPE_BYTES: usize = 1024;
/// C3: at most 16 fields per `<Op>`.
pub const MAX_FIELDS: usize = 16;
/// `params.max_service_op_bytes` (default 2,048): the cap on one `bytes` / `string` field of an `<Op>`.
pub const DEFAULT_MAX_OP_BYTES: usize = 2048;
const T_TUPLE: &str = "(bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
const UASIG_TUPLE: &str = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
const MODE_RESTRICT_RELAYER: u32 = 1;

/// `[[chains.services]]`: a service's address and its entries.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServiceCfg {
    pub address: Address,
    pub entries: Vec<EntryCfg>,
}

/// One entry: the function's name and its `<Op>`'s EIP-712 `encodeType`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EntryCfg {
    pub entry: String,
    pub op_type: String,
}

/// One entry as the node builds it: `<Op>`'s fields (C3), the selector of `entry(<Op>, UAMetaTransfer, UASig)`, and the
/// token it pulls as the contract says (`None` before the startup read; `Some(0)`: `<Op>`'s `address token`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub entry: String,
    pub op_type: String,
    pub fields: Vec<(String, String)>,
    pub selector: [u8; 4],
    pub token: Option<Address>,
}

/// What a lane builds a service job from: the configured services' entries and the `bytes` / `string` cap.
#[derive(Debug, Clone, Default)]
pub struct Types {
    pub max_op_bytes: usize,
    pub entries: HashMap<Address, Vec<Entry>>,
}

/// A service as read from the chain at startup: its entries (the config's, with the contract's tokens), its domain separator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Service {
    pub address: Address,
    pub domain: B256,
    pub entries: Vec<Entry>,
}

/// An entry's calldata read back: the entry, `<Op>`'s values, the pull and its signature.
pub struct Decoded<'a> {
    pub entry: &'a Entry,
    pub op: Vec<Val>,
    pub t: UAMetaTransfer,
    pub auth: UASig,
}

fn ident(s: &str) -> bool {
    let mut c = s.chars();
    c.next().is_some_and(|f| f.is_ascii_alphabetic() || f == '_') && c.all(|x| x.is_ascii_alphanumeric() || x == '_')
}

/// C3's field types: `address`, `bool`, `bytesN`, `uintN`, `bytes`, `string`. `intN` is C3's too but not built here (no
/// client builder and no vector row has it): refused at startup, never mis-encoded.
fn field_type(ty: &str) -> bool {
    matches!(ty, "address" | "bool" | "bytes" | "string")
        || (1..=32).any(|n| ty == format!("bytes{n}"))
        || (1..=32).any(|n| ty == format!("uint{}", 8 * n))
}

/// `Name(type a,type b,…)` under C3: an identifier, 1 to 16 fields of [`field_type`]s with distinct names, the first
/// `bytes32 payer`. Anything else (an array, a nested struct, `intN`, a space too many) is refused.
pub fn parse_op_type(s: &str) -> Result<(String, Vec<(String, String)>)> {
    if s.len() > MAX_OP_TYPE_BYTES {
        bail!("op_type is {} B, above {MAX_OP_TYPE_BYTES}", s.len());
    }
    let (name, rest) = s.split_once('(').ok_or_else(|| anyhow!("op_type {s:?} is not Name(type field,…)"))?;
    let body = rest.strip_suffix(')').ok_or_else(|| anyhow!("op_type {s:?} is not Name(type field,…)"))?;
    if !ident(name) {
        bail!("op_type {s:?}: the struct name is not an identifier");
    }
    let fields: Vec<(String, String)> = body.split(',').map(|f| match f.split(' ').collect::<Vec<_>>()[..] {
        [t, n] if field_type(t) && ident(n) => Ok((t.to_string(), n.to_string())),
        [t, _] if t.ends_with(']') => Err(anyhow!("op_type {s:?}: {f:?} is an array (C3: atomic, bytes and string only)")),
        [t, n] if ident(n) => Err(anyhow!("op_type {s:?}: {t} is no C3 field type (atomic, bytes, string; no nested struct, no intN here)")),
        _ => Err(anyhow!("op_type {s:?}: {f:?} is not `type name`")),
    }).collect::<Result<_>>()?;
    if fields.len() > MAX_FIELDS {
        bail!("op_type {s:?} has {} fields, above {MAX_FIELDS} (C3)", fields.len());
    }
    if fields.first() != Some(&("bytes32".to_string(), "payer".to_string())) {
        bail!("op_type {s:?}: the first field is not bytes32 payer (spec §3.1)");
    }
    if fields.iter().map(|f| &f.1).collect::<HashSet<_>>().len() != fields.len() {
        bail!("op_type {s:?}: a field name twice");
    }
    Ok((name.to_string(), fields))
}

fn op_tuple(fields: &[(String, String)]) -> String {
    format!("({})", fields.iter().map(|f| f.0.as_str()).collect::<Vec<_>>().join(","))
}

/// The selector of `entry(<Op>, UAMetaTransfer, UASig)`.
pub fn selector(entry: &str, fields: &[(String, String)]) -> [u8; 4] {
    let sig = format!("{entry}({},{T_TUPLE},{UASIG_TUPLE})", op_tuple(fields));
    keccak256(sig.as_bytes())[..4].try_into().expect("4 bytes")
}

/// One configured service under the startup bounds: 1 to 32 entries, each an identifier and a C3 `op_type` of at most
/// 1,024 bytes, no selector twice.
pub fn entries_of(s: &ServiceCfg) -> Result<Vec<Entry>> {
    if s.entries.is_empty() || s.entries.len() > MAX_ENTRIES {
        bail!("service {:#x}: {} entries (1 to {MAX_ENTRIES})", s.address, s.entries.len());
    }
    let mut out: Vec<Entry> = vec![];
    for e in &s.entries {
        if !ident(&e.entry) {
            bail!("service {:#x}: entry {:?} is not a function name", s.address, e.entry);
        }
        let (_, fields) = parse_op_type(&e.op_type).with_context(|| format!("service {:#x}, entry {}", s.address, e.entry))?;
        let sel = selector(&e.entry, &fields);
        if out.iter().any(|o| o.selector == sel) {
            bail!("service {:#x}: entry {} ({}) twice", s.address, e.entry, e.op_type);
        }
        out.push(Entry { entry: e.entry.clone(), op_type: e.op_type.clone(), fields, selector: sel, token: None });
    }
    Ok(out)
}

impl Types {
    pub fn from_cfg(services: &[ServiceCfg], max_op_bytes: usize) -> Result<Self> {
        let mut entries = HashMap::new();
        for s in services {
            if entries.insert(s.address, entries_of(s)?).is_some() {
                bail!("service {:#x} configured twice", s.address);
            }
        }
        Ok(Self { max_op_bytes, entries })
    }
}

/// `SERVICE_ENTRIES_MISMATCH` unless the configured `(selector, op_type)` set equals the contract's, both directions; the
/// entries with the contract's tokens.
pub fn check_entries(s: Address, cfg: &[Entry], sels: &[[u8; 4]], types: &[String], tokens: &[Address]) -> Result<Vec<Entry>> {
    if sels.len() != types.len() || sels.len() != tokens.len() {
        bail!("SERVICE_ENTRIES_MISMATCH: {s:#x}: servicePullEntries() returns lists of unequal lengths");
    }
    let mut out = vec![];
    for (i, (sel, ty)) in sels.iter().zip(types).enumerate() {
        let Some(e) = cfg.iter().find(|e| e.selector == *sel && e.op_type == *ty) else {
            bail!("SERVICE_ENTRIES_MISMATCH: {s:#x}: the contract's entry 0x{} ({ty}) is not in [[chains.services]]", alloy::hex::encode(sel));
        };
        if sels[..i].contains(sel) {
            bail!("SERVICE_ENTRIES_MISMATCH: {s:#x}: the contract lists 0x{} twice", alloy::hex::encode(sel));
        }
        out.push(Entry { token: Some(tokens[i]), ..e.clone() });
    }
    if let Some(e) = cfg.iter().find(|e| !out.iter().any(|o| o.selector == e.selector)) {
        bail!("SERVICE_ENTRIES_MISMATCH: {s:#x}: [[chains.services]] entry {} ({}) is not the contract's", e.entry, e.op_type);
    }
    Ok(out)
}

/// The service's domain separator from its ERC-5267 `eip712Domain()`: `verifyingContract` the service, `chainId` the
/// chain's, no extensions, fields `0x0f` (name, version, chainId, verifyingContract) or `0x1f` (and a salt: a SCaaS-built
/// service, CTR-GEN-05); anything else is `SERVICE_ENTRIES_MISMATCH`.
#[allow(clippy::too_many_arguments)]
pub fn domain_of(s: Address, chain_number: u64, fields: [u8; 1], name: String, version: String, chain_id: U256,
    vc: Address, salt: B256, extensions: &[U256]) -> Result<B256>
{
    let bad = |why: String| anyhow!("SERVICE_ENTRIES_MISMATCH: {s:#x}: eip712Domain() {why}");
    if vc != s {
        return Err(bad(format!("verifyingContract {vc:#x} is not the service")));
    }
    if chain_id != U256::from(chain_number) {
        return Err(bad(format!("chainId {chain_id} is not the chain's {chain_number}")));
    }
    if !extensions.is_empty() {
        return Err(bad("has extensions".into()));
    }
    let salt = match fields[0] {
        0x0f => None,
        0x1f => Some(salt),
        f => return Err(bad(format!("fields 0x{f:02x} (0x0f or 0x1f)"))),
    };
    Ok(Eip712Domain::new(Some(name.into()), Some(version.into()), Some(chain_id), Some(vc), salt).separator())
}

/// A configured service read from the chain (startup): `servicePullEntries()` equal to the config both directions, and its
/// domain on this chain.
pub async fn load(chain: &crate::chain::Chain, s: Address, cfg: &[Entry]) -> Result<Service> {
    let read = |what: &str, e: crate::chain::SimError| anyhow!("SERVICE_ENTRIES_MISMATCH: {s:#x}: {what}: {e:?}");
    let r = chain.call_view(s, crate::abi::IServicePull::servicePullEntriesCall {}).await.map_err(|e| read("servicePullEntries()", e))?;
    let sels: Vec<[u8; 4]> = r.selectors.iter().map(|x| x.0).collect();
    let entries = check_entries(s, cfg, &sels, &r.opTypes, &r.tokens)?;
    let d = chain.call_view(s, crate::abi::IToken::eip712DomainCall {}).await.map_err(|e| read("eip712Domain()", e))?;
    let domain = domain_of(s, chain.number, d.fields.0, d.name, d.version, d.chainId, d.verifyingContract, d.salt, &d.extensions)?;
    Ok(Service { address: s, domain, entries })
}

/// EIP-712 `hashStruct(<Op>)`: an atomic field as its word, `bytes` and `string` as `keccak256(value)`.
pub fn op_hash(e: &Entry, op: &[Val]) -> B256 {
    let mut b = keccak256(e.op_type.as_bytes()).to_vec();
    for v in op {
        match v {
            Val::String(s) => b.extend_from_slice(keccak256(s.as_bytes()).as_slice()),
            Val::Bytes(x) => b.extend_from_slice(keccak256(x).as_slice()),
            v => b.extend_from_slice(&v.abi_encode()),
        }
    }
    keccak256(b)
}

/// The calldata of one entry read back (the node built it; a relay fee's inner call too): `None` unless it is one of
/// `entries`, in canonical encoding.
pub fn decode<'a>(entries: &'a [Entry], data: &[u8]) -> Option<Decoded<'a>> {
    let sel: [u8; 4] = data.get(..4)?.try_into().ok()?;
    let entry = entries.iter().find(|e| e.selector == sel)?;
    let ty = DynSolType::parse(&format!("({},{T_TUPLE},{UASIG_TUPLE})", op_tuple(&entry.fields))).ok()?;
    let v = ty.abi_decode_sequence(&data[4..]).ok()?;
    if v.abi_encode_sequence()?.as_slice() != &data[4..] {
        return None;
    }
    let Val::Tuple(mut p) = v else { return None };
    let auth = UASig::abi_decode(&p.pop()?.abi_encode()).ok()?;
    let t = UAMetaTransfer::abi_decode(&p.pop()?.abi_encode()).ok()?;
    let Val::Tuple(op) = p.pop()? else { return None };
    Some(Decoded { entry, op, t, auth })
}

/// §3.3 steps 1-4 on the decoded call (`SERVICE_PULL_SHAPE: <code>`), and the token it pulls as the contract says:
/// `tokens[i]`, or `<Op>`'s `address token` when that is 0.
pub fn shape(svc: &Service, d: &Decoded) -> Result<Address, String> {
    let s = svc.address;
    let refuse = |code: u8, why: &str| Err(format!("SERVICE_PULL_SHAPE: {code}: {why}"));
    if d.t.to != s.into_word() {
        return refuse(1, "t.to is not the service");
    }
    if d.t.mode != MODE_RESTRICT_RELAYER || d.t.relayer != s {
        return refuse(2, "t.mode is not MODE_RESTRICT_RELAYER at fee NONE, or t.relayer is not the service");
    }
    if d.t.fee != U256::ZERO || d.t.feeRecipient != Address::ZERO {
        return refuse(2, "t.fee or t.feeRecipient is not 0 (fee NONE)");
    }
    let r = keccak256([&[0x19, 0x01][..], svc.domain.as_slice(), op_hash(d.entry, &d.op).as_slice()].concat());
    if d.t.entryRef != r {
        return refuse(3, "t.entryRef is not the operation's digest in the service's domain");
    }
    if Some(&Val::FixedBytes(d.t.from, 32)) != d.op.first() {
        return refuse(4, "t.from is not op.payer");
    }
    match d.entry.token {
        Some(a) if a != Address::ZERO => Ok(a),
        Some(_) => d.entry.fields.iter().position(|f| f.0 == "address" && f.1 == "token").and_then(|i| d.op[i].as_address())
            .ok_or_else(|| format!("SERVICE_TOKEN_MISMATCH: {} names no fixed token and its <Op> no address token", d.entry.entry)),
        None => Err(format!("SERVICE_ENTRIES_MISMATCH: {s:#x} was not read at startup")),
    }
}

/// A job `{entry, contract: "service", token: <S>, args: {op, pullToken, t, auth}}` (spec §8): every value a named field,
/// built by the declared `op_type` under C3 and `max_op_bytes`; the in-flight key is the pull's digest in the pull token's
/// domain (`Typed.domain_of`), its lane the pull's.
pub fn op(o: &Map<String, Value>, entry: &str, types: &Types) -> Result<Op> {
    if let Some(k) = o.keys().find(|k| !matches!(k.as_str(), "entry" | "contract" | "token" | "args")) {
        bail!("BAD_PAYLOAD: op.{k}: a service job is {{entry, contract, token, args: {{op, pullToken, t, auth}}}}");
    }
    let s = o.get("token").and_then(Value::as_str).ok_or_else(|| anyhow!("BAD_PAYLOAD: op.token missing"))?;
    let s = crate::metatx::addr(s).map_err(|e| anyhow!("BAD_PAYLOAD: op.token: {e}"))?;
    let entries = types.entries.get(&s)
        .ok_or_else(|| anyhow!("CALL_TARGET_REFUSED: {s:#x} is no [[chains.services]] service of this chain"))?;
    let e = entries.iter().find(|x| x.entry == entry)
        .ok_or_else(|| anyhow!("UNKNOWN_ENTRY: {entry:?} is no entry of service {s:#x}"))?;
    let args = o.get("args").and_then(Value::as_object).ok_or_else(|| anyhow!("BAD_PAYLOAD: args is not an object"))?;
    if let Some(k) = args.keys().find(|k| !matches!(k.as_str(), "op" | "pullToken" | "t" | "auth")) {
        bail!("BAD_PAYLOAD: args.{k}: unknown field (op, pullToken, t, auth)");
    }
    let get = |k: &str| args.get(k).ok_or_else(|| anyhow!("BAD_PAYLOAD: args.{k}: missing"));
    let op_obj = get("op")?.as_object().ok_or_else(|| anyhow!("BAD_PAYLOAD: args.op is not an object"))?;
    let vals = typed::take(&e.fields, op_obj, "args.op")?;
    for ((_, n), v) in e.fields.iter().zip(&vals) {
        let len = match v { Val::Bytes(b) => b.len(), Val::String(x) => x.len(), _ => 0 };
        if len > types.max_op_bytes {
            bail!("BAD_PAYLOAD: args.op.{n}: {len} B, above max_service_op_bytes {}", types.max_op_bytes);
        }
    }
    let t_val = typed::parse("UAMetaTransfer", get("t")?, "args.t")?;
    let auth_val = typed::parse("UASig", get("auth")?, "args.auth")?;
    let t = UAMetaTransfer::abi_decode(&t_val.abi_encode())?;
    let auth = UASig::abi_decode(&auth_val.abi_encode())?;
    let pull = get("pullToken")?.as_str().ok_or_else(|| anyhow!("BAD_PAYLOAD: args.pullToken is not a string"))?;
    let pull = crate::metatx::addr(pull).map_err(|e| anyhow!("BAD_PAYLOAD: args.pullToken: {e}"))?;
    let data: Bytes = [&e.selector[..], &Val::Tuple(vec![Val::Tuple(vals), t_val, auth_val]).abi_encode_sequence().unwrap_or_default()]
        .concat().into();
    let native_sig = (auth.keyData.is_empty() && auth.members.is_empty()).then(|| auth.signature.clone());
    let derived_signer = native(&t.from).is_none();
    let typed = Typed { contract: "service", domain_of: pull, struct_hash: Some(UaMtx::Transfer(t.clone()).struct_hash()),
        lane_hash: None, signer: native(&t.from).zip(native_sig), payee: Some(t.to), digest: None, derived_signer,
        derived_side: derived_signer || native(&t.to).is_none(), pay_meta_len: 0, pqz_parties: vec![], pqz_auditor: false,
        pqz_verdict: None };
    Ok(Op { row: &typed::SERVICE_ROW, to: s, data, typed, lane: Some((t.from, t.batch, t.nonce)), valid_until: t.validUntil.saturating_to() })
}

/// A relay fee whose inner call is a service pull, the fee in the pulled token on the pull's lane: the pull runs first
/// (the router calls the target before the fee), so the fee is the pull's nonce + 1 (spec §2.4 (b)); another nonce would
/// fail `MetaTxBadNonce` after the pull. Another lane or token: nothing to check.
pub fn fee_nonce(inner: &Op, fee_token: Address, from: &Val, batch: &Val, nonce: &Val) -> Result<()> {
    let Some((pf, pb, pn)) = inner.lane.filter(|_| inner.typed.contract == "service") else { return Ok(()) };
    let word = |v: &Val| v.as_uint().map(|u| u.0);
    if fee_token == inner.typed.domain_of && from.as_fixed_bytes().map(|x| B256::from_slice(x.0)) == Some(pf) && word(batch) == Some(pb)
        && word(nonce) != pn.checked_add(U256::from(1))
    {
        bail!("SERVICE_PULL_SHAPE: fee nonce: the fee in the pulled token on the pull's lane is the pull's nonce + 1 ({pn} + 1), \
            not {:?}", word(nonce));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const VECTORS: &str = include_str!("../../smartcontracts/vectors/metatx/servicepull.json");

    fn rows() -> Vec<Value> {
        serde_json::from_str::<Value>(VECTORS).unwrap()["rows"].as_array().unwrap().clone()
    }

    fn a(v: &Value) -> Address {
        v.as_str().unwrap().parse().unwrap()
    }

    fn b32(v: &Value) -> B256 {
        v.as_str().unwrap().parse().unwrap()
    }

    fn hexb(v: &Value) -> Vec<u8> {
        alloy::hex::decode(v.as_str().unwrap()).unwrap()
    }

    /// The vectors' service as configured (both entries) and as read at startup (the row's `servicePullEntries()`).
    fn cfg_of(r: &Value) -> ServiceCfg {
        let e = &r["service"]["entries"];
        ServiceCfg { address: a(&r["service"]["address"]), entries: e["opTypes"].as_array().unwrap().iter().zip(["deposit", "note"])
            .map(|(t, n)| EntryCfg { entry: n.into(), op_type: t.as_str().unwrap().into() }).collect() }
    }

    fn types_of(r: &Value) -> Types {
        Types::from_cfg(&[cfg_of(r)], DEFAULT_MAX_OP_BYTES).unwrap()
    }

    fn service_of(r: &Value) -> Service {
        let cfg = cfg_of(r);
        let e = &r["service"]["entries"];
        let sels: Vec<[u8; 4]> = e["selectors"].as_array().unwrap().iter().map(|s| hexb(s).try_into().unwrap()).collect();
        let tys: Vec<String> = e["opTypes"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().into()).collect();
        let toks: Vec<Address> = e["tokens"].as_array().unwrap().iter().map(a).collect();
        let entries = check_entries(cfg.address, &entries_of(&cfg).unwrap(), &sels, &tys, &toks).unwrap();
        let ret = crate::abi::IToken::eip712DomainCall::abi_decode_returns(&hexb(&r["service"]["domainReturn"])).unwrap();
        let domain = domain_of(cfg.address, 7622, ret.fields.0, ret.name, ret.version, ret.chainId, ret.verifyingContract, ret.salt,
            &ret.extensions).unwrap();
        assert_eq!(domain, b32(&r["service"]["domainSeparator"]));
        Service { address: cfg.address, domain, entries }
    }

    fn job(r: &Value) -> Value {
        r["job"].clone()
    }

    fn build(j: &Value, t: &Types) -> Result<Op> {
        Op::parse_with(j, None, t)
    }

    use alloy::sol_types::SolCall;

    /// Every row of `servicepull.json` (Python generator; landed by forge `ServicePullVectors.t.sol`): the job's named fields
    /// build the row's calldata byte for byte, its in-flight digest is the row's transfer digest, the shape holds (or check 2
    /// refuses the unbound `feeRecipient` row, as the contract does), and the read-back `servicePullEntries()` / `eip712Domain()`
    /// are the row's.
    #[test]
    fn servicepull_kat_every_row() {
        for r in rows() {
            let name = r["name"].as_str().unwrap();
            let p = build(&job(&r), &types_of(&r)).unwrap_or_else(|e| panic!("{name}: {e:#}"));
            assert_eq!(p.data.to_vec(), hexb(&r["calldata"]), "{name}: calldata");
            assert_eq!(p.to, a(&r["service"]["address"]), "{name}");
            assert_eq!(p.typed.contract, "service");
            assert_eq!(p.typed.domain_of, a(&r["token"]["address"]), "{name}: the pull token");
            let d = p.typed.digest_in("SCaaS MetaToken", 7622, b32(&r["token"]["salt"])).unwrap();
            assert_eq!(d, b32(&r["transferDigest"]), "{name}: the in-flight key is the pull's digest");
            assert_eq!(p.typed.struct_hash, Some(b32(&r["transferStructHash"])), "{name}");
            let svc = service_of(&r);
            let dec = decode(&svc.entries, &p.data).unwrap();
            assert_eq!(op_hash(dec.entry, &dec.op), b32(&r["opStructHash"]), "{name}");
            let got = shape(&svc, &dec);
            if r["serviceAccepts"].as_bool().unwrap() {
                assert_eq!(got, Ok(a(&r["token"]["address"])), "{name}");
            } else {
                assert!(got.unwrap_err().starts_with("SERVICE_PULL_SHAPE: 2"), "{name}: the node refuses what check 2 refuses");
            }
        }
    }

    /// The relay-fee wrap of each row: the router's `relay` calldata the node builds from the named job is the row's.
    #[test]
    fn servicepull_kat_relay_fee() {
        for r in rows().into_iter().filter(|r| r.get("relayFee").is_some()) {
            let f = &r["relayFee"];
            let j = json!({"entry": "mtxRelayFee", "contract": "token", "token": f["feeToken"], "call": job(&r),
                "args": {"from": r["t"]["from"], "payee": f["payee"], "value": f["value"], "batch": f["batch"], "nonce": f["nonce"],
                         "validUntil": f["validUntil"], "relayer": f["router"]},
                "auth": {"keyData": "0x", "signature": f["signature"], "members": []}});
            let p = build(&j, &types_of(&r)).unwrap_or_else(|e| panic!("{}: {e:#}", r["name"]));
            assert_eq!(p.data.to_vec(), hexb(&f["relayCalldata"]), "{}", r["name"]);
            assert_eq!(p.to, a(&f["router"]));
            // the fee at the pull's own nonce on its lane: refused before any simulation (it would fail MetaTxBadNonce)
            let mut bad = j.clone();
            bad["args"]["nonce"] = r["t"]["nonce"].clone();
            let e = build(&bad, &types_of(&r)).unwrap_err().to_string();
            assert!(e.starts_with("SERVICE_PULL_SHAPE: fee nonce"), "{e}");
            // another lane: no constraint between the two nonces
            let mut other = bad.clone();
            other["args"]["batch"] = json!("99");
            build(&other, &types_of(&r)).unwrap();
        }
    }

    /// Both directions: a config entry the contract lacks, a contract entry the config lacks, another `op_type` under the
    /// same name, a contract list twice; the control passes.
    #[test]
    fn entries_equal_both_directions() {
        let r = &rows()[0];
        let cfg = entries_of(&cfg_of(r)).unwrap();
        let s = cfg_of(r).address;
        let t = Address::repeat_byte(0x70);
        let (sels, tys): (Vec<[u8; 4]>, Vec<String>) = cfg.iter().map(|e| (e.selector, e.op_type.clone())).unzip();
        check_entries(s, &cfg, &sels, &tys, &[t, t]).unwrap();
        let mm = |r: Result<Vec<Entry>>| assert!(r.unwrap_err().to_string().starts_with("SERVICE_ENTRIES_MISMATCH"));
        mm(check_entries(s, &cfg, &sels[..1], &tys[..1], &[t])); // config entry missing on the contract
        mm(check_entries(s, &cfg[..1], &sels, &tys, &[t, t])); // contract entry missing from config
        let other = vec![tys[0].clone(), tys[0].clone()];
        mm(check_entries(s, &cfg, &sels, &other, &[t, t])); // another op_type under note's selector
        mm(check_entries(s, &cfg, &[sels[0], sels[0]], &[tys[0].clone(), tys[0].clone()], &[t, t])); // twice
        mm(check_entries(s, &cfg, &sels, &tys, &[t])); // unequal lengths
    }

    /// The domain read at startup: the service's own address, the chain's id, no extensions, fields 0x0f or 0x1f.
    #[test]
    fn domain_refusals() {
        let s = Address::repeat_byte(5);
        let ok = |f: u8, cid: u64, vc: Address, ext: &[U256]| domain_of(s, 7622, [f], "N".into(), "1".into(), U256::from(cid), vc, B256::ZERO, ext);
        ok(0x0f, 7622, s, &[]).unwrap();
        ok(0x1f, 7622, s, &[]).unwrap();
        for e in [ok(0x0f, 1, s, &[]), ok(0x0f, 7622, Address::repeat_byte(6), &[]), ok(0x07, 7622, s, &[]), ok(0x0f, 7622, s, &[U256::from(1)])] {
            assert!(e.unwrap_err().to_string().starts_with("SERVICE_ENTRIES_MISMATCH"));
        }
    }

    /// C3 and the config bounds on `Note`: 17 fields, a nested struct, an array, `intN`, not `bytes32 payer` first; 33
    /// entries; an `op_type` over 1,024 bytes; each with its control.
    #[test]
    fn op_type_and_config_bounds() {
        let note = "Note(bytes32 payer,uint256 amount,string memo,bytes commitment,bytes32 salt)";
        assert_eq!(parse_op_type(note).unwrap().1.len(), 5);
        let plus = |extra: &str| format!("{},{extra})", note.strip_suffix(')').unwrap());
        let f16 = (0..11).map(|i| format!("uint8 f{i}")).collect::<Vec<_>>().join(",");
        assert_eq!(parse_op_type(&plus(&f16)).unwrap().1.len(), 16, "16 fields: the control");
        let f17 = (0..12).map(|i| format!("uint8 f{i}")).collect::<Vec<_>>().join(",");
        for bad in [plus(&f17), plus("Inner inner"), plus("uint256[] xs"), plus("int256 n"), plus("bytes33 x"), plus("uint7 x"),
            "Note(uint256 amount,bytes32 payer)".into(), plus("uint8 amount"), "Note(bytes32  payer)".into(), "1Note(bytes32 payer)".into()] {
            assert!(parse_op_type(&bad).is_err(), "{bad}");
        }
        let s = |n: usize, ty: &str| ServiceCfg { address: Address::repeat_byte(5),
            entries: (0..n).map(|i| EntryCfg { entry: format!("e{i}"), op_type: ty.into() }).collect() };
        entries_of(&s(32, note)).unwrap();
        assert!(entries_of(&s(33, note)).unwrap_err().to_string().contains("33 entries"));
        assert!(entries_of(&s(0, note)).is_err());
        let long = format!("Note(bytes32 payer,{})", (0..15).map(|i| format!("bytes32 {}{i}", "f".repeat(60))).collect::<Vec<_>>().join(","));
        assert!(long.len() > MAX_OP_TYPE_BYTES);
        assert!(format!("{:#}", entries_of(&s(1, &long)).unwrap_err()).contains("above 1024"), "op_type over 1,024 bytes");
        let mut twice = s(2, note);
        twice.entries[1].entry = "e0".into();
        assert!(entries_of(&twice).unwrap_err().to_string().contains("twice"));
    }

    /// The decode bounds on `Note`'s job: `bytes` over `max_service_op_bytes` refused, a `string` at the limit accepted, a
    /// missing or extra field, a hex `op`, an unknown `args` key or a top-level `auth` refused.
    #[test]
    fn note_decode_bounds() {
        let r = rows().into_iter().find(|r| r["name"] == "note_native").unwrap();
        let t = Types { max_op_bytes: 40, ..types_of(&r) };
        let mut j = job(&r);
        j["args"]["op"]["memo"] = json!("x".repeat(40));
        build(&j, &t).unwrap();
        j["args"]["op"]["commitment"] = json!(format!("0x{}", "ab".repeat(41)));
        assert!(build(&j, &t).unwrap_err().to_string().starts_with("BAD_PAYLOAD: args.op.commitment: 41 B"));
        let mut j = job(&r);
        j["args"]["op"]["memo"] = json!("x".repeat(41));
        assert!(build(&j, &t).unwrap_err().to_string().starts_with("BAD_PAYLOAD: args.op.memo: 41 B"));
        let refused = |f: &dyn Fn(&mut Value), why: &str| {
            let mut j = job(&r);
            f(&mut j);
            let e = build(&j, &types_of(&r)).unwrap_err().to_string();
            assert!(e.starts_with(why), "{why}: {e}");
        };
        refused(&|j| { j["args"]["op"].as_object_mut().unwrap().remove("salt"); }, "BAD_PAYLOAD: args.op.salt: missing");
        refused(&|j| j["args"]["op"]["extra"] = json!("1"), "BAD_PAYLOAD: args.op.extra: unknown field");
        refused(&|j| j["args"]["op"] = json!("0x1234"), "BAD_PAYLOAD: args.op is not an object");
        refused(&|j| j["args"]["calldata"] = json!("0x"), "BAD_PAYLOAD: args.calldata");
        refused(&|j| j["auth"] = json!({}), "BAD_PAYLOAD: op.auth");
        refused(&|j| j["entry"] = json!("withdraw"), "UNKNOWN_ENTRY");
        refused(&|j| j["token"] = json!(format!("{:#x}", Address::repeat_byte(9))), "CALL_TARGET_REFUSED");
        refused(&|j| j["args"]["op"]["amount"] = json!(2500), "BAD_PAYLOAD: args.op.amount");
    }

    /// §3.3 steps 1-4, one change at a time from the row (the shape the contract would refuse, before any simulation), the
    /// pull token the contract's (`SERVICE_TOKEN_MISMATCH` for an entry that names none), and the control.
    #[test]
    fn shape_refusals() {
        let r = &rows()[0];
        let svc = service_of(r);
        let shaped = |f: &dyn Fn(&mut Value)| {
            let mut j = job(r);
            f(&mut j);
            let p = build(&j, &types_of(r)).unwrap();
            shape(&svc, &decode(&svc.entries, &p.data).unwrap())
        };
        assert_eq!(shaped(&|_| {}), Ok(a(&r["token"]["address"])), "the control");
        let code = |f: &dyn Fn(&mut Value), c: &str| {
            let e = shaped(f).unwrap_err();
            assert!(e.starts_with(&format!("SERVICE_PULL_SHAPE: {c}")), "{c}: {e}");
        };
        code(&|j| j["args"]["t"]["to"] = json!(format!("{:#x}", Address::repeat_byte(9).into_word())), "1");
        code(&|j| j["args"]["t"]["mode"] = json!(0), "2");
        code(&|j| j["args"]["t"]["mode"] = json!(0x21), "2");
        code(&|j| j["args"]["t"]["relayer"] = json!(format!("{:#x}", Address::repeat_byte(9))), "2");
        code(&|j| j["args"]["t"]["fee"] = json!("1"), "2");
        code(&|j| j["args"]["t"]["feeRecipient"] = json!(format!("{:#x}", Address::repeat_byte(9))), "2");
        code(&|j| j["args"]["op"]["amount"] = json!("1001"), "3");
        code(&|j| j["args"]["t"]["entryRef"] = json!(format!("{:#x}", B256::repeat_byte(1))), "3");
        let other = format!("{:#x}", Address::repeat_byte(0x44).into_word());
        code(&|j| j["args"]["t"]["from"] = json!(other), "4");
        let mut none = svc.clone();
        none.entries[0].token = Some(Address::ZERO);
        let p = build(&job(r), &types_of(r)).unwrap();
        assert!(shape(&none, &decode(&none.entries, &p.data).unwrap()).unwrap_err().starts_with("SERVICE_TOKEN_MISMATCH"));
        assert!(decode(&svc.entries, &p.data[..p.data.len() - 1]).is_none(), "a truncated call is no entry");
    }
}
