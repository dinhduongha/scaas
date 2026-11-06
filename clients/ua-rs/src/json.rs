// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `json`: the registry's explicit arguments as one JSON string call each (typed-signing R2 / R2c), the surface of ua-c,
//! ua-cxx, ua-qt and ua-dart-frb. Bytes are "0x…" hex and an absent field is empty. [`registration_args_json`] in: the object of
//! clientkeys `registrationArgs`, `{kind, keyData, pqzKey, pqzPopHash, pqzPop, kemPk, pop, kemCommit, inner}`: an msig's `pop` is its
//! member signatures `[{index, members: [{index, sig}], sig}]`, `kemCommit` true / false forces the KEM form (absent: the hash commit
//! only over `REGISTER_CALLDATA_LIMIT`), `inner` `{id: keyData}` the `msig` members' structures. Out: `{args, kemFill, calldataLength, kemFillCalldataLength}`: `args` with its `entry` and `kemFill`
//! as portable.json `registrations[i].args` / `kemCommit.fill`, the two `kemFill…` null without a hash commit, lengths in bytes
//! with the selector. [`set_kem_key_args_json`] in: `{ua, version, kemPk, sig}`; [`set_pqz_key_args_json`] in: `{ua, pqzKey,
//! pqzPopHash, sig}`, `sig` the `UASig` `{keyData, signature, members: [{index, members, sig}]}`; out: portable.json
//! `kemRecords[i].args` / `pqzKeyRecords[i].args`.
use crate::ua8::{registration_args, replayed_member_sig, InnerSig, KemKey, MemberSig, RegisterArgs, RegistrationInput, SetKemKeyArgs, UASig, UAAttrs};
use crate::UAError;
use serde_json::{json, Value};

/// `Argument`: input that is not this JSON (`UAArgument`).
#[derive(Debug, PartialEq, Eq)]
pub enum JsonError {
    Argument,
    Ua(UAError),
}
impl From<UAError> for JsonError {
    fn from(e: UAError) -> Self {
        JsonError::Ua(e)
    }
}
use JsonError::Argument;
// not `R`: flutter_rust_bridge resolves type aliases across its crate, and ua-dart-frb's ua.rs has its own
pub type JsonResult<T> = Result<T, JsonError>;

fn unhex(v: &Value) -> JsonResult<Vec<u8>> {
    if v.is_null() {
        return Ok(vec![]);
    }
    let h = v.as_str().and_then(|s| s.strip_prefix("0x")).ok_or(Argument)?;
    if h.len() % 2 != 0 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(Argument);
    }
    Ok((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect())
}
fn u16_of(v: &Value) -> JsonResult<u16> {
    v.as_u64().and_then(|n| u16::try_from(n).ok()).ok_or(Argument)
}
fn members_in(v: &Value) -> JsonResult<Vec<MemberSig>> {
    if v.is_null() {
        return Ok(vec![]);
    }
    let m = |s: &Value| Ok(MemberSig { index: u16_of(&s["index"])?, members: inner_in(&s["members"])?, sig: unhex(&s["sig"])? });
    v.as_array().ok_or(Argument)?.iter().map(m).collect()
}
/// At most 16 entries, the type's two levels: nothing here recurses.
fn inner_in(v: &Value) -> JsonResult<Vec<InnerSig>> {
    if v.is_null() {
        return Ok(vec![]);
    }
    let m = |s: &Value| Ok(InnerSig { index: u16_of(&s["index"])?, sig: unhex(&s["sig"])? });
    v.as_array().filter(|a| a.len() <= 16).ok_or(Argument)?.iter().map(m).collect()
}
/// `{id: keyData}`: at most 16 entries of at most `4 + 36 × 16` bytes each, an `msig` of 16 members (`Argument` otherwise). A value is a
/// string, so the object is the one level; serde_json's recursion limit bounds the parse.
fn inners_in(v: &Value) -> JsonResult<Vec<([u8; 32], Vec<u8>)>> {
    if v.is_null() {
        return Ok(vec![]);
    }
    let id = |k: &String| unhex(&Value::from(k.as_str()))?.try_into().map_err(|_| Argument);
    let data = |d: &Value| unhex(d).and_then(|d| if d.len() <= 4 + 36 * 16 { Ok(d) } else { Err(Argument) });
    v.as_object().filter(|o| o.len() <= 16).ok_or(Argument)?.iter().map(|(k, d)| Ok((id(k)?, data(d)?))).collect()
}
/// The longest `inner` text [`inner_json`] reads: 16 entries in hex are about 20 KB, the rest is room for whitespace.
pub const INNER_JSON_MAX: usize = 65_536;
/// `inner` alone, `{id: keyData}` as [`registration_args_json`] takes it: the `msig` members' structures for the `_with` calls of ua-c,
/// ua-cxx, ua-qt and ua-dart-frb (no callback crosses their ABI). "" or `null` is none; over [`INNER_JSON_MAX`] bytes, more than 16
/// entries or key data over 580 bytes is `Argument`. A missing entry, or one that holds an `msig` (a third level), is then `MemberUnknown`.
pub fn inner_json(t: &str) -> JsonResult<Vec<([u8; 32], Vec<u8>)>> {
    if t.is_empty() {
        return Ok(vec![]);
    }
    if t.len() > INNER_JSON_MAX {
        return Err(Argument);
    }
    inners_in(&parse(t)?)
}
/// The `inner` lookup of the `_with` calls over [`inner_json`]'s entries.
pub fn lookup(inner: &[([u8; 32], Vec<u8>)]) -> impl Fn([u8; 32]) -> Option<Vec<u8>> + '_ {
    move |id| inner.iter().find(|(x, _)| *x == id).map(|(_, d)| d.clone())
}
/// [`replayed_member_sig`] as one slot `{index, members: [{index, sig}], sig}`, the shape of a `pop` or `sig.members` entry.
pub fn replayed_member_sig_json(key_data: &[u8], index: u16, stored: &[u8]) -> JsonResult<String> {
    Ok(members_json(&[replayed_member_sig(key_data, index, stored)?])[0].to_string())
}
fn parse(t: &str) -> JsonResult<Value> {
    serde_json::from_str(t).map_err(|_| Argument)
}
fn ua_in(v: &Value) -> JsonResult<[u8; 32]> {
    unhex(v)?.try_into().map_err(|_| Argument)
}
fn sig_in(v: &Value) -> JsonResult<UASig> {
    if !v.is_null() && !v.is_object() {
        return Err(Argument); // indexing it would read as an empty signature
    }
    Ok(UASig { key_data: unhex(&v["keyData"])?, signature: unhex(&v["signature"])?, members: members_in(&v["members"])? })
}
fn input(t: &str) -> JsonResult<RegistrationInput> {
    let v = parse(t)?;
    let kind = u16_of(&v["kind"])?;
    let hash = unhex(&v["pqzPopHash"])?;
    let msig = kind == 0x0120;
    Ok(RegistrationInput {
        kind,
        key_data: unhex(&v["keyData"])?,
        pqz_key: unhex(&v["pqzKey"])?,
        pqz_pop_hash: if hash.is_empty() { [0; 32] } else { hash.try_into().map_err(|_| UAError::PqzPopHash)? },
        pqz_pop: unhex(&v["pqzPop"])?,
        kem_pk: unhex(&v["kemPk"])?,
        pop: if msig { vec![] } else { unhex(&v["pop"])? },
        members: if msig { members_in(&v["pop"])? } else { vec![] },
        kem_commit: match &v["kemCommit"] {
            Value::Null => None,
            Value::Bool(b) => Some(*b),
            _ => return Err(Argument),
        },
        inners: inners_in(&v["inner"])?,
    })
}

fn hx(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
}
fn hxs(l: &[Vec<u8>]) -> Vec<String> {
    l.iter().map(|b| hx(b)).collect()
}
fn kem_json(k: &KemKey) -> Value {
    json!({ "scheme": k.scheme, "mlkemEk": hx(&k.mlkem_ek), "x25519": hx(&k.x25519) })
}
fn members_json(m: &[MemberSig]) -> Value {
    let inner = |l: &[InnerSig]| l.iter().map(|x| json!({ "index": x.index, "sig": hx(&x.sig) })).collect::<Vec<_>>();
    m.iter().map(|s| json!({ "index": s.index, "members": inner(&s.members), "sig": hx(&s.sig) })).collect()
}
fn attrs_json(a: &UAAttrs) -> Value {
    json!({ "pqzKey": hx(&a.pqz_key), "pqzPopHash": hx(&a.pqz_pop_hash), "kem": kem_json(&a.kem), "kemPkHash": hx(&a.kem_pk_hash) })
}
fn args_json(r: &RegisterArgs) -> Value {
    let tail = |entry: &str, attrs: &UAAttrs, pqz_pop: &[u8]| json!({ "entry": entry, "attrs": attrs_json(attrs), "pqzPop": hx(pqz_pop) });
    let (mut o, extra) = match r {
        RegisterArgs::Register { kind, key_data, attrs, pop, pqz_pop } => {
            (tail("register", attrs, pqz_pop), json!({ "kind": kind, "keyData": hx(key_data), "pop": hx(pop) }))
        }
        RegisterArgs::RegisterMsig { structure, attrs, pop, pqz_pop } => {
            let members: Vec<Value> =
                structure.members.iter().map(|m| json!({ "kind": m.kind, "id": hx(&m.id), "weight": m.weight })).collect();
            let structure = json!({ "threshold": structure.threshold, "members": members });
            (tail("registerMsig", attrs, pqz_pop), json!({ "structure": structure, "pop": members_json(pop) }))
        }
        RegisterArgs::RegisterWebAuthn { key, attrs, pop, pqz_pop } => {
            let key = json!({ "x": hx(&key.x), "y": hx(&key.y), "rpIdHash": hx(&key.rp_id_hash) });
            (tail("registerWebAuthn", attrs, pqz_pop), json!({ "key": key, "pop": hx(pop) }))
        }
        RegisterArgs::RegisterMuSig2 { kind, key, attrs, pop, pqz_pop } => {
            let key = json!({ "aggKey": hx(&key.agg_key), "memberKeys": hxs(&key.member_keys) });
            (tail("registerMuSig2", attrs, pqz_pop), json!({ "kind": kind, "key": key, "pop": hx(pop) }))
        }
        RegisterArgs::RegisterFrost { kind, key, attrs, pop, pqz_pop } => {
            let members: Vec<Value> =
                key.members.iter().map(|m| json!({ "commitments": hxs(&m.commitments), "r": hx(&m.r), "z": hx(&m.z) })).collect();
            let key = json!({ "groupKey": hx(&key.group_key), "threshold": key.threshold, "members": members });
            (tail("registerFrost", attrs, pqz_pop), json!({ "kind": kind, "key": key, "pop": hx(pop) }))
        }
    };
    o.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    o
}
fn sig_json(s: &UASig) -> Value {
    json!({ "keyData": hx(&s.key_data), "signature": hx(&s.signature), "members": members_json(&s.members) })
}
fn fill_json(f: &SetKemKeyArgs) -> Value {
    json!({ "ua": hx(&f.ua), "version": f.version, "kem": kem_json(&f.kem), "sig": sig_json(&f.sig) })
}

pub fn registration_args_json(t: &str) -> JsonResult<String> {
    let r = registration_args(&input(t)?)?;
    let fill = r.kem_fill.as_ref();
    let out = json!({ "args": args_json(&r.args), "kemFill": fill.map(fill_json), "calldataLength": r.args.calldata_len(),
        "kemFillCalldataLength": fill.map(SetKemKeyArgs::calldata_len) });
    Ok(out.to_string())
}

pub fn set_kem_key_args_json(t: &str) -> JsonResult<String> {
    let v = parse(t)?;
    let (ua, version) = (ua_in(&v["ua"])?, v["version"].as_u64().ok_or(Argument)?);
    let (kem_pk, sig) = (unhex(&v["kemPk"])?, sig_in(&v["sig"])?);
    if kem_pk.is_empty() {
        return Err(UAError::KemKeyLength.into()); // the empty key is `register`'s "none", never a `setKemKey`
    }
    Ok(fill_json(&SetKemKeyArgs { ua, version, kem: KemKey::from_kem_pk(&kem_pk)?, sig }).to_string())
}

pub fn set_pqz_key_args_json(t: &str) -> JsonResult<String> {
    let v = parse(t)?;
    let ua = ua_in(&v["ua"])?;
    let hash: [u8; 32] = unhex(&v["pqzPopHash"])?.try_into().map_err(|_| UAError::PqzPopHash)?;
    let sig = sig_json(&sig_in(&v["sig"])?);
    Ok(json!({ "ua": hx(&ua), "pqzKey": hx(&unhex(&v["pqzKey"])?), "pqzPopHash": hx(&hash), "sig": sig }).to_string())
}

// ------------------------------------------------------------------ pay-meta-tax T41: the pay structs (`crate::pay`)

/// A uint of the JSON, a number or a decimal string, as its ABI word (`Argument` above 256 bits or not a number).
fn uint_in(v: &Value) -> JsonResult<[u8; 32]> {
    let s = match v {
        Value::Number(n) => n.as_u64().ok_or(Argument)?.to_string(),
        Value::String(s) if !s.is_empty() && s.len() <= 78 && s.bytes().all(|c| c.is_ascii_digit()) => s.clone(),
        _ => return Err(Argument),
    };
    let mut w = [0u8; 32];
    for d in s.bytes() {
        let mut carry = (d - b'0') as u32;
        for b in w.iter_mut().rev() {
            let x = *b as u32 * 10 + carry;
            *b = x as u8;
            carry = x >> 8;
        }
        if carry != 0 {
            return Err(Argument);
        }
    }
    Ok(w)
}
fn addr_in(v: &Value) -> JsonResult<[u8; 20]> {
    unhex(v)?.try_into().map_err(|_| Argument)
}
fn small_in<T: TryFrom<u64>>(v: &Value) -> JsonResult<T> {
    let n = match v {
        Value::Number(n) => n.as_u64(),
        Value::String(s) => s.parse().ok(),
        _ => None,
    };
    n.and_then(|n| T::try_from(n).ok()).ok_or(Argument)
}
fn transfer_in(m: &Value) -> JsonResult<crate::pay::UAMetaTransfer> {
    Ok(crate::pay::UAMetaTransfer {
        from: ua_in(&m["from"])?,
        to: ua_in(&m["to"])?,
        value: uint_in(&m["value"])?,
        entry_ref: ua_in(&m["entryRef"])?,
        batch: uint_in(&m["batch"])?,
        nonce: uint_in(&m["nonce"])?,
        valid_until: uint_in(&m["validUntil"])?,
        mode: small_in(&m["mode"])?,
        relayer: addr_in(&m["relayer"])?,
        fee: uint_in(&m["fee"])?,
        fee_recipient: addr_in(&m["feeRecipient"])?,
    })
}

/// `{struct, domain: {name, chainId, verifyingContract, salt}, message}` → `{structHash, digest}`: what a payer signs for
/// `UAMetaTransfer` (`mtxPay`), `UAPayWithTax` (`{payment, taxMode, tax}`, kinds 8-13) or `UARelayFee` (`{from, target,
/// callDataHash, payee, value, batch, nonce, validUntil, relayer}`); uints as numbers or decimal strings, an unbound
/// `relayer` / `feeRecipient` hashed as 0. `Argument` for anything else, a tax mode not 1 or 2, or `tax > value`.
pub fn pay_digest_json(t: &str) -> JsonResult<String> {
    use crate::pay::{pay_with_tax_hash, relay_fee_hash, token_domain_separator, transfer_hash, typed_digest, RelayFee};
    let v = parse(t)?;
    let (d, m) = (&v["domain"], &v["message"]);
    let sh = match v["struct"].as_str() {
        Some("UAMetaTransfer") => transfer_hash(&transfer_in(m)?),
        Some("UAPayWithTax") => pay_with_tax_hash(&transfer_in(&m["payment"])?, small_in(&m["taxMode"])?, &uint_in(&m["tax"])?)
            .map_err(|_| Argument)?,
        Some("UARelayFee") => relay_fee_hash(&RelayFee { from: ua_in(&m["from"])?, target: addr_in(&m["target"])?,
            call_data_hash: ua_in(&m["callDataHash"])?, payee: ua_in(&m["payee"])?, value: uint_in(&m["value"])?,
            batch: uint_in(&m["batch"])?, nonce: uint_in(&m["nonce"])?, valid_until: uint_in(&m["validUntil"])?,
            relayer: addr_in(&m["relayer"])? }),
        _ => return Err(Argument),
    };
    let ds = token_domain_separator(d["name"].as_str().ok_or(Argument)?, small_in(&d["chainId"])?,
        &addr_in(&d["verifyingContract"])?, &ua_in(&d["salt"])?);
    Ok(json!({ "structHash": hx(&sh), "digest": hx(&typed_digest(&ds, &sh)) }).to_string())
}

/// `{salt, payNo, schema, body}` → `{payId}`: `metaPayId` under `scaas.pay.meta.v2`, after the shape and `payNo` checks
/// (`Argument` when refused).
pub fn meta_pay_id_json(t: &str) -> JsonResult<String> {
    let v = parse(t)?;
    let m = crate::pay::PayMeta { salt: ua_in(&v["salt"])?, pay_no: v["payNo"].as_str().unwrap_or("").to_string(),
        schema: small_in(&v["schema"])?, body: unhex(&v["body"])? };
    Ok(json!({ "payId": hx(&crate::pay::meta_pay_id_v2(&m).map_err(|_| Argument)?) }).to_string())
}
