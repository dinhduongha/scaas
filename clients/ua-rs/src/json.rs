// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `json`: the registry's explicit arguments as one JSON string call each (typed-signing R2 / R2c), the surface of ua-c,
//! ua-cxx, ua-qt and ua-dart-frb. Bytes are "0x…" hex and an absent field is empty. [`registration_args_json`] in: the object of
//! clientkeys `registrationArgs`, `{kind, keyData, pqzKey, pqzPopHash, pqzPop, kemPk, pop, kemCommit}`: an msig's `pop` is its
//! member signatures `[{index, keyData, sig}]`, `kemCommit` true / false forces the KEM form (absent: the hash commit only over
//! `REGISTER_CALLDATA_LIMIT`). Out: `{args, kemFill, calldataLength, kemFillCalldataLength}`: `args` with its `entry` and `kemFill`
//! as portable.json `registrations[i].args` / `kemCommit.fill`, the two `kemFill…` null without a hash commit, lengths in bytes
//! with the selector. [`set_kem_key_args_json`] in: `{ua, version, kemPk, sig}`; [`set_pqz_key_args_json`] in: `{ua, pqzKey,
//! pqzPopHash, sig}`, `sig` the `UASig` `{keyData, signature, members: [{index, keyData, sig}]}`; out: portable.json
//! `kemRecords[i].args` / `pqzKeyRecords[i].args`.
use crate::ua8::{registration_args, KemKey, MemberSig, RegisterArgs, RegistrationInput, SetKemKeyArgs, UASig, UAAttrs};
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
    let m = |s: &Value| Ok(MemberSig { index: u16_of(&s["index"])?, key_data: unhex(&s["keyData"])?, sig: unhex(&s["sig"])? });
    v.as_array().ok_or(Argument)?.iter().map(m).collect()
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
    m.iter().map(|s| json!({ "index": s.index, "keyData": hx(&s.key_data), "sig": hx(&s.sig) })).collect()
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
    let a = SetKemKeyArgs { ua, version, kem: KemKey::from_kem_pk(&unhex(&v["kemPk"])?)?, sig: sig_in(&v["sig"])? };
    Ok(fill_json(&a).to_string())
}

pub fn set_pqz_key_args_json(t: &str) -> JsonResult<String> {
    let v = parse(t)?;
    let ua = ua_in(&v["ua"])?;
    let hash: [u8; 32] = unhex(&v["pqzPopHash"])?.try_into().map_err(|_| UAError::PqzPopHash)?;
    let sig = sig_json(&sig_in(&v["sig"])?);
    Ok(json!({ "ua": hx(&ua), "pqzKey": hx(&unhex(&v["pqzKey"])?), "pqzPopHash": hx(&hash), "sig": sig }).to_string())
}
