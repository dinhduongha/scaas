// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs `registration_args` over JSON (typed-signing R2; the same file in ua-c, ua-cxx, ua-qt and ua-dart-frb). In: the object of
//! clientkeys `registrationArgs`, `{kind, keyData, pqzKey, pqzPopHash, pqzPop, kemPk, pop, kemCommit}`: bytes as "0x…" hex, an
//! absent field is empty, an msig's `pop` is its member signatures `[{index, keyData, sig}]`, `kemCommit` true / false forces the
//! KEM form (absent: the hash commit only over `REGISTER_CALLDATA_LIMIT`). Out: `{args, kemFill, calldataLength,
//! kemFillCalldataLength}`: `args` with its `entry` and `kemFill` as portable.json `registrations[i].args` / `kemCommit.fill`,
//! the two `kemFill…` null without a hash commit, lengths in bytes with the selector.
use scaas_ua::ua8::{registration_args, KemKey, MemberSig, RegisterArgs, RegistrationInput, SetKemKeyArgs, UAAttrs};
use scaas_ua::UAError;
use serde_json::{json, Value};

/// `Argument`: input that is not this JSON (`UAArgument`).
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
// not `R`: flutter_rust_bridge resolves type aliases across the crate, and ua.rs has its own
type JsonResult<T> = Result<T, JsonError>;

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
fn input(t: &str) -> JsonResult<RegistrationInput> {
    let v: Value = serde_json::from_str(t).map_err(|_| Argument)?;
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
fn fill_json(f: &SetKemKeyArgs) -> Value {
    let sig = json!({ "keyData": hx(&f.sig.key_data), "signature": hx(&f.sig.signature), "members": members_json(&f.sig.members) });
    json!({ "ua": hx(&f.ua), "version": f.version, "kem": kem_json(&f.kem), "sig": sig })
}

pub fn registration_args_json(t: &str) -> JsonResult<String> {
    let r = registration_args(&input(t)?)?;
    let fill = r.kem_fill.as_ref();
    let out = json!({ "args": args_json(&r.args), "kemFill": fill.map(fill_json), "calldataLength": r.args.calldata_len(),
        "kemFillCalldataLength": fill.map(SetKemKeyArgs::calldata_len) });
    Ok(out.to_string())
}
