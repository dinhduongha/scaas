// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
//! `UaKinds`: QML singleton over `scaas-ua`. Bytes travel as "0x…" hex strings. Every invokable clears `lastError`, and on
//! failure sets it to the error code and returns "" (strings) or false (bools); panics never cross the FFI.
#[cxx_qt::bridge]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        type QString = cxx_qt_lib::QString;
    }

    extern "RustQt" {
        #[qobject]
        #[qml_element]
        #[qml_singleton]
        #[qproperty(QString, last_error, cxx_name = "lastError")]
        type UaKinds = super::UaKindsRust;

        #[qinvokable] #[cxx_name = "kindInfo"] fn kind_info(self: Pin<&mut Self>, kind: i32) -> QString;
        #[qinvokable] fn tag(self: Pin<&mut Self>, kind: i32) -> QString;
        #[qinvokable] #[cxx_name = "kindTagString"] fn kind_tag_string(self: Pin<&mut Self>, kind: i32) -> QString;
        #[qinvokable] #[cxx_name = "groupTag"] fn group_tag(self: Pin<&mut Self>, group: &QString) -> QString;
        #[qinvokable] #[cxx_name = "groupTagString"] fn group_tag_string(self: Pin<&mut Self>, group: &QString) -> QString;
        #[qinvokable] #[cxx_name = "msgTag"] fn msg_tag(self: Pin<&mut Self>) -> QString;
        #[qinvokable] #[cxx_name = "purposeTag"] fn purpose_tag(self: Pin<&mut Self>, purpose: &QString) -> QString;
        #[qinvokable] #[cxx_name = "uaOf"] fn ua_of(self: Pin<&mut Self>, kind: i32, key_data: &QString) -> QString;
        #[qinvokable] #[cxx_name = "deriveUA"]
        fn derive_ua(self: Pin<&mut Self>, kind: i32, key_data: &QString, hedera_native: bool) -> QString;
        #[qinvokable] #[cxx_name = "nativeId"] fn native_id(self: Pin<&mut Self>, kind: i32, raw: &QString) -> QString;
        /// "" for a structure kind (no error) -- check `lastError` to tell it from a failure.
        #[qinvokable] #[cxx_name = "keyHashOf"] fn key_hash_of(self: Pin<&mut Self>, kind: i32, key_data: &QString) -> QString;
        /// false on failure (see `lastError`).
        #[qinvokable] #[cxx_name = "validateKeyData"]
        fn validate_key_data(self: Pin<&mut Self>, kind: i32, key_data: &QString, hedera_native: bool) -> bool;
        #[qinvokable] #[cxx_name = "inNativeSpace"] fn in_native_space(self: Pin<&mut Self>, id: &QString) -> bool;
        #[qinvokable] #[cxx_name = "isNative"] fn is_native(self: Pin<&mut Self>, kind: i32) -> bool;
        #[qinvokable] #[cxx_name = "isZether"] fn is_zether(self: Pin<&mut Self>, kind: i32) -> bool;
        #[qinvokable] #[cxx_name = "isSigning"] fn is_signing(self: Pin<&mut Self>, kind: i32) -> bool;
        #[qinvokable] #[cxx_name = "isMember"] fn is_member(self: Pin<&mut Self>, kind: i32, hedera_native: bool) -> bool;
        #[qinvokable] #[cxx_name = "uaMessage"]
        fn ua_message(self: Pin<&mut Self>, kind: i32, purpose: &QString, digest: &QString) -> QString;
        /// `chain_id` is a JS number: exact up to 2^53.
        #[qinvokable] #[cxx_name = "chainKeyHash"] fn chain_key_hash(self: Pin<&mut Self>, chain_id: f64) -> QString;
        #[qinvokable] #[cxx_name = "popDigest"]
        fn pop_digest(self: Pin<&mut Self>, chain_id: f64, chain_uid: &QString, registry: &QString, ua: &QString, auth_ref: &QString) -> QString;
        #[qinvokable] #[cxx_name = "uaAuthDomainSeparator"]
        fn ua_auth_domain_separator(self: Pin<&mut Self>, generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString) -> QString;
        #[qinvokable] #[cxx_name = "uaAuthDigest"]
        fn ua_auth_digest(self: Pin<&mut Self>, generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString, ua: &QString, purpose: &QString, digest: &QString) -> QString;
        #[qinvokable] #[cxx_name = "memberDigest"]
        fn member_digest(self: Pin<&mut Self>, structure_ua: &QString, ua_msg: &QString) -> QString;
        #[qinvokable] #[cxx_name = "canonicalId"] fn canonical_id(self: Pin<&mut Self>, text: &QString) -> QString;
        /// `members` is a JSON array of `[kind, "0x<id32>", weight]`.
        #[qinvokable] #[cxx_name = "encodeMsig"]
        fn encode_msig(self: Pin<&mut Self>, threshold: i32, members: &QString) -> QString;
    }
}

use core::pin::Pin;
use cxx_qt_lib::QString;
use scaas_ua as ua;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[derive(Default)]
pub struct UaKindsRust {
    last_error: QString,
}

/// Error code: a `scaas-ua` code; `UAKeyData` for undecodable key data; `UAArgument` for other input the binding cannot
/// decode (bad hex / length / range of digests, ids, purposes, chain ids, JSON).
type Res<T> = Result<T, &'static str>;
const ARG: &str = "UAArgument";

fn from_ua<T>(r: ua::Result<T>) -> Res<T> {
    r.map_err(|e| e.code())
}
fn s(q: &QString) -> String {
    String::from(q)
}
fn hx(b: &[u8]) -> String {
    let mut o = String::with_capacity(2 + 2 * b.len());
    o.push_str("0x");
    for x in b {
        o.push_str(&format!("{x:02x}"));
    }
    o
}
fn bytes(q: &QString) -> Res<Vec<u8>> {
    let t = s(q);
    let h = t.strip_prefix("0x").unwrap_or(&t);
    if h.len() % 2 != 0 || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(ARG);
    }
    Ok((0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect())
}
/// Key data and native ids: undecodable hex is malformed key data (`UAKeyData`), as in every other UA library.
fn key(q: &QString) -> Res<Vec<u8>> {
    bytes(q).map_err(|_| "UAKeyData")
}
fn fixed<const N: usize>(q: &QString) -> Res<[u8; N]> {
    bytes(q)?.try_into().map_err(|_| ARG)
}
fn k(kind: i32) -> Res<u16> {
    u16::try_from(kind).map_err(|_| ARG)
}
fn id(v: f64) -> Res<u64> {
    if v.fract() == 0.0 && (0.0..=9007199254740992.0).contains(&v) { Ok(v as u64) } else { Err(ARG) }
}
fn domain(generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString) -> Res<ua::Domain> {
    Ok(ua::Domain {
        generation: u32::try_from(generation).map_err(|_| ARG)?,
        chain_id: id(chain_id)?,
        registry: fixed(registry)?,
        chain_uid: fixed(chain_uid)?,
    })
}

impl qobject::UaKinds {
    /// Clear `lastError`, run `f` (panic-guarded); on failure set `lastError` and return `T::default()`.
    fn run<T: Default>(mut self: Pin<&mut Self>, f: impl FnOnce() -> Res<T>) -> T {
        self.as_mut().set_last_error(QString::default());
        match catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err("UAInternal")) {
            Ok(v) => v,
            Err(code) => {
                self.set_last_error(QString::from(code));
                T::default()
            }
        }
    }
    fn hex(self: Pin<&mut Self>, f: impl FnOnce() -> Res<Vec<u8>>) -> QString {
        QString::from(&self.run(|| f().map(|b| hx(&b))))
    }

    pub fn kind_info(self: Pin<&mut Self>, kind: i32) -> QString {
        QString::from(&self.run(|| {
            let i = from_ua(ua::kind_info(k(kind)?))?;
            Ok(serde_json::json!({"kind": i.kind, "name": i.name, "native": i.native, "lengths": i.lengths, "group": i.group})
                .to_string())
        }))
    }
    pub fn tag(self: Pin<&mut Self>, kind: i32) -> QString {
        self.hex(|| Ok(from_ua(ua::tag(k(kind)?))?.to_vec()))
    }
    pub fn kind_tag_string(self: Pin<&mut Self>, kind: i32) -> QString {
        QString::from(&self.run(|| from_ua(ua::kind_tag_string(k(kind)?))))
    }
    pub fn group_tag(self: Pin<&mut Self>, group: &QString) -> QString {
        self.hex(|| Ok(ua::group_tag(&s(group)).ok_or("UAKindUnknown")?.to_vec()))
    }
    pub fn group_tag_string(self: Pin<&mut Self>, group: &QString) -> QString {
        QString::from(&self.run(|| ua::group_tag_string(&s(group)).ok_or("UAKindUnknown")))
    }
    pub fn msg_tag(self: Pin<&mut Self>) -> QString {
        self.hex(|| Ok(ua::msg_tag().to_vec()))
    }
    pub fn purpose_tag(self: Pin<&mut Self>, purpose: &QString) -> QString {
        self.hex(|| Ok(from_ua(ua::purpose_tag(&s(purpose)))?.to_vec()))
    }
    pub fn ua_of(self: Pin<&mut Self>, kind: i32, key_data: &QString) -> QString {
        self.hex(|| Ok(from_ua(ua::ua_of(k(kind)?, &key(key_data)?))?.to_vec()))
    }
    pub fn derive_ua(self: Pin<&mut Self>, kind: i32, key_data: &QString, hedera_native: bool) -> QString {
        self.hex(|| Ok(from_ua(ua::derive_ua(k(kind)?, &key(key_data)?, hedera_native))?.to_vec()))
    }
    pub fn native_id(self: Pin<&mut Self>, kind: i32, raw: &QString) -> QString {
        self.hex(|| Ok(from_ua(ua::native_id(k(kind)?, &key(raw)?))?.to_vec()))
    }
    pub fn key_hash_of(self: Pin<&mut Self>, kind: i32, key_data: &QString) -> QString {
        QString::from(&self.run(|| Ok(from_ua(ua::key_hash_of(k(kind)?, &key(key_data)?))?.map(|h| hx(&h)).unwrap_or_default())))
    }
    pub fn validate_key_data(self: Pin<&mut Self>, kind: i32, key_data: &QString, hedera_native: bool) -> bool {
        self.run(|| from_ua(ua::validate_key_data(k(kind)?, &key(key_data)?, hedera_native)).map(|_| true))
    }
    pub fn in_native_space(self: Pin<&mut Self>, id: &QString) -> bool {
        self.run(|| Ok(ua::in_native_space(&fixed(id)?)))
    }
    pub fn is_native(self: Pin<&mut Self>, kind: i32) -> bool {
        self.run(|| Ok(ua::is_native(k(kind)?)))
    }
    pub fn is_zether(self: Pin<&mut Self>, kind: i32) -> bool {
        self.run(|| Ok(ua::is_zether(k(kind)?)))
    }
    pub fn is_signing(self: Pin<&mut Self>, kind: i32) -> bool {
        self.run(|| Ok(ua::is_signing(k(kind)?)))
    }
    pub fn is_member(self: Pin<&mut Self>, kind: i32, hedera_native: bool) -> bool {
        self.run(|| Ok(ua::is_member(k(kind)?, hedera_native)))
    }
    pub fn ua_message(self: Pin<&mut Self>, kind: i32, purpose: &QString, digest: &QString) -> QString {
        self.hex(|| Ok(from_ua(ua::ua_message(k(kind)?, &fixed(purpose)?, &fixed(digest)?))?.to_vec()))
    }
    pub fn chain_key_hash(self: Pin<&mut Self>, chain_id: f64) -> QString {
        self.hex(|| Ok(ua::chain_key_hash(id(chain_id)?).to_vec()))
    }
    pub fn pop_digest(self: Pin<&mut Self>, chain_id: f64, chain_uid: &QString, registry: &QString, ua: &QString, auth_ref: &QString) -> QString {
        self.hex(|| Ok(ua::pop_digest(id(chain_id)?, &fixed(chain_uid)?, &fixed(registry)?, &fixed(ua)?, &fixed(auth_ref)?).to_vec()))
    }
    pub fn ua_auth_domain_separator(self: Pin<&mut Self>, generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString) -> QString {
        self.hex(|| Ok(ua::ua_auth_domain_separator(&domain(generation, chain_id, registry, chain_uid)?).to_vec()))
    }
    pub fn ua_auth_digest(self: Pin<&mut Self>, generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString, ua: &QString, purpose: &QString, digest: &QString) -> QString {
        self.hex(|| {
            let d = domain(generation, chain_id, registry, chain_uid)?;
            Ok(ua::ua_auth_digest(&d, &fixed(ua)?, &fixed(purpose)?, &fixed(digest)?).to_vec())
        })
    }
    pub fn member_digest(self: Pin<&mut Self>, structure_ua: &QString, ua_msg: &QString) -> QString {
        self.hex(|| Ok(ua::member_digest(&fixed(structure_ua)?, &fixed(ua_msg)?).to_vec()))
    }
    pub fn canonical_id(self: Pin<&mut Self>, text: &QString) -> QString {
        QString::from(&self.run(|| from_ua(ua::canonical_id(&s(text)))))
    }
    pub fn encode_msig(self: Pin<&mut Self>, threshold: i32, members: &QString) -> QString {
        self.hex(|| {
            let v: Vec<(i32, String, i32)> = serde_json::from_str(&s(members)).map_err(|_| ARG)?;
            let m = v
                .iter()
                .map(|(kd, idh, w)| Ok((k(*kd)?, fixed::<32>(&QString::from(idh))?, u16::try_from(*w).map_err(|_| ARG)?)))
                .collect::<Res<Vec<_>>>()?;
            Ok(ua::encode_msig(u16::try_from(threshold).map_err(|_| ARG)?, &m))
        })
    }
}
