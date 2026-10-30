// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
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
        /// A purpose tag of a version: every purpose is 1, `pop` is also 2 (the portable PoP).
        #[qinvokable] #[cxx_name = "purposeTagV"] fn purpose_tag_v(self: Pin<&mut Self>, purpose: &QString, version: i32) -> QString;
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
        #[qinvokable] #[cxx_name = "isPqzHolder"] fn is_pqz_holder(self: Pin<&mut Self>, kind: i32) -> bool;
        /// false on failure (see `lastError`) as well as for a non-eligible `msig`.
        #[qinvokable] #[cxx_name = "msigPqzEligible"] fn msig_pqz_eligible(self: Pin<&mut Self>, key_data: &QString) -> bool;
        #[qinvokable] #[cxx_name = "isSigning"] fn is_signing(self: Pin<&mut Self>, kind: i32) -> bool;
        #[qinvokable] #[cxx_name = "isMember"] fn is_member(self: Pin<&mut Self>, kind: i32, hedera_native: bool) -> bool;
        #[qinvokable] #[cxx_name = "uaMessage"]
        fn ua_message(self: Pin<&mut Self>, kind: i32, purpose: &QString, digest: &QString) -> QString;
        /// `chain_id` is a JS number: exact up to 2^53.
        #[qinvokable] #[cxx_name = "chainKeyHash"] fn chain_key_hash(self: Pin<&mut Self>, chain_id: f64) -> QString;
        /// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`; a hash is 32 zero bytes when absent.
        #[qinvokable] #[cxx_name = "portablePopDigest"]
        fn portable_pop_digest(self: Pin<&mut Self>, ua: &QString, pqz_key_hash: &QString, kem_record_hash: &QString) -> QString;
        #[qinvokable] #[cxx_name = "registrationDigest"]
        fn registration_digest(self: Pin<&mut Self>, portable: &QString, pqz_pop_hash: &QString) -> QString;
        /// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kemPk))`; `version` is a JS number (exact up to 2^53).
        #[qinvokable] #[cxx_name = "kemRecordDigest"]
        fn kem_record_digest(self: Pin<&mut Self>, ua: &QString, version: f64, kem_pk: &QString) -> QString;
        /// JSON `{pqzKeyHash, pqzPopHash, kemRecordHash, portablePopDigest, registrationDigest, message[, memberDigest]}`.
        /// `key_data` is needed for an `msig` ("0x" otherwise); `pqz_key` / `pqz_pop` "" or "0x" = absent; `kem_version` 0 with
        /// an empty `kem_pk` = no KEM record. A key for a non-holder is `UAPqzHolder` / `UAKemHolder`.
        #[qinvokable] #[cxx_name = "holderPopMessage"]
        fn holder_pop_message(self: Pin<&mut Self>, kind: i32, ua: &QString, key_data: &QString, pqz_key: &QString, pqz_pop: &QString, kem_version: f64, kem_pk: &QString) -> QString;
        /// As `holderPopMessage`, with only the proof's hash (`pqz_pop_hash` 32 bytes, "0x" = absent) next to or instead of the proof bytes.
        #[qinvokable] #[cxx_name = "holderPopMessageH"]
        fn holder_pop_message_h(self: Pin<&mut Self>, kind: i32, ua: &QString, key_data: &QString, pqz_key: &QString, pqz_pop: &QString, pqz_pop_hash: &QString, kem_version: f64, kem_pk: &QString) -> QString;
        /// The `setPqzKey` record (ruling A1-I1), JSON `{pqzKeyHash, pqzPopHash, pqzKeyDigest, recordDigest, message, pqzRegMessage[, memberDigest]}`:
        /// `message` is what the UA signs, `pqzRegMessage` what the key's `R_REG` proves over. `pqz_pop` bytes and / or `pqz_pop_hash`
        /// ("0x" = absent); `already_set` = the registration has a PQZ key (`UAPqzKeySet`).
        #[qinvokable] #[cxx_name = "pqzKeyRecordMessage"]
        fn pqz_key_record_message(self: Pin<&mut Self>, kind: i32, ua: &QString, key_data: &QString, pqz_key: &QString, pqz_pop: &QString, pqz_pop_hash: &QString, already_set: bool) -> QString;
        /// What the PQZ key's `R_REG` proves over.
        #[qinvokable] #[cxx_name = "pqzRegMessage"]
        fn pqz_reg_message(self: Pin<&mut Self>, ua: &QString, pqz_key: &QString, kem_version: f64, kem_pk: &QString) -> QString;
        /// `UAMessage(kind, PURPOSE_KEM, kemRecordDigest(ua, version, kemPk))`: what the UA signs for `setKemKey`.
        #[qinvokable] #[cxx_name = "kemRecordMessage"]
        fn kem_record_message(self: Pin<&mut Self>, kind: i32, ua: &QString, version: f64, kem_pk: &QString) -> QString;
        #[qinvokable] #[cxx_name = "kemRecordTag"] fn kem_record_tag(self: Pin<&mut Self>) -> QString;
        #[qinvokable] #[cxx_name = "pqzKeyRecordTag"] fn pqz_key_record_tag(self: Pin<&mut Self>) -> QString;
        /// `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash)`: what a later PQZ key's `R_REG` proves over.
        #[qinvokable] #[cxx_name = "pqzKeyDigest"]
        fn pqz_key_digest(self: Pin<&mut Self>, ua: &QString, pqz_key_hash: &QString) -> QString;
        /// `keccak256(pqzKeyDigest ‖ pqzPopHash)`: what `setPqzKey`'s signature signs under `UAMessage(kind, PURPOSE_PQZ_KEY, ·)`.
        #[qinvokable] #[cxx_name = "pqzKeyRecordDigest"]
        fn pqz_key_record_digest(self: Pin<&mut Self>, key_digest: &QString, pqz_pop_hash: &QString) -> QString;
        /// EIP-191 `personal_sign` of a 32-byte digest: what a code-less native `msig` member signs over the `memberDigest`
        /// of a portable record (POP_V2, KEM, PQZ_KEY; ruling C7).
        #[qinvokable] #[cxx_name = "personalSignDigest"]
        fn personal_sign_digest(self: Pin<&mut Self>, digest: &QString) -> QString;
        /// True for the three portable purposes (POP_V2, KEM, PQZ_KEY); false (see `lastError`) for a tag that is not 32 bytes.
        #[qinvokable] #[cxx_name = "isPortablePurpose"]
        fn is_portable_purpose(self: Pin<&mut Self>, tag: &QString) -> bool;
        #[qinvokable] #[cxx_name = "uaAuthDomainSeparator"]
        fn ua_auth_domain_separator(self: Pin<&mut Self>, generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString) -> QString;
        #[qinvokable] #[cxx_name = "uaAuthDigest"]
        fn ua_auth_digest(self: Pin<&mut Self>, generation: i32, chain_id: f64, registry: &QString, chain_uid: &QString, ua: &QString, purpose: &QString, digest: &QString) -> QString;
        #[qinvokable] #[cxx_name = "memberDigest"]
        fn member_digest(self: Pin<&mut Self>, structure_ua: &QString, ua_msg: &QString) -> QString;
        #[qinvokable] #[cxx_name = "canonicalId"] fn canonical_id(self: Pin<&mut Self>, text: &QString) -> QString;
        /// CTR-MTX-26: `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`; `salt` 32 bytes.
        #[qinvokable] #[cxx_name = "metaPayId"] fn meta_pay_id(self: Pin<&mut Self>, salt: &QString, meta: &QString) -> QString;
        /// CTR-MTX-03: `keccak256("scaas.pay.lane" ‖ p)` as 32 bytes hex (the on-chain `uint256`).
        #[qinvokable] #[cxx_name = "payLane"] fn pay_lane(self: Pin<&mut Self>, p: &QString) -> QString;
        /// CTR-MTX-27 (EVM): `keccak256("scaas.relayfee" ‖ uint256 chainId ‖ target ‖ keccak256(callData))`; `chain_id`
        /// is a JS number (exact up to 2^53), `target` 20 bytes.
        #[qinvokable] #[cxx_name = "relayRef"]
        fn relay_ref(self: Pin<&mut Self>, chain_id: f64, target: &QString, call_data: &QString) -> QString;
        /// near-algorand T18: `sha256(op)`, `op` = the full MetaOp v1 encoding (label ‖ Borsh / ARC-4).
        #[qinvokable] #[cxx_name = "nearDigest"] fn near_digest(self: Pin<&mut Self>, op: &QString) -> QString;
        /// NEAR relay-fee `ref`; `network` 32 bytes, `target` = `u8 len ‖ account id`, `salt` 32 bytes.
        #[qinvokable] #[cxx_name = "nearRelayRef"]
        fn near_relay_ref(self: Pin<&mut Self>, network: &QString, target: &QString, call: &QString, salt: &QString) -> QString;
        #[qinvokable] #[cxx_name = "algorandDigest"] fn algorand_digest(self: Pin<&mut Self>, op: &QString) -> QString;
        /// Algorand relay-fee `ref`; `network` = GenesisHash 32 bytes, `target` = the target app address 32 bytes.
        #[qinvokable] #[cxx_name = "algorandRelayRef"]
        fn algorand_relay_ref(self: Pin<&mut Self>, network: &QString, target: &QString, call: &QString, salt: &QString) -> QString;
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
/// A proof hash: "" or "0x" = absent, else exactly 32 bytes (`UAPqzPopHash` otherwise, as every other UA library).
fn optional_hash(q: &QString) -> Res<Option<[u8; 32]>> {
    let b = bytes(q)?;
    if b.is_empty() { Ok(None) } else { b.try_into().map(Some).map_err(|_| "UAPqzPopHash") }
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
    pub fn purpose_tag_v(self: Pin<&mut Self>, purpose: &QString, version: i32) -> QString {
        self.hex(|| Ok(from_ua(ua::purpose_tag_v(&s(purpose), u32::try_from(version).map_err(|_| ARG)?))?.to_vec()))
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
    pub fn is_pqz_holder(self: Pin<&mut Self>, kind: i32) -> bool {
        self.run(|| Ok(ua::is_pqz_holder(k(kind)?)))
    }
    pub fn msig_pqz_eligible(self: Pin<&mut Self>, key_data: &QString) -> bool {
        self.run(|| from_ua(ua::msig_pqz_eligible(&key(key_data)?)))
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
    pub fn portable_pop_digest(self: Pin<&mut Self>, ua: &QString, pqz_key_hash: &QString, kem_record_hash: &QString) -> QString {
        self.hex(|| Ok(ua::ua8::portable_pop_digest(&fixed(ua)?, &fixed(pqz_key_hash)?, &fixed(kem_record_hash)?).to_vec()))
    }
    pub fn registration_digest(self: Pin<&mut Self>, portable: &QString, pqz_pop_hash: &QString) -> QString {
        self.hex(|| Ok(ua::ua8::registration_digest(&fixed(portable)?, &fixed(pqz_pop_hash)?).to_vec()))
    }
    pub fn kem_record_digest(self: Pin<&mut Self>, ua: &QString, version: f64, kem_pk: &QString) -> QString {
        self.hex(|| Ok(from_ua(ua::ua8::kem_record_digest(&fixed(ua)?, id(version)?, &bytes(kem_pk)?))?.to_vec()))
    }
    pub fn holder_pop_message(self: Pin<&mut Self>, kind: i32, ua: &QString, key_data: &QString, pqz_key: &QString, pqz_pop: &QString, kem_version: f64, kem_pk: &QString) -> QString {
        self.holder_pop_message_h(kind, ua, key_data, pqz_key, pqz_pop, &QString::from("0x"), kem_version, kem_pk)
    }
    pub fn holder_pop_message_h(self: Pin<&mut Self>, kind: i32, ua: &QString, key_data: &QString, pqz_key: &QString, pqz_pop: &QString, pqz_pop_hash: &QString, kem_version: f64, kem_pk: &QString) -> QString {
        QString::from(&self.run(|| {
            let (pk, pop, kpk) = (key(pqz_key)?, bytes(pqz_pop)?, bytes(kem_pk)?);
            let hash = optional_hash(pqz_pop_hash)?;
            let kem = (id(kem_version)? != 0 || !kpk.is_empty()).then(|| (id(kem_version).unwrap_or(0), kpk));
            let h = from_ua(ua::ua8::holder_pop_message(
                k(kind)?, &fixed(ua)?, &key(key_data)?, Some(&pk[..]), Some(&pop[..]), hash.as_ref(), kem.as_ref().map(|(v, p)| (*v, &p[..])),
            ))?;
            let mut o = serde_json::json!({
                "pqzKeyHash": hx(&h.pqz_key_hash), "pqzPopHash": hx(&h.pqz_pop_hash), "kemRecordHash": hx(&h.kem_record_hash),
                "portablePopDigest": hx(&h.portable_pop_digest), "registrationDigest": hx(&h.registration_digest), "message": hx(&h.message),
            });
            if let Some(m) = h.member_digest {
                o["memberDigest"] = hx(&m).into();
            }
            Ok(o.to_string())
        }))
    }
    pub fn pqz_key_record_message(self: Pin<&mut Self>, kind: i32, ua: &QString, key_data: &QString, pqz_key: &QString, pqz_pop: &QString, pqz_pop_hash: &QString, already_set: bool) -> QString {
        QString::from(&self.run(|| {
            let (pop, hash) = (bytes(pqz_pop)?, optional_hash(pqz_pop_hash)?);
            let r = from_ua(ua::ua8::pqz_key_record_message(
                k(kind)?, &fixed(ua)?, &key(key_data)?, &key(pqz_key)?, Some(&pop[..]), hash.as_ref(), already_set,
            ))?;
            let mut o = serde_json::json!({
                "pqzKeyHash": hx(&r.pqz_key_hash), "pqzPopHash": hx(&r.pqz_pop_hash), "pqzKeyDigest": hx(&r.pqz_key_digest),
                "recordDigest": hx(&r.record_digest), "message": hx(&r.message), "pqzRegMessage": hx(&r.pqz_reg_message),
            });
            if let Some(m) = r.member_digest {
                o["memberDigest"] = hx(&m).into();
            }
            Ok(o.to_string())
        }))
    }
    pub fn pqz_reg_message(self: Pin<&mut Self>, ua: &QString, pqz_key: &QString, kem_version: f64, kem_pk: &QString) -> QString {
        self.hex(|| {
            let kpk = bytes(kem_pk)?;
            let kem = (id(kem_version)? != 0 || !kpk.is_empty()).then(|| (id(kem_version).unwrap_or(0), kpk));
            Ok(from_ua(ua::ua8::pqz_reg_message(&fixed(ua)?, &key(pqz_key)?, kem.as_ref().map(|(v, p)| (*v, &p[..]))))?.to_vec())
        })
    }
    pub fn kem_record_message(self: Pin<&mut Self>, kind: i32, ua: &QString, version: f64, kem_pk: &QString) -> QString {
        self.hex(|| Ok(from_ua(ua::ua8::kem_record_message(k(kind)?, &fixed(ua)?, id(version)?, &bytes(kem_pk)?))?.to_vec()))
    }
    pub fn kem_record_tag(self: Pin<&mut Self>) -> QString {
        self.hex(|| Ok(ua::ua8::kem_record_tag().to_vec()))
    }
    pub fn pqz_key_record_tag(self: Pin<&mut Self>) -> QString {
        self.hex(|| Ok(ua::ua8::pqz_key_record_tag().to_vec()))
    }
    pub fn pqz_key_digest(self: Pin<&mut Self>, ua: &QString, pqz_key_hash: &QString) -> QString {
        self.hex(|| Ok(ua::ua8::pqz_key_digest(&fixed(ua)?, &fixed(pqz_key_hash)?).to_vec()))
    }
    pub fn pqz_key_record_digest(self: Pin<&mut Self>, key_digest: &QString, pqz_pop_hash: &QString) -> QString {
        self.hex(|| Ok(ua::ua8::pqz_key_record_digest(&fixed(key_digest)?, &fixed(pqz_pop_hash)?).to_vec()))
    }
    pub fn personal_sign_digest(self: Pin<&mut Self>, digest: &QString) -> QString {
        self.hex(|| Ok(ua::ua8::personal_sign_digest(&fixed(digest)?).to_vec()))
    }
    pub fn is_portable_purpose(self: Pin<&mut Self>, tag: &QString) -> bool {
        self.run(|| Ok(ua::ua8::is_portable_purpose(&fixed(tag)?)))
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
    pub fn meta_pay_id(self: Pin<&mut Self>, salt: &QString, meta: &QString) -> QString {
        self.hex(|| Ok(ua::meta_pay_id(&fixed(salt)?, &bytes(meta)?).to_vec()))
    }
    pub fn pay_lane(self: Pin<&mut Self>, p: &QString) -> QString {
        self.hex(|| Ok(ua::pay_lane(&fixed(p)?).to_vec()))
    }
    pub fn relay_ref(self: Pin<&mut Self>, chain_id: f64, target: &QString, call_data: &QString) -> QString {
        self.hex(|| Ok(ua::relay_ref(id(chain_id)?, &fixed(target)?, &bytes(call_data)?).to_vec()))
    }
    pub fn near_digest(self: Pin<&mut Self>, op: &QString) -> QString {
        self.hex(|| Ok(ua::near::metaop_digest(&bytes(op)?).to_vec()))
    }
    pub fn near_relay_ref(self: Pin<&mut Self>, network: &QString, target: &QString, call: &QString, salt: &QString) -> QString {
        self.hex(|| Ok(ua::near::relay_ref(&fixed(network)?, &bytes(target)?, &bytes(call)?, &fixed(salt)?).to_vec()))
    }
    pub fn algorand_digest(self: Pin<&mut Self>, op: &QString) -> QString {
        self.hex(|| Ok(ua::algorand::metaop_digest(&bytes(op)?).to_vec()))
    }
    pub fn algorand_relay_ref(self: Pin<&mut Self>, network: &QString, target: &QString, call: &QString, salt: &QString) -> QString {
        self.hex(|| Ok(ua::algorand::relay_ref(&fixed(network)?, &fixed(target)?, &bytes(call)?, &fixed(salt)?).to_vec()))
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
