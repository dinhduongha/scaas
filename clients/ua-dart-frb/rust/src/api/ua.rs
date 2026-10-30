// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! flutter_rust_bridge surface over `scaas-ua`. Every function is synchronous; failures are a `UAError { code, reason }`
//! (a Dart exception). Byte data is `Uint8List` (`Vec<u8>`), ids and digests are fixed-size arrays.
use flutter_rust_bridge::frb;

/// `code` is one of the shared codes (the seven of the vector files plus `UAPqzHolder`, `UAKemHolder`, `UAKemVersion`, `UAKemKeyLength`, `UAKemScheme`, `UAPqzPopHash`, `UAPqzKeySet`) (`UAKeyData`, `UAKindUnknown`, ...); `reason` is the label after `UAKeyData: ` (empty for every other code),
/// as in the cxx and pure-Dart libraries.
///
/// Integers are `i64` so a Dart value cannot wrap at the Rust width: a kind outside 0..=0xFFFF is `UAKindUnknown`; a chain
/// id, generation, threshold or weight outside its range (chain id < 0, generation > u32, ...) is `UAArgument`.
#[derive(Debug, Clone)]
pub struct UAError {
    pub code: String,
    pub reason: String,
}

impl From<scaas_ua::UAError> for UAError {
    fn from(e: scaas_ua::UAError) -> Self {
        UAError { code: e.code().into(), reason: match &e {
            scaas_ua::UAError::KeyData(r) => r.to_string(),
            _ => String::new(),
        },
        }
    }
}

type R<T> = Result<T, UAError>;

fn arg() -> UAError {
    UAError { code: "UAArgument".into(), reason: String::new() }
}
fn k(kind: i64) -> R<u16> {
    u16::try_from(kind).map_err(|_| UAError { code: "UAKindUnknown".into(), reason: String::new() })
}
fn n<T: TryFrom<i64>>(v: i64) -> R<T> {
    T::try_from(v).map_err(|_| arg())
}

pub struct KindInfo {
    pub kind: u16,
    pub name: String,
    pub native: bool,
    /// Empty = variable length.
    pub lengths: Vec<u32>,
    pub group: Option<String>,
}

/// The registry's EIP-712 domain (`generation` 0..=u32::MAX, `chain_id` >= 0, else `UAArgument`).
pub struct UaDomain {
    pub generation: i64,
    pub chain_id: i64,
    pub registry: [u8; 20],
    pub chain_uid: [u8; 32],
}

impl TryFrom<UaDomain> for scaas_ua::Domain {
    type Error = UAError;
    fn try_from(d: UaDomain) -> R<Self> {
        Ok(scaas_ua::Domain { generation: n(d.generation)?, chain_id: n(d.chain_id)?, registry: d.registry, chain_uid: d.chain_uid })
    }
}

#[frb(sync)]
pub fn kind_info(kind: i64) -> R<KindInfo> {
    let k = scaas_ua::kind_info(k(kind)?)?;
    Ok(KindInfo {
        kind: k.kind,
        name: k.name.into(),
        native: k.native,
        lengths: k.lengths.iter().map(|l| *l as u32).collect(),
        group: k.group.map(Into::into),
    })
}
#[frb(sync)]
pub fn tag(kind: i64) -> R<[u8; 32]> {
    Ok(scaas_ua::tag(k(kind)?)?)
}
#[frb(sync)]
pub fn kind_tag_string(kind: i64) -> R<String> {
    Ok(scaas_ua::kind_tag_string(k(kind)?)?)
}
#[frb(sync)]
pub fn group_tag(group: String) -> Option<[u8; 32]> {
    scaas_ua::group_tag(&group)
}
#[frb(sync)]
pub fn group_tag_string(group: String) -> Option<String> {
    scaas_ua::group_tag_string(&group)
}
#[frb(sync)]
pub fn msg_tag() -> [u8; 32] {
    scaas_ua::msg_tag()
}
#[frb(sync)]
pub fn purpose_tag(purpose: String) -> R<[u8; 32]> {
    Ok(scaas_ua::purpose_tag(&purpose)?)
}
/// The tag of a purpose version: every purpose is v1, `pop` is also v2 (the portable PoP); any other pair is `UAPurposeUnknown`
/// (a version outside u32 is `UAArgument`).
#[frb(sync)]
pub fn purpose_tag_v(purpose: String, version: i64) -> R<[u8; 32]> {
    Ok(scaas_ua::purpose_tag_v(&purpose, n(version)?)?)
}
#[frb(sync)]
pub fn kem_record_tag() -> [u8; 32] {
    scaas_ua::ua8::kem_record_tag()
}
#[frb(sync)]
pub fn pqz_key_record_tag() -> [u8; 32] {
    scaas_ua::ua8::pqz_key_record_tag()
}
#[frb(sync)]
pub fn ua_of(kind: i64, key_data: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::ua_of(k(kind)?, &key_data)?)
}
#[frb(sync)]
pub fn derive_ua(kind: i64, key_data: Vec<u8>, hedera_native: bool) -> R<[u8; 32]> {
    Ok(scaas_ua::derive_ua(k(kind)?, &key_data, hedera_native)?)
}
#[frb(sync)]
pub fn native_id(kind: i64, raw: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::native_id(k(kind)?, &raw)?)
}
#[frb(sync)]
pub fn key_hash_of(kind: i64, key_data: Vec<u8>) -> R<Option<[u8; 32]>> {
    Ok(scaas_ua::key_hash_of(k(kind)?, &key_data)?)
}
#[frb(sync)]
pub fn validate_key_data(kind: i64, key_data: Vec<u8>, hedera_native: bool) -> R<()> {
    Ok(scaas_ua::validate_key_data(k(kind)?, &key_data, hedera_native)?)
}
#[frb(sync)]
pub fn in_native_space(id: [u8; 32]) -> bool {
    scaas_ua::in_native_space(&id)
}
// The predicates are false for a kind outside 0..=0xFFFF, like any unknown kind.
#[frb(sync)]
pub fn is_native(kind: i64) -> bool {
    k(kind).is_ok_and(scaas_ua::is_native)
}
#[frb(sync)]
pub fn is_zether(kind: i64) -> bool {
    k(kind).is_ok_and(scaas_ua::is_zether)
}
#[frb(sync)]
pub fn is_pqz_holder(kind: i64) -> bool {
    k(kind).is_ok_and(scaas_ua::is_pqz_holder)
}
/// An `msig` whose members of kinds outside 0x0130-0x0133 weigh less than its threshold (`UAKeyData` on malformed data).
#[frb(sync)]
pub fn msig_pqz_eligible(key_data: Vec<u8>) -> R<bool> {
    Ok(scaas_ua::msig_pqz_eligible(&key_data)?)
}
#[frb(sync)]
pub fn is_signing(kind: i64) -> bool {
    k(kind).is_ok_and(scaas_ua::is_signing)
}
#[frb(sync)]
pub fn is_member(kind: i64, hedera_native: bool) -> bool {
    k(kind).is_ok_and(|k| scaas_ua::is_member(k, hedera_native))
}
#[frb(sync)]
pub fn ua_message(kind: i64, purpose: [u8; 32], digest: [u8; 32]) -> R<[u8; 32]> {
    Ok(scaas_ua::ua_message(k(kind)?, &purpose, &digest)?)
}
#[frb(sync)]
pub fn chain_key_hash(chain_id: i64) -> R<[u8; 32]> {
    Ok(scaas_ua::chain_key_hash(n(chain_id)?))
}
/// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqz_key_hash ‖ kem_record_hash)`, each hash 32 zero bytes when absent (UA-8 P1: no chain).
#[frb(sync)]
pub fn portable_pop_digest(ua: [u8; 32], pqz_key_hash: [u8; 32], kem_record_hash: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::portable_pop_digest(&ua, &pqz_key_hash, &kem_record_hash)
}
/// `keccak256(portable_pop_digest ‖ pqz_pop_hash)`: what the signer's `pop` signs under `ua_message(kind, POP_V2, ·)`.
#[frb(sync)]
pub fn registration_digest(portable: [u8; 32], pqz_pop_hash: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::registration_digest(&portable, &pqz_pop_hash)
}
/// A KEM record attribute `(version >= 1, 1,601-byte key: scheme byte 1 first)`; `None`, or `(0, [])`, = absent. `version` is a `u64` (a Dart
/// `BigInt`: 1 ... 2^64 - 1).
pub struct KemRecord {
    pub version: u64,
    pub pk: Vec<u8>,
}
fn kem(k: &Option<KemRecord>) -> Option<(u64, &[u8])> {
    k.as_ref().map(|k| (k.version, k.pk.as_slice()))
}
/// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kem_pk))` (`UAKemVersion` for 0, `UAKemScheme` unless the first byte is 1, `UAKemKeyLength` unless 1,601 bytes).
#[frb(sync)]
pub fn kem_record_digest(ua: [u8; 32], version: u64, kem_pk: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::ua8::kem_record_digest(&ua, version, &kem_pk)?)
}
/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`.
#[frb(sync)]
pub fn kem_record_message(kind: i64, ua: [u8; 32], version: u64, kem_pk: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::ua8::kem_record_message(k(kind)?, &ua, version, &kem_pk)?)
}
/// An empty proof hash is absent; another length than 32 is `UAPqzPopHash`.
fn hash(h: &Option<Vec<u8>>) -> R<Option<[u8; 32]>> {
    match h.as_deref() {
        None | Some([]) => Ok(None),
        Some(b) => Ok(Some(b.try_into().map_err(|_| UAError { code: "UAPqzPopHash".into(), reason: String::new() })?)),
    }
}
/// The portable PoP of a registration (UA-8 P1, P2). `message = ua_message(kind, POP_V2, registration_digest)`: what the signer's
/// `pop` signs (every kind). `member_digest` (an `msig` only) is what each member signs under `member`; a code-less native
/// member signs `personal_sign_digest(member_digest)` (ruling C7).
pub struct HolderPop {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub kem_record_hash: [u8; 32],
    pub portable_pop_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    pub message: [u8; 32],
    pub member_digest: Option<[u8; 32]>,
}
/// The portable PoP message of a registration. Attributes: `pqz_key` with its proof `pqz_pop` (or only its hash `pqz_pop_hash`;
/// null / empty = absent) and the initial KEM record; only holders carry them (`UAPqzHolder`, `UAKemHolder`; an `msig` needs
/// `key_data` to show it is PQ-eligible); a PQZ key always comes with its proof hash and only with it (`UAPqzPopHash`).
#[frb(sync)]
pub fn holder_pop_message(
    kind: i64,
    ua: [u8; 32],
    key_data: Vec<u8>,
    pqz_key: Option<Vec<u8>>,
    pqz_pop: Option<Vec<u8>>,
    pqz_pop_hash: Option<Vec<u8>>,
    kem_record: Option<KemRecord>,
) -> R<HolderPop> {
    let h = hash(&pqz_pop_hash)?;
    let r = scaas_ua::holder_pop_message(k(kind)?, &ua, &key_data, pqz_key.as_deref(), pqz_pop.as_deref(), h.as_ref(), kem(&kem_record))?;
    Ok(HolderPop {
        pqz_key_hash: r.pqz_key_hash,
        pqz_pop_hash: r.pqz_pop_hash,
        kem_record_hash: r.kem_record_hash,
        portable_pop_digest: r.portable_pop_digest,
        registration_digest: r.registration_digest,
        message: r.message,
        member_digest: r.member_digest,
    })
}
/// The message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_pop_digest(ua, key_hash(pqz_key), kem_record_hash))`.
#[frb(sync)]
pub fn pqz_reg_message(ua: [u8; 32], pqz_key: Vec<u8>, kem_record: Option<KemRecord>) -> R<[u8; 32]> {
    Ok(scaas_ua::pqz_reg_message(&ua, &pqz_key, kem(&kem_record))?)
}
/// `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqz_key_hash)`: what a later PQZ key's `R_REG` proves over.
#[frb(sync)]
pub fn pqz_key_digest(ua: [u8; 32], pqz_key_hash: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::pqz_key_digest(&ua, &pqz_key_hash)
}
/// `keccak256(pqz_key_digest ‖ pqz_pop_hash)`: what `setPqzKey`'s signature signs under `ua_message(kind, PURPOSE_PQZ_KEY, ·)`.
#[frb(sync)]
pub fn pqz_key_record_digest(key_digest: [u8; 32], pqz_pop_hash: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::pqz_key_record_digest(&key_digest, &pqz_pop_hash)
}
/// The PQZ key record of `setPqzKey` (ruling A1-I1): `message` is what the UA signs, `pqz_reg_message` what the key's `R_REG`
/// proves over; `member_digest` as in [`HolderPop`].
pub struct PqzKeyRecord {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub pqz_key_digest: [u8; 32],
    pub record_digest: [u8; 32],
    pub message: [u8; 32],
    pub pqz_reg_message: [u8; 32],
    pub member_digest: Option<[u8; 32]>,
}
/// The signed, portable, write-once PQZ key record: accepted only by a registration without a PQZ key (`already_set` = it has
/// one: `UAPqzKeySet`). The holder rules of [`holder_pop_message`]; the key and its proof (or hash) are both required.
#[frb(sync)]
pub fn pqz_key_record_message(
    kind: i64,
    ua: [u8; 32],
    key_data: Vec<u8>,
    pqz_key: Vec<u8>,
    pqz_pop: Option<Vec<u8>>,
    pqz_pop_hash: Option<Vec<u8>>,
    already_set: bool,
) -> R<PqzKeyRecord> {
    let h = hash(&pqz_pop_hash)?;
    let r = scaas_ua::ua8::pqz_key_record_message(k(kind)?, &ua, &key_data, &pqz_key, pqz_pop.as_deref(), h.as_ref(), already_set)?;
    Ok(PqzKeyRecord {
        pqz_key_hash: r.pqz_key_hash,
        pqz_pop_hash: r.pqz_pop_hash,
        pqz_key_digest: r.pqz_key_digest,
        record_digest: r.record_digest,
        message: r.message,
        pqz_reg_message: r.pqz_reg_message,
        member_digest: r.member_digest,
    })
}
/// EIP-191 `personal_sign` of a 32-byte digest: `keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ digest)`. A code-less native
/// (EOA) `msig` member signs it over the `member_digest` of a portable record only (POP_V2, KEM, PQZ_KEY; ruling C7); every
/// other purpose stays UAAuth.
#[frb(sync)]
pub fn personal_sign_digest(digest: [u8; 32]) -> [u8; 32] {
    scaas_ua::personal_sign_digest(&digest)
}
/// POP_V2, KEM, PQZ_KEY: the only purposes a code-less native `msig` member signs by `personal_sign`.
#[frb(sync)]
pub fn is_portable_purpose(tag: [u8; 32]) -> bool {
    scaas_ua::ua8::is_portable_purpose(&tag)
}
#[frb(sync)]
pub fn ua_auth_domain_separator(domain: UaDomain) -> R<[u8; 32]> {
    Ok(scaas_ua::ua_auth_domain_separator(&domain.try_into()?))
}
#[frb(sync)]
pub fn ua_auth_digest(domain: UaDomain, ua: [u8; 32], purpose: [u8; 32], digest: [u8; 32]) -> R<[u8; 32]> {
    Ok(scaas_ua::ua_auth_digest(&domain.try_into()?, &ua, &purpose, &digest))
}
#[frb(sync)]
pub fn member_digest(structure_ua: [u8; 32], ua_msg: [u8; 32]) -> [u8; 32] {
    scaas_ua::member_digest(&structure_ua, &ua_msg)
}
#[frb(sync)]
pub fn canonical_id(text: String) -> R<String> {
    Ok(scaas_ua::canonical_id(&text)?)
}
/// Members are `(kind, id, weight)`; a kind outside 0..=0xFFFF is `UAKindUnknown`, a threshold or weight outside u16 (or
/// more than 65535 members) is `UAArgument`.
#[frb(sync)]
pub fn encode_msig(threshold: i64, members: Vec<(i64, [u8; 32], i64)>) -> R<Vec<u8>> {
    if members.len() > u16::MAX as usize {
        return Err(arg());
    }
    let ms = members.into_iter().map(|(kd, id, w)| Ok((k(kd)?, id, n(w)?))).collect::<R<Vec<_>>>()?;
    Ok(scaas_ua::encode_msig(n(threshold)?, &ms))
}
