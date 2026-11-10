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

impl From<scaas_ua::json::JsonError> for UAError {
    fn from(e: scaas_ua::json::JsonError) -> Self {
        match e {
            scaas_ua::json::JsonError::Argument => arg(),
            scaas_ua::json::JsonError::Ua(e) => e.into(),
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

/// `governance_bits.json`'s row of `bit` as JSON, `{bit, name, type, sentences}` (spec 2026-11-02-governance §1.2): bits 0-27,
/// any other `UAArgument`.
#[frb(sync)]
pub fn governance_bit(bit: i64) -> R<String> {
    scaas_ua::governance_bit(n(bit)?).map(str::to_string).ok_or_else(arg)
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
/// An `msig` whose members of kinds outside 0x0130-0x0135 weigh less than its threshold (`UAKeyData` on malformed data); an `msig`
/// member is `UAMemberUnknown` here, [`msig_pqz_eligible_with`] reads its record.
#[frb(sync)]
pub fn msig_pqz_eligible(key_data: Vec<u8>) -> R<bool> {
    msig_pqz_eligible_with(key_data, String::new())
}
/// The `_with` forms take `inner`, the `msig` members' structures: `{id: keyData}` JSON as [`registration_args`]' `inner` ("" = none;
/// over 65,536 bytes, more than 16 entries or key data over 580 bytes is `UAArgument`). An `msig` member counts as PQ iff it is
/// PQ-eligible itself, read from its entry; a member without an entry, or an entry that holds an `msig` (two levels only), is
/// `UAMemberUnknown`.
#[frb(sync)]
pub fn msig_pqz_eligible_with(key_data: Vec<u8>, inner: String) -> R<bool> {
    let i = scaas_ua::json::inner_json(&inner)?;
    let l = scaas_ua::json::lookup(&i);
    Ok(scaas_ua::msig_pqz_eligible_with(&key_data, &l)?)
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
/// `keccak256(data)`: e.g. `memberSigHashOf`, the hash of a slot's `sig` or of an msig member's `abi.encode(InnerSig[])`.
#[frb(sync)]
pub fn keccak256(data: Vec<u8>) -> [u8; 32] {
    scaas_ua::keccak256(&data)
}
/// The portable EIP-712 domain separator `DS_P` (`EIP712Domain(string name,string version)` = ("SCaaS UA Portable", "1"), no
/// chain; typed-signing TS-D1): every portable digest is `keccak256(0x1901 ‖ DS_P ‖ hashStruct)`.
#[frb(sync)]
pub fn portable_domain_separator() -> [u8; 32] {
    scaas_ua::ua8::PORTABLE_DOMAIN_SEPARATOR
}
/// `hashStruct(UAKemRecord{ua, version, scheme, kemPkHash})`, the `kem` word of a portable record; `(0, [])` is the zero record
/// `UAKemRecord{ua, 0, 0, 0}` (no KEM record), `(0, key)` the `register` key's record (owner 2026-10-31), otherwise the rules
/// of [`kem_record_digest`].
#[frb(sync)]
pub fn kem_record_hash(ua: [u8; 32], version: u64, kem_pk: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::ua8::kem_record_hash(&ua, version, &kem_pk)?)
}
/// typed `UAPortableRecord{ua, kind, pqzKeyHash, kem}`: what `R_REG` proves over at `register`; a hash is 32 zero bytes when absent.
#[frb(sync)]
pub fn portable_record_digest(ua: [u8; 32], kind: i64, pqz_key_hash: [u8; 32], kem_record_hash: [u8; 32]) -> R<[u8; 32]> {
    Ok(scaas_ua::ua8::portable_record_digest(&ua, k(kind)?, &pqz_key_hash, &kem_record_hash))
}
/// typed `UARegistration{record, pqzPopHash}`: what the signer's `pop` signs under `ua_message(kind, POP_V2, ·)` (and a native
/// `msig` member signs itself, TS-D4).
#[frb(sync)]
pub fn registration_digest(ua: [u8; 32], kind: i64, pqz_key_hash: [u8; 32], kem_record_hash: [u8; 32], pqz_pop_hash: [u8; 32]) -> R<[u8; 32]> {
    Ok(scaas_ua::ua8::registration_digest(&ua, k(kind)?, &pqz_key_hash, &kem_record_hash, &pqz_pop_hash))
}
/// typed `UAKemRecord{ua, version, scheme, kemPkHash}` that `setKemKey` signs (`UAKemVersion` for 0, `UAKemScheme` unless the first byte is 1, `UAKemKeyLength` unless 1,601 bytes).
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
/// `pop` signs (every kind). `member_digest` (an `msig` only) is what each derived member signs under `member`; a native
/// member signs `registration_digest` itself (TS-D4).
pub struct HolderPop {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub kem_record_hash: [u8; 32],
    pub portable_record_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    pub message: [u8; 32],
    pub member_digest: Option<[u8; 32]>,
}
/// The portable PoP message of a registration. Attributes: `pqz_key` with its proof `pqz_pop` (or only its hash `pqz_pop_hash`;
/// null / empty = absent) and the initial KEM key `kem_pk` (1,601 bytes, scheme byte 1 first; its record is always version 0,
/// owner 2026-10-31; null / empty = absent); only holders carry them (`UAPqzHolder`, `UAKemHolder`; an `msig` needs
/// `key_data` to show it is PQ-eligible); a PQZ key always comes with its proof hash and only with it (`UAPqzPopHash`).
#[frb(sync)]
pub fn holder_pop_message(
    kind: i64,
    ua: [u8; 32],
    key_data: Vec<u8>,
    pqz_key: Option<Vec<u8>>,
    pqz_pop: Option<Vec<u8>>,
    pqz_pop_hash: Option<Vec<u8>>,
    kem_pk: Option<Vec<u8>>,
) -> R<HolderPop> {
    holder_pop_message_with(kind, ua, key_data, pqz_key, pqz_pop, pqz_pop_hash, kem_pk, String::new())
}
/// [`holder_pop_message`] with `inner` as in [`msig_pqz_eligible_with`].
#[frb(sync)]
#[allow(clippy::too_many_arguments)]
pub fn holder_pop_message_with(
    kind: i64,
    ua: [u8; 32],
    key_data: Vec<u8>,
    pqz_key: Option<Vec<u8>>,
    pqz_pop: Option<Vec<u8>>,
    pqz_pop_hash: Option<Vec<u8>>,
    kem_pk: Option<Vec<u8>>,
    inner: String,
) -> R<HolderPop> {
    let (h, i) = (hash(&pqz_pop_hash)?, scaas_ua::json::inner_json(&inner)?);
    let l = scaas_ua::json::lookup(&i);
    let (key, pop, kem) = (pqz_key.as_deref(), pqz_pop.as_deref(), kem_pk.as_deref());
    let r = scaas_ua::ua8::holder_pop_message_with(k(kind)?, &ua, &key_data, key, pop, h.as_ref(), kem, &l)?;
    Ok(HolderPop {
        pqz_key_hash: r.pqz_key_hash,
        pqz_pop_hash: r.pqz_pop_hash,
        kem_record_hash: r.kem_record_hash,
        portable_record_digest: r.portable_record_digest,
        registration_digest: r.registration_digest,
        message: r.message,
        member_digest: r.member_digest,
    })
}
/// The message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_record_digest(ua, kind, key_hash(pqz_key),
/// kem_record_hash))`, `kind` the registering kind, `kem_pk` the register KEM key (version 0; null / empty = none).
#[frb(sync)]
pub fn pqz_reg_message(kind: i64, ua: [u8; 32], pqz_key: Vec<u8>, kem_pk: Option<Vec<u8>>) -> R<[u8; 32]> {
    Ok(scaas_ua::pqz_reg_message(k(kind)?, &ua, &pqz_key, kem_pk.as_deref())?)
}
/// typed `UAPqzKey{ua, pqzKeyHash}`: what a later PQZ key's `R_REG` proves over.
#[frb(sync)]
pub fn pqz_key_digest(ua: [u8; 32], pqz_key_hash: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::pqz_key_digest(&ua, &pqz_key_hash)
}
/// typed `UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}`: what `setPqzKey`'s signature signs under
/// `ua_message(kind, PURPOSE_PQZ_KEY, ·)` (and a native `msig` member signs itself, TS-D4).
#[frb(sync)]
pub fn pqz_key_record_digest(ua: [u8; 32], pqz_key_hash: [u8; 32], pqz_pop_hash: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::pqz_key_record_digest(&ua, &pqz_key_hash, &pqz_pop_hash)
}
/// typed `UAMembership{ua, member}`: what `member` signs to accept its slot in the `msig` `ua` (CTR-UA-37): a native member this
/// digest itself, a derived member `member_digest(ua, ua_message(MSIG, PURPOSE_MEMBERSHIP, ·))` under `member`.
#[frb(sync)]
pub fn membership_digest(ua: [u8; 32], member: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua8::membership_digest(&ua, &member)
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
    pqz_key_record_message_with(kind, ua, key_data, pqz_key, pqz_pop, pqz_pop_hash, already_set, String::new())
}
/// [`pqz_key_record_message`] with `inner` as in [`msig_pqz_eligible_with`].
#[frb(sync)]
#[allow(clippy::too_many_arguments)]
pub fn pqz_key_record_message_with(
    kind: i64,
    ua: [u8; 32],
    key_data: Vec<u8>,
    pqz_key: Vec<u8>,
    pqz_pop: Option<Vec<u8>>,
    pqz_pop_hash: Option<Vec<u8>>,
    already_set: bool,
    inner: String,
) -> R<PqzKeyRecord> {
    let (h, i) = (hash(&pqz_pop_hash)?, scaas_ua::json::inner_json(&inner)?);
    let l = scaas_ua::json::lookup(&i);
    let r = scaas_ua::ua8::pqz_key_record_message_with(k(kind)?, &ua, &key_data, &pqz_key, pqz_pop.as_deref(), h.as_ref(), already_set, &l)?;
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
/// The `MemberSig` a copy sends to `acceptMembership` from the bytes of its `UAMemberSig` alone, which hash to `memberSigHashOf(ua, index)` (CTR-UA-37), as the slot JSON `{index,
/// members: [{index, sig}], sig}` of a [`registration_args`] `pop` entry: `key_data` the `msig` `ua`'s, `stored` a signing slot's `sig` or
/// an `msig` slot's `abi.encode(InnerSig[])`, canonical, at most 16 entries. Anything else, or an index past the members, is
/// `UAUnauthorized`; an index outside u16 `UAArgument`.
#[frb(sync)]
pub fn replayed_member_sig(key_data: Vec<u8>, index: i64, stored: Vec<u8>) -> R<String> {
    Ok(scaas_ua::json::replayed_member_sig_json(&key_data, n(index)?, &stored)?)
}
/// POP_V2, KEM, PQZ_KEY: the only purposes where a code-less native `msig` member signs the record's typed digest itself
/// (`eth_signTypedData_v4`, TS-D4); every other purpose stays UAAuth.
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
/// ua-mtx-merge spec §6: how a client shows a bytes32 id before the user signs: the EIP-55 address of a native-space id, else
/// `urn:scaas:ua:v1:<kind name>:<hex32>` under `kind`, the id's registry kind (0 = none known: UAKindUnknown). `id`: "0x" + 64 hex.
#[frb(sync)]
pub fn id_display(id: String, kind: i64) -> R<String> {
    Ok(scaas_ua::id_display(&id, k(kind)?)?.text().to_owned())
}
/// The registry's explicit arguments of a registration, JSON in and out. `input`: `{kind, keyData, pqzKey, pqzPopHash, pqzPop, kemPk,
/// pop, kemCommit, inner}` (bytes as "0x…" hex, an absent field is empty, an msig's `pop` is `[{index, members: [{index, sig}], sig}]`,
/// `inner` `{id: keyData}` its msig members' structures, `kemCommit` true / false forces the KEM form; absent: the hash commit only when
/// the full call is over 261,909 B). Out: `{args, kemFill, calldataLength, kemFillCalldataLength}`, `args.entry` the registry entry,
/// `kemFill` the `setKemKey(ua, 0, …)` of a hash-committed key (null otherwise). `UAArgument` when the input is not this JSON.
#[frb(sync)]
pub fn registration_args(input: String) -> R<String> {
    Ok(scaas_ua::json::registration_args_json(&input)?)
}
/// `setKemKey`'s explicit arguments, JSON in and out. `input`: `{ua, version, kemPk, sig}`, `sig` the `UASig` `{keyData, signature,
/// members: [{index, members: [{index, sig}], sig}]}` (absent: empty, the version-0 fill of a hash commit). Out: `{ua, version, kem, sig}`.
#[frb(sync)]
pub fn set_kem_key_args(input: String) -> R<String> {
    Ok(scaas_ua::json::set_kem_key_args_json(&input)?)
}
/// `setPqzKey`'s explicit arguments, JSON in and out. `input`: `{ua, pqzKey, pqzPopHash, sig}`, `sig` as [`set_kem_key_args`]. Out:
/// the same fields, `sig` complete.
#[frb(sync)]
pub fn set_pqz_key_args(input: String) -> R<String> {
    Ok(scaas_ua::json::set_pqz_key_args_json(&input)?)
}
/// What a payer signs (pay-meta-tax T41), JSON in and out: `{struct, domain: {name, chainId, verifyingContract, salt}, message}`,
/// `struct` `UAMetaTransfer`, `UAPayWithTax` (`{payment, taxMode, tax}`) or `UARelayFee`; out `{structHash, digest}`.
#[frb(sync)]
pub fn pay_digest(input: String) -> R<String> {
    Ok(scaas_ua::json::pay_digest_json(&input)?)
}
/// `metaPayId` under `scaas.pay.meta.v2` (pay-meta-tax T41): in `{salt, payNo, schema, body}`, out `{payId}`; a refused shape or
/// `payNo` is `UAArgument`.
#[frb(sync)]
pub fn meta_pay_id(input: String) -> R<String> {
    Ok(scaas_ua::json::meta_pay_id_json(&input)?)
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
