//! flutter_rust_bridge surface over `scaas-ua`. Every function is synchronous; failures are a `UAError { code, reason }`
//! (a Dart exception). Byte data is `Uint8List` (`Vec<u8>`), ids and digests are fixed-size arrays.
use flutter_rust_bridge::frb;

/// `code` is one of the seven shared codes (`UAKeyData`, `UAKindUnknown`, ...); `reason` is the label after `UAKeyData: ` (empty for every other code),
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
#[frb(sync)]
pub fn pop_digest(chain_id: i64, chain_uid: [u8; 32], registry: [u8; 20], ua: [u8; 32], auth_ref: [u8; 32]) -> R<[u8; 32]> {
    Ok(scaas_ua::pop_digest(n(chain_id)?, &chain_uid, &registry, &ua, &auth_ref))
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
