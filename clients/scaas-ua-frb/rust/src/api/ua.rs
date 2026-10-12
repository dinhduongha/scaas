//! flutter_rust_bridge surface over `scaas-ua`. Every function is synchronous; failures are a `UAError { code, reason }`
//! (a Dart exception). Byte data is `Uint8List` (`Vec<u8>`), ids and digests are fixed-size arrays.
use flutter_rust_bridge::frb;

/// `code` is one of the seven shared codes (`UAKeyData`, `UAKindUnknown`, ...); `reason` is `Display` text.
#[derive(Debug, Clone)]
pub struct UAError {
    pub code: String,
    pub reason: String,
}

impl From<scaas_ua::UAError> for UAError {
    fn from(e: scaas_ua::UAError) -> Self {
        UAError { code: e.code().into(), reason: e.to_string() }
    }
}

type R<T> = Result<T, UAError>;

pub struct KindInfo {
    pub kind: u16,
    pub name: String,
    pub native: bool,
    /// Empty = variable length.
    pub lengths: Vec<u32>,
    pub group: Option<String>,
}

/// The registry's EIP-712 domain.
pub struct UaDomain {
    pub generation: u32,
    pub chain_id: u64,
    pub registry: [u8; 20],
    pub chain_uid: [u8; 32],
}

impl From<UaDomain> for scaas_ua::Domain {
    fn from(d: UaDomain) -> Self {
        scaas_ua::Domain { generation: d.generation, chain_id: d.chain_id, registry: d.registry, chain_uid: d.chain_uid }
    }
}

#[frb(sync)]
pub fn kind_info(kind: u16) -> R<KindInfo> {
    let k = scaas_ua::kind_info(kind)?;
    Ok(KindInfo {
        kind: k.kind,
        name: k.name.into(),
        native: k.native,
        lengths: k.lengths.iter().map(|l| *l as u32).collect(),
        group: k.group.map(Into::into),
    })
}
#[frb(sync)]
pub fn tag(kind: u16) -> R<[u8; 32]> {
    Ok(scaas_ua::tag(kind)?)
}
#[frb(sync)]
pub fn kind_tag_string(kind: u16) -> R<String> {
    Ok(scaas_ua::kind_tag_string(kind)?)
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
pub fn ua_of(kind: u16, key_data: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::ua_of(kind, &key_data)?)
}
#[frb(sync)]
pub fn derive_ua(kind: u16, key_data: Vec<u8>, hedera_native: bool) -> R<[u8; 32]> {
    Ok(scaas_ua::derive_ua(kind, &key_data, hedera_native)?)
}
#[frb(sync)]
pub fn native_id(kind: u16, raw: Vec<u8>) -> R<[u8; 32]> {
    Ok(scaas_ua::native_id(kind, &raw)?)
}
#[frb(sync)]
pub fn key_hash_of(kind: u16, key_data: Vec<u8>) -> R<Option<[u8; 32]>> {
    Ok(scaas_ua::key_hash_of(kind, &key_data)?)
}
#[frb(sync)]
pub fn validate_key_data(kind: u16, key_data: Vec<u8>, hedera_native: bool) -> R<()> {
    Ok(scaas_ua::validate_key_data(kind, &key_data, hedera_native)?)
}
#[frb(sync)]
pub fn in_native_space(id: [u8; 32]) -> bool {
    scaas_ua::in_native_space(&id)
}
#[frb(sync)]
pub fn is_native(kind: u16) -> bool {
    scaas_ua::is_native(kind)
}
#[frb(sync)]
pub fn is_zether(kind: u16) -> bool {
    scaas_ua::is_zether(kind)
}
#[frb(sync)]
pub fn is_signing(kind: u16) -> bool {
    scaas_ua::is_signing(kind)
}
#[frb(sync)]
pub fn is_member(kind: u16, hedera_native: bool) -> bool {
    scaas_ua::is_member(kind, hedera_native)
}
#[frb(sync)]
pub fn ua_message(kind: u16, purpose: [u8; 32], digest: [u8; 32]) -> R<[u8; 32]> {
    Ok(scaas_ua::ua_message(kind, &purpose, &digest)?)
}
#[frb(sync)]
pub fn chain_key_hash(chain_id: u64) -> [u8; 32] {
    scaas_ua::chain_key_hash(chain_id)
}
#[frb(sync)]
pub fn pop_digest(chain_id: u64, chain_uid: [u8; 32], registry: [u8; 20], ua: [u8; 32], auth_ref: [u8; 32]) -> [u8; 32] {
    scaas_ua::pop_digest(chain_id, &chain_uid, &registry, &ua, &auth_ref)
}
#[frb(sync)]
pub fn ua_auth_domain_separator(domain: UaDomain) -> [u8; 32] {
    scaas_ua::ua_auth_domain_separator(&domain.into())
}
#[frb(sync)]
pub fn ua_auth_digest(domain: UaDomain, ua: [u8; 32], purpose: [u8; 32], digest: [u8; 32]) -> [u8; 32] {
    scaas_ua::ua_auth_digest(&domain.into(), &ua, &purpose, &digest)
}
#[frb(sync)]
pub fn member_digest(structure_ua: [u8; 32], ua_msg: [u8; 32]) -> [u8; 32] {
    scaas_ua::member_digest(&structure_ua, &ua_msg)
}
#[frb(sync)]
pub fn canonical_id(text: String) -> R<String> {
    Ok(scaas_ua::canonical_id(&text)?)
}
/// Members are `(kind, id, weight)`.
#[frb(sync)]
pub fn encode_msig(threshold: u16, members: Vec<(u16, [u8; 32], u16)>) -> Vec<u8> {
    scaas_ua::encode_msig(threshold, &members)
}
