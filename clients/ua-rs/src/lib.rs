//! SCaaS Universal Account identity layer (accounts.md §1.3–§1.6): the kind table, ids, keyHash, purpose tags, `ua_msg`,
//! `popDigest`, the registry's `UAAuth` digest, member digests, canonical ids and key-data validation. The same rules live
//! in Solidity (`UAKinds.sol`), JS (clientkeys `ua.js`), Python, Go and C#; `smartcontracts/vectors/ua/` pins all six.
//! The curve code here (k256, p256, curve25519-dalek, arkworks) is independent of the JS generator's (noble): the vectors
//! are accepted only when both agree. Feature `signers` (UA-2c): the MuSig2 / FROST group signers that generate
//! `groups.json` (`musig2`, `frost`); the group kinds' registry checks are in the default build (`verify`). UNAUDITED.
use sha3::{Digest, Keccak256};

mod keydata;
pub mod near;
pub mod algorand;
pub use keydata::validate_key_data;
pub mod verify;
pub mod ua8;
pub use ua8::{holder_pop_message, pqz_reg_message};
mod groups;
#[cfg(feature = "signers")]
pub mod musig2;
#[cfg(feature = "signers")]
pub mod frost;

/// An error whose [`UAError::code`] every implementation and the vector files share.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UAError {
    KeyData(&'static str),
    IdInNativeSpace,
    KindUnknown(u16),
    KindNotDerived(u16),
    KindNotNative(u16),
    IdFormat,
    PurposeUnknown,
    PqzHolder(u16),
    KemHolder(u16),
    KemVersion,
    KemKeyLength,
    /// First byte of a `kemPk` is not an enabled KEM scheme id (CTR-UA-32).
    KemScheme,
    PqzPopHash,
    /// `setPqzKey` on a registration that already has a PQZ key (write-once).
    PqzKeySet,
}

impl UAError {
    pub fn code(&self) -> &'static str {
        match self {
            UAError::KeyData(_) => "UAKeyData",
            UAError::IdInNativeSpace => "UAIdInNativeSpace",
            UAError::KindUnknown(_) => "UAKindUnknown",
            UAError::KindNotDerived(_) => "UAKindNotDerived",
            UAError::KindNotNative(_) => "UAKindNotNative",
            UAError::IdFormat => "UAIdFormat",
            UAError::PurposeUnknown => "UAPurposeUnknown",
            UAError::PqzHolder(_) => "UAPqzHolder",
            UAError::KemHolder(_) => "UAKemHolder",
            UAError::KemVersion => "UAKemVersion",
            UAError::KemKeyLength => "UAKemKeyLength",
            UAError::KemScheme => "UAKemScheme",
            UAError::PqzPopHash => "UAPqzPopHash",
            UAError::PqzKeySet => "UAPqzKeySet",
        }
    }
}

impl core::fmt::Display for UAError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            UAError::KeyData(reason) => write!(f, "UAKeyData: {reason}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for UAError {}

pub type Result<T> = core::result::Result<T, UAError>;

/// One row of the kind table; `lengths` empty = variable-length key data.
#[derive(Debug)]
pub struct Kind {
    pub kind: u16,
    pub name: &'static str,
    pub native: bool,
    pub lengths: &'static [usize],
    pub group: Option<&'static str>,
}

const fn native(kind: u16, name: &'static str, lengths: &'static [usize]) -> Kind {
    Kind { kind, name, native: true, lengths, group: None }
}
const fn derived(kind: u16, name: &'static str, lengths: &'static [usize], group: Option<&'static str>) -> Kind {
    Kind { kind, name, native: false, lengths, group }
}

pub const KINDS: &[Kind] = &[
    native(0x0001, "evm-eoa", &[20]),
    native(0x0002, "evm-contract", &[20]),
    native(0x0003, "hedera-native", &[20]),
    native(0x0010, "solana-ed25519", &[32]),
    native(0x0011, "stellar-account", &[32]),
    native(0x0012, "soroban-contract", &[32]),
    native(0x0013, "aptos-account", &[32]),
    native(0x0014, "sui-address", &[32]),
    native(0x0015, "cosmos-account", &[20, 32]),
    native(0x0016, "ton-wallet", &[32]),
    native(0x0017, "near-account", &[32]),
    native(0x0018, "algorand-address", &[32]),
    derived(0x0100, "webauthn-p256", &[96], Some("p256")),
    derived(0x0101, "p256", &[64], Some("p256")),
    derived(0x0102, "ed25519", &[32], Some("ed25519")),
    derived(0x0103, "bip340", &[32], Some("secp256k1")),
    derived(0x0104, "schnorr-bn254", &[64], Some("bn254-g1")),
    derived(0x0105, "schnorr-bls12381", &[128], Some("bls12381-g1")),
    derived(0x0106, "bls12381-minsig", &[256], Some("bls12381-g2")),
    derived(0x0107, "bls-bn254-minsig", &[128], Some("bn254-g2")),
    derived(0x0110, "musig2-secp256k1", &[], Some("secp256k1")),
    derived(0x0111, "frost-secp256k1", &[], Some("secp256k1")),
    derived(0x0112, "musig2-bn254", &[], Some("bn254-g1")),
    derived(0x0113, "frost-bn254", &[], Some("bn254-g1")),
    derived(0x0120, "msig", &[], None),
    derived(0x0130, "mldsa44", &[1312], Some("mldsa44")),
    derived(0x0131, "mldsa65", &[1952], Some("mldsa65")),
    derived(0x0132, "fndsa512", &[897], Some("fndsa512")),
    derived(0x0133, "slhdsa128s", &[32], Some("slhdsa128s")),
    derived(0x0141, "zether-bls12381", &[128], Some("bls12381-g1")),
    derived(0x0108, "secp256k1", &[64], Some("secp256k1")), // 2026-10-17, appended as in kinds.json
];

/// Schemes are not kinds (UA-6 U14): 0x0142 is the PQZ key attribute of a PQ holder; it keeps its tag and keyHash group.
pub const SCHEMES: &[Kind] = &[derived(0x0142, "pqz-mlwe", &PQZ_KEY_LENGTHS, Some("pqz-mlwe"))];
/// The key lengths of the PQZ parameter sets (PqzSet.PK).
pub const PQZ_KEY_LENGTHS: [usize; 4] = [16384, 18432, 20480, 22528];
/// The scheme number of the PQZ key attribute.
pub const PQZ_SCHEME: u16 = 0x0142;

pub const GROUPS: &[&str] = &[
    "p256", "ed25519", "secp256k1", "bn254-g1", "bls12381-g1", "bls12381-g2", "bn254-g2", "mldsa44", "mldsa65", "fndsa512",
    "slhdsa128s", "pqz-mlwe",
];

pub const PURPOSES: &[&str] = &[
    "pop", "metatx", "metatx-cancel", "member", "zether-auth", "zether-owner", "keyop", "receiver-fee", "vp",
    "vc-anchor", "trade", "kem", "pqz-key",
];

pub const DOMAIN_TYPE: &str =
    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)";
pub const UAAUTH_TYPE: &str = "UAAuth(bytes32 ua,bytes32 purpose,bytes32 digest)";
pub const REGISTRY_NAME: &str = "SCaaS UARegistry";

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    keccak(&[data])
}

/// CTR-MTX-26: the payment id that commits to its metadata, `keccak256("scaas.pay.meta" ‖ salt ‖ keccak256(meta))`
/// (`meta = abi.encode(uint16 schema, bytes body)`; on chain `metaPayId`).
pub fn meta_pay_id(salt: &[u8; 32], meta: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.pay.meta", salt, &keccak256(meta)])
}
/// CTR-MTX-03: a payment's lane, `keccak256("scaas.pay.lane" ‖ p)` (the 32 bytes of the on-chain `uint256 payLane(p)`).
pub fn pay_lane(p: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"scaas.pay.lane", p])
}
/// CTR-MTX-27 (EVM `MtxRelayFee.relayRef`): `keccak256("scaas.relayfee" ‖ uint256 chain_id ‖ target ‖ keccak256(call_data))`.
/// Other families use their own `ref` forms (salted, family address bytes); this is the EVM one only.
pub fn relay_ref(chain_id: u64, target: &[u8; 20], call_data: &[u8]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", &word(chain_id), target, &keccak256(call_data)])
}

pub(crate) fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn kind_info(kind: u16) -> Result<&'static Kind> {
    KINDS.iter().find(|k| k.kind == kind).ok_or(UAError::KindUnknown(kind))
}

fn derived_kind(kind: u16) -> Result<&'static Kind> {
    if SCHEMES.iter().any(|k| k.kind == kind) {
        return Err(UAError::KindNotDerived(kind));
    }
    let k = kind_info(kind)?;
    if k.native {
        return Err(UAError::KindNotDerived(kind));
    }
    Ok(k)
}

fn single_signing(kind: u16) -> bool {
    matches!(kind, 0x0100..=0x0108 | 0x0110..=0x0113 | 0x0130..=0x0133)
}
pub fn is_native(kind: u16) -> bool {
    KINDS.iter().any(|k| k.kind == kind && k.native)
}
pub fn is_zether(kind: u16) -> bool {
    kind == 0x0141
}
pub fn is_signing(kind: u16) -> bool {
    kind == 0x0120 || kind == 0x0141 || single_signing(kind)
}
/// Kinds that may hold a PQZ key attribute: mldsa44, mldsa65, fndsa512 (an `msig` per [`msig_pqz_eligible`]).
pub fn is_pqz_holder(kind: u16) -> bool {
    matches!(kind, 0x0130..=0x0132)
}
/// An `msig` whose members of kinds outside 0x0130-0x0133 weigh less than its threshold (CTR-PQZ-12).
pub fn msig_pqz_eligible(key_data: &[u8]) -> Result<bool> {
    let u16_at = |o: usize| key_data.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]) as usize);
    let bad = || UAError::KeyData("length");
    let count = u16_at(2).ok_or_else(bad)?;
    if key_data.len() != 4 + 36 * count {
        return Err(bad());
    }
    let mut classical = 0usize;
    for i in 0..count {
        let o = 4 + 36 * i;
        if !(0x0130..=0x0133).contains(&u16_at(o).ok_or_else(bad)?) {
            classical += u16_at(o + 34).ok_or_else(bad)?;
        }
    }
    Ok(classical < u16_at(0).ok_or_else(bad)?)
}
pub fn is_member(kind: u16, hedera_native: bool) -> bool {
    single_signing(kind) || kind == 0x0001 || kind == 0x0002 || (hedera_native && kind == 0x0003)
}

// tag / keyHash / message accept a kind or a scheme; id derivation and key-data validation accept kinds only
fn tagged_kind(kind: u16) -> Result<&'static Kind> {
    SCHEMES.iter().find(|k| k.kind == kind).map_or_else(|| derived_kind(kind), Ok)
}
pub fn kind_tag_string(kind: u16) -> Result<String> {
    Ok(format!("scaas.ua.{}.v1", tagged_kind(kind)?.name))
}
pub fn tag(kind: u16) -> Result<[u8; 32]> {
    Ok(keccak256(kind_tag_string(kind)?.as_bytes()))
}
pub fn group_tag_string(group: &str) -> Option<String> {
    GROUPS.contains(&group).then(|| format!("scaas.ua.group.{group}.v1"))
}
pub fn group_tag(group: &str) -> Option<[u8; 32]> {
    group_tag_string(group).map(|s| keccak256(s.as_bytes()))
}
pub fn msg_tag() -> [u8; 32] {
    keccak256(b"scaas.ua.msg.v1")
}
pub fn purpose_tag(purpose: &str) -> Result<[u8; 32]> {
    if !PURPOSES.contains(&purpose) {
        return Err(UAError::PurposeUnknown);
    }
    Ok(keccak256(format!("scaas.ua.purpose.{purpose}.v1").as_bytes()))
}

/// The tag of a purpose version: every purpose is v1, `pop` is also v2 (UA-8: the portable PoP).
pub fn purpose_tag_v(purpose: &str, version: u32) -> Result<[u8; 32]> {
    match (purpose, version) {
        (_, 1) => purpose_tag(purpose),
        ("pop", 2) => Ok(keccak256(b"scaas.ua.purpose.pop.v2")),
        _ => Err(UAError::PurposeUnknown),
    }
}

/// `keccak256(TAG(kind) ‖ keyData)`; no validation (see [`derive_ua`]).
pub fn ua_of(kind: u16, key_data: &[u8]) -> Result<[u8; 32]> {
    derived_kind(kind)?; // a scheme (0x0142) or a native kind has no derived id
    Ok(keccak(&[&tag(kind)?, key_data]))
}
pub fn in_native_space(id: &[u8; 32]) -> bool {
    id[..12].iter().all(|b| *b == 0)
}
/// Validate, derive, refuse an id whose top 96 bits are zero (CTR-UA-03).
pub fn derive_ua(kind: u16, key_data: &[u8], hedera_native: bool) -> Result<[u8; 32]> {
    validate_key_data(kind, key_data, hedera_native)?;
    let ua = ua_of(kind, key_data)?;
    if in_native_space(&ua) {
        return Err(UAError::IdInNativeSpace);
    }
    Ok(ua)
}
/// A native id left-padded to 32 bytes.
pub fn native_id(kind: u16, raw: &[u8]) -> Result<[u8; 32]> {
    let k = kind_info(kind)?;
    if !k.native {
        return Err(UAError::KindNotNative(kind));
    }
    if !k.lengths.contains(&raw.len()) {
        return Err(UAError::KeyData("length"));
    }
    let mut id = [0u8; 32];
    id[32 - raw.len()..].copy_from_slice(raw);
    Ok(id)
}
/// `keccak256(GROUP(g) ‖ canonical pubkey)`, `None` for structures. Call on validated key data.
pub fn key_hash_of(kind: u16, key_data: &[u8]) -> Result<Option<[u8; 32]>> {
    let k = tagged_kind(kind)?;
    let Some(group) = k.group else { return Ok(None) };
    let (lo, hi) = match kind {
        0x0100 | 0x0101 | 0x0108 => (0, 32),
        0x0110 | 0x0111 => (1, 33),
        0x0112 | 0x0113 => (0, 64),
        _ => (0, key_data.len()),
    };
    let pubkey = key_data.get(lo..hi).ok_or(UAError::KeyData("length"))?;
    Ok(Some(keccak(&[&group_tag(group).expect("table group"), pubkey])))
}

pub fn ua_message(kind: u16, purpose: &[u8; 32], digest: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(keccak(&[&msg_tag(), &tag(kind)?, purpose, digest]))
}
pub fn chain_key_hash(chain_id: u64) -> [u8; 32] {
    keccak256(format!("evm:{chain_id}").as_bytes())
}
fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}
fn address_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
/// LEGACY (pre-UA-8, chain-bound; the registry accepts only the typed [`ua8::registration_digest`]). `pop_digest_v1` (CTR-UA-07): `pqz_key_hash` is the keyHash of the UA's PQZ key, 0 without one (the bytes of the former `authRef = 0`).
pub fn pop_digest_v1(chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&purpose_tag("pop").expect("pop"), &chain_key_hash(chain_id), chain_uid, &address_word(registry), ua, pqz_key_hash])
}

/// LEGACY (pre-UA-8): what a PQ holder signed to register (UA-6 U14): `(pqzKeyHash, popDigest, message)`, `message = ua_message(kind, pop,
/// pop_digest(ua, h))`, `h = key_hash_of(0x0142, pqz_key)`, 0 without a key. A key needs a single-key holder ([`is_pqz_holder`]);
/// a PQ-eligible `msig` uses `pop_digest` / `key_hash_of` and signs `member_digest(ua, message)` per member.
pub fn holder_pop_message_v1(
    kind: u16, chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], ua: &[u8; 32], pqz_key: Option<&[u8]>,
) -> Result<([u8; 32], [u8; 32], [u8; 32])> {
    let h = match pqz_key {
        Some(k) => {
            if !is_pqz_holder(kind) {
                return Err(UAError::PqzHolder(kind));
            }
            key_hash_of(PQZ_SCHEME, k)?.expect("scheme group")
        }
        None => [0u8; 32],
    };
    let d = pop_digest_v1(chain_id, chain_uid, registry, ua, &h);
    Ok((h, d, ua_message(kind, &purpose_tag("pop")?, &d)?))
}

/// LEGACY (pre-UA-8): the message `R_REG` proved over: `ua_message(0x0142, pop, pop_digest(ua, key_hash_of(0x0142, pqz_key)))`.
pub fn pqz_reg_message_v1(chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], ua: &[u8; 32], pqz_key: &[u8]) -> Result<[u8; 32]> {
    let h = key_hash_of(PQZ_SCHEME, pqz_key)?.expect("scheme group");
    ua_message(PQZ_SCHEME, &purpose_tag("pop")?, &pop_digest_v1(chain_id, chain_uid, registry, ua, &h))
}

/// The registry's EIP-712 domain: `("SCaaS UARegistry", "<generation>", chainId, registry, salt = chainUid)`.
pub struct Domain {
    pub generation: u32,
    pub chain_id: u64,
    pub registry: [u8; 20],
    pub chain_uid: [u8; 32],
}
pub fn ua_auth_domain_separator(d: &Domain) -> [u8; 32] {
    keccak(&[
        &keccak256(DOMAIN_TYPE.as_bytes()),
        &keccak256(REGISTRY_NAME.as_bytes()),
        &keccak256(d.generation.to_string().as_bytes()),
        &word(d.chain_id),
        &address_word(&d.registry),
        &d.chain_uid,
    ])
}
/// EIP-712 digest of `UAAuth(ua, purpose, digest)`: what native signers behind the registry sign.
pub fn ua_auth_digest(d: &Domain, ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    let s = keccak(&[&keccak256(UAAUTH_TYPE.as_bytes()), ua, purpose, digest]);
    keccak(&[&[0x19, 0x01], &ua_auth_domain_separator(d), &s])
}
pub fn member_digest(structure_ua: &[u8; 32], ua_msg: &[u8; 32]) -> [u8; 32] {
    keccak(&[structure_ua, ua_msg])
}

/// Lower-case hex; a 32-byte id with the top 96 bits zero is written as its 20-byte native id (CTR-UA-03).
pub fn canonical_id(text: &str) -> Result<String> {
    let h = text.strip_prefix("0x").ok_or(UAError::IdFormat)?;
    if !(h.len() == 40 || h.len() == 64) || !h.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err(UAError::IdFormat);
    }
    let h = h.to_ascii_lowercase();
    Ok(if h.len() == 64 && h.as_bytes()[..24].iter().all(|c| *c == b'0') {
        format!("0x{}", &h[24..])
    } else {
        format!("0x{h}")
    })
}

/// `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖ u16 weight)`.
pub fn encode_msig(threshold: u16, members: &[(u16, [u8; 32], u16)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 36 * members.len());
    out.extend_from_slice(&threshold.to_be_bytes());
    out.extend_from_slice(&(members.len() as u16).to_be_bytes());
    for (kind, id, weight) in members {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(id);
        out.extend_from_slice(&weight.to_be_bytes());
    }
    out
}
