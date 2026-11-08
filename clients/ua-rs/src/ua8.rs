//! UA-8 portable registrations (P1, P2, P7; plan UA8-D1/D2): the chain-free PoP, the KEM record and the PQZ key record, as
//! typed EIP-712 structs under the name + version domain (typed-signing TS-D1 … TS-D4): no chain id, chain uid or registry.
//! The JS reference is clientkeys `src/ua.js`; `smartcontracts/vectors/ua/portable.json` pins every byte. The raw digests
//! before the typed records are in legacy/typed-signing/portable_raw.rs. `check_*` (ua8-soroban B5) is the off-chain verifier
//! of these records. UNAUDITED.
use crate::*;

/// KEM scheme ids, `kem_pk[0]` (CTR-UA-32): 1 = ML-KEM-1024 + X25519; 2 = ML-KEM-1024 + HQC + X25519, reserved (after
/// FIPS 207) and refused today.
pub const KEM_SCHEME_MLKEM1024_X25519: u8 = 1;
pub const KEM_SCHEME_MLKEM1024_HQC_X25519: u8 = 2;
/// A scheme-1 `kemPk`: `0x01 ‖ ML-KEM-1024 ek (1,568 B) ‖ X25519 pk (32 B)` (X-Wing order), the only KEM key the registry
/// stores (UA-8 P7).
pub const KEM_PK_LENGTH: usize = 1601;
pub use crate::PQZ_KEY_LENGTHS;

/// Who checked a part of a record (UA-8 P11.3); `Relayer` comes with the relayer id.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checked {
    None,
    Chain,
    Relayer([u8; 32]),
}
impl Checked {
    pub fn code(&self) -> u8 {
        match self {
            Checked::None => 0,
            Checked::Chain => 1,
            Checked::Relayer(_) => 2,
        }
    }
}

/// `PURPOSE_POP_V2` = keccak256("scaas.ua.purpose.pop.v2").
pub fn pop_v2_tag() -> [u8; 32] {
    purpose_tag_v("pop", 2).expect("pop v2")
}

/// The portable EIP-712 domain (TS-D1): name and version only, no chainId / verifyingContract / salt (the records register
/// a UA on every chain, CTR-UA-07).
pub const PORTABLE_DOMAIN_TYPE: &str = "EIP712Domain(string name,string version)";
pub const PORTABLE_DOMAIN_NAME: &str = "SCaaS UA Portable";
pub const PORTABLE_DOMAIN_VERSION: &str = "1";
/// `DS_P = keccak256(abi.encode(keccak256(PORTABLE_DOMAIN_TYPE), keccak256(name), keccak256(version)))`.
pub const PORTABLE_DOMAIN_SEPARATOR: [u8; 32] = [
    0x9a, 0x2c, 0x39, 0x0d, 0x4d, 0xc9, 0x40, 0xcc, 0xdb, 0x5f, 0xa6, 0xb2, 0x1e, 0x67, 0x3e, 0x87, 0x15, 0x9b, 0xdd, 0x99, 0xae,
    0xef, 0x22, 0xea, 0x79, 0x1b, 0xce, 0xa9, 0xef, 0xc6, 0x4c, 0xa1,
];
/// The portable structs' EIP-712 `encodeType` (primary, then the referenced types sorted by name); `kind` is `uint16`.
pub const PORTABLE_TYPES: [(&str, &str); 8] = [
    ("UAKemRecord", "UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)"),
    ("UAPortableRecord", "UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)"),
    ("UARegistration", "UARegistration(UAPortableRecord record,bytes32 pqzPopHash)UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)"),
    ("UAPqzKey", "UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)"),
    ("UAPqzKeyRecord", "UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)"),
    // group 3g (KV-1): a PQZ key version v >= 1 and the UA's consent to it; version 0 keeps `UAPqzKey` / `UAPqzKeyRecord`
    ("UAPqzKeyVersion", "UAPqzKeyVersion(bytes32 ua,uint64 version,bytes32 pqzKeyHash)"),
    ("UAPqzKeyVersionRecord", "UAPqzKeyVersionRecord(UAPqzKeyVersion key,bytes32 pqzPopHash)UAPqzKeyVersion(bytes32 ua,uint64 version,bytes32 pqzKeyHash)"),
    ("UAMembership", "UAMembership(bytes32 ua,bytes32 member)"),
];
/// `keccak256(encodeType)` of a portable struct by name (panics on another name).
pub fn portable_typehash(name: &str) -> [u8; 32] {
    let (_, t) = PORTABLE_TYPES.iter().find(|(n, _)| *n == name).unwrap_or_else(|| panic!("not a portable struct: {name}"));
    keccak256(t.as_bytes())
}
/// `keccak256(0x1901 ‖ DS_P ‖ structHash)`: what `eth_signTypedData_v4` returns for a portable record.
fn typed(struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], &PORTABLE_DOMAIN_SEPARATOR, struct_hash])
}

/// `hashStruct(UAKemRecord{ua, version, scheme: kem_pk[0], kemPkHash: keccak256(kem_pk)})` over the whole scheme-1 key:
/// version 0 … 2^64 − 1 (version 0 = the key given at `register`, owner 2026-10-31), `kem_pk` = scheme byte ‖ key (empty:
/// `KemKeyLength`; scheme not enabled, 0 included: `KemScheme`; another length: `KemKeyLength`). No key (`version` 0 and no
/// key) is the zero record `UAKemRecord{ua, 0, 0, 0}` (TS-D2: a present record has scheme ≠ 0); the `kem` word of a
/// `UAPortableRecord`.
pub fn kem_record_hash(ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    let th = portable_typehash("UAKemRecord");
    if version == 0 && kem_pk.is_empty() {
        return Ok(keccak(&[&th, ua, &[0; 32], &[0; 32], &[0; 32]]));
    }
    let scheme = match kem_pk.first() {
        None => return Err(UAError::KemKeyLength),
        Some(&s @ KEM_SCHEME_MLKEM1024_X25519) => s,
        Some(_) => return Err(UAError::KemScheme),
    };
    if kem_pk.len() != KEM_PK_LENGTH {
        return Err(UAError::KemKeyLength);
    }
    Ok(keccak(&[&th, ua, &word(version), &word(scheme as u64), &keccak256(kem_pk)]))
}
/// The typed `UAKemRecord` digest `setKemKey` signs (versions ≥ 1: version 0 is the `register` key, `KemVersion` here).
pub fn kem_record_digest(ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    if version == 0 {
        return Err(UAError::KemVersion);
    }
    Ok(typed(&kem_record_hash(ua, version, kem_pk)?))
}
/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`; a kind that holds no KEM key is
/// `KemHolder` ([`is_kem_holder`]).
pub fn kem_record_message(kind: u16, ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    if !is_kem_holder(kind) {
        return Err(UAError::KemHolder(kind));
    }
    ua_message(kind, &purpose_tag("kem")?, &kem_record_digest(ua, version, kem_pk)?)
}

/// `hashStruct(UAPortableRecord{ua, kind, pqzKeyHash, kem})`, `kem_record_hash` = [`kem_record_hash`] (the zero record's
/// hash when there is none).
pub fn portable_record_hash(ua: &[u8; 32], kind: u16, pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&portable_typehash("UAPortableRecord"), ua, &word(kind as u64), pqz_key_hash, kem_record_hash])
}
/// The typed `UAPortableRecord` digest: what `R_REG` proves over at `register` / the first `storePqzPop`.
pub fn portable_record_digest(ua: &[u8; 32], kind: u16, pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    typed(&portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash))
}
/// The typed `UARegistration{record, pqzPopHash}` digest: what the signer's `pop` signs under `ua_message(kind, POP_V2, ·)`
/// (and a native msig member signs itself, TS-D4).
pub fn registration_digest(ua: &[u8; 32], kind: u16, pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    let record = portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash);
    typed(&keccak(&[&portable_typehash("UARegistration"), &record, pqz_pop_hash]))
}
fn pqz_key_hash_struct(ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&portable_typehash("UAPqzKey"), ua, pqz_key_hash])
}
/// The typed `UAPqzKey{ua, pqzKeyHash}` digest: what a later PQZ key's `R_REG` proves over (no proof hash: no cycle).
pub fn pqz_key_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    typed(&pqz_key_hash_struct(ua, pqz_key_hash))
}
/// The typed `UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}` digest: what `setPqzKey`'s signature signs under
/// `ua_message(kind, PURPOSE_PQZ_KEY, ·)` (and a native msig member signs itself, TS-D4).
pub fn pqz_key_record_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    typed(&keccak(&[&portable_typehash("UAPqzKeyRecord"), &pqz_key_hash_struct(ua, pqz_key_hash), pqz_pop_hash]))
}
/// The typed `UAMembership{ua, member}` digest: what `member` signs to accept its slot in the `msig` `ua` (CTR-UA-37,
/// `acceptMembership`): a native member this digest itself (or ERC-1271 over it), a derived member
/// `member_digest(ua, ua_message(MSIG, PURPOSE_MEMBERSHIP, ·))` under `member`.
pub fn membership_digest(ua: &[u8; 32], member: &[u8; 32]) -> [u8; 32] {
    typed(&keccak(&[&portable_typehash("UAMembership"), ua, member]))
}

/// An `msig` member's key data by its id (see [`msig_pqz_eligible_with`]).
pub type Inner<'a> = dyn Fn([u8; 32]) -> Option<Vec<u8>> + 'a;
/// A PQZ key holder: a single-key PQ kind, or an `msig` whose key data is PQ-eligible (`key_data` shows it, `inner` its `msig` members).
/// Malformed `msig` key data is `UAKeyData` (as in the JS), not "not a holder".
fn holds(kind: u16, key_data: &[u8], inner: &Inner) -> Result<bool> {
    if is_pqz_holder(kind) {
        return Ok(true);
    }
    if kind == 0x0120 && !key_data.is_empty() {
        return msig_pqz_eligible_with(key_data, inner);
    }
    Ok(false)
}
/// A KEM key holder (CTR-UA-32; owner 2026-11-05, MD-11 (c), T66a): the single PQ kinds only, as the registry's `UAKemHolder`. An `msig`
/// holds no KEM key: a sender seals to each accepted member's own key.
pub fn is_kem_holder(kind: u16) -> bool {
    is_pqz_holder(kind)
}
/// `key_hash_of(0x0142, pqz_key)`; a key of no parameter set's length is `UAKeyData`.
fn pqz_key_hash_of(pqz_key: &[u8]) -> Result<[u8; 32]> {
    if !PQZ_KEY_LENGTHS.contains(&pqz_key.len()) {
        return Err(UAError::KeyData("PQZ key length"));
    }
    Ok(key_hash_of(PQZ_SCHEME, pqz_key)?.expect("scheme group"))
}
/// The proof hash from the proof bytes and / or the hash (absent = 0); both given and different is `UAPqzPopHash`, and so
/// is `keccak256("")` (an empty proof is no proof: ruling A6-m).
fn proof_hash_of(pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>) -> Result<[u8; 32]> {
    let proof = pqz_pop.filter(|p| !p.is_empty()).map(keccak256);
    let given = pqz_pop_hash.filter(|h| !h.iter().all(|b| *b == 0));
    if let (Some(a), Some(b)) = (&proof, given) {
        if a != b {
            return Err(UAError::PqzPopHash);
        }
    }
    let h = proof.or(given.copied()).unwrap_or([0; 32]);
    if h == keccak256(&[]) {
        return Err(UAError::PqzPopHash);
    }
    Ok(h)
}

/// The portable PoP of a registration (UA-8 P1, P2; typed-signing TS-D3), as [`holder_pop_message`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderPop {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    /// `hashStruct(UAKemRecord)` of the initial KEM record, the zero record's when there is none.
    pub kem_record_hash: [u8; 32],
    /// typed `UAPortableRecord{ua, kind, pqzKeyHash, kem}`.
    pub portable_record_digest: [u8; 32],
    /// typed `UARegistration{record, pqzPopHash}`; a native msig member signs it itself (`eth_signTypedData_v4`, TS-D4).
    pub registration_digest: [u8; 32],
    /// `ua_message(kind, POP_V2, registration_digest)`: what the signer's `pop` signs (every kind).
    pub message: [u8; 32],
    /// `msig` only: `member_digest(ua, message)`, what each derived member signs under `member` (a native member signs
    /// `registration_digest` instead, TS-D4).
    pub member_digest: Option<[u8; 32]>,
}

/// The portable PoP message of a registration. Attributes: `pqz_key` with its proof `pqz_pop` (or only its hash
/// `pqz_pop_hash`; a relayer may hold only that) and the initial KEM key `kem_pk` (its record is always version 0, owner
/// 2026-10-31: no version input); `None` / empty = absent. Only holders may carry them (`PqzHolder`: an `msig` needs `key_data` to show it
/// is PQ-eligible; `KemHolder`: a single PQ kind only, CTR-UA-32, never an `msig`); a PQZ key always comes with its proof hash and only
/// with it (`PqzPopHash`).
pub fn holder_pop_message(
    kind: u16, ua: &[u8; 32], key_data: &[u8], pqz_key: Option<&[u8]>, pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    kem_pk: Option<&[u8]>,
) -> Result<HolderPop> {
    holder_pop_message_with(kind, ua, key_data, pqz_key, pqz_pop, pqz_pop_hash, kem_pk, &|_| None)
}
/// [`holder_pop_message`] for an `msig` with `msig` members: `inner` gives their key data.
#[allow(clippy::too_many_arguments)]
pub fn holder_pop_message_with(
    kind: u16, ua: &[u8; 32], key_data: &[u8], pqz_key: Option<&[u8]>, pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    kem_pk: Option<&[u8]>, inner: &Inner,
) -> Result<HolderPop> {
    let pqz_key = pqz_key.filter(|k| !k.is_empty());
    let kem = kem_pk.filter(|pk| !pk.is_empty());
    if pqz_key.is_some() && !holds(kind, key_data, inner)? {
        return Err(UAError::PqzHolder(kind));
    }
    if kem.is_some() && !is_kem_holder(kind) {
        return Err(UAError::KemHolder(kind));
    }
    let pop_hash = proof_hash_of(pqz_pop, pqz_pop_hash)?;
    if pqz_key.is_some() != (pop_hash != [0; 32]) {
        return Err(UAError::PqzPopHash);
    }
    let pqz_key_hash = pqz_key.map(pqz_key_hash_of).transpose()?.unwrap_or([0; 32]);
    let kem_record_hash = kem_record_hash(ua, 0, kem.unwrap_or(&[]))?;
    let registration = registration_digest(ua, kind, &pqz_key_hash, &kem_record_hash, &pop_hash);
    let message = ua_message(kind, &pop_v2_tag(), &registration)?;
    Ok(HolderPop {
        pqz_key_hash,
        pqz_pop_hash: pop_hash,
        kem_record_hash,
        portable_record_digest: portable_record_digest(ua, kind, &pqz_key_hash, &kem_record_hash),
        registration_digest: registration,
        message,
        member_digest: (kind == 0x0120).then(|| member_digest(ua, &message)),
    })
}

/// The message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_record_digest(ua, kind, key_hash(pqz_key),
/// kem_record_hash))`, `kind` the registering kind (TS-D3); `kem_pk` the register KEM key (version 0), `None` / empty = none.
pub fn pqz_reg_message(kind: u16, ua: &[u8; 32], pqz_key: &[u8], kem_pk: Option<&[u8]>) -> Result<[u8; 32]> {
    let kem_record_hash = kem_record_hash(ua, 0, kem_pk.unwrap_or(&[]))?;
    ua_message(PQZ_SCHEME, &pop_v2_tag(), &portable_record_digest(ua, kind, &pqz_key_hash_of(pqz_key)?, &kem_record_hash))
}

/// The PQZ key record of `setPqzKey` (ruling A1-I1), see [`pqz_key_record_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzKeyRecord {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    /// typed `UAPqzKey{ua, pqzKeyHash}`.
    pub pqz_key_digest: [u8; 32],
    /// typed `UAPqzKeyRecord{key, pqzPopHash}`; a native msig member signs it itself (TS-D4).
    pub record_digest: [u8; 32],
    /// `ua_message(kind, PURPOSE_PQZ_KEY, record_digest)`: what the UA signs.
    pub message: [u8; 32],
    /// `ua_message(0x0142, PURPOSE_PQZ_KEY, pqz_key_digest)`: what the key's `R_REG` proves over.
    pub pqz_reg_message: [u8; 32],
    pub member_digest: Option<[u8; 32]>,
}

/// The signed, portable, write-once PQZ key record: accepted only by a registration without a PQZ key (`already_set` =
/// the registration has one: `PqzKeySet`). The holder rules of [`holder_pop_message`]; the key and its proof hash are
/// both required.
pub fn pqz_key_record_message(
    kind: u16, ua: &[u8; 32], key_data: &[u8], pqz_key: &[u8], pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    already_set: bool,
) -> Result<PqzKeyRecord> {
    pqz_key_record_message_with(kind, ua, key_data, pqz_key, pqz_pop, pqz_pop_hash, already_set, &|_| None)
}
/// [`pqz_key_record_message`] for an `msig` with `msig` members: `inner` gives their key data.
#[allow(clippy::too_many_arguments)]
pub fn pqz_key_record_message_with(
    kind: u16, ua: &[u8; 32], key_data: &[u8], pqz_key: &[u8], pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    already_set: bool, inner: &Inner,
) -> Result<PqzKeyRecord> {
    if !holds(kind, key_data, inner)? {
        return Err(UAError::PqzHolder(kind));
    }
    if already_set {
        return Err(UAError::PqzKeySet);
    }
    let pqz_key_hash = pqz_key_hash_of(pqz_key)?;
    let pop_hash = proof_hash_of(pqz_pop, pqz_pop_hash)?;
    if pop_hash == [0; 32] {
        return Err(UAError::PqzPopHash);
    }
    let key_digest = pqz_key_digest(ua, &pqz_key_hash);
    let record_digest = pqz_key_record_digest(ua, &pqz_key_hash, &pop_hash);
    let tag = purpose_tag("pqz-key")?;
    let message = ua_message(kind, &tag, &record_digest)?;
    Ok(PqzKeyRecord {
        pqz_key_hash,
        pqz_pop_hash: pop_hash,
        pqz_key_digest: key_digest,
        record_digest,
        message,
        pqz_reg_message: ua_message(PQZ_SCHEME, &tag, &key_digest)?,
        member_digest: (kind == 0x0120).then(|| member_digest(ua, &message)),
    })
}

fn pqz_key_version_hash(ua: &[u8; 32], version: u64, pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&version.to_be_bytes());
    keccak(&[&portable_typehash("UAPqzKeyVersion"), ua, &w, pqz_key_hash])
}
/// Group 3g: the typed `UAPqzKeyVersion{ua, version, pqzKeyHash}` digest: what version v >= 1's `R_REG` proves over.
pub fn pqz_key_version_digest(ua: &[u8; 32], version: u64, pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    typed(&pqz_key_version_hash(ua, version, pqz_key_hash))
}
/// Group 3g: the typed `UAPqzKeyVersionRecord{UAPqzKeyVersion{ua, version, pqzKeyHash}, pqzPopHash}` digest: what the UA signs for
/// version v >= 1 under `ua_message(kind, PURPOSE_PQZ_KEY, ·)`.
pub fn pqz_key_version_record_digest(ua: &[u8; 32], version: u64, pqz_key_hash: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    typed(&keccak(&[&portable_typehash("UAPqzKeyVersionRecord"), &pqz_key_version_hash(ua, version, pqz_key_hash), pqz_pop_hash]))
}

/// PQZ key version v >= 1 of `setPqzKey(ua, version, ...)`, see [`pqz_key_version_record_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzKeyVersionRecord {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    /// typed `UAPqzKeyVersion{ua, version, pqzKeyHash}`.
    pub version_digest: [u8; 32],
    /// typed `UAPqzKeyVersionRecord{key, pqzPopHash}`; a native msig member signs it itself (TS-D4).
    pub record_digest: [u8; 32],
    /// `ua_message(kind, PURPOSE_PQZ_KEY, record_digest)`: what the UA signs.
    pub message: [u8; 32],
    /// `ua_message(0x0142, PURPOSE_PQZ_KEY, version_digest)`: what the key's `R_REG` proves over.
    pub pqz_reg_message: [u8; 32],
    pub member_digest: Option<[u8; 32]>,
}

/// Group 3g (KV-1): the record of version `version`, from the UA's stored versions `(version, pqzKeyHash)` (the chain's `pqzKeyAt`):
/// version 0 is `PqzKeySet` (a new key gets a new version), a version other than `latest + 1` or no version 0 `PqzKeyVersion`, a key
/// a stored version holds `KeyInUse`. The holder rules of [`holder_pop_message`]; `inner` gives an `msig` member's key data.
#[allow(clippy::too_many_arguments)]
pub fn pqz_key_version_record_message(
    kind: u16, ua: &[u8; 32], key_data: &[u8], version: u64, pqz_key: &[u8], pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    stored: &[(u64, [u8; 32])], inner: &Inner,
) -> Result<PqzKeyVersionRecord> {
    if !holds(kind, key_data, inner)? {
        return Err(UAError::PqzHolder(kind));
    }
    if version == 0 {
        return Err(UAError::PqzKeySet);
    }
    let latest = stored.iter().map(|s| s.0).max();
    if !stored.iter().any(|s| s.0 == 0) || latest.map(|l| l.checked_add(1)) != Some(Some(version)) {
        return Err(UAError::PqzKeyVersion);
    }
    let pqz_key_hash = pqz_key_hash_of(pqz_key)?;
    if stored.iter().any(|s| s.1 == pqz_key_hash) {
        return Err(UAError::KeyInUse);
    }
    pqz_key_version_record_of(kind, ua, version, pqz_key_hash, pqz_pop, pqz_pop_hash)
}

fn pqz_key_version_record_of(
    kind: u16, ua: &[u8; 32], version: u64, pqz_key_hash: [u8; 32], pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
) -> Result<PqzKeyVersionRecord> {
    let pop_hash = proof_hash_of(pqz_pop, pqz_pop_hash)?;
    if pop_hash == [0; 32] {
        return Err(UAError::PqzPopHash);
    }
    let version_digest = pqz_key_version_digest(ua, version, &pqz_key_hash);
    let record_digest = pqz_key_version_record_digest(ua, version, &pqz_key_hash, &pop_hash);
    let tag = purpose_tag("pqz-key")?;
    let message = ua_message(kind, &tag, &record_digest)?;
    Ok(PqzKeyVersionRecord {
        pqz_key_hash,
        pqz_pop_hash: pop_hash,
        version_digest,
        record_digest,
        message,
        pqz_reg_message: ua_message(PQZ_SCHEME, &tag, &version_digest)?,
        member_digest: (kind == 0x0120).then(|| member_digest(ua, &message)),
    })
}

/// The minimal form of a stored `msig` signature (`pop` v2, KEM record, PQZ key record; owner 2026-10-31): with T = the
/// signing slots' total weight and N the threshold, T >= N and T - weight(i) < N for every slot (each slot necessary), i.e.
/// T - min(weight) < N. `indexes`: the `MemberSig` indexes; a set that is not strictly increasing within the members is
/// not minimal (`Ok(false)`). Malformed key data is `UAKeyData`. Same rule as clientkeys `msigSlotsMinimal`.
pub fn msig_slots_minimal(key_data: &[u8], indexes: &[u16]) -> Result<bool> {
    let u16_at = |o: usize| key_data.get(o..o + 2).map(|s| u16::from_be_bytes([s[0], s[1]]) as u32);
    let count = u16_at(2).ok_or(UAError::KeyData("length"))? as usize;
    if key_data.len() != 4 + 36 * count {
        return Err(UAError::KeyData("length"));
    }
    if !indexes.windows(2).all(|w| w[0] < w[1]) || indexes.iter().any(|&i| i as usize >= count) {
        return Ok(false);
    }
    let weights: Vec<u32> = indexes.iter().filter_map(|&i| u16_at(4 + 36 * i as usize + 34)).collect();
    let (total, n) = (weights.iter().sum::<u32>(), u16_at(0).unwrap_or(0));
    Ok(total >= n && weights.iter().min().is_none_or(|m| total - m < n))
}

/// The minimal rule at both levels of an `msig` signature (spec 2026-11-02-msig-nested N6): the slots of `key_data`, and each `msig` slot's
/// own list over that member's key data, `inner`. A wrong list is the slot's check, not this rule's. Same rule as clientkeys `msigSigMinimal`.
pub fn msig_sig_minimal(key_data: &[u8], slots: &[MemberSig], inner: &Inner) -> Result<bool> {
    if !msig_slots_minimal(key_data, &slots.iter().map(|s| s.index).collect::<Vec<_>>())? {
        return Ok(false);
    }
    let all = MsigStructure::from_key_data(key_data)?.members;
    for s in slots {
        let m = &all[s.index as usize];
        if m.kind == 0x0120 && !s.members.is_empty() {
            let d = inner(m.id).ok_or(UAError::MemberUnknown)?;
            if !msig_slots_minimal(&d, &s.members.iter().map(|x| x.index).collect::<Vec<_>>())? {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

/// `md_I = member_digest(I, ua_message(MSIG, member, md_U))`: what the members of the inner `msig` `inner` sign for its slot in an outer
/// whose `member_digest` is `md`, purpose `member` whatever the outer's.
pub fn inner_digest(inner: &[u8; 32], md: &[u8; 32]) -> Result<[u8; 32]> {
    Ok(member_digest(inner, &ua_message(0x0120, &purpose_tag("member")?, md)?))
}

/// The portable purposes (POP_V2, KEM, PQZ_KEY, MEMBERSHIP): the only ones where a code-less or EIP-7702-designator native msig member
/// signs the record's typed digest itself (`eth_signTypedData_v4`, 65-byte r ‖ s ‖ v, low-s, v 27 / 28; a contract member
/// answers ERC-1271 `isValidSignature(typedDigest, sig)`; TS-D4); every other purpose stays UAAuth (CTR-MTX-14).
pub fn is_portable_purpose(tag: &[u8; 32]) -> bool {
    [pop_v2_tag(), purpose_tag("kem").expect("kem"), purpose_tag("pqz-key").expect("pqz-key"), purpose_tag("membership").expect("membership")]
        .contains(tag)
}

// --- the registry's explicit arguments (typed-signing R1: TS-D10 … TS-D12; owner KEM rulings 2026-10-31) ---

/// `KemKey{scheme, mlkemEk, x25519}` (TS-D11): the registry assembles `kem_pk = scheme ‖ ek ‖ x25519` (scheme 1: 1,601 B);
/// the default (all zero / empty) is no key.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KemKey {
    pub scheme: u8,
    pub mlkem_ek: Vec<u8>,
    pub x25519: [u8; 32],
}
impl KemKey {
    /// The key of an assembled `kem_pk` (scheme byte, ek, the last 32 bytes); empty = no key; a malformed key is refused as the
    /// registry does ([`kem_record_hash`]: `KemScheme`, `KemKeyLength`).
    pub fn from_kem_pk(kem_pk: &[u8]) -> Result<Self> {
        kem_record_hash(&[0; 32], 0, kem_pk)?;
        Ok(match kem_pk.len() {
            0 => Self::default(),
            n => Self { scheme: kem_pk[0], mlkem_ek: kem_pk[1..n - 32].to_vec(), x25519: kem_pk[n - 32..].try_into().unwrap() },
        })
    }
    /// `scheme ‖ mlkem_ek ‖ x25519`, empty for no key.
    pub fn kem_pk(&self) -> Vec<u8> {
        if *self == Self::default() {
            return vec![];
        }
        [&[self.scheme][..], &self.mlkem_ek, &self.x25519].concat()
    }
}
/// An `msig` member (CTR-UA-09, TS-D10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsigMember {
    pub kind: u16,
    pub id: [u8; 32],
    pub weight: u16,
}
/// An `msig` structure (TS-D10); the registry assembles its CTR-UA-09 key data, so the id is the packed bytes'.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MsigStructure {
    pub threshold: u16,
    pub members: Vec<MsigMember>,
}
impl MsigStructure {
    pub fn from_key_data(d: &[u8]) -> Result<Self> {
        let u16at = |o: usize| u16::from_be_bytes([d[o], d[o + 1]]);
        if d.len() < 4 || d.len() != 4 + 36 * u16at(2) as usize {
            return Err(UAError::KeyData("length"));
        }
        let members = (0..u16at(2) as usize)
            .map(|i| {
                let o = 4 + 36 * i;
                MsigMember { kind: u16at(o), id: d[o + 2..o + 34].try_into().unwrap(), weight: u16at(o + 34) }
            })
            .collect();
        Ok(Self { threshold: u16at(0), members })
    }
    pub fn key_data(&self) -> Vec<u8> {
        encode_msig(self.threshold, &self.members.iter().map(|m| (m.kind, m.id, m.weight)).collect::<Vec<_>>())
    }
}
/// A `webauthn-p256` key (typed-signing TS-D13): the registry assembles `x ‖ y ‖ rp_id_hash` (96 B).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WebAuthnKey {
    pub x: [u8; 32],
    pub y: [u8; 32],
    pub rp_id_hash: [u8; 32],
}
/// A MuSig2 group key (TS-D13): points of 33 B (`musig2-secp256k1`) or 64 B (`musig2-bn254`); assembled
/// `agg_key ‖ u16 n ‖ n × key`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MuSig2Key {
    pub agg_key: Vec<u8>,
    pub member_keys: Vec<Vec<u8>>,
}
/// One FROST member (TS-D13): `threshold` commitments, R_i, z_i.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrostMember {
    pub commitments: Vec<Vec<u8>>,
    pub r: Vec<u8>,
    pub z: [u8; 32],
}
/// A FROST group key (TS-D13): assembled `group_key ‖ u16 threshold ‖ u16 n ‖ n × (commitments ‖ r ‖ z)`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FrostKey {
    pub group_key: Vec<u8>,
    pub threshold: u16,
    pub members: Vec<FrostMember>,
}
/// The point length of a MuSig2 / FROST kind (33 B secp256k1, 64 B bn254), 0 for any other kind.
fn point_size(kind: u16) -> usize {
    match kind {
        0x0110 | 0x0111 => 33,
        0x0112 | 0x0113 => 64,
        _ => 0,
    }
}
impl WebAuthnKey {
    pub fn from_key_data(d: &[u8]) -> Result<Self> {
        if d.len() != 96 {
            return Err(UAError::KeyData("length"));
        }
        Ok(Self { x: d[..32].try_into().unwrap(), y: d[32..64].try_into().unwrap(), rp_id_hash: d[64..].try_into().unwrap() })
    }
    pub fn key_data(&self) -> Vec<u8> {
        [self.x, self.y, self.rp_id_hash].concat()
    }
}
impl MuSig2Key {
    /// The key of `kind`'s packed key data (whole points; their validity is the registry's).
    pub fn from_key_data(kind: u16, d: &[u8]) -> Result<Self> {
        let s = point_size(kind);
        if s == 0 || d.len() < s + 2 || d.len() != s + 2 + u16::from_be_bytes([d[s], d[s + 1]]) as usize * s {
            return Err(UAError::KeyData("length"));
        }
        Ok(Self { agg_key: d[..s].to_vec(), member_keys: d[s + 2..].chunks(s).map(<[u8]>::to_vec).collect() })
    }
    pub fn key_data(&self) -> Vec<u8> {
        [self.agg_key.clone(), (self.member_keys.len() as u16).to_be_bytes().to_vec(), self.member_keys.concat()].concat()
    }
}
impl FrostKey {
    /// The key of `kind`'s packed key data (whole points; their validity is the registry's).
    pub fn from_key_data(kind: u16, d: &[u8]) -> Result<Self> {
        let s = point_size(kind);
        if s == 0 || d.len() < s + 4 {
            return Err(UAError::KeyData("length"));
        }
        let (t, n) = (u16::from_be_bytes([d[s], d[s + 1]]) as usize, u16::from_be_bytes([d[s + 2], d[s + 3]]) as usize);
        let per = (t + 1) * s + 32;
        if d.len() != s + 4 + n * per {
            return Err(UAError::KeyData("length"));
        }
        let members = d[s + 4..]
            .chunks(per)
            .map(|m| FrostMember {
                commitments: m[..t * s].chunks(s).map(<[u8]>::to_vec).collect(),
                r: m[t * s..(t + 1) * s].to_vec(),
                z: m[(t + 1) * s..].try_into().unwrap(),
            })
            .collect();
        Ok(Self { group_key: d[..s].to_vec(), threshold: t as u16, members })
    }
    pub fn key_data(&self) -> Vec<u8> {
        let mut o = [self.group_key.clone(), self.threshold.to_be_bytes().to_vec(), (self.members.len() as u16).to_be_bytes().to_vec()]
            .concat();
        for m in &self.members {
            o.extend([m.commitments.concat(), m.r.clone(), m.z.to_vec()].concat());
        }
        o
    }
}
/// One signature of a member of an inner `msig`: its slot there. No list of its own, so a third level has no form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InnerSig {
    pub index: u16,
    pub sig: Vec<u8>,
}
/// One `msig` slot's signature (CTR-UA-33): a signing member `sig`, `members` empty; an `msig` member `members`, `sig` empty.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberSig {
    pub index: u16,
    pub members: Vec<InnerSig>,
    pub sig: Vec<u8>,
}
/// A UA signature (TS-D12): native `signature`; derived single key `key_data` (empty for stored kinds) + `signature`; an
/// msig `members`; a portable record's signature never carries `key_data`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UASig {
    pub key_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub members: Vec<MemberSig>,
}
/// `register`'s attributes: the KEM key (version 0) in full (`kem`, `kem_pk_hash` 0) or as the hash commit (`kem` = its
/// scheme only, `kem_pk_hash = keccak256(kem_pk)`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UAAttrs {
    pub pqz_key: Vec<u8>,
    pub pqz_pop_hash: [u8; 32],
    pub kem: KemKey,
    pub kem_pk_hash: [u8; 32],
}
/// The typed registration call: `register(kind, keyData, attrs, pop, pqzPop)`, `registerMsig(structure, attrs, pop,
/// pqzPop)`, `registerWebAuthn(key, attrs, pop, pqzPop)` (`webauthn-p256`), `registerMuSig2` / `registerFrost(kind, key,
/// attrs, pop, pqzPop)` (typed-signing TS-D13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterArgs {
    Register { kind: u16, key_data: Vec<u8>, attrs: UAAttrs, pop: Vec<u8>, pqz_pop: Vec<u8> },
    RegisterMsig { structure: MsigStructure, attrs: UAAttrs, pop: Vec<MemberSig>, pqz_pop: Vec<u8> },
    RegisterWebAuthn { key: WebAuthnKey, attrs: UAAttrs, pop: Vec<u8>, pqz_pop: Vec<u8> },
    RegisterMuSig2 { kind: u16, key: MuSig2Key, attrs: UAAttrs, pop: Vec<u8>, pqz_pop: Vec<u8> },
    RegisterFrost { kind: u16, key: FrostKey, attrs: UAAttrs, pop: Vec<u8>, pqz_pop: Vec<u8> },
}
/// `setKemKey(ua, version, kem, sig)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetKemKeyArgs {
    pub ua: [u8; 32],
    pub version: u64,
    pub kem: KemKey,
    pub sig: UASig,
}
/// The largest calldata whose EIP-7976 floor (15,000 + 64 per byte) fits the EIP-7825 cap 2^24: 261,909 B.
pub const REGISTER_CALLDATA_LIMIT: usize = ((1 << 24) - 15_000) / 64;

fn tail_len(b: &[u8]) -> usize {
    32 + b.len().div_ceil(32) * 32
}
fn kem_key_len(k: &KemKey) -> usize {
    96 + tail_len(&k.mlkem_ek)
}
fn attrs_len(a: &UAAttrs) -> usize {
    128 + tail_len(&a.pqz_key) + kem_key_len(&a.kem)
}
fn inner_sigs_len(m: &[InnerSig]) -> usize {
    32 + m.iter().map(|s| 32 + 64 + tail_len(&s.sig)).sum::<usize>()
}
fn member_sigs_len(m: &[MemberSig]) -> usize {
    32 + m.iter().map(|s| 32 + 96 + inner_sigs_len(&s.members) + tail_len(&s.sig)).sum::<usize>()
}
fn bytes_arr_len(xs: &[Vec<u8>]) -> usize {
    32 + xs.iter().map(|x| 32 + tail_len(x)).sum::<usize>()
}
impl RegisterArgs {
    /// The ABI calldata length, selector included.
    pub fn calldata_len(&self) -> usize {
        match self {
            Self::Register { key_data, attrs, pop, pqz_pop, .. } => {
                4 + 160 + tail_len(key_data) + attrs_len(attrs) + tail_len(pop) + tail_len(pqz_pop)
            }
            Self::RegisterMsig { structure, attrs, pop, pqz_pop } => {
                4 + 128 + 96 + 96 * structure.members.len() + attrs_len(attrs) + member_sigs_len(pop) + tail_len(pqz_pop)
            }
            Self::RegisterWebAuthn { attrs, pop, pqz_pop, .. } => 4 + 192 + attrs_len(attrs) + tail_len(pop) + tail_len(pqz_pop),
            Self::RegisterMuSig2 { key, attrs, pop, pqz_pop, .. } => {
                4 + 160 + 64 + tail_len(&key.agg_key) + bytes_arr_len(&key.member_keys) + attrs_len(attrs) + tail_len(pop)
                    + tail_len(pqz_pop)
            }
            Self::RegisterFrost { key, attrs, pop, pqz_pop, .. } => {
                let members: usize =
                    key.members.iter().map(|m| 32 + 96 + bytes_arr_len(&m.commitments) + tail_len(&m.r)).sum();
                4 + 160 + 96 + tail_len(&key.group_key) + 32 + members + attrs_len(attrs) + tail_len(pop) + tail_len(pqz_pop)
            }
        }
    }
    /// The registration attributes.
    pub fn attrs(&self) -> &UAAttrs {
        match self {
            Self::Register { attrs, .. }
            | Self::RegisterMsig { attrs, .. }
            | Self::RegisterWebAuthn { attrs, .. }
            | Self::RegisterMuSig2 { attrs, .. }
            | Self::RegisterFrost { attrs, .. } => attrs,
        }
    }
    /// The packed key data the registry assembles (the id's input).
    pub fn key_data(&self) -> Vec<u8> {
        match self {
            Self::Register { key_data, .. } => key_data.clone(),
            Self::RegisterMsig { structure, .. } => structure.key_data(),
            Self::RegisterWebAuthn { key, .. } => key.key_data(),
            Self::RegisterMuSig2 { key, .. } => key.key_data(),
            Self::RegisterFrost { key, .. } => key.key_data(),
        }
    }
}
impl SetKemKeyArgs {
    /// The ABI calldata length, selector included.
    pub fn calldata_len(&self) -> usize {
        4 + 128 + kem_key_len(&self.kem) + 96 + tail_len(&self.sig.key_data) + tail_len(&self.sig.signature)
            + member_sigs_len(&self.sig.members)
    }
}
/// The repair of a front-run hash commit (PRV M1, owner 2026-11-01, option (a); CTR-UA-07): both forms of a KEM key sign the
/// same record, so anyone can land the commit form of a full `register`. After `register`, or on `UAAlreadyRegistered`, the
/// client reads `registrationOf(ua).attrs.kemPkHash` and `kemKeyAt(ua, 0).kem` (`stored`) and sends what this returns:
/// `setKemKey(ua, 0, kem, UASig())` when the commit is unfilled, equal to the `kem_fill` of a `kem_commit` registration.
pub fn kem_repair(ua: &[u8; 32], kem_pk_hash: &[u8; 32], stored: &KemKey, kem_pk: &[u8]) -> Result<Option<SetKemKeyArgs>> {
    if *kem_pk_hash == [0; 32] || *stored != KemKey::default() {
        return Ok(None);
    }
    kem_record_hash(ua, 1, kem_pk)?; // a fill needs a key: version 0 alone has a no-key record
    Ok(Some(SetKemKeyArgs { ua: *ua, version: 0, kem: KemKey::from_kem_pk(kem_pk)?, sig: UASig::default() }))
}
/// The registration's inputs (empty = absent): `pop` the signer's signature (single keys), `members` an msig's member
/// signatures; `kem_commit` forces the KEM form (`None`: the hash commit only when the full call is over
/// [`REGISTER_CALLDATA_LIMIT`]); `inners`: an `msig` member's id and key data, for the minimal rule of its list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RegistrationInput {
    pub kind: u16,
    pub key_data: Vec<u8>,
    pub pqz_key: Vec<u8>,
    pub pqz_pop_hash: [u8; 32],
    pub pqz_pop: Vec<u8>,
    pub kem_pk: Vec<u8>,
    pub pop: Vec<u8>,
    pub members: Vec<MemberSig>,
    pub kem_commit: Option<bool>,
    pub inners: Vec<([u8; 32], Vec<u8>)>,
}
/// The typed registration and, for a hash-committed KEM key, the second call that stores it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registration {
    pub args: RegisterArgs,
    pub kem_fill: Option<SetKemKeyArgs>,
}

/// The registry's explicit arguments (typed-signing R1 / R1b; clientkeys `registrationArgs`): `register` / `registerMsig` /
/// `registerWebAuthn` / `registerMuSig2` / `registerFrost`, the KEM
/// key (version 0, owner 2026-10-31) in full, or — only when the full call does not fit one transaction, or `kem_commit:
/// Some(true)` — as the hash commit with the fill `setKemKey(ua, 0, kem, UASig::default())` (no signature: the pop signed the
/// same `UAKemRecord{ua, 0, scheme, kemPkHash}`; anyone may send it). `pqz_pop_hash` defaults to `keccak256(pqz_pop)`.
pub fn registration_args(i: &RegistrationInput) -> Result<Registration> {
    if !i.kem_pk.is_empty() && !is_kem_holder(i.kind) {
        return Err(UAError::KemHolder(i.kind));
    }
    let pqz_pop_hash = if i.pqz_key.is_empty() && zero32(&i.pqz_pop_hash) {
        [0; 32]
    } else {
        proof_hash_of(Some(&i.pqz_pop), Some(&i.pqz_pop_hash))?
    };
    let kem = KemKey::from_kem_pk(&i.kem_pk)?;
    let attrs = UAAttrs { pqz_key: i.pqz_key.clone(), pqz_pop_hash, kem: kem.clone(), kem_pk_hash: [0; 32] };
    // every stored msig signature is minimal (owner 2026-10-31): the registry refuses any other set, so it is never built
    let inner = |id: [u8; 32]| i.inners.iter().find(|(x, _)| *x == id).map(|(_, d)| d.clone());
    if i.kind == 0x0120 && !i.members.is_empty() && !msig_sig_minimal(&i.key_data, &i.members, &inner)? {
        return Err(UAError::Pop);
    }
    let build = |attrs: UAAttrs| -> Result<RegisterArgs> {
        let (kind, pop, pqz_pop) = (i.kind, i.pop.clone(), i.pqz_pop.clone());
        Ok(match kind {
            0x0120 => RegisterArgs::RegisterMsig {
                structure: MsigStructure::from_key_data(&i.key_data)?, attrs, pop: i.members.clone(), pqz_pop,
            },
            0x0100 => RegisterArgs::RegisterWebAuthn { key: WebAuthnKey::from_key_data(&i.key_data)?, attrs, pop, pqz_pop },
            0x0110 | 0x0112 => {
                RegisterArgs::RegisterMuSig2 { kind, key: MuSig2Key::from_key_data(kind, &i.key_data)?, attrs, pop, pqz_pop }
            }
            0x0111 | 0x0113 => {
                RegisterArgs::RegisterFrost { kind, key: FrostKey::from_key_data(kind, &i.key_data)?, attrs, pop, pqz_pop }
            }
            _ => RegisterArgs::Register { kind, key_data: i.key_data.clone(), attrs, pop, pqz_pop },
        })
    };
    let full = build(attrs.clone())?;
    let commit = !i.kem_pk.is_empty() && i.kem_commit.unwrap_or(full.calldata_len() > REGISTER_CALLDATA_LIMIT);
    if !commit {
        return Ok(Registration { args: full, kem_fill: None });
    }
    let hashed = UAAttrs { kem: KemKey { scheme: kem.scheme, ..Default::default() }, kem_pk_hash: keccak256(&i.kem_pk), ..attrs };
    Ok(Registration {
        args: build(hashed)?,
        kem_fill: Some(SetKemKeyArgs { ua: ua_of(i.kind, &i.key_data)?, version: 0, kem, sig: UASig::default() }),
    })
}
fn zero32(b: &[u8; 32]) -> bool {
    b.iter().all(|x| *x == 0)
}

// --- the off-chain verifier (UA8-D24, C14): what a relayer runs before `Checked::Relayer`, the only check some parts get ---

/// `register`'s attributes.
pub type Attrs = UAAttrs;
/// `id` → the registered `(kind, key data)`: an `msig` member's record as the node reads it. Never trusted: the answer must
/// be a canonical key that hashes to `id` under its stated kind.
pub type Members<'a> = dyn Fn([u8; 32]) -> Option<(u16, Vec<u8>)> + 'a;

/// The ABI tail of a dynamic array: its length, the offsets, the items.
fn abi_list(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut o = word(items.len() as u64).to_vec();
    let mut off = 32 * items.len();
    for t in &items {
        o.extend(word(off as u64));
        off += t.len();
    }
    o.extend(items.concat());
    o
}
fn abi_bytes(o: &mut Vec<u8>, b: &[u8]) {
    o.extend(word(b.len() as u64));
    o.extend(b);
    o.resize(o.len() + b.len().next_multiple_of(32) - b.len(), 0);
}
fn inner_sig(s: &InnerSig) -> Vec<u8> {
    let mut o = [word(s.index as u64), word(64)].concat();
    abi_bytes(&mut o, &s.sig);
    o
}
/// `abi.encode(MemberSig[])`, the stored form of an `msig` signature (CTR-UA-33); empty for no slots, as the registries. `members` sits where
/// the always-empty `keyData` sat, so a flat slot's bytes did not change.
pub fn encode_member_sigs(sigs: &[MemberSig]) -> Vec<u8> {
    if sigs.is_empty() {
        return vec![];
    }
    let slot = |m: &MemberSig| {
        let list = abi_list(m.members.iter().map(inner_sig).collect());
        let mut o = [word(m.index as u64), word(96), word(96 + list.len() as u64)].concat();
        o.extend(list);
        abi_bytes(&mut o, &m.sig);
        o
    };
    [word(32).to_vec(), abi_list(sigs.iter().map(slot).collect())].concat()
}
/// `abi.encode(InnerSig[])`: what `UAMemberSig` carries for an `msig` slot.
pub fn encode_inner_sigs(members: &[InnerSig]) -> Vec<u8> {
    [word(32).to_vec(), abi_list(members.iter().map(inner_sig).collect())].concat()
}
/// The `MemberSig` a copy sends to `acceptMembership` from the bytes of its `UAMemberSig` alone, which hash to `memberSigHashOf(ua, index)` (CTR-UA-37, owner 2026-11-03): an `msig` slot's
/// stored bytes are `abi.encode(InnerSig[])`, canonical, at most 16; a signing slot's its `sig`. `Unauthorized` otherwise.
pub fn replayed_member_sig(key_data: &[u8], index: u16, stored: &[u8]) -> Result<MemberSig> {
    use crate::verify::word_usize as w;
    let m = *MsigStructure::from_key_data(key_data)?.members.get(index as usize).ok_or(UAError::Unauthorized)?;
    if m.kind != 0x0120 {
        return Ok(MemberSig { index, members: vec![], sig: stored.to_vec() });
    }
    let read = || -> Option<Vec<InnerSig>> {
        let n = w(stored, 32).filter(|n| *n <= 16 && w(stored, 0) == Some(32))?;
        let mut members = Vec::with_capacity(n);
        for j in 0..n {
            let u = w(stored, 64 + 32 * j)?.checked_add(64)?;
            let o = u.checked_add(w(stored, u.checked_add(32)?)?)?;
            let start = o.checked_add(32)?;
            let sig = stored.get(start..start.checked_add(w(stored, o)?)?)?.to_vec();
            members.push(InnerSig { index: u16::try_from(w(stored, u)?).ok()?, sig });
        }
        (encode_inner_sigs(&members) == stored).then_some(members)
    };
    Ok(MemberSig { index, members: read().ok_or(UAError::Unauthorized)?, sig: vec![] })
}
/// `abi.decode(blob, (MemberSig[]))`, canonical only (re-encoded and compared), at most 16 slots at each level: the type's depth of 2 is the
/// depth bound. `None` for anything else, an empty blob included (it has no slots to return).
pub fn decode_member_sigs(blob: &[u8]) -> Option<Vec<MemberSig>> {
    use crate::verify::word_usize as w;
    let at = |base: usize, head: usize| {
        let o = base.checked_add(w(blob, head)?)?;
        let start = o.checked_add(32)?;
        blob.get(start..start.checked_add(w(blob, o)?)?).map(<[u8]>::to_vec)
    };
    let n = w(blob, 32).filter(|n| *n <= 16 && w(blob, 0) == Some(32))?;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let t = w(blob, 64 + 32 * i)?.checked_add(64)?;
        let l = t.checked_add(w(blob, t.checked_add(32)?)?)?;
        let m = w(blob, l).filter(|m| *m <= 16)?;
        let mut members = Vec::with_capacity(m);
        for j in 0..m {
            let u = w(blob, l.checked_add(32 + 32 * j)?)?.checked_add(l.checked_add(32)?)?;
            members.push(InnerSig { index: u16::try_from(w(blob, u)?).ok()?, sig: at(u, u.checked_add(32)?)? });
        }
        out.push(MemberSig { index: u16::try_from(w(blob, t)?).ok()?, members, sig: at(t, t.checked_add(64)?)? });
    }
    (encode_member_sigs(&out) == blob).then_some(out)
}

/// EVM `_memberOk` before the signature: each derived member's key by its id, in member order (native members: empty), an `msig` member's
/// its structure, which holds no `msig` (two levels only, as the registry refused it).
fn member_keys(d: &[u8], members: &Members) -> Result<Vec<Vec<u8>>> {
    let key = |m: &MsigMember| {
        if is_native(m.kind) {
            return Ok(vec![]);
        }
        match members(m.id) {
            Some((k, key)) if k == m.kind && derive_ua(k, &key, false) == Ok(m.id) => {
                if k == 0x0120 && MsigStructure::from_key_data(&key)?.members.iter().any(|x| x.kind == 0x0120) {
                    return Err(UAError::MemberUnknown);
                }
                Ok(key)
            }
            _ => Err(UAError::MemberUnknown),
        }
    };
    MsigStructure::from_key_data(d)?.members.iter().map(key).collect()
}
/// `(id, index)` → `memberAccepted(id, index)` of the target registry (CTR-UA-37): has slot `index` of `id` agreed?
pub type Accepted<'a> = dyn Fn([u8; 32], u16) -> bool + 'a;
/// The accepted bits a verdict reads. `slot`: a bit the registry always reads (an inner `msig`'s, a `pop` exempting only its own record's;
/// every bit of `requireAuthorized`); with no `accepted` it is marked unchecked, and [`Bits::verdict`] turns a pass into `NotVerifiable`,
/// never `Ok`. `record`: a record's own bits outside its `pop` (`setKemKey`, `setPqzKey`), read when `accepted` comes, else the chain's state
/// as before nesting.
struct Bits<'a> {
    accepted: Option<&'a Accepted<'a>>,
    unchecked: std::cell::Cell<bool>,
}
impl<'a> Bits<'a> {
    fn new(accepted: Option<&'a Accepted<'a>>) -> Self {
        Bits { accepted, unchecked: Default::default() }
    }
    fn slot(&self, id: &[u8; 32], index: u16) -> bool {
        self.accepted.map_or_else(|| { self.unchecked.set(true); true }, |f| f(*id, index))
    }
    fn record(&self, id: &[u8; 32], index: u16) -> bool {
        self.accepted.is_none_or(|f| f(*id, index))
    }
    fn verdict(&self, ok: bool, refused: UAError) -> Result<()> {
        match (ok, self.unchecked.get()) {
            (false, _) => Err(refused),
            (true, true) => Err(UAError::NotVerifiable),
            (true, false) => Ok(()),
        }
    }
}
/// `members` as the key data of an `msig` member.
fn inner_of<'a>(members: &'a Members<'a>) -> impl Fn([u8; 32]) -> Option<Vec<u8>> + 'a {
    move |id| members(id).map(|(_, key)| key)
}

/// EVM `_sigOk` + `_msig(portable = true)` over `ua_message(kind, purpose, digest)`, `Err` for a part nothing here can check.
/// An `msig`: no slots unless PQ-eligible (U8S-D2), then the canonical minimal `MemberSig[]` (U8S-D1, both levels), each slot accepted
/// ([`Bits::record`], outside the `pop`) and by [`slot_ok`].
#[allow(clippy::too_many_arguments)]
fn signature_ok(kind: u16, d: &[u8], ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32], sig: &[u8], members: &Members, bits: &Bits) -> Result<bool> {
    let message = ua_message(kind, purpose, digest)?;
    if kind != 0x0120 {
        return Ok(crate::verify::verify(kind, d, &message, sig, true));
    }
    let keys = member_keys(d, members)?;
    if !msig_pqz_eligible_with(d, &inner_of(members))? {
        return Ok(sig.is_empty());
    }
    let Some(slots) = decode_member_sigs(sig) else { return Ok(false) };
    if !msig_slots_minimal(d, &slots.iter().map(|s| s.index).collect::<Vec<_>>())? {
        return Ok(false);
    }
    let structure = MsigStructure::from_key_data(d)?;
    let md = member_digest(ua, &message);
    let pop = *purpose == pop_v2_tag();
    for s in &slots {
        if !(pop || bits.record(ua, s.index)) || !slot_ok(&structure.members[s.index as usize], &keys[s.index as usize], digest, &md, s, members, bits)? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// One member's slot: a derived member under `member` over `md`, an `evm-eoa` member over `digest` itself, no list on either; another
/// native member is a part nothing here can check. An `msig` member by its own list, minimal, no `sig`, each leaf one level down an accepted
/// slot of it ([`Bits::slot`]) over [`inner_digest`], `digest` the same.
fn slot_ok(m: &MsigMember, key: &[u8], digest: &[u8; 32], md: &[u8; 32], s: &MemberSig, members: &Members, bits: &Bits) -> Result<bool> {
    if m.kind == 0x0120 {
        let indexes: Vec<u16> = s.members.iter().map(|x| x.index).collect();
        if !s.sig.is_empty() || !msig_slots_minimal(key, &indexes)? {
            return Ok(false);
        }
        let leaves = MsigStructure::from_key_data(key)?.members;
        let keys = member_keys(key, members)?;
        let inner = inner_digest(&m.id, md)?;
        for x in &s.members {
            let i = x.index as usize;
            if !bits.slot(&m.id, x.index) || !leaf_ok(&leaves[i], &keys[i], digest, &inner, &x.sig)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    Ok(s.members.is_empty() && leaf_ok(m, key, digest, md, &s.sig)?)
}
fn leaf_ok(m: &MsigMember, key: &[u8], digest: &[u8; 32], md: &[u8; 32], sig: &[u8]) -> Result<bool> {
    let vk = &key[..match point_size(m.kind) {
        0 => key.len(),
        head => head, // a group kind signs against its stored `vk`
    }];
    Ok(match m.kind {
        0x0001 => crate::verify::native_ecdsa(m.id[12..].try_into().expect("20 bytes"), digest, sig),
        k if is_native(k) => return Err(UAError::NotVerifiable),
        k => crate::verify::verify(k, vk, &ua_message(k, &purpose_tag("member")?, md)?, sig, false),
    })
}

/// `true` iff `(kind, d)` is the record of `ua`.
fn is_record_of(kind: u16, d: &[u8], ua: &[u8; 32]) -> Result<bool> {
    Ok(derive_ua(kind, d, false)? == *ua)
}

/// EVM `_attrs` in its order; the typed registration digest. The `register` KEM key is version 0, in whole or by its hash
/// (a hash commit has no key bytes to check: `kem` is its scheme alone).
fn registration_attrs(kind: u16, ua: &[u8; 32], d: &[u8], a: &Attrs, pqz_pop: &[u8], inner: &Inner) -> Result<[u8; 32]> {
    let (pqz, commit) = (!a.pqz_key.is_empty(), !zero32(&a.kem_pk_hash));
    let kem_pk = if commit { vec![] } else { a.kem.kem_pk() };
    if pqz && !holds(kind, d, inner)? {
        return Err(UAError::PqzHolder(kind));
    }
    if (commit || !kem_pk.is_empty()) && !is_kem_holder(kind) {
        return Err(UAError::KemHolder(kind));
    }
    if pqz == zero32(&a.pqz_pop_hash) || a.pqz_pop_hash == keccak256(&[]) || (!pqz_pop.is_empty() && keccak256(pqz_pop) != a.pqz_pop_hash) {
        return Err(UAError::PqzPopHash);
    }
    let pqz_key_hash = if pqz { pqz_key_hash_of(&a.pqz_key)? } else { [0; 32] };
    let kem = if commit {
        if !a.kem.mlkem_ek.is_empty() || !zero32(&a.kem.x25519) {
            return Err(UAError::KemKeyLength);
        }
        if a.kem.scheme != KEM_SCHEME_MLKEM1024_X25519 {
            return Err(UAError::KemScheme);
        }
        keccak(&[&portable_typehash("UAKemRecord"), ua, &[0; 32], &word(a.kem.scheme as u64), &a.kem_pk_hash])
    } else {
        kem_record_hash(ua, 0, &kem_pk)?
    };
    Ok(registration_digest(ua, kind, &pqz_key_hash, &kem, &a.pqz_pop_hash))
}

/// A registration as `register` checks it, on bytes only (no state, no `keyHash`): the id from canonical key data, every
/// `msig` member resolved, the attributes in `_attrs`' order, `keccak256(pqz_pop) == pqz_pop_hash` when proof bytes come,
/// the `pop`. The PQZ proof itself is not checked (U8S-D6). `Err` for anything it cannot check: an unknown kind, an
/// `evm-contract` slot (`NotVerifiable`), a member `members` does not resolve (`MemberUnknown`).
pub fn check_registration(kind: u16, key_data: &[u8], attrs: &Attrs, pop: &[u8], pqz_pop: &[u8], members: &Members) -> Result<()> {
    check_registration_with(kind, key_data, attrs, pop, pqz_pop, members, None)
}
/// [`check_registration`] on the target registry's accepted bits (CTR-UA-37): the `pop` accepts its own record's slots, never an inner
/// `msig`'s, so with no `accepted` a `pop` with an inner list is `NotVerifiable`. The same `accepted` in every `check_*_with`.
pub fn check_registration_with(
    kind: u16, key_data: &[u8], attrs: &Attrs, pop: &[u8], pqz_pop: &[u8], members: &Members, accepted: Option<&Accepted>,
) -> Result<()> {
    let ua = derive_ua(kind, key_data, false)?;
    let digest = registration_attrs(kind, &ua, key_data, attrs, pqz_pop, &inner_of(members))?;
    let bits = Bits::new(accepted);
    bits.verdict(signature_ok(kind, key_data, &ua, &pop_v2_tag(), &digest, pop, members, &bits)?, UAError::Pop)
}

/// A KEM record as `setKemKey` (version ≥ 1) checks it: `ua` the id of `key_data`, a holder, the key, `sig` in the `pop` format
/// over `kem_record_message`. Version 0 is `KemVersion`: its key is `register`'s (a commit's fill has no signature).
pub fn check_kem_record(kind: u16, key_data: &[u8], ua: &[u8; 32], version: u64, kem_pk: &[u8], sig: &[u8], members: &Members) -> Result<()> {
    check_kem_record_with(kind, key_data, ua, version, kem_pk, sig, members, None)
}
/// [`check_kem_record`] on the accepted bits, as [`check_registration_with`]; the record's own bits read too when `accepted` comes.
#[allow(clippy::too_many_arguments)]
pub fn check_kem_record_with(
    kind: u16, key_data: &[u8], ua: &[u8; 32], version: u64, kem_pk: &[u8], sig: &[u8], members: &Members, accepted: Option<&Accepted>,
) -> Result<()> {
    if !is_record_of(kind, key_data, ua)? {
        return Err(UAError::Unauthorized);
    }
    if !is_kem_holder(kind) {
        return Err(UAError::KemHolder(kind));
    }
    let digest = kem_record_digest(ua, version, kem_pk)?;
    let bits = Bits::new(accepted);
    bits.verdict(signature_ok(kind, key_data, ua, &purpose_tag("kem")?, &digest, sig, members, &bits)?, UAError::Unauthorized)
}

/// A PQZ key record as `setPqzKey` checks it, without its state (a key already set is the chain's `PqzKeySet`): `ua` the id of
/// `key_data`, a holder, the key's length, the proof hash, `sig` over `pqz_key_record_digest`.
pub fn check_pqz_key_record(kind: u16, key_data: &[u8], ua: &[u8; 32], pqz_key: &[u8], pqz_pop_hash: &[u8; 32], sig: &[u8], members: &Members) -> Result<()> {
    check_pqz_key_record_with(kind, key_data, ua, pqz_key, pqz_pop_hash, sig, members, None)
}
/// [`check_pqz_key_record`] on the accepted bits, as [`check_kem_record_with`].
#[allow(clippy::too_many_arguments)]
pub fn check_pqz_key_record_with(
    kind: u16, key_data: &[u8], ua: &[u8; 32], pqz_key: &[u8], pqz_pop_hash: &[u8; 32], sig: &[u8], members: &Members, accepted: Option<&Accepted>,
) -> Result<()> {
    if !is_record_of(kind, key_data, ua)? {
        return Err(UAError::Unauthorized);
    }
    let r = pqz_key_record_message_with(kind, ua, key_data, pqz_key, None, Some(pqz_pop_hash), false, &inner_of(members))?;
    let bits = Bits::new(accepted);
    bits.verdict(signature_ok(kind, key_data, ua, &purpose_tag("pqz-key")?, &r.record_digest, sig, members, &bits)?, UAError::Unauthorized)
}

/// A PQZ key version record as `setPqzKey(ua, version, ...)` checks it, without its state (the sequence and the per-UA marker are the
/// chain's): `ua` the id of `key_data`, a holder, version >= 1, the key's length, the proof hash, `sig` over the record digest.
#[allow(clippy::too_many_arguments)]
pub fn check_pqz_key_version_record(
    kind: u16, key_data: &[u8], ua: &[u8; 32], version: u64, pqz_key: &[u8], pqz_pop_hash: &[u8; 32], sig: &[u8], members: &Members,
) -> Result<()> {
    if !is_record_of(kind, key_data, ua)? {
        return Err(UAError::Unauthorized);
    }
    if !holds(kind, key_data, &inner_of(members))? {
        return Err(UAError::PqzHolder(kind));
    }
    if version == 0 {
        return Err(UAError::PqzKeySet);
    }
    let r = pqz_key_version_record_of(kind, ua, version, pqz_key_hash_of(pqz_key)?, None, Some(pqz_pop_hash))?;
    let bits = Bits::new(None);
    bits.verdict(signature_ok(kind, key_data, ua, &purpose_tag("pqz-key")?, &r.record_digest, sig, members, &bits)?, UAError::Unauthorized)
}

/// An acceptance as `accept_membership` / `acceptMembership` checks it, without its state (a slot already accepted is the chain's
/// no-op), CTR-UA-37: `ua` the id of the `msig` `key_data`, `slot.index` one of its members, the member's signature over
/// typed(`UAMembership{ua, member}`). One slot, no threshold. `Err` as `check_registration` for a part it cannot check.
pub fn check_membership(key_data: &[u8], ua: &[u8; 32], slot: &MemberSig, members: &Members) -> Result<()> {
    check_membership_with(key_data, ua, slot, members, None)
}
/// [`check_membership`] on the accepted bits: an `msig` slot's list counts only accepted slots of that member.
pub fn check_membership_with(key_data: &[u8], ua: &[u8; 32], slot: &MemberSig, members: &Members, accepted: Option<&Accepted>) -> Result<()> {
    if !is_record_of(0x0120, key_data, ua)? {
        return Err(UAError::Unauthorized);
    }
    let structure = MsigStructure::from_key_data(key_data)?;
    let i = slot.index as usize;
    let m = structure.members.get(i).ok_or(UAError::Unauthorized)?;
    let keys = member_keys(key_data, members)?;
    let digest = membership_digest(ua, &m.id);
    let md = member_digest(ua, &ua_message(0x0120, &purpose_tag("membership")?, &digest)?);
    let bits = Bits::new(accepted);
    bits.verdict(slot_ok(m, &keys[i], &digest, &md, slot, members, &bits)?, UAError::Unauthorized)
}

/// `requireAuthorized(ua, purpose, digest, UASig{"", "", slots})` of the `msig` `key_data`, without its state (UARegistry `_msig`, clientkeys
/// `verifyAuthorization`): at both levels strictly increasing accepted slots that stop at the threshold, no minimal rule, no eligibility; an
/// `msig` slot by its list one level down over [`inner_digest`], no `sig`; a derived leaf under `member` over its level's member digest, an
/// `evm-eoa` leaf over `UAAuth(id, member, that digest)` in `domain`. Every bit is read: no `accepted` is `NotVerifiable`.
#[allow(clippy::too_many_arguments)]
pub fn check_authorization(
    key_data: &[u8], ua: &[u8; 32], purpose: &[u8; 32], digest: &[u8; 32], slots: &[MemberSig], domain: &Domain, members: &Members,
    accepted: Option<&Accepted>,
) -> Result<()> {
    if !is_record_of(0x0120, key_data, ua)? {
        return Err(UAError::Unauthorized);
    }
    let md = member_digest(ua, &ua_message(0x0120, purpose, digest)?);
    let bits = Bits::new(accepted);
    bits.verdict(auth_ok(ua, key_data, &md, slots, domain, members, &bits)?, UAError::Unauthorized)
}
fn auth_ok(id: &[u8; 32], d: &[u8], md: &[u8; 32], slots: &[MemberSig], domain: &Domain, members: &Members, bits: &Bits) -> Result<bool> {
    let structure = MsigStructure::from_key_data(d)?;
    let keys = member_keys(d, members)?;
    let (mut acc, mut next) = (0u32, 0u16);
    for s in slots {
        let i = s.index as usize;
        let Some(m) = structure.members.get(i) else { return Ok(false) };
        if acc >= structure.threshold.into() || s.index < next || !bits.slot(id, s.index) {
            return Ok(false);
        }
        next = s.index + 1;
        let ok = if m.kind == 0x0120 {
            // `lift`: the inner slots carry no list, so a third level has nothing to sign with
            let lifted: Vec<MemberSig> = s.members.iter().map(|x| MemberSig { index: x.index, members: vec![], sig: x.sig.clone() }).collect();
            s.sig.is_empty() && auth_ok(&m.id, &keys[i], &inner_digest(&m.id, md)?, &lifted, domain, members, bits)?
        } else {
            s.members.is_empty() && leaf_ok(m, &keys[i], &ua_auth_digest(domain, &m.id, &purpose_tag("member")?, md), md, &s.sig)?
        };
        if !ok {
            return Ok(false);
        }
        acc += u32::from(m.weight);
    }
    Ok(acc >= structure.threshold.into())
}
