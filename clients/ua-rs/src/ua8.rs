//! UA-8 portable registrations (P1, P2, P7; plan UA8-D1/D2): the chain-free PoP, the KEM record and the PQZ key record, as
//! typed EIP-712 structs under the name + version domain (typed-signing TS-D1 … TS-D4): no chain id, chain uid or registry.
//! The JS reference is clientkeys `src/ua.js`; `smartcontracts/vectors/ua/portable.json` pins every byte. The raw digests
//! before the typed records are in legacy/typed-signing/portable_raw.rs. UNAUDITED.
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
pub const PORTABLE_TYPES: [(&str, &str); 5] = [
    ("UAKemRecord", "UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)"),
    ("UAPortableRecord", "UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)"),
    ("UARegistration", "UARegistration(UAPortableRecord record,bytes32 pqzPopHash)UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)"),
    ("UAPqzKey", "UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)"),
    ("UAPqzKeyRecord", "UAPqzKeyRecord(UAPqzKey key,bytes32 pqzPopHash)UAPqzKey(bytes32 ua,bytes32 pqzKeyHash)"),
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
/// version 1 … 2^64 − 1, `kem_pk` = scheme byte ‖ key (empty: `KemKeyLength`; scheme not enabled: `KemScheme`; another
/// length: `KemKeyLength`). No record (`version` 0 and no key) is the zero record `UAKemRecord{ua, 0, 0, 0}` (TS-D2); the
/// `kem` word of a `UAPortableRecord`.
pub fn kem_record_hash(ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    let th = portable_typehash("UAKemRecord");
    if version == 0 && kem_pk.is_empty() {
        return Ok(keccak(&[&th, ua, &[0; 32], &[0; 32], &[0; 32]]));
    }
    if version == 0 {
        return Err(UAError::KemVersion);
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
/// The typed `UAKemRecord` digest `setKemKey` signs (a real record: version 0 is `KemVersion`).
pub fn kem_record_digest(ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    if version == 0 {
        return Err(UAError::KemVersion);
    }
    Ok(typed(&kem_record_hash(ua, version, kem_pk)?))
}
/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`.
pub fn kem_record_message(kind: u16, ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
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

/// A PQZ / KEM holder: a single-key PQ kind, or an `msig` whose key data is PQ-eligible (`key_data` shows it).
/// Malformed `msig` key data is `UAKeyData` (as in the JS), not "not a holder".
fn holds(kind: u16, key_data: &[u8]) -> Result<bool> {
    if is_pqz_holder(kind) {
        return Ok(true);
    }
    if kind == 0x0120 && !key_data.is_empty() {
        return msig_pqz_eligible(key_data);
    }
    Ok(false)
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
/// `pqz_pop_hash`; a relayer may hold only that) and the initial KEM record `(version >= 1, kem_pk)`; `None` / `(0, [])` =
/// absent. Only holders may carry them (`PqzHolder`, `KemHolder`; an `msig` needs `key_data` to show it is PQ-eligible); a
/// PQZ key always comes with its proof hash and only with it (`PqzPopHash`).
pub fn holder_pop_message(
    kind: u16, ua: &[u8; 32], key_data: &[u8], pqz_key: Option<&[u8]>, pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    kem: Option<(u64, &[u8])>,
) -> Result<HolderPop> {
    let pqz_key = pqz_key.filter(|k| !k.is_empty());
    let kem = kem.filter(|(v, pk)| *v != 0 || !pk.is_empty());
    if pqz_key.is_some() || kem.is_some() {
        let holder = holds(kind, key_data)?;
        if pqz_key.is_some() && !holder {
            return Err(UAError::PqzHolder(kind));
        }
        if kem.is_some() && !holder {
            return Err(UAError::KemHolder(kind));
        }
    }
    let pop_hash = proof_hash_of(pqz_pop, pqz_pop_hash)?;
    if pqz_key.is_some() != (pop_hash != [0; 32]) {
        return Err(UAError::PqzPopHash);
    }
    let pqz_key_hash = pqz_key.map(pqz_key_hash_of).transpose()?.unwrap_or([0; 32]);
    let (kem_version, kem_pk) = kem.unwrap_or((0, &[]));
    let kem_record_hash = kem_record_hash(ua, kem_version, kem_pk)?;
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
/// kem_record_hash))`, `kind` the registering kind (TS-D3); `kem` `None` / `(0, [])` = no KEM record.
pub fn pqz_reg_message(kind: u16, ua: &[u8; 32], pqz_key: &[u8], kem: Option<(u64, &[u8])>) -> Result<[u8; 32]> {
    let (kem_version, kem_pk) = kem.unwrap_or((0, &[]));
    let kem_record_hash = kem_record_hash(ua, kem_version, kem_pk)?;
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
    if !holds(kind, key_data)? {
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

/// The portable purposes (POP_V2, KEM, PQZ_KEY): the only ones where a code-less or EIP-7702-designator native msig member
/// signs the record's typed digest itself (`eth_signTypedData_v4`, 65-byte r ‖ s ‖ v, low-s, v 27 / 28; a contract member
/// answers ERC-1271 `isValidSignature(typedDigest, sig)`; TS-D4); every other purpose stays UAAuth (CTR-MTX-14).
pub fn is_portable_purpose(tag: &[u8; 32]) -> bool {
    [pop_v2_tag(), purpose_tag("kem").expect("kem"), purpose_tag("pqz-key").expect("pqz-key")].contains(tag)
}
