//! UA-8 portable registrations (P1, P2, P7; plan UA8-D1/D2): the chain-free PoP digests, the KEM record and the PQZ key
//! record. The JS reference is clientkeys `src/ua.js`; `smartcontracts/vectors/ua/portable.json` pins every byte. All
//! digests are keccak256 of 32-byte words (= `abi.encode`): no chain id, chain uid or registry. UNAUDITED.
use crate::*;

/// ML-KEM-1024 ek ‖ X25519 pk (X-Wing order): the only KEM key the registry stores (UA-8 P7).
pub const KEM_PK_LENGTH: usize = 1600;
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
pub fn kem_record_tag() -> [u8; 32] {
    keccak256(b"scaas.ua.kem-record.v1")
}
pub fn pqz_key_record_tag() -> [u8; 32] {
    keccak256(b"scaas.ua.pqz-key-record.v1")
}

/// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`, each hash 0 when absent.
pub fn portable_pop_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&pop_v2_tag(), ua, pqz_key_hash, kem_record_hash])
}
/// `keccak256(portablePopDigest ‖ pqzPopHash)`: what the signer's `pop` signs under `ua_message(kind, POP_V2, ·)`.
pub fn registration_digest(portable: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[portable, pqz_pop_hash])
}
/// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kemPk))`: version 1 … 2^64 − 1, a 1,600-byte key.
pub fn kem_record_digest(ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    if version == 0 {
        return Err(UAError::KemVersion);
    }
    if kem_pk.len() != KEM_PK_LENGTH {
        return Err(UAError::KemKeyLength);
    }
    Ok(keccak(&[&kem_record_tag(), ua, &word(version), &keccak256(kem_pk)]))
}
/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`.
pub fn kem_record_message(kind: u16, ua: &[u8; 32], version: u64, kem_pk: &[u8]) -> Result<[u8; 32]> {
    ua_message(kind, &purpose_tag("kem")?, &kem_record_digest(ua, version, kem_pk)?)
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

/// The portable PoP of a registration (UA-8 P1, P2), as [`holder_pop_message`] returns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HolderPop {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub kem_record_hash: [u8; 32],
    pub portable_pop_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    /// `ua_message(kind, POP_V2, registration_digest)`: what the signer's `pop` signs (every kind).
    pub message: [u8; 32],
    /// `msig` only: `member_digest(ua, message)`, what each member signs under `member` (a code-less native member by
    /// [`personal_sign_digest`], ruling C7).
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
    let kem_record_hash = kem.map(|(v, pk)| kem_record_digest(ua, v, pk)).transpose()?.unwrap_or([0; 32]);
    let portable = portable_pop_digest(ua, &pqz_key_hash, &kem_record_hash);
    let registration = registration_digest(&portable, &pop_hash);
    let message = ua_message(kind, &pop_v2_tag(), &registration)?;
    Ok(HolderPop {
        pqz_key_hash,
        pqz_pop_hash: pop_hash,
        kem_record_hash,
        portable_pop_digest: portable,
        registration_digest: registration,
        message,
        member_digest: (kind == 0x0120).then(|| member_digest(ua, &message)),
    })
}

/// The message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_pop_digest(ua, key_hash(pqz_key), kem_record_hash))`.
pub fn pqz_reg_message(ua: &[u8; 32], pqz_key: &[u8], kem: Option<(u64, &[u8])>) -> Result<[u8; 32]> {
    let kem = kem.filter(|(v, pk)| *v != 0 || !pk.is_empty());
    let kem_record_hash = kem.map(|(v, pk)| kem_record_digest(ua, v, pk)).transpose()?.unwrap_or([0; 32]);
    ua_message(PQZ_SCHEME, &pop_v2_tag(), &portable_pop_digest(ua, &pqz_key_hash_of(pqz_key)?, &kem_record_hash))
}

/// `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash)`: what a later PQZ key's `R_REG` proves over (no proof hash: no cycle).
pub fn pqz_key_digest(ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&pqz_key_record_tag(), ua, pqz_key_hash])
}
/// `keccak256(pqzKeyDigest ‖ pqzPopHash)`: what `setPqzKey`'s signature signs under `ua_message(kind, PURPOSE_PQZ_KEY, ·)`.
pub fn pqz_key_record_digest(key_digest: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[key_digest, pqz_pop_hash])
}

/// The PQZ key record of `setPqzKey` (ruling A1-I1), see [`pqz_key_record_message`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzKeyRecord {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub pqz_key_digest: [u8; 32],
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
    let record_digest = pqz_key_record_digest(&key_digest, &pop_hash);
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

/// EIP-191 `personal_sign` of a 32-byte digest: `keccak256("\x19Ethereum Signed Message:\n32" ‖ digest)`. What a code-less
/// native (EOA) `msig` member signs over the `member_digest` of a portable record only (POP_V2, KEM, PQZ_KEY; ruling C7);
/// every other purpose stays UAAuth (CTR-MTX-14).
pub fn personal_sign_digest(digest: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"\x19Ethereum Signed Message:\n32", digest])
}

/// The portable purposes (POP_V2, KEM, PQZ_KEY): the only ones a code-less native msig member signs by `personal_sign`.
pub fn is_portable_purpose(tag: &[u8; 32]) -> bool {
    [pop_v2_tag(), purpose_tag("kem").expect("kem"), purpose_tag("pqz-key").expect("pqz-key")].contains(tag)
}
