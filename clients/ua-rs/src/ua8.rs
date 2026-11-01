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
/// `pqz_pop_hash`; a relayer may hold only that) and the initial KEM key `kem_pk` (its record is always version 0, owner
/// 2026-10-31: no version input); `None` / empty = absent. Only holders may carry them (`PqzHolder`, `KemHolder`; an `msig` needs `key_data` to show it is PQ-eligible); a
/// PQZ key always comes with its proof hash and only with it (`PqzPopHash`).
pub fn holder_pop_message(
    kind: u16, ua: &[u8; 32], key_data: &[u8], pqz_key: Option<&[u8]>, pqz_pop: Option<&[u8]>, pqz_pop_hash: Option<&[u8; 32]>,
    kem_pk: Option<&[u8]>,
) -> Result<HolderPop> {
    let pqz_key = pqz_key.filter(|k| !k.is_empty());
    let kem = kem_pk.filter(|pk| !pk.is_empty());
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

/// The portable purposes (POP_V2, KEM, PQZ_KEY): the only ones where a code-less or EIP-7702-designator native msig member
/// signs the record's typed digest itself (`eth_signTypedData_v4`, 65-byte r ‖ s ‖ v, low-s, v 27 / 28; a contract member
/// answers ERC-1271 `isValidSignature(typedDigest, sig)`; TS-D4); every other purpose stays UAAuth (CTR-MTX-14).
pub fn is_portable_purpose(tag: &[u8; 32]) -> bool {
    [pop_v2_tag(), purpose_tag("kem").expect("kem"), purpose_tag("pqz-key").expect("pqz-key")].contains(tag)
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
/// One `msig` member's signature (`key_data` always empty, CTR-UA-33).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MemberSig {
    pub index: u16,
    pub key_data: Vec<u8>,
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
fn member_sigs_len(m: &[MemberSig]) -> usize {
    32 + m.iter().map(|s| 32 + 96 + tail_len(&s.key_data) + tail_len(&s.sig)).sum::<usize>()
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
/// [`REGISTER_CALLDATA_LIMIT`]).
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
    let pqz_pop_hash = if i.pqz_key.is_empty() && zero32(&i.pqz_pop_hash) {
        [0; 32]
    } else {
        proof_hash_of(Some(&i.pqz_pop), Some(&i.pqz_pop_hash))?
    };
    let kem = KemKey::from_kem_pk(&i.kem_pk)?;
    let attrs = UAAttrs { pqz_key: i.pqz_key.clone(), pqz_pop_hash, kem: kem.clone(), kem_pk_hash: [0; 32] };
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
