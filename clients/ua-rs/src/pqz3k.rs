// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ three-key model (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, CTR-PQZ-38, CTR-PQZ-40, CTR-PQZ-41), the parts a signer
//! reproduces without PQZ arithmetic: the scoped key seeds of `offchain-shared` / `offchain-token` (K3-2), the opening KEM seed
//! (K3-6b), the leg seed (K3-4), an opening token's `memoHash`, the holder's `PqzRollOver` digest. The sealed opening's KEM and
//! the holder check (K3-7) are pqz-ffi's (`opening`). UNAUDITED.
use crate::keccak;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        Mac::update(&mut m, p);
    }
    m.finalize().into_bytes().into()
}

/// RFC 5869 HKDF-SHA256, `out.len() ≤ 255 · 32`.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac(salt, &[ikm]);
    let (mut t, mut done, mut i) = (Vec::new(), 0, 1u8);
    while done < out.len() {
        let b = hmac(&prk, &[&t, info, &[i]]);
        let n = (out.len() - done).min(32);
        out[done..done + n].copy_from_slice(&b[..n]);
        (t, done, i) = (b.to_vec(), done + n, i + 1);
    }
}

/// K3-2: the PQZ key seed of class `offchain-shared` (`token` `None`) or `offchain-token`, 32 bytes:
/// `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = label ‖ u32 account ‖ u32 index ‖ chainUid ‖ [token] ‖ be64 v)`.
pub fn pqz_scoped_key_seed(seed: &[u8; 64], account: u32, index: u32, chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 32] {
    let label: &[u8] = if token.is_some() { b"scaas.ua.pqz-mlwe.offchain-token.v1" } else { b"scaas.ua.pqz-mlwe.offchain-shared.v1" };
    let info = [label, &account.to_be_bytes(), &index.to_be_bytes(), chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    let mut o = [0u8; 32];
    hkdf(b"scaas.ua.pq.v1", seed, &info, &mut o);
    o
}

/// K3-6b: the opening KEM seed of a scoped record, 96 bytes (ML-KEM `d ‖ z`, then the X25519 secret).
pub fn open_kem_seed(seed: &[u8; 64], ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 96] {
    let label: &[u8] = if token.is_some() { b"scaas.kem.pqz-opening-token.1" } else { b"scaas.kem.pqz-opening.1" };
    let info = [label, ua, chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    let mut o = [0u8; 96];
    hkdf(b"scaas.ua.kem.v1", seed, &info, &mut o);
    o
}

/// K3-4: `seed_leg = SHAKE256("SCAAS-PQZ-ENC-LEG-V1" ‖ seed_enc ‖ be4(0) ‖ toUA ‖ keccak256(pk_t))[0..32)`, `keccak256(pk_t)` given.
pub fn leg_seed(seed_enc: &[u8; 32], to_ua: &[u8; 32], pk_t_hash: &[u8; 32]) -> [u8; 32] {
    let mut x = Shake256::default();
    for p in [&b"SCAAS-PQZ-ENC-LEG-V1"[..], seed_enc, &[0u8; 4], to_ua, pk_t_hash] {
        x.update(p);
    }
    let mut o = [0u8; 32];
    x.finalize_xof().read(&mut o);
    o
}

/// CTR-PQZ-40: an opening token's op 1 `memoHash = keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))`.
pub fn opening_memo_hash(memo: &[u8], own_tag: &[u8; 32], openings: &[&[u8]]) -> [u8; 32] {
    keccak(&[memo, own_tag, &keccak(openings)])
}

/// CTR-PQZ-41: `PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,
/// uint64 validUntilBlock,bytes32 chainUid)`, signed by the holder under `zether-auth` in the token's domain.
pub const ROLL_OVER_TYPE: &str = "PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,\
bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)";

fn w64(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

/// The `PqzRollOver` struct hash: `rollSeq` and `rolled` the token's `pqzAccount(ua, keyVersion)`, `entriesHash` over the
/// entries' contents (`h(i) = keccak256(abi.encode(i, slot without the mark, blob code hash or 0))`).
#[allow(clippy::too_many_arguments)]
pub fn roll_over_struct_hash(ua: &[u8; 32], key_version: u64, roll_seq: u64, rolled: u64, n: u64, skip: &[u64], entries_hash: &[u8; 32],
    valid_until_block: u64, chain_uid: &[u8; 32]) -> [u8; 32] {
    let sk: Vec<u8> = skip.iter().flat_map(|s| w64(*s)).collect();
    keccak(&[&keccak(&[ROLL_OVER_TYPE.as_bytes()]), ua, &w64(key_version), &w64(roll_seq), &w64(rolled), &w64(n), &keccak(&[&sk]),
        entries_hash, &w64(valid_until_block), chain_uid])
}

/// A PQZ key class (CTR-PQZ-37): `registry` (class 1), `offchain-shared` (class 2), `offchain-token` (class 3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    Registry,
    OffchainShared,
    OffchainToken,
}

/// A credit as the wallet reads it from state for the holder check: its key class and scope (the token; zero for class 2),
/// the holder's key version, the stored opening and its `aad` (CTR-PQZ-40), and what the binding's check reads besides.
pub struct OpeningCredit<'a> {
    pub class: KeyClass,
    pub scope: [u8; 20],
    pub version: u64,
    pub opening: &'a [u8],
    pub aad: &'a [u8],
}

/// A credit of another class, scope or key version than the handle's, or any credit on a handle without the opening.
#[derive(Debug, PartialEq, Eq)]
pub struct Refused;

/// Owner ruling 2026-11-14 (CLI-SGN-51's Change; spec §13 "no bare class-2 decrypt", §14.18): the wallet's handle of one PQZ
/// key class and scope. It holds its record's opening KEM seed only (K3-6b), never the PQZ key seed: no method decrypts a
/// ciphertext or returns a secret. Its one entry, [`PqzKeyHandle::check`], refuses a credit of another class, scope or version
/// before the binding's check runs, then hands the opening KEM seed and the credit to that check (pqz-ffi
/// `opening::check_recipient`: open, Enc-expand, `u`, `w = Δ·d`, `O_t` recomputed; `None` is skip).
pub struct PqzKeyHandle {
    class: KeyClass,
    scope: [u8; 20],
    version: u64,
    open_kem_seed: Option<[u8; 96]>,
}

impl PqzKeyHandle {
    /// `token`: class 3's token (`None` otherwise); `opening`: always on class 2, never on class 1, the token's flag on class 3.
    pub fn new(seed: &[u8; 64], class: KeyClass, ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, version: u64,
        opening: bool) -> Result<Self, Refused>
    {
        let scope = match (class, token) {
            (KeyClass::OffchainToken, Some(t)) => *t,
            (KeyClass::OffchainToken, None) | (_, Some(_)) => return Err(Refused),
            _ => [0u8; 20],
        };
        if (class == KeyClass::OffchainShared && !opening) || (class == KeyClass::Registry && opening) {
            return Err(Refused);
        }
        let open_kem_seed = opening.then(|| open_kem_seed(seed, ua, chain_uid, token, version));
        Ok(Self { class, scope, version, open_kem_seed })
    }

    pub fn class(&self) -> KeyClass {
        self.class
    }

    pub fn scope(&self) -> [u8; 20] {
        self.scope
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    /// The holder check of `credit` by the binding's `check(open_kem_seed, credit)`; `Err(Refused)` before it runs when the
    /// credit is not this handle's (class, scope, version) or the handle has no opening.
    pub fn check<T>(&self, credit: &OpeningCredit, check: impl FnOnce(&[u8; 96], &OpeningCredit) -> Option<T>)
        -> Result<Option<T>, Refused>
    {
        let s = self.open_kem_seed.as_ref().ok_or(Refused)?;
        if credit.class != self.class || credit.scope != self.scope || credit.version != self.version {
            return Err(Refused);
        }
        Ok(check(s, credit))
    }
}

impl core::fmt::Debug for PqzKeyHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqzKeyHandle").field("class", &self.class).field("scope", &self.scope).field("version", &self.version)
            .field("opening", &self.open_kem_seed.is_some()).finish()
    }
}

impl Drop for PqzKeyHandle {
    fn drop(&mut self) {
        if let Some(s) = self.open_kem_seed.as_mut() {
            s.fill(0);
            core::hint::black_box(s); // keep the wipe
        }
    }
}
