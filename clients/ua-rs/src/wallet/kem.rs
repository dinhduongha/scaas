// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The UA KEM key, scheme 1 (CTR-UA-32: `kemPk = 0x01 ‖ ek (1,568) ‖ pk_X (32)`, 1,601 B), its encapsulation and
//! decapsulation with the checks, and the combiner (spec §6.1, §6.2; clientkeys `kem.js`; T7):
//!
//! ```text
//! kemSeed  = HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.kem.v1", info = "scaas.kem.1" ‖ ua ‖ be64 version, L = 96)
//! (ek, dk) = ML-KEM-1024.KeyGen_internal(d = kemSeed[0:32], z = kemSeed[32:64]);  sk_X = kemSeed[64:96], pk_X = X25519(sk_X, 9)
//! ss       = SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1")
//! ```
//!
//! [`UaKey::kem_key`] takes no wallet: the seed is the one in the UA key handle's own store (C-05), so no call can combine a
//! handle with another wallet's seed. KEM holders only (`mldsa44`, `mldsa65`, `fndsa512`, `mldsa87`, `fndsa1024`; else
//! `KemHolder`); an `msig` has no KEM key (MD-11): no wallet handle of an `msig` exists, seal to its accepted members. The store
//! keeps the 96-byte `kemSeed` (`d ‖ z ‖ sk_X`: the ML-KEM key's seed form and `sk_X`), the crate's key rebuilt per call; the
//! FIPS 203 §7.3 decapsulation-key check runs once per store per `(ua, version)`, its record in the store. `m` and `e` come
//! from the OS RNG inside; fixed ones only through feature `vectors`. Whoever holds a [`KemKeyPair`] has a decapsulation
//! oracle. UNAUDITED.
use super::seal::RecipientId;
use super::store::{Handle, SecretStore};
use super::{Error, KeyId, Result, UaKey};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use ml_kem::{Decapsulate, KeyExport, MlKem1024};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use sha3::{Digest, Sha3_256};
use zeroize::{Zeroize, Zeroizing};

type Dk = ml_kem::DecapsulationKey<MlKem1024>;
type Ek = ml_kem::EncapsulationKey<MlKem1024>;

const EK: usize = 1568;
const DK: usize = 3168;
const SEED: usize = 96;
const KEM_PK_LEN: usize = 1 + EK + 32;
const LABEL: &[u8] = b"scaas.kem.1";
const SALT: &[u8] = b"scaas.ua.kem.v1";

/// `(mlkem_ct, x25519_eph, ss)`.
pub type Encapsulated = (Vec<u8>, [u8; 32], Zeroizing<[u8; 32]>);

/// A KEM holder's kind (CTR-UA-32); an `msig` is never one here (MD-11).
pub fn is_kem_holder(kind: u16) -> bool {
    crate::is_pqz_holder(kind)
}

fn kem_seed(seed: &[u8; 64], ua: &[u8; 32], version: u64) -> Result<Zeroizing<Vec<u8>>> {
    let mut okm = Zeroizing::new(vec![0u8; SEED]);
    Hkdf::<Sha256>::new(Some(SALT), seed)
        .expand_multi_info(&[LABEL, ua, &version.to_be_bytes()], &mut okm)
        .map_err(|_| Error::Argument)?;
    Ok(okm)
}

/// The ML-KEM key of a 96-byte KEM seed (`KeyGen_internal(d, z)`).
fn dk_of(s: &[u8]) -> Result<Dk> {
    let d_z = Zeroizing::new(ml_kem::Seed::try_from(s.get(..64).ok_or(Error::Argument)?).map_err(|_| Error::Argument)?);
    Ok(Dk::from_seed(*d_z))
}

fn sk_x(s: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(s.get(64..SEED).and_then(|b| b.try_into().ok()).ok_or(Error::Argument)?))
}

/// `kemPk = 0x01 ‖ ek ‖ pk_X` of a 96-byte KEM seed.
fn kem_pk_of(s: &[u8]) -> Result<Vec<u8>> {
    if s.len() != SEED {
        return Err(Error::Argument);
    }
    let ek = dk_of(s)?.encapsulation_key().to_bytes();
    let pk_x = MontgomeryPoint::mul_base_clamped(*sk_x(s)?).to_bytes();
    Ok([&[1u8][..], &ek, &pk_x].concat())
}

/// RFC 7748 X25519(k, u) (the top bit of `u` ignored); a small-order `u` gives the all-zero output.
pub fn x25519(k: &[u8; 32], u: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(MontgomeryPoint(*u).mul_clamped(*k).to_bytes())
}

/// FIPS 203 §7.2 modulus check: `ByteEncode12(ByteDecode12(ek[0:1536])) == ek[0:1536]`, i.e. every coefficient < q, of a
/// 1,568-byte `ek`.
pub fn ek_modulus_ok(ek: &[u8]) -> bool {
    let lt_q = |c: &[u8]| match c {
        [a, b, c] => (u16::from(*a) | u16::from(*b & 15) << 8) < 3329 && (u16::from(*b >> 4) | u16::from(*c) << 4) < 3329,
        _ => false,
    };
    ek.len() == EK && ek.get(..1536).is_some_and(|t| t.chunks(3).all(lt_q))
}

/// FIPS 203 §7.3 decapsulation-key check of an expanded `dk`: its length, and `H(dk[384k : 768k + 32]) == dk[768k + 32 :
/// 768k + 64]`.
pub fn dk_check_ok(dk: &[u8]) -> bool {
    match (dk.len(), dk.get(1536..3104), dk.get(3104..3136)) {
        (DK, Some(ek), Some(h)) => <[u8; 32]>::from(Sha3_256::digest(ek)).as_slice() == h,
        _ => false,
    }
}

/// The §7.3 check of the key a KEM seed derives (a self-test: a derived key always passes it).
#[allow(deprecated)] // the expanded form exists here for the check only
fn self_test(s: &[u8]) -> Result<()> {
    use ml_kem::ExpandedKeyEncoding;
    let mut dk = dk_of(s)?.to_expanded_bytes();
    let ok = dk_check_ok(&dk);
    dk.zeroize();
    ok.then_some(()).ok_or(Error::KemCheck)
}

fn combine(ss_m: &[u8], ss_x: &[u8; 32], e: &[u8; 32], pk_x: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut h = Sha3_256::new();
    for part in [ss_m, ss_x, e, pk_x, LABEL] {
        h.update(part);
    }
    Zeroizing::new(h.finalize().into())
}

fn encaps(kem_pk: &[u8], m: &[u8; 32], e: &[u8; 32]) -> Result<Encapsulated> {
    if kem_pk.first() != Some(&1) || kem_pk.len() != KEM_PK_LEN {
        return Err(Error::KemCheck);
    }
    let (ek, pk_x) = kem_pk.get(1..).and_then(|b| b.split_at_checked(EK)).ok_or(Error::KemCheck)?;
    if !ek_modulus_ok(ek) {
        return Err(Error::KemCheck);
    }
    // the crate runs the same type and modulus checks (FIPS 203 §7.2) again
    let ek = Ek::new(&ml_kem::Key::<Ek>::try_from(ek).map_err(|_| Error::KemCheck)?).map_err(|_| Error::KemCheck)?;
    let pk_x: &[u8; 32] = pk_x.try_into().map_err(|_| Error::KemCheck)?;
    let ss_x = x25519(e, pk_x);
    if *ss_x == [0; 32] {
        return Err(Error::KemCheck); // a small-order pk_X
    }
    let big_e = MontgomeryPoint::mul_base_clamped(*e).to_bytes();
    let m = Zeroizing::new(ml_kem::B32::from(*m));
    let (ct, mut ss_m) = ek.encapsulate_deterministic(&m);
    let ss = combine(&ss_m, &ss_x, &big_e, pk_x);
    ss_m.zeroize();
    Ok((ct.to_vec(), big_e, ss))
}

/// `(mlkem_ct, x25519_eph, ss)` to `kem_pk`, `m` and `e` from the OS RNG: `KemCheck` for a scheme other than 1, a length other
/// than 1,601, an `ek` coefficient ≥ q, or an all-zero `ss_X` (a small-order `pk_X`). Needs no secret.
pub fn kem_encaps(kem_pk: &[u8]) -> Result<Encapsulated> {
    let (mut m, mut e) = (Zeroizing::new([0u8; 32]), Zeroizing::new([0u8; 32]));
    OsRng.try_fill_bytes(&mut m[..]).map_err(|_| Error::Rng)?;
    OsRng.try_fill_bytes(&mut e[..]).map_err(|_| Error::Rng)?;
    encaps(kem_pk, &m, &e)
}

fn decaps(s: &[u8], pk_x: &[u8], mlkem_ct: &[u8], eph: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(mlkem_ct).map_err(|_| Error::KemCheck)?; // 1,568 bytes
    let ss_x = x25519(&*sk_x(s)?, eph);
    if *ss_x == [0; 32] {
        return Err(Error::KemCheck); // a small-order E: not contributory
    }
    // a wrong ciphertext gives another ss (ML-KEM's implicit rejection), never a distinct error
    let mut ss_m = dk_of(s)?.decapsulate(&ct);
    let ss = combine(&ss_m, &ss_x, eph, pk_x);
    ss_m.zeroize();
    Ok(ss)
}

/// A KEM key: its `kemPk` and the handle of its 96-byte seed in a secret store (a UA's: its wallet's store, revoked with
/// it; an ephemeral key's: a store of its own, wiped on drop). No secret bytes of its own, no `Clone`.
pub struct KemKeyPair {
    kem_pk: Vec<u8>,
    recipient: RecipientId,
    secret: Handle,
}

impl KemKeyPair {
    /// A KEM key of no UA (a device without a seed yet, a link session), from the OS RNG; never stored.
    pub fn generate_ephemeral() -> Result<KemKeyPair> {
        let mut s = Zeroizing::new(vec![0u8; SEED]);
        OsRng.try_fill_bytes(&mut s).map_err(|_| Error::Rng)?;
        KemKeyPair::ephemeral(&s)
    }

    fn ephemeral(s: &[u8]) -> Result<KemKeyPair> {
        let kem_pk = kem_pk_of(s)?;
        self_test(s)?; // its store's only key, checked once
        let recipient = RecipientId::KemPkHash(crate::keccak256(&kem_pk));
        Ok(KemKeyPair { kem_pk, recipient, secret: SecretStore::single(s)? })
    }

    /// `0x01 ‖ ek ‖ pk_X`, 1,601 bytes.
    pub fn kem_pk(&self) -> Vec<u8> {
        self.kem_pk.clone()
    }

    /// The id a container names this key by (spec §6.3): `{ua, version}` of a UA's key, `keccak256(kemPk)` of an ephemeral one.
    pub fn recipient(&self) -> RecipientId {
        self.recipient
    }

    /// A second handle of the same key (a link session's probe, feature `vectors`).
    #[cfg_attr(not(feature = "vectors"), allow(dead_code))]
    pub(super) fn dup(&self) -> KemKeyPair {
        KemKeyPair { kem_pk: self.kem_pk.clone(), recipient: self.recipient, secret: self.secret.dup() }
    }

    /// Wipes the key's store and revokes every handle of it: a link session's own store (spec §6.3), never a wallet's.
    pub(super) fn wipe_own_store(&self) {
        self.secret.revoke_store();
    }

    /// `ss` of `(mlkem_ct, x25519_eph)`: `KemCheck` for an `mlkem_ct` of other than 1,568 bytes or a small-order `E`;
    /// `KeyRevoked` once the wallet was locked. ML-KEM's implicit rejection kept: a wrong `mlkem_ct` gives another `ss`.
    pub fn decaps(&self, mlkem_ct: &[u8], x25519_eph: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let pk_x = self.kem_pk.get(1 + EK..).ok_or(Error::Argument)?;
        self.secret.with(|s| decaps(s, pk_x, mlkem_ct, x25519_eph))?
    }
}

impl UaKey {
    /// The UA's KEM key of record version `version` (0 = the `register` key), derived from this handle's own store (spec
    /// §6.1, C-05; no wallet argument): `KemHolder` for a kind that holds none, `KeyRevoked` once the wallet was locked. The
    /// FIPS 203 §7.3 check runs once per store per `(ua, version)`.
    pub fn kem_key(&self, version: u64) -> Result<KemKeyPair> {
        let ua = match self.ua {
            Some(ua) if is_kem_holder(self.kind) => ua,
            _ => return Err(Error::KemHolder),
        };
        let id = KeyId::Kem(ua, version);
        let (secret, kem_pk) = self.secret.derive(id, |seed| {
            let s = kem_seed(seed, &ua, version)?;
            let kem_pk = kem_pk_of(&s)?;
            Ok((s, kem_pk))
        })?;
        secret.self_test(id, self_test)?;
        secret.note(|m| m.add_kem(ua, version));
        Ok(KemKeyPair { kem_pk, recipient: RecipientId::Ua { ua, version }, secret })
    }
}

/// Test-only entry points (feature `vectors`, never in a release build).
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;

    /// [`kem_encaps`] with the given `m` (the ML-KEM message) and `e` (the X25519 ephemeral secret).
    pub fn vectors_encaps(kem_pk: &[u8], m: &[u8; 32], e: &[u8; 32]) -> Result<Encapsulated> {
        encaps(kem_pk, m, e)
    }

    /// `KeyGen_internal(d, z)`: `ek` and the expanded `dk`.
    #[allow(deprecated)]
    pub fn vectors_mlkem_keygen(d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Zeroizing<Vec<u8>>) {
        use ml_kem::ExpandedKeyEncoding;
        let dk = Dk::from_seed(ml_kem::B32::from(*d).concat(ml_kem::B32::from(*z)));
        (dk.encapsulation_key().to_bytes().to_vec(), Zeroizing::new(dk.to_expanded_bytes().to_vec()))
    }

    /// `Encaps_internal(ek, m)`: `(c, K)`.
    pub fn vectors_mlkem_encaps(ek: &[u8], m: &[u8; 32]) -> Result<(Vec<u8>, Zeroizing<[u8; 32]>)> {
        let ek = Ek::new(&ml_kem::Key::<Ek>::try_from(ek).map_err(|_| Error::KemCheck)?).map_err(|_| Error::KemCheck)?;
        let (c, k) = ek.encapsulate_deterministic(&ml_kem::B32::from(*m));
        Ok((c.to_vec(), Zeroizing::new(k.into())))
    }

    /// `Decaps_internal(dk, c)` with an expanded `dk`.
    #[allow(deprecated)]
    pub fn vectors_mlkem_decaps(dk: &[u8], c: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        use ml_kem::ExpandedKeyEncoding;
        let dk = ml_kem::ExpandedDecapsulationKey::<MlKem1024>::try_from(dk).map_err(|_| Error::KemCheck)?;
        let dk = Dk::from_expanded_bytes(&dk).map_err(|_| Error::KemCheck)?;
        let c = ml_kem::Ciphertext::<MlKem1024>::try_from(c).map_err(|_| Error::KemCheck)?;
        Ok(Zeroizing::new(dk.decapsulate(&c).into()))
    }

    impl KemKeyPair {
        /// The ephemeral key of 96 given bytes laid out as `kemSeed`.
        pub fn vectors_ephemeral(bytes: &[u8; 96]) -> Result<KemKeyPair> {
            KemKeyPair::ephemeral(bytes)
        }
        /// Whether the seed the handle's operations read lies in its store's arena and outside the handle itself.
        pub fn vectors_secret_in_arena(&self) -> Result<bool> {
            self.secret.in_arena((self as *const Self as usize, std::mem::size_of::<Self>()))
        }
    }
}
#[cfg(feature = "vectors")]
pub use vectors::{vectors_encaps, vectors_mlkem_decaps, vectors_mlkem_encaps, vectors_mlkem_keygen};
