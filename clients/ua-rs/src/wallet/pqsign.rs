// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQ signers (spec §3; T3b). ML-DSA-44 / -65 / -87 (`0x0130`, `0x0131`, `0x0134`): FIPS 204
//! `Sign_internal(M' = 0x00 ‖ 0x00 ‖ pq_msg, rnd)`, hedged with 32 bytes of the OS RNG. SLH-DSA-SHA2-128s (`0x0133`): FIPS 205
//! `slh_sign_internal(M', opt_rand)` with 16 bytes of the OS RNG. Falcon-padded-512 / -1024 (`0x0132`, `0x0135`): PQClean's
//! signer over `ua_msg` itself, with 88 bytes of the OS RNG (`src/falcon.rs`). `pq_msg = keccak256(TAG(kind) ‖ ua_msg)`
//! ([`crate::pq::signed_message`], CTR-UA-23), so the context is empty by construction. The arena keeps what a signer
//! rebuilds its key from: ML-DSA's 32-byte seed ξ, SLH-DSA's 64-byte key `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` (no keygen
//! per signature), Falcon's PQClean secret key; a crate key type lives for one call and is wiped on drop (`zeroize`), and
//! Falcon's bytes go from the arena to the C code with no copy. Fixed randomness only through feature `vectors`. UNAUDITED.
use super::{Error, Result};
use crate::falcon;
use crate::pq::signed_message;
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, MlDsaParams};
use rand_core::{OsRng, RngCore};
use slh_dsa::{Sha2_128s, VerifyingKey};
use zeroize::{Zeroize, Zeroizing};

type SlhSigningKey = slh_dsa::SigningKey<Sha2_128s>;

/// Whether `kind` is a PQ signing kind.
pub(crate) fn is_pq(kind: u16) -> bool {
    matches!(kind, 0x0130..=0x0135)
}

fn falcon_params(kind: u16) -> Result<falcon::Params> {
    match kind {
        0x0132 => Ok(falcon::FNDSA512),
        0x0135 => Ok(falcon::FNDSA1024),
        _ => Err(Error::Argument),
    }
}

/// Bytes of randomness per signature: ML-DSA `rnd`, SLH-DSA `opt_rand`, Falcon nonce ‖ sampler seed.
fn rnd_len(kind: u16) -> Result<usize> {
    match kind {
        0x0130 | 0x0131 | 0x0134 => Ok(32),
        0x0133 => Ok(16),
        0x0132 | 0x0135 => Ok(falcon::RND_LEN),
        _ => Err(Error::Argument),
    }
}

/// What the arena keeps for PQ kind `kind` from its HKDF seed (32 bytes for ML-DSA, 48 for SLH-DSA and Falcon), and the
/// key data. `KindUnavailable` for Falcon on a build without it (wasm32).
pub(crate) fn keypair(kind: u16, seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    match kind {
        0x0130 => mldsa_keypair::<MlDsa44>(seed),
        0x0131 => mldsa_keypair::<MlDsa65>(seed),
        0x0134 => mldsa_keypair::<MlDsa87>(seed),
        0x0133 => {
            let part = |r: std::ops::Range<usize>| seed.get(r).ok_or(Error::Argument);
            if seed.len() != 48 {
                return Err(Error::Argument);
            }
            let sk = SlhSigningKey::slh_keygen_internal(part(0..16)?, part(16..32)?, part(32..48)?);
            let mut b = sk.to_bytes();
            let secret = Zeroizing::new(b.to_vec());
            b.as_mut_slice().zeroize();
            Ok((secret, AsRef::<VerifyingKey<Sha2_128s>>::as_ref(&sk).to_bytes().to_vec()))
        }
        0x0132 | 0x0135 => {
            let p = falcon_params(kind)?;
            if !falcon::AVAILABLE {
                return Err(Error::KindUnavailable);
            }
            let (mut pk, mut sk) = (vec![0u8; p.pk], Zeroizing::new(vec![0u8; p.sk]));
            if !falcon::keypair(p, seed, &mut pk, &mut sk) {
                return Err(Error::Argument);
            }
            Ok((sk, pk))
        }
        _ => Err(Error::Argument),
    }
}

fn mldsa_keypair<P: MlDsaParams>(seed: &[u8]) -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    use ml_dsa::Keypair;
    let xi = Zeroizing::new(ml_dsa::Seed::try_from(seed).map_err(|_| Error::Argument)?);
    let vk = ml_dsa::SigningKey::<P>::from_seed(&xi).verifying_key().encode().to_vec();
    Ok((Zeroizing::new(seed.to_vec()), vk))
}

/// The signature of `ua_msg` with `secret` (as [`keypair`] keeps it): randomness from the OS RNG, or `fixed` (feature
/// `vectors` only: exactly the kind's length; ML-DSA zero = the deterministic variant, SLH-DSA `PK.seed` = its deterministic
/// variant).
pub(crate) fn sign(kind: u16, secret: &[u8], ua_msg: &[u8; 32], fixed: Option<&[u8]>) -> Result<Vec<u8>> {
    let mut rnd = Zeroizing::new(vec![0u8; rnd_len(kind)?]);
    match fixed {
        None => OsRng.try_fill_bytes(&mut rnd).map_err(|_| Error::Rng)?,
        Some(f) if f.len() == rnd.len() => rnd.copy_from_slice(f),
        Some(_) => return Err(Error::Argument),
    }
    let m = signed_message(kind, ua_msg); // pq_msg (ML-DSA, SLH-DSA), ua_msg (Falcon)
    let mp: [&[u8]; 2] = [&[0, 0], &m]; // M' = 0x00 (pure) ‖ 0x00 (context length) ‖ pq_msg
    match kind {
        0x0130 => mldsa::<MlDsa44>(&seed_key::<MlDsa44>(secret)?, &mp, &rnd),
        0x0131 => mldsa::<MlDsa65>(&seed_key::<MlDsa65>(secret)?, &mp, &rnd),
        0x0134 => mldsa::<MlDsa87>(&seed_key::<MlDsa87>(secret)?, &mp, &rnd),
        0x0133 => slhdsa(secret, &mp, Some(&rnd)),
        _ => {
            let p = falcon_params(kind)?;
            if !falcon::AVAILABLE {
                return Err(Error::KindUnavailable);
            }
            let mut sig = vec![0u8; p.sig];
            if falcon::sign(p, secret, &m, &rnd, &mut sig) {
                Ok(sig)
            } else {
                Err(Error::Argument)
            }
        }
    }
}

fn seed_key<P: MlDsaParams>(secret: &[u8]) -> Result<ml_dsa::SigningKey<P>> {
    let xi = Zeroizing::new(ml_dsa::Seed::try_from(secret).map_err(|_| Error::Argument)?);
    Ok(ml_dsa::SigningKey::<P>::from_seed(&xi))
}

fn mldsa<P: MlDsaParams>(sk: &ml_dsa::SigningKey<P>, mp: &[&[u8]], rnd: &[u8]) -> Result<Vec<u8>> {
    let rnd = ml_dsa::B32::try_from(rnd).map_err(|_| Error::Argument)?;
    Ok(sk.expanded_key().sign_internal(mp, &rnd).encode().to_vec())
}

fn slhdsa(secret: &[u8], mp: &[&[u8]], opt_rand: Option<&[u8]>) -> Result<Vec<u8>> {
    let sk = SlhSigningKey::try_from(secret).map_err(|_| Error::Argument)?;
    if opt_rand.is_some_and(|r| r.len() != 16) {
        return Err(Error::Argument); // the crate panics on another length
    }
    Ok(sk.slh_sign_internal(mp, opt_rand).to_bytes().to_vec())
}

/// The FIPS internal signing function over `mprime` as given (feature `vectors`: the ACVP `sigGen` answers, both
/// interfaces): ML-DSA with the expanded secret key of FIPS 204 (`skEncode`) and `rnd` (`None` = zero), SLH-DSA with its
/// 64-byte key and `opt_rand` (`None` = `PK.seed`).
#[cfg(feature = "vectors")]
pub fn sign_internal(kind: u16, sk: &[u8], mprime: &[u8], rnd: Option<&[u8]>) -> Result<Vec<u8>> {
    #[allow(deprecated)] // the expanded encoding: the form ACVP gives its keys in
    fn expanded<P: MlDsaParams>(sk: &[u8], mprime: &[u8], rnd: &[u8]) -> Result<Vec<u8>> {
        let enc = ml_dsa::ExpandedSigningKeyBytes::<P>::try_from(sk).map_err(|_| Error::Argument)?;
        let rnd = ml_dsa::B32::try_from(rnd).map_err(|_| Error::Argument)?;
        Ok(ml_dsa::ExpandedSigningKey::<P>::from_expanded(&enc).sign_internal(&[mprime], &rnd).encode().to_vec())
    }
    let zero = [0u8; 32];
    match kind {
        0x0130 => expanded::<MlDsa44>(sk, mprime, rnd.unwrap_or(&zero)),
        0x0131 => expanded::<MlDsa65>(sk, mprime, rnd.unwrap_or(&zero)),
        0x0134 => expanded::<MlDsa87>(sk, mprime, rnd.unwrap_or(&zero)),
        0x0133 => slhdsa(sk, &[mprime], rnd),
        _ => Err(Error::Argument),
    }
}
