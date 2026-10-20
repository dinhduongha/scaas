//! Schnorr (zether-design §11.1), the UA registry's PoP and owner authorization of a Zether UA (accounts.md CTR-UA-07,
//! §1.7 Z-auth) and transfer disclosure (§12).

use ark_ff::Zero;
use rand_core::{CryptoRng, RngCore};

use crate::abi::{self, Tok};
use crate::curve::{
    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, ua_of, zether_tag, Fr,
    ZCurve, G,
};
use crate::keys::ZetherKey;
use crate::nonce::Nonces;
use crate::transcript::hash_to_scalar;
use crate::ZError;

fn challenge<C: ZCurve>(r: &G<C>, y: &G<C>, msg: &[u8; 32]) -> Fr<C> {
    let mut b = b"SCAAS-ZETHER-SCHNORR-V1".to_vec();
    b.extend(encode_point::<C>(r));
    b.extend(encode_point::<C>(y));
    b.extend_from_slice(msg);
    hash_to_scalar::<C>(&keccak256(&b))
}

/// Schnorr with an explicit nonce; returns `(R, e, z)`. Only for vectors and [`sign`].
#[doc(hidden)]
pub fn sign_with_k<C: ZCurve>(x: &Fr<C>, msg: &[u8; 32], k: &Fr<C>) -> (G<C>, Fr<C>, Fr<C>) {
    let g = generator::<C>();
    let r = g * k;
    let e = challenge::<C>(&r, &(g * x), msg);
    (r, e, *k + e * x)
}

/// `sig = R ‖ be32(z)`, hedged nonce (`k = H(x ‖ msg ‖ CSPRNG)`).
pub fn sign<C: ZCurve, R: RngCore + CryptoRng>(key: &ZetherKey<C>, msg: &[u8; 32], rng: &mut R) -> Vec<u8> {
    let mut secret = zeroize::Zeroizing::new(encode_scalar::<C>(&key.x).to_vec());
    secret.extend_from_slice(msg);
    let k = Nonces::new(&secret, rng).next::<C>();
    let (r, _, z) = sign_with_k(&key.x, msg, &k);
    let mut sig = encode_point::<C>(&r);
    sig.extend(encode_scalar::<C>(&z));
    sig
}

pub fn verify<C: ZCurve>(y: &G<C>, msg: &[u8; 32], sig: &[u8]) -> Result<(), ZError> {
    let pl = point_len::<C>();
    if sig.len() != pl + 32 {
        return Err(ZError::Verify("schnorr: length"));
    }
    let r = decode_point::<C>(&sig[..pl])?;
    let z = decode_scalar::<C>(&sig[pl..])?;
    if r.is_zero() || y.is_zero() {
        return Err(ZError::Verify("schnorr: R or Y is O"));
    }
    let e = challenge::<C>(&r, y, msg);
    if e.is_zero() || generator::<C>() * z - r - *y * e != G::<C>::zero() {
        return Err(ZError::Verify("schnorr"));
    }
    Ok(())
}

/// `purposeTag = keccak256("scaas.ua.purpose.<p>.v1")` (accounts.md CTR-UA-10): `pop`, `zether-owner`, …
pub fn purpose_tag(purpose: &str) -> [u8; 32] {
    keccak256(format!("scaas.ua.purpose.{purpose}.v1").as_bytes())
}

/// `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)` of this curve's Zether kind (CTR-UA-12) — what the
/// Zether key signs; the registry's `uaMessage(kind, purposeTag, digest)`.
pub fn ua_message<C: ZCurve>(purpose: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    keccak256(&[keccak256(b"scaas.ua.msg.v1"), zether_tag::<C>(), *purpose, *digest].concat())
}

/// `pop_digest = keccak256(abi.encode(POP_TAG, keccak256("evm:" ‖ decimal(chainId)), chainUid, registry, ua, pqzKeyHash))`
/// (CTR-UA-07) — the registry's `popDigest(ua, pqzKeyHash)`; 0 without a PQZ key (always, for a Zether UA).
pub fn pop_digest(chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    let chain_key = keccak256(format!("evm:{chain_id}").as_bytes());
    keccak256(&[purpose_tag("pop"), chain_key, *chain_uid, abi::addr(registry), *ua, *pqz_key_hash].concat())
}

/// The `pop` of `register(0x0141, Y, pop, "", "")`: Schnorr by `x` under the Zether tag over
/// `ua_message(POP, pop_digest(…, UA(Y), 0))`.
pub fn zether_pop<C: ZCurve, R: RngCore + CryptoRng>(
    key: &ZetherKey<C>,
    chain_id: u64,
    chain_uid: &[u8; 32],
    registry: &[u8; 20],
    rng: &mut R,
) -> Vec<u8> {
    let d = pop_digest(chain_id, chain_uid, registry, &key.ua(), &[0u8; 32]);
    sign(key, &ua_message::<C>(&purpose_tag("pop"), &d), rng)
}

pub fn verify_pop<C: ZCurve>(
    y: &G<C>,
    chain_id: u64,
    chain_uid: &[u8; 32],
    registry: &[u8; 20],
    pop: &[u8],
) -> Result<(), ZError> {
    let d = pop_digest(chain_id, chain_uid, registry, &ua_of::<C>(y), &[0u8; 32]);
    verify(y, &ua_message::<C>(&purpose_tag("pop"), &d), pop)
}

/// The `sig` of an owner op (`zetherRollOverSigned`, `zetherSetRollOverMode`):
/// `abi.encode(bytes(""), Schnorr by x over ua_message(zether-owner, digest))` — the registry reads `Y` from its record.
pub fn owner_auth<C: ZCurve, R: RngCore + CryptoRng>(key: &ZetherKey<C>, digest: &[u8; 32], rng: &mut R) -> Vec<u8> {
    let sig = sign(key, &ua_message::<C>(&purpose_tag("zether-owner"), digest), rng);
    abi::encode(&[Tok::Bytes(vec![]), Tok::Bytes(sig)])
}

// ---------------------------------------------------------------------------------------------
// Disclosure (§12)
// ---------------------------------------------------------------------------------------------

/// `ITransferDisclosure.OpeningKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum OpeningKind {
    SenderS = 0,
    ReceiverX = 1,
    Auditor = 2,
    /// The sender opens one leg with a Chaum-Pedersen proof on `s` instead of handing `s` over.
    SenderCp = 3,
}

/// `entryRef = keccak256(abi.encode(keccak256("SCAAS-ZETHER-ENTRY-V1"), chainid, chainUid, token, fromUA, sendCounter))`.
pub fn entry_ref(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], from_ua: &[u8; 32], send_counter: u64) -> [u8; 32] {
    keccak256(
        &[
            keccak256(b"SCAAS-ZETHER-ENTRY-V1"),
            abi::u256(chain_id),
            *chain_uid,
            abi::addr(token),
            *from_ua,
            abi::u256(send_counter),
        ]
        .concat(),
    )
}

/// Stored transfer record the opening is checked against: leg `index` of `entry_ref`
/// (`B_j = Y_t ‖ C_out ‖ D_out ‖ C_aud`; a single-recipient transfer has `index = 0`).
pub struct Entry<C: ZCurve> {
    pub chain_id: u64,
    pub chain_uid: [u8; 32],
    pub token: [u8; 20],
    pub entry_ref: [u8; 32],
    pub index: u64,
    pub y_t: G<C>,
    pub c_out: G<C>,
    pub d_out: G<C>,
    pub y_a: G<C>,
    pub c_aud: G<C>,
}

/// `SENDER_S`: `abi.encode(uint256 s)`.
pub fn open_sender<C: ZCurve>(s: &Fr<C>) -> Vec<u8> {
    encode_scalar::<C>(s).to_vec()
}

/// Challenge preimage up to (not including) `A1 ‖ A2`; also the opening nonce's public input.
fn cp_prefix<C: ZCurve>(e: &Entry<C>, amount: u64, kind: OpeningKind) -> Vec<u8> {
    let mut b = b"SCAAS-ZETHER-DISCLOSE-V1".to_vec();
    b.extend(abi::u256(e.chain_id));
    b.extend_from_slice(&e.chain_uid);
    b.extend_from_slice(&e.token);
    b.extend_from_slice(&e.entry_ref);
    b.extend(abi::u256(e.index));
    b.extend(abi::u256(amount));
    b.push(kind as u8);
    b
}

fn cp_challenge<C: ZCurve>(e: &Entry<C>, amount: u64, kind: OpeningKind, a1: &[u8], a2: &[u8]) -> Fr<C> {
    let mut b = cp_prefix(e, amount, kind);
    b.extend_from_slice(a1);
    b.extend_from_slice(a2);
    hash_to_scalar::<C>(&keccak256(&b))
}

/// `(K, M, B)` of the Chaum-Pedersen `log_G(K) == log_B(M − [amount]G)` for `kind`.
fn kmb<C: ZCurve>(e: &Entry<C>, kind: OpeningKind) -> (G<C>, G<C>, G<C>) {
    match kind {
        OpeningKind::Auditor => (e.y_a, e.c_aud, e.d_out),
        OpeningKind::SenderCp => (e.d_out, e.c_out, e.y_t),
        _ => (e.y_t, e.c_out, e.d_out),
    }
}

/// Hedged nonce over the secret and everything the challenge covers, then `abi.encode(A1, A2, z)`.
fn cp_open<C: ZCurve, R: RngCore + CryptoRng>(
    e: &Entry<C>,
    amount: u64,
    kind: OpeningKind,
    x: &Fr<C>,
    rng: &mut R,
) -> Vec<u8> {
    // With a dead RNG, two kinds (receiver == auditor), two legs or two amounts must not share `k`.
    let mut secret = zeroize::Zeroizing::new(encode_scalar::<C>(x).to_vec());
    secret.extend_from_slice(&cp_prefix(e, amount, kind));
    let k = Nonces::new(&secret, rng).next::<C>();
    let (_, _, b) = kmb(e, kind);
    let a1 = encode_point::<C>(&(generator::<C>() * k));
    let a2 = encode_point::<C>(&(b * k));
    let c = cp_challenge(e, amount, kind, &a1, &a2);
    let z = k + c * x;
    abi::encode(&[Tok::Bytes(a1), Tok::Bytes(a2), Tok::Word(encode_scalar::<C>(&z))])
}

/// `RECEIVER_X` / `AUDITOR`: Chaum-Pedersen `log_G(K) == log_{D_out}(M − [amount]G)`,
/// `abi.encode(bytes A1, bytes A2, uint256 z)`.
pub fn open_chaum_pedersen<C: ZCurve, R: RngCore + CryptoRng>(
    e: &Entry<C>,
    amount: u64,
    kind: OpeningKind,
    key: &ZetherKey<C>,
    rng: &mut R,
) -> Result<Vec<u8>, ZError> {
    let (k_pt, m, _) = kmb(e, kind);
    if !crate::zether::value_in_range(amount) {
        return Err(ZError::OutOfRange);
    }
    if matches!(kind, OpeningKind::SenderS | OpeningKind::SenderCp) || key.y != k_pt {
        return Err(ZError::BadStatement("opening key does not match the entry"));
    }
    if m - generator::<C>() * Fr::<C>::from(amount) != e.d_out * key.x {
        return Err(ZError::BadStatement("amount does not open this ciphertext"));
    }
    Ok(cp_open(e, amount, kind, &key.x, rng))
}

/// `SENDER_CP`: Chaum-Pedersen on the shared `s`, `log_G(D_out) == log_{Y_t}(C_out − [amount]G)`;
/// opens leg `e.index` only, where `s` itself opens every leg of the transfer.
pub fn open_sender_cp<C: ZCurve, R: RngCore + CryptoRng>(
    e: &Entry<C>,
    amount: u64,
    s: &Fr<C>,
    rng: &mut R,
) -> Result<Vec<u8>, ZError> {
    if !crate::zether::value_in_range(amount) {
        return Err(ZError::OutOfRange);
    }
    if generator::<C>() * *s != e.d_out {
        return Err(ZError::BadStatement("s does not match D_out"));
    }
    if e.c_out - generator::<C>() * Fr::<C>::from(amount) != e.y_t * *s {
        return Err(ZError::BadStatement("amount does not open this ciphertext"));
    }
    Ok(cp_open(e, amount, OpeningKind::SenderCp, s, rng))
}

/// Mirror of `verifyTransferAmount`.
pub fn verify_opening<C: ZCurve>(e: &Entry<C>, amount: u64, kind: OpeningKind, opening: &[u8]) -> Result<(), ZError> {
    let g = generator::<C>();
    let va = g * Fr::<C>::from(amount);
    let bad = ZError::Verify("disclosure");
    // §12: amount < 2^n_v, else amount + r would "open" too.
    if !crate::zether::value_in_range(amount) {
        return Err(bad);
    }
    match kind {
        OpeningKind::SenderS => {
            let s = decode_scalar::<C>(opening)?;
            if g * s == e.d_out && va + e.y_t * s == e.c_out {
                Ok(())
            } else {
                Err(bad)
            }
        }
        _ => {
            let pl = point_len::<C>();
            // abi.encode(bytes, bytes, uint256): fixed layout for P-byte points.
            let padl = pl.div_ceil(32) * 32;
            if opening.len() != 96 + 2 * (32 + padl) {
                return Err(ZError::BadProof("opening length"));
            }
            let want = abi::encode(&[
                Tok::Bytes(opening[96 + 32..96 + 32 + pl].to_vec()),
                Tok::Bytes(opening[96 + 64 + padl..96 + 64 + padl + pl].to_vec()),
                Tok::Word(opening[64..96].try_into().unwrap()),
            ]);
            if want != opening {
                return Err(ZError::BadProof("opening encoding"));
            }
            let a1b = &opening[96 + 32..96 + 32 + pl];
            let a2b = &opening[96 + 64 + padl..96 + 64 + padl + pl];
            let (a1, a2, z) = (decode_point::<C>(a1b)?, decode_point::<C>(a2b)?, decode_scalar::<C>(&opening[64..96])?);
            let (k_pt, m, b) = kmb(e, kind);
            // AUDITOR is false when the token has no auditor or the sender left it out (C_aud = O, Z12).
            if k_pt.is_zero() || (kind == OpeningKind::Auditor && e.c_aud.is_zero()) {
                return Err(bad);
            }
            let c = cp_challenge(e, amount, kind, a1b, a2b);
            if g * z - a1 - k_pt * c == G::<C>::zero() && b * z - a2 - (m - va) * c == G::<C>::zero() {
                Ok(())
            } else {
                Err(bad)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::Bls12381;
    #[cfg(feature = "bn254")]
    use crate::curve::Bn254;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn suite<C: ZCurve>() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let k1 = ZetherKey::<C>::conf(&[1u8; 64], 60, 0).unwrap();
        let k2 = ZetherKey::<C>::conf(&[1u8; 64], 60, 1).unwrap();
        let msg = keccak256(b"m");
        let sig = sign(&k1, &msg, &mut rng);
        verify(&k1.y, &msg, &sig).unwrap();
        assert!(verify(&k2.y, &msg, &sig).is_err());
        assert!(verify(&k1.y, &keccak256(b"n"), &sig).is_err());
        let mut bad = sig.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(verify(&k1.y, &msg, &bad).is_err());

        // PoP is bound to chain, chainUid, registry and key (CTR-UA-07), never to the caller.
        let (uid, reg) = ([0x24; 32], [0xaa; 20]);
        let pop = zether_pop(&k1, 31337, &uid, &reg, &mut rng);
        verify_pop(&k1.y, 31337, &uid, &reg, &pop).unwrap();
        assert!(verify_pop(&k1.y, 1337, &uid, &reg, &pop).is_err());
        assert!(verify_pop(&k1.y, 31337, &[0x25; 32], &reg, &pop).is_err());
        assert!(verify_pop(&k1.y, 31337, &uid, &[0xab; 20], &pop).is_err());
        assert!(verify_pop(&k2.y, 31337, &uid, &reg, &pop).is_err());
        // the owner op signs zether-owner: not a PoP, not the raw digest
        let d = keccak256(b"rollover");
        let auth_blob = owner_auth(&k1, &d, &mut rng);
        let sig = &auth_blob[auth_blob.len() - (point_len::<C>() + 32)..]; // the second `bytes`, a multiple of 32 long
        assert_eq!(auth_blob.len(), 32 * 4 + sig.len(), "abi.encode(bytes(\"\"), sig)");
        verify(&k1.y, &ua_message::<C>(&purpose_tag("zether-owner"), &d), sig).unwrap();
        assert!(verify(&k1.y, &d, sig).is_err());

        // Nonce reuse leaks x: (z1 - z2)/(e1 - e2) — the reason nonces are hedged.
        let k = Fr::<C>::from(12345u64);
        let (_, e1, z1) = sign_with_k::<C>(&k1.x, &keccak256(b"a"), &k);
        let (_, e2, z2) = sign_with_k::<C>(&k1.x, &keccak256(b"b"), &k);
        use ark_ff::Field;
        assert_eq!((z1 - z2) * (e1 - e2).inverse().unwrap(), k1.x);
        // Hedged signing of two messages never repeats R.
        let s1 = sign(&k1, &keccak256(b"a"), &mut rng);
        let s2 = sign(&k1, &keccak256(b"b"), &mut rng);
        assert_ne!(s1[..point_len::<C>()], s2[..point_len::<C>()]);
    }

    #[cfg(feature = "bn254")]
    #[test]
    fn schnorr_pop_bn254() {
        suite::<Bn254>();
    }

    #[test]
    fn schnorr_pop_bls12_381() {
        suite::<Bls12381>();
    }
}
