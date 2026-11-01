//! Schnorr (zether-design §11.1), the UA registry's PoP and owner authorization of a Zether UA (accounts.md CTR-UA-07,
//! §1.7 Z-auth) and transfer disclosure (§12).

use ark_ff::Zero;
use rand_core::{CryptoRng, RngCore};

use crate::abi::{self, Tok};
use crate::curve::{
    decode_point, decode_scalar, encode_point, encode_scalar, generator, keccak256, point_len, ua_of, zether_kind, zether_tag,
    Fr, ZCurve, G,
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

/// `purposeTag = keccak256("scaas.ua.purpose.<p>.v<version>")` (accounts.md CTR-UA-10; the JS `purposeTag(p, version)`).
pub fn purpose_tag_v(purpose: &str, version: u32) -> [u8; 32] {
    keccak256(format!("scaas.ua.purpose.{purpose}.v{version}").as_bytes())
}

/// The v1 purpose tag: `zether-owner`, `metatx`, … (`pop` is v2 since UA-8, see [`pop_tag`]).
pub fn purpose_tag(purpose: &str) -> [u8; 32] {
    purpose_tag_v(purpose, 1)
}

/// `PURPOSE_POP_V2` of the portable PoP (UA-8 P1).
pub fn pop_tag() -> [u8; 32] {
    purpose_tag_v("pop", 2)
}

/// `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)` of this curve's Zether kind (CTR-UA-12) — what the
/// Zether key signs; the registry's `uaMessage(kind, purposeTag, digest)`.
pub fn ua_message<C: ZCurve>(purpose: &[u8; 32], digest: &[u8; 32]) -> [u8; 32] {
    keccak256(&[keccak256(b"scaas.ua.msg.v1"), zether_tag::<C>(), *purpose, *digest].concat())
}

// ---- The portable records as typed EIP-712 structs (typed-signing TS-D1 / TS-D3; ua-rs `ua8`, clientkeys `ua.js`) ----
// The raw digests before typed-signing are in legacy/typed-signing/portable_raw.rs.

const DOMAIN_TYPE: &str = "EIP712Domain(string name,string version)";
const KEM_RECORD_TYPE: &str = "UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)";
const PORTABLE_RECORD_TYPE: &str = "UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)\
UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)";
const REGISTRATION_TYPE: &str = "UARegistration(UAPortableRecord record,bytes32 pqzPopHash)\
UAKemRecord(bytes32 ua,uint64 version,uint8 scheme,bytes32 kemPkHash)\
UAPortableRecord(bytes32 ua,uint16 kind,bytes32 pqzKeyHash,UAKemRecord kem)";

/// `DS_P` of the portable domain `{name: "SCaaS UA Portable", version: "1"}`: no chainId / verifyingContract / salt.
pub fn portable_domain_separator() -> [u8; 32] {
    keccak256(&[keccak256(DOMAIN_TYPE.as_bytes()), keccak256(b"SCaaS UA Portable"), keccak256(b"1")].concat())
}

fn typed(struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[&[0x19, 0x01][..], &portable_domain_separator(), struct_hash].concat())
}

/// `hashStruct(UAKemRecord{ua, 0, 0, 0})`: "no KEM record" (TS-D2), the `kem` of a Zether UA's record.
pub fn no_kem_record_hash(ua: &[u8; 32]) -> [u8; 32] {
    keccak256(&[keccak256(KEM_RECORD_TYPE.as_bytes()), *ua, [0u8; 32], [0u8; 32], [0u8; 32]].concat())
}

fn portable_record_hash(ua: &[u8; 32], kind: u16, pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    keccak256(&[keccak256(PORTABLE_RECORD_TYPE.as_bytes()), *ua, abi::u256(kind as u64), *pqz_key_hash, *kem_record_hash].concat())
}

/// The typed `UAPortableRecord{ua, kind, pqzKeyHash, kem}` digest (`kem_record_hash` = `hashStruct(UAKemRecord)`).
pub fn portable_record_digest(ua: &[u8; 32], kind: u16, pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32]) -> [u8; 32] {
    typed(&portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash))
}

/// The typed `UARegistration{record, pqzPopHash}` digest: what `ua_message(kind, POP_V2, ·)` is taken over.
pub fn registration_digest(ua: &[u8; 32], kind: u16, pqz_key_hash: &[u8; 32], kem_record_hash: &[u8; 32], pqz_pop_hash: &[u8; 32]) -> [u8; 32] {
    let record = portable_record_hash(ua, kind, pqz_key_hash, kem_record_hash);
    typed(&keccak256(&[keccak256(REGISTRATION_TYPE.as_bytes()), record, *pqz_pop_hash].concat()))
}

/// The typed `UAPortableRecord{UA, kind, 0, UAKemRecord{UA, 0, 0, 0}}` digest of a Zether UA (no PQZ key, no KEM record).
pub fn zether_record_digest<C: ZCurve>(ua: &[u8; 32]) -> [u8; 32] {
    portable_record_digest(ua, zether_kind::<C>(), &[0u8; 32], &no_kem_record_hash(ua))
}

/// The typed `UARegistration{UAPortableRecord{UA, kind, 0, UAKemRecord{UA, 0, 0, 0}}, 0}` digest of a Zether UA (TS-D3):
/// it holds no PQZ key, KEM record or PQZ proof.
pub fn zether_registration_digest<C: ZCurve>(ua: &[u8; 32]) -> [u8; 32] {
    registration_digest(ua, zether_kind::<C>(), &[0u8; 32], &no_kem_record_hash(ua), &[0u8; 32])
}

/// The `pop` of `register(0x0141, Y, …)` (UA-8 P1, portable: no chain, chainUid or registry): Schnorr by `x` under the
/// Zether tag over `ua_message(POP_V2, zether_registration_digest(UA(Y)))`.
pub fn zether_pop<C: ZCurve, R: RngCore + CryptoRng>(key: &ZetherKey<C>, rng: &mut R) -> Vec<u8> {
    sign(key, &ua_message::<C>(&pop_tag(), &zether_registration_digest::<C>(&key.ua())), rng)
}

pub fn verify_pop<C: ZCurve>(y: &G<C>, pop: &[u8]) -> Result<(), ZError> {
    verify(y, &ua_message::<C>(&pop_tag(), &zether_registration_digest::<C>(&ua_of::<C>(y))), pop)
}

// ---- Legacy (backup, not delete): the chain-bound PoP before UA-8 (pop.v1) ----

/// `pop_digest = keccak256(abi.encode(POP_TAG, keccak256("evm:" ‖ decimal(chainId)), chainUid, registry, ua, pqzKeyHash))`
/// (CTR-UA-07) — the pre-UA-8 registry's `popDigest(ua, pqzKeyHash)`.
pub fn pop_digest_v1(chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], ua: &[u8; 32], pqz_key_hash: &[u8; 32]) -> [u8; 32] {
    let chain_key = keccak256(format!("evm:{chain_id}").as_bytes());
    keccak256(&[purpose_tag("pop"), chain_key, *chain_uid, abi::addr(registry), *ua, *pqz_key_hash].concat())
}

/// The pre-UA-8 `pop`: Schnorr by `x` over `ua_message(pop.v1, pop_digest_v1(…, UA(Y), 0))`.
pub fn zether_pop_v1<C: ZCurve, R: RngCore + CryptoRng>(
    key: &ZetherKey<C>,
    chain_id: u64,
    chain_uid: &[u8; 32],
    registry: &[u8; 20],
    rng: &mut R,
) -> Vec<u8> {
    let d = pop_digest_v1(chain_id, chain_uid, registry, &key.ua(), &[0u8; 32]);
    sign(key, &ua_message::<C>(&purpose_tag("pop"), &d), rng)
}

pub fn verify_pop_v1<C: ZCurve>(y: &G<C>, chain_id: u64, chain_uid: &[u8; 32], registry: &[u8; 20], pop: &[u8]) -> Result<(), ZError> {
    let d = pop_digest_v1(chain_id, chain_uid, registry, &ua_of::<C>(y), &[0u8; 32]);
    verify(y, &ua_message::<C>(&purpose_tag("pop"), &d), pop)
}

/// The `sig` of an owner op (`mtxRollOverSigned`, `mtxSetRollOverMode`):
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
/// (`B_j = Y_t ‖ C_out ‖ D_out ‖ C_aud ‖ D_aud`; a single-recipient transfer has `index = 0`, `B = Y_t ‖ C_out ‖ D_out ‖
/// C_aud` and `D_aud = D_out`, its auditor copy being under `s`).
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
    /// The auditor copy's `D` (`[t_j]G` on a multi-recipient leg, review C0-1; `D_out` on the single format).
    pub d_aud: G<C>,
}

/// `SENDER_S`: `abi.encode(uint256 s)`.
pub fn open_sender<C: ZCurve>(s: &Fr<C>) -> Vec<u8> {
    encode_scalar::<C>(s).to_vec()
}

/// Challenge preimage up to the statement points; also the opening nonce's public input.
fn cp_prefix<C: ZCurve>(e: &Entry<C>, amount: u64, kind: OpeningKind) -> Vec<u8> {
    let mut b = b"SCAAS-ZETHER-DISCLOSE-V2".to_vec();
    b.extend(abi::u256(e.chain_id));
    b.extend_from_slice(&e.chain_uid);
    b.extend_from_slice(&e.token);
    b.extend_from_slice(&e.entry_ref);
    b.extend(abi::u256(e.index));
    b.extend(abi::u256(amount));
    b.push(kind as u8);
    b
}

/// `e = hashToScalar(keccak256(pre ‖ G ‖ K ‖ B ‖ M ‖ A1 ‖ A2))` (review C0-4): the statement points are absorbed, in
/// the contract's G1 encoding, so `e` cannot be known before `s` is chosen.
fn cp_challenge<C: ZCurve>(e: &Entry<C>, amount: u64, kind: OpeningKind, a1: &[u8], a2: &[u8]) -> Fr<C> {
    let (k, m, bb) = kmb(e, kind);
    let mut b = cp_prefix(e, amount, kind);
    for p in [generator::<C>(), k, bb, m] {
        b.extend(encode_point::<C>(&p));
    }
    b.extend_from_slice(a1);
    b.extend_from_slice(a2);
    hash_to_scalar::<C>(&keccak256(&b))
}

/// `(K, M, B)` of the Chaum-Pedersen `log_G(K) == log_B(M − [amount]G)` for `kind`.
fn kmb<C: ZCurve>(e: &Entry<C>, kind: OpeningKind) -> (G<C>, G<C>, G<C>) {
    match kind {
        OpeningKind::Auditor => (e.y_a, e.c_aud, e.d_aud),
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

/// `RECEIVER_X` / `AUDITOR`: Chaum-Pedersen `log_G(K) == log_B(M − [amount]G)` (`B = D_out`, or `D_aud` for the
/// auditor), `abi.encode(bytes A1, bytes A2, uint256 z)`.
pub fn open_chaum_pedersen<C: ZCurve, R: RngCore + CryptoRng>(
    e: &Entry<C>,
    amount: u64,
    kind: OpeningKind,
    key: &ZetherKey<C>,
    rng: &mut R,
) -> Result<Vec<u8>, ZError> {
    let (k_pt, m, b) = kmb(e, kind);
    if !crate::zether::value_in_range(amount) {
        return Err(ZError::OutOfRange);
    }
    if matches!(kind, OpeningKind::SenderS | OpeningKind::SenderCp) || key.y != k_pt {
        return Err(ZError::BadStatement("opening key does not match the entry"));
    }
    if m - generator::<C>() * Fr::<C>::from(amount) != b * key.x {
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

        // The portable PoP is bound to the key alone (UA-8 P1): no chain, chainUid or registry.
        let pop = zether_pop(&k1, &mut rng);
        verify_pop(&k1.y, &pop).unwrap();
        assert!(verify_pop(&k2.y, &pop).is_err());
        // legacy chain-bound PoP (pop.v1): bound to chain, chainUid, registry and key; not a v2 PoP
        let (uid, reg) = ([0x24; 32], [0xaa; 20]);
        let pop1 = zether_pop_v1(&k1, 31337, &uid, &reg, &mut rng);
        verify_pop_v1(&k1.y, 31337, &uid, &reg, &pop1).unwrap();
        assert!(verify_pop_v1(&k1.y, 1337, &uid, &reg, &pop1).is_err());
        assert!(verify_pop_v1(&k1.y, 31337, &[0x25; 32], &reg, &pop1).is_err());
        assert!(verify_pop_v1(&k1.y, 31337, &uid, &[0xab; 20], &pop1).is_err());
        assert!(verify_pop_v1(&k2.y, 31337, &uid, &reg, &pop1).is_err());
        assert!(verify_pop(&k1.y, &pop1).is_err());
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

    /// typed-signing P4: the Zether PoP signs the typed `UARegistration{UAPortableRecord{UA, 0x0141, 0, UAKemRecord{UA, 0,
    /// 0, 0}}, 0}` (TS-D1 / TS-D3), byte-identical with portable.json's `zether-bls12381` row (clientkeys, ua-rs, the registry).
    #[test]
    fn zether_registration_digest_pinned() {
        type C = Bls12381;
        assert_eq!(hex::encode(portable_domain_separator()), "9a2c390d4dc940ccdb5fa6b21e673e87159bdd99aeef22ea791bcea9efc64ca1");
        for (t, want) in [
            (KEM_RECORD_TYPE, "0ab7989827627b89c268e88a0a0b06b62aefa70b0a466014931ca44acfa9a201"),
            (PORTABLE_RECORD_TYPE, "0c1553cfab3c35326558484df79963dced75ead85272d2a85985f264757bfe7f"),
            (REGISTRATION_TYPE, "c78b548ceb2fadf1f0a895f79f88b517327c120f0f9ab345f02981441048c87e"),
        ] {
            assert_eq!(hex::encode(keccak256(t.as_bytes())), want, "{t}");
        }
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/vectors/ua/portable.json");
        let pj: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let r = pj["registrations"].as_array().unwrap().iter().find(|r| r["name"] == "zether-bls12381").unwrap();
        let h = |f: &str| hex::decode(&r[f].as_str().unwrap()[2..]).unwrap();
        let h32 = |f: &str| -> [u8; 32] { h(f).try_into().unwrap() };
        let ua = h32("ua");
        assert_eq!(r["kind"], crate::curve::zether_kind::<C>());
        assert_eq!(no_kem_record_hash(&ua), h32("kemRecordHash"));
        assert_eq!(zether_record_digest::<C>(&ua), h32("portableRecordDigest"));
        let rd = zether_registration_digest::<C>(&ua);
        assert_eq!(rd, h32("registrationDigest"));
        assert_eq!(ua_message::<C>(&pop_tag(), &rd), h32("popMessage"));
        // the JS reference's PoP of that row verifies here
        verify_pop(&decode_point::<C>(&h("keyData")).unwrap(), &h("pop")).unwrap();
    }

    /// Review C0-4: every statement point is in the challenge; moving any one of them moves `e`.
    #[test]
    fn cp_challenge_binds_statement_points() {
        type C = Bls12381;
        let g = generator::<C>();
        let p = |n: u64| g * Fr::<C>::from(n);
        let mk = |pts: [G<C>; 6]| Entry::<C> {
            chain_id: 1, chain_uid: [2; 32], token: [3; 20], entry_ref: [4; 32], index: 0,
            y_t: pts[0], c_out: pts[1], d_out: pts[2], y_a: pts[3], c_aud: pts[4], d_aud: pts[5],
        };
        let pts: [G<C>; 6] = [p(5), p(6), p(7), p(8), p(9), p(10)];
        let e0 = mk(pts);
        let (a1, a2) = (encode_point::<C>(&p(11)), encode_point::<C>(&p(12)));
        for kind in [OpeningKind::ReceiverX, OpeningKind::Auditor, OpeningKind::SenderCp] {
            let base = cp_challenge(&e0, 1, kind, &a1, &a2);
            let (k, m, b) = kmb(&e0, kind);
            let mut seen = vec![base];
            for (n, src) in [k, m, b].into_iter().enumerate() {
                // replace the one point that plays K, M or B for this kind by another
                let c = cp_challenge(&mk(pts.map(|q| if q == src { p(99) } else { q })), 1, kind, &a1, &a2);
                assert!(!seen.contains(&c), "{kind:?}: statement point {n} is not bound");
                seen.push(c);
            }
        }
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
