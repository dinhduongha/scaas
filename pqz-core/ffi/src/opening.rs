// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Opening tokens (spec "three-key model" K3-4, K3-6, K3-6b, K3-7; feature `prove`): split randomness, the sealed
//! opening and the holder check. UNAUDITED.
//!
//! ```text
//! seed_leg   = SHAKE256("SCAAS-PQZ-ENC-LEG-V1" ‖ seed_enc ‖ be4(0) ‖ toUA ‖ keccak256(pk_t))[0..32)
//! own        = Enc([pk_f], [d_f], seed_enc)            -> u_f, v_f          (the sender's own randomness)
//! leg        = Enc([pk_t, (pk_a)], [d, (d)], seed_leg) -> u, v_t, (v_a)     (r, e1, then e2_t, then e2_a)
//! coins      = SHAKE256("SCAAS-PQZ-OPEN-COINS-V1" ‖ seed_leg ‖ u8(role) ‖ keccak256(kemPk))[0..64)   role 0 recipient, 1 auditor
//! (ct, E, ss)= encaps(kemPk, m = coins[0..32), e = coins[32..64))  ss = SHA3-256(ss_M ‖ ss_X ‖ E ‖ pk_X ‖ "scaas.kem.1")
//! kek        = HKDF-SHA256(ikm = ss, salt = ∅, info = "PQZ/opening/kek/v1"), 32 B
//! sealedSeed = AES-256-GCM(kek, nonce 0^96, seed_leg, aad = chainUid ‖ token ‖ ua ‖ be8(keyVersion) ‖ keccak256(P(u) ‖ P(v)))
//! opening    = mlkemCt (1,568) ‖ x25519Eph (32) ‖ sealedSeed (48)  = 1,648 B
//! openKemSeed= HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.kem.v1", info, L = 96)
//!              info "scaas.kem.pqz-opening.1" ‖ ua ‖ chainUid ‖ be64(v)                 (offchain-shared)
//!                   "scaas.kem.pqz-opening-token.1" ‖ ua ‖ chainUid ‖ token ‖ be64(v)   (offchain-token, opening on)
//! (ek, dk)   = ML-KEM-1024.KeyGen_internal(d = seed[0:32], z = seed[32:64]); sk_X = seed[64:96]; kemPk = 0x01 ‖ ek ‖ X25519(sk_X, 9)
//! ```
//!
//! The holder check ([`check_recipient`], [`check_auditor`]) takes public bytes and the opening KEM seed only: the PQZ
//! secret `s` is never an input, and every failure is the one outcome (`None` / [`AuditorOutcome::Unreadable`]): no
//! error detail leaves. There is no entry that decrypts an opening token's credit with `s`. The KEM is CTR-UA-32's
//! scheme 1 with fixed randomness (`encaps` as ua-rs `wallet/kem.rs`); ML-KEM's implicit rejection and a small-order
//! X25519 point both end in the same outcome. Timing: the check stops at the first failing step (local work only; the
//! wallet reports nothing but the outcome).
use crate::pqzl::{self as pl, PK_BYTES};
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hkdf::Hkdf;
use ml_kem::{Decapsulate, KeyExport, MlKem1024};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Keccak256, Sha3_256, Shake256};

type Dk = ml_kem::DecapsulationKey<MlKem1024>;
type Ek = ml_kem::EncapsulationKey<MlKem1024>;

/// `kemPk` (CTR-UA-32 scheme 1): `0x01 ‖ ek ‖ pk_X`.
pub const KEM_PK: usize = 1601;
pub const MLKEM_CT: usize = 1568;
pub const SEALED: usize = 48;
/// one opening in state: `mlkemCt ‖ x25519Eph ‖ sealedSeed`
pub const OPENING: usize = MLKEM_CT + 32 + SEALED;
const EK: usize = 1568;

/// Who reads an opening: the leg's recipient (`O_t`) or the token's auditor (`O_a`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Recipient = 0,
    Auditor = 1,
}

pub fn keccak(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Keccak256::new();
    parts.iter().for_each(|p| Digest::update(&mut h, p));
    h.finalize().into()
}

fn shake(parts: &[&[u8]], out: &mut [u8]) {
    let mut h = Shake256::default();
    parts.iter().for_each(|p| h.update(p));
    h.finalize_xof().read(out);
}

/// The leg seed (K3-4).
pub fn leg_seed(seed_enc: &[u8; 32], to_ua: &[u8; 32], pk_t: &[u8; PK_BYTES]) -> [u8; 32] {
    pl::enc_leg_seed(seed_enc, to_ua, &keccak(&[&pk_t[..]]))
}

/// An op 1 encryption with split randomness (K3-4): `own` = `(u_f, [v_f])` under `seed_enc`, `leg` = `(u, [v_t,
/// (v_a)])` under `seed_leg`. `seed_leg` is cleared on drop (each `Enc` clears its own short vectors).
pub struct Split {
    pub own: pl::Enc,
    pub leg: pl::Enc,
    pub seed_leg: [u8; 32],
}

impl Drop for Split {
    fn drop(&mut self) {
        pl::clear(&mut self.seed_leg);
    }
}

/// `None` when two of `pk_f`, `pk_t`, `pk_a` are equal (the contract refuses it), an `Enc` fails, or `u_f == u`
/// (spec §14 item 21: the builder refuses it).
pub fn enc_split(
    pk_f: &[u8; PK_BYTES],
    d_f: [u8; 16],
    to_ua: &[u8; 32],
    pk_t: &[u8; PK_BYTES],
    d: [u8; 16],
    pk_a: Option<&[u8; PK_BYTES]>,
    seed_enc: &[u8; 32],
) -> Option<Split> {
    if pk_f == pk_t || pk_a.is_some_and(|a| a == pk_f || a == pk_t) {
        return None;
    }
    let own = pl::enc(&[pk_f], &[d_f], seed_enc)?;
    let seed_leg = leg_seed(seed_enc, to_ua, pk_t);
    let pks: Vec<&[u8; PK_BYTES]> = std::iter::once(pk_t).chain(pk_a).collect();
    let leg = pl::enc(&pks, &vec![d; pks.len()], &seed_leg)?;
    let s = Split { own, leg, seed_leg };
    (s.own.u != s.leg.u).then_some(s)
}

/// The opening's encapsulation coins (K3-6): `m ‖ e`.
pub fn coins(seed_leg: &[u8; 32], role: Role, kem_pk: &[u8]) -> [u8; 64] {
    let mut c = [0u8; 64];
    shake(&[b"SCAAS-PQZ-OPEN-COINS-V1", seed_leg, &[role as u8], &keccak(&[kem_pk])], &mut c);
    c
}

/// The opening KEM seed (K3-6b): `token` `None` for offchain-shared, `Some` for offchain-token with the opening on.
pub fn open_kem_seed(bip39_seed: &[u8; 64], ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 96] {
    let label: &[u8] = if token.is_some() { b"scaas.kem.pqz-opening-token.1" } else { b"scaas.kem.pqz-opening.1" };
    let mut okm = [0u8; 96];
    let info = [label, ua, chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()];
    // 96 <= 255 * 32: never fails
    Hkdf::<Sha256>::new(Some(b"scaas.ua.kem.v1"), bip39_seed).expand_multi_info(&info, &mut okm).expect("HKDF length");
    okm
}

fn dk_of(seed: &[u8; 96]) -> Dk {
    Dk::from_seed(ml_kem::Seed::try_from(&seed[..64]).expect("64 bytes"))
}

fn sk_x(seed: &[u8; 96]) -> [u8; 32] {
    seed[64..].try_into().expect("32 bytes")
}

/// `kemPk = 0x01 ‖ ek ‖ X25519(sk_X, 9)` of an opening KEM seed.
pub fn open_kem_pk(seed: &[u8; 96]) -> Vec<u8> {
    let ek = dk_of(seed).encapsulation_key().to_bytes();
    let pk_x = MontgomeryPoint::mul_base_clamped(sk_x(seed)).to_bytes();
    [&[1u8][..], &ek, &pk_x].concat()
}

fn combine(ss_m: &[u8], ss_x: &[u8; 32], e: &[u8; 32], pk_x: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    for p in [ss_m, ss_x, e, pk_x, b"scaas.kem.1"] {
        Digest::update(&mut h, p);
    }
    h.finalize().into()
}

fn kek(ss: &[u8; 32]) -> [u8; 32] {
    let mut k = [0u8; 32];
    Hkdf::<Sha256>::new(None, ss).expand(b"PQZ/opening/kek/v1", &mut k).expect("HKDF length");
    k
}

/// One reader of a leg: its UA, key version, PQZ key, opening KEM key (the scoped record's), its `v`, and the opening
/// bytes stored for it.
#[derive(Clone, Copy)]
pub struct Party<'a> {
    pub ua: &'a [u8; 32],
    pub key_version: u64,
    pub pk: &'a [u8; PK_BYTES],
    pub kem_pk: &'a [u8],
    pub v: &'a [u8; 128],
    pub opening: &'a [u8],
}

/// A credit read from state: the token, the leg's `u`, the recipient, the auditor when `v_a` exists.
#[derive(Clone, Copy)]
pub struct Credit<'a> {
    pub chain_uid: &'a [u8; 32],
    pub token: &'a [u8; 20],
    pub u: &'a [u8; PK_BYTES],
    pub to: Party<'a>,
    pub auditor: Option<Party<'a>>,
}

/// The stored form `P` of a ciphertext part (the contract's packing, `PqzSet.PACK_BITS`, P46): each be8 lane (a
/// coefficient `< q`) as `PACK_BITS = ceil(log2 q)` bits, big-endian, concatenated. `lanes.len()` is a multiple of 8 and
/// the bit count a multiple of 8 (every part here: `u` of `PK_BYTES`, `v` of 128 bytes).
pub fn pack(lanes: &[u8]) -> Vec<u8> {
    let b = 64 - (crate::stmt::Q - 1).leading_zeros() as usize;
    let n = lanes.len() / 8;
    assert!(lanes.len() == 8 * n && (n * b) % 8 == 0, "pack: whole lanes and bytes");
    let mut out = Vec::with_capacity(n * b / 8);
    let (mut acc, mut bits) = (0u128, 0usize);
    for i in 0..n {
        let x = u64::from_be_bytes(lanes[8 * i..8 * i + 8].try_into().expect("8 bytes"));
        acc = (acc << b) | (x as u128 & ((1u128 << b) - 1));
        bits += b;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1u128 << bits) - 1;
    }
    out
}

/// The sealed seed's `aad` (CTR-PQZ-40): `chainUid ‖ token(20) ‖ ua ‖ be8(keyVersion) ‖ keccak256(P(u) ‖ P(v))`, `P` the
/// stored form ([`pack`]) the reader finds in the op blob, with the reader's `ua`, `keyVersion` and `v`.
pub fn aad(c: &Credit, p: &Party) -> Vec<u8> {
    let h = keccak(&[&pack(&c.u[..]), &pack(&p.v[..])]);
    [&c.chain_uid[..], c.token, p.ua, &p.key_version.to_be_bytes(), &h].concat()
}

/// The opening of `seed_leg` to `p` (K3-6), deterministic: `None` for a `kemPk` that is not scheme 1, not 1,601 bytes,
/// has an `ek` coefficient >= q, or a small-order `pk_X`.
pub fn seal(role: Role, c: &Credit, p: &Party, seed_leg: &[u8; 32]) -> Option<Vec<u8>> {
    let kem_pk = p.kem_pk;
    if kem_pk.len() != KEM_PK || kem_pk[0] != 1 {
        return None;
    }
    let (ek, pk_x) = kem_pk[1..].split_at(EK);
    let ek = Ek::new(&ml_kem::Key::<Ek>::try_from(ek).ok()?).ok()?;
    let pk_x: [u8; 32] = pk_x.try_into().ok()?;
    let mut cn = coins(seed_leg, role, kem_pk);
    let e: [u8; 32] = cn[32..].try_into().ok()?;
    let ss_x = MontgomeryPoint(pk_x).mul_clamped(e).to_bytes();
    let big_e = MontgomeryPoint::mul_base_clamped(e).to_bytes();
    let m = ml_kem::B32::try_from(&cn[..32]).ok()?;
    pl::clear(&mut cn);
    if ss_x == [0; 32] {
        return None;
    }
    let (ct, mut ss_m) = ek.encapsulate_deterministic(&m);
    let mut ss = combine(&ss_m, &ss_x, &big_e, &pk_x);
    pl::clear(&mut ss_m);
    let mut k = kek(&ss);
    pl::clear(&mut ss);
    let sealed = Aes256Gcm::new_from_slice(&k).expect("32-byte key").encrypt(Nonce::from_slice(&[0; 12]), Payload { msg: seed_leg, aad: &aad(c, p) });
    pl::clear(&mut k);
    Some([&ct[..], &big_e, &sealed.ok()?].concat())
}

/// K3-7 steps 3–4: decapsulate `p.opening` with the opening KEM seed and open the sealed seed.
fn open(seed: &[u8; 96], c: &Credit, p: &Party) -> Option<[u8; 32]> {
    if p.opening.len() != OPENING || p.kem_pk.len() != KEM_PK {
        return None;
    }
    let (ct, rest) = p.opening.split_at(MLKEM_CT);
    let (eph, sealed) = rest.split_at(32);
    let eph: [u8; 32] = eph.try_into().ok()?;
    let ct = ml_kem::Ciphertext::<MlKem1024>::try_from(ct).ok()?;
    let mut ss_x = MontgomeryPoint(eph).mul_clamped(sk_x(seed)).to_bytes();
    if ss_x == [0; 32] {
        return None; // a small-order E: the same outcome as any other failure
    }
    let mut ss_m = dk_of(seed).decapsulate(&ct); // implicit rejection: a wrong ct gives another ss
    let mut ss = combine(&ss_m, &ss_x, &eph, &p.kem_pk[1 + EK..]);
    pl::clear(&mut ss_m);
    pl::clear(&mut ss_x);
    let mut k = kek(&ss);
    pl::clear(&mut ss);
    let pt = Aes256Gcm::new_from_slice(&k).expect("32-byte key").decrypt(Nonce::from_slice(&[0; 12]), Payload { msg: sealed, aad: &aad(c, p) });
    pl::clear(&mut k);
    let mut pt = pt.ok()?;
    let out = pt.as_slice().try_into().ok();
    pl::clear(&mut pt);
    out
}

/// K3-7 step 7: `w_i = v_i − v0_i (mod q)` must be exactly `Δ·d_i`, `d_i < 16`, with `v` canonical (every be8 < q),
/// `v0` the zero-message encryption under the leg's randomness.
fn digits(v: &[u8; 128], v0: &[u8; 128]) -> Option<[u8; 16]> {
    let (q, delta) = (crate::stmt::Q, crate::stmt::DELTA as u64);
    let be = |b: &[u8], i: usize| u64::from_be_bytes(b[8 * i..8 * i + 8].try_into().expect("8 bytes"));
    let mut d = [0u8; 16];
    let mut ok = true;
    for i in 0..16 {
        let (a, b) = (be(v, i), be(v0, i));
        ok &= a < q;
        let w = (a % q + q - b) % q;
        let mut hit = false;
        for k in 0..16u8 {
            let h = w == delta * k as u64;
            hit |= h;
            d[i] |= k * h as u8;
        }
        ok &= hit;
    }
    ok.then_some(d)
}

/// Steps 5–9 on a known `seed_leg`: `(digits of v_t, digits of v_a, O_t good, O_a good)`; `None` when the expansion
/// fails or its `P(u)` is not byte-equal to the stored `u` (step 6).
fn verify_leg(c: &Credit, seed_leg: &[u8; 32]) -> Option<(Option<[u8; 16]>, Option<[u8; 16]>, bool, bool)> {
    let pks: Vec<&[u8; PK_BYTES]> = std::iter::once(c.to.pk).chain(c.auditor.map(|a| a.pk)).collect();
    // step 5: the pinned sampler (resampled to the relation's norm bounds) with zero messages
    let exp = pl::enc(&pks, &vec![[0u8; 16]; pks.len()], seed_leg)?;
    if exp.u[..] != c.u[..] {
        return None; // step 6: packed bytes, not values mod q
    }
    let d_t = digits(c.to.v, &exp.vs[0]); // step 7
    let o_t = seal(Role::Recipient, c, &c.to, seed_leg).is_some_and(|o| o == c.to.opening); // step 8
    let (d_a, o_a) = match c.auditor {
        Some(a) => (digits(a.v, &exp.vs[1]), seal(Role::Auditor, c, &a, seed_leg).is_some_and(|o| o == a.opening)),
        None => (None, true),
    };
    Some((d_t, d_a, o_t, o_a))
}

/// K3-7 for the recipient, with its opening KEM seed of the key version the leg is encrypted to: the 16 digits of an
/// accepted credit (amount `Σ d_i·16^i`), `None` = skip.
pub fn check_recipient(open_kem_seed: &[u8; 96], c: &Credit) -> Option<[u8; 16]> {
    let mut seed_leg = open(open_kem_seed, c, &c.to)?;
    let r = verify_leg(c, &seed_leg);
    pl::clear(&mut seed_leg);
    let (d_t, d_a, o_t, o_a) = r?;
    let d = d_t.filter(|_| o_t)?;
    // step 9: with the auditor on, v_a carries the same digits and O_a is the deterministic opening
    (c.auditor.is_none() || (d_a == Some(d) && o_a)).then_some(d)
}

/// The auditor tool's outcome per credit (K3-7; spec review C-4). `unreadable, taken` is read from state: [`taken`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditorOutcome {
    /// both openings good: the amount's digits
    Read([u8; 16]),
    /// `O_a` good, `O_t` or `v_t` bad: an honest recipient skips it
    RecipientUnreadable,
    /// `O_a` fails (or the credit has no auditor copy)
    Unreadable,
}

/// K3-7 with the roles swapped, with the auditor's opening KEM seed: never applies `s`.
pub fn check_auditor(open_kem_seed: &[u8; 96], c: &Credit) -> AuditorOutcome {
    let Some(a) = c.auditor else { return AuditorOutcome::Unreadable };
    let Some(mut seed_leg) = open(open_kem_seed, c, &a) else { return AuditorOutcome::Unreadable };
    let r = verify_leg(c, &seed_leg);
    pl::clear(&mut seed_leg);
    match r {
        Some((d_t, Some(d), o_t, true)) => match d_t == Some(d) && o_t {
            true => AuditorOutcome::Read(d),
            false => AuditorOutcome::RecipientUnreadable,
        },
        _ => AuditorOutcome::Unreadable,
    }
}

/// `unreadable, taken` (K3-7): an entry the auditor found unreadable or recipient-unreadable that is not skip-marked
/// and that the recipient's own rollover or debit has taken (index below the account's `rolled` or `floor`).
pub fn taken(index: u64, rolled: u64, floor: u64, marked: bool) -> bool {
    !marked && (index < rolled || index < floor)
}
