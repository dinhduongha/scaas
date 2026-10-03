//! Transfer/burn: valid proofs on both curves, Σ soundness negatives, Σ-Bullets linkage,
//! statement binding (every header field), wire round-trips, ElGamal effects end to end.

use ark_ff::{One, Zero};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zether_prover::bulletproofs::Gens;
use zether_prover::curve::{generator, point_len, Bls12381, Bn254, Fr, ZCurve, G};
use zether_prover::elgamal::{encrypt, BsgsTable, Ciphertext};
use zether_prover::keys::ZetherKey;
use zether_prover::zether::*;
use zether_prover::ZError;

fn rng() -> ChaCha20Rng {
    ChaCha20Rng::seed_from_u64(42)
}

fn key<C: ZCurve>(account: u32) -> ZetherKey<C> {
    ZetherKey::<C>::conf(&[7u8; 64], 60, account).unwrap()
}

fn header(fee: u64) -> Header {
    Header {
        chain_id: 31337,
        token: [0x11; 20],
        binding: Binding::Direct,
        send_counter: 3,
        acc_seq: 5,
        fee,
        beneficiary: if fee > 0 { [0x22; 32] } else { [0; 32] },
        amount: 0,
        recipient: [0; 20],
    }
}

struct Fx<C: ZCurve> {
    gens: Gens<C>,
    from: ZetherKey<C>,
    to: ZetherKey<C>,
    aud: ZetherKey<C>,
    acc: Ciphertext<C>,
}

const BAL: u64 = 1_000_000;

fn fx<C: ZCurve>() -> Fx<C> {
    let from = key::<C>(0);
    let acc = encrypt(&from.y, BAL, &Fr::<C>::from(987654321u64));
    Fx { gens: Gens::new(), from, to: key::<C>(1), aud: key::<C>(2), acc }
}

fn transfer<C: ZCurve>(f: &Fx<C>, h: Header, aud: bool, v: u64) -> (TransferStatement<C>, TransferProof<C>, TransferWitness<C>) {
    let ya = if aud { f.aud.y } else { G::<C>::zero() };
    prove_transfer(&f.gens, &f.from, h, f.to.y, ya, f.acc, BAL, v, &mut rng()).unwrap()
}

fn valid_and_effects<C: ZCurve>() {
    let f = fx::<C>();
    let t = BsgsTable::<C>::new();
    for aud in [true, false] {
        let (st, p, _) = transfer(&f, header(300), aud, 250_000);
        verify_transfer(&f.gens, &st, &p).unwrap();
        // Wire round-trips and sizes (§9).
        let enc = p.encode();
        assert_eq!(enc.len(), TransferProof::<C>::wire_len());
        assert_eq!(enc.len(), if point_len::<C>() == 64 { 3072 } else { 5632 });
        assert!(TransferProof::<C>::decode(&enc).unwrap() == p);
        assert!(TransferStatement::<C>::decode(&st.encode()).unwrap() == st);
        assert_eq!(st.payload().len(), 64 + 6 * point_len::<C>());
        // On-chain effects (§5), then decrypt both sides.
        let g = generator::<C>();
        let fee = g * Fr::<C>::from(300u64);
        let acc2 = Ciphertext { c: st.acc.c - st.c_deb - fee, d: st.acc.d - st.d_out };
        let pend = Ciphertext { c: st.c_out, d: st.d_out };
        assert_eq!(t.decrypt(&acc2, &f.from.x).unwrap(), BAL - 250_000 - 300);
        assert_eq!(t.decrypt(&pend, &f.to.x).unwrap(), 250_000);
        if aud {
            assert_eq!(t.decrypt(&Ciphertext { c: st.c_aud, d: st.d_out }, &f.aud.x).unwrap(), 250_000);
        } else {
            assert!(st.c_aud.is_zero() && p.a_aud.is_zero());
        }
    }
    // Zero-value and full-balance transfers are fine.
    let (st, p, _) = transfer(&f, header(0), true, 0);
    verify_transfer(&f.gens, &st, &p).unwrap();
    let (st, p, _) = transfer(&f, header(0), true, BAL);
    verify_transfer(&f.gens, &st, &p).unwrap();
}

#[test]
fn transfer_valid_bn254() {
    valid_and_effects::<Bn254>();
}

#[test]
fn transfer_valid_bls12_381() {
    valid_and_effects::<Bls12381>();
}

fn prover_refuses<C: ZCurve>() {
    let f = fx::<C>();
    let ya = f.aud.y;
    let mut r = rng();
    let bad = |e: Result<_, ZError>| assert!(e.is_err());
    // insufficient balance (v + fee > b)
    bad(prove_transfer(&f.gens, &f.from, header(1), f.to.y, ya, f.acc, BAL, BAL, &mut r).map(|_| ()));
    // claimed balance does not match acc
    bad(prove_transfer(&f.gens, &f.from, header(0), f.to.y, ya, f.acc, BAL + 1, 5, &mut r).map(|_| ()));
    // v >= 2^32
    bad(prove_transfer(&f.gens, &f.from, header(0), f.to.y, ya, f.acc, BAL, 1 << 32, &mut r).map(|_| ()));
    // self transfer
    bad(prove_transfer(&f.gens, &f.from, header(0), f.from.y, ya, f.acc, BAL, 5, &mut r).map(|_| ()));
    // fee without beneficiary, fee >= 2^32
    let mut h = header(0);
    h.fee = 5;
    bad(prove_transfer(&f.gens, &f.from, h.clone(), f.to.y, ya, f.acc, BAL, 5, &mut r).map(|_| ()));
    h.beneficiary = [1; 32];
    h.fee = 1 << 32;
    bad(prove_transfer(&f.gens, &f.from, h, f.to.y, ya, f.acc, BAL, 5, &mut r).map(|_| ()));
}

#[test]
fn transfer_prover_refuses_bad_requests() {
    prover_refuses::<Bn254>();
    prover_refuses::<Bls12381>();
}

fn sigma_negatives<C: ZCurve>() {
    let f = fx::<C>();
    let (st, _, w) = transfer(&f, header(300), true, 250_000);
    let one = Fr::<C>::one();
    let reject = |st: &TransferStatement<C>, w: &TransferWitness<C>, what: &str| {
        let p = prove_transfer_core(&f.gens, st, w, &mut rng()).unwrap();
        assert!(verify_transfer(&f.gens, st, &p).is_err(), "{what} must be rejected");
    };
    // Wrong secret key.
    let mut w2 = w.clone();
    w2.x = key::<C>(9).x;
    reject(&st, &w2, "wrong x");
    // Wrong balance: b' off by one (E5 fails).
    let mut w2 = w.clone();
    w2.b_prime += one;
    reject(&st, &w2, "wrong b'");
    // Overspend: b' negative (b − v − fee < 0) is outside [0, 2^64): BP#2 fails.
    let mut w2 = w.clone();
    w2.b_prime = -one;
    reject(&st, &w2, "negative b'");
    // Σ-Bullets linkage: V_v commits to a v different from the v inside C_out/C_deb.
    let mut w2 = w.clone();
    w2.v += one;
    reject(&st, &w2, "v mismatch");
    // Wrong s.
    let mut w2 = w.clone();
    w2.s += one;
    reject(&st, &w2, "wrong s");
    // A statement minting money: credit v + 1 to the recipient while debiting v.
    let mut st2 = st.clone();
    st2.c_out += generator::<C>();
    reject(&st2, &w, "credit != debit");
    // Forged range: v >= 2^32 hidden in the ciphertexts (prover core forced).
    let mut st3 = st.clone();
    let big = Fr::<C>::from(1u64 << 32);
    let g = generator::<C>();
    st3.c_out = g * big + st.y_t * w.s;
    st3.c_deb = g * big + st.y_f * w.s;
    st3.c_aud = g * big + st.y_a * w.s;
    let mut w3 = w.clone();
    w3.v = big;
    w3.b_prime = w.b - big - Fr::<C>::from(300u64);
    reject(&st3, &w3, "v >= 2^32");

    // A valid proof against a modified statement: swapped recipient, other auditor, etc.
    let p = prove_transfer_core(&f.gens, &st, &w, &mut rng()).unwrap();
    verify_transfer(&f.gens, &st, &p).unwrap();
    let mut s = st.clone();
    s.y_t = key::<C>(5).y;
    assert!(verify_transfer(&f.gens, &s, &p).is_err(), "swapped recipient");
    let mut s = st.clone();
    s.y_a = key::<C>(6).y;
    assert!(verify_transfer(&f.gens, &s, &p).is_err(), "other auditor");
    let mut s = st.clone();
    s.acc.c += g;
    assert!(verify_transfer(&f.gens, &s, &p).is_err(), "other acc");
}

#[test]
fn transfer_sigma_negatives_bn254() {
    sigma_negatives::<Bn254>();
}

#[test]
fn transfer_sigma_negatives_bls12_381() {
    sigma_negatives::<Bls12381>();
}

/// Strong Fiat-Shamir: change any header field and the proof dies (research §3.4.7).
fn header_binding<C: ZCurve>() {
    let f = fx::<C>();
    let mut h0 = header(300);
    h0.binding = Binding::Relayed([0x33; 32]);
    let (st, p, _) = transfer(&f, h0.clone(), true, 1000);
    verify_transfer(&f.gens, &st, &p).unwrap();
    let muts: Vec<fn(&mut Header)> = vec![
        |h| h.chain_id += 1,
        |h| h.token[19] ^= 1,
        |h| h.binding = Binding::Direct,
        |h| h.binding = Binding::Relayed([0x34; 32]),
        |h| h.send_counter += 1,
        |h| h.acc_seq += 1,
        |h| h.fee += 1,
        |h| h.beneficiary[0] ^= 1,
    ];
    for m in muts {
        let mut s = st.clone();
        m(&mut s.header);
        assert!(verify_transfer(&f.gens, &s, &p).is_err());
    }
    // Every byte position class of the encoded proof: flip one bit in each 32-byte word.
    let enc = p.encode();
    for i in (0..enc.len()).step_by(32) {
        let mut e = enc.clone();
        e[i + 31] ^= 1;
        match TransferProof::<C>::decode(&e) {
            Ok(q) => assert!(verify_transfer(&f.gens, &st, &q).is_err(), "bit flip at {i}"),
            Err(_) => {}
        }
    }
    // A burn proof can never be read as a transfer and vice versa (opTag in the header).
    assert!(BurnStatement::<C>::decode(&st.encode()).is_err());
}

#[test]
fn transfer_header_binding_bn254() {
    header_binding::<Bn254>();
}

#[test]
fn transfer_header_binding_bls12_381() {
    header_binding::<Bls12381>();
}

fn burn_suite<C: ZCurve>() {
    let f = fx::<C>();
    let mut h = header(300);
    h.amount = 400_000;
    h.recipient = [0x44; 20];
    let (st, p, w) = prove_burn(&f.gens, &f.from, h.clone(), f.acc, BAL, &mut rng()).unwrap();
    verify_burn(&f.gens, &st, &p).unwrap();
    let enc = p.encode();
    assert_eq!(enc.len(), if point_len::<C>() == 64 { 1536 } else { 2816 });
    assert!(BurnProof::<C>::decode(&enc).unwrap() == p);
    assert!(BurnStatement::<C>::decode(&st.encode()).unwrap() == st);
    assert_eq!(st.payload().len(), 64 + point_len::<C>());
    // Effect: acc −= [amount + fee]G.
    let acc2 = Ciphertext { c: st.acc.c - generator::<C>() * Fr::<C>::from(400_300u64), d: st.acc.d };
    assert_eq!(BsgsTable::<C>::new().decrypt(&acc2, &f.from.x).unwrap(), BAL - 400_300);
    // Relayer cannot redirect or resize the withdrawal.
    let muts: Vec<fn(&mut Header)> =
        vec![|h| h.recipient[0] ^= 1, |h| h.amount += 1, |h| h.amount -= 1, |h| h.fee += 1, |h| h.send_counter += 1];
    for m in muts {
        let mut s = st.clone();
        m(&mut s.header);
        assert!(verify_burn(&f.gens, &s, &p).is_err());
    }
    // Wrong key / wrong balance / overdraw.
    for (i, m) in [
        (|w: &mut BurnWitness<C>, k: Fr<C>| w.x = k) as fn(&mut BurnWitness<C>, Fr<C>),
        |w, _| w.b_prime += Fr::<C>::one(),
        |w, _| w.b_prime = -Fr::<C>::one(),
    ]
    .into_iter()
    .enumerate()
    {
        let mut w2 = w.clone();
        m(&mut w2, key::<C>(9).x);
        let q = prove_burn_core(&f.gens, &st, &w2, &mut rng()).unwrap();
        assert!(verify_burn(&f.gens, &st, &q).is_err(), "burn negative {i}");
    }
    // Prover refuses an overdraw.
    let mut h2 = h;
    h2.amount = BAL;
    assert!(prove_burn(&f.gens, &f.from, h2, f.acc, BAL, &mut rng()).is_err());
}

#[test]
fn burn_bn254() {
    burn_suite::<Bn254>();
}

#[test]
fn burn_bls12_381() {
    burn_suite::<Bls12381>();
}
