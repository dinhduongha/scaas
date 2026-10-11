//! Transfer/burn: valid proofs on both curves, Σ soundness negatives, Σ-Bullets linkage,
//! statement binding (every header field), wire round-trips, ElGamal effects end to end.

use ark_ff::{One, Zero};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zether_prover::bulletproofs::Gens;
use zether_prover::curve::{generator, point_len, Bls12381, Bn254, Fr, ZCurve, G};
use zether_prover::elgamal::{encrypt, Ciphertext};
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
        chain_uid: [0x24; 32],
        token: [0x11; 20],
        binding: Binding::Direct,
        send_counter: 3,
        acc_seq: 5,
        fee,
        beneficiary: if fee > 0 { [0x22; 32] } else { [0; 32] },
        amount: 0,
        recipient: [0; 20],
        salt: [0; 16],
        memo_hash: [0; 32],
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

/// Small test table (2^18 entries, shared) — `BAL`-sized plaintexts decrypt with bound 2^24.
fn decrypt<C: ZCurve>(ct: &Ciphertext<C>, x: &Fr<C>) -> u64 {
    zether_prover::elgamal::cached_table::<C>(18).unwrap().decrypt(ct, x, 24).unwrap()
}

fn valid_and_effects<C: ZCurve>() {
    let f = fx::<C>();
    for aud in [true, false] {
        let (st, p, _) = transfer(&f, header(300), aud, 250_000);
        verify_transfer(&f.gens, &st, &p).unwrap();
        // Wire round-trips and sizes (§9).
        let enc = p.encode();
        assert_eq!(enc.len(), TransferProof::<C>::wire_len());
        // n_v = n_b = 64: 42P + 512 (RS-NV64-1).
        assert_eq!(enc.len(), if point_len::<C>() == 64 { 3200 } else { 5888 });
        assert!(TransferProof::<C>::decode(&enc).unwrap() == p);
        assert!(TransferStatement::<C>::decode(&st.encode()).unwrap() == st);
        assert_eq!(st.payload().len(), 80 + 6 * point_len::<C>(), "accSeq ‖ sendCounter ‖ salt ‖ points");
        assert_eq!(st.record().len(), 16 + 4 * point_len::<C>(), "R = salt ‖ B");
        assert_eq!(&st.record()[..16], &st.header.salt);
        // On-chain effects (§5), then decrypt both sides.
        let g = generator::<C>();
        let fee = g * Fr::<C>::from(300u64);
        let acc2 = Ciphertext { c: st.acc.c - st.c_deb - fee, d: st.acc.d - st.d_out };
        let pend = Ciphertext { c: st.c_out, d: st.d_out };
        assert_eq!(decrypt(&acc2, &f.from.x), BAL - 250_000 - 300);
        assert_eq!(decrypt(&pend, &f.to.x), 250_000);
        if aud {
            assert_eq!(decrypt(&Ciphertext { c: st.c_aud, d: st.d_out }, &f.aud.x), 250_000);
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
    // v + fee > b with v > 2^32 (n_v = 64: the bound is the balance, not 2^32)
    bad(prove_transfer(&f.gens, &f.from, header(0), f.to.y, ya, f.acc, BAL, 1 << 32, &mut r).map(|_| ()));
    // self transfer
    bad(prove_transfer(&f.gens, &f.from, header(0), f.from.y, ya, f.acc, BAL, 5, &mut r).map(|_| ()));
    // fee without beneficiary; fee > balance
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
    // Forged range: v = 2^64 hidden in the ciphertexts (prover core forced), b' kept consistent.
    let mut st3 = st.clone();
    let big = Fr::<C>::from(1u128 << 64);
    let g = generator::<C>();
    st3.c_out = g * big + st.y_t * w.s;
    st3.c_deb = g * big + st.y_f * w.s;
    st3.c_aud = g * big + st.y_a * w.s;
    let mut w3 = w.clone();
    w3.v = big;
    w3.b_prime = w.b - big - Fr::<C>::from(300u64);
    reject(&st3, &w3, "v >= 2^64");

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
        |h| h.chain_uid[31] ^= 1,
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
        // A flip that breaks decoding (non-canonical point/scalar) is a rejection too.
        if let Ok(q) = TransferProof::<C>::decode(&e) {
            assert!(verify_transfer(&f.gens, &st, &q).is_err(), "bit flip at {i}");
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
    let mut memo = h.clone();
    memo.memo_hash = [1; 32];
    assert!(prove_burn(&f.gens, &f.from, memo, f.acc, BAL, &mut rng()).is_err(), "a burn has no memo");
    let mut salted = h.clone();
    salted.salt = [1; 16];
    assert!(prove_burn(&f.gens, &f.from, salted, f.acc, BAL, &mut rng()).is_err(), "a burn has no salt");
    let (st, p, w) = prove_burn(&f.gens, &f.from, h.clone(), f.acc, BAL, &mut rng()).unwrap();
    verify_burn(&f.gens, &st, &p).unwrap();
    let enc = p.encode();
    assert_eq!(enc.len(), if point_len::<C>() == 64 { 1536 } else { 2816 });
    assert!(BurnProof::<C>::decode(&enc).unwrap() == p);
    assert!(BurnStatement::<C>::decode(&st.encode()).unwrap() == st);
    assert_eq!(st.payload().len(), 64 + point_len::<C>());
    // Effect: acc −= [amount + fee]G.
    let acc2 = Ciphertext { c: st.acc.c - generator::<C>() * Fr::<C>::from(400_300u64), d: st.acc.d };
    assert_eq!(decrypt(&acc2, &f.from.x), BAL - 400_300);
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
    assert!(prove_burn(&f.gens, &f.from, h2.clone(), f.acc, BAL, &mut rng()).is_err());
    // amount must be in (0, 2^54] (no mod-r aliasing of amount + fee).
    h2.amount = 0;
    h2.fee = 0;
    h2.beneficiary = [0; 32];
    assert!(prove_burn(&f.gens, &f.from, h2.clone(), f.acc, BAL, &mut rng()).is_err());
    let mut s = st.clone();
    s.header.amount = (1 << 54) + 1;
    assert!(s.validate().is_err());
}

#[test]
fn burn_bn254() {
    burn_suite::<Bn254>();
}

#[test]
fn burn_bls12_381() {
    burn_suite::<Bls12381>();
}

/// limits D1: one transfer > 2^32 from a balance > 2^44 and a fee near 2^64 are provable; the
/// effects check with `check_balance` (no BSGS needed for any of it).
fn large_values<C: ZCurve>() {
    use zether_prover::elgamal::check_balance;
    let from = key::<C>(0);
    let bal: u64 = (1 << 44) + 12_345;
    let acc = encrypt(&from.y, bal, &Fr::<C>::from(55u64));
    let gens = Gens::<C>::new();
    let to = key::<C>(1);
    let v: u64 = (1 << 33) + 7;
    let (st, p, _) = prove_transfer(&gens, &from, header(300), to.y, key::<C>(2).y, acc, bal, v, &mut rng()).unwrap();
    verify_transfer(&gens, &st, &p).unwrap();
    let g = generator::<C>();
    let acc2 = Ciphertext { c: st.acc.c - st.c_deb - g * Fr::<C>::from(300u64), d: st.acc.d - st.d_out };
    assert!(check_balance(&acc2, &from.x, bal - v - 300));
    assert!(!check_balance(&acc2, &from.x, bal - v - 301));
    assert!(check_balance(&Ciphertext { c: st.c_out, d: st.d_out }, &to.x, v));
    // whole balance in one transfer
    let (st, p, _) = prove_transfer(&gens, &from, header(0), to.y, G::<C>::zero(), acc, bal, bal, &mut rng()).unwrap();
    verify_transfer(&gens, &st, &p).unwrap();
    // fee = 2^64 − 1 from a balance just above it
    let mut h = header(0);
    h.fee = u64::MAX;
    h.beneficiary = [0x22; 32];
    let big = encrypt(&from.y, u64::MAX, &Fr::<C>::from(9u64));
    assert!(prove_transfer(&gens, &from, h.clone(), to.y, G::<C>::zero(), big, u64::MAX, 1, &mut rng()).is_err());
    let (st, p, _) = prove_transfer(&gens, &from, h, to.y, G::<C>::zero(), big, u64::MAX, 0, &mut rng()).unwrap();
    verify_transfer(&gens, &st, &p).unwrap();
}

#[test]
fn transfer_large_values_bn254() {
    large_values::<Bn254>();
}

#[test]
fn transfer_large_values_bls12_381() {
    large_values::<Bls12381>();
}

// ---------------------------------------------------------------------------------------------
// Multi-recipient transfer
// ---------------------------------------------------------------------------------------------

fn multi<C: ZCurve>(
    f: &Fx<C>,
    h: Header,
    mode: TransferMode,
    aud: bool,
    vs: &[u64],
) -> (MultiTransferStatement<C>, MultiTransferProof<C>, MultiTransferWitness<C>) {
    let ya = if aud { f.aud.y } else { G::<C>::zero() };
    let rs: Vec<(G<C>, u64)> = vs.iter().enumerate().map(|(j, v)| (key::<C>(10 + j as u32).y, *v)).collect();
    prove_transfer_multi(&f.gens, &f.from, h, mode, &rs, ya, f.acc, BAL, &mut rng()).unwrap()
}

fn multi_valid_and_effects<C: ZCurve>() {
    let f = fx::<C>();
    for (vs, aud, mode) in [
        (vec![250_000u64], true, TransferMode::Hash),
        (vec![0, 7, 0, 100], false, TransferMode::Bundle),
        (vec![1, 2, 3, 4, 5, 6, 7, 8], true, TransferMode::NoBundle),
    ] {
        let (st, p, w) = multi(&f, header(300), mode, aud, &vs);
        verify_transfer_multi(&f.gens, &st, &p).unwrap();
        let m = vs.len();
        let enc = p.encode();
        assert_eq!(enc.len(), MultiTransferProof::<C>::wire_len(m));
        assert!(MultiTransferProof::<C>::decode(&enc, m).unwrap() == p);
        assert!(MultiTransferStatement::<C>::decode(&st.encode()).unwrap() == st);
        let memo = if mode == TransferMode::Hash { memo_len(m) } else { 0 };
        assert_eq!(w.memo.len(), memo, "a memo on commit-reveal only");
        assert_eq!(st.header.memo_hash == [0; 32], memo == 0, "memoHash in the header exactly then");
        assert_eq!(st.payload(&w.memo).len(), 112 + (3 + 3 * m) * point_len::<C>() + memo, "… ‖ legs [‖ memo]");
        assert_eq!(st.bundles().len(), 16 + 4 * m * point_len::<C>(), "R = salt ‖ B_1 ‖ … ‖ B_M");
        // Effects: the sender loses Σv + fee, each recipient decrypts its own v (decoys: 0).
        let g = generator::<C>();
        let acc2 = Ciphertext { c: st.acc.c - st.c_deb - g * Fr::<C>::from(300u64), d: st.acc.d - st.d_out };
        assert_eq!(decrypt(&acc2, &f.from.x), BAL - vs.iter().sum::<u64>() - 300);
        for (j, l) in st.legs.iter().enumerate() {
            assert_eq!(decrypt(&Ciphertext { c: l.c_out, d: st.d_out }, &key::<C>(10 + j as u32).x), vs[j]);
            if aud {
                assert_eq!(decrypt(&Ciphertext { c: l.c_aud, d: st.d_out }, &f.aud.x), vs[j]);
            } else {
                assert!(l.c_aud.is_zero() && p.legs[j].a_aud.is_zero());
            }
        }
    }
    // M = 1 has exactly the single transfer's proof size (42P + 512).
    assert_eq!(MultiTransferProof::<C>::wire_len(1), TransferProof::<C>::wire_len());
}

#[test]
fn multi_valid_bn254() {
    multi_valid_and_effects::<Bn254>();
}

#[test]
fn multi_valid_bls12_381() {
    multi_valid_and_effects::<Bls12381>();
}

fn multi_negatives<C: ZCurve>() {
    let f = fx::<C>();
    let mut r = rng();
    let ya = f.aud.y;
    let y = |i: u32| key::<C>(i).y;
    let bad = |e: Result<_, ZError>| assert!(e.is_err());
    let pm = |rs: &[(G<C>, u64)], h: Header, r: &mut ChaCha20Rng| {
        prove_transfer_multi(&f.gens, &f.from, h, TransferMode::Hash, rs, ya, f.acc, BAL, r).map(|_| ())
    };
    bad(pm(&[], header(0), &mut r)); // no recipient
    let many = |n: u32| (10..10 + n).map(|i| (y(i), 1)).collect::<Vec<_>>();
    bad(pm(&many(17), header(0), &mut r)); // above the cap
    bad(pm(&[(y(10), 1), (y(10), 2)], header(0), &mut r)); // duplicate
    bad(pm(&[(y(10), 1), (f.from.y, 2)], header(0), &mut r)); // self
    bad(pm(&[(y(10), BAL), (y(11), 1)], header(0), &mut r)); // Σv > balance
    // 16 is the cap (BUNDLE: commit-reveal + auditor at M >= 8 on BLS12-381 is over the EIP-7825 gas cap, refused)
    prove_transfer_multi(&f.gens, &f.from, header(0), TransferMode::Bundle, &many(16), ya, f.acc, BAL, &mut r).unwrap();

    let (st, _, w) = multi(&f, header(300), TransferMode::Hash, true, &[0, 500, 0]);
    let one = Fr::<C>::one();
    let g = generator::<C>();
    let reject = |st: &MultiTransferStatement<C>, w: &MultiTransferWitness<C>, what: &str| {
        let p = prove_transfer_multi_core(&f.gens, st, w, &mut rng()).unwrap();
        assert!(verify_transfer_multi(&f.gens, st, &p).is_err(), "{what} must be rejected");
    };
    // A decoy's commitment opens to 1 while its ciphertexts hold 0 (E3_j/E7_j link).
    let mut w2 = w.clone();
    w2.v[0] += one;
    reject(&st, &w2, "v_j mismatch");
    // Credit one recipient more than the debit carries.
    let mut s2 = st.clone();
    s2.legs[2].c_out += g;
    reject(&s2, &w, "credit != debit");
    // Debit Σv − 1: the sender keeps one unit (E4).
    let mut s2 = st.clone();
    s2.c_deb -= g;
    reject(&s2, &w, "debit != Σv");
    // Auditor ciphertext of one leg encrypts another value (E6_j).
    let mut s2 = st.clone();
    s2.legs[1].c_aud += g;
    reject(&s2, &w, "auditor mismatch");
    // Wrong balance, wrong key.
    let mut w2 = w.clone();
    w2.b_prime += one;
    reject(&st, &w2, "wrong b'");
    let mut w2 = w.clone();
    w2.x = key::<C>(9).x;
    reject(&st, &w2, "wrong x");

    // A valid proof does not move to another mode, recipient order or recipient.
    let p = prove_transfer_multi_core(&f.gens, &st, &w, &mut rng()).unwrap();
    verify_transfer_multi(&f.gens, &st, &p).unwrap();
    let mut s = st.clone();
    s.mode = TransferMode::Bundle;
    assert!(verify_transfer_multi(&f.gens, &s, &p).is_err(), "mode switch");
    let mut s = st.clone();
    s.legs.swap(0, 2);
    assert!(verify_transfer_multi(&f.gens, &s, &p).is_err(), "reordered legs");
    let mut s = st.clone();
    s.legs[1].y_t = key::<C>(30).y;
    assert!(verify_transfer_multi(&f.gens, &s, &p).is_err(), "swapped recipient");
    // A single-recipient statement never decodes as a multi one (other opTag, psid, layout).
    let (single, _, _) = transfer(&f, header(0), true, 5);
    assert!(MultiTransferStatement::<C>::decode(&single.encode()).is_err());
}

#[test]
fn multi_negatives_bn254() {
    multi_negatives::<Bn254>();
}

#[test]
fn multi_negatives_bls12_381() {
    multi_negatives::<Bls12381>();
}

/// CTR-ZTH-30: `s` depends on the chain (K1: a re-created chain keeps chainId and the CREATE2 token address), the
/// salt (a retry at the same counter), the token, the sender, the counter and the key — and on nothing else: not on
/// the amounts, the recipients, the fee or the binding (so the sender rebuilds it from its key and chain data alone).
#[test]
fn s_inputs() {
    let (x, ua, salt) = (Fr::<Bn254>::from(7u64), [0x77u8; 32], [0x5a; 16]);
    let base = derive_s::<Bn254>(&x, &header(0), &ua, &salt);
    let mut h = header(0);
    h.chain_uid[31] ^= 1;
    assert_ne!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "chainUid");
    assert_ne!(derive_s::<Bn254>(&x, &header(0), &ua, &[0x5b; 16]), base, "salt");
    let mut h = header(0);
    h.token[0] ^= 1;
    assert_ne!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "token");
    let mut h = header(0);
    h.send_counter += 1;
    assert_ne!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "sendCounter");
    assert_ne!(derive_s::<Bn254>(&x, &header(0), &[0x78; 32], &salt), base, "fromUA");
    assert_ne!(derive_s::<Bn254>(&Fr::<Bn254>::from(8u64), &header(0), &ua, &salt), base, "the key");
    let mut h = header(300);
    (h.chain_id, h.acc_seq, h.binding, h.memo_hash, h.salt) = (1, 9, Binding::Relayed([1; 32]), [2; 32], [3; 16]);
    assert_eq!(derive_s::<Bn254>(&x, &h, &ua, &salt), base, "chainId, accSeq, fee, beneficiary, binding, the header fields are not inputs (the salt argument is)");
}

/// CTR-ZTH-50: the memo opens under the sender's key and header to the flag and the legs, and under nothing else.
#[test]
fn memo_roundtrip() {
    let (x, ua, salt) = (Fr::<Bn254>::from(7u64), [0x77u8; 32], [0x5a; 16]);
    let (y1, y2) = (generator::<Bn254>() * Fr::<Bn254>::from(3u64), generator::<Bn254>());
    let memo = seal_memo::<Bn254>(&x, &header(0), &ua, &salt, true, &[(y1, 1200u64), (y2, 0)]);
    assert_eq!(memo.len(), memo_len(2));
    assert_eq!(memo.len(), 17 + 2 * 40);
    assert_eq!(&memo[..16], &salt, "the salt in clear");
    let (s2, aud, legs) = open_memo::<Bn254>(&x, &header(0), &ua, &memo).unwrap();
    assert!(s2 == salt && aud);
    assert_eq!(legs[0], MemoLeg { amount: 1200, to_ua: zether_prover::curve::ua_of::<Bn254>(&y1) });
    assert_eq!(legs[1].amount, 0);
    let mut h = header(0);
    h.chain_uid[0] ^= 1;
    assert_ne!(open_memo::<Bn254>(&x, &h, &ua, &memo).unwrap().2, legs, "another chain: garbage");
    assert_ne!(open_memo::<Bn254>(&Fr::<Bn254>::from(8u64), &header(0), &ua, &memo).unwrap().2, legs, "another key");
    assert!(open_memo::<Bn254>(&x, &header(0), &ua, &memo[..memo.len() - 1]).is_err(), "length");
    let off = seal_memo::<Bn254>(&x, &header(0), &ua, &salt, false, &[(y1, 1200u64)]);
    assert!(!open_memo::<Bn254>(&x, &header(0), &ua, &off).unwrap().1, "the auditor flag");
}
