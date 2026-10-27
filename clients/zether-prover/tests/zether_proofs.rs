//! Transfer/burn: valid proofs on both curves, Σ soundness negatives, Σ-Bullets linkage,
//! statement binding (every header field), wire round-trips, ElGamal effects end to end.

use ark_ff::{One, Zero};
use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zether_prover::bulletproofs::Gens;
use zether_prover::curve::{generator, point_len, Bls12381, Fr, ZCurve, G};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
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
        recipient: [0; 32],
        salt: [0; 16],
        memo_hash: [0; 32],
        valid_until_block: 1_000,
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
        assert_eq!(st.payload().len(), 112 + 6 * point_len::<C>(), "accSeq ‖ sendCounter ‖ validUntilBlock ‖ salt ‖ points");
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

#[cfg(feature = "bn254")]
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
    #[cfg(feature = "bn254")]
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

#[cfg(feature = "bn254")]
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
        |h| h.valid_until_block += 1,
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

#[cfg(feature = "bn254")]
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
    h.recipient[12..].fill(0x44); // a padded address
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
    assert_eq!(st.payload().len(), 96 + point_len::<C>(), "accSeq ‖ sendCounter ‖ validUntilBlock ‖ Y_f");
    // Effect: acc −= [amount + fee]G.
    let acc2 = Ciphertext { c: st.acc.c - generator::<C>() * Fr::<C>::from(400_300u64), d: st.acc.d };
    assert_eq!(decrypt(&acc2, &f.from.x), BAL - 400_300);
    // Relayer cannot redirect or resize the withdrawal.
    let muts: Vec<fn(&mut Header)> = vec![
        |h| h.recipient[0] ^= 1,
        |h| h.amount += 1,
        |h| h.amount -= 1,
        |h| h.fee += 1,
        |h| h.send_counter += 1,
        |h| h.valid_until_block -= 1,
    ];
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

#[cfg(feature = "bn254")]
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

#[cfg(feature = "bn254")]
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
    prove_transfer_multi(&f.gens, &f.from, h, 0, mode, &rs, ya, f.acc, BAL, &mut rng()).unwrap()
}

fn multi_valid_and_effects<C: ZCurve>() {
    let f = fx::<C>();
    for (vs, aud, mode) in [
        (vec![250_000u64], true, TransferMode::Hash),
        (vec![0, 7, 0, 100], false, TransferMode::Bundle),
        (vec![1, 2, 3, 4, 5, 6, 7], true, TransferMode::Hash), // M = 7 with the auditor: the edge on BLS12-381
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
        assert_eq!(st.payload(w.decoy_fee, &w.memo).len(), 176 + (3 + 4 * m) * point_len::<C>() + memo, "… ‖ legs [‖ memo]");
        assert_eq!(st.bundles().len(), 16 + 5 * m * point_len::<C>(), "R = salt ‖ B_1 ‖ … ‖ B_M, 5 points per leg");
        // Effects: the sender loses Σv + fee, each recipient decrypts its own v (decoys: 0).
        let g = generator::<C>();
        let acc2 = Ciphertext { c: st.acc.c - st.c_deb - g * Fr::<C>::from(300u64), d: st.acc.d - st.d_out };
        assert_eq!(decrypt(&acc2, &f.from.x), BAL - vs.iter().sum::<u64>() - 300);
        for (j, l) in st.legs.iter().enumerate() {
            assert_eq!(decrypt(&Ciphertext { c: l.c_out, d: st.d_out }, &key::<C>(10 + j as u32).x), vs[j]);
            if aud {
                assert_eq!(decrypt(&Ciphertext { c: l.c_aud, d: l.d_aud }, &f.aud.x), vs[j]);
            } else {
                assert!(l.c_aud.is_zero() && l.d_aud.is_zero() && p.legs[j].a_aud.is_zero() && p.legs[j].a_daud.is_zero());
                assert!(p.legs[j].z_t.is_zero());
            }
        }
    }
    // M = 1 is the single transfer's proof (42P + 512) plus `A_Daud` and `z_t` (review C0-1).
    assert_eq!(MultiTransferProof::<C>::wire_len(1), TransferProof::<C>::wire_len() + point_len::<C>() + 32);
}

#[cfg(feature = "bn254")]
#[test]
fn multi_valid_bn254() {
    multi_valid_and_effects::<Bn254>();
}

#[test]
fn multi_valid_bls12_381() {
    multi_valid_and_effects::<Bls12381>();
}

/// Owner fee ruling 4 (2026-10-20): the payload's `decoyFee` word (bytes 144..176), the statement fee `txFee + M · d`
/// (with and without a beneficiary), the sender debited by it, the bound `< 2^64`, and the gas a decoy payout adds.
#[test]
fn multi_decoy_fee_bls12_381() {
    type C = Bls12381;
    let f = fx::<C>();
    let rs: Vec<(G<C>, u64)> = [0u64, 70, 0].iter().enumerate().map(|(j, v)| (key::<C>(10 + j as u32).y, *v)).collect();
    let prove = |h: Header, d: u64, rs: &[(G<C>, u64)]| {
        prove_transfer_multi(&f.gens, &f.from, h, d, TransferMode::Bundle, rs, f.aud.y, f.acc, BAL, &mut rng())
    };
    let (st, p, w) = prove(header(300), 5, &rs).unwrap();
    assert_eq!(st.header.fee, 300 + 3 * 5, "statement fee = txFee + M · decoyFee");
    verify_transfer_multi(&f.gens, &st, &p).unwrap();
    let pl = st.payload(w.decoy_fee, &w.memo);
    assert_eq!(&pl[112..144], &{ let mut x = [0u8; 32]; x[31] = 3; x }, "be32(M)");
    assert_eq!(&pl[144..176], &{ let mut x = [0u8; 32]; x[31] = 5; x }, "be32(decoyFee)");
    let g = generator::<C>();
    let acc2 = Ciphertext { c: st.acc.c - st.c_deb - g * Fr::<C>::from(315u64), d: st.acc.d - st.d_out };
    assert_eq!(decrypt(&acc2, &f.from.x), BAL - 70 - 315);
    // no beneficiary: fee = M · d, a multiple of M; a txFee without one is still refused
    let (st0, p0, _) = prove(header(0), 4, &rs[..2]).unwrap();
    assert_eq!(st0.header.fee, 8);
    verify_transfer_multi(&f.gens, &st0, &p0).unwrap();
    let mut bad = st0.clone();
    bad.header.fee = 7;
    assert!(bad.validate().is_err(), "fee without beneficiary not M · decoyFee");
    assert!(prove(Header { beneficiary: [0; 32], ..header(300) }, 4, &rs).is_err());
    assert!(prove(header(300), u64::MAX / 2, &rs).is_err(), "txFee + M · d >= 2^64");
    // the decoy payout's gas: bls12-381 commit-reveal without the auditor, direct, fits M = 8 without a decoy fee, 7 with one;
    // a leg costs 116,698 under Amsterdam (F185 ZetherDecoyFee.test_gas_decoyFeePerLeg; 28,663 on Osaka)
    assert!(DECOY_LEG_GAS >= 116_698, "the measured Amsterdam leg payout");
    assert_eq!(build_gas::<C>(TransferMode::Hash, false, false, 8, true), transfer_gas::<C>(TransferMode::Hash, false, false, 8) + 8 * DECOY_LEG_GAS);
    let rs8: Vec<(G<C>, u64)> = (0..8).map(|i| (key::<C>(10 + i).y, 1)).collect();
    let none = |d| prove_transfer_multi(&f.gens, &f.from, header(0), d, TransferMode::Hash, &rs8, G::<C>::zero(), f.acc, BAL, &mut rng()).map(|_| ());
    assert!(none(0).is_ok());
    match none(1) {
        Err(ZError::GasCap { m: 8, max_m: 7, .. }) => {}
        other => panic!("M = 8 with a decoy fee not refused: {other:?}"),
    }
}

fn multi_negatives<C: ZCurve>() {
    let f = fx::<C>();
    let mut r = rng();
    let ya = f.aud.y;
    let y = |i: u32| key::<C>(i).y;
    let bad = |e: Result<_, ZError>| assert!(e.is_err());
    let pm = |rs: &[(G<C>, u64)], h: Header, r: &mut ChaCha20Rng| {
        prove_transfer_multi(&f.gens, &f.from, h, 0, TransferMode::Hash, rs, ya, f.acc, BAL, r).map(|_| ())
    };
    bad(pm(&[], header(0), &mut r)); // no recipient
    let many = |n: u32| (10..10 + n).map(|i| (y(i), 1)).collect::<Vec<_>>();
    bad(pm(&many(17), header(0), &mut r)); // above the cap
    bad(pm(&[(y(10), 1), (y(10), 2)], header(0), &mut r)); // duplicate
    bad(pm(&[(y(10), 1), (f.from.y, 2)], header(0), &mut r)); // self
    bad(pm(&[(y(10), BAL), (y(11), 1)], header(0), &mut r)); // Σv > balance
    // 16 = MAX_RECIPIENTS is the statement's bound (no form builds 16 under the gas cap: `gas_table_edges`): a 16-leg
    // statement validates and round-trips, a 17-leg one does not
    let (st, _, _) = multi(&f, header(0), TransferMode::Hash, true, &[0, 500, 0]);
    let mut s16 = st.clone();
    // structural only: every extra leg its own auditor copy (two legs never share C_aud / D_aud)
    let leg = |yt: G<C>, i: u64| {
        let d = generator::<C>() * Fr::<C>::from(1000 + i);
        Leg { y_t: yt, c_aud: st.legs[0].c_aud + d, d_aud: st.legs[0].d_aud + d, ..st.legs[0].clone() }
    };
    for i in 0..13 {
        s16.legs.push(leg(y(40 + i), i as u64));
    }
    s16.validate().unwrap();
    assert!(MultiTransferStatement::<C>::decode(&s16.encode()).unwrap() == s16, "16 legs decode");
    s16.legs.push(leg(y(60), 99));
    bad(s16.validate());
    bad(MultiTransferStatement::<C>::decode(&s16.encode()).map(|_| ()));
    // review T1 m2: a memo hash exactly on commit-reveal
    let mut h = st.clone();
    h.mode = TransferMode::Bundle;
    bad(h.validate());
    h.header.memo_hash = [0; 32];
    h.validate().unwrap();

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

/// Review T1 m2: the single format has no memo: a caller's memo hash is dropped, and a statement with one is refused.
#[test]
fn single_has_no_memo_hash() {
    let f = fx::<Bls12381>();
    let mut h = header(0);
    h.memo_hash = [7; 32];
    let (mut st, _, _) = transfer(&f, h, true, 5);
    assert_eq!(st.header.memo_hash, [0; 32]);
    st.header.memo_hash = [7; 32];
    assert!(st.validate().is_err());
}

/// Review T1 I1, final review I1: the most recipients per (stored form, auditor in / out) under the EIP-7825 cap less
/// the 1 % margin, from the measured transaction gas limits (zether.md §19), direct and relayed (a build with an
/// envelope binding takes the relayed column): the edge builds, one more is refused with the estimate. Columns:
/// compact, bundle; each (auditor in, out).
fn gas_table_edges<C: ZCurve>(relayed: bool, want: [[usize; 2]; 2]) {
    let f = fx::<C>();
    let ya = f.aud.y;
    let mut h = header(0);
    if relayed {
        h.binding = Binding::Relayed([0x33; 32]);
    }
    for (mode, row) in [TransferMode::Hash, TransferMode::Bundle].into_iter().zip(want) {
        for (aud, max) in [(true, row[0]), (false, row[1])] {
            let what = format!("{} {mode:?} auditor {aud} relayed {relayed}", C::NAME);
            assert_eq!(max_recipients::<C>(mode, aud, relayed), max, "{what}");
            assert!(transfer_gas::<C>(mode, aud, relayed, max) <= TX_GAS_CAP - GAS_MARGIN);
            assert!(transfer_gas::<C>(mode, aud, relayed, max + 1) > TX_GAS_CAP - GAS_MARGIN);
            let rs = |n: usize| (0..n as u32).map(|i| (key::<C>(10 + i).y, 1)).collect::<Vec<_>>();
            let y_a = if aud { ya } else { G::<C>::zero() };
            let build = |n| prove_transfer_multi(&f.gens, &f.from, h.clone(), 0, mode, &rs(n), y_a, f.acc, BAL, &mut rng());
            assert!(build(max).is_ok(), "{what}: M = {max} builds");
            match build(max + 1).map(|_| ()) {
                Err(ZError::GasCap { m, gas, cap, max_m, .. }) => {
                    let want = (max + 1, transfer_gas::<C>(mode, aud, relayed, max + 1), TX_GAS_CAP, max);
                    assert_eq!((m, gas, cap, max_m), want, "{what}");
                }
                other => panic!("{what}: M = {} not refused: {other:?}", max + 1),
            }
        }
    }
}

#[cfg(feature = "bn254")]
#[test]
fn gas_table_edges_bn254() {
    gas_table_edges::<Bn254>(false, [[8, 9], [8, 8]]);
    gas_table_edges::<Bn254>(true, [[8, 8], [7, 8]]);
}

#[test]
fn gas_table_edges_bls12_381() {
    gas_table_edges::<Bls12381>(false, [[7, 8], [6, 7]]);
    gas_table_edges::<Bls12381>(true, [[7, 7], [6, 6]]);
}

/// The relayed column is the dearer one: at `M` = 9 a bn254 compact transfer without the auditor fits direct, not
/// relayed; past a measured row the estimate grows by the row's last step.
#[cfg(feature = "bn254")]
#[test]
fn gas_relayed_column_and_extrapolation() {
    assert_eq!(transfer_gas::<Bn254>(TransferMode::Hash, false, false, 9), 16_364_440);
    assert_eq!(transfer_gas::<Bn254>(TransferMode::Hash, false, true, 9), 16_936_814);
    assert_eq!(transfer_gas::<Bn254>(TransferMode::Hash, false, true, 11), 16_936_814 + 2 * (16_936_814 - 15_262_054));
    let f = fx::<Bn254>();
    let rs = (0..9).map(|i| (key::<Bn254>(10 + i).y, 1)).collect::<Vec<_>>();
    let h = Header { binding: Binding::Relayed([0x33; 32]), ..header(0) };
    let msg = prove_transfer_multi(&f.gens, &f.from, h, 0, TransferMode::Hash, &rs, G::<Bn254>::zero(), f.acc, BAL, &mut rng())
    .map(|_| ())
    .unwrap_err()
    .to_string();
    assert!(msg.contains("compact without the auditor, relayed, M = 9") && msg.contains("none without the auditor (~16559080)"), "{msg}");
}

#[cfg(feature = "bn254")]
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
    let (x, ua, salt) = (Fr::<Bls12381>::from(7u64), [0x77u8; 32], [0x5a; 16]);
    let base = derive_s::<Bls12381>(&x, &header(0), &ua, &salt);
    let mut h = header(0);
    h.chain_uid[31] ^= 1;
    assert_ne!(derive_s::<Bls12381>(&x, &h, &ua, &salt), base, "chainUid");
    assert_ne!(derive_s::<Bls12381>(&x, &header(0), &ua, &[0x5b; 16]), base, "salt");
    let mut h = header(0);
    h.token[0] ^= 1;
    assert_ne!(derive_s::<Bls12381>(&x, &h, &ua, &salt), base, "token");
    let mut h = header(0);
    h.send_counter += 1;
    assert_ne!(derive_s::<Bls12381>(&x, &h, &ua, &salt), base, "sendCounter");
    assert_ne!(derive_s::<Bls12381>(&x, &header(0), &[0x78; 32], &salt), base, "fromUA");
    assert_ne!(derive_s::<Bls12381>(&Fr::<Bls12381>::from(8u64), &header(0), &ua, &salt), base, "the key");
    let mut h = header(300);
    (h.chain_id, h.acc_seq, h.binding, h.memo_hash, h.salt) = (1, 9, Binding::Relayed([1; 32]), [2; 32], [3; 16]);
    assert_eq!(derive_s::<Bls12381>(&x, &h, &ua, &salt), base, "chainId, accSeq, fee, beneficiary, binding, the header fields are not inputs (the salt argument is)");
}

/// CTR-ZTH-50: the memo opens under the sender's key and header to the flag and the legs, and under nothing else.
#[test]
fn memo_roundtrip() {
    let (x, ua, salt) = (Fr::<Bls12381>::from(7u64), [0x77u8; 32], [0x5a; 16]);
    let (y1, y2) = (generator::<Bls12381>() * Fr::<Bls12381>::from(3u64), generator::<Bls12381>());
    let memo = seal_memo::<Bls12381>(&x, &header(0), &ua, &salt, true, &[(y1, 1200u64), (y2, 0)]);
    assert_eq!(memo.len(), memo_len(2));
    assert_eq!(memo.len(), 17 + 2 * 40);
    assert_eq!(&memo[..16], &salt, "the salt in clear");
    let (s2, aud, legs) = open_memo::<Bls12381>(&x, &header(0), &ua, &memo).unwrap();
    assert!(s2 == salt && aud);
    assert_eq!(legs[0], MemoLeg { amount: 1200, to_ua: zether_prover::curve::ua_of::<Bls12381>(&y1) });
    assert_eq!(legs[1].amount, 0);
    let mut h = header(0);
    h.chain_uid[0] ^= 1;
    assert_ne!(open_memo::<Bls12381>(&x, &h, &ua, &memo).unwrap().2, legs, "another chain: garbage");
    assert_ne!(open_memo::<Bls12381>(&Fr::<Bls12381>::from(8u64), &header(0), &ua, &memo).unwrap().2, legs, "another key");
    assert!(open_memo::<Bls12381>(&x, &header(0), &ua, &memo[..memo.len() - 1]).is_err(), "length");
    // review T1 m4: the longest memo (M = MAX_RECIPIENTS, 657 B), which no build reaches under the gas cap
    let legs16: Vec<_> = (1..=16u64).map(|i| (generator::<Bls12381>() * Fr::<Bls12381>::from(i), i)).collect();
    let long = seal_memo::<Bls12381>(&x, &header(0), &ua, &salt, true, &legs16);
    assert_eq!(long.len(), 657);
    assert_eq!(open_memo::<Bls12381>(&x, &header(0), &ua, &long).unwrap().2[15].amount, 16);
    let off = seal_memo::<Bls12381>(&x, &header(0), &ua, &salt, false, &[(y1, 1200u64)]);
    assert!(!open_memo::<Bls12381>(&x, &header(0), &ua, &off).unwrap().1, "the auditor flag");
}

// ---------------------------------------------------------------------------------------------
// Review C0-1 (owner ruling 2026-10-27, option (ii)): every audited leg its own auditor randomness `t_j`
// ---------------------------------------------------------------------------------------------

/// The audited multi-recipient transfer round-trips, the auditor decrypts every leg as `C_aud_j − [x_a]D_aud_j`, the
/// sender re-derives every `t_j` (`derive_t`), and no public combination of the auditor copies cancels the mask: two
/// decoys (`v = 0`) have distinct `C_aud`, `C_aud_j − C_aud_k ≠ [v_j − v_k]G`, and `h_k·C_aud_j − h_j·C_aud_k ≠
/// [h_k·v_j − h_j·v_k]G` for every small public `h` (what broke option (i)).
#[test]
fn multi_audited_roundtrip() {
    type C = Bls12381;
    let f = fx::<C>();
    let vs = [0u64, 70_000, 0, 5];
    let (st, p, w) = multi(&f, header(300), TransferMode::Bundle, true, &vs);
    verify_transfer_multi(&f.gens, &st, &p).unwrap();
    assert!(MultiTransferStatement::<C>::decode(&st.encode()).unwrap() == st);
    assert!(MultiTransferProof::<C>::decode(&p.encode(), vs.len()).unwrap() == p);
    let g = generator::<C>();
    for (j, l) in st.legs.iter().enumerate() {
        assert_eq!(l.c_aud - l.d_aud * f.aud.x, g * Fr::<C>::from(vs[j]), "the auditor decrypts leg {j}");
        let t = derive_t::<C>(&f.from.x, &st.header, &f.from.ua(), &st.header.salt, j);
        assert!(t == w.t[j] && l.d_aud == g * t, "t_{j} re-derives from the key and chain data");
        assert!(t != w.s, "t_{j} is not s");
        assert!(l.d_aud != st.d_out);
    }
    // decoys 0 and 2 encrypt the same 0: their copies still differ
    assert!(st.legs[0].c_aud != st.legs[2].c_aud && st.legs[0].d_aud != st.legs[2].d_aud, "decoys share no C_aud");
    for j in 0..vs.len() {
        for k in 0..vs.len() {
            if j == k {
                continue;
            }
            let (cj, ck) = (st.legs[j].c_aud, st.legs[k].c_aud);
            assert!(cj - ck != g * (Fr::<C>::from(vs[j]) - Fr::<C>::from(vs[k])), "C_aud_{j} − C_aud_{k} leaks");
            for hj in 1..=4u64 {
                for hk in 1..=4u64 {
                    let (hj, hk) = (Fr::<C>::from(hj), Fr::<C>::from(hk));
                    let lin = cj * hk - ck * hj;
                    assert!(!lin.is_zero(), "h_k·C_aud_{j} − h_j·C_aud_{k} = O");
                    assert!(lin != g * (hk * Fr::<C>::from(vs[j]) - hj * Fr::<C>::from(vs[k])), "the mask cancels");
                }
            }
        }
    }
    // the indices differ per leg; tag, salt and counter enter t_j, the binding and accSeq do not (as `s`)
    let (x, ua, salt) = (Fr::<C>::from(7u64), [0x77u8; 32], [0x5a; 16]);
    let t0 = derive_t::<C>(&x, &header(0), &ua, &salt, 0);
    assert!(t0 != derive_t::<C>(&x, &header(0), &ua, &salt, 1), "j");
    assert!(t0 != derive_t::<C>(&x, &header(0), &ua, &[0x5b; 16], 0), "salt");
    assert!(t0 != derive_s::<C>(&x, &header(0), &ua, &salt), "its own tag");
    let mut h = header(0);
    h.send_counter += 1;
    assert!(t0 != derive_t::<C>(&x, &h, &ua, &salt, 0), "sendCounter");
    let mut h = header(300);
    (h.acc_seq, h.binding, h.valid_until_block) = (9, Binding::Relayed([1; 32]), 7);
    assert!(t0 == derive_t::<C>(&x, &h, &ua, &salt, 0), "accSeq, binding, validUntilBlock are no inputs");
    // the auditor key as a party, with the auditor on: refused (prover and statement); off: allowed
    let rs = |y0: G<C>| vec![(y0, 1u64), (key::<C>(11).y, 2)];
    let pm = |rs: &[(G<C>, u64)], ya: G<C>| {
        prove_transfer_multi(&f.gens, &f.from, header(0), 0, TransferMode::Bundle, rs, ya, f.acc, BAL, &mut rng()).map(|_| ())
    };
    assert!(pm(&rs(f.aud.y), f.aud.y).unwrap_err().to_string().contains("AuditorKeyAsParty"), "Y_tj == Y_a");
    assert!(pm(&rs(f.aud.y), G::<C>::zero()).is_ok(), "the auditor's key as a recipient with the auditor off");
    let ya_f = f.from.y;
    assert!(pm(&rs(key::<C>(12).y), ya_f).unwrap_err().to_string().contains("AuditorKeyAsParty"), "Y_f == Y_a");
    let single = |y_to: G<C>, ya: G<C>| prove_transfer(&f.gens, &f.from, header(0), y_to, ya, f.acc, BAL, 5, &mut rng());
    assert!(single(f.aud.y, f.aud.y).map(|_| ()).unwrap_err().to_string().contains("AuditorKeyAsParty"), "single Y_t");
    assert!(single(f.to.y, f.from.y).map(|_| ()).unwrap_err().to_string().contains("AuditorKeyAsParty"), "single Y_f");
}

/// `D_aud_j` is bound by E6′_j: another `D_aud_j`, `A_Daud_j` or `z_tj` is refused; `D_aud_j = O` with the auditor on and
/// `D_aud_j ≠ O` (or `z_tj ≠ 0`) with it off are refused before the equations.
#[test]
fn multi_tampered_d_aud_rejected() {
    type C = Bls12381;
    let f = fx::<C>();
    let g = generator::<C>();
    let (st, p, w) = multi(&f, header(0), TransferMode::Hash, true, &[0, 900, 0]);
    verify_transfer_multi(&f.gens, &st, &p).unwrap();
    let mut s = st.clone();
    s.legs[1].d_aud += g;
    assert!(verify_transfer_multi(&f.gens, &s, &p).is_err(), "D_aud moved");
    let mut s = st.clone();
    s.legs[1].d_aud = st.legs[0].d_aud;
    assert!(verify_transfer_multi(&f.gens, &s, &p).is_err(), "another leg's D_aud");
    let mut s = st.clone();
    s.legs[2].d_aud = G::<C>::zero();
    assert!(s.validate().is_err(), "auditor on, D_aud = O");
    // two decoys (v = 0) under one reused t: byte-identical copies, refused even with an otherwise honest proof
    let (mut s, mut w2) = (st.clone(), w.clone());
    (s.legs[2].c_aud, s.legs[2].d_aud, w2.t[2]) = (st.legs[0].c_aud, st.legs[0].d_aud, w.t[0]);
    let q = prove_transfer_multi_core(&f.gens, &s, &w2, &mut rng()).unwrap();
    match verify_transfer_multi(&f.gens, &s, &q) {
        Err(ZError::BadStatement(m)) => assert!(m.contains("share C_aud"), "{m}"),
        other => panic!("a reused t_j not refused: {:?}", other.map(|_| ())),
    }
    let mut q = p.clone();
    q.legs[1].a_daud += g;
    assert!(verify_transfer_multi(&f.gens, &st, &q).is_err(), "A_Daud moved");
    let mut q = p.clone();
    q.legs[1].z_t += Fr::<C>::one();
    assert!(verify_transfer_multi(&f.gens, &st, &q).is_err(), "z_t moved");
    // a witness whose t_j is not the one inside (C_aud_j, D_aud_j): E6_j / E6′_j fail
    let mut w2 = w.clone();
    w2.t[1] += Fr::<C>::one();
    let q = prove_transfer_multi_core(&f.gens, &st, &w2, &mut rng()).unwrap();
    assert!(verify_transfer_multi(&f.gens, &st, &q).is_err(), "wrong t_j");
    // a forged copy under the shared s (the pre-fix form) does not verify under its D_aud
    let mut s = st.clone();
    s.legs[1].c_aud = g * Fr::<C>::from(900u64) + st.y_a * w.s;
    let q = prove_transfer_multi_core(&f.gens, &s, &w, &mut rng()).unwrap();
    assert!(verify_transfer_multi(&f.gens, &s, &q).is_err(), "C_aud under s");
    // auditor off: every D_aud_j = O, every z_tj = 0
    let (st, p, _) = multi(&f, header(0), TransferMode::Hash, false, &[0, 900]);
    verify_transfer_multi(&f.gens, &st, &p).unwrap();
    let mut s = st.clone();
    s.legs[0].d_aud = g;
    assert!(s.validate().is_err(), "auditor off, D_aud != O");
    let mut q = p.clone();
    q.legs[0].z_t = Fr::<C>::one();
    assert!(verify_transfer_multi(&f.gens, &st, &q).is_err(), "auditor off, z_t != 0");
    let mut q = p.clone();
    q.legs[0].a_daud = g;
    assert!(verify_transfer_multi(&f.gens, &st, &q).is_err(), "auditor off, A_Daud != O");
}

/// `…/v2` statements and proofs (the committed pre-fix vectors, `vectors/v2/`) are refused: another `proofSystemId`
/// (`…/v3`), another header (512 bytes, `validUntilBlock`), another leg layout. A v3 statement relabelled `…/v2` is refused
/// too.
#[test]
fn v2_vectors_refused() {
    use serde_json::{json, Value};
    use zether_prover::curve::keccak256;
    assert_eq!(zether_prover::curve::proof_system_id::<Bls12381>(), keccak256(b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v3"));
    assert_eq!(
        zether_prover::curve::proof_system_id_multi::<Bls12381>(),
        keccak256(b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v3/multi")
    );
    let dir = format!("{}/vectors/v2", env!("CARGO_MANIFEST_DIR"));
    for (file, cmd) in [
        ("transfer_bls12381.json", "verifyTransfer"),
        ("transfer_multi_bls12381.json", "verifyTransferMulti"),
        ("burn_bls12381.json", "verifyBurn"),
    ] {
        let v: Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}/{file}")).unwrap()).unwrap();
        let req = json!({"curve": "bls12381", "statement": v["statement"], "proof": v["proof"]});
        let out: Value = serde_json::from_str(&zether_prover::api::call(cmd, &req.to_string()).unwrap()).unwrap();
        assert_eq!(out["ok"], json!(false), "{file}: a v2 proof verified");
    }
    let f = fx::<Bls12381>();
    let (st, _, _) = multi(&f, header(0), TransferMode::Hash, true, &[0, 900]);
    let mut b = st.encode();
    b[32..64].copy_from_slice(&keccak256(b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v2/multi"));
    assert!(MultiTransferStatement::<Bls12381>::decode(&b).is_err(), "v2 multi label");
    let (st, _, _) = transfer(&f, header(0), true, 5);
    let mut b = st.encode();
    b[32..64].copy_from_slice(&keccak256(b"scaas/zether/sigma-bullets/bls12-381/n64-n64/v2"));
    assert!(TransferStatement::<Bls12381>::decode(&b).is_err(), "v2 label");
}
