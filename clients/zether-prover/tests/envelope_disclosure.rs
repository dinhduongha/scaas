//! Envelope binding / EIP-712 digest / op calldata against foundry `cast` (tools/env_ref.sh),
//! relayed-binding end to end, and the four disclosure openings.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zether_prover::bulletproofs::Gens;
use ark_ff::Zero;
use zether_prover::curve::{Bls12381, Bn254, Fr, ZCurve, G};
use zether_prover::elgamal::encrypt;
use zether_prover::envelope::*;
use zether_prover::keys::ZetherKey;
use zether_prover::schnorr::{entry_ref, open_chaum_pedersen, open_sender, open_sender_cp, verify_opening, Entry, OpeningKind};
use zether_prover::zether::{prove_transfer, verify_transfer, Binding, Header};

const TOK: [u8; 20] = [0x11; 20];

fn mtx() -> MetaTx {
    MetaTx {
        from: [0xaa; 20],
        to: [0; 20],
        value: 0,
        data: hex::decode("deadbeef").unwrap(),
        batch: [1; 32],
        nonce: 7,
        valid_until: 1_800_000_000,
        mode: MODE_RESTRICT_RELAYER | MODE_FEE_FIXED,
        relayer: [0xbb; 20],
        fee: 1000,
        fee_recipient: [0xcc; 20], // not bound under this mode → hashed as 0
    }
}

#[test]
fn envelope_matches_cast() {
    let m = mtx();
    assert_eq!(hex::encode(envelope_binding(31337, &TOK, &m)), "4d183691f11a44b9d055aaed42a4b26d9c7b4de5b72619c6ad1f83c5675a83aa");
    assert_eq!(hex::encode(digest(31337, &TOK, &m)), "63cc8309bee1be82025aa9f74b24113d13d2b1c3a2dfbe8003521b246d89087d");
    // data is outside the binding, inside the digest.
    let mut m2 = m.clone();
    m2.data = vec![1];
    assert_eq!(envelope_binding(31337, &TOK, &m), envelope_binding(31337, &TOK, &m2));
    assert_ne!(digest(31337, &TOK, &m), digest(31337, &TOK, &m2));
    // Unbound feeRecipient does not move the binding; a bound one does.
    m2.fee_recipient = [0xcd; 20];
    assert_eq!(envelope_binding(31337, &TOK, &m), envelope_binding(31337, &TOK, &m2));
    m2.mode |= MODE_RESTRICT_FEE_RECIPIENT;
    assert_ne!(envelope_binding(31337, &TOK, &m), envelope_binding(31337, &TOK, &m2));
    assert_eq!(
        hex::encode(transfer_data(&[0xaa, 0xbb], &[0xcc, 0xdd, 0xee], &[], &[0x22; 32])),
        "d228e5c0000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c0000000000000000000000000000000000000000000000000000000000000010022222222222222222222222222222222222222222222222222222222222222220000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ccddee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode(burn_data(&[0xaa, 0xbb], 400_000, &[0x44; 20], &[0; 32], &[0xcc, 0xdd], &[])),
        "1d0a6c7c00000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000061a8000000000000000000000000044444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002ccdd0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode(entry_ref(31337, &TOK, &[0x55; 32], 3)),
        "77b2ecc949e3ee4236bb158750916d10eaa531605fe2f3dbe790b26ee11c1643"
    );
}

fn relayed_and_disclosure<C: ZCurve>() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let gens = Gens::<C>::new();
    let from = ZetherKey::<C>::conf(&[3u8; 64], 60, 0).unwrap();
    let to = ZetherKey::<C>::conf(&[3u8; 64], 60, 1).unwrap();
    let aud = ZetherKey::<C>::conf(&[4u8; 64], 60, 0).unwrap();
    let acc = encrypt(&from.y, 5000, &Fr::<C>::from(77u64));
    let mut m = mtx();
    m.data.clear();
    let binding = envelope_binding(31337, &TOK, &m);
    let h = Header {
        chain_id: 31337,
        token: TOK,
        binding: Binding::Relayed(binding),
        send_counter: 3,
        acc_seq: 1,
        fee: 0,
        beneficiary: [0; 32],
        amount: 0,
        recipient: [0; 20],
    };
    let (st, p, w) = prove_transfer(&gens, &from, h, to.y, aud.y, acc, 5000, 1234, &mut rng).unwrap();
    verify_transfer(&gens, &st, &p).unwrap();
    m.data = transfer_data(&st.payload(), &p.encode(), &[], &[0; 32]);
    // Same proof inside a different envelope (other nonce) → different binding → rejected.
    let mut m2 = m.clone();
    m2.nonce += 1;
    let mut st2 = st.clone();
    st2.header.binding = Binding::Relayed(envelope_binding(31337, &TOK, &m2));
    assert!(verify_transfer(&gens, &st2, &p).is_err());
    // Lifted out and called directly → DIRECT statement → rejected.
    st2.header.binding = Binding::Direct;
    assert!(verify_transfer(&gens, &st2, &p).is_err());

    // Disclosure of this transfer, four ways.
    let e = Entry {
        chain_id: 31337,
        token: TOK,
        entry_ref: entry_ref(31337, &TOK, &from.ua(), 3),
        index: 0,
        y_t: st.y_t,
        c_out: st.c_out,
        d_out: st.d_out,
        y_a: st.y_a,
        c_aud: st.c_aud,
    };
    let s_open = open_sender::<C>(&w.s);
    verify_opening(&e, 1234, OpeningKind::SenderS, &s_open).unwrap();
    assert!(verify_opening(&e, 1235, OpeningKind::SenderS, &s_open).is_err());
    assert!(verify_opening(&e, 1234 + (1 << 32), OpeningKind::SenderS, &s_open).is_err());
    let r_open = open_chaum_pedersen(&e, 1234, OpeningKind::ReceiverX, &to, &mut rng).unwrap();
    verify_opening(&e, 1234, OpeningKind::ReceiverX, &r_open).unwrap();
    assert!(verify_opening(&e, 1233, OpeningKind::ReceiverX, &r_open).is_err());
    assert!(verify_opening(&e, 1234, OpeningKind::Auditor, &r_open).is_err());
    let a_open = open_chaum_pedersen(&e, 1234, OpeningKind::Auditor, &aud, &mut rng).unwrap();
    verify_opening(&e, 1234, OpeningKind::Auditor, &a_open).unwrap();
    // A key that does not own the ciphertext cannot open it; a wrong amount is refused.
    assert!(open_chaum_pedersen(&e, 1234, OpeningKind::ReceiverX, &aud, &mut rng).is_err());
    assert!(open_chaum_pedersen(&e, 999, OpeningKind::ReceiverX, &to, &mut rng).is_err());
    // Receiver is the auditor (Y_a == Y_t, C_aud == C_out) and the RNG is dead: the RECEIVER_X
    // and AUDITOR openings must still use different nonces, or x = (z1 - z2)/(e1 - e2).
    let e3 = Entry { y_a: e.y_t, c_aud: e.c_out, ..e };
    let ro = open_chaum_pedersen(&e3, 1234, OpeningKind::ReceiverX, &to, &mut DeadRng).unwrap();
    let ao = open_chaum_pedersen(&e3, 1234, OpeningKind::Auditor, &to, &mut DeadRng).unwrap();
    verify_opening(&e3, 1234, OpeningKind::ReceiverX, &ro).unwrap();
    verify_opening(&e3, 1234, OpeningKind::Auditor, &ao).unwrap();
    let a1 = 96 + 32..96 + 32 + 2 * C::COORD_LEN;
    assert_ne!(ro[a1.clone()], ao[a1], "same nonce across opening kinds");
    // SENDER_CP (Z10): the sender proves the leg on `s` without handing it over.
    let cp = open_sender_cp(&e, 1234, &w.s, &mut rng).unwrap();
    verify_opening(&e, 1234, OpeningKind::SenderCp, &cp).unwrap();
    assert!(verify_opening(&e, 1233, OpeningKind::SenderCp, &cp).is_err());
    assert!(verify_opening(&e, 1234, OpeningKind::ReceiverX, &cp).is_err());
    assert!(open_sender_cp(&e, 1233, &w.s, &mut rng).is_err());
    assert!(open_sender_cp(&e, 1234, &(w.s + Fr::<C>::from(1u64)), &mut rng).is_err());
    assert!(open_chaum_pedersen(&e, 1234, OpeningKind::SenderCp, &to, &mut rng).is_err());
    // Every kind is bound to the leg index j.
    let ej = Entry { index: 1, ..e };
    for (kind, o) in [(OpeningKind::ReceiverX, &r_open), (OpeningKind::Auditor, &a_open), (OpeningKind::SenderCp, &cp)] {
        assert!(verify_opening(&ej, 1234, kind, o).is_err(), "{kind:?} moved to another leg");
    }
    // Auditor left out of this transfer (Z12, C_aud = O): AUDITOR is false, the others still open.
    let eo = Entry { c_aud: G::<C>::zero(), ..e };
    assert!(verify_opening(&eo, 1234, OpeningKind::Auditor, &a_open).is_err());
    verify_opening(&eo, 1234, OpeningKind::ReceiverX, &r_open).unwrap();
    verify_opening(&eo, 1234, OpeningKind::SenderCp, &cp).unwrap();
    // Opening bound to entryRef.
    let mut e2 = e;
    e2.entry_ref[0] ^= 1;
    assert!(verify_opening(&e2, 1234, OpeningKind::ReceiverX, &r_open).is_err());
    assert!(verify_opening(&e2, 1234, OpeningKind::SenderCp, &cp).is_err());
}

struct DeadRng;
impl rand_chacha::rand_core::RngCore for DeadRng {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, d: &mut [u8]) {
        d.fill(0)
    }
    fn try_fill_bytes(&mut self, d: &mut [u8]) -> Result<(), rand_chacha::rand_core::Error> {
        d.fill(0);
        Ok(())
    }
}
impl rand_chacha::rand_core::CryptoRng for DeadRng {}

#[test]
fn relayed_and_disclosure_bn254() {
    relayed_and_disclosure::<Bn254>();
}

#[test]
fn relayed_and_disclosure_bls12_381() {
    relayed_and_disclosure::<Bls12381>();
}

#[test]
fn direct_call_selectors_match_s2_spec() {
    // zether-design §9 (RS2-14): direct transfers have 4 args, no outer fee. The selector of
    // `transferConfidential` now belongs to the multi-recipient HASH entry; the single format is
    // `transferConfidentialSingle` (same arguments).
    assert_eq!(hex::encode(selector("transferConfidential(bytes,bytes,bytes,bytes32)")), "7c947e8e");
    assert_eq!(hex::encode(selector("transferConfidentialSingle(bytes,bytes,bytes,bytes32)")), "663f4320");
    assert_eq!(hex::encode(selector("burn(bytes,uint256,address,bytes32,bytes,bytes)")), "8938052e");
}
