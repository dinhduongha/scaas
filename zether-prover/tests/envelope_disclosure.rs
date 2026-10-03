//! Envelope binding / EIP-712 digest / op calldata against foundry `cast` (tools/env_ref.sh),
//! relayed-binding end to end, and the three disclosure openings.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zether_prover::bulletproofs::Gens;
use zether_prover::curve::{Bls12381, Bn254, Fr, ZCurve};
use zether_prover::elgamal::encrypt;
use zether_prover::envelope::*;
use zether_prover::keys::ZetherKey;
use zether_prover::schnorr::{entry_ref, open_chaum_pedersen, open_sender, verify_opening, Entry, OpeningKind};
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
    assert_eq!(hex::encode(envelope_binding(31337, &TOK, &m)), "b0aeeef968fc66aa8d86051f2dd52314ef6da7f6d63140a03c7f424eb3eec4b2");
    assert_eq!(hex::encode(digest(31337, &TOK, &m)), "2406e667e3c3c66f9bfab8999395c9e9b1655f3d56fb7a42d0fb1429076be283");
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
        "6552874bc08a5e69d48f02326e94754e2f2fa8a33f36af66395a0ebba405eedc"
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

    // Disclosure of this transfer, three ways.
    let e = Entry {
        chain_id: 31337,
        token: TOK,
        entry_ref: entry_ref(31337, &TOK, &from.ua(), 3),
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
    // Opening bound to entryRef.
    let mut e2 = e;
    e2.entry_ref[0] ^= 1;
    assert!(verify_opening(&e2, 1234, OpeningKind::ReceiverX, &r_open).is_err());
}

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
    // zether-design §9 (RS2-14): direct transferConfidential has 4 args, no outer fee.
    assert_eq!(hex::encode(selector("transferConfidential(bytes,bytes,bytes,bytes32)")), "7c947e8e");
    assert_eq!(hex::encode(selector("burn(bytes,uint256,address,bytes32,bytes,bytes)")), "8938052e");
}
