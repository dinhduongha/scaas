//! Envelope binding / EIP-712 digest / calldata / entryRef / unwrap binding against foundry `cast`
//! (tools/env_ref.sh), relayed-binding end to end, and the four disclosure openings.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use zether_prover::bulletproofs::Gens;
use ark_ff::Zero;
use zether_prover::curve::{Bls12381, Fr, ZCurve, G};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
use zether_prover::elgamal::encrypt;
use zether_prover::envelope::*;
use zether_prover::keys::ZetherKey;
use zether_prover::schnorr::{entry_ref, open_chaum_pedersen, open_sender, open_sender_cp, verify_opening, Entry, OpeningKind};
use zether_prover::zether::{prove_transfer, verify_transfer, Binding, Header, TransferStatement};

const TOK: [u8; 20] = [0x11; 20];
const UID: [u8; 32] = hex_literal(b"24e43dcbfc9624b23bf89409acd104d6e5671e2c41d8c192373d65519321c464");

const fn hex_literal(s: &[u8; 64]) -> [u8; 32] {
    let mut o = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        o[i] = nib(s[2 * i]) << 4 | nib(s[2 * i + 1]);
        i += 1;
    }
    o
}

const fn nib(c: u8) -> u8 {
    if c <= b'9' { c - b'0' } else { c - b'a' + 10 }
}

fn mtx() -> MetaTx {
    MetaTx {
        from: [0xaa; 20],
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
    assert_eq!(hex::encode(envelope_binding(31337, &UID, &TOK, &m)), "29764986e75d275afefd0f799cae4e8ea5b1c9771e9ed9b43ffa9cc26d81350d");
    assert_eq!(hex::encode(digest(31337, &UID, &TOK, &m)), "0f6659afa867aae303e5e90723cdc6c803ec597a777d686a91fcd2226e962509");
    // data is outside the binding, inside the digest; chainUid is in both.
    let mut m2 = m.clone();
    m2.data = vec![1];
    assert_eq!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &UID, &TOK, &m2));
    assert_ne!(digest(31337, &UID, &TOK, &m), digest(31337, &UID, &TOK, &m2));
    assert_ne!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &[0x24; 32], &TOK, &m));
    assert_ne!(digest(31337, &UID, &TOK, &m), digest(31337, &[0x24; 32], &TOK, &m));
    // Unbound feeRecipient does not move the binding; a bound one does.
    m2.fee_recipient = [0xcd; 20];
    assert_eq!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &UID, &TOK, &m2));
    m2.mode |= MODE_RESTRICT_FEE_RECIPIENT;
    assert_ne!(envelope_binding(31337, &UID, &TOK, &m), envelope_binding(31337, &UID, &TOK, &m2));
    assert_eq!(
        hex::encode(transfer_call("mtxConfidentialTransferSingle(bytes,bytes,bytes,bytes32,bytes)", &[0xaa, 0xbb], &[0xcc, 0xdd, 0xee], &[0x22; 32])),
        "ebc62fbb00000000000000000000000000000000000000000000000000000000000000a000000000000000000000000000000000000000000000000000000000000000e00000000000000000000000000000000000000000000000000000000000000120222222222222222222222222222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003ccddee000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode(unshield_call(&[0xaa, 0xbb], &[0xcc, 0xdd], &[0; 32], &{ let mut t = [0x44; 32]; t[..12].fill(0); t }, 400_000)),
        "a85a2deb00000000000000000000000000000000000000000000000000000000000000e000000000000000000000000000000000000000000000000000000000000001200000000000000000000000000000000000000000000000000000000000000160000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000061a8000000000000000000000000044444444444444444444444444444444444444440000000000000000000000000000000000000000000000000000000000000002aabb0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002ccdd00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(
        hex::encode(entry_ref(31337, &UID, &TOK, &[0x55; 32], 3)),
        "a23a980f358bbb47c48881a7a3307f419df074facb84ed878f881d623bf7bb7e"
    );
    let mut min_out = [0u8; 32];
    min_out[30..].copy_from_slice(&1000u16.to_be_bytes());
    assert_eq!(
        hex::encode(unwrap_binding(&[0x44; 20], &min_out)),
        "2c9fb536a22f965b443581f392be9ed8757762610e687fd2e4f73d2da7202591"
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
    let binding = envelope_binding(31337, &UID, &TOK, &m);
    let h = Header {
        chain_id: 31337,
        chain_uid: UID,
        token: TOK,
        binding: Binding::Relayed(binding),
        send_counter: 3,
        acc_seq: 1,
        fee: 0,
        beneficiary: [0; 32],
        amount: 0,
        recipient: [0; 32],
        salt: [0; 16],
        memo_hash: [0; 32],
        valid_until_block: 100,
    };
    let (st, p, w) = prove_transfer(&gens, &from, h, to.y, aud.y, acc, 5000, 1234, &mut rng).unwrap();
    verify_transfer(&gens, &st, &p).unwrap();
    m.data = transfer_call("mtxConfidentialTransferSingle(bytes,bytes,bytes,bytes32,bytes)", &st.payload(), &p.encode(), &[0; 32]);
    // Same proof inside a different envelope (other nonce) → different binding → rejected.
    let mut m2 = m.clone();
    m2.nonce += 1;
    let mut st2 = st.clone();
    st2.header.binding = Binding::Relayed(envelope_binding(31337, &UID, &TOK, &m2));
    assert!(verify_transfer(&gens, &st2, &p).is_err());
    // Lifted out and called directly → DIRECT statement → rejected; a DIRECT word that is not 0 decodes as Unwrap.
    st2.header.binding = Binding::Direct;
    assert!(verify_transfer(&gens, &st2, &p).is_err());
    st2.header.binding = Binding::Unwrap(binding);
    assert!(verify_transfer(&gens, &st2, &p).is_err());
    assert_eq!(TransferStatement::<C>::decode(&st2.encode()).unwrap().header.binding, Binding::Unwrap(binding));
    // Another chain with the same chain id (a re-created chain): chainUid differs → rejected.
    let mut st3 = st.clone();
    st3.header.chain_uid[0] ^= 1;
    assert!(verify_transfer(&gens, &st3, &p).is_err());

    // Disclosure of this transfer, four ways.
    let e = Entry {
        chain_id: 31337,
        chain_uid: UID,
        token: TOK,
        entry_ref: entry_ref(31337, &UID, &TOK, &from.ua(), 3),
        index: 0,
        y_t: st.y_t,
        c_out: st.c_out,
        d_out: st.d_out,
        y_a: st.y_a,
        c_aud: st.c_aud,
        d_aud: st.d_out,
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
    // Opening bound to chainUid (CTR-ZTH-36).
    let eu = Entry { chain_uid: [0x24; 32], ..e };
    assert!(verify_opening(&eu, 1234, OpeningKind::ReceiverX, &r_open).is_err());
    assert!(verify_opening(&eu, 1234, OpeningKind::SenderCp, &cp).is_err());
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

#[cfg(feature = "bn254")]
#[test]
fn relayed_and_disclosure_bn254() {
    relayed_and_disclosure::<Bn254>();
}

#[test]
fn relayed_and_disclosure_bls12_381() {
    relayed_and_disclosure::<Bls12381>();
}

#[test]
fn entry_point_selectors_match_the_spec() {
    // CTR-ZTH-45 / plan 5h D20: the shared `IConfidentialToken` names; the multi-recipient default is
    // `mtxConfidentialTransfer`, the single format `mtxConfidentialTransferSingle` (payload, proof, auth, beneficiary,
    // accHint; Zether: `auth` and `accHint` empty).
    assert_eq!(hex::encode(selector("mtxConfidentialTransfer(bytes,bytes,bytes,bytes32,bytes)")), "5dc7af97");
    assert_eq!(hex::encode(selector("mtxConfidentialTransferSingle(bytes,bytes,bytes,bytes32,bytes)")), "ebc62fbb");
    assert_eq!(hex::encode(selector("mtxUnshield(bytes,bytes,bytes,bytes32,bytes,uint256,bytes32)")), "a85a2deb");
    assert_eq!(hex::encode(selector("mtxShield(bytes32,uint256)")), "e9385800");
}

/// Final review m3 (CTR-ZTH-51): an unshield to a derived UA. `proveBurn` takes a 32-byte recipient id as well as a
/// 20-byte address (its padded id); the statement's word 12 and the calldata's `recipient` word are that id, and the
/// statement decodes back to it (no "dirty high bytes" refusal).
#[test]
fn burn_recipient_address_or_ua() {
    use serde_json::{json, Value};
    use zether_prover::curve::{encode_point, encode_scalar};
    use zether_prover::zether::BurnStatement;
    type C = Bls12381;
    let from = ZetherKey::<C>::conf(&[3u8; 64], 60, 0).unwrap();
    let acc = encrypt(&from.y, 5000, &Fr::<C>::from(77u64));
    let hx = |b: &[u8]| format!("0x{}", hex::encode(b));
    let ua = [0x5au8; 32];
    let mut padded = [0u8; 32];
    padded[12..].fill(0x44);
    let req = |given: String| json!({
        "curve": "bls12381", "key": {"x": hx(&encode_scalar::<C>(&from.x))}, "chainId": 31337, "chainUid": hx(&UID),
        "token": hx(&TOK), "sendCounter": 0, "accSeq": 1, "validUntilBlock": 100, "balance": 5000, "amount": 1000,
        "recipient": given,
        "acc": {"C": hx(&encode_point::<C>(&acc.c)), "D": hx(&encode_point::<C>(&acc.d))},
    });
    for (given, id) in [(hx(&[0x44; 20]), padded), (hx(&ua), ua)] {
        let out: Value = serde_json::from_str(&zether_prover::api::call("proveBurn", &req(given).to_string()).unwrap()).unwrap();
        let st = hex::decode(&out["statement"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(&st[384..416], &id, "statement word 12");
        assert_eq!(BurnStatement::<C>::decode(&st).unwrap().header.recipient, id);
        let cd = hex::decode(&out["directCalldata"].as_str().unwrap()[2..]).unwrap();
        assert_eq!(&cd[4 + 6 * 32..4 + 7 * 32], &id, "mtxUnshield's recipient argument");
        let v = json!({"curve": "bls12381", "statement": out["statement"], "proof": out["proof"]});
        let ok: Value = serde_json::from_str(&zether_prover::api::call("verifyBurn", &v.to_string()).unwrap()).unwrap();
        assert_eq!(ok["ok"], json!(true));
    }
    let err = zether_prover::api::call("proveBurn", &req(hx(&[1; 21])).to_string()).unwrap_err();
    assert!(err.contains("20-byte address or a 32-byte UA id"), "{err}");
}
