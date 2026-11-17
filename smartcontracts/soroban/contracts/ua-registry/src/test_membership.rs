// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! MA-S, CTR-UA-37 on Soroban (owner 2026-11-02): listing in an `msig` is no consent, a member accepts, and at verify only accepted
//! members count. `portable.json` `memberships` are the rows EVM verifies, read here unchanged.
extern crate std;
use std::{vec, vec::Vec as StdVec};

use serde_json::Value;
use soroban_sdk::{
    testutils::{storage::Persistent as _, Address as _, Events as _, Ledger as _},
    Address, Bytes, BytesN, Env, Event as _, IntoVal, Val, Vec as SVec,
};

use crate::{
    digest,
    test::{self, err, msig, n, no_attrs, portable, Msig, Sk, PORTABLE},
    test_ua8::{authorise, classical_members, flipped, relayed, HOST_REFUSED},
    test_verify::{b, hx, json, kind_of, n32},
    Error, Key, UaMembershipAccepted, UaRegistryClient,
};
use scaas_ua_common::*;

const DAY: u32 = 17_280;
const NO_SLOTS: fn(&Env) -> SVec<MemberSig> = |env| SVec::new(env);

fn rows() -> StdVec<Value> {
    json(PORTABLE)["memberships"].as_array().unwrap().clone()
}

fn row(name: &str) -> Value {
    rows().into_iter().find(|r| r["name"] == name).unwrap()
}

fn slot_of(env: &Env, r: &Value) -> MemberSig {
    MemberSig { index: r["index"].as_u64().unwrap() as u32, key_data: Bytes::new(env), sig: b(env, &hx(&r["sig"])) }
}

/// A 2-of-3 of in-test ed25519 keys, classical-dominant: an empty `pop`, nobody accepted; `signable`.
fn two_of_three(env: &Env, c: &UaRegistryClient) -> (Msig, Sk, Sk, Sk) {
    let (x, y, z) = (test::ed(71), test::ed(72), test::ed(73));
    for s in [&x, &y, &z] {
        s.register(env, c);
    }
    let m = msig(env, 2, &[(0x0102, x.ua(env).to_array(), 1), (0x0102, y.ua(env).to_array(), 1), (0x0102, z.ua(env).to_array(), 1)]);
    m.register(env, c, &NO_SLOTS(env));
    (m, x, y, z)
}

/// `(digest, auth)` of `require_authorized(m, metatx, d)` by `signers`, in slot order.
fn authorization(env: &Env, m: &Msig, signers: &[&Sk], d: u8) -> (BytesN<32>, UaSig) {
    let d = n(env, [d; 32]);
    let mut slots: StdVec<_> = signers.iter().map(|s| m.slot(env, s, PURPOSE_METATX, &d)).collect();
    slots.sort_by_key(|s| s.0);
    (d, test::msig_auth(env, &slots))
}

/// The tag and the struct are EVM's, and every row's digest, message and member digest rebuild here, from `ua` and `member` alone.
#[test]
fn rows_digests_rebuild() {
    let (env, _) = test::setup();
    let p = json(PORTABLE);
    assert_eq!(n32(&env, &p["tags"]["PURPOSE_MEMBERSHIP"]["hash"]).to_array(), PURPOSE_MEMBERSHIP);
    assert_eq!(p["tags"]["PURPOSE_MEMBERSHIP"]["tag"], "scaas.ua.purpose.membership.v1");
    assert_eq!(n32(&env, &p["typed"]["types"]["UAMembership"]["typehash"]).to_array(), UA_MEMBERSHIP_TYPEHASH);
    let pm = n(&env, PURPOSE_MEMBERSHIP);
    assert_eq!(rows().len(), 6);
    for r in rows() {
        let (ua, member) = (n32(&env, &r["ua"]), n32(&env, &r["member"]));
        let typed = membership_digest(&env, &ua, &member).to_bytes();
        assert_eq!(typed, n32(&env, &r["digest"]), "{}", r["name"]);
        let m = digest::ua_message(&env, 0x0120, &pm, &typed);
        assert_eq!(m.to_bytes(), n32(&env, &r["message"]), "{}", r["name"]);
        assert_eq!(digest::member_digest(&env, &ua, &m), n32(&env, &r["memberDigest"]), "{}", r["name"]);
    }
}

/// `msig-classical` (`evm-eoa`, `bls-bn254-minsig`, `schnorr-bn254`, `p256`) and `msig-pq-native` (`evm-eoa`, `mldsa65`): every row
/// accepts its slot unchanged, each by its own kind's rule: the chain verifies `evm-eoa`, `p256`, `mldsa65` with no relayer, and asks
/// for one on the two relayer-checked members.
#[test]
fn rows_accept_unchanged() {
    let (env, c, by) = relayed();
    classical_members(&env, &c, &by);
    portable(&env, "mldsa65#1").on(&c);
    let (classical, pq) = (portable(&env, "msig-classical"), portable(&env, "msig-pq-native"));
    classical.on(&c);
    assert_eq!((0..4).filter(|i| c.member_accepted(&classical.ua, i)).count(), 0, "an empty `pop` accepts nobody");
    pq.on(&c);
    assert!(c.member_accepted(&pq.ua, &0) && c.member_accepted(&pq.ua, &1), "a pop signer reads accepted with no call");
    let events = |ua: &BytesN<32>, member: &BytesN<32>, index, checked, sig: &Bytes| {
        UaMembershipAccepted { ua: ua.clone(), member: member.clone(), index, sig_hash: env.crypto().keccak256(sig).into(), checked }.to_xdr(&env, &c.address)
    };
    for name in ["msig-classical/0", "msig-classical/3"] {
        let r = row(name);
        c.accept_membership(&classical.ua, &slot_of(&env, &r), &None);
        let i = r["index"].as_u64().unwrap() as u32;
        assert_eq!(env.events().all().events(), [events(&classical.ua, &n32(&env, &r["member"]), i, Checked::Chain, &slot_of(&env, &r).sig)], "{name}");
        assert!(c.member_accepted(&classical.ua, &i), "{name}");
        assert_eq!(c.member_checked(&classical.ua, &i), Checked::Chain, "{name}");
        assert_eq!(c.membership_sig_of(&classical.ua, &i), Bytes::new(&env), "{name}: the chain checked it, nothing to re-check");
    }
    assert!(env.auths().is_empty(), "the chain's own check asks nobody");
    for name in ["msig-classical/1", "msig-classical/2"] {
        let r = row(name);
        let i = r["index"].as_u64().unwrap() as u32;
        assert_eq!(err(c.try_accept_membership(&classical.ua, &slot_of(&env, &r), &None)), Error::NotVerifiable, "{name}");
        assert!(!c.member_accepted(&classical.ua, &i), "{name}");
        c.accept_membership(&classical.ua, &slot_of(&env, &r), &by);
        assert_eq!(env.events().all().events(), [events(&classical.ua, &n32(&env, &r["member"]), i, Checked::Relayer(by.clone().unwrap()), &slot_of(&env, &r).sig)], "{name}");
        assert_eq!(c.member_checked(&classical.ua, &i), Checked::Relayer(by.clone().unwrap()), "{name}");
        assert_eq!(c.membership_sig_of(&classical.ua, &i), slot_of(&env, &r).sig, "{name}: the row's bytes, for a client to re-check");
    }
    assert_eq!((0..4).filter(|i| c.member_accepted(&classical.ua, i)).count(), 4);
    // the `pop` already accepted these two: the rows are a no-op here, no second word on the same slot
    for name in ["msig-pq-native/0", "msig-pq-native/1"] {
        let r = row(name);
        c.accept_membership(&pq.ua, &slot_of(&env, &r), &None);
        assert_eq!(env.events().all().events().len(), 0, "{name}");
    }
}

/// One byte of a row's signature changed: the chain's own check refuses, however the row was refused, and the slot stays out.
#[test]
fn a_row_with_a_changed_byte_refused() {
    let (env, c, by) = relayed();
    classical_members(&env, &c, &by);
    let classical = portable(&env, "msig-classical");
    classical.on(&c);
    for name in ["msig-classical/0", "msig-classical/3"] {
        let r = row(name);
        let i = r["index"].as_u64().unwrap() as u32;
        let good = slot_of(&env, &r);
        let bad = MemberSig { sig: flipped(&env, &good.sig), ..good.clone() };
        assert!(c.try_accept_membership(&classical.ua, &bad, &None).is_err(), "{name}");
        assert!(!c.member_accepted(&classical.ua, &i), "{name}");
        c.accept_membership(&classical.ua, &good, &None);
    }
}

/// A registered member and an `evm-eoa` member accept with no account of their own: the entry takes no submitter, and asks no auth.
/// An `evm-eoa` slot, accepted or not, never signs an operation here: its own check is `NotVerifiable`, only after the accepted bit.
#[test]
fn native_and_registered_members_accept() {
    let (env, c) = test::setup();
    let (k, e, q) = (test::k1(6), test::ed(7), test::ml(9));
    e.register(&env, &c);
    q.register(&env, &c);
    let id = test::eoa(&env, &k);
    let m = msig(&env, 1, &[(0x0001, id, 1), (0x0102, e.ua(&env).to_array(), 2), (0x0131, q.ua(&env).to_array(), 1)]);
    m.register(&env, &c, &NO_SLOTS(&env));
    let i = m.index(&id);
    let typed = m.membership(&env, &id);
    let slot = |sig: StdVec<u8>| MemberSig { index: i, key_data: Bytes::new(&env), sig: b(&env, &sig) };
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot(test::k1_sign(&k, &m.md(&env, PURPOSE_MEMBERSHIP, &typed).to_array())), &None)), Error::Unauthorized, "not the member digest");
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot(test::k1_sign(&test::k1(66), &typed.to_array())), &None)), Error::Unauthorized, "another EOA");
    let eoa_slot = test::msig_auth(&env, &[(i, vec![], test::k1_sign(&k, &m.md(&env, PURPOSE_METATX, &n(&env, [1; 32])).to_array()))]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &n(&env, [1; 32]), &eoa_slot)), Error::Unauthorized, "not accepted: refused before its own check");
    c.accept_membership(&m.ua, &slot(test::k1_sign(&k, &typed.to_array())), &None);
    assert!(c.member_accepted(&m.ua, &i));
    assert_eq!(err(c.try_require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &n(&env, [1; 32]), &eoa_slot)), Error::NotVerifiable);
    m.accepted_by(&env, &c, &[&e, &q]);
    assert!(env.auths().is_empty());
    for s in [&e, &q] {
        let (d, a) = authorization(&env, &m, &[s], 2);
        c.require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &d, &a);
    }
}

/// A `G…` member accepts as it signs: the host checks `require_auth_for_args((ua, purpose, typed))`, over a real signed entry anyone
/// may carry; `sig` stays empty. No entry, or an entry for anything else, is refused; a slot that carries bytes is `Unauthorized`.
#[test]
fn g_member_accepts_by_a_signed_entry() {
    let gsk = ed25519_dalek::SigningKey::from_bytes(&[8; 32]);
    let gpk = gsk.verifying_key().to_bytes();
    let mut snap: soroban_ledger_snapshot::LedgerSnapshot = Env::default().to_ledger_snapshot();
    snap.ledger_entries.push(test::ledger_account(gpk));
    let env = Env::from_ledger_snapshot(snap);
    env.cost_estimate().budget().reset_unlimited();
    env.ledger().with_mut(|l| l.network_id = test::NETWORK);
    let c = test::deploy(&env, &[]);
    let m = msig(&env, 1, &[(0x0011, gpk, 1)]);
    m.register(&env, &c, &NO_SLOTS(&env));
    assert!(c.record_of(&m.ua).unwrap().signable, "listed: a verify would pass it but for the bit");
    let (pa, typed) = (n(&env, PURPOSE_MEMBERSHIP), m.membership(&env, &gpk));
    let empty = MemberSig { index: 0, key_data: Bytes::new(&env), sig: Bytes::new(&env) };
    let (pm, d) = (n(&env, PURPOSE_METATX), n(&env, [0x51; 32]));
    let authorize = |nonce| {
        let args: SVec<Val> = (m.ua.clone(), pm.clone(), d.clone()).into_val(&env);
        env.set_auths(&[test::signed_entry(&env, &gsk, nonce, &c.address, "require_authorized", args)]);
        c.try_require_authorized(&m.ua, &pm, &d, &test::msig_auth(&env, &[(0, vec![], vec![])]))
    };
    assert_eq!(err(authorize(1)), Error::Unauthorized, "a good host auth of an unaccepted slot");
    env.set_auths(&[]);
    assert!(c.try_accept_membership(&m.ua, &empty, &None).is_err(), "without the entry");
    let other: SVec<Val> = (m.ua.clone(), pa.clone(), n(&env, [9; 32])).into_val(&env);
    env.set_auths(&[test::signed_entry(&env, &gsk, 2, &c.address, "accept_membership", other)]);
    assert!(c.try_accept_membership(&m.ua, &empty, &None).is_err(), "an entry for another digest");
    let pop: SVec<Val> = (m.ua.clone(), n(&env, PURPOSE_POP_V2), typed.clone()).into_val(&env);
    env.set_auths(&[test::signed_entry(&env, &gsk, 3, &c.address, "accept_membership", pop)]);
    assert!(c.try_accept_membership(&m.ua, &empty, &None).is_err(), "an entry under another purpose");
    let args: SVec<Val> = (m.ua.clone(), pa, typed).into_val(&env);
    env.set_auths(&[test::signed_entry(&env, &gsk, 4, &c.address, "accept_membership", args.clone())]);
    let bytes = MemberSig { sig: b(&env, &[1]), ..empty.clone() };
    assert_eq!(err(c.try_accept_membership(&m.ua, &bytes, &None)), Error::Unauthorized, "a native slot carrying bytes");
    assert!(!c.member_accepted(&m.ua, &0));
    env.set_auths(&[test::signed_entry(&env, &gsk, 5, &c.address, "accept_membership", args)]);
    c.accept_membership(&m.ua, &empty, &None);
    assert_eq!((c.member_accepted(&m.ua, &0), c.member_checked(&m.ua, &0)), (true, Checked::Chain));
    assert_eq!(c.membership_sig_of(&m.ua, &0), Bytes::new(&env), "the host checked it");
    authorize(6).unwrap().unwrap();
}

/// A classical-dominant `msig` authorizes nothing until the accepted weight reaches the threshold: each good signature of an unaccepted
/// slot is refused, the same call passes after it accepts.
#[test]
fn nothing_until_the_accepted_weight_reaches_the_threshold() {
    let (env, c) = test::setup();
    let (m, x, y, z) = two_of_three(&env, &c);
    let pm = n(&env, PURPOSE_METATX);
    let (d, a) = authorization(&env, &m, &[&x, &y], 1);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &a)), Error::Unauthorized);
    m.accepted_by(&env, &c, &[&x]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d, &a)), Error::Unauthorized, "one of two accepted");
    let (d2, one) = authorization(&env, &m, &[&x], 2);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d2, &one)), Error::Unauthorized, "the accepted slot alone is under the threshold");
    m.accepted_by(&env, &c, &[&y]);
    c.require_authorized(&m.ua, &pm, &d, &a);
    let (d3, with_z) = authorization(&env, &m, &[&x, &z], 3);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &d3, &with_z)), Error::Unauthorized, "a third slot, still only listed");
    m.accepted_by(&env, &c, &[&z]);
    c.require_authorized(&m.ua, &pm, &d3, &with_z);
}

/// A 1-of-2 PQ-eligible `msig` signed by `p` alone: its `pop` accepts `p`, and only `p`, with no call.
fn pq_one_of_two(env: &Env, c: &UaRegistryClient) -> (Msig, Sk, Sk) {
    let (p, q) = (test::ml(21), test::ml(22));
    p.register(env, c);
    q.register(env, c);
    let m = msig(env, 1, &[(0x0131, p.ua(env).to_array(), 1), (0x0131, q.ua(env).to_array(), 1)]);
    let rd = test::reg_digest(env, &m.ua, 0x0120);
    m.register(env, c, &test::member_sigs(env, &[m.slot(env, &p, PURPOSE_POP_V2, &rd)]));
    (m, p, q)
}

/// `set_pqz_key` goes through the accepted bits too: the same record by a good signature of the slot that only is listed is refused,
/// and passes after it accepts. The `pop` itself is exempt. `set_kem_key` is `KemHolder` before any slot, accepted or not: an `msig`
/// has no KEM key (CTR-UA-32).
#[test]
fn records_count_accepted_slots_only() {
    let (env, c) = test::setup();
    let (m, p, q) = pq_one_of_two(&env, &c);
    let (ip, iq) = (m.index(&p.ua(&env).to_array()), m.index(&q.ua(&env).to_array()));
    assert!(c.member_accepted(&m.ua, &ip) && !c.member_accepted(&m.ua, &iq));
    assert_eq!((c.member_checked(&m.ua, &ip), c.member_checked(&m.ua, &iq)), (Checked::Chain, Checked::None));

    let kem = crate::test_ua8::kem_row_key(&env);
    let kem_pk_ = kem_pk(&env, &kem);
    let kem_sig = |v: u64, s: &Sk| {
        let d = kem_record_digest(&env, &m.ua, v, &kem_pk_).to_bytes();
        test::msig_auth(&env, &[m.slot(&env, s, PURPOSE_KEM, &d)])
    };
    for s in [&q, &p] {
        assert_eq!(err(c.try_set_kem_key(&m.ua, &1, &kem, &kem_sig(1, s), &None)), Error::KemHolder);
    }
    let (key, ph) = (b(&env, &[7; 16_384]), n(&env, [9; 32]));
    let d = pqz_key_record_digest(&env, &m.ua, &pqz_key_hash(&env, &key), &ph).to_bytes();
    let by_q = test::msig_auth(&env, &[m.slot(&env, &q, PURPOSE_PQZ_KEY, &d)]);
    assert_eq!(err(c.try_set_pqz_key(&m.ua, &key, &ph, &by_q, &None)), Error::Unauthorized);
    assert_eq!(c.pqz_key_of(&m.ua), None);
    m.accepted_by(&env, &c, &[&q]);
    assert_eq!(err(c.try_set_kem_key(&m.ua, &2, &kem, &kem_sig(2, &q), &None)), Error::KemHolder);
    c.set_pqz_key(&m.ua, &key, &ph, &by_q, &None);
    assert_eq!(c.kem_key_of(&m.ua), None);
    assert!(c.pqz_key_of(&m.ua).is_some());
}

/// A relayer-checked slot: refused unaccepted whatever a listed relayer says, accepted only on that relayer's attestation, marked with
/// its id in state and in the event, and it never signs an operation (it has no `Signer`).
#[test]
fn a_relayer_checked_slot() {
    let (env, c, by) = relayed();
    let f = portable(&env, "fndsa512");
    f.on_by(&c, &by);
    let q = test::ml(61);
    q.register(&env, &c);
    let m = msig(&env, 1, &[(0x0132, f.ua.to_array(), 1), (0x0131, q.ua(&env).to_array(), 1)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    m.register(&env, &c, &test::member_sigs(&env, &[m.slot(&env, &q, PURPOSE_POP_V2, &rd)]));
    let fi = m.index(&f.ua.to_array());
    let (key, ph) = (b(&env, &[7; 16_384]), n(&env, [9; 32]));
    let attested = test::msig_auth(&env, &[(fi, vec![], vec![0xf5; 666])]);
    assert_eq!(err(c.try_set_pqz_key(&m.ua, &key, &ph, &attested, &by)), Error::Unauthorized, "the bit is asked before the relayer");
    assert_eq!(err(c.try_set_pqz_key(&m.ua, &key, &ph, &attested, &None)), Error::Unauthorized);
    let slot = MemberSig { index: fi, key_data: Bytes::new(&env), sig: b(&env, &[0xf5; 666]) };
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot, &None)), Error::NotVerifiable);
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot, &Some(Address::generate(&env)))), Error::RelayerNotListed);
    assert_eq!(c.member_checked(&m.ua, &fi), Checked::None);
    c.accept_membership(&m.ua, &slot, &by);
    let sig_hash: BytesN<32> = env.crypto().keccak256(&slot.sig).into();
    assert_eq!(env.events().all().events(), [UaMembershipAccepted { ua: m.ua.clone(), member: f.ua.clone(), index: fi, sig_hash, checked: Checked::Relayer(by.clone().unwrap()) }.to_xdr(&env, &c.address)]);
    assert_eq!(c.member_checked(&m.ua, &fi), Checked::Relayer(by.clone().unwrap()));
    assert_eq!(c.membership_sig_of(&m.ua, &fi), slot.sig, "junk bytes too: a client's re-check finds them out");
    assert_eq!(c.membership_sig_of(&m.ua, &m.index(&q.ua(&env).to_array())), Bytes::new(&env), "a `pop` slot: `pop_of` holds it");
    env.as_contract(&c.address, || env.storage().persistent().remove(&Key::AcceptSig(m.ua.clone(), fi)));
    assert_eq!(c.membership_sig_of(&m.ua, &fi), Bytes::new(&env));
    c.set_pqz_key(&m.ua, &key, &ph, &attested, &by); // no verify reads the entry
    assert_eq!(c.pqz_key_of(&m.ua).unwrap().3, Checked::Relayer(by.clone().unwrap()));
    let pm = n(&env, PURPOSE_METATX);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &n(&env, [1; 32]), &attested)), Error::Unauthorized, "an attestation is never a signature");
}

/// Owner 2026-11-02: a listed relayer's junk takes the slot for good, on that registry: the member's real acceptance is a no-op, and the junk
/// stays, its relayer named. The bound: nothing counts it as a signature, and a client's re-check refuses its bytes (CTR-UA-34 rule 6).
#[test]
fn a_listed_relayers_junk_acceptance_is_write_once() {
    let (env, c, by) = relayed();
    let f = portable(&env, "fndsa512");
    f.on_by(&c, &by);
    let q = test::ml(61);
    q.register(&env, &c);
    let m = msig(&env, 1, &[(0x0132, f.ua.to_array(), 1), (0x0131, q.ua(&env).to_array(), 1)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    m.register(&env, &c, &test::member_sigs(&env, &[m.slot(&env, &q, PURPOSE_POP_V2, &rd)]));
    let fi = m.index(&f.ua.to_array());
    let junk = MemberSig { index: fi, key_data: Bytes::new(&env), sig: b(&env, &[0xf5; 666]) };
    c.accept_membership(&m.ua, &junk, &by);
    let real = MemberSig { index: fi, key_data: Bytes::new(&env), sig: b(&env, &[0xaa; 666]) }; // stands for the member's real signature
    c.accept_membership(&m.ua, &real, &by);
    assert_eq!(env.events().all().events().len(), 0, "a no-op");
    assert_eq!(c.membership_sig_of(&m.ua, &fi), junk.sig, "the junk stays for good");
    assert_eq!(c.member_checked(&m.ua, &fi), Checked::Relayer(by.clone().unwrap()), "its relayer named");
    let auth = test::msig_auth(&env, &[(fi, vec![], vec![0xf5; 666])]);
    let pm = n(&env, PURPOSE_METATX);
    assert_eq!(err(c.try_require_authorized(&m.ua, &pm, &n(&env, [1; 32]), &auth)), Error::Unauthorized, "the slot never signs");
}

/// The attestation binds every argument of `accept_membership` under its own name (`attest_digest`): another slot, another signature,
/// another `ua`, another relayer or another function's digest does not pass, and the changed call stores on its own attestation.
#[test]
fn the_attestation_binds() {
    let env = test::new_env();
    let (r, other) = (Address::generate(&env), Address::generate(&env));
    let c = test::deploy(&env, &[r.clone(), other.clone()]);
    env.mock_all_auths();
    let mk = |id: u8| {
        let ua = c.register(&0x0103, &b(&env, &[0x70 + id; 32]), &no_attrs(&env), &b(&env, &[1; 64]), &Bytes::new(&env), &Some(r.clone()));
        (0x0103u16, ua.to_array(), 1u16)
    };
    let (ms, by) = ([mk(0), mk(1)], Some(r.clone()));
    let (m, m2) = (msig(&env, 1, &ms), msig(&env, 1, &[ms[0]]));
    m.register(&env, &c, &NO_SLOTS(&env));
    m2.register(&env, &c, &NO_SLOTS(&env));
    let args = |ua: &BytesN<32>, s: &MemberSig, by: &Option<Address>| -> SVec<Val> { (ua.clone(), s.clone(), by.clone()).into_val(&env) };
    let base = MemberSig { index: 0, key_data: Bytes::new(&env), sig: b(&env, &[5; 666]) };
    let call = |ua: &BytesN<32>, s: &MemberSig, by: &Option<Address>| c.try_accept_membership(ua, s, by).err().map(|e| e.unwrap_or_else(|_| panic!("an invoke error")));
    authorise(&env, &c, &r, "accept_membership", "accept_membership", args(&m.ua, &base, &by));
    let (slot1, sig2) = (MemberSig { index: 1, ..base.clone() }, MemberSig { sig: flipped(&env, &base.sig), ..base.clone() });
    assert_eq!(call(&m.ua, &slot1, &by), Some(HOST_REFUSED), "index");
    authorise(&env, &c, &r, "accept_membership", "accept_membership", args(&m.ua, &base, &by));
    assert_eq!(call(&m.ua, &sig2, &by), Some(HOST_REFUSED), "sig");
    authorise(&env, &c, &r, "accept_membership", "accept_membership", args(&m.ua, &base, &by));
    assert_eq!(call(&m2.ua, &base, &by), Some(HOST_REFUSED), "ua");
    authorise(&env, &c, &other, "accept_membership", "accept_membership", args(&m.ua, &base, &by));
    assert_eq!(call(&m.ua, &base, &Some(other.clone())), Some(HOST_REFUSED), "relayer: the digest names who attests");
    authorise(&env, &c, &r, "accept_membership", "set_kem_key", args(&m.ua, &base, &by));
    assert_eq!(call(&m.ua, &base, &by), Some(HOST_REFUSED), "another function's digest");
    assert_eq!((c.member_accepted(&m.ua, &0), c.member_accepted(&m.ua, &1), c.member_accepted(&m2.ua, &0)), (false, false, false));
    for (ua, s, by) in [(&m.ua, &base, &by), (&m.ua, &slot1, &by), (&m2.ua, &base, &by)] {
        authorise(&env, &c, &r, "accept_membership", "accept_membership", args(ua, s, by));
        assert_eq!(call(ua, s, by), None, "stores on its own attestation");
    }
}

/// An `evm-contract` slot: ERC-1271 runs on no Soroban host, so it is a part the chain cannot verify, as in the stored records.
#[test]
fn an_evm_contract_slot_needs_a_relayer() {
    let (env, c, by) = relayed();
    let e = test::ed(31);
    e.register(&env, &c);
    let mut id = [0u8; 32];
    id[31] = 7;
    let m = msig(&env, 1, &[(0x0002, id, 1), (0x0102, e.ua(&env).to_array(), 1)]);
    m.register(&env, &c, &NO_SLOTS(&env));
    let slot = MemberSig { index: m.index(&id), key_data: Bytes::new(&env), sig: b(&env, &[1; 65]) };
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot, &None)), Error::NotVerifiable);
    c.accept_membership(&m.ua, &slot, &by);
    assert_eq!(c.member_checked(&m.ua, &slot.index), Checked::Relayer(by.unwrap()));
    assert_eq!(c.membership_sig_of(&m.ua, &slot.index), slot.sig);
}

/// A `C…` member cannot be listed, so it has no slot to accept (S10, owner ruling 2026-10-31); `MemberUnknown`, before any acceptance.
#[test]
fn a_c_member_has_no_slot() {
    let (env, c) = test::setup();
    let e = test::ed(32);
    e.register(&env, &c);
    let m = msig(&env, 1, &[(0x0012, [3; 32], 1), (0x0102, e.ua(&env).to_array(), 1)]);
    assert_eq!(err(c.try_register_msig(&m.s, &no_attrs(&env), &NO_SLOTS(&env), &Bytes::new(&env), &None)), Error::MemberUnknown);
    let slot = MemberSig { index: 0, key_data: Bytes::new(&env), sig: Bytes::new(&env) };
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot, &None)), Error::Unauthorized, "no record");
}

/// A wrong member, `ua`, index, a `pop` or `kem` signature as an acceptance and the reverse, non-empty `key_data`: each refused, the slot
/// stays out, and a good acceptance of the same slot passes after them.
#[test]
fn wrong_acceptances_refused() {
    let (env, c) = test::setup();
    let (m, x, y, z) = two_of_three(&env, &c);
    let (ix, iy) = (m.index(&x.ua(&env).to_array()), m.index(&y.ua(&env).to_array()));
    let good = m.acceptance(&env, &x);
    let wrong_member = MemberSig { index: ix, ..m.acceptance(&env, &y) };
    assert_eq!(c.try_accept_membership(&m.ua, &wrong_member, &None), Err(Ok(HOST_REFUSED)), "y's signature at x's slot");
    assert_eq!(c.try_accept_membership(&m.ua, &MemberSig { index: iy, ..good.clone() }, &None), Err(Ok(HOST_REFUSED)), "x's signature at y's slot");
    assert_eq!(err(c.try_accept_membership(&m.ua, &MemberSig { index: 3, ..good.clone() }, &None)), Error::Unauthorized, "past the members");
    assert_eq!(err(c.try_accept_membership(&m.ua, &MemberSig { index: u32::MAX, ..good.clone() }, &None)), Error::Unauthorized);
    let m2 = msig(&env, 1, &[(0x0102, x.ua(&env).to_array(), 1), (0x0102, z.ua(&env).to_array(), 1)]);
    m2.register(&env, &c, &NO_SLOTS(&env));
    let other_ua = MemberSig { index: ix, ..m2.acceptance(&env, &x) };
    assert_eq!(c.try_accept_membership(&m.ua, &other_ua, &None), Err(Ok(HOST_REFUSED)), "signed for another msig");
    let with_key = MemberSig { key_data: x.key_data(&env), ..good.clone() };
    assert_eq!(err(c.try_accept_membership(&m.ua, &with_key, &None)), Error::Unauthorized, "CTR-UA-33: no key data");
    assert_eq!(err(c.try_accept_membership(&x.ua(&env), &good, &None)), Error::Unauthorized, "a single key is no msig");
    assert_eq!(err(c.try_accept_membership(&n(&env, [0x77; 32]), &good, &None)), Error::Unauthorized, "unregistered");
    assert!(!c.member_accepted(&m.ua, &ix));
    c.accept_membership(&m.ua, &good, &None);
    assert!(c.member_accepted(&m.ua, &ix) && !c.member_accepted(&m.ua, &iy));

    // purposes: a `pop` signature of the slot's member is no acceptance, an acceptance is no `pop`, nor a KEM record's
    let (p, q) = (test::ml(23), test::ml(24));
    p.register(&env, &c);
    q.register(&env, &c);
    let pq = msig(&env, 2, &[(0x0131, p.ua(&env).to_array(), 1), (0x0131, q.ua(&env).to_array(), 1)]);
    let rd = test::reg_digest(&env, &pq.ua, 0x0120);
    let mut pop = vec![pq.slot(&env, &p, PURPOSE_POP_V2, &rd), pq.slot(&env, &q, PURPOSE_POP_V2, &rd)];
    pop.sort_by_key(|s| s.0);
    let (ap, aq) = (pq.acceptance(&env, &p), pq.acceptance(&env, &q));
    let mut swapped = vec![(ap.index, vec![], test::vecu8(&ap.sig)), (aq.index, vec![], test::vecu8(&aq.sig))];
    swapped.sort_by_key(|s| s.0);
    assert_eq!(c.try_register_msig(&pq.s, &no_attrs(&env), &test::member_sigs(&env, &swapped), &Bytes::new(&env), &None), Err(Ok(HOST_REFUSED)), "an acceptance is no pop");
    pq.register(&env, &c, &test::member_sigs(&env, &pop));
    let (p2, q2) = (test::ml(25), test::ml(26));
    p2.register(&env, &c);
    q2.register(&env, &c);
    let late = msig(&env, 1, &[(0x0102, x.ua(&env).to_array(), 2), (0x0131, p2.ua(&env).to_array(), 1), (0x0131, q2.ua(&env).to_array(), 1)]);
    late.register(&env, &c, &NO_SLOTS(&env));
    let lrd = test::reg_digest(&env, &late.ua, 0x0120);
    let (ri, _, rs) = late.slot(&env, &p2, PURPOSE_POP_V2, &lrd);
    let as_pop = MemberSig { index: ri, key_data: Bytes::new(&env), sig: b(&env, &rs) };
    assert_eq!(c.try_accept_membership(&late.ua, &as_pop, &None), Err(Ok(HOST_REFUSED)), "a pop signature is no acceptance");
    let kem_d = kem_record_digest(&env, &late.ua, 1, &kem_pk(&env, &crate::test_ua8::kem_row_key(&env))).to_bytes();
    let (ki, _, ks) = late.slot(&env, &p2, PURPOSE_KEM, &kem_d);
    let as_kem = MemberSig { index: ki, key_data: Bytes::new(&env), sig: b(&env, &ks) };
    assert_eq!(c.try_accept_membership(&late.ua, &as_kem, &None), Err(Ok(HOST_REFUSED)), "a KEM signature is no acceptance");
    late.accepted_by(&env, &c, &[&p2]);
}

/// `require_authorized` refuses the purpose, as the other portable ones, so an acceptance never serves as an authorization.
#[test]
fn an_acceptance_is_no_authorization() {
    let (env, c) = test::setup();
    let e = test::ed(33);
    e.register(&env, &c);
    let id = e.ua(&env).to_array();
    let m = msig(&env, 1, &[(0x0102, id, 1)]);
    m.register(&env, &c, &NO_SLOTS(&env));
    m.accepted_by(&env, &c, &[&e]);
    let typed = m.membership(&env, &id);
    let a = test::msig_auth(&env, &[m.slot(&env, &e, PURPOSE_MEMBERSHIP, &typed)]);
    assert_eq!(err(c.try_require_authorized(&m.ua, &n(&env, PURPOSE_MEMBERSHIP), &typed, &a)), Error::Unauthorized);
    let (d, ok) = authorization(&env, &m, &[&e], 4);
    c.require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &d, &ok);
}

/// Accepting twice: a no-op, no second event, whatever the second call carries; the bit stays.
#[test]
fn accepting_twice_is_a_no_op() {
    let (env, c) = test::setup();
    let (m, x, ..) = two_of_three(&env, &c);
    let good = m.acceptance(&env, &x);
    c.accept_membership(&m.ua, &good, &None);
    assert_eq!(env.events().all().events().len(), 1);
    c.accept_membership(&m.ua, &good, &None);
    assert_eq!(env.events().all().events().len(), 0, "no second event");
    c.accept_membership(&m.ua, &MemberSig { sig: b(&env, &[1]), ..good.clone() }, &None);
    assert_eq!(env.events().all().events().len(), 0);
    assert!(c.member_accepted(&m.ua, &good.index));
}

/// The top slot of the largest structure: its bit alone, at the entry's edge; the view is false past the members and for any other id.
#[test]
fn top_slot() {
    let (env, c) = test::setup();
    let keys: StdVec<Sk> = (100..116).map(test::ed).collect();
    for k in &keys {
        k.register(&env, &c);
    }
    let list: StdVec<_> = keys.iter().map(|k| (0x0102u16, k.ua(&env).to_array(), 1u16)).collect();
    let m = msig(&env, 1, &list);
    m.register(&env, &c, &NO_SLOTS(&env));
    let top = keys.iter().find(|k| m.index(&k.ua(&env).to_array()) == 15).unwrap();
    m.accepted_by(&env, &c, &[top]);
    assert_eq!((0..16).filter(|i| c.member_accepted(&m.ua, i)).collect::<StdVec<_>>(), [15]);
    for i in [16, 31, 32, 33, u32::MAX] {
        assert!(!c.member_accepted(&m.ua, &i), "{i}");
        assert_eq!(c.member_checked(&m.ua, &i), Checked::None, "{i}");
    }
    assert!(!c.member_accepted(&top.ua(&env), &0), "a single key");
    assert!(!c.member_accepted(&n(&env, [9; 32]), &0), "unregistered");
    let (d, a) = authorization(&env, &m, &[top], 5);
    c.require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &d, &a);
}

/// The relayer-checked slots of a `pop` are marked with its relayer, its chain slots are not, and a slot outside it reads `None`.
#[test]
fn a_pop_marks_its_attested_slots() {
    let (env, c, by) = relayed();
    let f = portable(&env, "fndsa512");
    f.on_by(&c, &by);
    let (q, r) = (test::ml(62), test::ml(63));
    q.register(&env, &c);
    r.register(&env, &c);
    let m = msig(&env, 2, &[(0x0132, f.ua.to_array(), 1), (0x0131, q.ua(&env).to_array(), 1), (0x0131, r.ua(&env).to_array(), 1)]);
    let rd = test::reg_digest(&env, &m.ua, 0x0120);
    let mut slots = vec![m.slot(&env, &q, PURPOSE_POP_V2, &rd), (m.index(&f.ua.to_array()), vec![], vec![0xf5; 666])];
    slots.sort_by_key(|s| s.0);
    c.register_msig(&m.s, &no_attrs(&env), &test::member_sigs(&env, &slots), &Bytes::new(&env), &by);
    assert_eq!(c.member_checked(&m.ua, &m.index(&f.ua.to_array())), Checked::Relayer(by.clone().unwrap()));
    assert_eq!(c.member_checked(&m.ua, &m.index(&q.ua(&env).to_array())), Checked::Chain);
    assert_eq!(c.member_checked(&m.ua, &m.index(&r.ua(&env).to_array())), Checked::None);
}

/// `Accepted(ua)` lives as the record does: written at registration, extended on every read and write, so a verify never meets a
/// missing value; one entry of at most a kilobyte, every slot marked.
#[test]
fn ttl_and_size_of_the_entry() {
    let (env, c, by) = relayed();
    let (m, x, y, _) = two_of_three(&env, &c);
    let k = Key::Accepted(m.ua.clone());
    let ttl = || env.as_contract(&c.address, || env.storage().persistent().get_ttl(&k));
    assert_eq!(ttl(), 60 * DAY, "written at registration, empty `pop` or not");
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    assert_eq!(ttl(), 29 * DAY);
    assert!(!c.member_accepted(&m.ua, &0));
    assert_eq!(ttl(), 60 * DAY, "the view reads it");
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    m.accepted_by(&env, &c, &[&x, &y]);
    assert_eq!(ttl(), 60 * DAY, "accepting writes it");
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    let (d, a) = authorization(&env, &m, &[&x, &y], 6);
    env.cost_estimate().budget().reset_unlimited();
    c.require_authorized(&m.ua, &n(&env, PURPOSE_METATX), &d, &a);
    assert_eq!(ttl(), 60 * DAY, "a verify reads it");

    let list: StdVec<_> = (0..16u8).map(|i| {
        let ua = c.register(&0x0103, &b(&env, &[0x40 + i; 32]), &no_attrs(&env), &b(&env, &[1; 64]), &Bytes::new(&env), &by);
        (0x0103u16, ua.to_array(), 1u16)
    }).collect();
    let big = msig(&env, 1, &list);
    big.register(&env, &c, &NO_SLOTS(&env));
    for index in 0..16 {
        c.accept_membership(&big.ua, &MemberSig { index, key_data: Bytes::new(&env), sig: b(&env, &[1; 7_856]) }, &by);
    }
    assert_eq!((0..16).filter(|i| c.member_accepted(&big.ua, i)).count(), 16);
    // each attested signature in an entry of its own, as every other entry here: 16 of 7,856 B fit no single one
    let sig_key = Key::AcceptSig(big.ua.clone(), 3);
    let sig_ttl = || env.as_contract(&c.address, || env.storage().persistent().get_ttl(&sig_key));
    assert_eq!(sig_ttl(), 60 * DAY);
    env.ledger().with_mut(|l| l.sequence_number += 31 * DAY);
    assert_eq!(sig_ttl(), 29 * DAY);
    c.member_accepted(&big.ua, &3);
    assert_eq!(sig_ttl(), 29 * DAY, "the bit's view leaves it");
    assert_eq!(c.membership_sig_of(&big.ua, &3).len(), 7_856);
    assert_eq!(sig_ttl(), 60 * DAY, "its own view reads it");
    let entry: crate::AcceptedEntry = env.as_contract(&c.address, || env.storage().persistent().get(&Key::Accepted(big.ua.clone())).unwrap());
    use soroban_sdk::xdr::{FromXdr as _, ToXdr as _};
    let size = entry.clone().to_xdr(&env).len();
    assert!(size <= 1_024, "{size} B");
    assert_eq!(crate::AcceptedEntry::from_xdr(&env, &entry.to_xdr(&env)).unwrap().0, 0xffff);
}

/// The high-s twin of a good `evm-eoa` signature accepts nothing: the low-s rule of every native signature holds here too.
#[test]
fn a_high_s_evm_eoa_slot_is_refused() {
    let (env, c) = test::setup();
    let (k, e) = (test::k1(6), test::ed(7));
    e.register(&env, &c);
    let id = test::eoa(&env, &k);
    let m = msig(&env, 1, &[(0x0001, id, 1), (0x0102, e.ua(&env).to_array(), 2)]);
    m.register(&env, &c, &NO_SLOTS(&env));
    let good = test::k1_sign(&k, &m.membership(&env, &id).to_array());
    const N: [u8; 32] = h32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");
    let (mut high, mut borrow) = (good.clone(), 0i32);
    for j in (0..32).rev() {
        let d = N[j] as i32 - good[32 + j] as i32 - borrow;
        high[32 + j] = (d & 0xff) as u8;
        borrow = (d < 0) as i32;
    }
    high[64] = 27 + 28 - good[64];
    let slot = |sig: StdVec<u8>| MemberSig { index: m.index(&id), key_data: Bytes::new(&env), sig: b(&env, &sig) };
    assert_eq!(err(c.try_accept_membership(&m.ua, &slot(high), &None)), Error::Unauthorized);
    c.accept_membership(&m.ua, &slot(good), &None);
}

/// What the rows cover: `evm-eoa`, a `Chain` kind and a relayer-checked kind each, so `rows_accept_unchanged` walks every path of a slot.
#[test]
fn rows_cover_chain_and_relayer_kinds() {
    let kinds: StdVec<u32> = rows().iter().map(|r| kind_of(&r["memberKind"])).collect();
    assert_eq!(kinds, [0x0001, 0x0107, 0x0104, 0x0101, 0x0001, 0x0131]);
}

/// CTR-UA-33 Change 2026-11-08 (EVM `popSlotsOf`): every `msig` row of `portable.json` answers its `popSigners`, each with its
/// `memberSigHashes` hash, `keccak256` of the slot's `sig`; `msig-classical`'s empty `pop` answers empty. (The Soroban suite
/// registers no `nested.json` row.)
#[test]
fn pop_slots_of_rows() {
    let rows: StdVec<Value> = json(PORTABLE)["registrations"].as_array().unwrap().iter().filter(|r| kind_of(&r["kind"]) == 0x0120).cloned().collect();
    let mut signers = 0;
    for row in &rows {
        let name = row["name"].as_str().unwrap();
        let (env, c, by) = relayed();
        classical_members(&env, &c, &by);
        portable(&env, "mldsa65#1").on(&c);
        portable(&env, "mldsa65#2").on(&c);
        let r = portable(&env, name);
        r.on(&c);
        let hashes = row["memberSigHashes"].as_array().unwrap();
        let index: StdVec<u32> = row["popSigners"].as_array().unwrap().iter().map(|x| x.as_u64().unwrap() as u32).collect();
        assert_eq!(hashes.iter().map(|h| h["index"].as_u64().unwrap() as u32).collect::<StdVec<_>>(), index, "{name}");
        let hash: StdVec<BytesN<32>> = hashes.iter().map(|h| n32(&env, &h["hash"])).collect();
        let (i, h) = c.pop_slots_of(&r.ua);
        assert_eq!((i.iter().collect::<StdVec<_>>(), h.iter().collect::<StdVec<_>>()), (index, hash), "{name}");
        signers += i.len();
    }
    assert_eq!((rows.len(), signers), (6, 10), "msig-classical none, msig-pq/<set> and msig-pq-native two each");
}

/// `PopSlots` is written once, at registration, and never by `accept_membership`: `msig-classical`'s empty `pop` answers empty after
/// a slot accepts on the chain's check and one on a relayer's word, while `member_accepted` turns true; a 1-of-2 whose `pop` `p`
/// signed answers `p` alone, its hash that of the stored `pop`'s slot, before and after `q` accepts. A single key's id and an
/// unregistered one answer empty.
#[test]
fn pop_slots_of_never_from_acceptance() {
    let (env, c, by) = relayed();
    let none: (SVec<u32>, SVec<BytesN<32>>) = (SVec::new(&env), SVec::new(&env));
    classical_members(&env, &c, &by);
    let classical = portable(&env, "msig-classical");
    classical.on(&c);
    assert_eq!(c.pop_slots_of(&classical.ua), none);
    for (name, relayer) in [("msig-classical/0", &None), ("msig-classical/1", &by)] {
        let r = row(name);
        let i = r["index"].as_u64().unwrap() as u32;
        assert!(!c.member_accepted(&classical.ua, &i), "{name}");
        c.accept_membership(&classical.ua, &slot_of(&env, &r), relayer);
        assert!(c.member_accepted(&classical.ua, &i), "{name}");
        assert_eq!(c.pop_slots_of(&classical.ua), none, "{name}: an acceptance is no `pop` slot");
    }
    let (m, p, q) = pq_one_of_two(&env, &c);
    let slots = test::members_of(&env, &c.pop_of(&m.ua));
    let s = slots.get(0).unwrap();
    assert_eq!((slots.len(), s.index), (1, m.index(&p.ua(&env).to_array())));
    let want = (SVec::from_array(&env, [s.index]), SVec::from_array(&env, [BytesN::from(env.crypto().keccak256(&s.sig))]));
    assert_eq!(c.pop_slots_of(&m.ua), want);
    let iq = m.index(&q.ua(&env).to_array());
    m.accepted_by(&env, &c, &[&q]);
    assert!(c.member_accepted(&m.ua, &iq));
    assert_eq!(c.pop_slots_of(&m.ua), want, "`q` accepted later: no `pop` slot");
    let single = portable(&env, "mldsa65#1");
    single.on(&c);
    assert_eq!(c.pop_slots_of(&single.ua), none, "a single key");
    assert_eq!(c.pop_slots_of(&n(&env, [0x42; 32])), none, "no record");
}
