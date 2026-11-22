// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T4 (CLI-PQC-07): every check of a record read, each negative beside its positive control, changing one thing, its drop
//! reason asserted and no write caused (the recording port). Real keys, signatures and ciphertexts: the SDK on its fake chain.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::sdk::*;
use pqchat_core::check::{self, Drop};
use pqchat_core::model::{hex, Epoch};
use pqchat_core::PqChat;
use std::collections::BTreeMap;

fn only(d: Drop) -> BTreeMap<Drop, u64> {
    BTreeMap::from([(d, 1)])
}

/// The positive control: alice's message, received by bob's client, opens to alice's content; nothing dropped, nothing written.
#[tokio::test(flavor = "multi_thread")]
async fn a_valid_message_is_shown() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    assert!(w.app.same_key(ep.k.clone(), o.k.clone()).unwrap());
    let m = sealed(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        0,
        r#"{"body":"hi","type":"text"}"#,
    )
    .await;
    let got = w.pq.receive(&ep, m.env.clone()).await.unwrap();
    assert_eq!(text(&got.content), r#"{"body":"hi","type":"text"}"#);
    assert_eq!(got.message_id, m.message_id);
    assert!(w.pq.dropped(&o.e.session_id).is_empty());
    assert_eq!(w.net.writes(), 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn envelope_a_flipped_byte() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let m = sealed(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        0,
        r#"{"body":"hi","type":"text"}"#,
    )
    .await;
    let mut bad = m.env.clone();
    let n = bad.len() - 1;
    bad[n] ^= 1;
    assert_eq!(w.pq.receive(&ep, bad).await.err(), Some(Drop::Envelope));
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::Envelope));
    // twin: the unflipped envelope is shown
    assert!(w.pq.receive(&ep, m.env).await.is_ok());
    assert_eq!(w.net.writes(), 0);
}

/// `signature`: carol's message checked against a registry record holding bob's key (a signature of another key).
#[tokio::test(flavor = "multi_thread")]
async fn signature_of_another_key() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob, &w.carol]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let m = sealed(&w, &w.carol, &o.e, &o.k, 0, r#"{"body":"c","type":"text"}"#).await;
    register(&w.chain, &w.carol, &w.bob);
    assert_eq!(
        w.pq.receive(&ep, m.env.clone()).await.err(),
        Some(Drop::Signature)
    );
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::Signature));
    // twin: carol's own key registered
    register(&w.chain, &w.carol, &w.carol);
    assert!(w.pq.receive(&ep, m.env).await.is_ok());
    assert_eq!(w.net.writes(), 0);
}

/// `member`: carol holds the key (a removed member's view) but is no member of the epoch at home.
#[tokio::test(flavor = "multi_thread")]
async fn member_a_sender_outside_the_epoch() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let c = sealed(&w, &w.carol, &o.e, &o.k, 0, r#"{"body":"c","type":"text"}"#).await;
    assert_eq!(w.pq.receive(&ep, c.env).await.err(), Some(Drop::Member));
    // twin: a member's message
    let a = sealed(&w, &w.alice, &o.e, &o.k, 0, r#"{"body":"a","type":"text"}"#).await;
    assert!(w.pq.receive(&ep, a.env).await.is_ok());
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::Member));
    assert_eq!(w.net.writes(), 0);
}

/// `counter`: two different records of one sender and device with one counter (distinct ids): the second dropped.
#[tokio::test(flavor = "multi_thread")]
async fn counter_two_records_one_counter() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let a = sealed(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        3,
        r#"{"body":"one","type":"text"}"#,
    )
    .await;
    let b = sealed(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        3,
        r#"{"body":"two","type":"text"}"#,
    )
    .await;
    assert_ne!(a.message_id, b.message_id);
    assert!(w.pq.receive(&ep, a.env).await.is_ok());
    assert_eq!(w.pq.receive(&ep, b.env).await.err(), Some(Drop::Counter));
    // twin: the next counter
    let c = sealed(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        4,
        r#"{"body":"three","type":"text"}"#,
    )
    .await;
    assert!(w.pq.receive(&ep, c.env).await.is_ok());
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::Counter));
}

/// `duplicate`: one record arriving on two stores: the second dropped before the counter check.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_one_record_twice() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let a = sealed(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        0,
        r#"{"body":"one","type":"text"}"#,
    )
    .await;
    assert!(w.pq.receive(&ep, a.env.clone()).await.is_ok());
    assert_eq!(w.pq.receive(&ep, a.env).await.err(), Some(Drop::Duplicate));
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::Duplicate));
}

/// `replica`: a replica's record differing from the home's under the same id; twin: an equal one.
#[tokio::test(flavor = "multi_thread")]
async fn replica_differs_from_home() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    list(&w.net, REPLICA, 3, 1);
    put_record(&w.net, REPLICA, &o.e);
    assert!(w
        .pq
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, Some(REPLICA))
        .await
        .is_ok());
    let mut other = o.e.clone();
    other.sig_hash = hex(&[0x77; 32]);
    put_record(&w.net, REPLICA, &other);
    let r =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, Some(REPLICA))
            .await;
    assert_eq!(r.err(), Some(Drop::Replica));
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::Replica));
}

/// Membership is the home's: a replica holding a competing record with carol as a member gives carol nothing.
#[tokio::test(flavor = "multi_thread")]
async fn member_read_at_home_not_at_the_replica() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    list(&w.net, REPLICA, 3, 1);
    let mut rival = session(&w.alice, &[&w.alice, &w.bob, &w.carol]);
    // bob's own wrap signed in the rival too, at its index there: only the membership differs
    let (bi, ri) = (
        o.e.index_of(&w.bob.ua).unwrap(),
        rival.index_of(&w.bob.ua).unwrap(),
    );
    rival.wrap_hashes[ri] = o.e.wrap_hashes[bi].clone();
    put_wrap(&w.net, HOME, &o.e.id, ri, &o.wrap);
    put_record(&w.net, REPLICA, &rival);
    // the replica is not named: the home's record decides
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let c = sealed(&w, &w.carol, &o.e, &o.k, 0, r#"{"body":"c","type":"text"}"#).await;
    assert_eq!(w.pq.receive(&ep, c.env).await.err(), Some(Drop::Member));
    // named, the differing replica is refused, and still nothing of carol's counts
    let r =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, Some(REPLICA))
            .await;
    assert_eq!(r.err(), Some(Drop::Replica));
}

/// `unlisted`: a home the factory lists with version 0, or as another class: dropped; the user's own action
/// `InstanceUnlisted`.
#[tokio::test(flavor = "multi_thread")]
async fn unlisted_instance() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    assert!(w.pq.listed(CHAIN, HOME).await.unwrap());
    w.pq.require_listed(CHAIN, HOME).await.unwrap();
    for (class, version) in [(3, 0), (2, 1)] {
        list(&w.net, HOME, class, version);
        let r =
            w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
                .await;
        assert_eq!(r.err(), Some(Drop::Unlisted));
        assert_eq!(
            w.pq.require_listed(CHAIN, HOME).await.unwrap_err().code(),
            "InstanceUnlisted"
        );
    }
    assert_eq!(
        w.pq.dropped(&o.e.session_id),
        BTreeMap::from([(Drop::Unlisted, 2)])
    );
    assert_eq!(w.pq.unwrap_calls(), 0);
}

/// `wrap-hash`: a wrap read from state whose hash differs from the signed one never reaches the KEM.
#[tokio::test(flavor = "multi_thread")]
async fn wrap_hash_before_any_decapsulation() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let i = o.e.index_of(&w.bob.ua).unwrap();
    let mut other = o.wrap.clone();
    other.sealed_key[0] ^= 1;
    put_wrap(&w.net, HOME, &o.e.id, i, &other);
    let r =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await;
    assert_eq!(r.err(), Some(Drop::WrapHash));
    assert_eq!(w.pq.unwrap_calls(), 0);
    // twin: the signed wrap opens
    put_wrap(&w.net, HOME, &o.e.id, i, &o.wrap);
    assert!(w
        .pq
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .is_ok());
    assert_eq!(w.pq.unwrap_calls(), 1);
    assert_eq!(w.pq.dropped(&o.e.session_id), only(Drop::WrapHash));
}

fn child_of(
    p: &Epoch,
    author: &str,
    members: Vec<pqchat_core::model::Member>,
    admins: Vec<String>,
) -> Epoch {
    Epoch {
        id: hex(&[0x61; 32]),
        session_id: p.session_id.clone(),
        author: author.into(),
        nonce: 2,
        epoch: p.epoch + 1,
        parent: p.id.clone(),
        admins,
        wrap_hashes: members.iter().map(|_| hex(&[0xcc; 32])).collect(),
        members,
        sealed_info: vec![],
        sig_hash: hex(&[0x62; 32]),
    }
}

/// The control-plane rules, one change at a time: the number, the author's rights, the order, the creator.
#[tokio::test(flavor = "multi_thread")]
async fn control_plane_rules() {
    let _one = ONE.lock().await;
    let w = world().await;
    let p = session(&w.alice, &[&w.alice, &w.bob]);
    assert_eq!(check::shapes(&p), Ok(()));
    // the creator absent from admins
    let mut x = p.clone();
    x.admins = vec![w.bob.ua.clone()];
    assert_eq!(check::shapes(&x), Err(Drop::Control));
    // unsorted members
    let mut x = p.clone();
    x.members.reverse();
    assert_eq!(check::shapes(&x), Err(Drop::Control));
    // a plain rekey by a member (bob, no admin): accepted
    let plain = child_of(&p, &w.bob.ua, p.members.clone(), p.admins.clone());
    assert_eq!(check::child(&plain, &p, &[], &[]), Ok(()));
    // its number not the parent's plus one
    let mut x = plain.clone();
    x.epoch = p.epoch;
    assert_eq!(check::child(&x, &p, &[], &[]), Err(Drop::Control));
    // a membership change (bob drops alice) by a non-admin
    let change = child_of(
        &p,
        &w.bob.ua,
        vec![member(&w.bob)],
        vec![w.alice.ua.clone()],
    );
    assert_eq!(check::child(&change, &p, &[], &[]), Err(Drop::Control));
    // the same change by the admin: accepted
    let by_admin = child_of(
        &p,
        &w.alice.ua,
        vec![member(&w.bob)],
        vec![w.alice.ua.clone()],
    );
    assert_eq!(check::child(&by_admin, &p, &[], &[]), Ok(()));
    // a member who left authors no plain rekey; a removed one is kept by no child
    let without = child_of(
        &p,
        &w.bob.ua,
        vec![member(&w.alice)],
        vec![w.alice.ua.clone()],
    );
    assert_eq!(
        check::child(&without, &p, std::slice::from_ref(&w.bob.ua), &[]),
        Err(Drop::Control)
    );
    assert_eq!(
        check::child(&plain, &p, &[], std::slice::from_ref(&w.bob.ua)),
        Err(Drop::Control)
    );
    // through the reads: a child at home whose number breaks the rule is dropped (`control`)
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let mut bad = child_of(&o.e, &w.bob.ua, o.e.members.clone(), o.e.admins.clone());
    bad.epoch = 5;
    put_record(&w.net, HOME, &bad);
    let r =
        w.pq.open_epoch(&o.s, &bad.id, &w.bob.key, &w.bob.ua, None)
            .await;
    assert_eq!(r.err(), Some(Drop::Control));
    let _ = PqChat::replica;
}

/// K12: a posted message (`messageAt`) counts only from a listed instance, with the sender's membership checked at home.
#[tokio::test(flavor = "multi_thread")]
async fn posted_message_from_a_listed_instance() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let put = |i: u64, m: &scaas_sdk::pqchat_keys::PqSealedMessage, at: &str| {
        let r = &m.record;
        let x = serde_json::json!({"sessionId": r.session_id, "epochId": r.epoch_id, "sender": r.sender,
            "device": r.device, "counter": r.counter.to_string(), "parents": r.parents, "ciphertext": hex(&r.ciphertext)});
        w.net.answer(
            at,
            "IPqChat.messageAt",
            serde_json::json!({"sessionId": o.e.session_id, "index": i.to_string()}),
            serde_json::json!({"m": x, "sigHash": hex(&[1; 32])}),
        );
    };
    let a = sealed(&w, &w.alice, &o.e, &o.k, 0, r#"{"body":"a","type":"text"}"#).await;
    put(0, &a, HOME);
    let got = w.pq.posted(HOME, 0, &ep).await.unwrap();
    assert_eq!(text(&got.content), r#"{"body":"a","type":"text"}"#);
    // carol posted (a replica took it): no member at home
    let c = sealed(&w, &w.carol, &o.e, &o.k, 0, r#"{"body":"c","type":"text"}"#).await;
    list(&w.net, REPLICA, 3, 1);
    put(0, &c, REPLICA);
    assert_eq!(w.pq.posted(REPLICA, 0, &ep).await.err(), Some(Drop::Member));
    // an unlisted instance's
    put(0, &a, UNLISTED);
    list(&w.net, UNLISTED, 3, 0);
    assert_eq!(
        w.pq.posted(UNLISTED, 0, &ep).await.err(),
        Some(Drop::Unlisted)
    );
    assert_eq!(w.net.reads_of("IPqChat.messageAt"), 2);
}
