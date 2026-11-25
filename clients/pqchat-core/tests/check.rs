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
use pqchat_core::check::{self, DropReason};
use pqchat_core::model::{hex, Epoch};
use pqchat_core::PqChat;
use std::collections::BTreeMap;

fn only(d: DropReason) -> BTreeMap<DropReason, u64> {
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
    assert_eq!(
        w.pq.receive(&ep, bad).await.err(),
        Some(DropReason::Envelope)
    );
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::Envelope));
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
        Some(DropReason::Signature)
    );
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::Signature));
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
    assert_eq!(
        w.pq.receive(&ep, c.env).await.err(),
        Some(DropReason::Member)
    );
    // twin: a member's message
    let a = sealed(&w, &w.alice, &o.e, &o.k, 0, r#"{"body":"a","type":"text"}"#).await;
    assert!(w.pq.receive(&ep, a.env).await.is_ok());
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::Member));
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
    assert_eq!(
        w.pq.receive(&ep, b.env).await.err(),
        Some(DropReason::Counter)
    );
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
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::Counter));
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
    assert_eq!(
        w.pq.receive(&ep, a.env).await.err(),
        Some(DropReason::Duplicate)
    );
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::Duplicate));
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
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, Some(REPLICA.into()))
        .await
        .is_ok());
    let mut other = o.e.clone();
    other.sig_hash = hex(&[0x77; 32]);
    put_record(&w.net, REPLICA, &other);
    let r =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, Some(REPLICA.into()))
            .await;
    assert_eq!(r.err(), Some(DropReason::Replica));
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::Replica));
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
    assert_eq!(
        w.pq.receive(&ep, c.env).await.err(),
        Some(DropReason::Member)
    );
    // named, the differing replica is refused, and still nothing of carol's counts
    let r =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, Some(REPLICA.into()))
            .await;
    assert_eq!(r.err(), Some(DropReason::Replica));
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
        assert_eq!(r.err(), Some(DropReason::Unlisted));
        assert_eq!(
            w.pq.require_listed(CHAIN, HOME).await.unwrap_err().code(),
            "InstanceUnlisted"
        );
    }
    assert_eq!(
        w.pq.dropped(&o.e.session_id),
        BTreeMap::from([(DropReason::Unlisted, 2)])
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
    assert_eq!(r.err(), Some(DropReason::WrapHash));
    assert_eq!(w.pq.unwrap_calls(), 0);
    // twin: the signed wrap opens
    put_wrap(&w.net, HOME, &o.e.id, i, &o.wrap);
    assert!(w
        .pq
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .is_ok());
    assert_eq!(w.pq.unwrap_calls(), 1);
    assert_eq!(w.pq.dropped(&o.e.session_id), only(DropReason::WrapHash));
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
    assert_eq!(check::shapes(&x), Err(DropReason::Control));
    // unsorted members
    let mut x = p.clone();
    x.members.reverse();
    assert_eq!(check::shapes(&x), Err(DropReason::Control));
    // a plain rekey by a member (bob, no admin): accepted
    let plain = child_of(&p, &w.bob.ua, p.members.clone(), p.admins.clone());
    assert_eq!(check::child(&plain, &p, &[], &[]), Ok(()));
    // its number not the parent's plus one
    let mut x = plain.clone();
    x.epoch = p.epoch;
    assert_eq!(check::child(&x, &p, &[], &[]), Err(DropReason::Control));
    // a membership change (bob drops alice) by a non-admin
    let change = child_of(
        &p,
        &w.bob.ua,
        vec![member(&w.bob)],
        vec![w.alice.ua.clone()],
    );
    assert_eq!(
        check::child(&change, &p, &[], &[]),
        Err(DropReason::Control)
    );
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
        Err(DropReason::Control)
    );
    assert_eq!(
        check::child(&plain, &p, &[], std::slice::from_ref(&w.bob.ua)),
        Err(DropReason::Control)
    );
    // through the reads: a child at home whose number breaks the rule is dropped (`control`)
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let mut bad = child_of(&o.e, &w.bob.ua, o.e.members.clone(), o.e.admins.clone());
    bad.epoch = 5;
    put_record(&w.net, HOME, &bad);
    let r =
        w.pq.open_epoch(&o.s, &bad.id, &w.bob.key, &w.bob.ua, None)
            .await;
    assert_eq!(r.err(), Some(DropReason::Control));
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
    assert_eq!(
        w.pq.posted(REPLICA, 0, &ep).await.err(),
        Some(DropReason::Member)
    );
    // an unlisted instance's
    put(0, &a, UNLISTED);
    list(&w.net, UNLISTED, 3, 0);
    assert_eq!(
        w.pq.posted(UNLISTED, 0, &ep).await.err(),
        Some(DropReason::Unlisted)
    );
    assert_eq!(w.net.reads_of("IPqChat.messageAt"), 2);
}

/// E-1 (P1, fable re-review 2026-11-25) and D2-8: "plain" is the contract's `_keeps` (PqGroupBase.sol): the child is the
/// parent's lists less some of the UAs flagged there, left or removed; a flagged UA may be dropped or kept (a removed one is
/// then refused as kept); nothing added. Each case beside its twin, one change at a time.
#[tokio::test(flavor = "multi_thread")]
async fn plain_is_the_contracts_keeps() {
    let _one = ONE.lock().await;
    let w = world().await;
    let p = session(&w.alice, &[&w.alice, &w.bob, &w.carol]);
    let all = p.members.clone();
    let without_carol: Vec<_> = all.iter().filter(|m| m.ua != w.carol.ua).cloned().collect();
    let carol = std::slice::from_ref(&w.carol.ua);
    // (a) bob (no admin) keeps carol who left: plain at home (`PqChatEpochs.t.sol`'s control of the leaver rule)
    let keeps = child_of(&p, &w.bob.ua, all.clone(), p.admins.clone());
    assert_eq!(check::child(&keeps, &p, carol, &[]), Ok(()));
    // bob drops carol who left: plain
    let drops = child_of(&p, &w.bob.ua, without_carol.clone(), p.admins.clone());
    assert_eq!(check::child(&drops, &p, carol, &[]), Ok(()));
    // (b) bob drops carol who was removed: plain (CTR-CHAT-20); twin: carol not flagged, a membership change by a non-admin
    assert_eq!(check::child(&drops, &p, &[], carol), Ok(()));
    assert_eq!(check::child(&drops, &p, &[], &[]), Err(DropReason::Control));
    // a removed carol kept: refused (`_noneRemoved`)
    assert_eq!(
        check::child(&keeps, &p, &[], carol),
        Err(DropReason::Control)
    );
    // a UA added is no plain rekey, even with carol flagged
    let mut more = p.clone();
    more.members.retain(|m| m.ua != w.carol.ua);
    let add = child_of(&more, &w.bob.ua, all.clone(), more.admins.clone());
    assert_eq!(
        check::child(&add, &more, &[], &[]),
        Err(DropReason::Control)
    );
    // an admin who left (or was removed) is no live admin: its membership change is refused; twin: the live admin's
    let change = child_of(&p, &w.alice.ua, without_carol.clone(), p.admins.clone());
    assert_eq!(check::child(&change, &p, &[], &[]), Ok(()));
    let alice = std::slice::from_ref(&w.alice.ua);
    assert_eq!(
        check::child(&change, &p, alice, &[]),
        Err(DropReason::Control)
    );
    // a dropped admin that left: plain for a member
    let mut two = p.clone();
    two.admins = {
        let mut a = vec![w.alice.ua.clone(), w.bob.ua.clone()];
        a.sort();
        a
    };
    let drop_alice_admin = child_of(&two, &w.carol.ua, all.clone(), vec![w.bob.ua.clone()]);
    assert_eq!(check::child(&drop_alice_admin, &two, alice, &[]), Ok(()));
    assert_eq!(
        check::child(&drop_alice_admin, &two, &[], &[]),
        Err(DropReason::Control)
    );
}
