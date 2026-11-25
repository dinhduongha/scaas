// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T5 on the SDK's fake chain (real keys, real wraps and signatures; the crate's reads answered by a recording fake):
//! sessions, epochs, wraps and KEM versions, removal and leave, `msig` expansion, the send hold. Each negative beside its
//! positive control, its code or drop reason asserted, and the writes it caused counted (none).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::sdk::*;
use pqchat_core::message::OpenEpoch;
use pqchat_core::model::{hex, Epoch, ZERO32};
use pqchat_core::session::{Built, CreateSession, Info, Me, Rekey, Skipped, StoreEntry, MSIG};
use pqchat_core::{DropReason, Event, PqChatError};
use scaas_sdk::op::KeyRef;
use serde_json::json;
use std::sync::atomic::Ordering;

fn me(a: &Acc) -> Me {
    Me {
        key: a.key.clone(),
        ua: a.ua.clone(),
    }
}

fn info() -> Info {
    Info {
        stores: vec![StoreEntry::Chain {
            chain_id: "31337".into(),
            chain_uid: hex(&[7; 32]),
            contract: HOME.into(),
        }],
        name: "t5".into(),
        topic: "plan T5".into(),
        matrix: Default::default(),
    }
}

fn payer(w: &World) -> KeyRef {
    KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    }
}

fn code<T>(r: Result<T, PqChatError>) -> &'static str {
    match r {
        Ok(_) => "Ok",
        Err(e) => e.code(),
    }
}

/// The world with HOME listed, prepares answered, alice, bob and carol at KEM version 1.
async fn ready() -> World {
    let w = world().await;
    list(&w.net, HOME, 3, 1);
    w.net.accept.store(true, Ordering::SeqCst);
    for a in [&w.alice, &w.bob, &w.carol] {
        kem(&w, a, 1);
    }
    w
}

async fn create(
    w: &World,
    members: &[&Acc],
    admins: &[&Acc],
    nonce: u64,
) -> Result<Built, PqChatError> {
    w.pq.create(CreateSession {
        me: me(&w.alice),
        chain: CHAIN.into(),
        home: HOME.into(),
        nonce,
        members: members.iter().map(|a| a.ua.clone()).collect(),
        admins: admins.iter().map(|a| a.ua.clone()).collect(),
        info: info(),
        payer: payer(w),
    })
    .await
}

fn uas(e: &Epoch) -> Vec<String> {
    e.members.iter().map(|m| m.ua.clone()).collect()
}

fn sorted(v: &[&Acc]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|a| a.ua.clone()).collect();
    v.sort();
    v
}

fn review<'a>(b: &'a Built, name: &str) -> &'a str {
    b.signed
        .review
        .iter()
        .find(|f| f.name == name)
        .unwrap()
        .value
        .as_str()
}

/// The 2-member session: the creator added to `members` and `admins`, both strictly sorted, every wrap in the one write.
#[tokio::test(flavor = "multi_thread")]
async fn two_members_one_write() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let b = create(&w, &[&w.bob], &[], 1).await.unwrap();
    assert_eq!(uas(&b.epoch), sorted(&[&w.alice, &w.bob]));
    assert_eq!(b.epoch.admins, vec![w.alice.ua.clone()]);
    assert_eq!(review(&b, "message.admins[0]"), w.alice.ua);
    assert_eq!((b.epoch.epoch, b.sent, b.wraps.len()), (0, 2, 2));
    assert!(b.skipped.is_empty());
    let calls = w.net.writes_of("IPqChat.createSession");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0]["wraps"].as_array().unwrap().len(), 2);
    assert_eq!(calls[0]["s"]["admins"], json!([w.alice.ua]));
    // a duplicate member refused before anything is read or written
    let (r, wr) = (w.net.reads.lock().unwrap().len(), w.net.writes());
    let e = create(&w, &[&w.bob, &w.bob], &[], 2).await;
    assert_eq!(code(e), "MembersInvalid");
    assert_eq!((w.net.reads.lock().unwrap().len(), w.net.writes()), (r, wr));
}

/// Wraps in chunks sized by the quote: halved on its refusal, the rest by `addWraps` after the first write, nothing assumed
/// about a limit; the positive control, every wrap in one write.
#[tokio::test(flavor = "multi_thread")]
async fn chunks_sized_by_the_quote() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let all = create(&w, &[&w.bob, &w.carol], &[], 1).await.unwrap();
    assert_eq!(all.sent, 3);
    // the most that fit, not a halving: 2 of 3
    *w.net.wrap_cap.lock().unwrap() = Some(2);
    assert_eq!(
        create(&w, &[&w.bob, &w.carol], &[], 2).await.unwrap().sent,
        2
    );
    // none fits: the quote's own refusal
    *w.net.wrap_cap.lock().unwrap() = Some(0);
    assert_eq!(
        code(create(&w, &[&w.bob, &w.carol], &[], 3).await),
        "GasAboveTxCap"
    );
    *w.net.wrap_cap.lock().unwrap() = Some(1);
    let mut b = create(&w, &[&w.bob, &w.carol], &[], 4).await.unwrap();
    assert_eq!(b.sent, 1);
    let s = pqchat_core::reads::SessionRef {
        chain: CHAIN.into(),
        home: HOME.into(),
        session_id: b.session_id.clone(),
    };
    let mut firsts = vec![];
    while w
        .pq
        .next_wraps(&s, &mut b, &payer(&w))
        .await
        .unwrap()
        .is_some()
    {
        let a = w.net.writes_of("IPqChat.addWraps").last().unwrap().clone();
        assert_eq!(a["wraps"].as_array().unwrap().len(), 1);
        firsts.push(a["first"].as_str().unwrap().to_string());
    }
    assert_eq!(firsts, ["1", "2"]);
    assert_eq!(b.sent, 3);
}

fn sref(o: &Opened) -> pqchat_core::reads::SessionRef {
    o.s.clone()
}

fn open(w: &World, o: &Opened) -> OpenEpoch {
    let _ = w;
    OpenEpoch {
        chain: CHAIN.into(),
        epoch: o.e.clone(),
        k: o.k.clone(),
    }
}

fn rk(w: &World, by: &Acc, nonce: u64, members: &[&Acc], admins: &[&Acc]) -> Rekey {
    Rekey {
        me: me(by),
        nonce,
        members: members.iter().map(|a| a.ua.clone()).collect(),
        admins: admins.iter().map(|a| a.ua.clone()).collect(),
        info: info(),
        payer: payer(w),
    }
}

/// An opened 2-member session (alice, bob) whose home slot is free.
async fn session2(w: &World) -> Opened {
    let o = opened(w, &[&w.alice, &w.bob]).await;
    child(&w.net, HOME, &o.e.id, ZERO32);
    o
}

async fn plain_rekey(w: &World, o: &Opened) -> Built {
    w.pq.rekey(
        &sref(o),
        &open(w, o),
        rk(w, &w.bob, 2, &[&w.alice, &w.bob], &[&w.alice]),
    )
    .await
    .unwrap()
}

/// A plain rekey by a member who is no admin: the parent's number plus one, under it, the same members.
#[tokio::test(flavor = "multi_thread")]
async fn plain_rekey_is_the_parents_number_plus_one() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    let b = plain_rekey(&w, &o).await;
    assert_eq!((b.epoch.epoch, review(&b, "message.epoch")), (1, "1"));
    assert_eq!(b.epoch.parent, o.e.id);
    assert_eq!(b.epoch.author, w.bob.ua);
    assert_eq!(uas(&b.epoch), uas(&o.e));
    assert_eq!(w.net.writes_of("IPqChat.rekey").len(), 1);
}

/// Every epoch draws its own `K`, never the parent's (their hints differ).
#[tokio::test(flavor = "multi_thread")]
async fn rekey_draws_a_fresh_k() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    let b = plain_rekey(&w, &o).await;
    let hint = |k| w.app.pqchat_hint(k).unwrap();
    assert_eq!(hint(o.k.clone()), hint(o.k.clone()));
    assert_ne!(
        hint(b.k.clone()),
        hint(o.k.clone()),
        "K reused from the parent"
    );
}

/// A membership change by a member who is no admin: `NotAdmin`, nothing written; the admin's own: built.
#[tokio::test(flavor = "multi_thread")]
async fn membership_change_needs_an_admin() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    let all = [&w.alice, &w.bob, &w.carol];
    let e =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.bob, 2, &all, &[&w.alice]),
        )
        .await;
    assert_eq!(code(e), "NotAdmin");
    assert_eq!(w.net.writes(), 0);
    let b =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.alice, 3, &all, &[&w.alice]),
        )
        .await
        .unwrap();
    assert_eq!(uas(&b.epoch), sorted(&all));
}

/// `o.e` is the home's head (`latestEpoch`): what an exit is checked at (C9, D2-4).
fn latest(w: &World, o: &Opened) {
    w.net.answer(
        HOME,
        "IPqChat.latestEpoch",
        json!({"sessionId": o.e.session_id}),
        json!({"epochId": o.e.id}),
    );
}

fn flag(w: &World, o: &Opened, item: &str, a: &Acc) {
    w.net.answer(
        HOME,
        item,
        json!({"epochId": o.e.id, "member": a.ua}),
        json!({"0": true}),
    );
}

/// After `remove(bob)` the admin's next epoch leaves bob out though listed; bob authors no rekey (`NotMember`); a non-admin
/// removes no one (`NotAdmin`).
#[tokio::test(flavor = "multi_thread")]
async fn removed_member_dropped_and_authors_nothing() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    latest(&w, &o);
    let e =
        w.pq.remove(
            &sref(&o),
            &o.e,
            &me(&w.bob),
            1,
            std::slice::from_ref(&w.alice.ua),
            &payer(&w),
        )
        .await;
    assert_eq!(code(e), "NotAdmin");
    assert_eq!(w.net.writes(), 0);
    w.pq.remove(
        &sref(&o),
        &o.e,
        &me(&w.alice),
        2,
        std::slice::from_ref(&w.bob.ua),
        &payer(&w),
    )
    .await
    .unwrap();
    assert_eq!(
        w.net.writes_of("IPqChat.remove")[0]["r"]["members"],
        json!([w.bob.ua])
    );
    flag(&w, &o, "IPqChat.removedIn", &w.bob);
    let n = w.net.writes();
    let e =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.bob, 3, &[&w.alice, &w.bob], &[&w.alice]),
        )
        .await;
    assert_eq!(code(e), "NotMember");
    assert_eq!(w.net.writes(), n);
    let all = [&w.alice, &w.bob, &w.carol];
    let b =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.alice, 4, &all, &[&w.alice]),
        )
        .await
        .unwrap();
    assert_eq!(
        uas(&b.epoch),
        sorted(&[&w.alice, &w.carol]),
        "a removed member kept"
    );
}

/// E-1 / D2-8 (the builder): dropping a removed member is a plain rekey (CTR-CHAT-20), so a member who is no admin rekeys after
/// a removal; twin: dropping carol unflagged is a membership change (`NotAdmin`).
#[tokio::test(flavor = "multi_thread")]
async fn a_non_admin_drops_a_removed_member() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = opened(&w, &[&w.alice, &w.bob, &w.carol]).await;
    child(&w.net, HOME, &o.e.id, ZERO32);
    let two = [&w.alice, &w.bob];
    let e =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.bob, 2, &two, &[&w.alice]),
        )
        .await;
    assert_eq!(code(e), "NotAdmin");
    flag(&w, &o, "IPqChat.removedIn", &w.carol);
    let all = [&w.alice, &w.bob, &w.carol];
    let b =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.bob, 3, &all, &[&w.alice]),
        )
        .await
        .unwrap();
    assert_eq!(uas(&b.epoch), sorted(&two));
}

/// D2-4: a leave or removal is checked where the contract checks it, at the home's head: an epoch named 17 below the head is
/// `ExitLag` before anything is signed (16: built); a UA removed at the head is `NotMember` though the epoch named has no
/// flag. Only the flags of the UAs concerned are read.
#[tokio::test(flavor = "multi_thread")]
async fn exits_are_checked_at_the_head() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    let mut h = o.e.clone();
    h.id = hex(&[0x71; 32]);
    h.parent = hex(&[0x70; 32]);
    h.epoch = 17;
    put_record(&w.net, HOME, &h);
    w.net.answer(
        HOME,
        "IPqChat.latestEpoch",
        json!({"sessionId": o.e.session_id}),
        json!({"epochId": h.id}),
    );
    macro_rules! leave {
        () => {
            w.pq.leave(&sref(&o), &o.e, &me(&w.bob), 1, &payer(&w))
                .await
        };
    }
    macro_rules! remove {
        () => {
            w.pq.remove(
                &sref(&o),
                &o.e,
                &me(&w.alice),
                2,
                std::slice::from_ref(&w.bob.ua),
                &payer(&w),
            )
            .await
        };
    }
    assert_eq!(code(leave!()), "ExitLag");
    assert_eq!(code(remove!()), "ExitLag");
    assert_eq!(w.net.writes(), 0);
    h.epoch = 16;
    put_record(&w.net, HOME, &h);
    let flags = w.net.reads_of("IPqChat.leftIn") + w.net.reads_of("IPqChat.removedIn");
    assert_eq!(code(leave!()), "Ok");
    assert_eq!(
        w.net.reads_of("IPqChat.leftIn") + w.net.reads_of("IPqChat.removedIn") - flags,
        2,
        "the leaver's two flags only"
    );
    assert_eq!(code(remove!()), "Ok");
    // bob removed at the head (not at the epoch named): refused at the head as the contract does
    w.net.answer(
        HOME,
        "IPqChat.removedIn",
        json!({"epochId": h.id, "member": w.bob.ua}),
        json!({"0": true}),
    );
    assert_eq!(code(leave!()), "NotMember");
    assert_eq!(code(remove!()), "NotMember");
}

/// A member who left authors no plain rekey (`NotMember`); the others' plain rekey drops them.
#[tokio::test(flavor = "multi_thread")]
async fn a_member_who_left_authors_nothing() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = opened(&w, &[&w.alice, &w.bob, &w.carol]).await;
    child(&w.net, HOME, &o.e.id, ZERO32);
    latest(&w, &o);
    w.pq.leave(&sref(&o), &o.e, &me(&w.carol), 1, &payer(&w))
        .await
        .unwrap();
    assert_eq!(
        w.net.writes_of("IPqChat.leave")[0]["l"]["member"],
        json!(w.carol.ua)
    );
    flag(&w, &o, "IPqChat.leftIn", &w.carol);
    let all = [&w.alice, &w.bob, &w.carol];
    let e =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.carol, 2, &all, &[&w.alice]),
        )
        .await;
    assert_eq!(code(e), "NotMember");
    let b =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.bob, 3, &all, &[&w.alice]),
        )
        .await
        .unwrap();
    assert_eq!(uas(&b.epoch), sorted(&[&w.alice, &w.bob]));
}

/// A child of a parent whose home slot another child holds: `EpochTaken`, nothing written; rebuilt on the winner, opened from
/// its own wrap: the winner's number plus one, under it.
#[tokio::test(flavor = "multi_thread")]
async fn epoch_taken_rebuilt_from_the_winner() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    // bob's child of e0 won the slot
    let kw = w.app.pqchat_epoch_key(&w.seed).unwrap();
    let wid = w
        .app
        .pqchat_epoch_id(o.e.session_id.clone(), w.bob.ua.clone(), 9)
        .unwrap();
    let mut win = o.e.clone();
    (win.id, win.author, win.nonce, win.epoch, win.parent) =
        (wid.clone(), w.bob.ua.clone(), 9, 1, o.e.id.clone());
    let i = win.index_of(&w.alice.ua).unwrap();
    let wrap = w
        .app
        .pqchat_wrap(
            CHAIN.into(),
            kw,
            win.session_id.clone(),
            wid.clone(),
            w.alice.ua.clone(),
            1,
        )
        .await
        .unwrap();
    win.wrap_hashes[i] = w.app.pqchat_wrap_hash(wrap.clone()).unwrap();
    put_record(&w.net, HOME, &win);
    put_wrap(&w.net, HOME, &wid, i, &wrap);
    child(&w.net, HOME, &o.e.id, &wid);
    child(&w.net, HOME, &wid, ZERO32);
    let e =
        w.pq.rekey(
            &sref(&o),
            &open(&w, &o),
            rk(&w, &w.alice, 3, &[&w.alice, &w.bob], &[&w.alice]),
        )
        .await;
    assert_eq!(code(e), "EpochTaken");
    assert_eq!(w.net.writes(), 0);
    let winner = w.pq.child_of(&sref(&o), &o.e.id).await.unwrap().unwrap();
    let ep =
        w.pq.open_epoch(&sref(&o), &winner, &w.alice.key, &w.alice.ua, None)
            .await
            .unwrap();
    let b =
        w.pq.rekey(
            &sref(&o),
            &ep,
            rk(&w, &w.alice, 4, &[&w.alice, &w.bob], &[&w.alice]),
        )
        .await
        .unwrap();
    assert_eq!((b.epoch.epoch, b.epoch.parent.as_str()), (2, wid.as_str()));
}

/// Sends held from a child's first sight until the home's final block holds it (`EpochNotFinal`, nothing written); then
/// under the child; with no child seen, under the epoch itself.
#[tokio::test(flavor = "multi_thread")]
async fn sends_held_until_the_child_is_final() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    let c = hex(&[0xc1; 32]);
    assert_eq!(w.pq.send_epoch(&sref(&o), &o.e.id).await.unwrap(), o.e.id);
    w.pq.saw_child(&o.e.id, &c);
    assert_eq!(
        code(w.pq.send_epoch(&sref(&o), &o.e.id).await),
        "EpochNotFinal"
    );
    assert_eq!(w.net.writes(), 0);
    child(&w.net, HOME, &o.e.id, &c);
    assert_eq!(w.pq.send_epoch(&sref(&o), &o.e.id).await.unwrap(), c);
}

/// Each member wrapped at the highest KEM version seen; a raised one is an event and starts nothing.
#[tokio::test(flavor = "multi_thread")]
async fn wraps_at_the_highest_version() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let a = create(&w, &[&w.bob], &[], 1).await.unwrap();
    let key = |b: &Built| {
        b.epoch
            .members
            .iter()
            .find(|m| m.ua == w.bob.ua)
            .unwrap()
            .key_id
    };
    assert_eq!(key(&a), 1);
    assert!(w.pq.events().is_empty());
    kem(&w, &w.bob, 2);
    let b = create(&w, &[&w.bob], &[], 2).await.unwrap();
    assert_eq!(
        key(&b),
        2,
        "the highest KEM version replaced by the first seen"
    );
    assert_eq!(
        w.pq.events(),
        [Event::KemVersionRaised {
            session: b.session_id.clone(),
            member: w.bob.ua.clone()
        }]
    );
    assert_eq!(w.net.writes_of("IPqChat.createSession").len(), 2);
}

/// A member's raised version found by the check: the event, no write (the rekey is the user's choice); unchanged, nothing.
#[tokio::test(flavor = "multi_thread")]
async fn raised_version_starts_no_rekey() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    assert!(w.pq.kem_changes(&sref(&o), &o.e).await.unwrap().is_empty());
    assert!(w.pq.events().is_empty());
    kem(&w, &w.bob, 2);
    assert_eq!(
        w.pq.kem_changes(&sref(&o), &o.e).await.unwrap(),
        std::slice::from_ref(&w.bob.ua)
    );
    assert_eq!(
        w.pq.events(),
        [Event::KemVersionRaised {
            session: o.e.session_id.clone(),
            member: w.bob.ua.clone()
        }]
    );
    assert_eq!(w.net.writes(), 0, "a rekey started on a raised version");
}

/// An own wrap of the winning epoch whose hash holds but which does not open: dropped (`envelope`), shown only, nothing
/// written; the untouched wrap opens.
#[tokio::test(flavor = "multi_thread")]
async fn own_wrap_that_does_not_open_starts_nothing() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let o = session2(&w).await;
    assert!(w
        .pq
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .is_ok());
    let mut bad = o.wrap.clone();
    bad.sealed_key[0] ^= 1;
    let mut e = o.e.clone();
    let i = e.index_of(&w.bob.ua).unwrap();
    e.wrap_hashes[i] = w.app.pqchat_wrap_hash(bad.clone()).unwrap();
    put_record(&w.net, HOME, &e);
    put_wrap(&w.net, HOME, &e.id, i, &bad);
    let r =
        w.pq.open_epoch(&o.s, &e.id, &w.bob.key, &w.bob.ua, None)
            .await;
    assert_eq!(r.err(), Some(DropReason::Envelope));
    assert_eq!(
        w.pq.dropped(&e.session_id).get(&DropReason::Envelope),
        Some(&1)
    );
    assert_eq!(w.net.writes(), 0);
}

/// A UA with `checkedOf.kem` `NONE` skipped and named (`KemKeyMissing`); the creator's own: refused by that code.
#[tokio::test(flavor = "multi_thread")]
async fn kem_key_missing_skipped_and_named() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let dave = acc(&w.seed, 3);
    not_msig(&w.net, &dave.ua);
    kem(&w, &dave, 1);
    let b = create(&w, &[&w.bob, &dave], &[], 1).await.unwrap();
    assert_eq!(b.epoch.members.len(), 3);
    no_kem(&w, &dave);
    let b = create(&w, &[&w.bob, &dave], &[], 2).await.unwrap();
    assert_eq!(uas(&b.epoch), sorted(&[&w.alice, &w.bob]));
    let named = Skipped {
        ua: dave.ua.clone(),
        via: ZERO32.into(),
        code: "KemKeyMissing",
    };
    assert_eq!(b.skipped, [named]);
    no_kem(&w, &w.alice);
    assert_eq!(code(create(&w, &[&w.bob], &[], 3).await), "KemKeyMissing");
}

/// A member whose registered key P14 refuses (a vector row: the first coefficient equal to q) skipped and named
/// (`KemKeyInvalid`); a valid row's key wrapped.
#[tokio::test(flavor = "multi_thread")]
async fn kem_key_invalid_skipped_and_named() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let keys: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!(
            "{}/../../smartcontracts/vectors/pqchat/keys.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap();
    let row = |n: &str| {
        let r = keys["p14"]["rows"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["name"].as_str().unwrap().contains(n))
            .unwrap();
        pqchat_core::model::unhex(r["kemPk"].as_str().unwrap()).unwrap()
    };
    kem_with(&w, &w.carol, 1, &row("q - 1 = 3328"));
    let b = create(&w, &[&w.bob, &w.carol], &[], 1).await.unwrap();
    assert_eq!(b.epoch.members.len(), 3);
    kem_with(&w, &w.carol, 1, &row("first coefficient q = 3329"));
    let b = create(&w, &[&w.bob, &w.carol], &[], 2).await.unwrap();
    assert_eq!(uas(&b.epoch), sorted(&[&w.alice, &w.bob]));
    assert_eq!(b.skipped.len(), 1);
    assert_eq!(
        (b.skipped[0].ua.as_str(), b.skipped[0].code),
        (w.carol.ua.as_str(), "KemKeyInvalid")
    );
}

/// An `msig` seat expanded into its accepted, KEM-holding leaves over two levels, each with `via` the seat; a leaf without a
/// KEM key named, one not accepted and a third level left out; a seat with no accepted leaf refused (`MembersInvalid`).
#[tokio::test(flavor = "multi_thread")]
async fn msig_seat_expanded() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (dave, erin, frank) = (acc(&w.seed, 3), acc(&w.seed, 4), acc(&w.seed, 5));
    for a in [&dave, &erin, &frank] {
        not_msig(&w.net, &a.ua);
    }
    kem(&w, &frank, 1);
    no_kem(&w, &dave);
    let (seat, inner, deep) = (hex(&[0x5e; 32]), hex(&[0x5f; 32]), hex(&[0x60; 32]));
    msig(
        &w.net,
        &seat,
        &[
            (KIND, &w.carol.ua, true),
            (KIND, &dave.ua, true),
            (KIND, &erin.ua, false),
            (MSIG as u16, &inner, true),
        ],
    );
    msig(
        &w.net,
        &inner,
        &[(KIND, &frank.ua, true), (MSIG as u16, &deep, true)],
    );
    let b =
        w.pq.create(CreateSession {
            me: me(&w.alice),
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce: 1,
            members: vec![w.bob.ua.clone(), seat.clone()],
            admins: vec![],
            info: info(),
            payer: payer(&w),
        })
        .await
        .unwrap();
    assert_eq!(uas(&b.epoch), sorted(&[&w.alice, &w.bob, &w.carol, &frank]));
    for m in &b.epoch.members {
        let via = if m.ua == w.carol.ua || m.ua == frank.ua {
            seat.as_str()
        } else {
            ZERO32
        };
        assert_eq!(m.via, via, "via not set");
    }
    assert_eq!(review(&b, "message.members[0].via").len(), 66);
    assert_eq!(
        b.skipped,
        [Skipped {
            ua: dave.ua.clone(),
            via: seat.clone(),
            code: "KemKeyMissing"
        }]
    );
    let mut seats = b.epoch.seats();
    seats.sort();
    let mut want = vec![w.alice.ua.clone(), w.bob.ua.clone(), seat.clone()];
    want.sort();
    assert_eq!(seats, want);
    // no accepted leaf
    let empty = hex(&[0x61; 32]);
    msig(&w.net, &empty, &[(KIND, &erin.ua, false)]);
    let e =
        w.pq.create(CreateSession {
            me: me(&w.alice),
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce: 2,
            members: vec![w.bob.ua.clone(), empty],
            admins: vec![],
            info: info(),
            payer: payer(&w),
        })
        .await;
    assert_eq!(code(e), "MembersInvalid");
}

/// A record whose author is an `msig`: refused before any read (`MsigAuthorPlanned`, CLI-PQC-02).
#[tokio::test(flavor = "multi_thread")]
async fn msig_author_planned() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let seat = hex(&[0x5e; 32]);
    let e =
        w.pq.create(CreateSession {
            me: Me {
                key: KeyRef::Msig {
                    ua: seat.clone(),
                    slots: vec![],
                },
                ua: seat,
            },
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce: 1,
            members: vec![w.bob.ua.clone()],
            admins: vec![],
            info: info(),
            payer: payer(&w),
        })
        .await;
    assert_eq!(code(e), "MsigAuthorPlanned");
    assert_eq!((w.net.reads.lock().unwrap().len(), w.net.writes()), (0, 0));
}
