// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T8 on the SDK's fake chain and the fake Matrix server (CLI-PQC-05, spec §6, Fable K8): the event's bounds; rooms
//! created without Matrix encryption and bound by the creator's `create`; events of a room no session binds ignored; a room
//! the account had joined before, or that another session holds, not used (shown with the reason); invites only to Matrix
//! ids bound to their UA and only once the epoch is complete at home; removals only by an admin of the parent by the
//! home's record, never by a Matrix power level; the room id in no chain write; a rekey's new room not joined until
//! confirmed; a transport failure reported for that store only; chain stores read while detached. Each negative beside its
//! positive control.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;
use common::confirmed;

use base64::engine::general_purpose::{STANDARD, URL_SAFE};
use base64::Engine as _;
use common::epochs::*;
use common::matrix::{Client, Server};
use common::sdk::*;
use pqchat_core::content::Content;
use pqchat_core::matrix::{self, MatrixIn, RoomEvent, RoomRefusal, RoomUse};
use pqchat_core::message::{Incoming, OpenEpoch};
use pqchat_core::model::hex;
use pqchat_core::session::{CreateSession, Info, Rekey, StoreEntry};
use pqchat_core::stores::Delivery;
use pqchat_core::{DropReason, Event};
use scaas_sdk::pqchat_records::PqChatCard;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;

const ALICE: &str = "@alice:fake.local";
const BOB: &str = "@bob:fake.local";
const CAROL: &str = "@carol:fake.local";

fn txt(s: &str) -> Content {
    Content::Text {
        media_type: None,
        body: s.into(),
    }
}

/// `from`'s sealed message at `counter` under `s` as a Matrix event of sender `mxid`.
async fn ev_of(w: &World, from: &Acc, s: &Signed, counter: u64, mxid: &str) -> RoomEvent {
    let m = sealed(
        w,
        from,
        &s.e,
        &s.k,
        counter,
        r#"{"body":"m","type":"text"}"#,
    )
    .await;
    RoomEvent {
        sender: mxid.into(),
        content: matrix::event(&m.hint, &m.env).to_string().into_bytes(),
    }
}

/// `s` in use on alice's crate with its stores confirmed and their spend consented.
async fn in_use(w: &World, s: &Signed) -> Arc<OpenEpoch> {
    let ep = w.pq.use_epoch(&sref(&s.e), s.open()).await.unwrap();
    w.pq.confirm_stores(&ep).unwrap();
    w.pq.accept(&sref(&s.e), true).unwrap();
    ep
}

/// A room `creator` made with alice invited (a session's room alice has not joined yet).
fn invited_room(server: &Server, creator: &str) -> String {
    let r = server.ordinary(creator, &[], false);
    server
        .rooms
        .lock()
        .unwrap()
        .get_mut(&r)
        .unwrap()
        .invited
        .insert(ALICE.into());
    r
}

fn attach(w: &World) -> (Arc<Server>, Arc<Client>) {
    let server = Server::new();
    let c = Client::new(&server, ALICE);
    w.pq.attach_matrix(c.clone());
    (server, c)
}

/// The event's bounds: the padded standard form read; unpadded, URL-safe, above 65,536 B, `v ≠ 1`, a hint not 8 bytes, an
/// empty envelope or another member dropped (`decode`).
#[test]
fn event_bounds() {
    let (hint, env) = ([0xfb; 8], vec![0xfe; 40]);
    let ev = matrix::event(&hint, &env);
    assert_eq!(
        matrix::parse(ev.to_string().as_bytes()),
        Ok((hint, env.clone()))
    );
    let bad = |v: Value| matrix::parse(v.to_string().as_bytes());
    let h = STANDARD.encode(hint);
    let e = STANDARD.encode(&env);
    assert!(h.contains('+') || h.contains('/'));
    for v in [
        json!({"v": 1, "hint": h.trim_end_matches('='), "env": e}),
        json!({"v": 1, "hint": URL_SAFE.encode(hint), "env": e}),
        json!({"v": 2, "hint": h, "env": e}),
        json!({"v": 1, "hint": STANDARD.encode([1u8; 7]), "env": e}),
        json!({"v": 1, "hint": h, "env": ""}),
        json!({"v": 1, "hint": h, "env": e, "x": 1}),
        json!({"v": 1, "hint": h, "env": STANDARD.encode(vec![0u8; 50_000])}),
    ] {
        assert_eq!(bad(v), Err(DropReason::Decode));
    }
}

/// A room alice's client creates has no Matrix encryption and is bound to the session her `create` names it in, at the
/// confirm after the signature; a room it did not create is refused there (`MatrixRoom`) before anything is written. A
/// creation whose first write cannot be prepared releases its room for the next session (review A-1, E-7), and accepts no
/// session.
#[tokio::test(flavor = "multi_thread")]
async fn created_room_unencrypted_and_bound_by_create() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, _) = attach(&w);
    let room = w.pq.create_room().await.unwrap();
    assert!(!server.rooms.lock().unwrap()[&room].encrypted);
    let req = |room: &str, nonce| CreateSession {
        me: me(&w.alice),
        chain: CHAIN.into(),
        home: HOME.into(),
        nonce,
        members: vec![w.bob.ua.clone()],
        admins: vec![],
        info: Info {
            stores: vec![StoreEntry::Matrix { room: room.into() }],
            name: "t8".into(),
            topic: String::new(),
            matrix: Default::default(),
        },
        payer: payer(&w),
    };
    let other = server.ordinary(ALICE, &[], false);
    assert_eq!(
        code(confirmed(&w.pq, w.pq.create(req(&other, 1)).await).await),
        "MatrixRoom"
    );
    assert_eq!(w.net.writes(), 0);
    let b = confirmed(&w.pq, w.pq.create(req(&room, 2)).await)
        .await
        .unwrap();
    assert_eq!(
        w.pq.room_session(&room).unwrap(),
        Some(b.session_id.clone())
    );
    // the room serves that session only
    assert_eq!(
        code(confirmed(&w.pq, w.pq.create(req(&room, 3)).await).await),
        "MatrixRoom"
    );
    // a creation whose call is refused: its room released, its session not accepted; the next creation binds the room
    let free = w.pq.create_room().await.unwrap();
    let p = w.pq.create(req(&free, 4)).await.unwrap();
    let sid = p.facts().session_id.clone();
    w.net
        .accept
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(w.pq.confirm(p).await.is_err());
    assert_eq!(w.pq.room_session(&free).unwrap(), None, "released");
    assert_eq!(w.pq.consent(&sid).unwrap(), None, "not accepted");
    w.net
        .accept
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let b = confirmed(&w.pq, w.pq.create(req(&free, 5)).await)
        .await
        .unwrap();
    assert_eq!(w.pq.room_session(&free).unwrap(), Some(b.session_id));
}

/// Every `Bound` answer is told to the transport (`bound`), the first bind and each later use alike: a fresh device or a new
/// Matrix login learns the binding the crate's store holds (scaas-matrix marks the room PqChat on it).
#[tokio::test(flavor = "multi_thread")]
async fn a_bound_room_is_told_to_the_transport() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    let room = invited_room(&server, BOB);
    let s = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&room)], &[]),
    )
    .await;
    let ep = in_use(&w, &s).await;
    assert!(c.calls_of("bound").is_empty());
    assert_eq!(w.pq.join_room(&ep).await.unwrap(), RoomUse::Bound);
    assert_eq!(c.calls_of("bound"), vec![room.clone()]);
    assert_eq!(w.pq.join_room(&ep).await.unwrap(), RoomUse::Bound);
    assert_eq!(c.calls_of("bound"), vec![room.clone(), room.clone()]);
    // a Matrix client that knows nothing (a new login) learns every bound room at once, before any session is opened
    let fresh = Client::new(&server, ALICE);
    w.pq.attach_matrix(fresh.clone());
    assert_eq!(w.pq.tell_bound_rooms().await.unwrap(), 1);
    assert_eq!(fresh.calls_of("bound"), vec![room]);
}

/// An event of a room no session binds is ignored (nothing counted, nothing read); the same kind of event in the bound room
/// is read and shown.
#[tokio::test(flavor = "multi_thread")]
async fn events_of_an_unbound_room_ignored() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, _) = attach(&w);
    let room = invited_room(&server, BOB);
    let s = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&room)], &[]),
    )
    .await;
    let ep = in_use(&w, &s).await;
    assert_eq!(w.pq.join_room(&ep).await.unwrap(), RoomUse::Bound);
    let e0 = ev_of(&w, &w.bob, &s, 0, BOB).await;
    assert!(matches!(
        w.pq.matrix_event(&room, e0).await.unwrap(),
        MatrixIn::Read(Incoming::Shown(_))
    ));
    let other = server.ordinary(BOB, &[ALICE], false);
    let reads = w.net.reads.lock().unwrap().len();
    let e1 = ev_of(&w, &w.bob, &s, 1, BOB).await;
    assert_eq!(
        w.pq.matrix_event(&other, e1).await.unwrap(),
        MatrixIn::Ignored
    );
    assert!(w.pq.dropped(&s.e.session_id).is_empty());
    assert_eq!(w.net.reads.lock().unwrap().len(), reads);
    assert_eq!(w.pq.timeline(&s.e.session_id).len(), 1);
}

/// A room the account had joined before a session named it is not used: shown with the reason, not joined, its events
/// ignored, a send's copy for it not written; a room it had not joined is joined and bound (the control).
#[tokio::test(flavor = "multi_thread")]
async fn room_joined_before_not_used() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    let old = server.ordinary(CAROL, &[ALICE], true);
    let s = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&old), chain_entry(HOME)], &[]),
    )
    .await;
    let ep = in_use(&w, &s).await;
    assert_eq!(
        w.pq.join_room(&ep).await.unwrap(),
        RoomUse::Refused(RoomRefusal::JoinedBefore)
    );
    assert_eq!(
        w.pq.events(),
        [Event::RoomNotUsed {
            session: s.e.session_id.clone(),
            reason: RoomRefusal::JoinedBefore
        }]
    );
    assert!(c.calls_of("join").is_empty());
    let e0 = ev_of(&w, &w.bob, &s, 0, BOB).await;
    assert_eq!(
        w.pq.matrix_event(&old, e0).await.unwrap(),
        MatrixIn::Ignored
    );
    let rep =
        w.pq.send_content(&sref(&s.e), &me(&w.alice), &txt("x"), None, &opts(&w))
            .await
            .unwrap();
    assert_eq!(rep.stores[0].1, Delivery::Failed("MatrixRoom"));
    assert!(matches!(rep.stores[1].1, Delivery::Sent(_)));
    assert!(c.calls_of("send_event").is_empty());
    // the control: a room alice was only invited to
    let fresh = invited_room(&server, BOB);
    let s2 = signed(
        &w,
        &w.bob,
        None,
        2,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&fresh)], &[]),
    )
    .await;
    let ep2 = in_use(&w, &s2).await;
    assert_eq!(w.pq.join_room(&ep2).await.unwrap(), RoomUse::Bound);
    assert_eq!(c.calls_of("join"), [fresh]);
}

/// A room named by two sessions serves the first bound only: the second is shown with the reason and its events are read
/// under the first's (never shown under the second).
#[tokio::test(flavor = "multi_thread")]
async fn room_named_by_two_sessions() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, _) = attach(&w);
    let room = invited_room(&server, BOB);
    let s1 = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&room)], &[]),
    )
    .await;
    let s2 = signed(
        &w,
        &w.carol,
        None,
        1,
        &[&w.alice, &w.carol],
        &[&w.carol],
        info(vec![room_entry(&room)], &[]),
    )
    .await;
    let ep1 = in_use(&w, &s1).await;
    let ep2 = in_use(&w, &s2).await;
    assert_eq!(w.pq.join_room(&ep1).await.unwrap(), RoomUse::Bound);
    assert_eq!(
        w.pq.join_room(&ep2).await.unwrap(),
        RoomUse::Refused(RoomRefusal::OtherSession)
    );
    let e = ev_of(&w, &w.carol, &s2, 0, CAROL).await;
    w.pq.matrix_event(&room, e).await.unwrap();
    assert!(w.pq.timeline(&s2.e.session_id).is_empty());
    assert_eq!(w.pq.pending(&s1.e.session_id).unwrap(), 1);
}

/// alice's session over a room her client created, `members` and the `sealedInfo` map `matrix`, created by her crate, the
/// record at HOME complete or not.
async fn alice_creates(
    w: &World,
    members: &[&Acc],
    matrix_map: &[(&Acc, &str)],
    nonce: u64,
) -> (String, OpenEpoch) {
    let room = w.pq.create_room().await.unwrap();
    let b = confirmed(
        &w.pq,
        w.pq.create(CreateSession {
            me: me(&w.alice),
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce,
            members: members.iter().map(|a| a.ua.clone()).collect(),
            admins: vec![],
            info: Info {
                stores: vec![StoreEntry::Matrix { room: room.clone() }],
                name: "t8".into(),
                topic: String::new(),
                matrix: matrix_map
                    .iter()
                    .map(|(a, id)| (a.ua.clone(), id.to_string()))
                    .collect(),
            },
            payer: payer(w),
        })
        .await,
    )
    .await
    .unwrap();
    let ep = OpenEpoch {
        chain: CHAIN.into(),
        epoch: b.epoch.clone(),
        k: b.k.clone(),
    };
    put_record(&w.net, HOME, &b.epoch);
    (room, ep)
}

/// Invites go to Matrix ids bound to their UA only (an envelope signed by that UA received from that sender), and only once
/// the session is complete at home; a claimed id not asserted is named (`unbound`), never invited.
#[tokio::test(flavor = "multi_thread")]
async fn invites_only_bound_ids_once_complete() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    let (room, ep) = alice_creates(
        &w,
        &[&w.bob, &w.carol],
        &[(&w.bob, BOB), (&w.carol, CAROL)],
        1,
    )
    .await;
    let s = sref(&ep.epoch);
    let ep = w.pq.use_epoch(&s, ep).await.unwrap();
    complete(&w.net, &ep.epoch.id, false);
    assert_eq!(
        code(w.pq.sync_room(&s, &ep, None, &me(&w.alice)).await),
        "EpochIncomplete"
    );
    assert!(c.calls_of("invite").is_empty());
    complete(&w.net, &ep.epoch.id, true);
    // carol asserts her id: her envelope received from her Matrix id in a room alice's crate binds
    let r0 = invited_room(&server, BOB);
    let s0 = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob, &w.carol],
        &[&w.bob],
        info(vec![room_entry(&r0)], &[]),
    )
    .await;
    let ep0 = in_use(&w, &s0).await;
    w.pq.join_room(&ep0).await.unwrap();
    server.add_member(&r0, CAROL);
    let e = ev_of(&w, &w.carol, &s0, 0, CAROL).await;
    assert!(matches!(
        w.pq.matrix_event(&r0, e).await.unwrap(),
        MatrixIn::Read(Incoming::Shown(_))
    ));
    assert_eq!(w.pq.matrix_ids_of(&w.carol.ua).unwrap(), [CAROL]);
    let r = w.pq.sync_room(&s, &ep, None, &me(&w.alice)).await.unwrap();
    assert_eq!(
        (r.invited, r.unbound, r.failed),
        (vec![w.carol.ua.clone()], vec![w.bob.ua.clone()], None)
    );
    assert!(server.is_invited(&room, CAROL));
    assert!(!server.is_invited(&room, BOB));
}

/// A member dropped by alice's epoch is removed from the room only when alice is an admin of the parent by the home's
/// record; the room's creator holds the top Matrix power level and that grants nothing.
#[tokio::test(flavor = "multi_thread")]
async fn removal_by_a_parent_admin_only() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    for (admins, removed) in [(vec![&w.bob], false), (vec![&w.alice], true)] {
        let room = w.pq.create_room().await.unwrap();
        let nonce = if removed { 2 } else { 1 };
        let map = [(&w.alice, ALICE), (&w.bob, BOB), (&w.carol, CAROL)];
        let p = signed(
            &w,
            &w.alice,
            None,
            nonce,
            &[&w.alice, &w.bob, &w.carol],
            &admins,
            info(vec![room_entry(&room)], &map),
        )
        .await;
        let ep0 = in_use(&w, &p).await;
        assert_eq!(w.pq.join_room(&ep0).await.unwrap(), RoomUse::Bound);
        server.add_member(&room, CAROL);
        let e = ev_of(&w, &w.carol, &p, 0, CAROL).await;
        w.pq.matrix_event(&room, e).await.unwrap();
        let ch = signed(
            &w,
            &w.alice,
            Some(&p.e),
            10 + nonce,
            &[&w.alice, &w.bob],
            &admins,
            info(vec![room_entry(&room)], &map[..2]),
        )
        .await;
        let ep1 = w.pq.use_epoch(&sref(&p.e), ch.open()).await.unwrap();
        let r =
            w.pq.sync_room(&sref(&p.e), &ep1, Some(&ep0), &me(&w.alice))
                .await
                .unwrap();
        assert_eq!(r.removed.is_empty(), !removed);
        assert_eq!(server.is_member(&room, CAROL), !removed);
    }
    assert_eq!(c.calls_of("remove").len(), 1);
}

/// The room id is in no chain write: `createSession`, `rekey`, `storeMessage` and `postMessage` scanned, as text and as
/// hex of its bytes.
#[tokio::test(flavor = "multi_thread")]
async fn room_id_in_no_chain_write() {
    let _one = ONE.lock().await;
    let w = ready().await;
    attach(&w);
    let room = w.pq.create_room().await.unwrap();
    let st = vec![
        StoreEntry::Matrix { room: room.clone() },
        serde_json::from_value(chain_entry(HOME)).unwrap(),
    ];
    let b = confirmed(
        &w.pq,
        w.pq.create(CreateSession {
            me: me(&w.alice),
            chain: CHAIN.into(),
            home: HOME.into(),
            nonce: 1,
            members: vec![w.bob.ua.clone()],
            admins: vec![],
            info: Info {
                stores: st.clone(),
                name: "t8".into(),
                topic: String::new(),
                matrix: Default::default(),
            },
            payer: payer(&w),
        })
        .await,
    )
    .await
    .unwrap();
    put_record(&w.net, HOME, &b.epoch);
    let s = sref(&b.epoch);
    let ep =
        w.pq.use_epoch(
            &s,
            OpenEpoch {
                chain: CHAIN.into(),
                epoch: b.epoch.clone(),
                k: b.k.clone(),
            },
        )
        .await
        .unwrap();
    w.pq.confirm_stores(&ep).unwrap();
    w.pq.consent_chain_spend(&s.session_id, true).unwrap();
    child(&w.net, HOME, &b.epoch_id, pqchat_core::model::ZERO32);
    let mut o = opts(&w);
    o.post = true;
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &o)
            .await
            .unwrap();
    assert!(
        rep.stores
            .iter()
            .all(|(_, d)| matches!(d, Delivery::Sent(_))),
        "{rep:?}"
    );
    for a in [&w.alice, &w.bob] {
        for it in ["IPqChat.leftIn", "IPqChat.removedIn"] {
            w.net.answer(
                HOME,
                it,
                json!({"epochId": b.epoch_id, "member": a.ua}),
                json!({"0": false}),
            );
        }
    }
    confirmed(
        &w.pq,
        w.pq.rekey(
            &s,
            &ep,
            Rekey {
                me: me(&w.alice),
                nonce: 2,
                members: vec![w.alice.ua.clone(), w.bob.ua.clone()],
                admins: vec![w.alice.ua.clone()],
                info: Info {
                    stores: st,
                    name: "t8".into(),
                    topic: String::new(),
                    matrix: Default::default(),
                },
                payer: payer(&w),
            },
        )
        .await,
    )
    .await
    .unwrap();
    let writes = w.net.writes.lock().unwrap().clone();
    let items: Vec<&str> = writes.iter().map(|x| x.1.as_str()).collect();
    for it in [
        "IPqChat.createSession",
        "IPqChat.rekey",
        "IPqChat.storeMessage",
        "IPqChat.postMessage",
    ] {
        assert!(items.contains(&it), "{it} not written: {items:?}");
    }
    let hexed = hex(room.as_bytes())[2..].to_string();
    for (_, it, args) in &writes {
        let t = args.to_string().to_ascii_lowercase();
        assert!(
            !t.contains(&room.to_ascii_lowercase()) && !t.contains(&hexed),
            "{it} carries the room id"
        );
    }
}

/// A rekey's list naming a new room: neither joined nor read until the user confirms it; then joined and bound.
#[tokio::test(flavor = "multi_thread")]
async fn new_room_of_a_rekey_joined_once_confirmed() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    let s0 = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![chain_entry(HOME)], &[]),
    )
    .await;
    in_use(&w, &s0).await;
    let room = invited_room(&server, BOB);
    let s1 = signed(
        &w,
        &w.bob,
        Some(&s0.e),
        2,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![chain_entry(HOME), room_entry(&room)], &[]),
    )
    .await;
    let ep1 = w.pq.use_epoch(&sref(&s0.e), s1.open()).await.unwrap();
    assert_eq!(w.pq.join_room(&ep1).await.unwrap(), RoomUse::Unconfirmed);
    assert_eq!(c.acting(), 0);
    w.pq.confirm_stores(&ep1).unwrap();
    assert_eq!(w.pq.join_room(&ep1).await.unwrap(), RoomUse::Bound);
    assert_eq!(c.calls_of("join"), [room]);
}

/// A transport failure is that store's outcome only: the chain store of the same send is still written.
#[tokio::test(flavor = "multi_thread")]
async fn transport_failure_for_that_store_only() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    let room = invited_room(&server, BOB);
    let s = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&room), chain_entry(HOME)], &[]),
    )
    .await;
    let ep = in_use(&w, &s).await;
    w.pq.join_room(&ep).await.unwrap();
    c.fail_send.store(true, Ordering::SeqCst);
    let rep =
        w.pq.send_content(&sref(&s.e), &me(&w.alice), &txt("x"), None, &opts(&w))
            .await
            .unwrap();
    assert_eq!(rep.stores[0].1, Delivery::Failed("MatrixRoom"));
    assert!(matches!(rep.stores[1].1, Delivery::Sent(_)));
    assert_eq!(w.net.writes_of("IPqChat.storeMessage").len(), 1);
    // the control: the transport back, both stores take the next one
    c.fail_send.store(false, Ordering::SeqCst);
    let rep =
        w.pq.send_content(&sref(&s.e), &me(&w.alice), &txt("y"), None, &opts(&w))
            .await
            .unwrap();
    assert!(rep
        .stores
        .iter()
        .all(|(_, d)| matches!(d, Delivery::Sent(_))));
    assert_eq!(server.events_of(&room).len(), 1);
}

/// Detached, a session's chain store is still read; a send that lists the room is `MatrixDetached`.
#[tokio::test(flavor = "multi_thread")]
async fn chain_store_read_while_detached() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, _) = attach(&w);
    let room = invited_room(&server, BOB);
    let s = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&room), chain_entry(HOME)], &[]),
    )
    .await;
    let ep = in_use(&w, &s).await;
    w.pq.join_room(&ep).await.unwrap();
    w.pq.detach_matrix();
    let hint = w.app.pqchat_hint(s.k.clone()).unwrap();
    let m = sealed(&w, &w.bob, &s.e, &s.k, 0, r#"{"body":"m","type":"text"}"#).await;
    w.net.answer(
        HOME,
        "IPqChat.storedRange",
        json!({"hint": hex(&hint), "offset": "0", "limit": "16"}),
        json!({"0": [hex(&m.payload)]}),
    );
    let st: StoreEntry = serde_json::from_value(chain_entry(HOME)).unwrap();
    assert_eq!(w.pq.read_chain_store(&ep, &st).await.unwrap(), 1);
    assert_eq!(
        code(
            w.pq.send_content(&sref(&s.e), &me(&w.alice), &txt("x"), None, &opts(&w))
                .await
        ),
        "MatrixDetached"
    );
}

/// A contact card (UA-7 §14 O7) binds its Matrix id to its UA once the SDK verifies it for that UA (V1 on the registry);
/// a forged one (another UA's key) binds nothing (`CardRefused`), nor does a card without a Matrix id; invites follow.
#[tokio::test(flavor = "multi_thread")]
async fn card_binds_its_matrix_id() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, _) = attach(&w);
    let card = |a: &Acc, id: &str| {
        let (app, key, id) = (w.app.clone(), a.key.clone(), id.to_string());
        async move { app.prepare_pqchat_card(key, 1, id).await?.sign().await }
    };
    let b = card(&w.bob, BOB).await.unwrap();
    assert!(w.pq.add_card(CHAIN, &b.card, &b.sig).await.unwrap());
    assert_eq!(w.pq.matrix_ids_of(&w.bob.ua).unwrap(), [BOB]);
    let none = card(&w.alice, "").await.unwrap();
    assert!(!w.pq.add_card(CHAIN, &none.card, &none.sig).await.unwrap());
    // carol's card, signed by bob's key
    let by_bob = card(&w.bob, "@mallory:fake.local").await.unwrap();
    let forged = PqChatCard {
        ua: w.carol.ua.clone(),
        ..by_bob.card.clone()
    };
    assert_eq!(
        code(w.pq.add_card(CHAIN, &forged, &by_bob.sig).await),
        "CardRefused"
    );
    assert!(w.pq.matrix_ids_of(&w.carol.ua).unwrap().is_empty());
    let (room, ep) = alice_creates(
        &w,
        &[&w.bob, &w.carol],
        &[(&w.bob, BOB), (&w.carol, "@mallory:fake.local")],
        1,
    )
    .await;
    let s = sref(&ep.epoch);
    let ep = w.pq.use_epoch(&s, ep).await.unwrap();
    complete(&w.net, &ep.epoch.id, true);
    let r = w.pq.sync_room(&s, &ep, None, &me(&w.alice)).await.unwrap();
    assert_eq!(
        (r.invited, r.unbound),
        (vec![w.bob.ua.clone()], vec![w.carol.ua.clone()])
    );
    assert!(server.is_invited(&room, BOB));
    assert!(!server.is_invited(&room, "@mallory:fake.local"));
}

/// A card binds the Matrix id it asserts, no other: an epoch mapping its UA to another id leaves that UA unbound (not
/// invited); the same UA mapped to the card's id is invited (the control).
#[tokio::test(flavor = "multi_thread")]
async fn card_binds_only_its_own_matrix_id() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, _) = attach(&w);
    let c = w
        .app
        .prepare_pqchat_card(w.carol.key.clone(), 1, CAROL.into())
        .await
        .unwrap()
        .sign()
        .await
        .unwrap();
    assert!(w.pq.add_card(CHAIN, &c.card, &c.sig).await.unwrap());
    for (nonce, claimed, bound) in [(1, "@carol2:fake.local", false), (2, CAROL, true)] {
        let (room, ep) = alice_creates(&w, &[&w.carol], &[(&w.carol, claimed)], nonce).await;
        let s = sref(&ep.epoch);
        let ep = w.pq.use_epoch(&s, ep).await.unwrap();
        complete(&w.net, &ep.epoch.id, true);
        let r = w.pq.sync_room(&s, &ep, None, &me(&w.alice)).await.unwrap();
        assert_eq!(r.invited.is_empty(), !bound, "{claimed}");
        assert_eq!(r.unbound.is_empty(), bound, "{claimed}");
        assert_eq!(server.is_invited(&room, claimed), bound, "{claimed}");
    }
}

/// A room the account had joined before (a fresh device's) is used once its members check against the epoch: each one,
/// joined or invited, the account's own id or one the epoch's `sealedInfo` maps to a member of that epoch; its history is
/// then read under the session without a join. A room holding any other member is not used: a stranger joined, a
/// stranger invited, or an id mapped to a UA the epoch does not list.
#[tokio::test(flavor = "multi_thread")]
async fn room_joined_before_used_when_its_members_check() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (server, c) = attach(&w);
    let map = [(&w.alice, ALICE), (&w.bob, BOB)];
    let old = server.ordinary(BOB, &[ALICE], false);
    let s = signed(
        &w,
        &w.bob,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.bob],
        info(vec![room_entry(&old)], &map),
    )
    .await;
    let e = ev_of(&w, &w.bob, &s, 0, BOB).await;
    server.post_as(&old, BOB, serde_json::from_slice(&e.content).unwrap());
    let ep = in_use(&w, &s).await;
    assert_eq!(w.pq.join_room(&ep).await.unwrap(), RoomUse::Bound);
    assert!(c.calls_of("join").is_empty());
    assert_eq!(w.pq.read_room(&old).await.unwrap(), 1);
    // each room holds one member the epoch does not check
    let joined = server.ordinary(BOB, &[ALICE, CAROL], false);
    let invited = server.ordinary(BOB, &[ALICE], false);
    server
        .rooms
        .lock()
        .unwrap()
        .get_mut(&invited)
        .unwrap()
        .invited
        .insert(CAROL.into());
    let unlisted = server.ordinary(BOB, &[ALICE, CAROL], false);
    let cases = [
        (2, joined, &map[..]),
        (3, invited, &map[..]),
        (
            4,
            unlisted,
            &[(&w.alice, ALICE), (&w.bob, BOB), (&w.carol, CAROL)][..],
        ),
    ];
    for (nonce, room, m) in cases {
        let s = signed(
            &w,
            &w.bob,
            None,
            nonce,
            &[&w.alice, &w.bob],
            &[&w.bob],
            info(vec![room_entry(&room)], m),
        )
        .await;
        let ep = in_use(&w, &s).await;
        assert_eq!(
            w.pq.join_room(&ep).await.unwrap(),
            RoomUse::Refused(RoomRefusal::JoinedBefore),
            "nonce {nonce}"
        );
        assert_eq!(w.pq.room_session(&room).unwrap(), None);
    }
    assert!(c.calls_of("join").is_empty());
}
