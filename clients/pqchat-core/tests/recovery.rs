// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T9 on the SDK's fake chain and the fake Matrix server (CLI-PQC-08, CLI-PQC-09, CLI-PQC-10, CLI-PQC-13, K11, K18,
//! K25): a fresh store finds every session from the factory's index and `sessionsOf` on each listed instance, de-duplicated,
//! with progress; a session shown only when its home is listed, holds the equal record and has epochs; a pending session
//! makes no store read, join, receipt or write and its wrap is opened only on the user's look; after acceptance the latest
//! messages of the chain store and the room; a session the UA left declined; a fresh device asked again (O6 (a)); the device
//! id bound to the app's anchor; events kept while the seed is locked, across a restart, and read at unlock, none dropped;
//! a trusted read never answered by a discovered endpoint alone. Each negative beside its positive control.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::epochs::*;
use common::matrix::{Client, Server};
use common::sdk::fake_chain::{fake, serve};
use common::sdk::*;
use pqchat_core::consent::Consent;
use pqchat_core::content::Content;
use pqchat_core::matrix::{self, MatrixIn, RoomEvent, RoomUse, LOCKED_MAX};
use pqchat_core::model::{hex, Epoch};
use pqchat_core::net::{Net, SdkNet};
use pqchat_core::session::StoreEntry;
use pqchat_core::{Event, MemoryStore, PqChat};
use serde_json::{json, Value};
use std::sync::Arc;

const ALICE: &str = "@alice:fake.local";
const BOB: &str = "@bob:fake.local";

/// A `sealedInfo` handle's name.
fn name_of(i: &scaas_sdk::SecretBytes) -> String {
    i.with(|b| serde_json::from_slice::<pqchat_core::session::Info>(b))
        .unwrap()
        .name
}

fn txt(s: &str) -> Content {
    Content::Text {
        media_type: None,
        body: s.into(),
    }
}

/// A fresh crate over `store` on the world's scope and port.
fn device(w: &World, store: Arc<MemoryStore>) -> Arc<PqChat> {
    PqChat::with_net(w.app.clone(), w.net.clone(), store, conf())
}

fn info_of(contract: &str, version: u64) -> Value {
    json!({"addr": contract, "creatorId": hex(&[0; 32]), "contractClass": "3", "kind": "0",
        "version": version.to_string(), "createdBlock": "1", "createdAt": "1"})
}

/// The factory's index: `entries` (instance, version) in one page.
fn index(w: &World, entries: &[(&str, u64)]) {
    let page: Vec<Value> = entries.iter().map(|(c, v)| info_of(c, *v)).collect();
    w.net.answer(
        FACTORY,
        "IOpenFactory.contractsPage",
        json!({"contractClass": "3", "from": "0", "n": "64"}),
        json!({"page": page, "total": entries.len().to_string()}),
    );
}

/// `ua`'s session ids at `contract`.
fn sessions_at(w: &World, contract: &str, ua: &str, ids: &[&str]) {
    w.net.answer(
        contract,
        "IPqChat.sessionCount",
        json!({ "ua": ua }),
        json!({"0": ids.len().to_string()}),
    );
    w.net.answer(
        contract,
        "IPqChat.sessionsOf",
        json!({"ua": ua, "offset": "0", "limit": "64"}),
        json!({ "0": ids }),
    );
}

/// `s` at home with `epochs` epochs, its latest `latest`.
fn at_home(w: &World, s: &Epoch, epochs: u64, latest: &str) {
    w.net.answer(
        HOME,
        "IPqChat.epochCount",
        json!({"sessionId": s.session_id}),
        json!({"0": epochs.to_string()}),
    );
    w.net.answer(
        HOME,
        "IPqChat.latestEpoch",
        json!({"sessionId": s.session_id}),
        json!({ "epochId": latest }),
    );
}

/// `e`'s `sessionOf` at `contract`, naming `home` (put_record's form with another home).
fn session_at(w: &World, contract: &str, e: &Epoch, home: &str, sig_hash: &str) {
    let members: Vec<Value> = e
        .members
        .iter()
        .map(|m| json!({"ua": m.ua, "keyId": m.key_id.to_string(), "via": m.via}))
        .collect();
    let s = json!({"creator": e.author, "nonce": e.nonce.to_string(), "homeChain": hex(&[7; 32]),
        "homeChatContract": home, "groupMode": "0", "pathRefreshBound": "0", "confirmTag": format!("0x{}", "00".repeat(32)), "admins": e.admins, "members": members, "wrapHashes": e.wrap_hashes,
        "sealedInfo": hex(&e.sealed_info)});
    w.net.answer(
        contract,
        "IPqChat.sessionOf",
        json!({"sessionId": e.id}),
        json!({"s": s, "sigHash": sig_hash}),
    );
}

/// alice's session with bob over `stores` at HOME, one epoch, discoverable at HOME.
async fn found_one(w: &World, stores: Vec<Value>) -> Signed {
    let s = signed(
        w,
        &w.alice,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.alice],
        info(stores, &[]),
    )
    .await;
    index(w, &[(HOME, 1)]);
    sessions_at(w, HOME, &w.bob.ua, &[&s.e.id]);
    sessions_at(w, HOME, &w.alice.ua, &[&s.e.id]);
    at_home(w, &s.e, 1, &s.e.id);
    s
}

/// A fresh store finds the session through the factory's index and `sessionsOf` on each listed instance (an instance of
/// version 0 not read), repeated entries de-duplicated, with progress per instance; nothing opened, nothing written.
#[tokio::test(flavor = "multi_thread")]
async fn finds_every_session_once() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let s = signed(
        &w,
        &w.alice,
        None,
        1,
        &[&w.alice, &w.bob],
        &[&w.alice],
        info(vec![chain_entry(HOME)], &[]),
    )
    .await;
    put_record(&w.net, REPLICA, &s.e);
    index(&w, &[(HOME, 1), (UNLISTED, 0), (REPLICA, 1)]);
    sessions_at(&w, HOME, &w.bob.ua, &[&s.e.id, &s.e.id]);
    sessions_at(&w, REPLICA, &w.bob.ua, &[&s.e.id]);
    sessions_at(&w, UNLISTED, &w.bob.ua, &[&s.e.id]);
    at_home(&w, &s.e, 1, &s.e.id);
    let bob = device(&w, Arc::new(MemoryStore::new()));
    let found = bob.sessions(&me(&w.bob)).await.unwrap();
    let ids: Vec<_> = found.iter().map(|f| &f.s).collect();
    assert_eq!(found.len(), 1, "{ids:?}");
    assert_eq!(
        (found[0].consent, &found[0].latest, found[0].epochs),
        (Consent::Pending, &s.e.id, 1)
    );
    assert_eq!(found[0].s, sref(&s.e));
    let unlisted_reads = w
        .net
        .reads
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.0 == UNLISTED)
        .count();
    assert_eq!(unlisted_reads, 0);
    let progress: Vec<Event> = bob
        .events()
        .into_iter()
        .filter(|e| matches!(e, Event::RecoveryProgress { .. }))
        .collect();
    assert_eq!(progress.len(), 2);
    assert_eq!(
        progress[1],
        Event::RecoveryProgress {
            chain: CHAIN.into(),
            instances_done: 2,
            instances: 2,
            found: 1
        }
    );
    assert_eq!((bob.unwrap_calls(), w.net.writes()), (0, 0));
}

/// Shown only when the home is listed and reachable, holds the equal record and has an epoch (K25): a record whose home is
/// not listed, one unequal to the home's, one with no epoch at home not shown; the equal one is.
#[tokio::test(flavor = "multi_thread")]
async fn shown_only_with_a_listed_equal_home() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let mut sids = vec![];
    let mut ss = vec![];
    for n in 1..=4 {
        let s = signed(
            &w,
            &w.alice,
            None,
            n,
            &[&w.alice, &w.bob],
            &[&w.alice],
            info(vec![chain_entry(HOME)], &[]),
        )
        .await;
        at_home(&w, &s.e, 1, &s.e.id);
        sids.push(s.e.id.clone());
        ss.push(s);
    }
    // 1: its record at REPLICA names UNLISTED as home (unlisted there, its own record equal)
    session_at(&w, REPLICA, &ss[0].e, UNLISTED, &ss[0].e.sig_hash);
    session_at(&w, UNLISTED, &ss[0].e, UNLISTED, &ss[0].e.sig_hash);
    list(&w.net, UNLISTED, 3, 0);
    // everything else answered there, so only the listing keeps it out
    let e0 = &ss[0].e;
    w.net.answer(
        UNLISTED,
        "IPqChat.epochCount",
        json!({"sessionId": e0.id}),
        json!({"0": "1"}),
    );
    w.net.answer(
        UNLISTED,
        "IPqChat.latestEpoch",
        json!({"sessionId": e0.id}),
        json!({ "epochId": e0.id }),
    );
    w.net.answer(
        UNLISTED,
        "IPqChat.leftIn",
        json!({"epochId": e0.id, "member": w.bob.ua}),
        json!({"0": false}),
    );
    // 2: REPLICA's record unequal to the home's
    session_at(&w, REPLICA, &ss[1].e, HOME, &hex(&[0x77; 32]));
    // 3: no epoch at home
    at_home(&w, &ss[2].e, 0, &ss[2].e.id);
    put_record(&w.net, REPLICA, &ss[2].e);
    // 4: equal at REPLICA: shown
    put_record(&w.net, REPLICA, &ss[3].e);
    index(&w, &[(REPLICA, 1)]);
    let ids: Vec<&str> = sids.iter().map(String::as_str).collect();
    sessions_at(&w, REPLICA, &w.bob.ua, &ids);
    let bob = device(&w, Arc::new(MemoryStore::new()));
    let found = bob.sessions(&me(&w.bob)).await.unwrap();
    let shown: Vec<&str> = found.iter().map(|f| f.s.session_id.as_str()).collect();
    assert_eq!(shown, [sids[3].as_str()]);
    assert_eq!(found[0].s.home, HOME);
}

/// A transport that refuses to hold the room a pending session names (scaas-matrix: a room the account uses as a Matrix room)
/// makes the preview fail closed (`MatrixRoom`); the control holds and previews.
#[tokio::test(flavor = "multi_thread")]
async fn preview_fails_closed_when_the_hold_is_refused() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let server = Server::new();
    let room = server.ordinary(ALICE, &[], false);
    let s = found_one(&w, vec![room_entry(&room), chain_entry(HOME)]).await;
    let bob = device(&w, Arc::new(MemoryStore::new()));
    let c = Client::new(&server, BOB);
    bob.attach_matrix(c.clone());
    let sr = sref(&s.e);
    c.refuse_hold
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(code(bob.preview(&sr, &me(&w.bob)).await), "MatrixRoom");
    c.refuse_hold
        .store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(bob.preview(&sr, &me(&w.bob)).await.is_ok());
    assert!(c.held.lock().unwrap().contains(&room));
    // a room the account is already joined to (the user's own session seen from a fresh device) is not held: no refusal
    let joined = server.ordinary(ALICE, &[BOB], false);
    let s2 = found_one(&w, vec![room_entry(&joined), chain_entry(HOME)]).await;
    c.refuse_hold
        .store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(bob.preview(&sref(&s2.e), &me(&w.bob)).await.is_ok());
    assert!(!c.calls_of("hold_invite").contains(&joined));
}

/// A pending session makes no store read, no join, no receipt and no write; its wrap is opened only on the user's look,
/// which holds its room's invite; declining writes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn pending_session_reaches_nothing() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let server = Server::new();
    let room = server.ordinary(ALICE, &[], false);
    let s = found_one(&w, vec![room_entry(&room), chain_entry(HOME)]).await;
    let bob = device(&w, Arc::new(MemoryStore::new()));
    let c = Client::new(&server, BOB);
    bob.attach_matrix(c.clone());
    let found = bob.sessions(&me(&w.bob)).await.unwrap();
    assert_eq!(found[0].consent, Consent::Pending);
    assert_eq!(bob.unwrap_calls(), 0);
    let sr = sref(&s.e);
    assert_eq!(
        code(
            bob.send_content(&sr, &me(&w.bob), &txt("x"), None, &opts(&w))
                .await
        ),
        "SessionPending"
    );
    let ep = s.open();
    let st: StoreEntry = serde_json::from_value(chain_entry(HOME)).unwrap();
    assert_eq!(code(bob.read_chain_store(&ep, &st).await), "SessionPending");
    assert_eq!(code(bob.join_room(&ep).await), "SessionPending");
    let e = ev(&w, &w.alice, &s, 0).await;
    assert_eq!(bob.matrix_event(&room, e).await.unwrap(), MatrixIn::Ignored);
    // the user's look: the own wrap and sealedInfo opened locally, the invite held, nothing else
    let p = bob.preview(&sr, &me(&w.bob)).await.unwrap();
    assert_eq!(
        (
            name_of(&p.info).as_str(),
            p.creator.as_str(),
            p.chain_stores,
            p.matrix
        ),
        ("t8", w.alice.ua.as_str(), 1, true)
    );
    assert_eq!(bob.unwrap_calls(), 1);
    assert_eq!(c.calls_of("hold_invite"), std::slice::from_ref(&room));
    assert_eq!(c.acting(), 0);
    bob.decline(&sr).unwrap();
    assert_eq!(
        bob.consent(&sr.session_id).unwrap(),
        Some(Consent::Declined)
    );
    assert_eq!(w.net.writes(), 0);
    assert_eq!(w.net.reads_of("IPqChat.storedRange"), 0);
    assert!(server.events_of(&room).is_empty());
}

/// After an explicit `accept`: the latest messages from the chain store and the room's history, the room joined.
#[tokio::test(flavor = "multi_thread")]
async fn accepted_reads_the_stores_and_the_room() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let server = Server::new();
    let room = server.ordinary(ALICE, &[], false);
    server
        .rooms
        .lock()
        .unwrap()
        .get_mut(&room)
        .unwrap()
        .invited
        .insert(BOB.into());
    let s = found_one(&w, vec![room_entry(&room), chain_entry(HOME)]).await;
    let m0 = sealed(
        &w,
        &w.alice,
        &s.e,
        &s.k,
        0,
        r#"{"body":"chain","type":"text"}"#,
    )
    .await;
    let hint = w.app.pqchat_hint(s.k.clone()).unwrap();
    w.net.answer(
        HOME,
        "IPqChat.storedRange",
        json!({"hint": hex(&hint), "offset": "0", "limit": "16"}),
        json!({"0": [hex(&m0.payload)]}),
    );
    for c in 1..3 {
        server.post_as(
            &room,
            ALICE,
            serde_json::from_slice(&ev(&w, &w.alice, &s, c).await.content).unwrap(),
        );
    }
    let bob = device(&w, Arc::new(MemoryStore::new()));
    let c = Client::new(&server, BOB);
    bob.attach_matrix(c.clone());
    bob.sessions(&me(&w.bob)).await.unwrap();
    let sr = sref(&s.e);
    bob.accept(&sr, true).unwrap();
    let o = bob.open_session(&sr, &me(&w.bob)).await.unwrap();
    assert_eq!((o.room, o.shown), (RoomUse::Bound, 3));
    assert_eq!(bob.timeline(&sr.session_id).len(), 3);
    assert_eq!(c.calls_of("join"), [room]);
}

/// A session the UA left is declined on recovery (K11), never accepted; one it is still in is pending.
#[tokio::test(flavor = "multi_thread")]
async fn left_session_declined() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let s = found_one(&w, vec![chain_entry(HOME)]).await;
    let bob = device(&w, Arc::new(MemoryStore::new()));
    assert_eq!(
        bob.sessions(&me(&w.bob)).await.unwrap()[0].consent,
        Consent::Pending
    );
    w.net.answer(
        HOME,
        "IPqChat.leftIn",
        json!({"epochId": s.e.id, "member": w.bob.ua}),
        json!({"0": true}),
    );
    let bob = device(&w, Arc::new(MemoryStore::new()));
    assert_eq!(
        bob.sessions(&me(&w.bob)).await.unwrap()[0].consent,
        Consent::Declined
    );
    assert_eq!(
        code(
            bob.send_content(&sref(&s.e), &me(&w.bob), &txt("x"), None, &opts(&w))
                .await
        ),
        "SessionPending"
    );
}

/// O6 (a): a fresh device asks again, even for a session the UA created; the device that accepted keeps its consent.
#[tokio::test(flavor = "multi_thread")]
async fn fresh_device_asks_again() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let s = found_one(&w, vec![chain_entry(HOME)]).await;
    w.pq.accept(&sref(&s.e), true).unwrap();
    let kept = w.pq.sessions(&me(&w.alice)).await.unwrap();
    assert_eq!(
        (kept[0].consent, kept[0].info.as_deref().map(name_of)),
        (Consent::Accepted, Some("t8".to_string()))
    );
    let fresh = device(&w, Arc::new(MemoryStore::new()));
    let f = fresh.sessions(&me(&w.alice)).await.unwrap();
    assert_eq!(
        (f[0].consent, f[0].info.as_deref().map(name_of)),
        (Consent::Pending, None)
    );
}

/// The device id (K18): kept under the same anchor; a store copied to another instance with a different anchor, or no
/// anchor, makes a new one; a fresh store makes its own; no `(device, counter)` is used twice.
#[tokio::test(flavor = "multi_thread")]
async fn device_bound_to_its_anchor() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let d1 = w.pq.start_device(Some("anchor-a".into())).unwrap();
    assert_eq!(w.pq.start_device(Some("anchor-a".into())).unwrap(), d1);
    assert_eq!(w.pq.device().unwrap(), d1);
    let copied = device(&w, Arc::new(w.store.copy()));
    assert_eq!(
        copied.device().unwrap(),
        d1,
        "the copy holds the id until its start"
    );
    let d2 = copied.start_device(Some("anchor-b".into())).unwrap();
    assert_ne!(d2, d1);
    let missing = device(&w, Arc::new(w.store.copy()));
    let d3 = missing.start_device(None).unwrap();
    assert!(d3 != d1 && d3 != d2);
    assert_ne!(missing.start_device(None).unwrap(), d3);
    let fresh = device(&w, Arc::new(MemoryStore::new()));
    assert!(![d1.clone(), d2.clone()].contains(&fresh.device().unwrap()));
    // sends of the original and the copy under one epoch: distinct chains, counter 0 each
    let s = found_one(&w, vec![chain_entry(HOME)]).await;
    let mut ids = vec![];
    for pq in [&w.pq, &copied] {
        pq.accept(&sref(&s.e), true).unwrap();
        pq.use_epoch(&sref(&s.e), s.open()).await.unwrap();
        let out = pq
            .seal(&sref(&s.e), &me(&w.alice), &txt("x"), None)
            .await
            .unwrap();
        ids.push((out.sealed.record.device.clone(), out.sealed.record.counter));
    }
    assert_eq!(ids, [(d1, 0), (d2, 0)]);
}

/// Events handed in while the seed is locked are kept (every one, an unbound room's too), across a locked restart, up to
/// the bound per room and then the room marked; nothing read, sent or answered; at unlock every one is read, the rest from
/// the room's history, none dropped.
#[tokio::test(flavor = "multi_thread")]
async fn locked_events_kept_and_read_at_unlock() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let server = Server::new();
    let room = server.ordinary(ALICE, &[], false);
    server
        .rooms
        .lock()
        .unwrap()
        .get_mut(&room)
        .unwrap()
        .invited
        .insert(BOB.into());
    let s = found_one(&w, vec![room_entry(&room)]).await;
    let store = Arc::new(MemoryStore::new());
    let bob = device(&w, store.clone());
    let c = Client::new(&server, BOB);
    bob.attach_matrix(c.clone());
    bob.sessions(&me(&w.bob)).await.unwrap();
    bob.accept(&sref(&s.e), false).unwrap();
    assert_eq!(
        bob.open_session(&sref(&s.e), &me(&w.bob))
            .await
            .unwrap()
            .room,
        RoomUse::Bound
    );
    let total = LOCKED_MAX as u64 + 4;
    let mut evs = vec![];
    for n in 0..total {
        let e = ev(&w, &w.alice, &s, n).await;
        server.post_as(&room, ALICE, serde_json::from_slice(&e.content).unwrap());
        evs.push(e);
    }
    bob.locked();
    let (reads, calls) = (
        w.net.reads.lock().unwrap().len(),
        c.calls.lock().unwrap().len(),
    );
    for e in evs.iter().take(LOCKED_MAX - 1) {
        assert_eq!(
            bob.matrix_event(&room, e.clone()).await.unwrap(),
            MatrixIn::Kept
        );
    }
    let other = server.ordinary(ALICE, &[BOB], false);
    assert_eq!(
        bob.matrix_event(&other, evs[0].clone()).await.unwrap(),
        MatrixIn::Kept
    );
    // a restart with the seed still locked: the app tells the new crate, which keeps on
    drop(bob);
    let bob = device(&w, store.clone());
    bob.attach_matrix(c.clone());
    bob.locked();
    for e in evs.iter().skip(LOCKED_MAX - 1) {
        assert_eq!(
            bob.matrix_event(&room, e.clone()).await.unwrap(),
            MatrixIn::Kept
        );
    }
    assert_eq!(bob.kept(&room).unwrap(), (LOCKED_MAX, true));
    assert_eq!(bob.kept(&other).unwrap(), (1, false));
    assert_eq!(w.net.reads.lock().unwrap().len(), reads);
    assert_eq!(c.calls.lock().unwrap().len(), calls);
    assert_eq!(w.net.writes(), 0);
    let shown = bob.resume(&me(&w.bob)).await.unwrap();
    assert_eq!(shown as u64, total);
    assert_eq!(bob.timeline(&s.e.session_id).len() as u64, total);
    assert_eq!(bob.kept(&room).unwrap(), (0, false));
    assert!(c.calls_of("send_event").is_empty());
    assert_eq!(w.net.writes(), 0);
}

/// A trusted read (`latestEpoch`) is never answered by a discovered endpoint alone (CLI-PQC-13): with a named one beside
/// it, the named one's answer; with the discovered one alone, refused; a plain read (`sessionCount`) is served by it.
#[tokio::test(flavor = "multi_thread")]
async fn stale_latest_epoch_from_a_discovered_endpoint_refused() {
    let _one = ONE.lock().await;
    let (stale, good) = (fake(), fake());
    let sid = [0x51u8; 32];
    for (c, latest) in [(&stale, [0x0du8; 32]), (&good, [0x0eu8; 32])] {
        answer(
            c,
            HOME,
            "latestEpoch(bytes32)",
            &sid,
            hex(&latest)[2..].to_string(),
        );
        answer(c, HOME, "sessionCount(bytes32)", &sid, w(3));
    }
    let (us, ug) = (serve(stale.clone()).await, serve(good.clone()).await);
    let genesis = stale.lock().unwrap().genesis.clone();
    let read = |sdk: Arc<scaas_sdk::Sdk>, item: &'static str| async move {
        let app = pqchat_core::scope(&sdk).unwrap();
        let net = SdkNet { sdk, app };
        net.read(CHAIN, HOME, item, json!({ "sessionId": hex(&sid) }))
            .await
    };
    let (both, _) = sdk_on(vec![discovered(us.clone()), named(ug)], genesis.clone()).await;
    let v = read(both, "IPqChat.latestEpoch").await.unwrap();
    assert_eq!(v["epochId"], hex(&[0x0e; 32]));
    let (alone, _) = sdk_on(vec![discovered(us)], genesis).await;
    let plain = SdkNet {
        sdk: alone.clone(),
        app: pqchat_core::scope(&alone).unwrap(),
    };
    let n = plain
        .read(
            CHAIN,
            HOME,
            "IPqChat.sessionCount",
            json!({ "ua": hex(&sid) }),
        )
        .await
        .unwrap();
    assert_eq!(n["0"], "3");
    drop(plain);
    assert_eq!(
        code(read(alone, "IPqChat.latestEpoch").await),
        "NoTrustedEndpoint"
    );
}

/// `from`'s message at `counter` under `s` as alice's Matrix event.
async fn ev(w: &World, from: &Acc, s: &Signed, counter: u64) -> RoomEvent {
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
        sender: ALICE.into(),
        content: matrix::event(&m.hint, &m.env).to_string().into_bytes(),
    }
}
