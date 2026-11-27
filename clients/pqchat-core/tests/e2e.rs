// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T11 (CLI-PQC-12): the real-crypto end-to-end run, local (gate `pqc-e2e`; `#[ignore]`: anvil, forge, cast,
//! smartcontracts/evm/lib and Docker). Real keys, real wraps, real ciphertexts: every honest write through `pqchat-core` over
//! the SDK into `anvil --enable-tx-gas-limit` after its positive control; the Matrix store a Synapse in Docker; writes an
//! honest client refuses only through the hostile harness (`tests/hostile/`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;
use common::{called, confirmed};
#[path = "e2e/harness.rs"]
mod harness;
#[path = "hostile/e2e.rs"]
mod hostile;
#[path = "e2e/matrix.rs"]
mod matrix;

use matrix::{LastN, Synapse, SynapseWitness};
use pqchat_core::matrix::MatrixTransport;

/// The test transport over Synapse passes T8's conformance test (CLI-PQC-05, K9).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs Docker and the Synapse image (gate pqc-e2e)"]
async fn e2e_matrix_conformance() {
    let s = Synapse::start().await;
    s.register("alice", false);
    s.register("witness", false);
    let t = s.login("alice").await;
    let w = SynapseWitness {
        s: &s,
        other: s.login("witness").await,
    };
    assert_eq!(pqchat_core::matrix::conformance(&t, &w).await, Ok(()));
    // the witness's positive control: the other account's signals in a room are seen
    let room = w.other.create_room().await.unwrap();
    w.other
        .send_event(&room, pqchat_core::matrix::event(&[1; 8], &[2; 33]))
        .await
        .unwrap();
    w.other.signals(&room).await;
    let seen = s.seen_of(&room, &w.other.user);
    assert!(
        seen.receipts > 0 && seen.read_markers > 0 && seen.typing > 0,
        "the witness sees no signal: {seen:?}"
    );
    println!("[matrix] the HTTP transport conforms on {}", matrix::IMAGE);
}

use common::chain::CHAIN;
use harness::{selector, World, DEPTH, DISC, FINAL};
use pqchat_core::consent::Consent;
use pqchat_core::content::Content;
use pqchat_core::matrix::RoomUse;
use pqchat_core::message::{Incoming, OpenEpoch};
use pqchat_core::net::Net;
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{CreateSession, Info, Me, Rekey, StoreEntry};
use pqchat_core::stores::{Delivery, SendOpts};
use pqchat_core::topics::{At, List, RefFault, RefState, Vote};
use pqchat_core::{DropReason, MemoryStore, PqChat};
use scaas_sdk::pqchat_records::PqEntryRef;
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::Arc;

fn txt(s: &str) -> Content {
    Content::Text {
        media_type: None,
        body: s.into(),
    }
}

fn uas(v: &[&Me]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|m| m.ua.clone()).collect();
    v.sort();
    v
}

fn opts(w: &World, post: bool) -> SendOpts {
    SendOpts {
        payer: w.l.payer.clone(),
        post,
        post_cost_confirmed: false,
    }
}

fn create(
    w: &World,
    by: &Me,
    nonce: u64,
    members: &[&Me],
    stores: Vec<StoreEntry>,
    name: &str,
) -> CreateSession {
    CreateSession {
        me: by.clone(),
        chain: CHAIN.into(),
        home: w.l.home.clone(),
        nonce,
        members: uas(members),
        admins: vec![],
        info: Info {
            stores,
            name: name.into(),
            topic: "plan T11".into(),
            matrix: Default::default(),
        },
        payer: w.l.payer.clone(),
    }
}

/// The creator's own epoch put to use: its record at home with the key it drew, its stores confirmed, the spend consented.
async fn creator_uses(
    w: &World,
    pq: &Arc<PqChat>,
    sid: &str,
    eid: &str,
    k: Arc<scaas_sdk::app_core::AppKey>,
) -> Arc<OpenEpoch> {
    let s = w.sref(sid);
    let e = pq
        .record_at(CHAIN, &w.l.home, sid, eid)
        .await
        .unwrap()
        .unwrap();
    let ep = pq
        .use_epoch(
            &s,
            OpenEpoch {
                chain: CHAIN.into(),
                epoch: e,
                k,
            },
        )
        .await
        .unwrap();
    pq.confirm_stores(&ep).unwrap();
    pq.consent_chain_spend(sid, true).unwrap();
    ep
}

/// `ep`'s `sealedInfo`, read from its handle.
fn info_of(pq: &PqChat, ep: &OpenEpoch) -> pqchat_core::session::Info {
    pq.info(ep)
        .unwrap()
        .with(|b| serde_json::from_slice(b))
        .unwrap()
}

fn texts(pq: &PqChat, sid: &str) -> Vec<(String, Content)> {
    pq.timeline(sid)
        .into_iter()
        .map(|m| (m.sender, m.content.with(Content::parse).content))
        .collect()
}

/// The plan's steps in their order on one chain and one homeserver (CLI-PQC-12): 1:1 session with the Matrix room and the
/// chain store, send and decrypt, a Matrix-only 1:1 session (B invited by its contact card's id), a group rekey with removal
/// (and the removed member's writes refused by the contract through the hostile harness), a fresh device (S2 from the room's
/// history), C's competing child at R1, replicas, a public topic, the fixtures of the plan's mutants, and the long chain.
#[test]
#[ignore = "needs anvil, forge, cast, smartcontracts/evm/lib, Docker and the Synapse image (gate pqc-e2e)"]
fn e2e_run() {
    // the run's future outgrows a test thread's stack in a debug build: its own thread and runtime, larger stacks
    std::thread::Builder::new()
        .stack_size(256 << 20)
        .spawn(|| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(32 << 20)
                .enable_all()
                .build()
                .unwrap()
                .block_on(run())
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn run() {
    let w = world_and_log().await;
    let hs = Synapse::start().await;
    for u in ["alice", "bob", "carol"] {
        hs.register(u, false);
    }
    let (ta, tb) = (
        Arc::new(hs.login("alice").await),
        Arc::new(hs.login("bob").await),
    );
    let (a, b, c) = (w.a.clone(), w.b.clone(), w.c.clone());
    let h = w.chain_store(&w.l.home);

    // --- mutant 1's fixture: B's KEM key rotated to version 1 before S1 (the registration's is version 0), by the SDK
    let acc = w.l.sdk.account();
    let wr = acc
        .prepare_set_kem_key(b.key.clone(), CHAIN.into(), 1, w.l.payer.clone())
        .await
        .unwrap()
        .expect("version 1 not stored yet");
    let q = acc.quote_registry_write(wr.clone()).await.unwrap();
    w.follow_landed(acc.submit_registry_write(wr, q).await.unwrap())
        .await;

    // --- 1:1 session S1: the Matrix room and H's chain store
    let store_a = Arc::new(MemoryStore::new());
    let pa = w.device_with(store_a.clone());
    pa.start_device(Some("a-1".into())).unwrap();
    pa.attach_matrix(ta.clone());
    let room = pa.create_room().await.unwrap();
    w.net.clear();
    let mut req = create(
        &w,
        &a,
        1,
        &[&b],
        vec![StoreEntry::Matrix { room: room.clone() }, h.clone()],
        "s1",
    );
    req.info.matrix = BTreeMap::from([
        (a.ua.clone(), ta.user.clone()),
        (b.ua.clone(), tb.user.clone()),
    ]);
    let s1b = confirmed(&pa, pa.create(req).await).await.unwrap();
    let kem_reads = w
        .net
        .read_items()
        .iter()
        .filter(|i| **i == "IUARegistry.kemKeyOf")
        .count();
    assert!(
        kem_reads >= 2,
        "the wraps' keys from kemKeyOf (trusted): {kem_reads}"
    );
    let s1b = w.land_all(&pa, s1b).await;
    let sid1 = s1b.session_id.clone();
    let kb =
        |e: &pqchat_core::model::Epoch| e.members.iter().find(|m| m.ua == b.ua).unwrap().key_id;
    assert_eq!(kb(&s1b.epoch), 1, "A wraps to B's KEM version 1");
    let s1 = w.sref(&sid1);
    let ea1 = creator_uses(&w, &pa, &sid1, &sid1, s1b.k.clone()).await;
    // the creator invites only ids bound to their UA: B's is not (no contact card row, UA-7 §14 O7), so no invite
    let sync = pa.sync_room(&s1, &ea1, None, &a).await.unwrap();
    assert_eq!(
        (sync.invited.len(), sync.unbound.clone()),
        (0, vec![b.ua.clone()])
    );
    assert_eq!(ta.calls_of("invite"), 0);
    println!("[e2e] S1 {sid1}: room and H's chain store; B's Matrix id unbound, not invited");

    // B finds it from state, pending; nothing read from a store before accept
    let pb = w.device();
    let db1 = pb.start_device(Some("b-1".into())).unwrap();
    pb.attach_matrix(tb.clone());
    w.net.clear();
    let found = pb.sessions(&b).await.unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!((&found[0].s, found[0].consent), (&s1, Consent::Pending));
    let p = pb
        .preview(&s1, &b)
        .await
        .expect("mutant 1: B opens its S1 wrap at KEM version 1");
    assert!(p.matrix && p.chain_stores == 1 && p.creator == a.ua);
    assert_eq!(
        tb.calls.lock().unwrap().clone(),
        vec![format!("hold_invite {room} true")]
    );
    for it in ["IPqChat.storedRange", "IPqChat.messageAt"] {
        assert!(!w.net.read_items().contains(&it), "{it} read before accept");
    }
    // A sends a text to the room and the chain store, posted too
    let hello = txt("hello B, from A");
    let r = pa
        .send_content(&s1, &a, &hello, Some(1), &opts(&w, true))
        .await
        .unwrap();
    assert_eq!(r.stores[0].1, Delivery::Sent(String::new()));
    w.delivered(&r.stores[1].1).await;
    w.delivered(r.post.as_ref().unwrap()).await;
    // B accepts; the room cannot be joined without an invite, so B's client opens the session with Matrix detached
    pb.accept(&s1, true).unwrap();
    pb.detach_matrix();
    let ob = pb.open_session(&s1, &b).await.unwrap();
    assert_eq!(ob.shown, 1);
    let eb1 = ob.epoch.clone();
    // mutant 7's fixture: one record on two stores (the chain store and postMessage; the room has no peer, see T11's call)
    let posted = pb.posted(&w.l.home, 0, &eb1).await;
    assert_eq!(
        posted.err(),
        Some(DropReason::Duplicate),
        "mutant 7: duplicate"
    );
    assert_eq!(
        pb.dropped(&sid1),
        BTreeMap::from([(DropReason::Duplicate, 1)])
    );
    assert_eq!(texts(&pb, &sid1), vec![(a.ua.clone(), hello.clone())]);
    // B replies (the room refused: not bound on B's device); A decrypts it from the chain store
    pb.attach_matrix(tb.clone());
    let reply = txt("hello A, from B");
    let r = pb
        .send_content(&s1, &b, &reply, Some(2), &opts(&w, false))
        .await
        .unwrap();
    assert_eq!(r.stores[0].1, Delivery::Failed("MatrixRoom"));
    w.delivered(&r.stores[1].1).await;
    assert_eq!(pa.read_chain_store(&ea1, &h).await.unwrap(), 1);
    assert_eq!(
        texts(&pa, &sid1),
        vec![(a.ua.clone(), hello.clone()), (b.ua.clone(), reply.clone())]
    );
    // the room: A's event there, no receipt, read marker, typing or presence of either account
    let sa = hs.seen_of(&room, &ta.user);
    assert!(sa.joined && !sa.encrypted && sa.events == 1, "{sa:?}");
    assert_eq!(
        (sa.receipts, sa.read_markers, sa.typing, sa.presence),
        (0, 0, 0, 0)
    );
    let sb = hs.seen_of(&room, &tb.user);
    assert_eq!(
        (
            sb.joined,
            sb.receipts,
            sb.read_markers,
            sb.typing,
            sb.presence
        ),
        (false, 0, 0, 0, 0)
    );
    println!("[e2e] S1: sent, posted, decrypted both ways; duplicate counted once; no receipt or typing in the room");

    // --- 1:1 session S2, the Matrix room its only store: B's signed contact card binds its Matrix id on A's device
    let card = w
        .app
        .prepare_pqchat_card(b.key.clone(), 1, tb.user.clone())
        .await
        .unwrap()
        .sign()
        .await
        .unwrap();
    assert!(pa.add_card(CHAIN, &card.card, &card.sig).await.unwrap());
    let room2 = pa.create_room().await.unwrap();
    let mut req = create(
        &w,
        &a,
        2,
        &[&b],
        vec![StoreEntry::Matrix {
            room: room2.clone(),
        }],
        "s2",
    );
    req.info.matrix = BTreeMap::from([
        (a.ua.clone(), ta.user.clone()),
        (b.ua.clone(), tb.user.clone()),
    ]);
    let s2b = w
        .land_all(&pa, confirmed(&pa, pa.create(req).await).await.unwrap())
        .await;
    let sid2 = s2b.session_id.clone();
    let s2 = w.sref(&sid2);
    let ea2 = creator_uses(&w, &pa, &sid2, &sid2, s2b.k.clone()).await;
    let sync = pa.sync_room(&s2, &ea2, None, &a).await.unwrap();
    assert_eq!(
        (sync.invited.clone(), sync.unbound.len()),
        (vec![b.ua.clone()], 0),
        "B invited by its card's id"
    );
    assert_eq!(ta.calls_of("invite"), 1);
    let m2 = txt("hello B, Matrix only");
    let r = pa
        .send_content(&s2, &a, &m2, Some(10), &opts(&w, false))
        .await
        .unwrap();
    assert_eq!(r.stores, vec![(0, Delivery::Sent(String::new()))]);
    // B: pending, the invite held; joined only after the acceptance, the room's history read then
    let found = pb.sessions(&b).await.unwrap();
    assert!(found
        .iter()
        .any(|f| f.s == s2 && f.consent == Consent::Pending));
    pb.preview(&s2, &b).await.unwrap();
    assert_eq!(tb.calls_of("join"), 0, "no join before acceptance");
    pb.accept(&s2, false).unwrap();
    let o = pb.open_session(&s2, &b).await.unwrap();
    assert_eq!((o.room, o.shown), (RoomUse::Bound, 1));
    assert_eq!(tb.calls_of("join"), 1);
    assert_eq!(texts(&pb, &sid2), vec![(a.ua.clone(), m2.clone())]);
    let rep2 = txt("hello A, Matrix only");
    let r = pb
        .send_content(&s2, &b, &rep2, Some(11), &opts(&w, false))
        .await
        .unwrap();
    assert_eq!(r.stores[0].1, Delivery::Sent(String::new()));
    assert_eq!(pa.read_room(&room2).await.unwrap(), 1);
    assert_eq!(
        texts(&pa, &sid2),
        vec![(a.ua.clone(), m2.clone()), (b.ua.clone(), rep2.clone())]
    );
    assert_eq!(
        pa.dropped(&sid2),
        BTreeMap::from([(DropReason::Duplicate, 1)])
    );
    let sr = hs.seen_of(&room2, &tb.user);
    assert!(sr.joined && !sr.encrypted && sr.events == 2, "{sr:?}");
    assert_eq!((sr.receipts, sr.read_markers, sr.typing), (0, 0, 0));
    println!("[e2e] S2 {sid2}: Matrix only; B invited by its card, joined after acceptance; decrypted both ways");

    // --- group S3 (A admin; B, C), H's chain store
    let pc = w.device();
    pc.start_device(Some("c-1".into())).unwrap();
    let s3b = confirmed(
        &pa,
        pa.create(create(&w, &a, 3, &[&b, &c], vec![h.clone()], "s3"))
            .await,
    )
    .await
    .unwrap();
    let (s3b, s3_calls) = w.land_all_calls(&pa, s3b).await;
    let sid3 = s3b.session_id.clone();
    let s3 = w.sref(&sid3);
    let ea3 = creator_uses(&w, &pa, &sid3, &sid3, s3b.k.clone()).await;
    let first = txt("to B and C");
    let r = pa
        .send_content(&s3, &a, &first, Some(3), &opts(&w, false))
        .await
        .unwrap();
    w.delivered(&r.stores[0].1).await;
    assert_eq!(pc.sessions(&c).await.unwrap().len(), 1);
    pc.accept(&s3, true).unwrap();
    let oc = pc.open_session(&s3, &c).await.unwrap();
    assert_eq!(
        (oc.shown, texts(&pc, &sid3)),
        (1, vec![(a.ua.clone(), first.clone())])
    );
    let ec0 = oc.epoch.clone();
    // the hostile harness's fixtures, built while C is a member: C's plain rekey of e0 and C's postMessage under e0
    let c_rekey = confirmed(
        &pc,
        pc.rekey(
            &s3,
            &ec0,
            Rekey {
                me: c.clone(),
                nonce: 1,
                members: uas(&[&a, &b, &c]),
                admins: uas(&[&a]),
                info: info_of(&pc, &ec0),
                payer: w.l.payer.clone(),
            },
        )
        .await,
    )
    .await
    .unwrap();
    let c_out = pc.seal(&s3, &c, &txt("C under e0"), Some(4)).await.unwrap();
    let c_post = w
        .net
        .inner
        .prepare(
            CHAIN,
            &w.l.home,
            "IPqChat.postMessage",
            c_out.post_args(),
            &w.l.payer,
        )
        .await
        .unwrap();
    // A removes C, then rekeys without C; A sends under e1
    w.land(
        called(
            &pa,
            pa.remove(
                &s3,
                &ea3.epoch,
                &a,
                4,
                std::slice::from_ref(&c.ua),
                &w.l.payer,
            )
            .await,
        )
        .await
        .map(|x| x.1)
        .unwrap(),
    )
    .await;
    // the hostile harness: C's rekey of e0 (its slot still free), sent as raw calldata, refused for the removal
    let not_member = selector("PqChatNotMember(bytes32)");
    assert_eq!(
        w.raw(&w.l.home, &c_rekey.call.quote.data),
        Err(not_member),
        "C's rekey"
    );
    let r1 = confirmed(
        &pa,
        pa.rekey(
            &s3,
            &ea3,
            Rekey {
                me: a.clone(),
                nonce: 5,
                members: uas(&[&a, &b, &c]),
                admins: uas(&[&a]),
                info: info_of(&pa, &ea3),
                payer: w.l.payer.clone(),
            },
        )
        .await,
    )
    .await
    .unwrap();
    assert_eq!(
        r1.epoch
            .members
            .iter()
            .map(|m| m.ua.clone())
            .collect::<Vec<_>>(),
        uas(&[&a, &b])
    );
    let r1 = w.land_all(&pa, r1).await;
    creator_uses(&w, &pa, &sid3, &r1.epoch_id, r1.k.clone()).await;
    let after = txt("after C left");
    let r = pa
        .send_content(&s3, &a, &after, Some(5), &opts(&w, true))
        .await
        .unwrap();
    w.delivered(&r.stores[0].1).await;
    w.delivered(r.post.as_ref().unwrap()).await;
    // C: no wrap of its own in e1, no K, nothing decrypted from either store, nothing sent
    let writes = w.net.writes();
    assert_eq!(
        pc.open_epoch(&s3, &r1.epoch_id, &c.key, &c.ua, None)
            .await
            .err(),
        Some(DropReason::Member)
    );
    assert_eq!(pc.read_chain_store(&ec0, &h).await.unwrap(), 0);
    assert!(pc.posted(&w.l.home, 0, &ec0).await.is_err());
    // (C's own sealed fixture is in its timeline; of A's, only the first)
    let from_a: Vec<_> = texts(&pc, &sid3)
        .into_iter()
        .filter(|(u, _)| *u == a.ua)
        .collect();
    assert_eq!(from_a, vec![(a.ua.clone(), first.clone())]);
    assert_eq!(w.net.writes(), writes, "C's client wrote nothing");
    // the hostile harness: C's postMessage under e0, raw calldata, refused (e0's slot taken by A's child)
    let taken = selector("PqChatEpochTaken(bytes32,bytes32)");
    assert_eq!(
        w.raw(&w.l.home, &c_post.quote.data),
        Err(taken.clone()),
        "C's postMessage"
    );
    println!("[e2e] S3 {sid3}: C removed, e1 {} without C; C decrypts nothing; C's rekey and post refused by the contract", r1.epoch_id);

    // --- fresh device for B: same seed, new store, new anchor
    let pb2 = w.device();
    let d2 = pb2.start_device(Some("b-2".into())).unwrap();
    assert_ne!(d2, db1);
    w.net.clear();
    let (joins, hist) = (tb.calls_of("join"), tb.calls_of("history"));
    let found = pb2.sessions(&b).await.unwrap();
    let mut ids: Vec<_> = found
        .iter()
        .map(|f| (f.s.session_id.clone(), f.consent))
        .collect();
    ids.sort_by(|x, y| x.0.cmp(&y.0));
    let mut want = vec![
        (sid1.clone(), Consent::Pending),
        (sid2.clone(), Consent::Pending),
        (sid3.clone(), Consent::Pending),
    ];
    want.sort_by(|x, y| x.0.cmp(&y.0));
    assert_eq!(ids, want);
    for it in [
        "IOpenFactory.contractsPage",
        "IPqChat.sessionsOf",
        "IPqChat.latestEpoch",
    ] {
        assert!(w.net.read_items().contains(&it), "{it} not read");
    }
    for it in ["IPqChat.storedRange", "IPqChat.messageAt", "IPqChat.wrapAt"] {
        assert!(!w.net.read_items().contains(&it), "{it} read before accept");
    }
    assert_eq!(pb2.unwrap_calls(), 0);
    assert_eq!(
        (tb.calls_of("join"), tb.calls_of("history")),
        (joins, hist),
        "the room neither joined nor read before accept"
    );
    pb2.accept(&s1, true).unwrap();
    pb2.accept(&s3, true).unwrap();
    let o1 = pb2.open_session(&s1, &b).await.unwrap();
    assert_eq!(o1.shown, 2);
    assert_eq!(
        texts(&pb2, &sid1),
        vec![(a.ua.clone(), hello.clone()), (b.ua.clone(), reply.clone())]
    );
    let o3 = pb2.open_session(&s3, &b).await.unwrap();
    assert_eq!(
        (o3.shown, o3.epoch.epoch.id.clone()),
        (1, r1.epoch_id.clone())
    );
    assert_eq!(texts(&pb2, &sid3), vec![(a.ua.clone(), after.clone())]);
    // S2 from the room's history: the room B's account joined before, used once its members check against the epoch
    // (attached now: S1's room never invited B, so a join of it would fail)
    pb2.attach_matrix(tb.clone());
    pb2.accept(&s2, false).unwrap();
    let o2 = pb2.open_session(&s2, &b).await.unwrap();
    assert_eq!(
        (o2.room, o2.shown),
        (RoomUse::Bound, 2),
        "a room joined before used after its members' check"
    );
    assert_eq!(tb.calls_of("join"), joins, "no second join");
    assert_eq!(
        texts(&pb2, &sid2),
        vec![(a.ua.clone(), m2.clone()), (b.ua.clone(), rep2.clone())]
    );
    // B sends from the new device (a new device id: A's counter scope is new, the counter starts again)
    let fresh = txt("from B's new device");
    let r = pb2
        .send_content(&s1, &b, &fresh, Some(6), &opts(&w, false))
        .await
        .unwrap();
    w.delivered(&r.stores[1].1).await;
    assert_eq!(pa.read_chain_store(&ea1, &h).await.unwrap(), 1);
    assert_eq!(
        texts(&pa, &sid1).last().unwrap(),
        &(b.ua.clone(), fresh.clone())
    );
    let fresh2 = txt("from B's new device, Matrix only");
    let r = pb2
        .send_content(&s2, &b, &fresh2, Some(7), &opts(&w, false))
        .await
        .unwrap();
    assert_eq!(r.stores[0].1, Delivery::Sent(String::new()));
    assert_eq!(pa.read_room(&room2).await.unwrap(), 1);
    assert_eq!(
        texts(&pa, &sid2).last().unwrap(),
        &(b.ua.clone(), fresh2.clone())
    );
    println!("[e2e] B's fresh device: S1, S2, S3 found from state, pending; read after accept (S1 storedRange, S2 the room); its sends decrypted by A");

    // --- C's competing child at R1 (hostile): S3's session copied to R1, then C's plain rekey of e0 sent there, where C
    // was never removed; at H, A's e1 holds e0's slot
    for call in &s3_calls {
        w.raw(&w.r1, &call.quote.data).unwrap();
    }
    assert_eq!(
        c_rekey.sent,
        c_rekey.wraps.len(),
        "C's child complete in one write"
    );
    w.raw(&w.r1, &c_rekey.call.quote.data).unwrap();
    let view =
        |at: &str, sig: &str| common::chain::cast(&["call", "--rpc-url", &w.l.rpc, at, sig, &sid3]);
    // a replica orders nothing (no slot written there): R1's latest complete epoch is C's child, H's slot A's e1
    assert_eq!(
        (
            view(&w.r1, "latestEpoch(bytes32)(bytes32)"),
            view(&w.r1, "childOf(bytes32)(bytes32)"),
            view(&w.l.home, "childOf(bytes32)(bytes32)")
        ),
        (
            c_rekey.epoch_id.clone(),
            pqchat_core::model::ZERO32.to_string(),
            r1.epoch_id.clone()
        )
    );
    // membership is the home's: C's child, named with R1 as the replica, does not open (the home's `epochOf` refuses an
    // epoch it does not hold: `decode`)
    assert_eq!(
        pb.open_epoch(&s3, &c_rekey.epoch_id, &b.key, &b.ua, Some(w.r1.clone()))
            .await
            .err(),
        Some(DropReason::Decode),
        "mutant 4: membership from the replica"
    );
    // B's first device, e0 in use, follows the home's slot: its next message goes under A's e1
    pb.accept(&s3, true).unwrap();
    let e0b = pb
        .open_epoch(&s3, &sid3, &b.key, &b.ua, None)
        .await
        .unwrap();
    let e0b = pb.use_epoch(&s3, e0b).await.unwrap();
    let out = pb
        .seal(&s3, &b, &txt("B follows H"), Some(8))
        .await
        .unwrap();
    assert_eq!(out.epoch.epoch.id, r1.epoch_id, "mutant 5: the home slot");
    println!(
        "[e2e] C's child {} complete at R1 (its latest); B's client follows H's slot {}",
        c_rekey.epoch_id, r1.epoch_id
    );

    // --- hostile envelopes, each handed to B's first device as a store would
    let hint1 = w.app.pqchat_hint(s1b.k.clone()).unwrap();
    // mutant 2: a valid S2 record and signature, sealed under S2's k_env, handed in under S1's hint
    let s2env = hostile::sealed(
        &w,
        &a,
        &s2b.k,
        (&sid2, &sid2),
        &format!("0x{}", "a2".repeat(16)),
        0,
        r#"{"body":"x","type":"text"}"#,
    )
    .await;
    assert_eq!(
        pb.incoming(&sid1, &hint1, s2env.env).await.unwrap(),
        Incoming::Dropped(DropReason::Envelope),
        "mutant 2: envelope"
    );
    // mutant 3: a record naming B as its sender, signed by C, sealed under e0's k_env (C holds e0's K)
    let forged = hostile::signed_by_another(&w, &c, &b.ua, &ec0.k, (&sid3, &sid3)).await;
    let hint0 = w.app.pqchat_hint(ec0.k.clone()).unwrap();
    assert_eq!(
        pb.incoming(&sid3, &hint0, forged).await.unwrap(),
        Incoming::Dropped(DropReason::Signature),
        "mutant 3: signature"
    );
    // mutant 12: A's message whose padded plaintext has a non-zero fill, sealed under its mk
    let filled = hostile::with_fill(
        &w,
        &a,
        &s1b.k,
        (&sid1, &sid1),
        &format!("0x{}", "a5".repeat(16)),
        5,
        r#"{"body":"fill","type":"text"}"#,
    )
    .await;
    assert_eq!(
        pb.incoming(&sid1, &hint1, filled.env).await.unwrap(),
        Incoming::Dropped(DropReason::Content),
        "mutant 12: content"
    );
    let _ = &e0b;
    println!("[e2e] hostile envelopes: another epoch's k_env (envelope), B's record signed by C (signature), a non-zero fill (content)");

    // --- replicas: S1's createSession copied to R1 (anyone may submit the signed record)
    w.raw(&w.r1, &s1b.call.quote.data).unwrap();
    assert!(pb
        .open_epoch(&s1, &sid1, &b.key, &b.ua, Some(w.r1.clone()))
        .await
        .is_ok());
    // A's second, different record with S1's nonce (hostile): refused in R1 (the nonce used), landed in R2
    let conflict = hostile::session_at(&w, &pa, &a, 1, &w.l.home, &[&b, &c], &w.r2).await;
    assert_eq!(
        w.raw(&w.r1, &conflict.quote.data),
        Err(selector("PqChatNonceUsed(bytes32,uint64)"))
    );
    w.land(conflict).await;
    assert_eq!(
        pb.open_epoch(&s1, &sid1, &b.key, &b.ua, Some(w.r2.clone()))
            .await
            .err(),
        Some(DropReason::Replica),
        "mutant 8: replica"
    );
    assert_eq!(pb.dropped(&sid1).get(&DropReason::Replica), Some(&1));
    println!("[e2e] replicas: S1 read at R1 equal to H's; the conflicting record in R2 not counted (replica)");

    // --- public topic at H; an entry of R1 referenced; one in U unlisted
    let p = &pqchat_core::confirm::Path::Payer(w.l.payer.clone());
    let on = At {
        chain: CHAIN.into(),
        instance: w.l.home.clone(),
    };
    let t = called(
        &pa,
        pa.create_topic(&on, &a, 1, "pqchat e2e", b"# e2e", p).await,
    )
    .await
    .unwrap();
    let tid = t.0.clone().unwrap();
    w.land(t.1).await;
    let x = called(
        &pa,
        pa.post(&on, &tid, &a, 1, None, None, b"A's post", p).await,
    )
    .await
    .unwrap();
    let a1 = x.0.clone().unwrap();
    w.land(x.1).await;
    let x = called(
        &pb,
        pb.post(&on, &tid, &b, 1, Some(a1.clone()), None, b"B's reply", p)
            .await,
    )
    .await
    .unwrap();
    let b1 = x.0.clone().unwrap();
    w.land(x.1).await;
    w.land(
        called(&pb, pb.vote(&on, &a1, &b, Vote::Up, p).await)
            .await
            .unwrap()
            .1,
    )
    .await;
    assert_eq!(pa.score(&on, &a1).await.unwrap(), (1, 0));
    assert_eq!(
        pa.page(&on, &List::Posts(tid.clone()), 0, 10)
            .await
            .unwrap()
            .ids,
        vec![a1.clone()]
    );
    assert_eq!(
        pa.page(&on, &List::Replies(a1.clone()), 0, 10)
            .await
            .unwrap()
            .ids,
        vec![b1.clone()]
    );
    let on1 = At {
        chain: CHAIN.into(),
        instance: w.r1.clone(),
    };
    let t1 = called(&pa, pa.create_topic(&on1, &a, 2, "at R1", b"# r1", p).await)
        .await
        .unwrap();
    let tid1 = t1.0.clone().unwrap();
    w.land(t1.1).await;
    let x = called(
        &pa,
        pa.post(&on1, &tid1, &a, 2, None, None, b"an entry of R1", p)
            .await,
    )
    .await
    .unwrap();
    let e1 = x.0.clone().unwrap();
    w.land(x.1).await;
    let r = PqEntryRef {
        chain_uid: w.l.uid.clone(),
        pqchat: w.r1.clone(),
        entry_id: e1.clone(),
        content_hash: pqchat_core::model::ZERO32.into(),
    };
    assert_eq!(pb.resolve_ref(&r).await, RefState::Verified);
    // G5 (CTR-CHAT-31): a pinned contentHash is checked against the version rebuilt from state: its version 1's digest
    // verifies, another hash is no version of it
    let pinned = PqEntryRef {
        content_hash: pb.content_hash_at(&on1, &e1, 1).await.unwrap(),
        ..r.clone()
    };
    assert_eq!(pb.resolve_ref(&pinned).await, RefState::Verified);
    let pinned = PqEntryRef {
        content_hash: format!("0x{}", "c4".repeat(32)),
        ..r.clone()
    };
    assert_eq!(
        pb.resolve_ref(&pinned).await,
        RefState::Unverified(RefFault::HashMismatch)
    );
    let in_u = PqEntryRef {
        pqchat: w.u.clone(),
        ..r.clone()
    };
    assert_eq!(
        pb.resolve_ref(&in_u).await,
        RefState::Unverified(RefFault::Unlisted)
    );
    println!("[e2e] topic {tid}: post, reply, vote, pages; R1's entry verified, U's unlisted");

    // --- mutant 6's fixture: two different records of A, one device, one counter (A's store copied: a second process
    // with the same device id and counters, the hostile harness's)
    let pa2 = w.device_with(Arc::new(store_a.copy()));
    let e1 = pa
        .record_at(CHAIN, &w.l.home, &sid3, &r1.epoch_id)
        .await
        .unwrap()
        .unwrap();
    pa2.use_epoch(
        &s3,
        OpenEpoch {
            chain: CHAIN.into(),
            epoch: e1,
            k: r1.k.clone(),
        },
    )
    .await
    .unwrap();
    for (pq, m) in [(&pa, "one counter, first"), (&pa2, "one counter, second")] {
        let r = pq
            .send_content(&s3, &a, &txt(m), Some(7), &opts(&w, false))
            .await
            .unwrap();
        w.delivered(&r.stores[0].1).await;
    }
    assert_eq!(pb2.read_chain_store(&o3.epoch, &h).await.unwrap(), 1);
    assert_eq!(
        pb2.dropped(&sid3).get(&DropReason::Counter),
        Some(&1),
        "mutant 6: counter"
    );

    // --- mutant 9's fixture: a session for B in U (hostile: no honest client writes to an unlisted instance)
    let in_u = hostile::session_at(&w, &pa, &a, 9, &w.u, &[&b], &w.u).await;
    w.land(in_u).await;
    let sid_u = w.app.pqchat_session_id(a.ua.clone(), 9).unwrap();
    let su = SessionRef {
        chain: CHAIN.into(),
        home: w.u.clone(),
        session_id: sid_u.clone(),
    };
    assert_eq!(
        pb.open_epoch(&su, &sid_u, &b.key, &b.ua, None).await.err(),
        Some(DropReason::Unlisted),
        "mutant 9: unlisted"
    );
    assert!(!pb2
        .sessions(&b)
        .await
        .unwrap()
        .iter()
        .any(|f| f.s.session_id == sid_u));

    // --- mutant 10's fixture: the named endpoint serves B's wrap of S1 changed (the contract refuses such a wrap)
    *w.net.tamper.lock().unwrap() = Some(Box::new(|item, mut v| {
        if item == "IPqChat.wrapAt" {
            let ct = v["0"]["mlkemCt"].as_str().unwrap().to_string();
            let last = if ct.ends_with('0') { "1" } else { "0" };
            v["0"]["mlkemCt"] = Value::String(format!("{}{last}", &ct[..ct.len() - 1]));
        }
        v
    }));
    let before = pb.unwrap_calls();
    let r = pb.open_epoch(&s1, &sid1, &b.key, &b.ua, None).await;
    *w.net.tamper.lock().unwrap() = None;
    assert_eq!(r.err(), Some(DropReason::WrapHash), "mutant 10: wrap-hash");
    assert_eq!(pb.unwrap_calls(), before, "mutant 10: no K2 call");

    // --- mutant 14's fixture: a new pending session from C with a room; B's client, Matrix attached, the stores looked
    // at and confirmed, not accepted: no join
    let tc = Arc::new(hs.login("carol").await);
    pc.attach_matrix(tc.clone());
    let room_c = pc.create_room().await.unwrap();
    let cb = confirmed(
        &pc,
        pc.create(create(
            &w,
            &c,
            14,
            &[&b],
            vec![StoreEntry::Matrix { room: room_c }, h.clone()],
            "from C",
        ))
        .await,
    )
    .await
    .unwrap();
    let cb = w.land_all(&pc, cb).await;
    let sc = w.sref(&cb.session_id);
    let ep = pb2
        .open_epoch(&sc, &cb.session_id, &b.key, &b.ua, None)
        .await
        .unwrap();
    pb2.confirm_stores(&ep).unwrap();
    let joins = tb.calls_of("join");
    assert_eq!(
        pb2.join_room(&ep).await.err().map(|e| e.code()),
        Some("SessionPending"),
        "mutant 14: pending"
    );
    assert_eq!(
        tb.calls_of("join"),
        joins,
        "mutant 14: no join before accept"
    );
    println!("[e2e] fixtures: counter, unlisted, wrap-hash, pending gate");

    // --- mutant 11's fixture: a session record A signed with a `sealedInfo` sealed under its own K that is not in K5's
    // canonical form (the hostile harness, the vectors build); B's new device opens nothing and joins nothing from it. Until
    // CLI-PQC-15 the fixture changed S2's `sealedInfo` in the endpoint's `sessionOf` answer; S2's record is now judged by its
    // author's kept signature first (DropReason::Signature, `SessionUnknown`), so the info check is reached only by a record
    // its author signed with that info
    // the old fixture's read, kept as the evidence of why it went stale: a `sessionOf` answer whose `sealedInfo` differs
    // from what A signed fails A's kept signature, dropped as `Signature`, before any info check
    let canon = pa.info(&ea2).unwrap().with(|b| b.to_vec());
    let bad = pqchat_core::model::hex(&hostile::info_spaced(&w, &s2b.k, (&sid2, &sid2), &canon));
    let real = pqchat_core::model::hex(&ea2.epoch.sealed_info);
    *w.net.tamper.lock().unwrap() = Some(Box::new(move |item, mut v| {
        if item == "IPqChat.sessionOf" && v["s"]["sealedInfo"].as_str() == Some(real.as_str()) {
            v["s"]["sealedInfo"] = Value::String(bad.clone());
        }
        v
    }));
    let pb3 = w.device();
    pb3.start_device(Some("b-3x".into())).unwrap();
    pb3.accept(&s2, false).unwrap();
    let r = pb3.open_session(&s2, &b).await;
    *w.net.tamper.lock().unwrap() = None;
    assert_eq!(
        r.err().map(|e| e.code()),
        Some("SessionUnknown"),
        "a changed sealedInfo: the record's signature"
    );
    assert!(
        pb3.dropped(&sid2)
            .contains_key(&pqchat_core::DropReason::Signature),
        "dropped by its signature: {:?}",
        pb3.dropped(&sid2)
    );
    let spaced = hostile::session_info_spaced(&w, &pa, &a, 21, &w.l.home, &[&b]).await;
    let s21 = w.sref(
        &w.app
            .pqchat_session_id(a.ua.to_ascii_lowercase(), 21)
            .unwrap(),
    );
    w.land(spaced).await;
    let pb4 = w.device();
    pb4.start_device(Some("b-4".into())).unwrap();
    pb4.attach_matrix(tb.clone());
    pb4.accept(&s21, false).unwrap();
    let (joins, hist) = (tb.calls_of("join"), tb.calls_of("history"));
    let r = pb4.open_session(&s21, &b).await;
    assert_eq!(
        r.err().map(|e| e.code()),
        Some("PqChatContent"),
        "mutant 11: the sealedInfo's check"
    );
    assert_eq!(
        (
            tb.calls_of("join"),
            tb.calls_of("history"),
            pb4.room_session(&room2).unwrap()
        ),
        (joins, hist, None),
        "mutant 11: no store joined from it"
    );

    // --- mutant 15's fixture: A's device on the profile whose first endpoint is a discovered one that serves C's KEM key
    // for B's; the key read feeds a wrap, so only the named endpoint answers it
    let kem_at = selector("kemKeyAt(bytes32,uint64)");
    let word = |x: &str| x.trim_start_matches("0x").to_string();
    *w.proxy.swap.lock().unwrap() = Some((
        format!("{kem_at}{}{:064x}", word(&b.ua), 1),
        format!("{kem_at}{}{:064x}", word(&c.ua), 0),
    ));
    let pad_ = w.device_on(DISC);
    pad_.start_device(Some("a-d".into())).unwrap();
    let mut req = create(&w, &a, 15, &[&b], vec![h.clone()], "s15");
    req.chain = DISC.into();
    let b15 = confirmed(&pad_, pad_.create(req).await).await.unwrap();
    *w.proxy.swap.lock().unwrap() = None;
    let wb = b15.wraps.iter().find(|x| x.member == b.ua).unwrap().clone();
    assert!(
        w.app
            .pqchat_unwrap(
                b.key.clone(),
                b15.session_id.clone(),
                b15.session_id.clone(),
                wb
            )
            .is_ok(),
        "mutant 15: A wraps to B's own key"
    );
    assert_eq!(w.proxy.swapped.load(std::sync::atomic::Ordering::SeqCst), 0);

    // --- mutant 13's fixture: B's device reading at two blocks below the latest; A's child of S2 lands, B sends, the chain
    // is reverted to before the child: B's message went under the final epoch, so A reads it
    let rpc = |m: &str, a: &[&str]| {
        let mut v = vec!["rpc", "--rpc-url", &w.l.rpc, m];
        v.extend_from_slice(a);
        common::chain::cast(&v)
    };
    rpc("anvil_mine", &[&format!("{DEPTH:#x}")]);
    let sf = SessionRef {
        chain: FINAL.into(),
        ..s2.clone()
    };
    let pbf = w.device_on(FINAL);
    pbf.start_device(Some("b-f".into())).unwrap();
    pbf.attach_matrix(tb.clone());
    pbf.accept(&sf, false).unwrap();
    assert_eq!(
        pbf.open_session(&sf, &b).await.unwrap().room,
        RoomUse::Bound
    );
    let snap = rpc("anvil_snapshot", &[]);
    let landed = w.txs.lock().unwrap().len();
    let ch = confirmed(
        &pa,
        pa.rekey(
            &s2,
            &ea2,
            Rekey {
                me: a.clone(),
                nonce: 13,
                members: uas(&[&a, &b]),
                admins: uas(&[&a]),
                info: info_of(&pa, &ea2),
                payer: w.l.payer.clone(),
            },
        )
        .await,
    )
    .await
    .unwrap();
    let ch = w.land_all(&pa, ch).await;
    assert_eq!(w.l.call("childOf(bytes32)(bytes32)", &[&sid2]), ch.epoch_id);
    let fin = txt("B under the final epoch");
    let r = pbf
        .send_content(&sf, &b, &fin, Some(13), &opts(&w, false))
        .await
        .unwrap();
    assert_eq!(r.stores[0].1, Delivery::Sent(String::new()));
    assert_eq!(rpc("anvil_revert", &[&snap]), "true");
    assert_eq!(
        w.l.call("childOf(bytes32)(bytes32)", &[&sid2]),
        pqchat_core::model::ZERO32
    );
    let reverted: Vec<String> = w.txs.lock().unwrap().drain(landed..).collect();
    pa.read_room(&room2).await.unwrap();
    assert_eq!(
        texts(&pa, &sid2).last().unwrap(),
        &(b.ua.clone(), fin.clone()),
        "mutant 13: a send under the vanished child"
    );
    println!(
        "[e2e] fixtures: sealedInfo, discovered endpoint, finality ({} reverted: {})",
        reverted.len(),
        reverted.join(" ")
    );

    // --- the long chain (CLI-PQC-14): A sends 5,000 texts in S2; B's store with a client serving only the room's last 10
    // events shows all 10
    const LONG: usize = 5000;
    for i in 0..LONG {
        let r = pa
            .send_content(&s2, &a, &txt(&format!("long {i}")), None, &opts(&w, false))
            .await
            .unwrap();
        assert_eq!(r.stores[0].1, Delivery::Sent(String::new()));
        if (i + 1) % 500 == 0 {
            println!("[e2e] long chain: {}/{LONG} sent", i + 1);
        }
    }
    let pb5 = w.device();
    pb5.start_device(Some("b-5".into())).unwrap();
    pb5.attach_matrix(Arc::new(LastN {
        inner: tb.clone(),
        n: 10,
    }));
    pb5.accept(&s2, false).unwrap();
    let o = pb5.open_session(&s2, &b).await.unwrap();
    assert_eq!(
        (o.room, o.shown),
        (RoomUse::Bound, 10),
        "CLI-PQC-14: the last 10"
    );
    let want: Vec<(String, Content)> = (LONG - 10..LONG)
        .map(|i| (a.ua.clone(), txt(&format!("long {i}"))))
        .collect();
    assert_eq!(texts(&pb5, &sid2), want);
    println!("[e2e] long chain: {LONG} sent in S2; the last 10 events shown on a fresh store");
    let _ = (&s3b, &eb1);
    // the run's writes (the gate's summary note), hashes only
    let txs = w.txs.lock().unwrap().clone();
    println!("[e2e] {} transactions landed: {}", txs.len(), txs.join(" "));
}

async fn world_and_log() -> World {
    harness::world().await
}
