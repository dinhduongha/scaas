// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T7 on the SDK's fake chain (CLI-PQC-06; UA-7 P27, P29, P49, §6.5): one send to every listed store its type may use
//! with the same bytes, `typing` to the room only, `storedRange` paged 16 at a time with a stranger's and an empty envelope
//! dropped and paged past, the spend consent, receipts off with a chain store, `postMessage` on the user's choice and its
//! bucket, an unimplemented kind refused before anything is signed, the list rules, a store brought by a non-admin's rekey
//! used only once confirmed, a test-chain store warned about. Each negative beside its positive control; writes counted.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use async_trait::async_trait;
use common::sdk::*;
use pqchat_core::content::{Content, BODY_MAX};
use pqchat_core::matrix::{MatrixTransport, TransportError};
use pqchat_core::message::OpenEpoch;
use pqchat_core::model::{hex, unhex, Epoch, Member, ZERO32};
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{Me, StoreEntry};
use pqchat_core::stores::{Delivery, SendOpts};
use pqchat_core::{ChainConf, DropReason, Event, MemoryStore, PqChat, PqChatError};
use scaas_sdk::app_core::AppKey;
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_keys::{PqEpochNew, PqSessionNew};
use scaas_sdk::pqchat_records::{PqChatSigned, PqMemberKey};
use scaas_sdk::SecretBytes;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

fn me(a: &Acc) -> Me {
    Me {
        key: a.key.clone(),
        ua: a.ua.clone(),
    }
}

fn payer(w: &World) -> KeyRef {
    KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    }
}

fn opts(w: &World) -> SendOpts {
    SendOpts {
        payer: payer(w),
        post: false,
        post_cost_confirmed: false,
    }
}

fn txt(s: &str) -> Content {
    Content::Text {
        media_type: None,
        body: s.into(),
    }
}

fn code<T>(r: Result<T, PqChatError>) -> &'static str {
    match r {
        Ok(_) => "Ok",
        Err(e) => e.code(),
    }
}

fn chain(contract: &str) -> Value {
    json!({"kind": "chain", "chainId": "31337", "chainUid": hex(&[7; 32]), "contract": contract})
}

fn entry(v: &Value) -> StoreEntry {
    serde_json::from_value(v.clone()).unwrap()
}

const ROOM: &str = "!room:example.org";

fn room() -> Value {
    json!({"kind": "matrix", "room": ROOM})
}

/// The app's Matrix client as a recording stub.
#[derive(Default)]
struct Room(Mutex<Vec<(String, Value)>>);

#[async_trait]
impl MatrixTransport for Room {
    fn user_id(&self) -> String {
        "@alice:example.org".into()
    }
    async fn create_room(&self) -> Result<String, TransportError> {
        Err(TransportError)
    }
    async fn joined(&self, _: &str) -> Result<bool, TransportError> {
        Ok(false)
    }
    async fn members(&self, _: &str) -> Result<Vec<String>, TransportError> {
        Ok(vec![])
    }
    async fn join(&self, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn invite(&self, _: &str, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn remove(&self, _: &str, _: &str) -> Result<(), TransportError> {
        Ok(())
    }
    async fn set_admin(&self, _: &str, _: &str, _: bool) -> Result<(), TransportError> {
        Ok(())
    }
    async fn send_event(&self, room: &str, content: Value) -> Result<(), TransportError> {
        self.0.lock().unwrap().push((room.into(), content));
        Ok(())
    }
    async fn history(
        &self,
        _: &str,
        _: Option<String>,
    ) -> Result<pqchat_core::matrix::HistoryPage, TransportError> {
        Ok(Default::default())
    }
    async fn hold_invite(&self, _: &str, _: bool) {}
}

fn review<'a>(s: &'a PqChatSigned, name: &str) -> &'a str {
    &s.review.iter().find(|f| f.name == name).unwrap().value
}

/// An epoch built by another client (the SDK's S1 / S2 directly: any store list), stored at HOME with every wrap landed.
struct Built {
    e: Epoch,
    k: Arc<AppKey>,
}

async fn signed_epoch(
    w: &World,
    by: &Acc,
    parent: Option<&Epoch>,
    nonce: u64,
    members: &[&Acc],
    stores: Vec<Value>,
) -> Built {
    let mut ms: Vec<&Acc> = members.to_vec();
    ms.sort_by(|a, b| a.ua.cmp(&b.ua));
    let sid = match parent {
        Some(p) => p.session_id.clone(),
        None => w.app.pqchat_session_id(by.ua.clone(), nonce).unwrap(),
    };
    let eid = match parent {
        Some(_) => w
            .app
            .pqchat_epoch_id(sid.clone(), by.ua.clone(), nonce)
            .unwrap(),
        None => sid.clone(),
    };
    let k = w.app.pqchat_epoch_key(&w.seed).unwrap();
    let mut wraps = vec![];
    for a in &ms {
        kem_at(&w.chain, &a.id, 1, &a.kem_pk);
        wraps.push(
            w.app
                .pqchat_wrap(
                    CHAIN.into(),
                    k.clone(),
                    sid.clone(),
                    eid.clone(),
                    a.ua.clone(),
                    1,
                )
                .await
                .unwrap(),
        );
    }
    let keys: Vec<PqMemberKey> = ms
        .iter()
        .map(|a| PqMemberKey {
            ua: a.ua.clone(),
            key_id: 1,
            via: ZERO32.into(),
        })
        .collect();
    let admins = vec![w.alice.ua.clone()];
    let info_json = json!({"stores": stores, "name": "t7", "topic": "plan T7"}).to_string();
    let signed = match parent {
        None => w
            .app
            .pqchat_prepare_session(
                by.key.clone(),
                k.clone(),
                PqSessionNew {
                    nonce,
                    home_chain: hex(&[7; 32]),
                    home_chat_contract: HOME.into(),
                    admins: admins.clone(),
                    members: keys,
                    wraps: wraps.clone(),
                    info_json,
                },
            )
            .await
            .unwrap()
            .sign()
            .await
            .unwrap(),
        Some(p) => w
            .app
            .pqchat_prepare_epoch(
                by.key.clone(),
                k.clone(),
                PqEpochNew {
                    session_id: sid.clone(),
                    nonce,
                    epoch: p.epoch + 1,
                    parent_epoch_id: p.id.clone(),
                    admins: admins.clone(),
                    members: keys,
                    wraps: wraps.clone(),
                    info_json,
                },
            )
            .await
            .unwrap()
            .sign()
            .await
            .unwrap(),
    };
    let e = Epoch {
        id: eid.clone(),
        session_id: sid,
        author: by.ua.clone(),
        nonce,
        epoch: parent.map_or(0, |p| p.epoch + 1),
        parent: parent.map_or(ZERO32.into(), |p| p.id.clone()),
        admins,
        members: ms
            .iter()
            .map(|a| Member {
                ua: a.ua.clone(),
                key_id: 1,
                via: ZERO32.into(),
            })
            .collect(),
        wrap_hashes: signed.wrap_hashes.clone(),
        sealed_info: unhex(review(&signed, "message.sealedInfo")).unwrap(),
        sig_hash: hex(&[0x5e; 32]),
    };
    put_record(&w.net, HOME, &e);
    for (i, x) in wraps.iter().enumerate() {
        put_wrap(&w.net, HOME, &eid, i, x);
    }
    child(&w.net, HOME, &eid, ZERO32);
    w.net.answer(
        HOME,
        "IPqChat.epochComplete",
        json!({"epochId": eid}),
        json!({"0": true}),
    );
    Built { e, k }
}

fn sref(e: &Epoch) -> SessionRef {
    SessionRef {
        chain: CHAIN.into(),
        home: HOME.into(),
        session_id: e.session_id.clone(),
    }
}

/// The world: HOME and REPLICA listed, prepares and submits answered.
async fn ready() -> World {
    let w = world().await;
    list(&w.net, HOME, 3, 1);
    list(&w.net, REPLICA, 3, 1);
    w.net.accept.store(true, Ordering::SeqCst);
    w
}

/// Alice's session (alice, bob) over `stores`, in use on her crate, its stores confirmed and their spend consented.
async fn alice_sends(w: &World, stores: Vec<Value>) -> (Built, SessionRef) {
    let b = signed_epoch(w, &w.alice, None, 1, &[&w.alice, &w.bob], stores).await;
    let s = sref(&b.e);
    let ep =
        w.pq.use_epoch(
            &s,
            OpenEpoch {
                chain: CHAIN.into(),
                epoch: b.e.clone(),
                k: b.k.clone(),
            },
        )
        .await
        .unwrap();
    w.pq.confirm_stores(&ep).unwrap();
    // accepted with the spend consent (CLI-PQC-08)
    w.pq.accept(&s, true).unwrap();
    // its room (if listed) joined through the session and bound (CLI-PQC-05), then the client detached again
    w.pq.attach_matrix(Arc::new(Room::default()));
    w.pq.join_room(&ep).await.unwrap();
    w.pq.detach_matrix();
    (b, s)
}

fn sent(d: &Delivery) -> bool {
    matches!(d, Delivery::Sent(_))
}

/// One send reaches every listed store with the same bytes: the room's event and each `storeMessage` carry one envelope.
#[tokio::test(flavor = "multi_thread")]
async fn one_send_every_store_same_bytes() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (_, s) = alice_sends(&w, vec![room(), chain(HOME), chain(REPLICA)]).await;
    let r = Arc::new(Room::default());
    w.pq.attach_matrix(r.clone());
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &txt("hi"), None, &opts(&w))
            .await
            .unwrap();
    assert_eq!(rep.stores.len(), 3);
    assert!(rep.stores.iter().all(|(_, d)| sent(d)), "{rep:?}");
    let st = w.net.writes_of("IPqChat.storeMessage");
    assert_eq!(st.len(), 2);
    assert_eq!(st[0], st[1]);
    assert_eq!(st[0]["v"], "1");
    let ev = r.0.lock().unwrap().clone();
    assert_eq!(ev.len(), 1);
    assert_eq!(ev[0].0, ROOM);
    let (hint, env) = pqchat_core::matrix::parse(ev[0].1.to_string().as_bytes()).unwrap();
    assert_eq!(
        (hex(&hint), hex(&env)),
        (
            st[0]["hint"].as_str().unwrap().into(),
            st[0]["env"].as_str().unwrap().into()
        )
    );
    assert!(rep.post.is_none() && w.net.writes_of("IPqChat.postMessage").is_empty());
}

/// `typing` goes to the room only, and with no room listed nothing is signed or sent.
#[tokio::test(flavor = "multi_thread")]
async fn typing_to_the_room_only() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (_, s) = alice_sends(&w, vec![room(), chain(HOME)]).await;
    let r = Arc::new(Room::default());
    w.pq.attach_matrix(r.clone());
    let t = Content::Typing { on: true };
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &t, None, &opts(&w))
            .await
            .unwrap();
    assert_eq!(rep.stores.len(), 1);
    assert_eq!(r.0.lock().unwrap().len(), 1);
    assert!(w.net.writes_of("IPqChat.storeMessage").is_empty());
    // twin: a text reaches the chain store too
    w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
        .await
        .unwrap();
    assert_eq!(w.net.writes_of("IPqChat.storeMessage").len(), 1);
    // a session with no room: no typing at all, no counter taken
    drop(w);
    let w = ready().await;
    let (b, s) = alice_sends(&w, vec![chain(HOME)]).await;
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &t, None, &opts(&w))
            .await
            .unwrap();
    assert_eq!((rep.message_id, rep.stores.len()), (None, 0));
    let d = w.pq.device().unwrap();
    assert_eq!(w.pq.next_counter(&b.e.id, &d).unwrap(), 0);
    assert_eq!(w.net.writes(), 0);
}

fn empty_payload(hint: &[u8]) -> String {
    let mut h = hint.to_vec();
    h.resize(32, 0);
    format!("0x{}{}{}{}", w(1), &hex(&h)[2..], w(0x60), w(0))
}

/// `storedRange` paged 16 at a time from the kept position: a stranger's envelope under the hint dropped (`member`), an empty
/// one paged past (`decode`), an offset past the end empty.
#[tokio::test(flavor = "multi_thread")]
async fn stored_range_paged_sixteen() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let b = signed_epoch(
        &w,
        &w.alice,
        None,
        1,
        &[&w.alice, &w.bob],
        vec![chain(HOME)],
    )
    .await;
    let s = sref(&b.e);
    let ep =
        w.pq.open_epoch(&s, &b.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    let ep = w.pq.use_epoch(&s, ep).await.unwrap();
    w.pq.confirm_stores(&ep).unwrap();
    w.pq.accept(&s, false).unwrap();
    let hint = w.app.pqchat_hint(b.k.clone()).unwrap();
    let mut payloads = vec![];
    for c in 0..16u64 {
        payloads.push(hex(&sealed(
            &w,
            &w.alice,
            &b.e,
            &b.k,
            c,
            r#"{"body":"m","type":"text"}"#,
        )
        .await
        .payload));
    }
    payloads[3] = hex(
        &sealed(&w, &w.carol, &b.e, &b.k, 0, r#"{"body":"c","type":"text"}"#)
            .await
            .payload,
    );
    payloads[9] = empty_payload(&hint);
    let page = |off: u64, v: &[String]| {
        w.net.answer(
            HOME,
            "IPqChat.storedRange",
            json!({"hint": hex(&hint), "offset": off.to_string(), "limit": "16"}),
            json!({"0": v}),
        )
    };
    page(0, &payloads);
    let last = vec![
        hex(&sealed(
            &w,
            &w.alice,
            &b.e,
            &b.k,
            16,
            r#"{"body":"m","type":"text"}"#,
        )
        .await
        .payload),
        hex(&sealed(
            &w,
            &w.alice,
            &b.e,
            &b.k,
            17,
            r#"{"body":"m","type":"text"}"#,
        )
        .await
        .payload),
    ];
    page(16, &last);
    page(18, &[]);
    let st = entry(&chain(HOME));
    assert_eq!(w.pq.read_chain_store(&ep, &st).await.unwrap(), 16);
    assert_eq!(
        w.pq.dropped(&s.session_id),
        BTreeMap::from([(DropReason::Member, 1), (DropReason::Decode, 1)])
    );
    // the kept position: the next read starts past the end, and its page is empty
    assert_eq!(w.pq.read_chain_store(&ep, &st).await.unwrap(), 0);
    let offs: Vec<String> = w
        .net
        .reads
        .lock()
        .unwrap()
        .iter()
        .filter(|r| r.1 == "IPqChat.storedRange")
        .map(|r| r.2["offset"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(offs, ["0", "16", "18"]);
    assert_eq!(w.net.writes(), 0);
}

/// A chain store without the session's spend consent refuses the send before anything is signed; consented, it is written.
#[tokio::test(flavor = "multi_thread")]
async fn chain_cost_unconfirmed() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (b, s) = alice_sends(&w, vec![chain(HOME)]).await;
    w.pq.consent_chain_spend(&s.session_id, false).unwrap();
    let e =
        w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
            .await;
    assert_eq!(code(e), "ChainCostUnconfirmed");
    let d = w.pq.device().unwrap();
    assert_eq!(
        (w.pq.next_counter(&b.e.id, &d).unwrap(), w.net.writes()),
        (0, 0)
    );
    w.pq.consent_chain_spend(&s.session_id, true).unwrap();
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
            .await
            .unwrap();
    assert!(sent(&rep.stores[0].1));
}

/// `receipt` is off by default while a chain store is listed (on when the user turns it on), on by default without one.
#[tokio::test(flavor = "multi_thread")]
async fn receipt_off_with_a_chain_store() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (_, s) = alice_sends(&w, vec![room(), chain(HOME)]).await;
    let r = Arc::new(Room::default());
    w.pq.attach_matrix(r.clone());
    let rc = Content::Receipt {
        target: hex(&[0x42; 32]),
    };
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &rc, None, &opts(&w))
            .await
            .unwrap();
    assert_eq!(rep.message_id, None);
    assert_eq!((w.net.writes(), r.0.lock().unwrap().len()), (0, 0));
    w.pq.set_receipts(&s.session_id, true).unwrap();
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &rc, None, &opts(&w))
            .await
            .unwrap();
    assert!(rep.message_id.is_some());
    // a session with the room only: on by default
    drop(w);
    let w = ready().await;
    let (_, s) = alice_sends(&w, vec![room()]).await;
    w.pq.attach_matrix(r.clone());
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &rc, None, &opts(&w))
            .await
            .unwrap();
    assert!(rep.message_id.is_some());
}

/// `postMessage` only on the user's choice, its arguments the envelope's; above the 1,024-B bucket only with the cost
/// confirmation (`ContentTooLarge`: nothing sent anywhere).
#[tokio::test(flavor = "multi_thread")]
async fn post_on_choice_within_the_bucket() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (_, s) = alice_sends(&w, vec![chain(HOME)]).await;
    let mut o = opts(&w);
    w.pq.send_content(&s, &me(&w.alice), &txt("a"), None, &o)
        .await
        .unwrap();
    assert!(w.net.writes_of("IPqChat.postMessage").is_empty());
    o.post = true;
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &txt("b"), None, &o)
            .await
            .unwrap();
    assert!(sent(rep.post.as_ref().unwrap()));
    let p = w.net.writes_of("IPqChat.postMessage");
    let st = w.net.writes_of("IPqChat.storeMessage");
    assert_eq!(p.len(), 1);
    assert_eq!(
        (&p[0]["m"]["sender"], &p[0]["m"]["counter"]),
        (&json!(w.alice.ua), &json!("1"))
    );
    let tl = w.pq.timeline(&s.session_id);
    assert_eq!(tl.last().unwrap().id, rep.message_id.clone().unwrap());
    let big = txt(&"l".repeat(1100));
    let n = w.net.writes();
    let e = w.pq.send_content(&s, &me(&w.alice), &big, None, &o).await;
    assert_eq!(code(e), "ContentTooLarge");
    assert_eq!(w.net.writes(), n, "nothing sent anywhere");
    assert_eq!(w.pq.timeline(&s.session_id).len(), 2);
    o.post_cost_confirmed = true;
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &big, None, &o)
            .await
            .unwrap();
    assert!(sent(rep.post.as_ref().unwrap()));
    assert_eq!(st.len(), 2);
}

/// A content's JSON in a handle, as a binding app writes it through the SDK's copy call.
fn handle(b: &[u8]) -> Arc<SecretBytes> {
    let h = SecretBytes::new(b.len()).unwrap();
    h.with_mut(|x| x.copy_from_slice(b));
    Arc::new(h)
}

/// Owner 2026-11-23 (plan T12): `send` takes the content's JSON as a `SecretBytes` handle, parsed and validated in Rust:
/// exactly a content of a type in scope in P49's form (`ts` is the call's argument); anything else is refused before a
/// counter is taken, nothing signed or sent. The twin: the same content well formed is sent and shown.
#[tokio::test(flavor = "multi_thread")]
async fn send_takes_the_content_json_as_a_handle() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (b, s) = alice_sends(&w, vec![room(), chain(HOME)]).await;
    let r = Arc::new(Room::default());
    w.pq.attach_matrix(r.clone());
    let d = w.pq.device().unwrap();
    let n = w.net.writes();
    let long = format!(r#"{{"type":"text","body":"{}"}}"#, "a".repeat(BODY_MAX + 1));
    let obo = format!(
        r#"{{"type":"text","body":"hi","onBehalfOf":"0x{}"}}"#,
        "11".repeat(32)
    );
    // a `file` goes only through `send_file`, which enters its key (a content without one opens nowhere)
    let z = format!("0x{}", "00".repeat(32));
    let file = format!(
        r#"{{"type":"file","mediaType":"image/png","name":"a.png","size":1,"sha256":"{z}","ctSha256":"{z}","url":"ar://{}"}}"#,
        "A".repeat(43)
    );
    let refused: Vec<(&[u8], &str)> = vec![
        (b"hi", "ContentInvalid"),
        (br#""hi""#, "ContentInvalid"),
        (br#"{"type":"call"}"#, "ContentInvalid"),
        (br#"{"type":"text","body":""}"#, "ContentInvalid"),
        (
            br#"{"type":"text","body":"hi","mediaType":"text/html"}"#,
            "ContentInvalid",
        ),
        (br#"{"type":"text","body":"hi","x":1}"#, "ContentInvalid"),
        (
            br#"{"type":"text","body":"hi","mediaType":null}"#,
            "ContentInvalid",
        ),
        (br#"{"type":"text","body":"hi","ts":1}"#, "ContentInvalid"),
        (obo.as_bytes(), "ContentInvalid"),
        (file.as_bytes(), "ContentInvalid"),
        (long.as_bytes(), "ContentTooLarge"),
    ];
    for (j, want) in refused {
        let e =
            w.pq.send(&s, &me(&w.alice), handle(j), Some(1), &opts(&w))
                .await;
        let shown = String::from_utf8_lossy(&j[..j.len().min(70)]).into_owned();
        assert_eq!(code(e), want, "{shown}");
    }
    assert_eq!(w.net.writes(), n, "nothing sent to the chain store");
    assert!(r.0.lock().unwrap().is_empty(), "nothing sent to the room");
    assert_eq!(
        w.pq.next_counter(&b.e.id, &d).unwrap(),
        0,
        "no counter taken"
    );
    // the twin: well formed (keys in any order), sent to both stores and shown with its `ts`
    let rep =
        w.pq.send(
            &s,
            &me(&w.alice),
            handle(br#"{"body":"hi","type":"text"}"#),
            Some(1),
            &opts(&w),
        )
        .await
        .unwrap();
    assert!(rep.message_id.is_some());
    assert_eq!(r.0.lock().unwrap().len(), 1);
    assert_eq!(w.net.writes_of("IPqChat.storeMessage").len(), 1);
    let tl = w.pq.timeline(&s.session_id);
    let shown: Value = tl
        .last()
        .unwrap()
        .content
        .with(|b| serde_json::from_slice(b).unwrap());
    assert_eq!(shown, json!({"type": "text", "body": "hi", "ts": 1}));
}

/// A list naming HCS: the send refused before anything is signed (`StoreUnsupported`), the chain store still read.
#[tokio::test(flavor = "multi_thread")]
async fn hcs_listed_refused_before_signing() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let hcs = json!({"kind": "hcs", "topic": "0.0.1234"});
    let (b, s) = alice_sends(&w, vec![chain(HOME), hcs]).await;
    let e =
        w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
            .await;
    assert_eq!(code(e), "StoreUnsupported");
    let d = w.pq.device().unwrap();
    assert_eq!(w.pq.next_counter(&b.e.id, &d).unwrap(), 0, "nothing signed");
    assert_eq!(w.net.writes(), 0);
    // bob reads the chain store
    let bob = PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        conf(),
    );
    let ep = bob
        .open_epoch(&s, &b.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .unwrap();
    let ep = bob.use_epoch(&s, ep).await.unwrap();
    bob.confirm_stores(&ep).unwrap();
    bob.accept(&s, false).unwrap();
    let hint = w.app.pqchat_hint(b.k.clone()).unwrap();
    let m = sealed(
        &w,
        &w.alice,
        &b.e,
        &b.k,
        0,
        r#"{"body":"read","type":"text"}"#,
    )
    .await;
    w.net.answer(
        HOME,
        "IPqChat.storedRange",
        json!({"hint": hex(&hint), "offset": "0", "limit": "16"}),
        json!({"0": [hex(&m.payload)]}),
    );
    assert_eq!(
        bob.read_chain_store(&ep, &entry(&chain(HOME)))
            .await
            .unwrap(),
        1
    );
}

/// UA-7 §4.2's list rules: no message store, two rooms, the same chain store twice: `StoreListInvalid`, nothing signed.
#[tokio::test(flavor = "multi_thread")]
async fn store_list_invalid() {
    let _one = ONE.lock().await;
    for stores in [
        vec![],
        vec![json!({"kind": "libp2p"})],
        vec![
            room(),
            json!({"kind": "matrix", "room": "!other:example.org"}),
        ],
        vec![chain(HOME), chain(HOME)],
    ] {
        let w = ready().await;
        let (b, s) = alice_sends(&w, stores.clone()).await;
        let e =
            w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
                .await;
        assert_eq!(code(e), "StoreListInvalid", "{stores:?}");
        let d = w.pq.device().unwrap();
        assert_eq!(w.pq.next_counter(&b.e.id, &d).unwrap(), 0);
        assert_eq!(w.net.writes(), 0);
    }
}

/// A non-admin's rekey adding a chain store: told (`StoresChanged`, not by an admin), not written to or read until the user
/// confirms it, the confirmed store still served; an admin's rekey told as by an admin.
#[tokio::test(flavor = "multi_thread")]
async fn rekey_by_a_member_adds_an_unconfirmed_store() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (b, s) = alice_sends(&w, vec![chain(HOME)]).await;
    let e1 = signed_epoch(
        &w,
        &w.bob,
        Some(&b.e),
        2,
        &[&w.alice, &w.bob],
        vec![chain(HOME), chain(REPLICA)],
    )
    .await;
    child(&w.net, HOME, &b.e.id, &e1.e.id);
    let ep1 =
        w.pq.open_epoch(&s, &e1.e.id, &w.alice.key, &w.alice.ua, None)
            .await
            .unwrap();
    let ep1 = w.pq.use_epoch(&s, ep1).await.unwrap();
    assert_eq!(
        w.pq.events(),
        [Event::StoresChanged {
            session: s.session_id.clone(),
            author: w.bob.ua.clone(),
            by_admin: false
        }]
    );
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
            .await
            .unwrap();
    assert_eq!(
        rep.stores,
        [(0, rep.stores[0].1.clone()), (1, Delivery::Unconfirmed)]
    );
    assert!(sent(&rep.stores[0].1));
    let st = w.net.writes_of("IPqChat.storeMessage");
    assert_eq!(st.len(), 1);
    assert_eq!(
        code(w.pq.read_chain_store(&ep1, &entry(&chain(REPLICA))).await),
        "StoreUnconfirmed"
    );
    assert_eq!(w.net.reads_of("IPqChat.storedRange"), 0);
    w.pq.confirm_stores(&ep1).unwrap();
    let rep =
        w.pq.send_content(&s, &me(&w.alice), &txt("y"), None, &opts(&w))
            .await
            .unwrap();
    assert!(rep.stores.iter().all(|(_, d)| sent(d)));
    // an admin's rekey (alice) adding a store: told as by an admin
    let e2 = signed_epoch(
        &w,
        &w.alice,
        Some(&e1.e),
        3,
        &[&w.alice, &w.bob],
        vec![chain(HOME), chain(REPLICA), room()],
    )
    .await;
    let ep2 =
        w.pq.open_epoch(&s, &e2.e.id, &w.alice.key, &w.alice.ua, None)
            .await
            .unwrap();
    w.pq.use_epoch(&s, ep2).await.unwrap();
    assert_eq!(
        w.pq.events(),
        [Event::StoresChanged {
            session: s.session_id.clone(),
            author: w.alice.ua.clone(),
            by_admin: true
        }]
    );
}

/// A Matrix room listed without an attached client: `MatrixDetached`, nothing signed.
#[tokio::test(flavor = "multi_thread")]
async fn matrix_detached() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (b, s) = alice_sends(&w, vec![room(), chain(HOME)]).await;
    let e =
        w.pq.send_content(&s, &me(&w.alice), &txt("x"), None, &opts(&w))
            .await;
    assert_eq!(code(e), "MatrixDetached");
    let d = w.pq.device().unwrap();
    assert_eq!(
        (w.pq.next_counter(&b.e.id, &d).unwrap(), w.net.writes()),
        (0, 0)
    );
}

/// A chain store on a chain the app serves as a test chain is warned about; one on another chain is not.
#[tokio::test(flavor = "multi_thread")]
async fn test_chain_store_warned() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let mut c = conf();
    c.chains.push(ChainConf {
        chain: "sepolia-testnet".into(),
        chain_uid: hex(&[0x5e; 32]),
        registry: REGISTRY.into(),
        factory: FACTORY.into(),
    });
    let pq = PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        c,
    );
    let test = json!({"kind": "chain", "chainId": "11155111", "chainUid": hex(&[0x5e; 32]), "contract": HOME});
    let info: pqchat_core::session::Info =
        serde_json::from_value(json!({"stores": [chain(HOME), test], "name": "", "topic": ""}))
            .unwrap();
    assert_eq!(pq.test_chain_stores(&info), [entry(&test)]);
}

/// Plan T10b (owner 2026-11-22): alice sends a `file` content to a chain store; the sealed item comes back for the app to post
/// (nothing posted), its object padded to its bucket; her own timeline shows the content without a key; bob's client receives
/// the envelope, reads the file's public fields and opens the object, its length and `ctSha256` checked before any
/// decryption (a flipped byte `FileHashMismatch`, a short object `FileLength`, each beside the control), no write caused.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_is_sent_and_read() {
    use pqchat_core::file::FileToSend;
    let _one = ONE.lock().await;
    let w = ready().await;
    let (b, s) = alice_sends(&w, vec![chain(HOME)]).await;
    let file: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
    let f = FileToSend {
        file: file.clone(),
        media_type: "application/octet-stream".into(),
        name: "a.bin".into(),
        max_object: 1 << 30,
    };
    let (rep, up) =
        w.pq.send_file(&s, &me(&w.alice), &f, None, &opts(&w))
            .await
            .unwrap();
    assert!(rep.stores.iter().all(|(_, d)| sent(d)), "{rep:?}");
    assert!(up.url.starts_with("ar://") && up.size == 1000);
    // the object is the item's data: exactly bucket(1000) + 16 = 2^16 + 16 B
    let object = up.item[up.item.len() - ((1 << 16) + 16)..].to_vec();
    // her own timeline: a file, its content without a key
    let mine = w.pq.timeline(&s.session_id);
    let own = mine
        .iter()
        .find(|m| w.pq.file_info(m.content.clone()).is_ok())
        .unwrap();
    assert!(own.supported);
    let shown: Value = own.content.with(|c| serde_json::from_slice(c).unwrap());
    assert!(shown.get("key").is_none(), "{shown}");
    assert_eq!(shown["url"], up.url.as_str());
    // bob's client receives it from the store
    let st = w.net.writes_of("IPqChat.storeMessage");
    let env = unhex(st[0]["env"].as_str().unwrap()).unwrap();
    let bob = PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        conf(),
    );
    let ep = OpenEpoch {
        chain: CHAIN.into(),
        epoch: b.e.clone(),
        k: b.k.clone(),
    };
    let got = bob.receive(&ep, env).await.unwrap();
    let info: Value = bob
        .file_info(got.content.clone())
        .unwrap()
        .with(|b| serde_json::from_slice(b).unwrap());
    assert_eq!(
        (
            &info["url"],
            &info["size"],
            &info["name"],
            &info["ctSha256"]
        ),
        (
            &json!(up.url),
            &json!(1000),
            &json!("a.bin"),
            &json!(up.ct_sha256)
        )
    );
    // the key stays in the content's own handle, never in what the app reads
    assert!(info.get("key").is_none(), "{info}");
    assert!(got
        .content
        .with(|b| serde_json::from_slice::<Value>(b).unwrap())["key"]
        .is_string());
    let writes = w.net.writes();
    let mut flip = object.clone();
    flip[1000] ^= 1;
    assert_eq!(
        code(bob.open_file(got.content.clone(), flip)),
        "FileHashMismatch"
    );
    assert_eq!(
        code(bob.open_file(got.content.clone(), object[..object.len() - 1].to_vec())),
        "FileLength"
    );
    let opened = bob.open_file(got.content.clone(), object).unwrap();
    assert_eq!(opened.with(|b| b.to_vec()), file, "control");
    assert_eq!(w.net.writes(), writes, "no write from a read");
    // a text content is no file
    assert!(bob.file_info(own.content.clone()).is_ok());
    // review T26 C-10: an own message's handle and a file's info handle are built sealed: no copy call overwrites them
    let info_h = bob.file_info(own.content.clone()).unwrap();
    for (what, h) in [("own", &own.content), ("file info", &info_h)] {
        let zeros = vec![0; h.len()];
        assert!(
            scaas_ua::wallet::secret_write(h.id(), &zeros).is_err(),
            "{what}"
        );
    }
    let twin = Arc::new(scaas_ua::wallet::SecretBytes::new(4).unwrap());
    assert!(
        scaas_ua::wallet::secret_write(twin.id(), &[1; 4]).is_ok(),
        "control: a secret made to be written"
    );
    let t =
        w.pq.send_content(&s, &me(&w.alice), &txt("hi"), None, &opts(&w))
            .await
            .unwrap();
    assert!(t.message_id.is_some());
    let text =
        w.pq.timeline(&s.session_id)
            .into_iter()
            .find(|m| m.id == t.message_id.clone().unwrap())
            .unwrap();
    assert_eq!(code(bob.file_info(text.content)), "ContentInvalid");
}

/// PqChat's scope carries its app id (owner 2026-11-22): `scaas-ua`'s `keccak256("scaas.pqchat.v1")`, the root
/// `seal_for_arweave` derives from.
#[test]
fn the_scope_has_pqchat_s_app_id() {
    assert_eq!(
        pqchat_core::APP_ID,
        hex(&scaas_ua::wallet::pqchat::app_id())
    );
}
