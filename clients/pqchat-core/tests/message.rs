// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T6 (UA-7 §6.3, §6.4.1, §6.5, P19, P49; CLI-PQC-07, CLI-PQC-14): own chain counters taken before the seal, chain positions
//! (no skipped key kept, one walk of at most 2^20 steps after the signature and membership checks, a bounded LRU, derived
//! lazily after a lock), the content types and their bounds, the 1,024-B bucket, the envelope's inner bytes as `postMessage`'s
//! arguments, display order, at most 8 sorted parents, the unknown-epoch buffer, edits and redactions by their sender only,
//! and the sender leaving an epoch with a complete child. On the SDK's fake chain, real keys and ciphertexts; each negative
//! beside its positive control, its drop reason asserted, no write caused.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::sdk::*;
use pqchat_core::chain_state::own_key;
use pqchat_core::content::{Content, BODY_MAX};
use pqchat_core::message::{
    Incoming, OpenEpoch, Outgoing, PENDING_MAX, POSITIONS_MAX, POST_BUCKET, WALK_MAX,
};
use pqchat_core::model::{hex, Epoch, ZERO32};
use pqchat_core::order::{self, display_order, Shown};
use pqchat_core::session::Me;
use pqchat_core::{DropReason, Items, MemoryStore, PqChat};
use scaas_sdk::app_core::AppKey;
use scaas_sdk::pqchat_keys::{PqMessageHeader, PqSealedMessage};
use scaas_sdk::SecretBytes;
use std::collections::BTreeMap;
use std::sync::Arc;

fn me(a: &Acc) -> Me {
    Me {
        key: a.key.clone(),
        ua: a.ua.clone(),
    }
}

fn ep_of(e: &Epoch, k: &Arc<AppKey>) -> OpenEpoch {
    OpenEpoch {
        chain: CHAIN.into(),
        epoch: e.clone(),
        k: k.clone(),
    }
}

/// Another device's crate (its own store) over the same scope and port.
fn device2(w: &World) -> Arc<PqChat> {
    PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        conf(),
    )
}

fn txt(s: &str) -> Content {
    Content::Text {
        media_type: None,
        body: s.into(),
    }
}

/// CLI-PQC-14's bound, as the rule states it.
const BOUND: u64 = 1 << 20;

fn dev(n: u32) -> String {
    format!("0x{n:032x}")
}

/// `from`'s message at `counter` of its chain `(e, device)` with `parents` (S5 through the scope; the walk in steps of 2^20).
#[allow(clippy::too_many_arguments)]
async fn sealed_at(
    w: &World,
    from: &Acc,
    e: &Epoch,
    k: &Arc<AppKey>,
    device: &str,
    counter: u64,
    content: &str,
    parents: Vec<String>,
) -> PqSealedMessage {
    let mut p = w
        .app
        .pqchat_chain(
            k.clone(),
            e.session_id.clone(),
            e.id.clone(),
            from.ua.clone(),
            device.into(),
        )
        .unwrap();
    let mut at = 0;
    while at < counter {
        let n = (counter - at).min(WALK_MAX);
        p = w.app.pqchat_advance(p, n).unwrap();
        at += n;
    }
    w.app
        .pqchat_seal_message(
            from.key.clone(),
            k.clone(),
            p,
            PqMessageHeader {
                session_id: e.session_id.clone(),
                epoch_id: e.id.clone(),
                device: device.into(),
                counter,
                parents,
            },
            content.into(),
        )
        .await
        .unwrap()
}

/// A 2-member session (alice, bob) in use on alice's crate, its home showing no child: alice sends.
async fn sending(w: &World) -> (Opened, Arc<OpenEpoch>) {
    let o = opened(w, &[&w.alice, &w.bob]).await;
    child(&w.net, HOME, &o.e.id, ZERO32);
    let ep = w.pq.use_epoch(&o.s, ep_of(&o.e, &o.k)).await.unwrap();
    (o, ep)
}

/// Bob's crate (another device) with the session's epoch opened from his own wrap and in use.
async fn bob_reads(w: &World, o: &Opened) -> (Arc<PqChat>, Arc<OpenEpoch>) {
    let pq = device2(w);
    let ep = pq
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .unwrap();
    let ep = pq.use_epoch(&o.s, ep).await.unwrap();
    (pq, ep)
}

/// A shown message's text, read from its content handle (an edit's own body when edited).
fn body(m: &order::Message) -> String {
    if !m.supported {
        return "<unsupported>".into();
    }
    let v: serde_json::Value = serde_json::from_str(&text(&m.content)).unwrap();
    v["body"].as_str().unwrap().to_string()
}

/// Counters from 0 per epoch and device, the device id kept; bob reads both, in order.
#[tokio::test(flavor = "multi_thread")]
async fn counters_from_zero_per_epoch_and_device() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, _) = sending(&w).await;
    let d = w.pq.device().unwrap();
    assert_eq!((d.len(), w.pq.device().unwrap()), (34, d.clone()));
    let a =
        w.pq.seal(&o.s, &me(&w.alice), &txt("one"), Some(1))
            .await
            .unwrap();
    let b =
        w.pq.seal(&o.s, &me(&w.alice), &txt("two"), Some(2))
            .await
            .unwrap();
    assert_eq!((a.sealed.record.counter, b.sealed.record.counter), (0, 1));
    assert_eq!(a.sealed.record.device, d);
    assert_eq!(w.pq.next_counter(&o.e.id, &d).unwrap(), 2);
    assert_eq!(w.pq.next_counter(&hex(&[0x99; 32]), &d).unwrap(), 0);
    // b names a as its parent
    assert_eq!(b.sealed.record.parents, vec![a.sealed.message_id.clone()]);
    let (bob, ep) = bob_reads(&w, &o).await;
    assert!(bob.receive(&ep, b.sealed.env.clone()).await.is_ok());
    assert!(bob.receive(&ep, a.sealed.env.clone()).await.is_ok());
    let t = bob.timeline(&o.e.session_id);
    assert_eq!(t.iter().map(body).collect::<Vec<_>>(), ["one", "two"]);
    // alice's own copy from a store: a duplicate, nothing shown twice
    assert_eq!(
        w.pq.receive(&ep, a.sealed.env.clone()).await.err(),
        Some(DropReason::Duplicate)
    );
    assert_eq!(w.pq.timeline(&o.e.session_id).len(), 2);
    assert_eq!(w.net.writes(), 0);
}

/// A crash between the counter's write and the send (the epoch key wiped under the seal): the counter is skipped, never
/// reused; a store that cannot take the counter seals nothing.
#[tokio::test(flavor = "multi_thread")]
async fn counter_taken_before_the_seal() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, ep) = sending(&w).await;
    let d = w.pq.device().unwrap();
    let a =
        w.pq.seal(&o.s, &me(&w.alice), &txt("a"), None)
            .await
            .unwrap();
    assert_eq!(a.sealed.record.counter, 0);
    w.app.destroy(ep.k.clone()).unwrap();
    assert!(w
        .pq
        .seal(&o.s, &me(&w.alice), &txt("b"), None)
        .await
        .is_err());
    assert_eq!(
        w.pq.next_counter(&o.e.id, &d).unwrap(),
        2,
        "the counter is spent"
    );
    w.pq.locked();
    // the epoch in use again (a fresh draw stands in for alice's own wrap of K)
    let k = w.app.pqchat_epoch_key(&w.seed).unwrap();
    w.pq.use_epoch(&o.s, ep_of(&o.e, &k)).await.unwrap();
    let c =
        w.pq.seal(&o.s, &me(&w.alice), &txt("c"), None)
            .await
            .unwrap();
    assert_eq!(
        c.sealed.record.counter, 2,
        "a counter skipped, never reused"
    );
    // a store that cannot write the counter: StoreIo, nothing sealed or shown
    let pq = PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(NoCounter::default()),
        conf(),
    );
    pq.use_epoch(&o.s, ep_of(&o.e, &k)).await.unwrap();
    let e = pq.seal(&o.s, &me(&w.alice), &txt("d"), None).await;
    assert_eq!(e.err().map(|e| e.code()), Some("StoreIo"));
    assert_eq!(pq.timeline(&o.e.session_id).len(), 0);
    assert_eq!(w.net.writes(), 0);
}

/// A store whose own-chain counters cannot be written.
#[derive(Default)]
struct NoCounter(MemoryStore);
impl pqchat_core::PqChatStore for NoCounter {
    fn load(&self, key: &str) -> Result<Option<pqchat_core::Item>, pqchat_core::StoreFault> {
        self.0.load(key)
    }
    fn replace(
        &self,
        key: &str,
        expected: u64,
        value: &[u8],
    ) -> Result<bool, pqchat_core::StoreFault> {
        if key.starts_with("own/") {
            return Err(pqchat_core::StoreFault);
        }
        self.0.replace(key, expected, value)
    }
}

/// An own chain at 2^64 − 1: `CounterExhausted`, nothing shown; one below the store's value seals.
#[tokio::test(flavor = "multi_thread")]
async fn counter_exhausted() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, _) = sending(&w).await;
    let d = w.pq.device().unwrap();
    let key = own_key(&o.e.id, &d);
    Items(&*w.store).update::<u64, _>(&key, |_| Ok(5)).unwrap();
    let a =
        w.pq.seal(&o.s, &me(&w.alice), &txt("a"), None)
            .await
            .unwrap();
    assert_eq!(a.sealed.record.counter, 5);
    Items(&*w.store)
        .update::<u64, _>(&key, |_| Ok(u64::MAX))
        .unwrap();
    let e = w.pq.seal(&o.s, &me(&w.alice), &txt("b"), None).await;
    assert_eq!(e.err().map(|e| e.code()), Some("CounterExhausted"));
    assert_eq!(w.pq.next_counter(&o.e.id, &d).unwrap(), u64::MAX);
    assert_eq!(w.pq.timeline(&o.e.session_id).len(), 1);
}

/// CLI-PQC-14 on a fresh store: a chain at counter 5,000, only its last 10 messages: all 10 shown, one position held; a
/// message 2^20 steps from `ck_0` read, one 2^20 + 1 steps `too-far`.
#[tokio::test(flavor = "multi_thread")]
async fn long_chain_fresh_store() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let (bob, ep) = bob_reads(&w, &o).await;
    let sid = &o.e.session_id;
    for c in 4991..=5000u64 {
        let body = format!(r#"{{"body":"m{c}","type":"text"}}"#);
        let m = sealed_at(&w, &w.alice, &o.e, &o.k, DEVICE, c, &body, vec![]).await;
        assert!(bob.receive(&ep, m.env).await.is_ok(), "counter {c}");
    }
    assert_eq!(bob.timeline(sid).len(), 10);
    assert_eq!(bob.held_positions(sid), 1);
    // another device's chain, nothing held for it: 2^20 steps read, 2^20 + 1 too far
    let far = sealed_at(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        &dev(7),
        BOUND + 1,
        r#"{"body":"x","type":"text"}"#,
        vec![],
    )
    .await;
    assert_eq!(
        bob.receive(&ep, far.env).await.err(),
        Some(DropReason::TooFar)
    );
    let edge = sealed_at(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        &dev(8),
        BOUND,
        r#"{"body":"y","type":"text"}"#,
        vec![],
    )
    .await;
    assert!(
        bob.receive(&ep, edge.env).await.is_ok(),
        "2^20 steps are read"
    );
    assert_eq!(bob.dropped(sid), BTreeMap::from([(DropReason::TooFar, 1)]));
    assert_eq!(w.net.writes(), 0);
}

/// A member signing under 500 new device ids at counter 2,000: every message shown, the held positions within their bound
/// (the least recently used dropped), no key kept beyond them.
#[tokio::test(flavor = "multi_thread")]
async fn five_hundred_devices_keep_positions_bounded() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let (bob, ep) = bob_reads(&w, &o).await;
    let sid = &o.e.session_id;
    for n in 0..500u32 {
        let m = sealed_at(
            &w,
            &w.alice,
            &o.e,
            &o.k,
            &dev(n + 100),
            2000,
            r#"{"body":"d","type":"text"}"#,
            vec![],
        )
        .await;
        assert!(bob.receive(&ep, m.env).await.is_ok(), "device {n}");
        assert!(bob.held_positions(sid) <= POSITIONS_MAX);
    }
    assert_eq!(bob.held_positions(sid), POSITIONS_MAX);
    assert_eq!(bob.timeline(sid).len(), 500);
    assert!(bob.dropped(sid).is_empty());
}

/// A walk runs only for a record that passed the signature and membership checks: none is held after either drop.
#[tokio::test(flavor = "multi_thread")]
async fn walk_only_after_signature_and_membership() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob, &w.carol]).await;
    let mut two = o.e.clone();
    two.members.retain(|m| m.ua != w.carol.ua);
    let (bob, ep) = bob_reads(&w, &o).await;
    let sid = &o.e.session_id;
    // carol's record checked against bob's key: `signature`
    let c = sealed_at(
        &w,
        &w.carol,
        &o.e,
        &o.k,
        DEVICE,
        1000,
        r#"{"body":"c","type":"text"}"#,
        vec![],
    )
    .await;
    register(&w.chain, &w.carol, &w.bob);
    assert_eq!(
        bob.receive(&ep, c.env.clone()).await.err(),
        Some(DropReason::Signature)
    );
    assert_eq!(bob.held_positions(sid), 0);
    register(&w.chain, &w.carol, &w.carol);
    // carol, no member of a two-member epoch: `member`
    let ep2 = OpenEpoch {
        epoch: two,
        ..(*ep).clone()
    };
    assert_eq!(
        bob.receive(&ep2, c.env.clone()).await.err(),
        Some(DropReason::Member)
    );
    assert_eq!(bob.held_positions(sid), 0);
    // twin: a member's record walks and holds its position
    assert!(bob.receive(&ep, c.env).await.is_ok());
    assert_eq!(bob.held_positions(sid), 1);
}

/// Positions are a cache: released at the lock, derived again only when a message needs one.
#[tokio::test(flavor = "multi_thread")]
async fn positions_derived_lazily_after_a_lock() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let (bob, ep) = bob_reads(&w, &o).await;
    let sid = &o.e.session_id;
    let m = |c: u64| {
        sealed_at(
            &w,
            &w.alice,
            &o.e,
            &o.k,
            DEVICE,
            c,
            r#"{"body":"m","type":"text"}"#,
            vec![],
        )
    };
    assert!(bob.receive(&ep, m(10).await.env).await.is_ok());
    assert_eq!(bob.held_positions(sid), 1);
    bob.locked();
    assert_eq!(bob.held_positions(sid), 0);
    let again = bob
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .unwrap();
    let ep = bob.use_epoch(&o.s, again).await.unwrap();
    assert_eq!(
        bob.held_positions(sid),
        0,
        "nothing derived before a message needs it"
    );
    assert!(bob.receive(&ep, m(11).await.env).await.is_ok());
    assert_eq!(bob.held_positions(sid), 1);
}

/// P49: each type in scope within its bounds; each bound broken, a bad field type, an unknown type or a type out of this
/// round's scope shown as unsupported; an unknown field ignored. Sending: above 16,000 B `ContentTooLarge`, out of bounds
/// `ContentInvalid`.
#[test]
fn content_types_and_bounds() {
    let id = hex(&[0x11; 32]);
    let ok = [
        (r#"{"body":"hi","type":"text"}"#.to_string(), txt("hi")),
        (
            r#"{"body":"*b*","mediaType":"text/markdown","type":"text"}"#.into(),
            Content::Text {
                media_type: Some("text/markdown".into()),
                body: "*b*".into(),
            },
        ),
        (
            format!(r#"{{"body":"new","target":"{id}","type":"edit"}}"#),
            Content::Edit {
                target: id.clone(),
                media_type: None,
                body: "new".into(),
            },
        ),
        (
            format!(r#"{{"target":"{id}","type":"redact"}}"#),
            Content::Redact {
                target: id.clone(),
                reason: None,
            },
        ),
        (
            format!(r#"{{"reaction":"+1","target":"{id}","type":"react"}}"#),
            Content::React {
                target: id.clone(),
                reaction: "+1".into(),
            },
        ),
        (
            format!(r#"{{"target":"{id}","type":"receipt"}}"#),
            Content::Receipt { target: id.clone() },
        ),
        (
            r#"{"on":true,"type":"typing"}"#.into(),
            Content::Typing { on: true },
        ),
        (r#"{"body":"x","later":[1],"type":"text"}"#.into(), txt("x")),
    ];
    for (j, c) in &ok {
        assert_eq!(&Content::parse(j.as_bytes()).content, c, "{j}");
    }
    let p = Content::parse(br#"{"body":"t","ts":9007199254740991,"type":"text"}"#);
    assert_eq!(p.ts, Some((1 << 53) - 1));
    let big = "x".repeat(BODY_MAX + 1);
    let bad = [
        r#"{"body":"","type":"text"}"#.to_string(),
        format!(r#"{{"body":"{big}","type":"text"}}"#),
        r#"{"body":"x","mediaType":"text/html","type":"text"}"#.into(),
        r#"{"body":"x","ts":9007199254740992,"type":"text"}"#.into(),
        r#"{"body":"x","ts":-1,"type":"text"}"#.into(),
        r#"{"body":"x","type":"te-xt"}"#.into(),
        r#"{"body":"x"}"#.into(),
        r#"{"body":7,"type":"text"}"#.into(),
        format!(
            r#"{{"body":"x","target":"0x{}","type":"edit"}}"#,
            "AB".repeat(32)
        ),
        format!(r#"{{"reaction":"","target":"{id}","type":"react"}}"#),
        format!(
            r#"{{"reason":"{}","target":"{id}","type":"redact"}}"#,
            "r".repeat(513)
        ),
        r#"{"on":"yes","type":"typing"}"#.into(),
        r#"{"type":"file"}"#.into(),
        r#"{"callId":"x","type":"callKey"}"#.into(),
        r#"{"type":"poll"}"#.into(),
        r#"[1]"#.into(),
    ];
    for j in &bad {
        assert_eq!(
            Content::parse(j.as_bytes()).content,
            Content::Unsupported,
            "{j}"
        );
    }
    assert!(txt(&"x".repeat(BODY_MAX)).value(None).is_ok());
    assert_eq!(txt(&big).value(None).unwrap_err().code(), "ContentTooLarge");
    assert_eq!(txt("").value(None).unwrap_err().code(), "ContentInvalid");
    assert_eq!(
        Content::Receipt {
            target: "0x12".into()
        }
        .value(None)
        .unwrap_err()
        .code(),
        "ContentInvalid"
    );
    assert_eq!(
        Content::Unsupported.value(None).unwrap_err().code(),
        "ContentInvalid"
    );
    assert_eq!(
        txt("t").value(Some(1 << 53)).unwrap_err().code(),
        "ContentInvalid"
    );
    assert_eq!(
        txt("t").value(Some(5)).unwrap(),
        serde_json::json!({"type": "text", "body": "t", "ts": 5})
    );
}

/// An unknown type received: shown as unsupported, acted on never, nothing written.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_type_shown_unsupported() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let (bob, ep) = bob_reads(&w, &o).await;
    let m = sealed_at(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        DEVICE,
        0,
        r#"{"q":1,"type":"poll"}"#,
        vec![],
    )
    .await;
    assert!(bob.receive(&ep, m.env).await.is_ok());
    let t = bob.timeline(&o.e.session_id);
    assert_eq!((t.len(), t[0].supported), (1, false));
    assert_eq!(text(&t[0].content), r#"{"q":1,"type":"poll"}"#);
    assert_eq!(w.net.writes(), 0);
}

/// The 1,024-B bucket: a text that pads within 1,024 B fits `postMessage` without confirmation, a longer one does not.
#[tokio::test(flavor = "multi_thread")]
async fn bucket_rule_for_the_chain() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, _) = sending(&w).await;
    let small =
        w.pq.seal(&o.s, &me(&w.alice), &txt(&"s".repeat(900)), None)
            .await
            .unwrap();
    let large =
        w.pq.seal(&o.s, &me(&w.alice), &txt(&"l".repeat(1100)), None)
            .await
            .unwrap();
    assert_eq!((small.bucket(), large.bucket()), (POST_BUCKET, 4096));
}

/// The envelope's inner bytes are `postMessage`'s arguments: the record and signature it opens to are the ones posted, under
/// one `messageId`.
#[tokio::test(flavor = "multi_thread")]
async fn inner_bytes_are_the_post_arguments() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, ep) = sending(&w).await;
    let out: Outgoing =
        w.pq.seal(&o.s, &me(&w.alice), &txt("p"), None)
            .await
            .unwrap();
    let s = &out.sealed;
    let inner = w
        .app
        .pqchat_open_envelope(
            ep.k.clone(),
            o.e.session_id.clone(),
            o.e.id.clone(),
            s.env.clone(),
        )
        .unwrap();
    assert_eq!((&inner.record, &inner.sig), (&s.record, &s.sig));
    assert_eq!(
        w.app.pqchat_message_id(inner.record.clone()).unwrap(),
        s.message_id
    );
    let a = out.post_args();
    let r = &s.record;
    assert_eq!(
        a["m"],
        serde_json::json!({"sessionId": r.session_id, "epochId": r.epoch_id, "sender": r.sender, "device": r.device,
            "counter": r.counter.to_string(), "parents": r.parents, "ciphertext": hex(&r.ciphertext)})
    );
    assert_eq!(a["sig"]["keyData"], hex(&s.sig.key_data));
    assert_eq!(a["sig"]["signature"], hex(&s.sig.signature));
    // the SDK's `inner` holds the record's ciphertext and the signature's bytes
    let has = |n: &[u8]| s.inner.windows(n.len()).any(|x| x == n);
    assert!(has(&r.ciphertext) && has(&s.sig.signature));
}

fn shown(id: u8, parents: &[u8], ts: Option<u64>) -> Shown {
    Shown {
        id: hex(&[id; 32]),
        epoch: hex(&[1; 32]),
        sender: hex(&[2; 32]),
        device: dev(1),
        counter: u64::from(id),
        parents: parents.iter().map(|p| hex(&[*p; 32])).collect(),
        ts,
        on_behalf_of: None,
        kind: "text",
        target: None,
        content: Arc::new(SecretBytes::new(0).unwrap()),
    }
}

/// Display order: after the parents held (whatever their `ts`), then `ts` (absent as 0), then `messageId`.
#[test]
fn display_order_parents_ts_id() {
    let msgs = vec![
        shown(5, &[], Some(50)),
        shown(3, &[5], Some(10)),
        shown(4, &[5], Some(10)),
        shown(9, &[0xee], None),
        shown(2, &[3, 4], Some(5)),
    ];
    let ids: Vec<u8> = display_order(&msgs)
        .iter()
        .map(|m| u8::from_str_radix(&m.id[2..4], 16).unwrap())
        .collect();
    assert_eq!(ids, [9, 5, 3, 4, 2]);
}

/// At most 8 parents, strictly sorted: the newest heads kept; a seal after ten concurrent messages names eight.
#[tokio::test(flavor = "multi_thread")]
async fn parents_at_most_eight_sorted() {
    let heads: Vec<String> = (0..10u8).rev().map(|i| hex(&[i; 32])).collect();
    let p = order::parents(&heads).unwrap();
    let want: Vec<String> = (0..8u8).map(|i| hex(&[i; 32])).collect();
    assert_eq!(p, want);
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, ep) = sending(&w).await;
    for c in 0..10u64 {
        let m = sealed_at(
            &w,
            &w.bob,
            &o.e,
            &o.k,
            DEVICE,
            100 - c,
            r#"{"body":"b","type":"text"}"#,
            vec![],
        )
        .await;
        assert!(w.pq.receive(&ep, m.env).await.is_ok());
    }
    let out =
        w.pq.seal(&o.s, &me(&w.alice), &txt("after"), None)
            .await
            .unwrap();
    let ps = &out.sealed.record.parents;
    assert_eq!(ps.len(), 8);
    assert!(ps.windows(2).all(|x| x[0] < x[1]), "parents sorted");
}

/// A message of an epoch not in use is kept and shown once its epoch is in use; the kept envelopes are bounded.
#[tokio::test(flavor = "multi_thread")]
async fn unknown_epoch_buffered_then_shown() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let sid = &o.e.session_id;
    let pq = device2(&w);
    let hint = w.app.pqchat_hint(o.k.clone()).unwrap();
    let m = sealed_at(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        DEVICE,
        0,
        r#"{"body":"early","type":"text"}"#,
        vec![],
    )
    .await;
    assert_eq!(
        pq.incoming(sid, &hint, m.env.clone()).await.unwrap(),
        Incoming::Buffered
    );
    assert_eq!(pq.pending(sid).unwrap(), 1);
    assert!(pq.timeline(sid).is_empty());
    let ep = pq
        .open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
        .await
        .unwrap();
    pq.use_epoch(&o.s, ep).await.unwrap();
    assert_eq!(pq.pending(sid).unwrap(), 0);
    assert_eq!(
        pq.timeline(sid).iter().map(body).collect::<Vec<_>>(),
        ["early"]
    );
    // in use now: read at once
    let n = sealed_at(
        &w,
        &w.alice,
        &o.e,
        &o.k,
        DEVICE,
        1,
        r#"{"body":"now","type":"text"}"#,
        vec![],
    )
    .await;
    assert!(matches!(
        pq.incoming(sid, &hint, n.env).await.unwrap(),
        Incoming::Shown(_)
    ));
    // another epoch's envelopes: at most PENDING_MAX kept
    for i in 0..PENDING_MAX + 5 {
        let r = pq.incoming(sid, &[9; 8], vec![i as u8; 40]).await.unwrap();
        assert_eq!(r, Incoming::Buffered);
    }
    assert_eq!(pq.pending(sid).unwrap(), PENDING_MAX);
    assert_eq!(w.net.writes(), 0);
}

/// An `edit` or `redact` counts only from its target's sender UA: bob's of alice's text ignored, alice's own applied.
#[tokio::test(flavor = "multi_thread")]
async fn edit_and_redact_from_another_ua_ignored() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let (pq, ep) = bob_reads(&w, &o).await;
    let sid = &o.e.session_id;
    let seal = |from: &Acc, c: u64, j: String| {
        let from = from.clone();
        let (w, o) = (&w, &o);
        async move { sealed_at(w, &from, &o.e, &o.k, DEVICE, c, &j, vec![]).await }
    };
    let a = seal(
        &w.alice,
        0,
        r#"{"body":"orig","ts":1,"type":"text"}"#.into(),
    )
    .await;
    let t = &a.message_id;
    pq.receive(&ep, a.env.clone()).await.unwrap();
    let bob_edit = seal(
        &w.bob,
        0,
        format!(r#"{{"body":"bob's","target":"{t}","ts":2,"type":"edit"}}"#),
    )
    .await;
    pq.receive(&ep, bob_edit.env).await.unwrap();
    assert_eq!(
        (body(&pq.timeline(sid)[0]), pq.timeline(sid)[0].edited),
        ("orig".to_string(), false)
    );
    let own_edit = seal(
        &w.alice,
        1,
        format!(r#"{{"body":"fixed","target":"{t}","ts":3,"type":"edit"}}"#),
    )
    .await;
    pq.receive(&ep, own_edit.env).await.unwrap();
    assert_eq!(
        (body(&pq.timeline(sid)[0]), pq.timeline(sid)[0].edited),
        ("fixed".to_string(), true)
    );
    let bob_redact = seal(
        &w.bob,
        1,
        format!(r#"{{"target":"{t}","ts":4,"type":"redact"}}"#),
    )
    .await;
    pq.receive(&ep, bob_redact.env).await.unwrap();
    assert_eq!(pq.timeline(sid).len(), 1);
    let own_redact = seal(
        &w.alice,
        2,
        format!(r#"{{"target":"{t}","ts":5,"type":"redact"}}"#),
    )
    .await;
    pq.receive(&ep, own_redact.env).await.unwrap();
    assert!(pq.timeline(sid).is_empty());
    assert_eq!(w.net.writes(), 0);
}

/// Decrypted content leaves only as the SDK's `SecretBytes` handles (owner 2026-11-22, "Handle SecretBytes"): a received
/// message's content, a shown message's (its newest own edit's when edited), each reaction's; their bytes the canonical JSON;
/// one reaction per UA and value.
#[tokio::test(flavor = "multi_thread")]
async fn content_leaves_only_as_handles() {
    let _one = ONE.lock().await;
    let w = world().await;
    let o = opened(&w, &[&w.alice, &w.bob]).await;
    let (pq, ep) = bob_reads(&w, &o).await;
    let sid = &o.e.session_id;
    let seal = |from: &Acc, c: u64, j: String| {
        let from = from.clone();
        let (w, o) = (&w, &o);
        async move { sealed_at(w, &from, &o.e, &o.k, DEVICE, c, &j, vec![]).await }
    };
    let orig = r#"{"body":"orig","ts":1,"type":"text"}"#;
    let a = seal(&w.alice, 0, orig.into()).await;
    let t = &a.message_id;
    let got = pq.receive(&ep, a.env.clone()).await.unwrap();
    let h: Arc<SecretBytes> = got.content.clone();
    assert_eq!(text(&h), orig);
    for (from, c, ts) in [(&w.bob, 0, 2), (&w.alice, 1, 3), (&w.bob, 1, 4)] {
        let j = format!(r#"{{"reaction":"ok","target":"{t}","ts":{ts},"type":"react"}}"#);
        pq.receive(&ep, seal(from, c, j).await.env).await.unwrap();
    }
    let edit = format!(r#"{{"body":"fixed","target":"{t}","ts":5,"type":"edit"}}"#);
    pq.receive(&ep, seal(&w.alice, 2, edit.clone()).await.env)
        .await
        .unwrap();
    let tl = pq.timeline(sid);
    assert_eq!(tl.len(), 1);
    let m = &tl[0];
    assert_eq!(
        (m.supported, m.edited, text(&m.content)),
        (true, true, edit)
    );
    assert_eq!(m.reactions.len(), 1);
    assert_eq!(m.reactions[0].count, 2);
    assert!(text(&m.reactions[0].content).contains(r#""reaction":"ok""#));
    assert_eq!(w.net.writes(), 0);
}

/// A sender stops using an epoch once a complete child is in use: sends held (`EpochNotFinal`) until the home's final block
/// shows the child, then under the child.
#[tokio::test(flavor = "multi_thread")]
async fn sender_stops_using_an_epoch_with_a_complete_child() {
    let _one = ONE.lock().await;
    let w = world().await;
    let (o, _) = sending(&w).await;
    let a =
        w.pq.seal(&o.s, &me(&w.alice), &txt("e0"), None)
            .await
            .unwrap();
    assert_eq!(a.sealed.record.epoch_id, o.e.id);
    // bob's plain rekey: e1, the same lists; alice's own wrap in it
    let k1 = w.app.pqchat_epoch_key(&w.seed).unwrap();
    let mut e1 = o.e.clone();
    e1.id = hex(&[0x61; 32]);
    e1.author = w.bob.ua.clone();
    e1.nonce = 2;
    e1.epoch = 1;
    e1.parent = o.e.id.clone();
    let i = e1.index_of(&w.alice.ua).unwrap();
    kem(&w, &w.alice, 1);
    let wrap = w
        .app
        .pqchat_wrap(
            CHAIN.into(),
            k1.clone(),
            e1.session_id.clone(),
            e1.id.clone(),
            w.alice.ua.clone(),
            1,
        )
        .await
        .unwrap();
    e1.wrap_hashes[i] = w.app.pqchat_wrap_hash(wrap.clone()).unwrap();
    put_record(&w.net, HOME, &e1);
    put_wrap(&w.net, HOME, &e1.id, i, &wrap);
    w.net.answer(
        HOME,
        "IPqChat.epochComplete",
        serde_json::json!({"epochId": e1.id}),
        serde_json::json!({"0": true}),
    );
    child(&w.net, HOME, &e1.id, ZERO32);
    let ep1 =
        w.pq.open_epoch(&o.s, &e1.id, &w.alice.key, &w.alice.ua, None)
            .await
            .unwrap();
    w.pq.use_epoch(&o.s, ep1).await.unwrap();
    let held = w.pq.seal(&o.s, &me(&w.alice), &txt("held"), None).await;
    assert_eq!(held.err().map(|e| e.code()), Some("EpochNotFinal"));
    child(&w.net, HOME, &o.e.id, &e1.id);
    let b =
        w.pq.seal(&o.s, &me(&w.alice), &txt("e1"), None)
            .await
            .unwrap();
    assert_eq!(b.sealed.record.epoch_id, e1.id);
    assert_eq!(b.sealed.record.counter, 0);
    assert_eq!(w.net.writes(), 0);
}
