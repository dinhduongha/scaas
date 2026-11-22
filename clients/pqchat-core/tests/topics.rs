// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T10 on the SDK's fake chain (topics spec P33–P46): create with `openReplies` true and this instance as home; post and
//! reply; an edit at `versionCount + 1`; votes, updates and writer records at `seq == stored + 1`; lists paged from state; a
//! `ref` unresolved until read on its chain, verified only when listed, at its topic's home and unpinned; an `msig` author
//! refused (`MsigAuthorPlanned`). Each refusal beside its positive control, with no write and no further read caused by it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::net::FakeNet;
use common::sdk::*;
use pqchat_core::model::{hex, ZERO32};
use pqchat_core::session::Me;
use pqchat_core::topics::{At, List, RefFault, RefState, Vote, PAGE_MAX};
use pqchat_core::{ChainConf, MemoryStore, PqChat, PqChatConfig, PqChatError};
use scaas_sdk::op::KeyRef;
use scaas_sdk::pqchat_records::PqEntryRef;
use serde_json::{json, Value};
use std::sync::atomic::Ordering;
use std::sync::Arc;

const ZERO20: &str = "0x0000000000000000000000000000000000000000";
/// The second chain the app serves (the fake answers every chain alike: its contracts are apart by address).
const OTHER: &str = "other";

fn code<T>(r: Result<T, PqChatError>) -> &'static str {
    match r {
        Ok(_) => "ok",
        Err(e) => e.code(),
    }
}

fn here() -> At {
    At {
        chain: CHAIN.into(),
        instance: HOME.into(),
    }
}

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

fn uid(n: u8) -> String {
    hex(&[n; 32])
}

/// The world, writes answered with a quote (never sent).
async fn ready() -> World {
    let w = world().await;
    w.net.accept.store(true, Ordering::SeqCst);
    w
}

/// The crate over the world's port serving `local` (uid 7) and `other` (uid 8).
fn two_chains(w: &World) -> Arc<PqChat> {
    let mut c = conf();
    c.chains.push(ChainConf {
        chain: OTHER.into(),
        chain_uid: uid(8),
        registry: REGISTRY.into(),
        factory: FACTORY.into(),
    });
    PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        PqChatConfig { chains: c.chains },
    )
}

fn topic_of(net: &FakeNet, contract: &str, tid: &str, home_uid: &str, home: &str, seq: u64) {
    let t = json!({"admin": hex(&[0xad; 32]), "nonce": "1", "homeChain": home_uid, "homeChatContract": home,
        "name": "t", "about": "0x", "openReplies": true});
    net.answer(
        contract,
        "IPqChat.topicOf",
        json!({ "topicId": tid }),
        json!({"t": t, "seq": seq.to_string()}),
    );
}

fn entry_of(net: &FakeNet, contract: &str, eid: &str, tid: &str, r: &PqEntryRef, versions: u64) {
    let e = json!({"topicId": tid, "author": hex(&[0xa0; 32]), "parentId": ZERO32, "depth": "0",
        "ref": {"chainUid": r.chain_uid, "pqchat": r.pqchat, "entryId": r.entry_id, "contentHash": r.content_hash},
        "mediaType": "text/markdown", "body": "0x6869", "sigHash": hex(&[0x5e; 32]), "versionCount": versions.to_string()});
    net.answer(
        contract,
        "IPqChat.entryOf",
        json!({ "entryId": eid }),
        json!({ "0": e }),
    );
}

fn none() -> PqEntryRef {
    PqEntryRef {
        chain_uid: ZERO32.into(),
        pqchat: ZERO20.into(),
        entry_id: ZERO32.into(),
        content_hash: ZERO32.into(),
    }
}

/// The only write prepared: its item's arguments.
fn only(net: &FakeNet, item: &str) -> Value {
    let w = net.writes_of(item);
    assert_eq!((w.len(), net.writes()), (1, 1), "{item}");
    w[0].clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn create_open_replies_home_here() {
    let _one = ONE.lock().await;
    let w = ready().await;
    // negative first, one change: the instance unlisted
    list(&w.net, HOME, 3, 0);
    let e =
        w.pq.create_topic(&here(), &me(&w.alice), 1, "rust", b"about", &payer(&w))
            .await;
    assert_eq!(code(e), "InstanceUnlisted");
    assert_eq!(w.net.writes(), 0);
    // positive control
    list(&w.net, HOME, 3, 1);
    let t =
        w.pq.create_topic(&here(), &me(&w.alice), 1, "rust", b"about", &payer(&w))
            .await
            .unwrap();
    assert_eq!(t.id.as_ref().unwrap().len(), 66);
    let a = &only(&w.net, "IPqChat.createTopic")["t"];
    assert_eq!(a["openReplies"], true);
    assert_eq!(a["homeChain"], uid(7));
    assert_eq!(a["homeChatContract"], HOME);
    assert_eq!(a["admin"], w.alice.ua);
    assert_eq!(a["about"], hex(b"about"));
}

/// An `msig` author is out of this round: every topic write refused before any read or write (CLI-PQC-02).
#[tokio::test(flavor = "multi_thread")]
async fn msig_topic_owner_planned() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let seat = hex(&[0x5e; 32]);
    let m = Me {
        key: KeyRef::Msig {
            ua: seat.clone(),
            slots: vec![],
        },
        ua: seat,
    };
    let (on, p, t) = (here(), payer(&w), uid(0x71));
    assert_eq!(
        code(w.pq.create_topic(&on, &m, 1, "n", b"", &p).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(w.pq.update_topic(&on, &t, &m, "n", b"", false, &p).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(w.pq.set_writer(&on, &t, &m, &w.bob.ua, true, &p).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(w.pq.post(&on, &t, &m, 1, None, None, b"x", &p).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(w.pq.edit(&on, &t, &m, 2, b"x", &p).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(w.pq.vote(&on, &t, &m, Vote::Up, &p).await),
        "MsigAuthorPlanned"
    );
    assert_eq!((w.net.reads.lock().unwrap().len(), w.net.writes()), (0, 0));
    // positive control: the same create by a single key
    list(&w.net, HOME, 3, 1);
    assert_eq!(
        code(w.pq.create_topic(&on, &me(&w.alice), 1, "n", b"", &p).await),
        "ok"
    );
}

/// Updates, writer records and votes at `seq == stored + 1` (P36), read from state.
#[tokio::test(flavor = "multi_thread")]
async fn seq_is_stored_plus_one() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, p, t, e) = (here(), payer(&w), uid(0x71), uid(0xe1));
    w.net.answer(
        HOME,
        "IPqChat.voteOf",
        json!({"entryId": e, "ua": w.carol.ua}),
        json!({"value": "-1", "seq": "5"}),
    );
    w.pq.vote(&on, &e, &me(&w.carol), Vote::Up, &p)
        .await
        .unwrap();
    let v = &only(&w.net, "IPqChat.voteEntry")["v"];
    assert_eq!(
        (v["seq"].as_str(), v["value"].as_str()),
        (Some("6"), Some("1"))
    );
    assert_eq!(v["voter"], w.carol.ua);
    w.net.writes.lock().unwrap().clear();

    w.net.answer(
        HOME,
        "IPqChat.writerOf",
        json!({"topicId": t, "ua": w.bob.ua}),
        json!({"granted": true, "seq": "3"}),
    );
    w.pq.set_writer(&on, &t, &me(&w.alice), &w.bob.ua, false, &p)
        .await
        .unwrap();
    let x = &only(&w.net, "IPqChat.setTopicWriter")["w"];
    assert_eq!(
        (x["seq"].as_str(), &x["granted"]),
        (Some("4"), &json!(false))
    );
    w.net.writes.lock().unwrap().clear();

    topic_of(&w.net, HOME, &t, &uid(7), HOME, 2);
    w.pq.update_topic(&on, &t, &me(&w.alice), "n2", b"a2", false, &p)
        .await
        .unwrap();
    let u = &only(&w.net, "IPqChat.updateTopic")["u"];
    assert_eq!(
        (u["seq"].as_str(), &u["openReplies"]),
        (Some("3"), &json!(false))
    );
}

/// A withdrawn and a down vote carry 0 and −1; the first vote on an entry is `seq` 1.
#[tokio::test(flavor = "multi_thread")]
async fn vote_values() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, p, e) = (here(), payer(&w), uid(0xe1));
    w.net.answer(
        HOME,
        "IPqChat.voteOf",
        json!({"entryId": e, "ua": w.bob.ua}),
        json!({"value": "0", "seq": "0"}),
    );
    for (vote, want) in [(Vote::Down, "-1"), (Vote::Withdraw, "0"), (Vote::Up, "1")] {
        w.net.writes.lock().unwrap().clear();
        w.pq.vote(&on, &e, &me(&w.bob), vote, &p).await.unwrap();
        let v = &only(&w.net, "IPqChat.voteEntry")["v"];
        assert_eq!(
            (v["value"].as_str(), v["seq"].as_str()),
            (Some(want), Some("1"))
        );
    }
}

/// An edit at `versionCount + 1` (P38), Markdown.
#[tokio::test(flavor = "multi_thread")]
async fn edit_at_next_version() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, p, t, e) = (here(), payer(&w), uid(0x71), uid(0xe1));
    entry_of(&w.net, HOME, &e, &t, &none(), 2);
    w.pq.edit(&on, &e, &me(&w.alice), 9, b"v3", &p)
        .await
        .unwrap();
    let d = &only(&w.net, "IPqChat.editEntry")["e"];
    assert_eq!(d["version"], "3");
    assert_eq!(d["mediaType"], "text/markdown");
    assert_eq!(d["body"], hex(b"v3"));
}

/// A post names no parent and no reference; a reply names its parent; a given `ref` is sent as given.
#[tokio::test(flavor = "multi_thread")]
async fn post_and_reply() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, p, t) = (here(), payer(&w), uid(0x71));
    let post =
        w.pq.post(&on, &t, &me(&w.alice), 1, None, None, b"# hi", &p)
            .await
            .unwrap();
    let a = &only(&w.net, "IPqChat.postEntry")["e"];
    assert_eq!(a["parentId"], ZERO32);
    assert_eq!(a["ref"]["chainUid"], ZERO32);
    assert_eq!(a["ref"]["pqchat"], ZERO20);
    let pid = post.id.unwrap();
    w.net.writes.lock().unwrap().clear();
    let r = PqEntryRef {
        chain_uid: uid(8),
        pqchat: REPLICA.into(),
        entry_id: uid(0xe9),
        content_hash: ZERO32.into(),
    };
    let reply =
        w.pq.post(
            &on,
            &t,
            &me(&w.carol),
            1,
            Some(pid.clone()),
            Some(r.clone()),
            b"re",
            &p,
        )
        .await
        .unwrap();
    let a = &only(&w.net, "IPqChat.postEntry")["e"];
    assert_eq!(a["parentId"], pid);
    assert_eq!(a["author"], w.carol.ua);
    assert_eq!(a["ref"]["entryId"], r.entry_id);
    assert_eq!(a["ref"]["pqchat"], REPLICA);
    assert_ne!(reply.id.unwrap(), pid);
}

/// Every list paged from state: at most [`PAGE_MAX`] asked, the answer's ids and total; more ids than asked refused.
#[tokio::test(flavor = "multi_thread")]
async fn pages_from_state() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, t) = (here(), uid(0x71));
    let ids: Vec<String> = (1..=3u8).map(|i| hex(&[i; 32])).collect();
    w.net.answer(
        HOME,
        "IPqChat.posts",
        json!({"topicId": t, "start": "5", "count": PAGE_MAX.to_string()}),
        json!({"ids": ids, "total": "8"}),
    );
    let pg =
        w.pq.page(&on, &List::Posts(t.clone()), 5, 1_000)
            .await
            .unwrap();
    assert_eq!((pg.ids, pg.total), (ids.clone(), 8));
    // an answer above the asked count: refused
    w.net.answer(
        HOME,
        "IPqChat.posts",
        json!({"topicId": t, "start": "0", "count": "2"}),
        json!({"ids": ids, "total": "3"}),
    );
    assert_eq!(
        code(w.pq.page(&on, &List::Posts(t.clone()), 0, 2).await),
        "Internal"
    );
    for (l, item, k, v) in [
        (
            List::Replies(t.clone()),
            "IPqChat.replies",
            "parentId",
            t.clone(),
        ),
        (
            List::ByAuthor(w.bob.ua.clone()),
            "IPqChat.byAuthor",
            "author",
            w.bob.ua.clone(),
        ),
        (
            List::TopicsByAdmin(w.alice.ua.clone()),
            "IPqChat.topicsByAdmin",
            "admin_",
            w.alice.ua.clone(),
        ),
        (
            List::Writers(t.clone()),
            "IPqChat.writersOf",
            "topicId",
            t.clone(),
        ),
    ] {
        w.net.answer(
            HOME,
            item,
            json!({k: v, "start": "0", "count": "1"}),
            json!({"ids": [ids[0]], "total": "1"}),
        );
        assert_eq!(
            w.pq.page(&on, &l, 0, 1).await.unwrap().ids,
            vec![ids[0].clone()]
        );
    }
    w.net.answer(
        HOME,
        "IPqChat.topics",
        json!({"start": "3", "count": "0"}),
        json!({"ids": [], "total": "3"}),
    );
    let pg = w.pq.page(&on, &List::Topics, 3, 0).await.unwrap();
    assert_eq!((pg.ids.len(), pg.total), (0, 3));
    assert_eq!(w.net.writes(), 0);
}

/// The world of a reference on `other`: entry `e` at REPLICA in topic `t`, whose home is `home` on `home_uid`.
fn referenced(w: &World, home_uid: &str, home: &str) -> (PqEntryRef, String) {
    let (t, e) = (uid(0x72), uid(0xe9));
    entry_of(&w.net, REPLICA, &e, &t, &none(), 1);
    topic_of(&w.net, REPLICA, &t, home_uid, home, 0);
    list(&w.net, REPLICA, 3, 1);
    (
        PqEntryRef {
            chain_uid: uid(8),
            pqchat: REPLICA.into(),
            entry_id: e.clone(),
            content_hash: ZERO32.into(),
        },
        e,
    )
}

/// An entry's `ref` is unresolved until read on its chain; an entry without one has none.
#[tokio::test(flavor = "multi_thread")]
async fn ref_unresolved_until_read() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (t, a, b) = (uid(0x71), uid(0xa1), uid(0xa2));
    let r = PqEntryRef {
        chain_uid: uid(8),
        pqchat: REPLICA.into(),
        entry_id: uid(0xe9),
        content_hash: ZERO32.into(),
    };
    entry_of(&w.net, HOME, &a, &t, &r, 1);
    entry_of(&w.net, HOME, &b, &t, &none(), 1);
    let ea = w.pq.entry(&here(), &a).await.unwrap();
    assert_eq!(
        (ea.entry_ref, ea.ref_state),
        (Some(r), Some(RefState::Unresolved))
    );
    let eb = w.pq.entry(&here(), &b).await.unwrap();
    assert_eq!((eb.entry_ref, eb.ref_state), (None, None));
    // nothing on the referenced chain read yet
    assert_eq!(w.net.reads_of("IOpenFactory.infoOf"), 0);
}

/// Verified when the factory lists the instance, the entry's topic names it as home and `contentHash` is zero (positive);
/// unlisted refused (one change).
#[tokio::test(flavor = "multi_thread")]
async fn ref_verified_only_when_listed() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let pq = two_chains(&w);
    let (r, _) = referenced(&w, &uid(8), REPLICA);
    assert_eq!(pq.resolve_ref(&r).await, RefState::Verified);
    list(&w.net, REPLICA, 3, 0);
    assert_eq!(
        pq.resolve_ref(&r).await,
        RefState::Unverified(RefFault::Unlisted)
    );
    list(&w.net, REPLICA, 1, 1);
    assert_eq!(
        pq.resolve_ref(&r).await,
        RefState::Unverified(RefFault::Unlisted)
    );
    assert_eq!(w.net.writes(), 0);
}

/// The referenced entry's topic names another home (Fable P3-4): another instance, or another chain; refused as verified.
#[tokio::test(flavor = "multi_thread")]
async fn ref_refused_at_another_home() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let pq = two_chains(&w);
    let (r, _) = referenced(&w, &uid(8), HOME);
    assert_eq!(
        pq.resolve_ref(&r).await,
        RefState::Unverified(RefFault::OtherHome)
    );
    let (r, _) = referenced(&w, &uid(7), REPLICA);
    assert_eq!(
        pq.resolve_ref(&r).await,
        RefState::Unverified(RefFault::OtherHome)
    );
    // positive control: its home is the referenced instance
    let (r, _) = referenced(&w, &uid(8), REPLICA);
    assert_eq!(pq.resolve_ref(&r).await, RefState::Verified);
    assert_eq!(w.net.writes(), 0);
}

/// A chain the app does not serve, an entry that cannot be read, a pinned `contentHash`: unverified, each by its reason.
#[tokio::test(flavor = "multi_thread")]
async fn ref_unverified_reasons() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let pq = two_chains(&w);
    let (r, _) = referenced(&w, &uid(8), REPLICA);
    assert_eq!(pq.resolve_ref(&r).await, RefState::Verified);
    let far = PqEntryRef {
        chain_uid: uid(9),
        ..r.clone()
    };
    assert_eq!(
        pq.resolve_ref(&far).await,
        RefState::Unverified(RefFault::ChainNotServed)
    );
    let gone = PqEntryRef {
        entry_id: uid(0xee),
        ..r.clone()
    };
    assert_eq!(
        pq.resolve_ref(&gone).await,
        RefState::Unverified(RefFault::Unreadable)
    );
    let pinned = PqEntryRef {
        content_hash: uid(0xc4),
        ..r
    };
    assert_eq!(
        pq.resolve_ref(&pinned).await,
        RefState::Unverified(RefFault::HashUnchecked)
    );
    assert_eq!(w.net.writes(), 0);
}
