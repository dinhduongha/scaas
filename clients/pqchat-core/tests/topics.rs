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

use common::called;
use common::net::FakeNet;
use common::sdk::*;
use pqchat_core::confirm::Path;
use pqchat_core::model::{hex, ZERO32};
use pqchat_core::session::Me;
use pqchat_core::topics::{
    rank, At, EntryRow, List, Rank, RefFault, RefState, Vote, PAGE_MAX, WINDOW,
};
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

fn payer(w: &World) -> Path {
    Path::Payer(KeyRef::Native {
        seed: w.seed.clone(),
        network: "evm".into(),
        index: 0,
    })
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
        chain_id: None,
        registry: REGISTRY.into(),
        factory: FACTORY.into(),
        tree_gas: None,
    });
    PqChat::with_net(
        w.app.clone(),
        w.net.clone(),
        Arc::new(MemoryStore::new()),
        PqChatConfig {
            chains: c.chains,
            ..PqChatConfig::default()
        },
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
        "mediaType": "text/markdown", "body": "0x6869", "sigHash": hex(&[0x5e; 32]), "versionCount": versions.to_string(),
        "postedAt": "1900000000", "editedAt": if versions > 1 { "1900000250" } else { "0" }, "nonce": "41"});
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
    let e = called(
        &w.pq,
        w.pq.create_topic(&here(), &me(&w.alice), 1, "rust", b"about", &payer(&w))
            .await,
    )
    .await;
    assert_eq!(code(e), "InstanceUnlisted");
    assert_eq!(w.net.writes(), 0);
    // positive control
    list(&w.net, HOME, 3, 1);
    let t = called(
        &w.pq,
        w.pq.create_topic(&here(), &me(&w.alice), 1, "rust", b"about", &payer(&w))
            .await,
    )
    .await
    .unwrap();
    assert_eq!(t.0.as_ref().unwrap().len(), 66);
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
        code(called(&w.pq, w.pq.create_topic(&on, &m, 1, "n", b"", &p).await).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(
            called(
                &w.pq,
                w.pq.update_topic(&on, &t, &m, "n", b"", false, &p).await
            )
            .await
        ),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(
            called(
                &w.pq,
                w.pq.set_writer(&on, &t, &m, &w.bob.ua, true, &p).await
            )
            .await
        ),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(called(&w.pq, w.pq.post(&on, &t, &m, 1, None, None, b"x", &p).await).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(called(&w.pq, w.pq.edit(&on, &t, &m, 2, b"x", &p).await).await),
        "MsigAuthorPlanned"
    );
    assert_eq!(
        code(called(&w.pq, w.pq.vote(&on, &t, &m, Vote::Up, &p).await).await),
        "MsigAuthorPlanned"
    );
    assert_eq!((w.net.reads.lock().unwrap().len(), w.net.writes()), (0, 0));
    // positive control: the same create by a single key
    list(&w.net, HOME, 3, 1);
    assert_eq!(
        code(
            called(
                &w.pq,
                w.pq.create_topic(&on, &me(&w.alice), 1, "n", b"", &p).await
            )
            .await
        ),
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
    called(&w.pq, w.pq.vote(&on, &e, &me(&w.carol), Vote::Up, &p).await)
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
    called(
        &w.pq,
        w.pq.set_writer(&on, &t, &me(&w.alice), &w.bob.ua, false, &p)
            .await,
    )
    .await
    .unwrap();
    let x = &only(&w.net, "IPqChat.setTopicWriter")["w"];
    assert_eq!(
        (x["seq"].as_str(), &x["granted"]),
        (Some("4"), &json!(false))
    );
    w.net.writes.lock().unwrap().clear();

    topic_of(&w.net, HOME, &t, &uid(7), HOME, 2);
    called(
        &w.pq,
        w.pq.update_topic(&on, &t, &me(&w.alice), "n2", b"a2", false, &p)
            .await,
    )
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
        called(&w.pq, w.pq.vote(&on, &e, &me(&w.bob), vote, &p).await)
            .await
            .unwrap();
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
    called(&w.pq, w.pq.edit(&on, &e, &me(&w.alice), 9, b"v3", &p).await)
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
    let post = called(
        &w.pq,
        w.pq.post(&on, &t, &me(&w.alice), 1, None, None, b"# hi", &p)
            .await,
    )
    .await
    .unwrap();
    let a = &only(&w.net, "IPqChat.postEntry")["e"];
    assert_eq!(a["parentId"], ZERO32);
    assert_eq!(a["ref"]["chainUid"], ZERO32);
    assert_eq!(a["ref"]["pqchat"], ZERO20);
    let pid = post.0.unwrap();
    w.net.writes.lock().unwrap().clear();
    let r = PqEntryRef {
        chain_uid: uid(8),
        pqchat: REPLICA.into(),
        entry_id: uid(0xe9),
        content_hash: ZERO32.into(),
    };
    let reply = called(
        &w.pq,
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
        .await,
    )
    .await
    .unwrap();
    let a = &only(&w.net, "IPqChat.postEntry")["e"];
    assert_eq!(a["parentId"], pid);
    assert_eq!(a["author"], w.carol.ua);
    assert_eq!(a["ref"]["entryId"], r.entry_id);
    assert_eq!(a["ref"]["pqchat"], REPLICA);
    assert_ne!(reply.0.unwrap(), pid);
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

/// CTR-CHAT-29, CTR-CHAT-31: `entryOf`'s times and latest nonce, `versionAt`'s nonce and times, as the views return them.
#[tokio::test(flavor = "multi_thread")]
async fn entry_and_version_times_and_nonce() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (t, e) = (uid(0x71), uid(0xe1));
    entry_of(&w.net, HOME, &e, &t, &none(), 2);
    let got = w.pq.entry(&here(), &e).await.unwrap();
    assert_eq!(
        (got.posted_at, got.edited_at, got.nonce),
        (1_900_000_000, 1_900_000_250, 41)
    );
    w.net.answer(
        HOME,
        "IPqChat.versionAt",
        json!({"entryId": e, "version": "2"}),
        json!({"mediaType": "text/plain", "body": "0x7632", "sigHash": hex(&[0x5e; 32]), "nonce": "7",
            "postedAt": "1900000000", "editedAt": "1900000250"}),
    );
    let v = w.pq.version_at(&here(), &e, 2).await.unwrap();
    assert_eq!(
        (
            v.media_type.as_str(),
            v.body.as_slice(),
            v.nonce,
            v.posted_at,
            v.edited_at
        ),
        ("text/plain", &b"v2"[..], 7, 1_900_000_000, 1_900_000_250)
    );
    assert_eq!(w.net.writes(), 0);
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
    version_at(&w.net, REPLICA, &pinned.entry_id, 1, "41");
    assert_eq!(
        pq.resolve_ref(&pinned).await,
        RefState::Unverified(RefFault::HashMismatch)
    );
    assert_eq!(w.net.writes(), 0);
}

fn version_at(net: &FakeNet, contract: &str, eid: &str, v: u64, nonce: &str) {
    net.answer(
        contract,
        "IPqChat.versionAt",
        json!({"entryId": eid, "version": v.to_string()}),
        json!({"mediaType": "text/markdown", "body": hex(format!("v{v}").as_bytes()), "sigHash": hex(&[0x5e; 32]),
            "nonce": nonce, "postedAt": "1900000000", "editedAt": if v > 1 { "1900000250" } else { "0" }}),
    );
}

/// G5 (CTR-CHAT-31): a pinned `contentHash` verifies only when it is the typed digest of one version rebuilt from state (the
/// version's nonce, media type and body, the original's place): version 1's `PqTopicEntry` and a later `PqTopicEdit` each
/// verify, newest first; a hash of no version is `HashMismatch` once every version was read, `HashUnchecked` when the entry
/// has more versions than [`REF_VERSIONS_MAX`] and none of the newest is it. A version that cannot be read: `Unreadable`.
#[tokio::test(flavor = "multi_thread")]
async fn a_pinned_content_hash_is_checked() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let pq = two_chains(&w);
    let (r, e) = referenced(&w, &uid(8), REPLICA);
    entry_of(&w.net, REPLICA, &e, &uid(0x72), &none(), 2);
    version_at(&w.net, REPLICA, &e, 1, "41");
    version_at(&w.net, REPLICA, &e, 2, "42");
    let on = At {
        chain: OTHER.into(),
        instance: REPLICA.into(),
    };
    for v in [1, 2] {
        let h = pq.content_hash_at(&on, &e, v).await.unwrap();
        let pinned = PqEntryRef {
            content_hash: h.clone(),
            ..r.clone()
        };
        assert_eq!(
            pq.resolve_ref(&pinned).await,
            RefState::VerifiedVersion(v),
            "v{v}"
        );
        // the same version under another nonce is another digest: one change
        version_at(&w.net, REPLICA, &e, v, "43");
        assert_eq!(
            pq.resolve_ref(&pinned).await,
            RefState::Unverified(RefFault::HashMismatch),
            "v{v} with another nonce"
        );
        version_at(&w.net, REPLICA, &e, v, if v == 1 { "41" } else { "42" });
    }
    // version 1 is its `PqTopicEntry`, rebuilt from the original's place and the version's fields
    let v1 = w
        .app
        .pqchat_entry_hash(scaas_sdk::pqchat_records::PqTopicEntry {
            topic_id: uid(0x72),
            author: hex(&[0xa0; 32]),
            nonce: 41,
            parent_id: ZERO32.into(),
            entry_ref: none(),
            media_type: "text/markdown".into(),
            body: b"v1".to_vec(),
        })
        .unwrap();
    assert_eq!(pq.content_hash_at(&on, &e, 1).await.unwrap(), v1);
    // version 2 is its `PqTopicEdit` (review D-5: an expected value of its own)
    let v2 = w
        .app
        .pqchat_edit_hash(scaas_sdk::pqchat_records::PqTopicEdit {
            entry_id: e.clone(),
            author: hex(&[0xa0; 32]),
            nonce: 42,
            version: 2,
            media_type: "text/markdown".into(),
            body: b"v2".to_vec(),
        })
        .unwrap();
    assert_eq!(pq.content_hash_at(&on, &e, 2).await.unwrap(), v2);
    // version 1 is a `PqTopicEntry`, version 2 a `PqTopicEdit`: their digests differ though the inputs match
    assert_ne!(
        pq.content_hash_at(&on, &e, 1).await.unwrap(),
        pq.content_hash_at(&on, &e, 2).await.unwrap()
    );
    let pinned = PqEntryRef {
        content_hash: pq.content_hash_at(&on, &e, 1).await.unwrap(),
        ..r.clone()
    };
    // more versions than are read: version 1 is not among the newest 64
    entry_of(&w.net, REPLICA, &e, &uid(0x72), &none(), 66);
    for v in 3..=66 {
        version_at(&w.net, REPLICA, &e, v, "44");
    }
    assert_eq!(
        pq.resolve_ref(&pinned).await,
        RefState::Unverified(RefFault::HashUnchecked)
    );
    // 65 versions: version 2 among the newest 64 (control: still checked)
    entry_of(&w.net, REPLICA, &e, &uid(0x72), &none(), 65);
    let at2 = PqEntryRef {
        content_hash: {
            entry_of(&w.net, REPLICA, &e, &uid(0x72), &none(), 2);
            let h = pq.content_hash_at(&on, &e, 2).await.unwrap();
            entry_of(&w.net, REPLICA, &e, &uid(0x72), &none(), 65);
            h
        },
        ..r.clone()
    };
    assert_eq!(pq.resolve_ref(&at2).await, RefState::VerifiedVersion(2));
    assert_eq!(w.net.writes(), 0);
}

/// The six topic writes for `me`, by `path`.
async fn six(w: &World, path: &Path) -> Vec<pqchat_core::topics::TopicWrite> {
    let (on, t, e, m) = (here(), uid(0x71), uid(0xe1), me(&w.alice));
    topic_of(&w.net, HOME, &t, &uid(7), HOME, 2);
    entry_of(&w.net, HOME, &e, &t, &none(), 1);
    w.net.answer(
        HOME,
        "IPqChat.writerOf",
        json!({"topicId": t, "ua": w.bob.ua}),
        json!({"granted": false, "seq": "0"}),
    );
    w.net.answer(
        HOME,
        "IPqChat.voteOf",
        json!({"entryId": e, "ua": w.alice.ua}),
        json!({"value": "0", "seq": "0"}),
    );
    list(&w.net, HOME, 3, 1);
    vec![
        w.pq.create_topic(&on, &m, 1, "n", b"a", path)
            .await
            .unwrap(),
        w.pq.update_topic(&on, &t, &m, "n", b"a", true, path)
            .await
            .unwrap(),
        w.pq.set_writer(&on, &t, &m, &w.bob.ua, true, path)
            .await
            .unwrap(),
        w.pq.post(&on, &t, &m, 2, None, None, b"x", path)
            .await
            .unwrap(),
        w.pq.edit(&on, &e, &m, 3, b"y", path).await.unwrap(),
        w.pq.vote(&on, &e, &m, Vote::Down, path).await.unwrap(),
    ]
}

/// CLI-SDK-36 (owner 2026-11-27): every topic write is built for the review with no signing call, no write and no relay; a
/// review dropped signs nothing; each confirm makes one signing call and still sends nothing. Relayed by default (CLI-PQC-18
/// F3): no payer quote, `dispatch` relays the signed record with its `UASig`, fee 0, and prepares no transaction; on the
/// payer's path the quote is asked with the signature empty and `dispatch` prepares the call.
#[tokio::test(flavor = "multi_thread")]
async fn topic_writes_sign_after_confirm_relayed_by_default() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let signs = || w.net.signs.load(Ordering::SeqCst);
    let relayed = six(&w, &Path::Relayed).await;
    assert_eq!((signs(), w.net.writes()), (0, 0));
    assert!(w.net.relayed.lock().unwrap().is_empty());
    assert!(
        w.net.quotes.lock().unwrap().is_empty(),
        "no payer: no quote"
    );
    assert!(relayed
        .iter()
        .all(|p| p.quote().is_none() && !p.review().is_empty()));
    drop(relayed);
    assert_eq!(signs(), 0, "six reviews dropped: no signature");
    let mut items = vec![];
    for p in six(&w, &Path::Relayed).await {
        let c = w.pq.confirm(p).await.unwrap();
        assert_eq!(c.out.path, Path::Relayed);
        let sent = w.pq.dispatch(&c.out).await.unwrap();
        assert!(matches!(sent, pqchat_core::confirm::Sent::Relayed(r) if r.queued));
        items.push(c.out.item());
    }
    assert_eq!(
        (signs(), w.net.writes()),
        (6, 0),
        "relayed: no transaction prepared"
    );
    let r = w.net.relayed.lock().unwrap().clone();
    assert_eq!(r.iter().map(|x| x.1.as_str()).collect::<Vec<_>>(), items);
    assert_eq!(items.len(), 6);
    for (_, item, args) in &r {
        assert_eq!(args["sig"]["members"], json!([]), "{item}");
        assert_ne!(args["sig"]["signature"], json!("0x"), "{item}: signed");
    }
    // the payer's own transaction: quoted with the signature empty, then called
    let paid = six(&w, &payer(&w)).await;
    let q = w.net.quotes.lock().unwrap().clone();
    assert_eq!(q.len(), 6);
    assert!(q.iter().all(|x| x.2["sig"]["signature"] == json!("0x")));
    assert!(paid.iter().all(|p| p.quote().is_some()));
    for p in paid {
        let c = w.pq.confirm(p).await.unwrap();
        assert!(matches!(
            w.pq.dispatch(&c.out).await.unwrap(),
            pqchat_core::confirm::Sent::Call(_)
        ));
    }
    assert_eq!((signs(), w.net.writes()), (12, 6));
}

/// A relayed write on a port without gateways: `RelayUnavailable` by name, and the same signed record goes by the payer's own
/// transaction instead (`dispatch_paid`).
#[tokio::test(flavor = "multi_thread")]
async fn no_relay_then_the_payers_transaction() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let pq = PqChat::with_net(
        w.app.clone(),
        Arc::new(NoRelay(w.net.clone())),
        Arc::new(MemoryStore::new()),
        conf(),
    );
    list(&w.net, HOME, 3, 1);
    let p = pq
        .create_topic(&here(), &me(&w.alice), 1, "n", b"a", &Path::Relayed)
        .await
        .unwrap();
    let c = pq.confirm(p).await.unwrap();
    assert_eq!(code(pq.dispatch(&c.out).await), "RelayUnavailable");
    let Path::Payer(k) = payer(&w) else {
        unreachable!()
    };
    pq.dispatch_paid(&c.out, &k).await.unwrap();
    assert_eq!(w.net.writes_of("IPqChat.createTopic").len(), 1);
}

/// A port with the fake's reads and writes but no relay (the trait's default).
struct NoRelay(Arc<FakeNet>);

#[async_trait::async_trait]
impl pqchat_core::net::Net for NoRelay {
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.0.read(chain, contract, item, args).await
    }
    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<scaas_sdk::app_core::AppCall, PqChatError> {
        self.0.prepare(chain, contract, item, args, payer).await
    }
    async fn submit(&self, call: scaas_sdk::app_core::AppCall) -> Result<String, PqChatError> {
        self.0.submit(call).await
    }
}

/// CLI-PQV-18's rule in pqchat-core: a fresh call is sent on the first confirm only with the reviewed payer and a `max_cost` no
/// higher; another payer, a higher cost, no reviewed quote or a figure that does not parse asks a second confirm.
#[test]
fn a_fresh_quote_within_the_review_needs_no_second_confirm() {
    use pqchat_core::confirm::Confirmed;
    use scaas_sdk::app_core::AppQuote;
    let k = KeyRef::Native {
        seed: "s".into(),
        network: "evm".into(),
        index: 0,
    };
    let call = |payer: Option<&str>, cost: &str| {
        let mut c = common::net::call(CHAIN, HOME, &k);
        c.quote.quote.payer = payer.map(str::to_string);
        c.quote.quote.max_cost = cost.into();
        c
    };
    let reviewed = |payer: Option<&str>, cost: &str| {
        Some(AppQuote {
            review: vec![],
            quote: Some(call(payer, cost).quote.quote),
        })
    };
    let c = |r| Confirmed {
        out: (),
        reviewed: r,
    };
    let a = Some("0xaa");
    assert!(c(reviewed(a, "100")).within_review(&call(a, "100")));
    assert!(c(reviewed(a, "100")).within_review(&call(a, "99")));
    assert!(
        !c(reviewed(a, "100")).within_review(&call(a, "101")),
        "a higher cost"
    );
    assert!(
        !c(reviewed(a, "100")).within_review(&call(Some("0xbb"), "1")),
        "another payer"
    );
    assert!(
        !c(reviewed(None, "100")).within_review(&call(None, "1")),
        "no payer named"
    );
    assert!(
        !c(None).within_review(&call(a, "1")),
        "relayed or a tree commit: nothing reviewed"
    );
    assert!(
        !c(Some(AppQuote {
            review: vec![],
            quote: None
        }))
        .within_review(&call(a, "1")),
        "an unquoted review"
    );
    assert!(
        !c(reviewed(a, "x")).within_review(&call(a, "1")),
        "a figure that does not parse"
    );
}

fn row(up: u128, down: u128) -> EntryRow {
    EntryRow {
        id: ZERO32.into(),
        topic_id: ZERO32.into(),
        author: ZERO32.into(),
        parent_id: ZERO32.into(),
        depth: 0,
        entry_ref: None,
        media_type: "text/markdown".into(),
        sig_hash: ZERO32.into(),
        version_count: 1,
        posted_at: 0,
        edited_at: 0,
        nonce: 0,
        body_length: 1,
        up,
        down,
        vote: 0,
        replies: 0,
        folded: false,
    }
}

fn order(rows: &[(u128, u128)], sort: Rank) -> Vec<u64> {
    let v: Vec<(u64, EntryRow)> = rows
        .iter()
        .enumerate()
        .map(|(i, (u, d))| (i as u64, row(*u, *d)))
        .collect();
    rank(v, sort).into_iter().map(|(i, _)| i).collect()
}

/// F6: each sort's order, ties by the lower index, the same whatever order the rows come in (every client alike): Top by
/// `up − down`; Controversial by `(up + down)^(min/max)`, 0 when either side is 0; Best by the Wilson lower bound at
/// z = 1.2816 (10/0 above 100/20 above 1/0 above 1/3); counts at the top of `u128` neither panic nor reorder.
#[test]
fn window_sorts_are_deterministic() {
    let rows = [(5, 1), (1, 5), (3, 3), (5, 1), (0, 0), (10, 9)];
    assert_eq!(order(&rows, Rank::Top), vec![0, 3, 5, 2, 4, 1]);
    // (10,9): 19^0.9 ≈ 14.1; (3,3): 6; (5,1) and (1,5): 6^0.2 ≈ 1.43; (0,0): 0
    assert_eq!(order(&rows, Rank::Controversial), vec![5, 2, 0, 1, 3, 4]);
    // no up-vote scores 0 exactly: 0/9 ties with 0/0 and goes by its higher index (review A-5: f64 noise put it first)
    let best = [(1, 0), (100, 20), (10, 0), (0, 0), (1, 3), (0, 9)];
    assert_eq!(order(&best, Rank::Best), vec![2, 1, 0, 4, 3, 5]);
    // the same rows reversed: the same order by index
    for sort in [Rank::Top, Rank::Controversial, Rank::Best] {
        let v: Vec<(u64, EntryRow)> = rows
            .iter()
            .enumerate()
            .map(|(i, (u, d))| (i as u64, row(*u, *d)))
            .rev()
            .collect();
        let got: Vec<u64> = rank(v, sort).into_iter().map(|(i, _)| i).collect();
        assert_eq!(got, order(&rows, sort), "{sort:?}");
    }
    let big = [(u128::MAX, u128::MAX - 1), (u128::MAX, 0), (2, 1)];
    assert_eq!(order(&big, Rank::Top), vec![1, 0, 2]);
    assert_eq!(order(&big, Rank::Controversial), vec![0, 2, 1]);
    assert_eq!(order(&big, Rank::Best), vec![1, 0, 2]);
}

fn rows_answer(net: &FakeNet, ids: &[String], viewer: &str, scores: &[(u128, u128)]) {
    let rows: Vec<Value> = scores
        .iter()
        .map(|(u, d)| {
            json!({"topicId": uid(0x71), "author": hex(&[0xa0; 32]), "parentId": ZERO32, "depth": "0",
                "ref": {"chainUid": ZERO32, "pqchat": ZERO20, "entryId": ZERO32, "contentHash": ZERO32},
                "mediaType": "text/markdown", "sigHash": hex(&[0x5e; 32]), "versionCount": "1", "postedAt": "1900000000",
                "editedAt": "0", "nonce": "1", "bodyLength": "2", "up": u.to_string(), "down": d.to_string(), "vote": "-1",
                "replies": "3"})
        })
        .collect();
    net.answer(
        HOME,
        "IPqChat.entryRows",
        json!({"entryIds": ids, "viewer": viewer}),
        json!({ "rows": rows }),
    );
}

/// G7, CTR-CHAT-30: `entryRows` read as one row per id (the viewer's vote, direct replies), folded at the user's threshold
/// (`down − up` of at least it; `None` folds nothing) and never dropped; a row count other than the ids' refused; a page
/// newest first below `before`.
#[tokio::test(flavor = "multi_thread")]
async fn entry_rows_fold_and_newest_pages() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let on = here();
    let ids = vec![uid(0xe1), uid(0xe2), uid(0xe3)];
    let v = w.alice.ua.clone();
    rows_answer(&w.net, &ids, &v, &[(1, 6), (2, 6), (0, 0)]);
    let r = w.pq.entry_rows(&on, &ids, &v, Some(5)).await.unwrap();
    assert_eq!(r.len(), 3);
    assert_eq!((r[0].vote, r[0].replies, r[0].body_length), (-1, 3, 2));
    assert_eq!(
        r.iter().map(|x| x.folded).collect::<Vec<_>>(),
        vec![true, false, false]
    );
    let r = w.pq.entry_rows(&on, &ids, &v, Some(4)).await.unwrap();
    assert_eq!(
        r.iter().map(|x| x.folded).collect::<Vec<_>>(),
        vec![true, true, false]
    );
    let r = w.pq.entry_rows(&on, &ids, &v, None).await.unwrap();
    assert!(r.iter().all(|x| !x.folded));
    rows_answer(&w.net, &ids, &v, &[(1, 6), (2, 6)]);
    assert_eq!(code(w.pq.entry_rows(&on, &ids, &v, None).await), "Internal");
    // newest first below a snapshot total: [5, 7) read, reversed
    let t = uid(0x71);
    w.net.answer(
        HOME,
        "IPqChat.posts",
        json!({"topicId": t, "start": "5", "count": "2"}),
        json!({"ids": [uid(5), uid(6)], "total": "9"}),
    );
    let p =
        w.pq.page_newest(&on, &List::Posts(t.clone()), 7, 2)
            .await
            .unwrap();
    assert_eq!((p.ids, p.total), (vec![uid(6), uid(5)], 9));
    assert_eq!(w.net.writes(), 0);
}

/// F6: a window of the newest [`WINDOW`] ids read by pages of [`PAGE_MAX`] against the snapshot (Top), the first ones for
/// Best; a longer list says it was not scored whole; a repeated id is ranked once.
#[tokio::test(flavor = "multi_thread")]
async fn a_window_is_the_newest_256() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, t, v) = (here(), uid(0x71), w.alice.ua.clone());
    let total = WINDOW + 10;
    let id = |i: u64| {
        hex(&{
            let mut b = [0u8; 32];
            b[24..].copy_from_slice(&i.to_be_bytes());
            b
        })
    };
    let mut at = 10;
    while at < total {
        let ids: Vec<String> = (at..at + PAGE_MAX).map(id).collect();
        w.net.answer(
            HOME,
            "IPqChat.posts",
            json!({"topicId": t, "start": at.to_string(), "count": PAGE_MAX.to_string()}),
            json!({"ids": ids, "total": total.to_string()}),
        );
        rows_answer(&w.net, &ids, &v, &vec![(1, 0); ids.len()]);
        at += PAGE_MAX;
    }
    // the newest id scores highest
    let last: Vec<String> = (total - PAGE_MAX..total).map(id).collect();
    let mut s = vec![(1, 0); PAGE_MAX as usize];
    s[PAGE_MAX as usize - 1] = (9, 0);
    rows_answer(&w.net, &last, &v, &s);
    let r =
        w.pq.ranked(&on, &List::Posts(t.clone()), Rank::Top, total, &v, None)
            .await
            .unwrap();
    assert_eq!(
        (r.rows.len() as u64, r.whole, r.total),
        (WINDOW, false, total)
    );
    assert_eq!(r.rows[0], (total - 1, r.rows[0].1.clone()));
    assert_eq!(r.rows[0].1.up, 9);
    assert_eq!(r.rows[1].0, 10, "ties by the lower index");
    assert_eq!(w.net.reads_of("IPqChat.posts"), 4);
    assert_eq!(w.net.reads_of("IPqChat.entryRows"), 4);
}

/// Review A-11: a repeated id is ranked once; Best ranks the first window of replies and Controversial the newest, through
/// `ranked`; a window with a short page is not `whole` (review A-9).
#[tokio::test(flavor = "multi_thread")]
async fn ranked_reads_each_id_once() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let (on, p, v) = (here(), uid(0xe0), w.alice.ua.clone());
    let ids = vec![uid(0xe1), uid(0xe2), uid(0xe1), uid(0xe3)];
    w.net.answer(
        HOME,
        "IPqChat.replies",
        json!({"parentId": p, "start": "0", "count": "4"}),
        json!({"ids": ids, "total": "4"}),
    );
    let once = vec![uid(0xe1), uid(0xe2), uid(0xe3)];
    rows_answer(&w.net, &once, &v, &[(1, 3), (5, 0), (2, 2)]);
    let list = List::Replies(p.clone());
    let r =
        w.pq.ranked(&on, &list, Rank::Best, 4, &v, None)
            .await
            .unwrap();
    let order: Vec<(u64, String)> = r.rows.iter().map(|(i, x)| (*i, x.id.clone())).collect();
    assert_eq!(
        order,
        vec![(1, uid(0xe2)), (3, uid(0xe3)), (0, uid(0xe1))],
        "e1 once, at its first index"
    );
    assert!(!r.whole, "4 indexes, 3 distinct ids");
    let r =
        w.pq.ranked(&on, &list, Rank::Controversial, 4, &v, None)
            .await
            .unwrap();
    assert_eq!(
        r.rows[0].1.id,
        uid(0xe3),
        "2 up, 2 down: the most controversial"
    );
    // a short page: fewer ids than the snapshot says
    w.net.answer(
        HOME,
        "IPqChat.replies",
        json!({"parentId": p, "start": "0", "count": "4"}),
        json!({"ids": once, "total": "4"}),
    );
    w.net.answer(
        HOME,
        "IPqChat.replies",
        json!({"parentId": p, "start": "3", "count": "1"}),
        json!({"ids": [], "total": "4"}),
    );
    let r =
        w.pq.ranked(&on, &list, Rank::Top, 4, &v, None)
            .await
            .unwrap();
    assert_eq!((r.rows.len(), r.whole), (3, false));
}

/// Review A-11: on the SDK's port a chain whose profile lists no gateway answers a relayed write `RelayUnavailable` by the
/// crate's name (the SDK's `SubmitPathNone`), nothing sent.
#[tokio::test(flavor = "multi_thread")]
async fn no_gateway_is_relay_unavailable() {
    let _one = ONE.lock().await;
    let w = ready().await;
    let sdk_net = pqchat_core::net::SdkNet {
        sdk: w.sdk.clone(),
        app: w.app.clone(),
    };
    let args = json!({"v": {"entryId": uid(0xe1), "voter": w.alice.ua, "value": "1", "seq": "1"},
        "sig": {"keyData": "0x01", "signature": "0x02", "members": []}});
    let e = pqchat_core::net::Net::relay(&sdk_net, CHAIN, HOME, "IPqChat.voteEntry", args).await;
    assert_eq!(code(e), "RelayUnavailable");
    assert!(w.chain.lock().unwrap().bodies.is_empty(), "nothing posted");
}

/// Review E-1 (CLI-PQC-21, CLI-PQC-13): the views a signed topic record's `seq` or `version` comes from are trusted reads; the
/// feed views stay plain.
#[test]
fn signed_record_inputs_are_trusted_reads() {
    use pqchat_core::net::{trust, Trust};
    for item in [
        "IPqChat.topicOf",
        "IPqChat.writerOf",
        "IPqChat.voteOf",
        "IPqChat.entryOf",
    ] {
        assert_eq!(trust(item).unwrap(), Trust::Trusted, "{item}");
    }
    for item in ["IPqChat.posts", "IPqChat.replies", "IPqChat.entryRows"] {
        assert_eq!(trust(item).unwrap(), Trust::Plain, "{item}");
    }
}
