// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T10 on a local chain (gate `pqc-chain`; `#[ignore]`: anvil, forge, cast and smartcontracts/evm/lib): public topics by
//! the crate over the SDK into `anvil --enable-tx-gas-limit` after its positive control. The contract judges every right; a
//! refused write is refused by the SDK's quote and nothing is sent: a stranger's post, a revoked writer's post, a reply to a
//! closed topic, another UA's edit. Posts, replies, edits, votes and every list read back from state; a `ref` to an entry of
//! this instance verified, to an unlisted address and with a pinned `contentHash` not.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::called;
use common::chain::*;
use pqchat_core::model::ZERO32;
use pqchat_core::topics::{At, List, Rank, RefFault, RefState, Vote};
use pqchat_core::PqChatError;
use scaas_sdk::pqchat_records::PqEntryRef;

/// A write the quote (the chain's simulation) refused: `Revert`, the contract's error named by `why` (the SDK's quote keeps
/// no revert data, so each refusal stands beside its positive control, one change apart, and the state that differs is read).
fn refused<T>(r: Result<T, PqChatError>, why: &str) -> String {
    match r {
        Ok(_) => panic!("{why}: the write was not refused"),
        Err(e) => assert_eq!(e.code(), "Revert", "{why}"),
    }
    why.to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_topics() {
    let (l, m) = local(&[(0, false), (1, false), (2, false)]).await;
    let (alice, bob, carol) = (m[0].clone(), m[1].clone(), m[2].clone());
    let pq = l.pq();
    let on = At {
        chain: CHAIN.into(),
        instance: l.home.clone(),
    };
    let p = &pqchat_core::confirm::Path::Payer(l.payer.clone());

    // create: openReplies true, home this instance
    let t = called(
        &pq,
        pq.create_topic(&on, &alice, 1, "pqchat", b"# about", p)
            .await,
    )
    .await
    .unwrap();
    let tid = t.0.clone().unwrap();
    land(&l, t.1).await;
    let topic = pq.topic(&on, &tid).await.unwrap();
    assert!(topic.open_replies);
    assert_eq!(
        (
            topic.admin.as_str(),
            topic.home_chain.as_str(),
            topic.home_chat_contract.as_str()
        ),
        (alice.ua.as_str(), l.uid.as_str(), l.home.as_str())
    );
    println!("[topics] topic {tid} created");

    // posts: the admin's lands, a stranger's is refused by the contract (the quote), then a granted writer's lands
    let a1 = called(
        &pq,
        pq.post(&on, &tid, &alice, 1, None, None, b"first", p).await,
    )
    .await
    .unwrap();
    let a1_id = a1.0.clone().unwrap();
    land(&l, a1.1).await;
    let e = refused(
        called(&pq, pq.post(&on, &tid, &bob, 1, None, None, b"no", p).await).await,
        "PqTopicNotWriter",
    );
    assert_eq!(
        l.call("writerOf(bytes32,bytes32)(bool,uint64)", &[&tid, &bob.ua]),
        "false\n0"
    );
    println!("[topics] a stranger's post refused: {e}");
    let g = called(
        &pq,
        pq.set_writer(&on, &tid, &alice, &bob.ua, true, p).await,
    )
    .await
    .unwrap();
    land(&l, g.1).await;
    let b1 = called(
        &pq,
        pq.post(&on, &tid, &bob, 1, None, None, b"bob's", p).await,
    )
    .await
    .unwrap();
    let b1_id = b1.0.clone().unwrap();
    land(&l, b1.1).await;

    // replies: open (a stranger's lands, depth 1, then 2); closed: the stranger refused, the writer lands
    let c1 = called(
        &pq,
        pq.post(&on, &tid, &carol, 1, Some(b1_id.clone()), None, b"re", p)
            .await,
    )
    .await
    .unwrap();
    let c1_id = c1.0.clone().unwrap();
    land(&l, c1.1).await;
    let c2 = called(
        &pq,
        pq.post(&on, &tid, &carol, 2, Some(c1_id.clone()), None, b"re re", p)
            .await,
    )
    .await
    .unwrap();
    let c2_id = c2.0.clone().unwrap();
    land(&l, c2.1).await;
    assert_eq!(pq.entry(&on, &c2_id).await.unwrap().depth, 2);
    let u = called(
        &pq,
        pq.update_topic(&on, &tid, &alice, "pqchat", b"# about", false, p)
            .await,
    )
    .await
    .unwrap();
    land(&l, u.1).await;
    let topic = pq.topic(&on, &tid).await.unwrap();
    assert_eq!((topic.open_replies, topic.seq), (false, 1));
    let e = refused(
        called(
            &pq,
            pq.post(
                &on,
                &tid,
                &carol,
                3,
                Some(b1_id.clone()),
                None,
                b"closed",
                p,
            )
            .await,
        )
        .await,
        "PqTopicNotWriter",
    );
    println!("[topics] a reply to a closed topic refused: {e}");
    let b2 = called(
        &pq,
        pq.post(
            &on,
            &tid,
            &bob,
            2,
            Some(a1_id.clone()),
            None,
            b"writer's reply",
            p,
        )
        .await,
    )
    .await
    .unwrap();
    land(&l, b2.1).await;

    // a revoked writer: its new post refused, its old post still listed
    let g = called(
        &pq,
        pq.set_writer(&on, &tid, &alice, &bob.ua, false, p).await,
    )
    .await
    .unwrap();
    land(&l, g.1).await;
    let e = refused(
        called(
            &pq,
            pq.post(&on, &tid, &bob, 3, None, None, b"late", p).await,
        )
        .await,
        "PqTopicNotWriter",
    );
    assert_eq!(
        l.call("writerOf(bytes32,bytes32)(bool,uint64)", &[&tid, &bob.ua]),
        "false\n2"
    );
    println!("[topics] a revoked writer's post refused: {e}");
    let posts = pq
        .page(&on, &List::Posts(tid.clone()), 0, 10)
        .await
        .unwrap();
    assert_eq!(
        (posts.ids, posts.total),
        (vec![a1_id.clone(), b1_id.clone()], 2)
    );
    let rep = pq
        .page(&on, &List::Replies(b1_id.clone()), 0, 10)
        .await
        .unwrap();
    assert_eq!(rep.ids, vec![c1_id.clone()]);
    assert_eq!(
        pq.page(&on, &List::ByAuthor(carol.ua.clone()), 0, 10)
            .await
            .unwrap()
            .total,
        2
    );
    assert_eq!(
        pq.page(&on, &List::Writers(tid.clone()), 0, 10)
            .await
            .unwrap()
            .ids,
        vec![bob.ua.clone()]
    );
    assert_eq!(
        pq.page(&on, &List::TopicsByAdmin(alice.ua.clone()), 0, 10)
            .await
            .unwrap()
            .ids,
        vec![tid.clone()]
    );
    let all = pq.page(&on, &List::Topics, 0, 10).await.unwrap();
    assert!(all.ids.contains(&tid));

    // edits: the author's version 2 and 3 land; the topic admin's edit of it refused
    for (n, body) in [(10, &b"v2"[..]), (11, &b"v3"[..])] {
        let d = called(&pq, pq.edit(&on, &b1_id, &bob, n, body, p).await)
            .await
            .unwrap();
        land(&l, d.1).await;
    }
    let e = refused(
        called(&pq, pq.edit(&on, &b1_id, &alice, 12, b"not yours", p).await).await,
        "PqTopicNotAuthor",
    );
    println!("[topics] another UA's edit refused: {e}");
    let b = pq.entry(&on, &b1_id).await.unwrap();
    assert_eq!((b.version_count, b.body.as_slice()), (3, &b"v3"[..]));
    let v1 = pq.version_at(&on, &b1_id, 1).await.unwrap();
    assert_eq!((v1.body.as_slice(), v1.edited_at), (&b"bob's"[..], 0));
    assert_eq!(v1.posted_at, b.posted_at, "versionAt: the original's time");
    assert!(
        b.posted_at > 0 && b.edited_at >= b.posted_at,
        "CTR-CHAT-29 times"
    );
    assert_eq!(b.nonce, 11, "CTR-CHAT-31: the latest version's nonce");
    // replies stay on the original id
    assert_eq!(
        pq.page(&on, &List::Replies(b1_id.clone()), 0, 10)
            .await
            .unwrap()
            .ids,
        vec![c1_id.clone()]
    );

    // votes: +1, then -1 moves one count, then 0 withdraws; each at seq + 1
    for (v, score, seq) in [
        (Vote::Up, (1, 0), 1),
        (Vote::Down, (0, 1), 2),
        (Vote::Withdraw, (0, 0), 3),
    ] {
        let x = called(&pq, pq.vote(&on, &b1_id, &carol, v, p).await)
            .await
            .unwrap();
        land(&l, x.1).await;
        assert_eq!(pq.score(&on, &b1_id).await.unwrap(), score);
        assert_eq!(pq.vote_of(&on, &b1_id, &carol.ua).await.unwrap().1, seq);
    }
    let x = called(&pq, pq.vote(&on, &b1_id, &alice, Vote::Up, p).await)
        .await
        .unwrap();
    land(&l, x.1).await;
    assert_eq!(pq.score(&on, &b1_id).await.unwrap(), (1, 0));

    // a ref to an entry of this instance at its topic's home: unresolved, then verified; an unlisted address or a pinned
    // contentHash: not
    let r = PqEntryRef {
        chain_uid: l.uid.clone(),
        pqchat: l.home.clone(),
        entry_id: a1_id.clone(),
        content_hash: ZERO32.into(),
    };
    let x = called(
        &pq,
        pq.post(&on, &tid, &alice, 4, None, Some(r.clone()), b"see also", p)
            .await,
    )
    .await
    .unwrap();
    let x_id = x.0.clone().unwrap();
    land(&l, x.1).await;
    let xe = pq.entry(&on, &x_id).await.unwrap();
    assert_eq!(
        (xe.entry_ref.clone(), xe.ref_state),
        (Some(r.clone()), Some(RefState::Unresolved))
    );
    assert_eq!(pq.resolve_ref(&r).await, RefState::Verified);
    let unlisted = PqEntryRef {
        pqchat: l.registry.clone(),
        ..r.clone()
    };
    assert_eq!(
        pq.resolve_ref(&unlisted).await,
        RefState::Unverified(RefFault::Unlisted)
    );
    // G5 (CTR-CHAT-31): a pinned contentHash names one version, rebuilt from state: bob's post at versions 1 and 2 (an edit)
    // verifies; a hash of no version does not
    for v in [1, 2] {
        let pinned = PqEntryRef {
            entry_id: b1_id.clone(),
            content_hash: pq.content_hash_at(&on, &b1_id, v).await.unwrap(),
            ..r.clone()
        };
        assert_eq!(
            pq.resolve_ref(&pinned).await,
            RefState::VerifiedVersion(v),
            "v{v}"
        );
    }
    let pinned = PqEntryRef {
        content_hash: format!("0x{}", "c4".repeat(32)),
        ..r
    };
    assert_eq!(
        pq.resolve_ref(&pinned).await,
        RefState::Unverified(RefFault::HashMismatch)
    );

    // F6, G7 (CTR-CHAT-30): the feed's rows in one call, newest first, ranked over the window, the fold at the user's threshold
    let posts = List::Posts(tid.clone());
    let total = pq.page(&on, &posts, 0, 0).await.unwrap().total;
    let newest = pq.page_newest(&on, &posts, total, 2).await.unwrap();
    assert_eq!(newest.ids, vec![x_id.clone(), b1_id.clone()]);
    let rows = pq
        .entry_rows(&on, &[b1_id.clone(), a1_id.clone()], &alice.ua, Some(1))
        .await
        .unwrap();
    assert_eq!(
        (
            rows[0].up,
            rows[0].down,
            rows[0].vote,
            rows[0].replies,
            rows[0].version_count
        ),
        (1, 0, 1, 1, 3)
    );
    assert_eq!(
        (rows[1].id.as_str(), rows[1].folded),
        (a1_id.as_str(), false)
    );
    let top = pq
        .ranked(&on, &posts, Rank::Top, total, &alice.ua, None)
        .await
        .unwrap();
    assert_eq!(
        top.rows.first().map(|r| r.1.id.clone()),
        Some(b1_id.clone())
    );
    assert!(top.whole);
    println!("[topics] ok: posts, replies, edits, votes, lists, rows, sorts and refs from state");
}
