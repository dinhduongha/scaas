// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan 2026-11-23-pqchat-treekem T6a, T6b and T8 on a local chain (gate `pqc-chain`; `#[ignore]`: anvil, forge, cast and
//! smartcontracts/evm/lib): a tree session (`groupMode = 1`) through the crate over the SDK with real keys, the contracts
//! deployed by their own forge script (the release with the tree modules) into `anvil --enable-tx-gas-limit` after its
//! positive control. Created small in one transaction (the record and every wrap), grown by a commit of Adds with their
//! Welcome wraps, a commit by a non-admin, a removal and the commit after it, a leave; each member's replay from state alone
//! gives the same epochs and `K` handles that open the same info; a fresh device (a new store) replays to the same head.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::chain::*;
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{Info, Me, StoreEntry};
use pqchat_core::tree::{CreateTree, TreeCommit, TreeState};
use pqchat_core::PqChat;
use serde_json::{json, Value};
use std::sync::Arc;

fn info(l: &Local) -> Info {
    Info {
        stores: vec![StoreEntry::Chain {
            chain_id: "31337".into(),
            chain_uid: l.uid.clone(),
            contract: l.home.clone(),
        }],
        name: "tree".into(),
        topic: "plan T8".into(),
        matrix: Default::default(),
    }
}

fn sref(l: &Local, sid: &str) -> SessionRef {
    SessionRef {
        chain: CHAIN.into(),
        home: l.home.clone(),
        session_id: sid.into(),
    }
}

/// Every transaction of `c` sent in its plan's order, each landed before the next (C37).
async fn land_commit(
    l: &Local,
    pq: &Arc<PqChat>,
    s: &SessionRef,
    c: &scaas_sdk::pqchat_tree::PqTreeCommitSigned,
    plan: &scaas_sdk::pqchat_tree::PqTreePlan,
) -> usize {
    let mut n = 0;
    while let Some(call) = pq.tree_next(s, c, plan, &l.payer).await.unwrap() {
        land(l, call).await;
        n += 1;
        assert!(n <= plan.txs.len(), "more sends than the plan");
    }
    n
}

/// The leaf `me` holds at the head of `st` with its key's version.
fn leaf_of(st: &TreeState, me: &Me) -> (u32, u64) {
    let head = st.replay.rosters.get(&st.head).unwrap();
    let ua = me.ua.to_ascii_lowercase();
    head.iter()
        .enumerate()
        .find_map(|(i, x)| {
            x.as_ref()
                .filter(|(u, _)| *u == ua)
                .map(|(_, k)| (i as u32, *k))
        })
        .expect("a live leaf")
}

/// The epochs `st` followed, by number.
fn followed(st: &TreeState) -> Vec<u64> {
    st.replay
        .epochs
        .iter()
        .filter(|e| e.state == "followed")
        .map(|e| e.epoch)
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_tree_session() {
    let (l, m) = local(&[(0, true), (1, true), (2, true), (3, true)]).await;
    let (alice, bob, carol, dave) = (m[0].clone(), m[1].clone(), m[2].clone(), m[3].clone());
    // one live PqChat scope at a time: every device a crate over the same scope with its own store
    let app = pqchat_core::scope(&l.sdk).unwrap();
    let device = || {
        PqChat::with_net(
            app.clone(),
            Arc::new(pqchat_core::net::SdkNet {
                sdk: l.sdk.clone(),
                app: app.clone(),
            }),
            Arc::new(pqchat_core::MemoryStore::new()),
            l.conf(),
        )
    };
    let pq = device();
    // created small: alice and bob, the record and both wraps in one transaction
    let created = pq
        .create_tree(CreateTree {
            me: alice.clone(),
            chain: CHAIN.into(),
            home: l.home.clone(),
            nonce: 1,
            admins: vec![],
            members: vec![bob.ua.clone()],
            info: info(&l),
            payer: l.payer.clone(),
        })
        .await
        .unwrap();
    // codex-r3-5: before it lands, a fresh store cannot finish the creation; this store prepares the same call again
    let s0 = sref(&l, &created.session_id);
    match device().tree_resume_create(&s0, &l.payer).await {
        Err(e) => assert_eq!(e.code(), "TreeCreationIncomplete"),
        Ok(_) => panic!("a fresh store finished a creation it does not hold"),
    }
    assert!(pq
        .tree_resume_create(&s0, &l.payer)
        .await
        .unwrap()
        .is_some());
    let gas = land(&l, created.call.clone()).await;
    println!(
        "[tree] session {} created in one transaction, gas limit {gas}",
        created.session_id
    );
    let s = sref(&l, &created.session_id);
    assert!(
        pq.tree_resume_create(&s, &l.payer).await.unwrap().is_none(),
        "complete: nothing to resend"
    );
    let a0 = pq.tree_state(&s, &alice, 0, None).await.unwrap();
    assert_eq!(
        (a0.head, followed(&a0)),
        (0, vec![0]),
        "epoch 0 followed by its creator"
    );
    // bob, on his own device, replays epoch 0 from state alone
    let pb = device();
    let b0 = pb.tree_state(&s, &bob, 0, None).await.unwrap();
    assert_eq!(followed(&b0), vec![0]);
    // alice adds carol and dave in one commit (their Welcome wraps)
    let (leaf_a, _) = leaf_of(&a0, &alice);
    let used = a0.replay.rosters.get(&0).unwrap().len() as u32;
    let adds: Vec<Value> = [&carol, &dave]
        .iter()
        .enumerate()
        .map(|(i, me)| {
            json!({"leaf": used + i as u32, "ua": me.ua.to_ascii_lowercase(), "keyId": 0, "via": format!("0x{}", "00".repeat(32)),
                "kemHash": kem_of(&l, me)})
        })
        .collect();
    let (c1, plan1) = pq
        .tree_commit(
            &s,
            &a0,
            TreeCommit {
                me: alice.clone(),
                key_id: 0,
                removes: vec![],
                adds,
                admins: vec![alice.ua.to_ascii_lowercase()],
                info: None,
                info_reviewed: false,
                payer: l.payer.clone(),
            },
            leaf_a,
        )
        .await
        .unwrap();
    let sent = land_commit(&l, &pq, &s, &c1, &plan1).await;
    println!(
        "[tree] commit 1 (2 Adds) in {sent} transaction(s), plan {:?}",
        plan1.txs.iter().map(|t| t.entry).collect::<Vec<_>>()
    );
    let a1 = pq.tree_state(&s, &alice, 0, None).await.unwrap();
    let c1s = device().tree_state(&s, &carol, 0, None).await.unwrap();
    assert_eq!(a1.head, 1);
    assert!(
        followed(&a1).contains(&1) && followed(&c1s).contains(&1),
        "{:?} {:?}",
        followed(&a1),
        followed(&c1s)
    );
    // a commit by a non-admin (bob refreshes his own leaf)
    let b1 = pb.tree_state(&s, &bob, 0, None).await.unwrap();
    let (leaf_b, _) = leaf_of(&b1, &bob);
    let (c2, plan2) = pb
        .tree_commit(
            &s,
            &b1,
            TreeCommit {
                me: bob.clone(),
                key_id: 0,
                removes: vec![],
                adds: vec![],
                admins: vec![alice.ua.to_ascii_lowercase()],
                info: None,
                info_reviewed: false,
                payer: l.payer.clone(),
            },
            leaf_b,
        )
        .await
        .unwrap();
    land_commit(&l, &pb, &s, &c2, &plan2).await;
    let a2 = pq.tree_state(&s, &alice, 0, None).await.unwrap();
    assert_eq!(a2.head, 2);
    assert!(followed(&a2).contains(&2), "{:?}", followed(&a2));
    // dave leaves (treeLeave names the head); the next commit drops his leaf
    let head_id = a2.replay.epochs.last().unwrap().epoch_id.clone();
    let pd = device();
    let d2 = pd.tree_state(&s, &dave, 0, None).await.unwrap();
    let call = pd
        .tree_leave(&s, &dave, &head_id, 7, &l.payer)
        .await
        .unwrap();
    land(&l, call).await;
    let (leaf_d, key_d) = leaf_of(&d2, &dave);
    let (c3, plan3) = pq
        .tree_commit(
            &s,
            &a2,
            TreeCommit {
                me: alice.clone(),
                key_id: 0,
                removes: vec![
                    json!({"leaf": leaf_d, "ua": dave.ua.to_ascii_lowercase(), "keyId": key_d}),
                ],
                adds: vec![],
                admins: vec![alice.ua.to_ascii_lowercase()],
                info: None,
                info_reviewed: false,
                payer: l.payer.clone(),
            },
            leaf_of(&a2, &alice).0,
        )
        .await
        .unwrap();
    land_commit(&l, &pq, &s, &c3, &plan3).await;
    let a3 = pq.tree_state(&s, &alice, 0, None).await.unwrap();
    assert_eq!(a3.head, 3);
    assert!(a3
        .replay
        .rosters
        .get(&3)
        .unwrap()
        .iter()
        .flatten()
        .all(|(u, _)| *u != dave.ua.to_ascii_lowercase()));
    // a fresh device of carol (a new store) replays to the same head and follows every epoch from her join
    let c3s = device().tree_state(&s, &carol, 0, None).await.unwrap();
    assert_eq!(c3s.head, 3);
    assert_eq!(followed(&c3s), vec![1, 2, 3]);
    // dave, gone, follows nothing after his leave's honouring commit
    let d3 = device().tree_state(&s, &dave, 0, None).await.unwrap();
    assert!(!followed(&d3).contains(&3), "{:?}", followed(&d3));
    println!(
        "[tree] heads: alice {}, carol (fresh) {}, dave stopped at {:?}",
        a3.head, c3s.head, d3.replay.end_epoch
    );
}

/// `kemHash` of `me`'s registry key at version 0 (`keccak256(scheme ‖ ek ‖ x25519)`) through `cast`.
fn kem_of(l: &Local, me: &Me) -> String {
    let out = cast(&[
        "call",
        "--rpc-url",
        &l.rpc,
        &l.registry,
        "kemKeyAt(bytes32,uint64)((uint8,bytes,bytes32),bytes)",
        &me.ua,
        "0",
    ]);
    // `(1, 0x<ek>, 0x<x>)\n0x<sig>`
    let t = out
        .lines()
        .next()
        .unwrap()
        .trim_start_matches('(')
        .trim_end_matches(')')
        .to_string();
    let parts: Vec<&str> = t.split(", ").collect();
    let pk = format!("0x01{}{}", &parts[1][2..], &parts[2][2..]);
    cast(&["keccak", &pk])
}
