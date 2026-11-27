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
use pqchat_core::content::Content;
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{Info, Me, StoreEntry};
use pqchat_core::stores::{Delivery, SendOpts};
use pqchat_core::tree::{CreateTree, TreeBuilt, TreeCommit, TreeState};
use pqchat_core::PqChat;
use scaas_sdk::OpState;
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

/// A store's send landed on the chain.
async fn landed(l: &Local, d: &Delivery) {
    let Delivery::Sent(op) = d else {
        panic!("not sent: {d:?}")
    };
    let st = follow(&l.sdk, op.clone()).await;
    assert!(matches!(st, OpState::Landed { .. }), "{st:?}");
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
    // alice's device keeps its store at hand: the path-less `try` counter (C47) is read below
    let alice_store = Arc::new(pqchat_core::MemoryStore::new());
    let pq = PqChat::with_net(
        app.clone(),
        Arc::new(pqchat_core::net::SdkNet {
            sdk: l.sdk.clone(),
            app: app.clone(),
        }),
        alice_store.clone(),
        l.conf(),
    );
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
            path_refresh_bound: None,
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
    let req1 = TreeCommit {
        me: alice.clone(),
        key_id: 0,
        removes: vec![],
        adds,
        admins: vec![alice.ua.to_ascii_lowercase()],
        info: None,
        info_reviewed: false,
        payer: l.payer.clone(),
        refresh: false,
    };
    // the path-less delta §6.5, §9 (the quote) and §6.4 (the deferred cost), on a device with the chain's rows: the
    // path-less build names both prices, its own and "add and refresh"'s (the same Adds as a path commit, dearer), and the
    // deferred cost of its two leaves (`sincePath` 0 plus 2: 2 ciphertexts); a path commit names one price
    let rows = include_str!("../../scaas-sdk/gas/pqchat-tree.json");
    let mut conf = l.conf();
    conf.chains[0].tree_gas = Some(rows.into());
    let quoting = PqChat::with_net(
        app.clone(),
        Arc::new(pqchat_core::net::SdkNet {
            sdk: l.sdk.clone(),
            app: app.clone(),
        }),
        Arc::new(pqchat_core::MemoryStore::new()),
        conf,
    );
    let q = quoting
        .tree_commit_plan(&s, &a0, &req1, leaf_a)
        .await
        .unwrap();
    let asked = |p: &[scaas_sdk::pqchat_tree::PqTreePlan]| -> u64 {
        p.iter().flat_map(|p| &p.txs).map(|t| t.gas.asked()).sum()
    };
    let refresh = q.refresh.as_deref().expect("the refresh price");
    assert!(
        asked(refresh) > asked(&q.plans),
        "{} vs {}",
        asked(refresh),
        asked(&q.plans)
    );
    let g: scaas_sdk::pqchat_tree::PqTreeGas = serde_json::from_str(rows).unwrap();
    let (n, d) = q.deferred.expect("the deferred cost");
    assert_eq!((n, d), (2, scaas_sdk::pqchat_tree::deferred_cost(&g, 2)));
    println!(
        "[tree] quote: path-less {} asked, add and refresh {} asked; {}",
        asked(&q.plans),
        asked(refresh),
        pqchat_core::tree::deferred_line(n, d)
    );
    let p = quoting
        .tree_commit_plan(
            &s,
            &a0,
            &TreeCommit {
                refresh: true,
                ..req1.clone()
            },
            leaf_a,
        )
        .await
        .unwrap();
    assert!(
        p.refresh.is_none() && p.deferred.is_none(),
        "a path commit names one price"
    );
    let TreeBuilt {
        signed: c1,
        plan: plan1,
        head_confirmed,
        adds_left,
        ..
    } = pq.tree_commit(&s, &a0, req1, leaf_a).await.unwrap();
    // R2-C-5 of the TreeKEM T4-T9 re-check: one endpoint, no strict majority: an Add built with its head not confirmed
    assert!(adds_left.is_empty(), "two Adds: one commit");
    // the path-less delta §6.5 (C46): an Adds-only change on the head the device holds goes path-less by default, relayed as
    // any commit (the record and its two Welcome wraps, the last one held back when it is sent in several transactions)
    assert_eq!(c1.record["pathless"], json!(true), "the default form");
    assert!(
        plan1.txs.iter().all(|t| !t.entry.starts_with("addPath")),
        "no path piece"
    );
    assert!(
        !head_confirmed && a0.unconfirmed,
        "one endpoint confirms nothing"
    );
    // C47: the device's next path-less Add on this head takes the next `try`
    let tries: Value = pqchat_core::Items(&*alice_store)
        .get(&format!("tree/tries/{}", s.session_id.to_ascii_lowercase()))
        .unwrap()
        .expect("the try counter");
    assert_eq!(
        (tries["parent"].clone(), tries["next"].clone()),
        (c1.record["parentEpochId"].clone(), json!(1)),
        "{tries}"
    );
    let sent = land_commit(&l, &pq, &s, &c1, &plan1).await;
    println!(
        "[tree] commit 1 (2 Adds) in {sent} transaction(s), plan {:?}",
        plan1.txs.iter().map(|t| t.entry).collect::<Vec<_>>()
    );
    let a1 = pq.tree_state(&s, &alice, 0, None).await.unwrap();
    let pc = device();
    assert_eq!(
        a1.replay.since_path, 2,
        "two path-less leaves since the last path commit"
    );
    let c1s = pc.tree_state(&s, &carol, 0, None).await.unwrap();
    assert_eq!(a1.head, 1);
    assert!(
        followed(&a1).contains(&1) && followed(&c1s).contains(&1),
        "{:?} {:?}",
        followed(&a1),
        followed(&c1s)
    );
    // C-3 = D-7 of the T4-T9 review: a message sent under the tree epoch opened from the replay (its info in force names the
    // chain store) and received by carol under the same epoch from her own replay; R11: no receipt by default
    let head1 = a1.replay.epochs.last().unwrap().epoch_id.clone();
    let ea = pq
        .use_epoch(&s, pq.tree_open(&s, &a1, &head1).unwrap())
        .await
        .unwrap();
    pq.confirm_stores(&ea).unwrap();
    pq.consent_chain_spend(&s.session_id, true).unwrap();
    let o = SendOpts {
        payer: l.payer.clone(),
        post: false,
        post_cost_confirmed: false,
    };
    let text = Content::Text {
        media_type: None,
        body: "under the tree".into(),
    };
    let sent = pq
        .send_content(&s, &alice, &text, Some(1), &o)
        .await
        .unwrap();
    landed(&l, &sent.stores[0].1).await;
    let ec = pc
        .use_epoch(&s, pc.tree_open(&s, &c1s, &head1).unwrap())
        .await
        .unwrap();
    pc.confirm_stores(&ec).unwrap();
    pc.accept(&s, true).unwrap();
    let store = info(&l).stores[0].clone();
    assert_eq!(pc.read_chain_store(&ec, &store).await.unwrap(), 1);
    assert!(pc
        .timeline(&s.session_id)
        .iter()
        .any(|m| Some(&m.id) == sent.message_id.as_ref()));
    let rc = Content::Receipt {
        target: sent.message_id.clone().unwrap(),
    };
    assert_eq!(
        pc.send_content(&s, &carol, &rc, None, &o)
            .await
            .unwrap()
            .message_id,
        None,
        "R11: no receipt from a tree session by default"
    );
    println!("[tree] a message sent and received under tree epoch 1; no receipt");
    // a commit by a non-admin (bob refreshes his own leaf)
    let b1 = pb.tree_state(&s, &bob, 0, None).await.unwrap();
    let (leaf_b, _) = leaf_of(&b1, &bob);
    let TreeBuilt {
        signed: c2,
        plan: plan2,
        ..
    } = pb
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
                refresh: false,
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
    let TreeBuilt {
        signed: c3,
        plan: plan3,
        ..
    } = pq
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
                refresh: false,
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
