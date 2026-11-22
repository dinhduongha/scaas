// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T5 on a local chain (gate `pqc-chain`; `#[ignore]`: anvil, forge, cast and smartcontracts/evm/lib): sessions, epochs,
//! wraps, removal, leave, through the crate over the SDK with real keys and real wraps, the contracts deployed by their own
//! forge script into `anvil --enable-tx-gas-limit` after its positive control.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::chain::*;
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{Built, CreateSession, Info, Me, Rekey, StoreEntry};
use pqchat_core::{DropReason, PqChat};
use std::sync::Arc;

fn info(l: &Local) -> Info {
    Info {
        stores: vec![StoreEntry::Chain {
            chain_id: "31337".into(),
            chain_uid: l.uid.clone(),
            contract: l.home.clone(),
        }],
        name: "t5".into(),
        topic: "plan T5".into(),
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

fn complete(l: &Local, id: &str) -> bool {
    l.call("epochComplete(bytes32)(bool)", &[id]) == "true"
}

fn uas(v: &[&Me]) -> Vec<String> {
    let mut v: Vec<String> = v.iter().map(|m| m.ua.clone()).collect();
    v.sort();
    v
}

fn rekey(l: &Local, by: &Me, nonce: u64, members: &[&Me], admins: &[&Me]) -> Rekey {
    Rekey {
        me: by.clone(),
        nonce,
        members: uas(members),
        admins: uas(admins),
        info: info(l),
        payer: l.payer.clone(),
    }
}

fn create_req(l: &Local, by: &Me, nonce: u64, members: &[&Me]) -> CreateSession {
    CreateSession {
        me: by.clone(),
        chain: CHAIN.into(),
        home: l.home.clone(),
        nonce,
        members: uas(members),
        admins: vec![],
        info: info(l),
        payer: l.payer.clone(),
    }
}

/// `b` landed: its first write, then every `addWraps` the quote sizes, the epoch complete only after the last; the writes'
/// gas limits.
async fn land_all(l: &Local, pq: &Arc<PqChat>, mut b: Built) -> (Built, Vec<u64>) {
    let mut gas = vec![land(l, b.call.clone()).await];
    let s = sref(l, &b.session_id);
    while let Some(c) = pq.next_wraps(&s, &mut b, &l.payer).await.unwrap() {
        assert!(!complete(l, &b.epoch_id), "complete before the last wrap");
        gas.push(land(l, c).await);
    }
    assert!(complete(l, &b.epoch_id));
    (b, gas)
}

fn code<T>(r: Result<T, pqchat_core::PqChatError>) -> &'static str {
    match r {
        Ok(_) => "Ok",
        Err(e) => e.code(),
    }
}

/// A 2-member session in one write; the record at home as built; a plain rekey by a member (a fresh `K`); a membership
/// change refused for a non-admin; a child of a taken slot refused and rebuilt on the winner; `remove` then the admin's
/// rekey without the removed member, who opens nothing of it and authors no rekey; a member who left authors no rekey; a UA
/// without a KEM key skipped and named.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_sessions_epochs_removal_leave() {
    let (l, m) = local(&[(0, true), (1, true), (2, true), (3, false)]).await;
    let (alice, bob, carol, dave) = (m[0].clone(), m[1].clone(), m[2].clone(), m[3].clone());
    println!(
        "[t5] registered alice {}, bob {}, carol {}, dave {} (no KEM key)",
        alice.ua, bob.ua, carol.ua, dave.ua
    );
    let pq = l.pq();
    // the 2-member session, every wrap in one write
    let b = pq.create(create_req(&l, &alice, 1, &[&bob])).await.unwrap();
    assert_eq!(b.sent, 2);
    let (b, gas) = land_all(&l, &pq, b).await;
    assert_eq!(gas.len(), 1);
    println!(
        "[t5] 2-member session {} in one write, gas limit {}",
        b.session_id, gas[0]
    );
    let s = sref(&l, &b.session_id);
    let e0 = pq
        .record_at(CHAIN, &l.home, &b.session_id, &b.session_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (&e0.members, &e0.admins, &e0.wrap_hashes),
        (
            &b.epoch.members,
            &vec![alice.ua.clone()],
            &b.epoch.wrap_hashes
        )
    );
    let ep0 = pq
        .open_epoch(&s, &b.session_id, &bob.key, &bob.ua, None)
        .await
        .unwrap();
    // a plain rekey by bob (a member, no admin): a fresh K
    let r1 = pq
        .rekey(&s, &ep0, rekey(&l, &bob, 2, &[&alice, &bob], &[&alice]))
        .await
        .unwrap();
    assert_eq!(r1.epoch.epoch, 1);
    let (r1, _) = land_all(&l, &pq, r1).await;
    let ep1 = pq
        .open_epoch(&s, &r1.epoch_id, &alice.key, &alice.ua, None)
        .await
        .unwrap();
    assert_eq!(ep1.epoch.members, r1.epoch.members);
    // a membership change by bob: NotAdmin
    let e = pq
        .rekey(
            &s,
            &ep1,
            rekey(&l, &bob, 3, &[&alice, &bob, &carol], &[&alice]),
        )
        .await;
    assert_eq!(code(e), "NotAdmin");
    // a child of e0 now: the slot is taken; rebuilt on the winner
    let e = pq
        .rekey(&s, &ep0, rekey(&l, &alice, 4, &[&alice, &bob], &[&alice]))
        .await;
    assert_eq!(code(e), "EpochTaken");
    assert_eq!(
        pq.child_of(&s, &b.session_id).await.unwrap().as_deref(),
        Some(r1.epoch_id.as_str())
    );
    // alice removes bob from e1, then rekeys listing bob: he is left out; he authors no rekey of e1
    land(
        &l,
        pq.remove(
            &s,
            &ep1.epoch,
            &alice,
            5,
            std::slice::from_ref(&bob.ua),
            &l.payer,
        )
        .await
        .unwrap(),
    )
    .await;
    let e = pq
        .rekey(&s, &ep1, rekey(&l, &bob, 6, &[&alice, &bob], &[&alice]))
        .await;
    assert_eq!(code(e), "NotMember");
    let r2 = pq
        .rekey(
            &s,
            &ep1,
            rekey(&l, &alice, 7, &[&alice, &bob, &carol], &[&alice]),
        )
        .await
        .unwrap();
    assert_eq!(
        r2.epoch
            .members
            .iter()
            .map(|m| m.ua.clone())
            .collect::<Vec<_>>(),
        uas(&[&alice, &carol])
    );
    let (r2, _) = land_all(&l, &pq, r2).await;
    assert_eq!(
        pq.open_epoch(&s, &r2.epoch_id, &bob.key, &bob.ua, None)
            .await
            .err(),
        Some(DropReason::Member)
    );
    let ep2 = pq
        .open_epoch(&s, &r2.epoch_id, &carol.key, &carol.ua, None)
        .await
        .unwrap();
    // carol leaves e2; she authors no rekey of it
    land(
        &l,
        pq.leave(&s, &ep2.epoch, &carol, 8, &l.payer).await.unwrap(),
    )
    .await;
    let e = pq
        .rekey(&s, &ep2, rekey(&l, &carol, 9, &[&alice], &[&alice]))
        .await;
    assert_eq!(code(e), "NotMember");
    // a UA without a KEM key: skipped and named
    let b = pq
        .create(create_req(&l, &alice, 10, &[&bob, &dave]))
        .await
        .unwrap();
    assert_eq!(
        b.epoch
            .members
            .iter()
            .map(|m| m.ua.clone())
            .collect::<Vec<_>>(),
        uas(&[&alice, &bob])
    );
    assert_eq!(
        (b.skipped.len(), b.skipped[0].ua.as_str(), b.skipped[0].code),
        (1, dave.ua.as_str(), "KemKeyMissing")
    );
    land_all(&l, &pq, b).await;
}

/// A 20-member session: the wraps in as many writes as the SDK's quote shows fit, complete only at the last wrap. At this
/// anvil's block gas limit all 20 fit one write under 2^24 (16.2 M measured 2026-11-22); at lower block limits, chosen
/// from that figure (the client assumes none), the first write carries fewer wraps and `addWraps` the rest.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_twenty_members_in_chunks() {
    let accounts: Vec<(u32, bool)> = (0..20).map(|a| (a, true)).collect();
    let (l, ms) = local(&accounts).await;
    let pq = l.pq();
    let refs: Vec<&Me> = ms.iter().collect();
    let mut whole = 0;
    let mut runs = vec![];
    for nonce in 1u64..=3 {
        // the whole session's gas, then three quarters of it, then nine sixteenths
        let limit = match nonce {
            1 => None,
            2 => Some(whole * 3 / 4),
            _ => Some(whole * 9 / 16),
        };
        if let Some(g) = limit {
            l.block_gas(g);
        }
        let b = pq
            .create(create_req(&l, &ms[0], nonce, &refs))
            .await
            .unwrap();
        assert_eq!(b.epoch.members.len(), 20);
        let first = b.sent;
        let (b, gas) = land_all(&l, &pq, b).await;
        println!("[t5] block gas {limit:?}: 20 wraps in {} writes, the first with {first}, gas limits {gas:?}", gas.len());
        assert!(gas.iter().all(|g| limit.is_none_or(|x| *g <= x)));
        let s = sref(&l, &b.session_id);
        let last = ms.last().unwrap();
        assert!(pq
            .open_epoch(&s, &b.session_id, &last.key, &last.ua, None)
            .await
            .is_ok());
        if nonce == 1 {
            whole = gas[0];
        }
        runs.push((first, gas.len()));
    }
    assert_eq!(runs[0], (20, 1));
    assert!(
        runs[1].1 > 1 && runs[2].1 > 1,
        "no chunks at the lower limits: {runs:?}"
    );
    assert!(
        runs[2].0 < runs[1].0,
        "the lower limit gave no smaller chunk: {runs:?}"
    );
}
