// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T7 on a local chain (gate `pqc-chain`; `#[ignore]`: anvil, forge, cast and smartcontracts/evm/lib): a session whose
//! store is its home instance; messages sent through `storeMessage` and posted (`postMessage`) by the crate over the SDK,
//! under the spend consent, into `anvil --enable-tx-gas-limit` after its positive control; the posted calldata is the
//! envelope's inner bytes; the other member reads the posted messages (`messageAt`, K12) and pages the chain store
//! (`storedRange`), a stranger's and an empty envelope under the hint dropped and paged past.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::chain::*;
use pqchat_core::content::Content;
use pqchat_core::message::OpenEpoch;
use pqchat_core::model::hex;
use pqchat_core::net::{Net, SdkNet};
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{CreateSession, Info, StoreEntry};
use pqchat_core::stores::{Delivery, SendOpts};
use pqchat_core::{DropReason, MemoryStore, PqChat};
use scaas_sdk::OpState;
use std::collections::BTreeMap;
use std::sync::Arc;

/// A stranger's envelope: 64 bytes that open under no key.
const JUNK: &str = "0xabababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab";

fn txt(s: &str) -> Content {
    Content::Text {
        media_type: None,
        body: s.into(),
    }
}

async fn landed(l: &Local, d: &Delivery) {
    let Delivery::Sent(op) = d else {
        panic!("not sent: {d:?}")
    };
    let s = follow(&l.sdk, op.clone()).await;
    assert!(matches!(s, OpState::Landed { .. }), "{s:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_store_post_and_read() {
    let (l, m) = local(&[(0, true), (1, true)]).await;
    let (alice, bob) = (m[0].clone(), m[1].clone());
    let app = pqchat_core::scope(&l.sdk).unwrap();
    let net = Arc::new(SdkNet {
        sdk: l.sdk.clone(),
        app: app.clone(),
    });
    let device = || {
        PqChat::with_net(
            app.clone(),
            net.clone(),
            Arc::new(MemoryStore::new()),
            l.conf(),
        )
    };
    let (pa, pb) = (device(), device());
    let store = StoreEntry::Chain {
        chain_id: "31337".into(),
        chain_uid: l.uid.clone(),
        contract: l.home.clone(),
    };
    let info = Info {
        stores: vec![store.clone()],
        name: "t7".into(),
        topic: "plan T7".into(),
        matrix: Default::default(),
    };
    let b = pa
        .create(CreateSession {
            me: alice.clone(),
            chain: CHAIN.into(),
            home: l.home.clone(),
            nonce: 1,
            members: vec![bob.ua.clone()],
            admins: vec![],
            info,
            payer: l.payer.clone(),
        })
        .await
        .unwrap();
    assert_eq!(b.sent, 2);
    land(&l, b.call.clone()).await;
    let sid = b.session_id.clone();
    let s = SessionRef {
        chain: CHAIN.into(),
        home: l.home.clone(),
        session_id: sid.clone(),
    };
    println!("[t7] session {sid} at {}", l.home);
    // alice: the creator's epoch in use, its store confirmed, the spend consented
    let e0 = pa
        .record_at(CHAIN, &l.home, &sid, &sid)
        .await
        .unwrap()
        .unwrap();
    let ea = pa
        .use_epoch(
            &s,
            OpenEpoch {
                chain: CHAIN.into(),
                epoch: e0,
                k: b.k.clone(),
            },
        )
        .await
        .unwrap();
    pa.confirm_stores(&ea).unwrap();
    pa.consent_chain_spend(&sid, true).unwrap();
    // `receipt` is off by default with a chain store
    let rc = Content::Receipt {
        target: hex(&[0x42; 32]),
    };
    let o = SendOpts {
        payer: l.payer.clone(),
        post: true,
        post_cost_confirmed: false,
    };
    assert_eq!(
        pa.send_content(&s, &alice, &rc, None, &o)
            .await
            .unwrap()
            .message_id,
        None
    );
    // one message stored and posted
    let r1 = pa
        .send_content(&s, &alice, &txt("stored and posted"), Some(1), &o)
        .await
        .unwrap();
    landed(&l, &r1.stores[0].1).await;
    landed(&l, r1.post.as_ref().unwrap()).await;
    // the posted calldata is the envelope's inner bytes
    let out = pa.seal(&s, &alice, &txt("posted"), Some(2)).await.unwrap();
    let call = net
        .prepare(
            CHAIN,
            &l.home,
            "IPqChat.postMessage",
            out.post_args(),
            &l.payer,
        )
        .await
        .unwrap();
    assert_eq!(&call.quote.data[10..], &hex(&out.sealed.inner)[2..]);
    let gas = land(&l, call).await;
    println!("[t7] postMessage gas limit {gas}, bucket {}", out.bucket());
    // one stored only
    let o2 = SendOpts {
        post: false,
        ..o.clone()
    };
    let r3 = pa
        .send_content(&s, &alice, &txt("stored"), Some(3), &o2)
        .await
        .unwrap();
    landed(&l, &r3.stores[0].1).await;
    // a stranger's bytes under the hint, and an empty envelope (the hostile writes, by cast)
    let hint = hex(&app.pqchat_hint(b.k.clone()).unwrap());
    for env in [JUNK, "0x"] {
        cast(&[
            "send",
            "--rpc-url",
            &l.rpc,
            "--private-key",
            DEPLOYER,
            &l.home,
            "storeMessage(uint8,bytes8,bytes)",
            "1",
            &hint,
            env,
        ]);
    }
    // bob: his own wrap, the posted messages (K12), then the chain store
    let eb = pb
        .open_epoch(&s, &sid, &bob.key, &bob.ua, None)
        .await
        .unwrap();
    let eb = pb.use_epoch(&s, eb).await.unwrap();
    pb.confirm_stores(&eb).unwrap();
    pb.accept(&s, false).unwrap();
    let p0 = pb.posted(&l.home, 0, &eb).await.unwrap();
    let p1 = pb.posted(&l.home, 1, &eb).await.unwrap();
    assert_eq!(
        (Some(p0.message_id), p1.message_id),
        (r1.message_id.clone(), out.sealed.message_id.clone())
    );
    assert_eq!(pb.read_chain_store(&eb, &store).await.unwrap(), 1);
    assert_eq!(
        pb.dropped(&sid),
        BTreeMap::from([
            (DropReason::Duplicate, 1),
            (DropReason::Envelope, 1),
            (DropReason::Decode, 1)
        ])
    );
    let t = pb.timeline(&sid);
    assert_eq!(t.len(), 3);
    assert!(t.iter().any(|m| Some(&m.id) == r3.message_id.as_ref()));
    // the kept position: nothing new
    assert_eq!(pb.read_chain_store(&eb, &store).await.unwrap(), 0);
    println!(
        "[t7] bob read 2 posted and 1 stored message; a stranger's and an empty envelope dropped"
    );
}
