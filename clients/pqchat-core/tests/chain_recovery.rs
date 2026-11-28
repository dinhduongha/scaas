// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T9 on a local chain (gate `pqc-chain`; `#[ignore]`: anvil, forge, cast and smartcontracts/evm/lib): recovery from
//! contract state alone through the crate over the SDK. alice's crate creates a session with the home instance as its chain
//! store and stores a message; bob's fresh store finds it from the factory's index and `sessionsOf`, pending, nothing opened
//! or read from its store until he looks and accepts; then the message from `storedRange`. alice's fresh device is asked
//! again (O6 (a)) and makes a new device id.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;
use common::confirmed;

use async_trait::async_trait;
use common::chain::*;
use pqchat_core::consent::Consent;
use pqchat_core::content::Content;
use pqchat_core::net::{Net, SdkNet};
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{CreateSession, Info, StoreEntry};
use pqchat_core::stores::{Delivery, SendOpts};
use pqchat_core::{MemoryStore, PqChat, PqChatError};
use scaas_sdk::app_core::AppCall;
use scaas_sdk::op::KeyRef;
use scaas_sdk::OpState;
use serde_json::Value;
use std::sync::{Arc, Mutex};

/// The SDK's port, every read item recorded.
struct Counted {
    inner: SdkNet,
    reads: Mutex<Vec<&'static str>>,
}

#[async_trait]
impl Net for Counted {
    async fn read(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
    ) -> Result<Value, PqChatError> {
        self.reads.lock().unwrap().push(item);
        self.inner.read(chain, contract, item, args).await
    }
    async fn prepare(
        &self,
        chain: &str,
        contract: &str,
        item: &'static str,
        args: Value,
        payer: &KeyRef,
    ) -> Result<AppCall, PqChatError> {
        self.inner.prepare(chain, contract, item, args, payer).await
    }
    async fn submit(&self, call: AppCall) -> Result<String, PqChatError> {
        self.inner.submit(call).await
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_recovery_from_state() {
    let (l, m) = local(&[(0, true), (1, true)]).await;
    let (alice, bob) = (m[0].clone(), m[1].clone());
    let app = pqchat_core::scope(&l.sdk).unwrap();
    let net = Arc::new(Counted {
        inner: SdkNet {
            sdk: l.sdk.clone(),
            app: app.clone(),
        },
        reads: Mutex::new(vec![]),
    });
    let device = || {
        PqChat::with_net(
            app.clone(),
            net.clone(),
            Arc::new(MemoryStore::new()),
            l.conf(),
        )
    };
    let pa = device();
    let store = StoreEntry::Chain {
        chain_id: "31337".into(),
        chain_uid: l.uid.clone(),
        contract: l.home.clone(),
    };
    let b = confirmed(
        &pa,
        pa.create(CreateSession {
            me: alice.clone(),
            chain: CHAIN.into(),
            home: l.home.clone(),
            nonce: 1,
            members: vec![bob.ua.clone()],
            admins: vec![],
            info: Info {
                stores: vec![store.clone()],
                name: "t9".into(),
                topic: "plan T9".into(),
                matrix: Default::default(),
            },
            payer: l.payer.clone(),
        })
        .await,
    )
    .await
    .unwrap();
    land(&l, b.call.clone()).await;
    let s = SessionRef {
        chain: CHAIN.into(),
        home: l.home.clone(),
        session_id: b.session_id.clone(),
    };
    let d_alice = pa.start_device(Some("alice-anchor".into())).unwrap();
    pa.accept(&s, true).unwrap();
    pa.open_session(&s, &alice).await.unwrap();
    let o = SendOpts {
        payer: l.payer.clone(),
        post: false,
        post_cost_confirmed: false,
    };
    let r = pa
        .send_content(
            &s,
            &alice,
            &Content::Text {
                media_type: None,
                body: "from state".into(),
            },
            Some(1),
            &o,
        )
        .await
        .unwrap();
    let Delivery::Sent(op) = &r.stores[0].1 else {
        panic!("{r:?}")
    };
    assert!(matches!(
        follow(&l.sdk, op.clone()).await,
        OpState::Landed { .. }
    ));
    println!("[t9] session {} created, one message stored", s.session_id);
    // bob's fresh store: found from the factory's index and sessionsOf, pending, nothing opened, no store read
    let pb = device();
    pb.start_device(Some("bob-anchor".into())).unwrap();
    net.reads.lock().unwrap().clear();
    let found = pb.sessions(&bob).await.unwrap();
    let ids: Vec<_> = found.iter().map(|f| &f.s).collect();
    assert_eq!(found.len(), 1, "{ids:?}");
    assert_eq!(
        (&found[0].s, found[0].consent, found[0].epochs),
        (&s, Consent::Pending, 1)
    );
    let reads = net.reads.lock().unwrap().clone();
    for it in [
        "IOpenFactory.contractsPage",
        "IPqChat.sessionCount",
        "IPqChat.sessionsOf",
        "IPqChat.latestEpoch",
    ] {
        assert!(reads.contains(&it), "{it} not read: {reads:?}");
    }
    assert!(!reads.contains(&"IPqChat.storedRange") && !reads.contains(&"IPqChat.wrapAt"));
    assert_eq!(pb.unwrap_calls(), 0);
    let p = pb.preview(&s, &bob).await.unwrap();
    assert_eq!(
        (
            p.info
                .with(|b| serde_json::from_slice::<Info>(b))
                .unwrap()
                .name,
            p.creator.as_str(),
            p.chain_stores
        ),
        ("t9".to_string(), alice.ua.as_str(), 1)
    );
    assert!(!net.reads.lock().unwrap().contains(&"IPqChat.storedRange"));
    pb.accept(&s, false).unwrap();
    let opened = pb.open_session(&s, &bob).await.unwrap();
    assert_eq!(opened.shown, 1);
    assert_eq!(pb.timeline(&s.session_id).len(), 1);
    println!("[t9] bob recovered the session from state and read its message after accepting");
    // alice's fresh device: asked again, a new device id
    let pa2 = device();
    let d2 = pa2.start_device(Some("alice-anchor-2".into())).unwrap();
    assert_ne!(d2, d_alice);
    let f = pa2.sessions(&alice).await.unwrap();
    assert_eq!((f.len(), f[0].consent), (1, Consent::Pending));
}
