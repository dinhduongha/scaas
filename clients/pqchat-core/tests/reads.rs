// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T4 (CLI-PQC-13): the reads that choose a key or an epoch are trusted reads, through the SDK's port over two fake
//! chains: a discovered endpoint listed first substitutes `kemKeyOf` or serves a stale `latestEpoch`; the named one is honest.
//! Each refused alone (`NoTrustedEndpoint`), never used beside a named one; a KEM version below the highest kept refused.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::sdk::fake_chain::{fake, serve, Fake};
use common::sdk::*;
use pqchat_core::{MemoryStore, PqChat};
use serde_json::json;
use std::sync::Arc;

/// `checkedOf(id)` answers a KEM key held.
fn checked(c: &Fake, id: &[u8; 32]) {
    answer(
        c,
        REGISTRY,
        "checkedOf(bytes32)",
        id,
        format!("{}{}{}", w(1), w(1), w(1)),
    );
}

async fn two_chains() -> (Fake, String, Fake, String, String) {
    let (honest, rogue) = (fake(), fake());
    let (h, r) = (serve(honest.clone()).await, serve(rogue.clone()).await);
    let g = honest.lock().unwrap().genesis.clone();
    (honest, h, rogue, r, g)
}

/// `kemKeyOf` through the SDK: the discovered endpoint's substituted key never chosen; alone, refused.
#[tokio::test(flavor = "multi_thread")]
async fn kem_key_of_is_trusted() {
    let _one = ONE.lock().await;
    let (honest, h, rogue, r, g) = two_chains().await;
    let (sdk, seed) = sdk_on(vec![discovered(r.clone()), named(h)], g.clone()).await;
    let (bob, carol) = (acc(&seed, 1), acc(&seed, 2));
    for c in [&honest, &rogue] {
        checked(c, &bob.id);
    }
    kem_of(&honest, &bob.id, 2, &bob.kem_pk);
    kem_of(&rogue, &bob.id, 7, &carol.kem_pk);
    let pq = PqChat::new(sdk, Arc::new(MemoryStore::new()), conf()).unwrap();
    assert_eq!(pq.kem_version(CHAIN, &bob.ua).await.unwrap(), (2, false));
    drop(pq);
    // the discovered endpoint alone: refused by name, nothing chosen
    let (sdk, _) = sdk_on(vec![discovered(r)], g).await;
    let pq = PqChat::new(sdk, Arc::new(MemoryStore::new()), conf()).unwrap();
    assert_eq!(
        pq.kem_version(CHAIN, &bob.ua).await.unwrap_err().code(),
        "NoTrustedEndpoint"
    );
}

/// `latestEpoch` through the SDK's port: the discovered endpoint's stale epoch never read beside a named endpoint.
#[tokio::test(flavor = "multi_thread")]
async fn latest_epoch_is_trusted() {
    let _one = ONE.lock().await;
    let (honest, h, rogue, r, g) = two_chains().await;
    let sid = [0x51u8; 32];
    answer(&honest, HOME, "latestEpoch(bytes32)", &sid, "62".repeat(32));
    answer(&rogue, HOME, "latestEpoch(bytes32)", &sid, "61".repeat(32));
    let (sdk, _) = sdk_on(vec![discovered(r.clone()), named(h)], g.clone()).await;
    let app = pqchat_core::scope(&sdk).unwrap();
    let net = pqchat_core::net::SdkNet {
        sdk: sdk.clone(),
        app,
    };
    let a = json!({"sessionId": pqchat_core::model::hex(&sid)});
    let v = pqchat_core::net::Net::read(&net, CHAIN, HOME, "IPqChat.latestEpoch", a.clone())
        .await
        .unwrap();
    assert_eq!(v["epochId"], format!("0x{}", "62".repeat(32)));
    drop(net);
    let (sdk, _) = sdk_on(vec![discovered(r)], g).await;
    let app = pqchat_core::scope(&sdk).unwrap();
    let net = pqchat_core::net::SdkNet {
        sdk: sdk.clone(),
        app,
    };
    let e = pqchat_core::net::Net::read(&net, CHAIN, HOME, "IPqChat.latestEpoch", a)
        .await
        .unwrap_err();
    assert_eq!(e.code(), "NoTrustedEndpoint");
}

/// The highest KEM version seen is kept: a lower one served later is refused; a higher one raises it (an event, no rekey).
#[tokio::test(flavor = "multi_thread")]
async fn kem_version_lowered() {
    let _one = ONE.lock().await;
    let w = world().await;
    let at = |v: u64| {
        w.net.answer(
            REGISTRY,
            "IUARegistry.checkedOf",
            json!({"ua": w.bob.ua}),
            json!({"pop": "1", "pqzPop": "0", "kem": "1"}),
        );
        w.net.answer(REGISTRY, "IUARegistry.kemKeyOf", json!({"ua": w.bob.ua}),
            json!({"version": v.to_string(), "kem": {"scheme": "1", "mlkemEk": "0x", "x25519": pqchat_core::model::ZERO32}, "sig": "0x"}));
    };
    at(2);
    assert_eq!(
        w.pq.kem_version(CHAIN, &w.bob.ua).await.unwrap(),
        (2, false)
    );
    at(3);
    assert_eq!(w.pq.kem_version(CHAIN, &w.bob.ua).await.unwrap(), (3, true));
    at(2);
    assert_eq!(
        w.pq.kem_version(CHAIN, &w.bob.ua).await.unwrap_err().code(),
        "KemVersionLowered"
    );
    // twin: the highest again
    at(3);
    assert_eq!(
        w.pq.kem_version(CHAIN, &w.bob.ua).await.unwrap(),
        (3, false)
    );
    // no usable key
    w.net.answer(
        REGISTRY,
        "IUARegistry.checkedOf",
        json!({"ua": w.carol.ua}),
        json!({"pop": "1", "pqzPop": "0", "kem": "0"}),
    );
    assert_eq!(
        w.pq.kem_version(CHAIN, &w.carol.ua)
            .await
            .unwrap_err()
            .code(),
        "KemKeyMissing"
    );
    assert_eq!(w.net.writes(), 0);
}
