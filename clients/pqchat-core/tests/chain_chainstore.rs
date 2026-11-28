// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The `chainstore` entry on a local chain (owner 2026-11-28; gate `pqc-chain`; `#[ignore]`: anvil, forge, cast, python3 and
//! smartcontracts/evm/lib): `PqChatStore` (CTR-CHAT-22) deployed at its pinned address by its own deploy path
//! (`deploy_pqchatstore.py local --rpc`: deploy, deploy again with no send, the probe), a session over a Matrix room (the
//! in-memory fake) and that store; the crate over the SDK writes the same envelope to both, the store's state holds it, bob
//! opens the session and reads it from the store, the room's copy a duplicate. The pinned code hash (spec 2026-11-21 §5.5, C4)
//! is the release data's, the forge build's and the chain's. An address without code and a `PqChat` (other code) listed as
//! `chainstore` entries are neither written nor read (`InstanceUnlisted`), beside the store that is.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;
use common::confirmed;

use common::chain::*;
use common::matrix::{Client, Server};
use pqchat_core::content::Content;
use pqchat_core::matrix::RoomUse;
use pqchat_core::message::OpenEpoch;
use pqchat_core::model::hex;
use pqchat_core::net::SdkNet;
use pqchat_core::reads::SessionRef;
use pqchat_core::session::{CreateSession, Info, Me, StoreEntry};
use pqchat_core::stores::{Delivery, SendOpts};
use pqchat_core::{DropReason, MemoryStore, PqChat};
use scaas_sdk::OpState;
use std::collections::BTreeMap;
use std::process::Command;
use std::sync::Arc;

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

/// `PqChatStore` deployed on the chain at `rpc` by `deploy_pqchatstore.py local --rpc` (its forge build in a temp dir made
/// here and removed); its pinned address, lower case, and the build's runtime code hash.
fn deploy_store(rpc: &str) -> (String, String) {
    let dir = std::env::temp_dir().join(format!("pqchat-chainstore-{}", std::process::id()));
    let (out, cache) = (dir.join("out"), dir.join("cache"));
    let built = Command::new("forge")
        .current_dir(sc())
        .args([
            "build",
            "src/pqchat/PqChatStore.sol",
            "test/forkcheck",
            "--extra-output",
            "evm.legacyAssembly",
            "--silent",
            "--out",
            out.to_str().unwrap(),
            "--cache-path",
            cache.to_str().unwrap(),
        ])
        .status()
        .expect("forge in PATH");
    let runtime = built.success().then(|| {
        let a: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(out.join("PqChatStore.sol/PqChatStore.json")).unwrap(),
        )
        .unwrap();
        cast(&["keccak", a["deployedBytecode"]["object"].as_str().unwrap()])
    });
    let deployed = built.success()
        && Command::new("python3")
            .current_dir(sc())
            .args([
                "-I",
                "script/deploy_pqchatstore.py",
                "local",
                "--out",
                out.to_str().unwrap(),
                "--rpc",
                rpc,
            ])
            .status()
            .expect("python3 in PATH")
            .success();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(built.success(), "forge build of PqChatStore failed");
    assert!(deployed, "deploy_pqchatstore.py local --rpc failed");
    let rel: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(format!("{}/release-data/PqChatStore.json", sc())).unwrap(),
    )
    .unwrap();
    (
        rel["address"].as_str().unwrap().to_ascii_lowercase(),
        runtime.unwrap().to_ascii_lowercase(),
    )
}

fn chainstore(l: &Local, contract: &str) -> StoreEntry {
    StoreEntry::Chainstore {
        chain_id: "31337".into(),
        chain_uid: l.uid.clone(),
        contract: contract.into(),
    }
}

/// The creator's session over `stores` landed, its epoch in use on `pa`, its stores confirmed and their spend consented.
async fn session(
    l: &Local,
    pa: &PqChat,
    alice: &Me,
    bob: &Me,
    nonce: u64,
    stores: Vec<StoreEntry>,
    matrix: BTreeMap<String, String>,
) -> SessionRef {
    let info = Info {
        stores,
        name: "chainstore".into(),
        topic: String::new(),
        matrix,
    };
    let b = confirmed(
        pa,
        pa.create(CreateSession {
            me: alice.clone(),
            chain: CHAIN.into(),
            home: l.home.clone(),
            nonce,
            members: vec![bob.ua.clone()],
            admins: vec![],
            info,
            payer: l.payer.clone(),
        })
        .await,
    )
    .await
    .unwrap();
    land(l, b.call.clone()).await;
    let sid = b.session_id.clone();
    let s = SessionRef {
        chain: CHAIN.into(),
        home: l.home.clone(),
        session_id: sid.clone(),
    };
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
    s
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs anvil, forge, cast, python3 and smartcontracts/evm/lib (gate pqc-chain)"]
async fn chain_chainstore_over_matrix_and_pqchatstore() {
    let (l, m) = local(&[(0, true), (1, true)]).await;
    let (alice, bob) = (m[0].clone(), m[1].clone());
    let (store, built) = deploy_store(&l.rpc);
    // C4's pin: the release data's runtime code hash (the chain's conf) is the forge build's (`bytecode_hash = none`) and the
    // code at the store's address
    let code = cast(&["code", "--rpc-url", &l.rpc, &store]);
    let onchain = cast(&["keccak", &code]).to_ascii_lowercase();
    assert_eq!(
        (store_code_hash(), onchain),
        (built.clone(), built),
        "the pin, the build, the chain"
    );
    println!("[chainstore] PqChatStore at {store}, its code hash the pinned one");
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
    let server = Server::new();
    let (ta, tb) = (
        Client::new(&server, "@alice:fake.local"),
        Client::new(&server, "@bob:fake.local"),
    );
    pa.attach_matrix(ta.clone());
    let room = pa.create_room().await.unwrap();
    let cs = chainstore(&l, &store);
    let ids = BTreeMap::from([
        (alice.ua.clone(), ta.user.clone()),
        (bob.ua.clone(), tb.user.clone()),
    ]);
    let s = session(
        &l,
        &pa,
        &alice,
        &bob,
        1,
        vec![StoreEntry::Matrix { room: room.clone() }, cs.clone()],
        ids,
    )
    .await;
    println!(
        "[chainstore] session {} over {room} and the store",
        s.session_id
    );
    let o = SendOpts {
        payer: l.payer.clone(),
        post: false,
        post_cost_confirmed: false,
    };
    // one send, the same envelope to the room and the store
    let r = pa
        .send_content(&s, &alice, &txt("over both"), None, &o)
        .await
        .unwrap();
    assert_eq!(r.stores[0].1, Delivery::Sent(String::new()));
    landed(&l, &r.stores[1].1).await;
    let ev = server.events_of(&room);
    assert_eq!(ev.len(), 1);
    let (hint, env) = pqchat_core::matrix::parse(&ev[0].content).unwrap();
    let kept = cast(&[
        "call",
        "--rpc-url",
        &l.rpc,
        &store,
        "storedAt(bytes8,uint256)(bytes)",
        &hex(&hint),
        "0",
    ]);
    assert!(
        kept.contains(&hex(&env)[2..]),
        "the store's state holds the room's envelope"
    );
    // bob: accepted, in the room; opening the session reads the store (shown) and the room (its copy a duplicate)
    server.add_member(&room, &tb.user);
    pb.attach_matrix(tb.clone());
    pb.accept(&s, false).unwrap();
    let ob = pb.open_session(&s, &bob).await.unwrap();
    assert_eq!((ob.shown, ob.room), (1, RoomUse::Bound));
    assert_eq!(
        pb.dropped(&s.session_id),
        BTreeMap::from([(DropReason::Duplicate, 1)])
    );
    // the identity check: an address without code and a `PqChat` (another interface) are not written, the store is
    pa.detach_matrix();
    let none = "0x000000000000000000000000000000000000dead";
    let s2 = session(
        &l,
        &pa,
        &alice,
        &bob,
        2,
        vec![cs.clone(), chainstore(&l, none), chainstore(&l, &l.home)],
        BTreeMap::new(),
    )
    .await;
    let r2 = pa
        .send_content(&s2, &alice, &txt("identity"), None, &o)
        .await
        .unwrap();
    landed(&l, &r2.stores[0].1).await;
    for (i, d) in &r2.stores[1..] {
        assert_eq!(*d, Delivery::Failed("InstanceUnlisted"), "store {i}");
    }
    println!("[chainstore] ok: both stores, bob read the store; no code and a PqChat refused");
}
