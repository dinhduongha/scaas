// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The e2e against one Synapse in Docker (`--memory 1g --cpus 1`, the image pinned by digest; `pqchat-core`'s helper
//! `tests/e2e/matrix.rs` reused): two users log in; one session restored from its store key on a fresh client; an E2EE
//! direct message sent and read decrypted; the two devices verified by SAS; nothing ephemeral, no pusher and no key backup
//! sent by default, beside positive controls that are counted; the room-kind rules; `pqchat-transport`'s conformance on
//! `transport()`. Run: `cargo test --test e2e -- --ignored --nocapture` (Docker in PATH).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../pqchat-core/tests/e2e/matrix.rs"]
#[allow(dead_code)]
mod synapse;

use scaas_matrix::{
    ItemKind, MatrixClient, MatrixError, Options, RoomFilter, RoomKind, Step, StoreKey, Trust,
    Update,
};
use serde_json::{json, Value};
use std::path::PathBuf;
use std::time::Duration;
use synapse::{Synapse, SynapseWitness, PASSWORD};

fn dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("scaas-matrix-e2e-{}-{name}", std::process::id()))
}

/// `dir(name)`, emptied first.
fn fresh(name: &str) -> PathBuf {
    let d = dir(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

async fn login(s: &Synapse, name: &str, key: [u8; 32], opts: Options) -> MatrixClient {
    MatrixClient::login_password(
        &fresh(name),
        Some(StoreKey::from_bytes(key)),
        opts,
        &s.base,
        name,
        PASSWORD,
        name,
    )
    .await
    .unwrap_or_else(|e| panic!("login {name}: {e}"))
}

/// Polls `f` up to 60 s (both sides' sync loops run meanwhile).
async fn until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..600 {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out: {what}");
}

/// A raw client-server login of `user`: its access token (the positive controls' client, outside the crate).
async fn raw_token(s: &Synapse, user: &str) -> String {
    let v: Value = reqwest::Client::new()
        .post(format!("{}/_matrix/client/v3/login", s.base))
        .json(&json!({"type": "m.login.password", "identifier": {"type": "m.id.user", "user": user}, "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    v["access_token"].as_str().unwrap().to_string()
}

fn uid(name: &str) -> String {
    format!("@{name}:localhost")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "Docker: one Synapse container"]
async fn scaas_matrix_against_synapse() {
    let s = Synapse::start().await;
    for u in ["alice", "bob", "carol", "witness", "control"] {
        s.register(u, false);
    }
    let (ka, kb) = ([0xa1; 32], [0xb2; 32]);

    // ---- two users log in
    let alice = login(&s, "alice", ka, Options::default()).await;
    let bob = login(&s, "bob", kb, Options::default()).await;
    assert_eq!(alice.user_id().unwrap(), uid("alice"));
    let bob_device = bob.device_id().unwrap();
    alice.sync_once(Duration::ZERO).await.unwrap();
    bob.sync_once(Duration::ZERO).await.unwrap();
    println!("[e2e] alice and bob logged in");

    // ---- an E2EE direct message
    let room = alice.create_direct(&uid("bob")).await.unwrap();
    alice.sync_once(Duration::ZERO).await.unwrap();
    let row = alice
        .rooms(RoomFilter::Matrix)
        .await
        .into_iter()
        .find(|r| r.room_id == room)
        .unwrap();
    assert!(
        row.encrypted,
        "a direct room is encrypted from its first event"
    );
    until("bob sees the invite", || async {
        bob.sync_once(Duration::from_secs(1)).await.unwrap();
        bob.rooms(RoomFilter::Matrix)
            .await
            .iter()
            .any(|r| r.room_id == room && r.invited)
    })
    .await;
    bob.accept_invite(&room).await.unwrap();
    bob.sync_once(Duration::ZERO).await.unwrap();
    alice.sync_once(Duration::ZERO).await.unwrap();
    let ev = alice.send_text(&room, "hello over megolm").await.unwrap();
    let mut seen = None;
    for _ in 0..60 {
        bob.sync_once(Duration::from_secs(1)).await.unwrap();
        let p = bob.messages(&room, None, 20).await.unwrap();
        seen = p.items.into_iter().find(|i| i.event_id == ev);
        if seen
            .as_ref()
            .is_some_and(|i| i.kind != ItemKind::Undecryptable)
        {
            break;
        }
    }
    let it = seen.expect("bob sees the message");
    assert_eq!(it.kind, ItemKind::Text("hello over megolm".into()));
    assert_eq!(it.sender, uid("alice"));
    assert_eq!(it.verification, Trust::Unverified, "before the SAS");
    println!("[e2e] E2EE message read decrypted");

    // ---- the session restored from the sealed key on a fresh client
    bob.close().await;
    let bob = MatrixClient::restore(&dir("bob"), StoreKey::from_bytes(kb), Options::default())
        .await
        .unwrap();
    assert_eq!(bob.user_id().unwrap(), uid("bob"));
    assert_eq!(bob.device_id().unwrap(), bob_device);
    bob.sync_once(Duration::ZERO).await.unwrap();
    let p = bob.messages(&room, None, 20).await.unwrap();
    assert!(
        p.items
            .iter()
            .any(|i| i.kind == ItemKind::Text("hello over megolm".into())),
        "restored keys open it"
    );
    // the profile's directory is held: a second client of it is refused
    assert_eq!(
        MatrixClient::restore(&dir("bob"), StoreKey::from_bytes(kb), Options::default())
            .await
            .err(),
        Some(MatrixError::MatrixProfileBusy)
    );
    println!("[e2e] bob restored from the store key");

    // ---- the defaults: nothing ephemeral, no pusher, no backup, no PqChat push rule
    for u in ["alice", "bob"] {
        let w = s.seen_of(&room, &uid(u));
        assert_eq!(
            (w.receipts, w.read_markers, w.typing, w.presence),
            (0, 0, 0, 0),
            "{u}: {w:?}"
        );
        assert_eq!(
            s.sql(
                "select count(*) from pushers where user_name=?",
                &[uid(u).as_str()]
            ),
            0,
            "{u}"
        );
        assert_eq!(
            s.sql(
                "select count(*) from e2e_room_keys_versions where user_id=?",
                &[uid(u).as_str()]
            ),
            0,
            "{u}"
        );
        assert_eq!(
            s.sql(
                "select count(*) from push_rules where user_name=? and rule_id like '%pqchat%'",
                &[uid(u).as_str()]
            ),
            0
        );
    }
    assert!(!alice.key_backup().await.unwrap());
    // typing is off: nothing sent
    assert!(!bob.typing(&room, true).await.unwrap());
    // a read position goes out private
    bob.mark_read(&room, &ev).await.unwrap();
    let rt = |t: &str| {
        s.sql(
            "select count(*) from receipts_linearized where room_id=? and user_id=? and receipt_type=?",
            &[room.as_str(), uid("bob").as_str(), t],
        )
    };
    assert_eq!((rt("m.read.private"), rt("m.read")), (1, 0));
    assert_eq!(s.seen_of(&room, &uid("bob")).typing, 0);
    // positive controls: another account's typing, receipt and read marker, and its sync without set_presence, are seen
    let ctl = s.login("control").await;
    alice.transport().invite(&room, &uid("control")).await.ok();
    ctl_join(&s, &room).await;
    ctl.signals(&room).await;
    let w = s.seen_of(&room, &uid("control"));
    assert!(
        w.receipts > 0 && w.read_markers > 0 && w.typing > 0,
        "{w:?}"
    );
    let tok = raw_token(&s, "control").await;
    reqwest::Client::new()
        .get(format!("{}/_matrix/client/v3/sync?timeout=0", s.base))
        .bearer_auth(&tok)
        .send()
        .await
        .unwrap();
    assert!(
        s.seen_of(&room, &uid("control")).presence > 0,
        "a sync without set_presence counts"
    );
    // the opt-ins move what goes out
    bob.set_public_receipts(true).await.unwrap();
    bob.mark_read(&room, &ev).await.unwrap();
    assert_eq!(rt("m.read"), 1);
    bob.set_public_receipts(false).await.unwrap();
    println!("[e2e] defaults hold; controls seen");

    // ---- push: event_id_only on the caller's call; none for a hidden profile
    alice
        .register_pusher(scaas_matrix::HttpPusher {
            app_id: "net.scaas.test".into(),
            pushkey: "pk".into(),
            url: "https://push.example/_matrix/push/v1/notify".into(),
            app_display_name: "t".into(),
            device_display_name: "t".into(),
            lang: "en".into(),
        })
        .await
        .unwrap();
    assert_eq!(
        s.sql(
            "select count(*) from pushers where user_name=? and data like '%event_id_only%'",
            &[uid("alice").as_str()]
        ),
        1
    );
    alice.remove_pusher("net.scaas.test", "pk").await.unwrap();
    assert_eq!(
        s.sql(
            "select count(*) from pushers where user_name=?",
            &[uid("alice").as_str()]
        ),
        0
    );
    alice.set_pqchat_push(true).await.unwrap();
    assert_eq!(
        s.sql(
            "select count(*) from push_rules where user_name=? and rule_id like '%pqchat%'",
            &[uid("alice").as_str()]
        ),
        1
    );
    alice.set_pqchat_push(false).await.unwrap();
    let carol = login(&s, "carol", [0xc3; 32], Options { hidden: true }).await;
    assert_eq!(
        carol.set_pqchat_push(true).await.err(),
        Some(MatrixError::MatrixPushHidden)
    );
    carol.close().await;
    // key backup on the user's call only
    alice.set_key_backup(true).await.unwrap();
    assert!(alice.key_backup().await.unwrap());
    alice.set_key_backup(false).await.unwrap();
    println!("[e2e] push and backup on the caller's call only");

    // ---- SAS between alice's and bob's devices
    alice.start_sync();
    bob.start_sync();
    let alice_device = alice.device_id().unwrap();
    let fa = alice
        .request_verification(&uid("bob"), &bob_device)
        .await
        .unwrap();
    let fb = loop {
        match tokio::time::timeout(Duration::from_secs(60), bob.next_update())
            .await
            .expect("a request")
        {
            Some(Update::VerificationRequest { flow, device }) => {
                assert_eq!(device, alice_device);
                break flow;
            }
            Some(_) => continue,
            None => panic!("bob's updates closed"),
        }
    };
    assert_eq!(fb.flow_id, fa.flow_id);
    bob.accept(&fb).await.unwrap();
    until("alice's request ready", || async {
        alice.step(&fa).await.unwrap() == Step::Ready
    })
    .await;
    alice.start_sas(&fa).await.unwrap();
    until("bob sees the SAS", || async {
        matches!(bob.step(&fb).await, Ok(Step::SasStarted | Step::SasEmoji))
    })
    .await;
    bob.accept(&fb).await.unwrap();
    until("both show emoji", || async {
        alice.step(&fa).await.unwrap() == Step::SasEmoji
            && bob.step(&fb).await.unwrap() == Step::SasEmoji
    })
    .await;
    let (ea, eb) = (
        alice.sas_emoji(&fa).await.unwrap().unwrap(),
        bob.sas_emoji(&fb).await.unwrap().unwrap(),
    );
    assert_eq!(ea.len(), 7);
    assert_eq!(ea, eb, "the same seven emoji on both sides");
    alice.confirm(&fa).await.unwrap();
    bob.confirm(&fb).await.unwrap();
    // a finished flow may already be dropped by matrix-sdk's verification cache (then `step` is MatrixVerification): the
    // outcome that counts is each device's trust, asserted right after
    let done = |r: Result<Step, MatrixError>| {
        matches!(r, Ok(Step::Verified) | Err(MatrixError::MatrixVerification))
    };
    until("both verified", || async {
        done(alice.step(&fa).await) && done(bob.step(&fb).await)
    })
    .await;
    assert_eq!(
        alice.device_trust(&uid("bob"), &bob_device).await.unwrap(),
        Trust::Verified
    );
    assert_eq!(
        bob.device_trust(&uid("alice"), &alice_device)
            .await
            .unwrap(),
        Trust::Verified
    );
    println!(
        "[e2e] devices verified by SAS: {}",
        ea.iter()
            .map(|e| e.1.as_str())
            .collect::<Vec<_>>()
            .join(" ")
    );

    // ---- the transport: conformance, and its rooms kept apart from the Matrix list
    let t = alice.transport();
    let w = SynapseWitness {
        s: &s,
        other: s.login("witness").await,
    };
    assert_eq!(pqchat_transport::conformance(&*t, &w).await, Ok(()));
    let pq = t.create_room().await.unwrap();
    assert_eq!(alice.kind(&pq), RoomKind::PqChat);
    until("alice's sync knows the PqChat room", || async {
        alice
            .rooms(RoomFilter::PqChat)
            .await
            .iter()
            .any(|r| r.room_id == pq)
    })
    .await;
    assert!(!alice
        .rooms(RoomFilter::Matrix)
        .await
        .iter()
        .any(|r| r.room_id == pq));
    assert!(alice
        .rooms(RoomFilter::Matrix)
        .await
        .iter()
        .any(|r| r.room_id == room));
    for r in [
        alice.send_text(&pq, "x").await.err(),
        alice.mark_read(&pq, &ev).await.err(),
    ] {
        assert_eq!(r, Some(MatrixError::MatrixRoomKind));
    }
    assert_eq!(
        alice.typing(&pq, true).await.err(),
        Some(MatrixError::MatrixRoomKind)
    );
    // after the whole run: nothing ephemeral of alice or bob in any room the server holds
    for u in ["alice", "bob"] {
        let n = s.sql(
            "select count(*) from receipts_linearized where user_id=? and receipt_type!='m.read.private'",
            &[uid(u).as_str()],
        );
        let pres = s.requests_where(&uid(u), |l| {
            l.contains("/sync") && !l.contains("set_presence=offline")
        }) + s.requests(&uid(u), "/presence/");
        let typing = s.requests(&uid(u), "/typing/");
        // bob's one public receipt was the opt-in's control
        assert_eq!(
            (n, pres, typing),
            (if u == "bob" { 1 } else { 0 }, 0, 0),
            "{u}"
        );
    }
    println!("[e2e] the transport conforms; PqChat rooms kept apart");

    // ---- logout deletes the store
    let bdir = dir("bob");
    bob.logout().await.unwrap();
    assert!(!bdir.join("store").exists());
    alice.close().await;
    for n in ["alice", "bob", "carol"] {
        let _ = std::fs::remove_dir_all(dir(n));
    }
    println!("[e2e] ok");
}

/// The control account joins `room` (it was invited).
async fn ctl_join(s: &Synapse, room: &str) {
    let tok = raw_token(s, "control").await;
    let r = reqwest::Client::new()
        .post(format!(
            "{}/_matrix/client/v3/join/{}",
            s.base,
            room.replace('!', "%21").replace(':', "%3A")
        ))
        .bearer_auth(&tok)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
}
