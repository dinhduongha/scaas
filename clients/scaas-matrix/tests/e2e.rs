// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The e2e against one Synapse in Docker (`--memory 1g --cpus 1`, the image pinned by digest; `pqchat-core`'s helper
//! `tests/e2e/matrix.rs` reused): two users log in; one session restored from its store key on a fresh client; an E2EE
//! direct message sent and read decrypted; the two devices verified by SAS; nothing ephemeral, no pusher and no key backup
//! sent by default, beside positive controls that are counted; recovery and backup refused over existing ones; a second
//! device refused to send until it recovers; the room-kind rules (a held invite never answered across sync rounds, a joined
//! Matrix room never taken by a held invite, a bound room marked on a fresh device, events routed by kind); `pqchat-transport`'s
//! conformance on `transport()`; nothing secret on disk after the run. Run: `cargo test --test e2e -- --ignored --nocapture`
//! (Docker in PATH).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "../../pqchat-core/tests/e2e/matrix.rs"]
#[allow(dead_code)]
mod synapse;

use pqchat_transport::MatrixTransport;
use scaas_matrix::{
    ItemKind, Login, MatrixClient, MatrixError, Options, RoomFilter, RoomKind, Step, StoreKey,
    Trust, Update,
};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::time::Duration;
use synapse::{Synapse, SynapseWitness, PASSWORD};

const SHOWN: Options = Options { hidden: false };

fn dir(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("scaas-matrix-e2e-{}-{name}", std::process::id()))
}

/// `dir(name)`, emptied first.
fn fresh(name: &str) -> PathBuf {
    let d = dir(name);
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn key(b: [u8; 32]) -> StoreKey {
    StoreKey::from_bytes(&mut b.clone())
}

async fn login_as(
    s: &Synapse,
    dirname: &str,
    user: &str,
    k: [u8; 32],
    opts: Options,
) -> MatrixClient {
    let l = Login {
        homeserver: &s.base,
        user,
        password: PASSWORD,
        device_name: dirname,
    };
    MatrixClient::login_password(&fresh(dirname), Some(key(k)), opts, l)
        .await
        .unwrap_or_else(|e| panic!("login {dirname}: {e}"))
}

/// Polls `f` for at most 60 s of wall time (the sync loops run meanwhile), then fails by name.
async fn until<F, Fut>(what: &str, mut f: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let end = tokio::time::Instant::now() + Duration::from_secs(60);
    while tokio::time::Instant::now() < end {
        if f().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("timed out: {what}");
}

/// The updates of `c` until `want` holds one (at most 60 s), all of them returned.
async fn updates_until(c: &MatrixClient, want: impl Fn(&Update) -> bool) -> Vec<Update> {
    let mut out = vec![];
    loop {
        let u = tokio::time::timeout(Duration::from_secs(60), c.next_update())
            .await
            .expect("an update")
            .expect("open");
        let done = want(&u);
        out.push(u);
        if done {
            return out;
        }
    }
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

/// Every file under `d` that holds `needle` (an unreadable file fails the test, one removed meanwhile is skipped).
fn holders(d: &Path, needle: &[u8]) -> Vec<PathBuf> {
    let mut out = vec![];
    let mut stack = vec![d.to_path_buf()];
    while let Some(p) = stack.pop() {
        for e in std::fs::read_dir(&p).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else {
                // a journal file SQLite removed meanwhile holds nothing any more; any other read failure fails the test
                let b = match std::fs::read(&p) {
                    Ok(b) => b,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => panic!("{}: {e}", p.display()),
                };
                if b.windows(needle.len()).any(|w| w == needle) {
                    out.push(p);
                }
            }
        }
    }
    out
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
    let alice = login_as(&s, "alice", "alice", ka, SHOWN).await;
    let bob = login_as(&s, "bob", "bob", kb, SHOWN).await;
    assert_eq!(alice.user_id().unwrap(), uid("alice"));
    let bob_device = bob.device_id().unwrap();
    assert!(
        alice.device_verified().await.unwrap(),
        "cross-signing bootstrapped at the first login"
    );
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
    until("bob sees the room", || async {
        bob.sync_once(Duration::from_secs(1)).await.unwrap();
        bob.rooms(RoomFilter::Matrix)
            .await
            .iter()
            .any(|r| r.room_id == room)
    })
    .await;
    // the crate answers no invite by itself: the room is still an invite after the syncs that brought it
    assert!(
        bob.rooms(RoomFilter::Matrix)
            .await
            .iter()
            .any(|r| r.room_id == room && r.invited),
        "an invite is never answered by the crate"
    );
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
    assert!(it.encrypted);
    assert_eq!(it.sender, uid("alice"));
    assert_eq!(it.verification, Trust::Unverified, "before the SAS");
    println!("[e2e] E2EE message read decrypted");

    // ---- the session restored from the sealed key on a fresh client
    bob.close().await;
    let bob = MatrixClient::restore(&dir("bob"), key(kb), SHOWN)
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
        MatrixClient::restore(&dir("bob"), key(kb), SHOWN)
            .await
            .err(),
        Some(MatrixError::MatrixProfileBusy)
    );
    println!("[e2e] bob restored from the store key");

    // ---- the defaults: nothing ephemeral, no pusher, no backup, no PqChat push rule
    let none_of = |u: &str| {
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
        // the server's presence state: never made online
        assert_eq!(
            s.sql(
                "select count(*) from presence_stream where user_id=? and state!='offline'",
                &[uid(u).as_str()]
            ),
            0,
            "{u}"
        );
    };
    none_of("alice");
    none_of("bob");
    assert!(!alice.key_backup().await.unwrap());
    assert!(
        !bob.typing(&room, true).await.unwrap(),
        "typing is off: nothing sent"
    );
    bob.mark_read(&room, &ev).await.unwrap();
    let rt = |t: &str| {
        s.sql(
            "select count(*) from receipts_linearized where room_id=? and user_id=? and receipt_type=?",
            &[room.as_str(), uid("bob").as_str(), t],
        )
    };
    assert_eq!((rt("m.read.private"), rt("m.read")), (1, 0));
    assert_eq!(s.seen_of(&room, &uid("bob")).typing, 0);
    // positive controls: another account's typing, receipt, read marker and online sync, in its own room, are counted
    let ctl = s.login("control").await;
    let croom = ctl.create_room().await.unwrap();
    ctl.send_event(&croom, json!({"v": 1})).await.unwrap();
    ctl.signals(&croom).await;
    let w = s.seen_of(&croom, &uid("control"));
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
        s.seen_of(&croom, &uid("control")).presence > 0,
        "a sync without set_presence counts"
    );
    assert!(
        s.sql(
            "select count(*) from presence_stream where user_id=? and state!='offline'",
            &[uid("control").as_str()]
        ) > 0,
        "and the server holds it online"
    );
    // the opt-in moves what goes out
    bob.set_public_receipts(true).await.unwrap();
    bob.mark_read(&room, &ev).await.unwrap();
    assert_eq!(rt("m.read"), 1);
    bob.set_public_receipts(false).await.unwrap();
    println!("[e2e] defaults hold; controls seen");

    // ---- push: https, event_id_only on the caller's call; none added for a hidden profile, removal allowed there
    let pusher = scaas_matrix::HttpPusher {
        app_id: "net.scaas.test".into(),
        pushkey: "pk".into(),
        url: "https://push.example/_matrix/push/v1/notify".into(),
        app_display_name: "t".into(),
        device_display_name: "t".into(),
        lang: "en".into(),
    };
    alice.register_pusher(pusher.clone()).await.unwrap();
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
    let carol = login_as(&s, "carol", "carol", [0xc3; 32], Options { hidden: true }).await;
    assert_eq!(
        carol.set_pqchat_push(true).await.err(),
        Some(MatrixError::MatrixPushHidden)
    );
    assert_eq!(
        carol.register_pusher(pusher.clone()).await.err(),
        Some(MatrixError::MatrixPushHidden)
    );
    carol.set_pqchat_push(false).await.ok();
    assert_eq!(
        s.sql(
            "select count(*) from pushers where user_name=?",
            &[uid("carol").as_str()]
        ),
        0
    );
    carol.close().await;
    println!("[e2e] push on the caller's call only");

    // ---- recovery and key backup: on the caller's call, never over an existing one
    let recovery_key = alice.setup_recovery().await.unwrap();
    assert_eq!(
        alice.setup_recovery().await.err(),
        Some(MatrixError::MatrixVerification),
        "never replaced"
    );
    alice.set_key_backup(true).await.unwrap();
    assert!(alice.key_backup().await.unwrap());
    assert_eq!(
        alice.set_key_backup(true).await.err(),
        Some(MatrixError::MatrixVerification),
        "never replaced"
    );
    println!("[e2e] recovery and backup on the caller's call, never replaced");

    // ---- SAS between alice's and bob's devices
    alice.start_sync();
    bob.start_sync();
    let alice_device = alice.device_id().unwrap();
    let fa = alice
        .request_verification(&uid("bob"), &bob_device)
        .await
        .unwrap();
    let mut fb = None;
    for u in updates_until(&bob, |u| matches!(u, Update::VerificationRequest { .. })).await {
        if let Update::VerificationRequest { flow, device } = u {
            assert_eq!(device, alice_device);
            fb = Some(flow);
        }
    }
    let fb = fb.unwrap();
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
    assert!(matches!(
        alice.step(&fa).await.unwrap(),
        Step::Confirmed | Step::Verified
    ));
    bob.confirm(&fb).await.unwrap();
    until("both verified", || async {
        alice.step(&fa).await == Ok(Step::Verified) && bob.step(&fb).await == Ok(Step::Verified)
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
        alice.accept_invite(&pq).await.err(),
        alice.messages(&pq, None, 10).await.err(),
    ] {
        assert_eq!(r, Some(MatrixError::MatrixRoomKind));
    }
    assert_eq!(
        alice.typing(&pq, true).await.err(),
        Some(MatrixError::MatrixRoomKind)
    );
    // a held invite can never take the Matrix room alice already uses
    assert!(t.hold_invite(&room, true).await.is_err());
    assert_eq!(alice.kind(&room), RoomKind::Matrix);
    // events routed by kind: the witness's envelope in the PqChat room reaches alice as a PqChat event, never a timeline row
    t.invite(&pq, &uid("witness")).await.unwrap();
    w.other.join(&pq).await.unwrap();
    w.other
        .send_event(&pq, json!({"v": 1, "hint": "AQEBAQEBAQE=", "env": "Ag=="}))
        .await
        .unwrap();
    let ups = updates_until(
        &alice,
        |u| matches!(u, Update::PqChatEvent { room: r, .. } if *r == pq),
    )
    .await;
    assert!(
        !ups.iter()
            .any(|u| matches!(u, Update::Timeline { room: r, .. } if *r == pq)),
        "{ups:?}"
    );
    // a held invite stays unanswered across sync rounds (the sync loop runs)
    let held = w.other.create_room().await.unwrap();
    w.other.invite(&held, &uid("alice")).await.unwrap();
    t.hold_invite(&held, true).await.unwrap();
    // the sync loop has seen the invite (an auto-join would act on it there), then a few more seconds of the loop
    until("alice's sync sees the held invite", || async {
        alice
            .rooms(RoomFilter::PqChat)
            .await
            .iter()
            .any(|r| r.room_id == held && r.invited)
    })
    .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        !s.seen_of(&held, &uid("alice")).joined,
        "a held invite is never answered by the crate"
    );
    // J-1: a held room the account then joins from another client is a Matrix room again after the next sync
    let tok = raw_token(&s, "alice").await;
    let r = reqwest::Client::new()
        .post(format!(
            "{}/_matrix/client/v3/join/{}",
            s.base,
            held.replace('!', "%21").replace(':', "%3A")
        ))
        .bearer_auth(&tok)
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "{}", r.status());
    until("the joined held room is a Matrix room again", || async {
        alice.kind(&held) == RoomKind::Matrix
    })
    .await;
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
    println!("[e2e] the transport conforms; PqChat rooms kept apart; events routed by kind");

    // ---- a second device of alice: refused to send encrypted until it recovers; a bound room marked on it
    let alice2 = login_as(&s, "alice-2", "alice", [0xa2; 32], SHOWN).await;
    // R-1: before its first sync the new device's local view knows no room; the homeserver's answer still refuses a hold
    // over the DM alice uses
    assert!(alice2.transport().hold_invite(&room, true).await.is_err());
    assert_eq!(alice2.kind(&room), RoomKind::Matrix);
    alice2.sync_once(Duration::ZERO).await.unwrap();
    assert!(!alice2.device_verified().await.unwrap());
    assert_eq!(
        alice2.send_text(&room, "from the new device").await.err(),
        Some(MatrixError::MatrixDeviceUnverified)
    );
    alice2.recover(&recovery_key).await.unwrap();
    assert!(
        alice2.device_verified().await.unwrap(),
        "verified by the recovery key"
    );
    alice2
        .send_text(&room, "from the recovered device")
        .await
        .unwrap();
    assert_eq!(
        alice2.kind(&pq),
        RoomKind::Matrix,
        "a fresh device knows no mark"
    );
    alice2.transport().bound(&pq).await.unwrap();
    assert_eq!(alice2.kind(&pq), RoomKind::PqChat);
    assert!(!alice2
        .rooms(RoomFilter::Matrix)
        .await
        .iter()
        .any(|r| r.room_id == pq));
    alice2.close().await;
    println!("[e2e] a second device recovers; bound rooms marked on it");

    // ---- nothing secret on disk: alice's Matrix id, the homeserver and her rooms' ids, while open and after close
    let port = s.base.rsplit(':').next().unwrap().to_string();
    let adir = dir("alice");
    let needles = [
        uid("alice"),
        format!("127.0.0.1:{port}"),
        room.clone(),
        pq.clone(),
    ];
    let scan = || {
        for n in &needles {
            assert_eq!(holders(&adir, n.as_bytes()), Vec::<PathBuf>::new(), "{n}");
        }
    };
    scan();
    alice.close().await;
    scan();
    assert!(
        t.create_room().await.is_err(),
        "the transport is dead after close"
    );

    // ---- logout deletes the store
    let bdir = dir("bob");
    assert!(
        bob.logout().await.unwrap(),
        "the server invalidated the token"
    );
    assert!(!bdir.join("store").exists());
    for n in ["alice", "alice-2", "bob", "carol"] {
        let _ = std::fs::remove_dir_all(dir(n));
    }
    println!("[e2e] ok");
}
