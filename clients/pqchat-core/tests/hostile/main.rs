// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The hostile harness (plan Global constraints): records an honest client refuses to build, made here through the SDK's
//! generic record entries and never by `pqchat-core`. Plan T5: a session whose wraps are the stand-in bytes of
//! `smartcontracts/evm/script/onchain/PqChat.s.sol` (`_wraps`: the contract checks shape and hash only; random bytes of a
//! real wrap's lengths), signed by the SDK's generic `sign_pqchat_session`: its hashes hold, the wrap reaches the KEM and does
//! not open (`envelope`), nothing written; the same record with a real wrap opens.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
#[path = "../common/mod.rs"]
mod common;

use common::sdk::*;
use pqchat_core::model::{hex, ZERO32};
use pqchat_core::reads::SessionRef;
use pqchat_core::DropReason;
use scaas_sdk::pqchat_records::{PqChatSession, PqMemberKey, PqWrap};

fn random(n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).unwrap();
    b
}

/// The script's stand-in wrap of `member`: 1,568 B ciphertext, a 32-byte ephemeral key, 48 B sealed key, none of them a wrap.
fn stand_in(member: &str) -> PqWrap {
    PqWrap {
        member: member.into(),
        key_id: 1,
        mlkem_ct: random(1568),
        x25519_eph: hex(&random(32)),
        sealed_key: random(48),
    }
}

/// The session of alice and bob signed by alice through the generic entry, with bob's wrap `bob_wrap`; stored and listed at
/// HOME with both wraps landed.
async fn session_with(w: &World, nonce: u64, bob_wrap: PqWrap) -> (SessionRef, String) {
    let sid = w.app.pqchat_session_id(w.alice.ua.clone(), nonce).unwrap();
    let mut ms = [w.alice.ua.clone(), w.bob.ua.clone()];
    ms.sort();
    let wraps: Vec<PqWrap> = ms
        .iter()
        .map(|m| {
            if *m == w.bob.ua {
                bob_wrap.clone()
            } else {
                stand_in(m)
            }
        })
        .collect();
    let members: Vec<PqMemberKey> = ms
        .iter()
        .map(|m| PqMemberKey {
            ua: m.clone(),
            key_id: 1,
            via: ZERO32.into(),
        })
        .collect();
    let signed = w
        .app
        .sign_pqchat_session(
            w.alice.key.clone(),
            PqChatSession {
                creator: w.alice.ua.clone(),
                nonce,
                home_chain: hex(&[7; 32]),
                home_chat_contract: HOME.into(),
                admins: vec![w.alice.ua.clone()],
                members,
                wraps: wraps.clone(),
                sealed_info: random(64),
            },
        )
        .await
        .unwrap();
    assert_eq!(signed.id.as_deref(), Some(sid.as_str()));
    let mut e = session(&w.alice, &[&w.alice, &w.bob]);
    (e.id, e.session_id, e.nonce, e.wrap_hashes) =
        (sid.clone(), sid.clone(), nonce, signed.wrap_hashes.clone());
    put_record(&w.net, HOME, &e);
    for (i, x) in wraps.iter().enumerate() {
        put_wrap(&w.net, HOME, &sid, i, x);
    }
    list(&w.net, HOME, 3, 1);
    (
        SessionRef {
            chain: CHAIN.into(),
            home: HOME.into(),
            session_id: sid.clone(),
        },
        sid,
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn stand_in_wraps_refused_at_open() {
    let _one = ONE.lock().await;
    let w = world().await;
    kem_at(&w.chain, &w.bob.id, 1, &w.bob.kem_pk);
    // the positive control: a real wrap of a fresh K to bob in the same kind of record opens
    let k = w.app.pqchat_epoch_key(&w.seed).unwrap();
    let sid = w.app.pqchat_session_id(w.alice.ua.clone(), 1).unwrap();
    let real = w
        .app
        .pqchat_wrap(CHAIN.into(), k, sid.clone(), sid, w.bob.ua.clone(), 1)
        .await
        .unwrap();
    let (s, sid) = session_with(&w, 1, real).await;
    assert!(w
        .pq
        .open_epoch(&s, &sid, &w.bob.key, &w.bob.ua, None)
        .await
        .is_ok());
    let before = w.pq.unwrap_calls();
    let (s, sid) = session_with(&w, 2, stand_in(&w.bob.ua)).await;
    let r = w.pq.open_epoch(&s, &sid, &w.bob.key, &w.bob.ua, None).await;
    assert_eq!(r.err(), Some(DropReason::Envelope));
    assert_eq!(
        w.pq.unwrap_calls(),
        before + 1,
        "the hashes hold: the wrap reached the KEM"
    );
    assert_eq!(w.pq.dropped(&sid).get(&DropReason::Envelope), Some(&1));
    assert_eq!(w.net.writes(), 0);
}
