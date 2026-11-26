// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Owner (M) 2026-11-23 (CTR-CHAT-24): a member may hold several KEM keys in an epoch, `(ua, keyId)` strictly ascending, one wrap
//! each, at most 8 per UA. The crate's checks read members per UA (shapes, the plain-rekey rule) and its own wraps per key: a
//! device key this account does not hold is skipped and the next own wrap opens. The default stays one key per member.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::sdk::*;
use pqchat_core::check::{self, DropReason};
use pqchat_core::model::{hex, Epoch, Member, ZERO32};

fn key(ua: &str, key_id: u64) -> Member {
    Member {
        ua: ua.into(),
        key_id,
        via: ZERO32.into(),
    }
}

fn with_members(mut e: Epoch, m: Vec<Member>) -> Epoch {
    e.wrap_hashes = m.iter().map(|_| hex(&[0xaa; 32])).collect();
    e.members = m;
    e
}

#[tokio::test(flavor = "multi_thread")]
async fn shapes_take_several_keys_per_member_in_order() {
    let _one = ONE.lock().await;
    let w = world().await;
    let e = session(&w.alice, &[&w.alice, &w.bob]);
    let (a, b) = (e.members[0].ua.clone(), e.members[1].ua.clone());
    let two = with_members(e.clone(), vec![key(&a, 1), key(&a, 4), key(&b, 1)]);
    assert_eq!(check::shapes(&two), Ok(()), "a second key of a member");
    assert_eq!(check::distinct(&two), vec![&a, &b]);
    let swapped = with_members(e.clone(), vec![key(&a, 4), key(&a, 1), key(&b, 1)]);
    assert_eq!(
        check::shapes(&swapped),
        Err(DropReason::Control),
        "keys of a member out of order"
    );
    let repeated = with_members(e.clone(), vec![key(&a, 1), key(&a, 1), key(&b, 1)]);
    assert_eq!(
        check::shapes(&repeated),
        Err(DropReason::Control),
        "a key repeated"
    );
    let mut nine: Vec<Member> = (0..9).map(|k| key(&a, k)).collect();
    nine.push(key(&b, 1));
    assert_eq!(
        check::shapes(&with_members(e.clone(), nine.clone())),
        Err(DropReason::Control),
        "9 keys"
    );
    nine.remove(8);
    assert_eq!(check::shapes(&with_members(e, nine)), Ok(()), "8 keys");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_members_keys_change_in_a_plain_rekey() {
    let _one = ONE.lock().await;
    let w = world().await;
    let p = session(&w.alice, &[&w.alice, &w.bob]);
    // `a` the only admin (the creator), `b` a member who is none: the plain rule, not admin rights, lets `b` author
    let (a, b) = (w.alice.ua.clone(), w.bob.ua.clone());
    assert!(p.admins == [a.clone()] && p.has_member(&b));
    let sorted = |mut m: Vec<Member>| {
        m.sort_by(|x, y| (x.ua.as_str(), x.key_id).cmp(&(y.ua.as_str(), y.key_id)));
        m
    };
    let mut c = with_members(p.clone(), sorted(vec![key(&a, 1), key(&b, 1), key(&b, 2)]));
    (c.id, c.parent, c.epoch, c.author) = (hex(&[0x61; 32]), p.id.clone(), 1, b.clone());
    assert_eq!(
        check::child(&c, &p, &[], &[]),
        Ok(()),
        "a non-admin member adds its device key: plain"
    );
    let back = c.clone();
    let mut d = with_members(back.clone(), sorted(vec![key(&a, 1), key(&b, 1)]));
    (d.id, d.parent, d.epoch) = (hex(&[0x62; 32]), back.id.clone(), 2);
    assert_eq!(
        check::child(&d, &back, &[], &[]),
        Ok(()),
        "and drops it again: plain"
    );
    // a removed UA kept with any of its keys: refused
    let removed = vec![b.clone()];
    let mut k = with_members(c.clone(), sorted(vec![key(&a, 1), key(&b, 2)]));
    (k.id, k.parent, k.epoch, k.author) = (hex(&[0x63; 32]), c.id.clone(), 2, a.clone());
    assert_eq!(
        check::child(&k, &c, &[], &removed),
        Err(DropReason::Control)
    );
}

/// Bob's device key (keyId 0, a wrap this account cannot open) sits before his seed key (keyId 1): the device wrap is tried and
/// skipped, the seed wrap opens; both pass their hash check first.
#[tokio::test(flavor = "multi_thread")]
async fn the_first_own_wrap_that_opens_is_used() {
    let _one = ONE.lock().await;
    let w = world().await;
    let mut o = opened(&w, &[&w.alice, &w.bob]).await;
    let i = o.e.index_of(&w.bob.ua).unwrap();
    let device = scaas_sdk::pqchat_records::PqWrap {
        member: w.bob.ua.clone(),
        key_id: 0,
        mlkem_ct: vec![7; 1568],
        x25519_eph: hex(&[9; 32]),
        sealed_key: vec![5; 48],
    };
    o.e.members.insert(i, key(&w.bob.ua, 0));
    o.e.wrap_hashes
        .insert(i, w.app.pqchat_wrap_hash(device.clone()).unwrap());
    put_record(&w.net, HOME, &o.e);
    put_wrap(&w.net, HOME, &o.e.id, i, &device);
    put_wrap(&w.net, HOME, &o.e.id, i + 1, &o.wrap);
    let ep =
        w.pq.open_epoch(&o.s, &o.e.id, &w.bob.key, &w.bob.ua, None)
            .await
            .unwrap();
    assert!(w.app.same_key(ep.k.clone(), o.k.clone()).unwrap());
    assert_eq!(
        w.pq.unwrap_calls(),
        2,
        "the device wrap tried, then the seed wrap"
    );
}
