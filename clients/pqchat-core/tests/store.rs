// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T2: the storage interface (spec §7): items keyed apart, each written at its own expected revision; a changed item read
//! again, `StoreConflict` after three tries; a failed write keeps the old item (`StoreIo`).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::Faulty;
use pqchat_core::store::TRIES;
use pqchat_core::{Items, MemoryStore, PqChatStore};
use std::sync::atomic::Ordering;

#[test]
fn revisions_per_item() {
    let m = MemoryStore::new();
    assert!(m.replace("a", 0, b"1").unwrap());
    assert!(m.replace("a", 1, b"2").unwrap());
    // a stale revision writes nothing (positive twin above)
    assert!(!m.replace("a", 1, b"3").unwrap());
    assert_eq!(m.load("a").unwrap().unwrap().value, b"2");
    // another item has its own revision: b's writes do not move a's
    assert!(m.replace("b", 0, b"x").unwrap());
    assert!(m.replace("b", 1, b"y").unwrap());
    assert_eq!(m.load("a").unwrap().unwrap().revision, 2);
    assert!(m.replace("a", 2, b"4").unwrap());
    assert_eq!(m.load("b").unwrap().unwrap().value, b"y");
    assert!(m.load("c").unwrap().is_none());
}

#[test]
fn update_keeps_items_apart() {
    let m = MemoryStore::new();
    let it = Items(&m);
    it.update::<u64, _>("chain/s/e/d", |_| Ok(5)).unwrap();
    it.update::<u64, _>("chain/s/e/d2", |_| Ok(9)).unwrap();
    it.update::<u64, _>("chain/s/e/d", |v| Ok(v.unwrap() + 1))
        .unwrap();
    assert_eq!(it.get::<u64>("chain/s/e/d").unwrap(), Some(6));
    assert_eq!(it.get::<u64>("chain/s/e/d2").unwrap(), Some(9));
}

#[test]
fn a_changed_item_is_read_again_then_conflict() {
    // one race: the second try reads the other writer's value and keeps it
    struct Once(Faulty, std::sync::atomic::AtomicBool);
    impl PqChatStore for Once {
        fn load(&self, k: &str) -> Result<Option<pqchat_core::Item>, pqchat_core::StoreFault> {
            self.0.inner().load(k)
        }
        fn replace(&self, k: &str, e: u64, v: &[u8]) -> Result<bool, pqchat_core::StoreFault> {
            if !self.1.swap(true, Ordering::SeqCst) {
                return self.0.replace(k, e, v);
            }
            self.0.inner().replace(k, e, v)
        }
    }
    let o = Once(Faulty::racing(), Default::default());
    let mut seen = vec![];
    let got = Items(&o)
        .update::<String, _>("k", |v| {
            seen.push(v.clone());
            Ok(format!("{}+mine", v.unwrap_or_default()))
        })
        .unwrap();
    assert_eq!(seen, [None, Some("other".to_string())]);
    assert_eq!(got, "other+mine");
    assert_eq!(Items(&o).get::<String>("k").unwrap().unwrap(), "other+mine");
    // a race on every try: StoreConflict after TRIES writes
    let f = Faulty::racing();
    let e = Items(&f)
        .update::<String, _>("k", |_| Ok("mine".into()))
        .unwrap_err();
    assert_eq!(e.code(), "StoreConflict");
    assert_eq!(f.replaces.load(Ordering::SeqCst), TRIES as u64);
    assert_eq!(TRIES, 3);
}

#[test]
fn a_failed_write_keeps_the_old_item() {
    let f = Faulty::replace();
    assert!(f.inner().replace("k", 0, b"\"old\"").unwrap());
    let e = Items(&f)
        .update::<String, _>("k", |_| Ok("new".into()))
        .unwrap_err();
    assert_eq!(e.code(), "StoreIo");
    assert_eq!(Items(f.inner()).get::<String>("k").unwrap().unwrap(), "old");
    // f's error writes nothing
    let m = MemoryStore::new();
    let e = Items(&m)
        .update::<String, _>("k", |_| Err(pqchat_core::PqChatError::ContentInvalid))
        .unwrap_err();
    assert_eq!(e.code(), "ContentInvalid");
    assert!(m.load("k").unwrap().is_none());
}
