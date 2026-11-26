// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T2: `PqChatError::code()` holds the names of spec §8, stable and in order; `Display` and `Debug` are the code; no error
//! and no log line holds an input (CLI-PQC-03), checked over every store failure path with marked inputs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod common;

use common::{logs, Faulty};
use pqchat_core::error::CODES;
use pqchat_core::{Items, MemoryStore, PqChatError, PqChatStore};

/// The codes of spec §8's table, in its order.
fn spec_codes() -> Vec<String> {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../docs/superpowers/specs/2026-11-17-pqchat-core.md"
    );
    let s = std::fs::read_to_string(p).unwrap();
    let t = s.split("| Code | When |").nth(1).unwrap();
    t.lines()
        .skip(2)
        .take_while(|l| l.starts_with('|'))
        .flat_map(|l| {
            let first = l.split('|').nth(1).unwrap();
            first
                .split('`')
                .skip(1)
                .step_by(2)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .collect()
}

#[test]
fn codes_are_spec_8_in_order() {
    let want = spec_codes();
    // CLI-PQC-15 (owner 2026-11-23): `HomeUnsigned` appended, 27 -> 28; D2-4 (2026-11-25): `ExitLag`, 28 -> 29
    assert_eq!(want.len(), 29, "{want:?}");
    assert_eq!(
        CODES,
        want.iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            .as_slice()
    );
    let own = PqChatError::own_variants();
    assert_eq!(own.len(), CODES.len());
    for (e, c) in own.iter().zip(CODES) {
        assert_eq!(e.code(), *c);
        assert_eq!(e.to_string(), *c);
        assert_eq!(format!("{e:?}"), *c);
    }
}

#[test]
fn sdk_codes_pass_through_by_their_own_names() {
    for e in scaas_sdk::SdkError::own_variants() {
        let c = e.code();
        let p = PqChatError::from(e);
        assert_eq!(p.code(), c);
        assert_eq!(p.to_string(), c);
        assert_eq!(format!("{p:?}"), c);
    }
}

const MARK: &str = "MARK-7f3a";

/// Every failure path of the store, each with marked inputs (the item's key, its stored bytes, the value written): no error's
/// `Display` or `Debug` and no log line of the crate holds the mark.
#[test]
fn no_error_or_log_line_holds_an_input() {
    let key = format!("session/{MARK}/k");
    let (errors, lines) = logs(|| {
        let mut errs = vec![];
        // a fault on load and on replace
        errs.push(Items(&Faulty::load()).get::<String>(&key).unwrap_err());
        errs.push(
            Items(&Faulty::replace())
                .update::<String, _>(&key, |_| Ok(MARK.into()))
                .unwrap_err(),
        );
        // an item that does not decode, on get and on update
        let m = MemoryStore::new();
        assert!(m
            .replace(&key, 0, format!("{{\"{MARK}\":").as_bytes())
            .unwrap());
        errs.push(Items(&m).get::<String>(&key).unwrap_err());
        errs.push(
            Items(&m)
                .update::<String, _>(&key, |_| Ok(MARK.into()))
                .unwrap_err(),
        );
        // a conflict on every try
        errs.push(
            Items(&Faulty::racing())
                .update::<String, _>(&key, |_| Ok(MARK.into()))
                .unwrap_err(),
        );
        errs
    });
    assert_eq!(
        errors.iter().map(PqChatError::code).collect::<Vec<_>>(),
        ["StoreIo", "StoreIo", "StoreIo", "StoreIo", "StoreConflict"]
    );
    assert!(lines.len() >= 5, "{lines:?}");
    for e in &errors {
        assert!(!e.to_string().contains(MARK) && !format!("{e:?}").contains(MARK));
    }
    for l in &lines {
        assert!(!l.contains(MARK), "{l}");
    }
}
