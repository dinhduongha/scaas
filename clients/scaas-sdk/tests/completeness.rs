// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T18 (spec §18, §21): every `(struct, domain kind)` pair of `smartcontracts/vectors/typed/typed_ops.json` has exactly one
//! SDK entry point (`scaas_sdk::surface::ENTRY_POINTS`), but the named exclusions; the table names no pair the vectors lack; an
//! entry point's pairs are in one module and one feature; each function is defined in its module's source.
#![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]

use scaas_sdk::surface::{ENTRY_POINTS, EXCLUDED, PLANNED};
use std::collections::{BTreeMap, BTreeSet};

fn root(p: &str) -> String {
    format!("{}/{p}", env!("CARGO_MANIFEST_DIR"))
}

/// The vectors' pairs.
fn pairs() -> BTreeSet<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(
        &std::fs::read_to_string(root("../../smartcontracts/vectors/typed/typed_ops.json"))
            .unwrap(),
    )
    .unwrap();
    let mut out = BTreeSet::new();
    for (name, row) in v["ops"].as_object().unwrap() {
        for kind in row["domains"].as_object().unwrap().keys() {
            out.insert((name.clone(), kind.clone()));
        }
    }
    out
}

/// The Rust source of `module` (its file, or every file of its directory).
fn source(module: &str) -> String {
    let file = root(&format!("src/{module}.rs"));
    let mut s = std::fs::read_to_string(&file).unwrap_or_default();
    if let Ok(dir) = std::fs::read_dir(root(&format!("src/{module}"))) {
        for e in dir {
            s.push_str(&std::fs::read_to_string(e.unwrap().path()).unwrap_or_default());
        }
    }
    s
}

#[test]
fn every_pair_has_one_entry_point() {
    let want = pairs();
    let mut by_pair: BTreeMap<(String, String), Vec<&str>> = BTreeMap::new();
    for e in ENTRY_POINTS {
        for (s, k) in e.pairs {
            by_pair
                .entry((s.to_string(), k.to_string()))
                .or_default()
                .push(e.function);
        }
    }
    let named: BTreeSet<_> = EXCLUDED
        .iter()
        .chain(PLANNED)
        .map(|(s, k)| (s.to_string(), k.to_string()))
        .collect();
    // vectors -> SDK: each pair once, or named
    for p in &want {
        match (by_pair.get(p).map(Vec::len), named.contains(p)) {
            (Some(1), false) | (None, true) => {}
            (n, x) => panic!("{p:?}: {n:?} entry points, named {x}"),
        }
    }
    // SDK -> vectors: no pair the vectors lack, no named pair also mapped
    for p in by_pair.keys().chain(&named) {
        assert!(want.contains(p), "{p:?} is not a pair of typed_ops.json");
    }
    assert_eq!(by_pair.len() + named.len(), want.len());
    // the table: functions unique, each entry's pairs in one module and one feature, defined in that module's source
    let mut seen = BTreeSet::new();
    for e in ENTRY_POINTS {
        assert!(seen.insert((e.module, e.function)), "{} twice", e.function);
        assert!(!e.pairs.is_empty(), "{} has no pair", e.function);
        let src = source(e.module);
        assert!(
            src.contains(&format!("fn {}(", e.function))
                || src.contains(&format!(" {},", e.function)),
            "{} not in src/{}",
            e.function,
            e.module
        );
        let features = ["wallet", "account", "zether", "pqz", "dex", "admin"];
        assert!(
            features.contains(&e.feature),
            "{}: {}",
            e.function,
            e.feature
        );
    }
}

/// Zether and PQZ are apart (AGENTS.md): no entry point prepares a Zether pair and a PQZ pair, but a token row of every kind
/// (`token`, `zether`, `pqz` together); a confidential entry's feature is its kind's.
#[test]
fn zether_and_pqz_pairs_are_apart() {
    for e in ENTRY_POINTS {
        let kinds: BTreeSet<_> = e.pairs.iter().map(|(_, k)| *k).collect();
        if kinds.contains("zether") && kinds.contains("pqz") {
            assert!(
                kinds.contains("token"),
                "{} mixes Zether and PQZ",
                e.function
            );
        }
        if e.module == "confidential" {
            assert_eq!(kinds.len(), 1, "{} mixes domain kinds", e.function);
            assert_eq!(e.feature, *kinds.iter().next().unwrap(), "{}", e.function);
        }
    }
}
