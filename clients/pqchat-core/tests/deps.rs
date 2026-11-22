// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-PQC-01's dependency rule (plan T2, gate `pqc-tree`): the crate depends on `scaas-sdk` and on nothing else that touches a
//! key, a node or Matrix (no direct `scaas-ua`, `scaas-rpc`, Matrix SDK), and its feature graph holds at most one PQZ set. Each
//! check runs on `cargo tree`'s real output and, as its positive control, on that output with one forbidden line added.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
use std::process::Command;

/// Crates the crate may not depend on directly (CLI-PQC-01).
const FORBIDDEN: &[&str] = &[
    "scaas-ua",
    "scaas-rpc",
    "matrix-sdk",
    "matrix-sdk-base",
    "ruma",
    "alloy",
];

fn tree(args: &[&str]) -> String {
    let out = Command::new(env!("CARGO"))
        .args(["tree", "--offline", "--locked", "--prefix", "depth"])
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// The forbidden crates among the direct normal dependencies of a `cargo tree -e normal --depth 1 --prefix depth` output.
fn forbidden_direct(t: &str) -> Vec<String> {
    t.lines()
        .filter_map(|l| l.strip_prefix('1'))
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| FORBIDDEN.contains(n))
        .map(str::to_string)
        .collect()
}

/// The PQZ set features in a `cargo tree -e features` output.
fn pqz_sets(t: &str) -> std::collections::BTreeSet<String> {
    t.split(|c: char| c.is_whitespace() || c == '"')
        .filter(|w| w.starts_with("pqz-set-"))
        .map(str::to_string)
        .collect()
}

#[test]
fn no_key_node_or_matrix_crate_of_its_own() {
    let t = tree(&["-e", "normal", "--depth", "1"]);
    assert!(t.lines().any(|l| l.starts_with("1scaas-sdk ")), "{t}");
    assert_eq!(forbidden_direct(&t), Vec::<String>::new());
    // positive control: the same output on a branch that adds one
    for f in ["scaas-ua", "scaas-rpc", "matrix-sdk"] {
        let added = format!("{t}1{f} v0.1.0\n");
        assert_eq!(forbidden_direct(&added), vec![f.to_string()]);
    }
}

#[test]
fn one_pqz_set_at_most() {
    let t = tree(&["-e", "features"]);
    assert!(pqz_sets(&t).len() <= 1, "{:?}", pqz_sets(&t));
    // positive control: two sets in one graph are seen
    let two = format!("{t}3scaas-ua feature \"pqz-set-n2048-kmax1024\"\n3scaas-ua feature \"pqz-set-n2304-kmax4096\"\n");
    assert!(pqz_sets(&two).len() >= 2);
}
