// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-MTX-01: the crate's normal dependency graph holds no `scaas-sdk`, `pqchat-core`, `scaas-ua` or `scaas-rpc` (scaas-app's
//! default build links it without the SDK), and it holds `matrix-sdk` and `pqchat-transport`. Each check runs on `cargo tree`'s
//! real output and, as its positive control, on that output with one forbidden line added.
use std::process::Command;

const FORBIDDEN: &[&str] = &["scaas-sdk", "pqchat-core", "scaas-ua", "scaas-rpc"];

fn tree() -> String {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--offline",
            "--locked",
            "-e",
            "normal",
            "--prefix",
            "none",
            "--target",
            "all",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo tree");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("utf-8")
}

/// The forbidden crates anywhere in a `cargo tree --prefix none` output.
fn forbidden(t: &str) -> Vec<String> {
    let mut v: Vec<String> = t
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| FORBIDDEN.contains(n))
        .map(str::to_string)
        .collect();
    v.sort();
    v.dedup();
    v
}

#[test]
fn no_sdk_and_no_pqchat_core_in_the_graph() {
    let t = tree();
    for needed in ["matrix-sdk ", "pqchat-transport "] {
        assert!(t.lines().any(|l| l.starts_with(needed)), "{needed}: {t}");
    }
    assert_eq!(forbidden(&t), Vec::<String>::new());
    // positive control: the same output on a branch that adds one, at any depth
    for f in FORBIDDEN {
        let added = format!("{t}{f} v0.1.0 (/x)\n");
        assert_eq!(forbidden(&added), vec![f.to_string()]);
    }
}
