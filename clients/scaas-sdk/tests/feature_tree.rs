// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T1 `feature_tree`: `scaas-ua` is taken without its defaults, so the build carries exactly the PQZ set it asks for
//! (none without `pqz`), read from `cargo tree -e features` of this build's own feature list.

use std::process::Command;

const SETS: [&str; 4] = [
    "n2048-kmax1024",
    "n2304-kmax4096",
    "n2560-kmax16384",
    "n2816-kmax65536",
];

fn this_build() -> Vec<&'static str> {
    let all = [
        (cfg!(feature = "vault"), "vault"),
        (cfg!(feature = "account"), "account"),
        (cfg!(feature = "wallet"), "wallet"),
        (cfg!(feature = "zether"), "zether"),
        (cfg!(feature = "pqz"), "pqz"),
        (
            cfg!(feature = "pqz-set-n2048-kmax1024"),
            "pqz-set-n2048-kmax1024",
        ),
        (
            cfg!(feature = "pqz-set-n2304-kmax4096"),
            "pqz-set-n2304-kmax4096",
        ),
        (
            cfg!(feature = "pqz-set-n2560-kmax16384"),
            "pqz-set-n2560-kmax16384",
        ),
        (
            cfg!(feature = "pqz-set-n2816-kmax65536"),
            "pqz-set-n2816-kmax65536",
        ),
        (cfg!(feature = "dex"), "dex"),
        (cfg!(feature = "admin"), "admin"),
        (cfg!(feature = "mlock"), "mlock"),
        (cfg!(feature = "file-store"), "file-store"),
    ];
    all.iter().filter(|(on, _)| *on).map(|(_, f)| *f).collect()
}

/// The features of `scaas-ua` the resolved graph enables for this build.
fn ua_features() -> Vec<String> {
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--offline",
            "--locked",
            "-e",
            "features",
            "-i",
            "scaas-ua",
            "--no-default-features",
            "--features",
        ])
        .arg(this_build().join(","))
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let mut f: Vec<String> = text
        .lines()
        .filter_map(|l| l.split("scaas-ua feature \"").nth(1))
        .filter_map(|t| t.split('"').next())
        .map(String::from)
        .collect();
    f.sort();
    f.dedup();
    f
}

#[test]
fn feature_tree() {
    let f = ua_features();
    assert!(
        f.iter().any(|x| x == "wallet"),
        "control: the graph was read: {f:?}"
    );
    assert!(
        !f.iter().any(|x| x == "default"),
        "scaas-ua's defaults are on: {f:?}"
    );
    let sets: Vec<_> = SETS
        .iter()
        .filter(|s| f.contains(&format!("pqz-set-{s}")))
        .collect();
    let asked: Vec<_> = SETS
        .iter()
        .filter(|s| this_build().contains(&format!("pqz-set-{s}").as_str()))
        .collect();
    assert_eq!(sets, asked, "scaas-ua's PQZ sets: {f:?}");
    assert!(sets.len() <= 1);
    assert_eq!(f.iter().any(|x| x == "pqz"), cfg!(feature = "pqz"), "{f:?}");
}
