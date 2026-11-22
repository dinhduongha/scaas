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
        (cfg!(feature = "classical-roots"), "classical-roots"),
        (cfg!(feature = "app-core"), "app-core"),
        (cfg!(feature = "pqchat-records"), "pqchat-records"),
        (cfg!(feature = "vectors"), "vectors"),
        (cfg!(feature = "soroban"), "soroban"),
        (cfg!(feature = "solana"), "solana"),
        (cfg!(feature = "near"), "near"),
        (cfg!(feature = "algorand"), "algorand"),
        (cfg!(feature = "aptos"), "aptos"),
        (cfg!(feature = "sui"), "sui"),
        (cfg!(feature = "cosmos"), "cosmos"),
        (cfg!(feature = "ton"), "ton"),
        (cfg!(feature = "substrate"), "substrate"),
        (cfg!(feature = "native-networks"), "native-networks"),
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
    // pqchat-core T1: scaas-ua's test feature comes only with the SDK's own `vectors`
    assert_eq!(
        f.iter().any(|x| x == "vectors"),
        cfg!(feature = "vectors"),
        "{f:?}"
    );
}

/// Plan T42: each SDK family feature and the `scaas-ua` `fam-<row>` features it enables (CLI-SDK-33 (31)); EVM is
/// `account` / `wallet`'s, Bitcoin, NEAR and Polkadot's native keys `native-networks`', the native keys of every build
/// (spec §8.5) `vault`'s (CLI-SDK-33 (37)).
const FAMILY: [(&str, &[&str]); 13] = [
    (
        "vault",
        &[
            "fam-evm",
            "fam-hedera",
            "fam-cosmos",
            "fam-sui",
            "fam-soroban",
            "fam-ton",
            "fam-aptos",
            "fam-solana",
        ],
    ),
    ("account", &["fam-evm"]),
    ("wallet", &["fam-evm"]),
    ("soroban", &["fam-soroban"]),
    ("solana", &["fam-solana"]),
    ("near", &["fam-near"]),
    ("algorand", &["fam-algorand"]),
    ("aptos", &["fam-aptos"]),
    ("sui", &["fam-sui"]),
    ("cosmos", &["fam-cosmos"]),
    ("ton", &["fam-ton"]),
    ("substrate", &["fam-dot"]),
    ("native-networks", &["fam-btc", "fam-near", "fam-dot"]),
];
/// Every `fam-<row>` of `scaas-ua` (one per row of chain-support).
const ROWS: [&str; 13] = [
    "fam-evm",
    "fam-hedera",
    "fam-near",
    "fam-algorand",
    "fam-cosmos",
    "fam-aptos",
    "fam-solana",
    "fam-soroban",
    "fam-sui",
    "fam-ton",
    "fam-dot",
    "fam-btc",
    "fam-arweave",
];

/// The `[features]` table of a Cargo.toml as (name, entries), read line by line (one entry per line or one line).
fn features_of(path: &str) -> Vec<(String, Vec<String>)> {
    let text = std::fs::read_to_string(format!("{}/{path}", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let body = text.split("[features]").nth(1).unwrap();
    let body = body.split("\n[").next().unwrap();
    let mut out: Vec<(String, Vec<String>)> = vec![];
    let mut open = false;
    for l in body
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if !open {
            let (k, v) = l.split_once(" = ").unwrap();
            out.push((k.to_string(), vec![]));
            open = !v.contains(']');
            out.last_mut().unwrap().1.extend(entries(v));
        } else {
            open = !l.contains(']');
            out.last_mut().unwrap().1.extend(entries(l));
        }
    }
    out
}
fn entries(l: &str) -> Vec<String> {
    l.split('"').skip(1).step_by(2).map(String::from).collect()
}

/// The SDK's family features each enable exactly their `scaas-ua` rows (and no other feature enables a row); in the
/// resolved graph of this build too.
#[test]
fn family_features_enable_their_rows() {
    let sdk = features_of("Cargo.toml");
    for (name, list) in &sdk {
        let rows: Vec<&str> = list
            .iter()
            .filter_map(|e| e.strip_prefix("scaas-ua/"))
            .filter(|e| e.starts_with("fam-") || e.starts_with("xcheck-"))
            .collect();
        let want = FAMILY
            .iter()
            .find(|(f, _)| f == name)
            .map_or(&[][..], |(_, r)| *r);
        assert_eq!(rows, want, "SDK feature {name}");
    }
    for (f, _) in FAMILY {
        assert!(sdk.iter().any(|(n, _)| n == f), "{f}");
    }
    let mut want: Vec<String> = FAMILY
        .iter()
        .filter(|(f, _)| this_build().contains(f))
        .flat_map(|(_, r)| r.iter().map(|x| x.to_string()))
        .collect();
    want.sort();
    want.dedup();
    let got: Vec<String> = ua_features()
        .into_iter()
        .filter(|x| x.starts_with("fam-") || x.starts_with("xcheck-"))
        .collect();
    assert_eq!(got, want, "the graph's scaas-ua rows");
}

/// `scaas-ua`'s placement (CLI-SDK-33 (31)): every row a feature, all on by default, no `xcheck-*` by default; RLP is
/// `fam-evm`'s and sr25519 `fam-dot`'s, never the core's; the core (`wallet` with `signers`, `pq`) keeps BIP-39, BIP-32, HKDF,
/// ML-KEM, AEAD, the KDFs and MuSig2 / FROST.
#[test]
fn ua_rows_and_the_core() {
    let ua = features_of("../ua-rs/Cargo.toml");
    let get = |n: &str| {
        ua.iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("scaas-ua feature {n}"))
    };
    let default = get("default");
    for r in ROWS {
        get(r);
        assert!(default.iter().any(|d| d == r), "{r} on by default");
    }
    for (k, _) in &ua {
        assert!(
            !(k.starts_with("xcheck-") && default.contains(k)),
            "{k} by default"
        );
        if k.starts_with("fam-") {
            assert!(ROWS.contains(&k.as_str()), "{k}: not a row");
        }
    }
    let wallet = get("wallet");
    for chain in ["dep:alloy-rlp", "dep:schnorrkel", "dep:pbkdf2"] {
        assert!(!wallet.iter().any(|d| d == chain), "{chain} in the core");
    }
    assert!(get("fam-evm").iter().any(|d| d == "dep:alloy-rlp"));
    assert!(get("fam-dot").iter().any(|d| d == "dep:schnorrkel"));
    for core in [
        "dep:bip39",
        "dep:bip32",
        "dep:hkdf",
        "dep:ml-kem",
        "dep:aes-gcm",
        "dep:scrypt",
        "signers",
        "pq",
    ] {
        assert!(wallet.iter().any(|d| d == core), "{core} not in the core");
    }
    assert!(get("signers").iter().any(|d| d == "dep:frost-secp256k1"));
}

/// Plan T42: `scaas-ua`'s `FeatureMissing` (a family this build leaves out) is the SDK's own, never `Ua(..)`.
#[test]
fn ua_feature_missing_is_the_sdks() {
    use scaas_sdk::SdkError;
    use scaas_ua::wallet::Error;
    assert!(matches!(
        SdkError::from(Error::FeatureMissing),
        SdkError::FeatureMissing
    ));
    assert!(
        matches!(
            SdkError::from(Error::Argument),
            SdkError::Ua(Error::Argument)
        ),
        "control"
    );
}
