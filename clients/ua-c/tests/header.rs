// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! include/scaas_ua.h is generated from src/lib.rs and committed; this fails when they drift.
//! `SCAAS_UA_C_BLESS=1 cargo test --locked --test header` rewrites it.
use std::path::Path;

#[test]
fn header_matches_src() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let config = cbindgen::Config::from_file(dir.join("cbindgen.toml")).unwrap();
    let mut generated = Vec::new();
    cbindgen::Builder::new()
        .with_config(config)
        .with_src(dir.join("src/lib.rs"))
        .generate()
        .unwrap()
        .write(&mut generated);
    let path = dir.join("include/scaas_ua.h");
    if std::env::var_os("SCAAS_UA_C_BLESS").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "include/scaas_ua.h drifted from src/lib.rs; regenerate with SCAAS_UA_C_BLESS=1 cargo test --locked --test header"
    );
}
