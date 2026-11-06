// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! include/scaas_ua.h is generated from src/lib.rs and committed; this fails when they drift.
//! `SCAAS_UA_C_BLESS=1 cargo test --locked --test header` rewrites it. ABI v6 (ua-rs-sign T12): the header states its rules,
//! `scaas_ua_kem_key` takes no wallet, and every export of src/lib.rs runs inside the one `catch_unwind` (`run`, `safe`,
//! `json_call`, or the helpers over them, `free` and `restore`) or only calls another export.
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

fn header() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("include/scaas_ua.h")).unwrap()
}

/// The declaration of `name` in the committed header: from its name to the `;`.
fn decl(h: &str, name: &str) -> String {
    let at = h.find(&format!("{name}(")).unwrap_or_else(|| panic!("{name} not in the header"));
    h[at..at + h[at..].find(';').unwrap()].to_owned()
}

#[test]
fn kem_key_takes_no_wallet() {
    let d = decl(&header(), "scaas_ua_kem_key");
    assert!(d.contains("const ScaasUaKey *ua_key") && !d.contains("ScaasUaWallet"), "{d}");
}

#[test]
fn header_states_its_rules() {
    let h = header();
    for rule in [
        "seal authenticates no sender",
        "no replay protection",
        "_free(NULL) is a no-op",
        "exactly once",
        "undefined",
        "zeroizes",
        "any thread",
        "per thread",
        "the caller zeroizes",
        "SCAAS_UA_ERR_KEY_REVOKED",
        "freeing the wallet before its children is defined",
    ] {
        assert!(h.contains(rule), "header rule missing: {rule}");
    }
    assert!(!h.contains("no allocation crosses the ABI") && !h.contains("pure computation over immutable static tables"));
}

#[test]
fn every_export_is_guarded() {
    let src = std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/lib.rs")).unwrap();
    let mut n = 0;
    for (i, _) in src.match_indices("pub extern \"C\" fn ") {
        let name = &src[i + 18..i + 18 + src[i + 18..].find('(').unwrap()];
        // the body: from the signature's `{` (no parameter holds one) to the closing `}` at column 0
        let body_at = i + src[i..].find('{').unwrap();
        let end = src[body_at..].find("\n}\n").map_or(src.len(), |e| body_at + e);
        let body = &src[body_at..end];
        // `free` and `restore` are the guarded helpers (`safe`, `run`) of the `_free` and `restore_backup*` exports
        let guarded = ["run(", "safe(", "json_call(", "free(", "restore("].iter().any(|g| body.contains(g))
            || body.lines().skip(1).filter(|l| !l.trim().is_empty()).any(|l| l.trim_start().starts_with("scaas_ua_"));
        assert!(guarded, "{name}: not inside run / safe / json_call and not a call of another export");
        n += 1;
    }
    assert!(n > 100, "{n} exports");
}
