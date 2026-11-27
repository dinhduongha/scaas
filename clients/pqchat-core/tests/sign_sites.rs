// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! CLI-SDK-36 (reviews A-4, D-4): the crate signs a record in one place. Every `.sign(` of `src/` is the SDK's signing call in
//! `net::sign_now` (a record, a tree commit, a tree exit) or the confirm's port call `self.net.sign(` in `confirm.rs`, so the
//! tests that count the port's signing calls see every signature; a signing call anywhere else fails here. A message's
//! seal-and-sign (`pqchat_seal_message`, CLI-PQC-04: the send is its confirm) is no `.sign(` and stays outside this gate.
#![allow(clippy::unwrap_used, clippy::panic)]

#[test]
fn every_signing_call_is_the_ports() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut seen = vec![];
    for f in std::fs::read_dir(&dir).unwrap() {
        let p = f.unwrap().path();
        if p.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let name = p.file_name().unwrap().to_str().unwrap().to_string();
        for (i, line) in std::fs::read_to_string(&p).unwrap().lines().enumerate() {
            if line.trim_start().starts_with("//") || !line.contains(".sign(") {
                continue;
            }
            seen.push(format!("{name}:{}: {}", i + 1, line.trim()));
        }
    }
    let allowed = |s: &str| {
        (s.starts_with("net.rs:")
            && (s.ends_with("Signature::Record(p.sign().await?),")
                || s.ends_with("Signature::Commit(c.sign()?),")
                || s.ends_with("Signature::Exit(e.sign()?),")))
            || (s.starts_with("confirm.rs:") && s.contains("self.net.sign(p.unsigned)"))
    };
    let bad: Vec<&String> = seen.iter().filter(|s| !allowed(s)).collect();
    assert!(bad.is_empty(), "a signing call outside the port: {bad:#?}");
    assert_eq!(
        seen.len(),
        4,
        "the three SDK calls and the confirm's: {seen:#?}"
    );
}
