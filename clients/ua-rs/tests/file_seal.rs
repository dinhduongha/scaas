// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The generic file seal of the core (decisions CLI-SDK-33 (35); CLI-UAL-65): with `app-core` and without `fam-arweave` a file
//! is sealed and opened (the gate step `ua-core` runs this file with `--no-default-features --features app-core`); the object
//! is exactly bucket + 16 bytes; `open_file` refuses another length, another `size`, another `sha256` and another key, each
//! beside its control; the file key is a `File` handle no other operation takes.
use scaas_ua::file::{bucket, CAP};
use scaas_ua::wallet::{Error, KeyUsage, Nonce, Wallet};
use sha2::{Digest, Sha256};

const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

#[test]
fn a_build_without_fam_arweave_still_seals_and_opens_a_file() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    for size in [0usize, 5, 65_528, 65_529] {
        let file: Vec<u8> = (0..size).map(|i| (i * 7 + 1) as u8).collect();
        let s = k.seal_file(&file).unwrap();
        assert_eq!(s.key.usage(), KeyUsage::File);
        assert_eq!(
            s.object.len() as u64,
            bucket(size as u64, CAP).unwrap() + 16
        );
        assert_eq!(s.ct_sha256, <[u8; 32]>::from(Sha256::digest(&s.object)));
        assert_eq!(s.sha256, <[u8; 32]>::from(Sha256::digest(&file)));
        assert_eq!(
            &k.open_file(&s.key, &s.object, s.size, &s.sha256, &s.ct_sha256)
                .unwrap()[..],
            &file[..]
        );
    }
}

#[test]
fn open_file_refuses_each_mismatch_beside_its_control() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    let s = k.seal_file(b"hello").unwrap();
    assert!(
        k.open_file(&s.key, &s.object, 5, &s.sha256, &s.ct_sha256)
            .is_ok(),
        "control"
    );
    let short = &s.object[..s.object.len() - 1];
    assert_eq!(
        k.open_file(&s.key, short, 5, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::FileLength
    );
    let mut flip = s.object.clone();
    flip[100] ^= 1;
    // with the flipped object's own ctSha256 (a content naming it) the check passes and the tag refuses
    let flip_ct: [u8; 32] = Sha256::digest(&flip).into();
    assert_eq!(
        k.open_file(&s.key, &flip, 5, &s.sha256, &flip_ct)
            .unwrap_err(),
        Error::Aead
    );
    assert_eq!(
        k.open_file(&s.key, &s.object, 4, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::FileFrame
    );
    assert_eq!(
        k.open_file(&s.key, &s.object, 6, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::FileFrame
    );
    assert_eq!(
        k.open_file(&s.key, &s.object, 5, &[0; 32], &s.ct_sha256)
            .unwrap_err(),
        Error::FileHashMismatch
    );
    let other = k.seal_file(b"hello").unwrap();
    assert_ne!(other.object, s.object, "a fresh key per file");
    assert_eq!(
        k.open_file(&other.key, &s.object, 5, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::Aead
    );
    // above the cap: refused before anything is read
    assert_eq!(
        k.open_file(&s.key, &s.object, CAP, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::FileTooLarge
    );
}

#[test]
fn a_file_key_serves_open_file_only() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    let s = k.seal_file(b"x").unwrap();
    assert_eq!(
        k.seal(&s.key, Nonce::Random, b"", b"y").unwrap_err(),
        Error::AppKeyUsage
    );
    let data = k.random_key(KeyUsage::Data).unwrap();
    assert_eq!(
        k.open_file(&data, &s.object, 1, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::AppKeyUsage
    );
    // a wrapped file key comes back as a File handle and opens the object
    let kw = k.random_key(KeyUsage::KeyWrap).unwrap();
    let wire = k.seal_key(&kw, &s.key, b"file").unwrap();
    let back = k.open_key(&kw, &wire, KeyUsage::File, b"file").unwrap();
    assert_eq!(
        &k.open_file(&back, &s.object, 1, &s.sha256, &s.ct_sha256)
            .unwrap()[..],
        b"x"
    );
}

/// pqchat-core T10b, the class fix: `open_file` checks the exact length and `ctSha256` before any decryption; a flipped byte is
/// `FileHashMismatch` (never reaching the tag), another `ctSha256` too; each beside its control.
#[test]
fn open_file_checks_ct_sha256_before_decryption() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    let s = k.seal_file(b"hello").unwrap();
    assert_eq!(
        &k.open_file(&s.key, &s.object, 5, &s.sha256, &s.ct_sha256)
            .unwrap()[..],
        b"hello",
        "control"
    );
    let mut flip = s.object.clone();
    flip[100] ^= 1;
    assert_eq!(
        k.open_file(&s.key, &flip, 5, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::FileHashMismatch
    );
    assert_eq!(
        k.open_file(&s.key, &s.object, 5, &s.sha256, &[0; 32])
            .unwrap_err(),
        Error::FileHashMismatch
    );
    let short = &s.object[..s.object.len() - 1];
    assert_eq!(
        k.open_file(&s.key, short, 5, &s.sha256, &s.ct_sha256)
            .unwrap_err(),
        Error::FileLength
    );
}
