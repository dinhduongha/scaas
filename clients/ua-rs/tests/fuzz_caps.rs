// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T11: each fuzz target's input past its cap (`fuzz/regress/<target>/over-*`, written by `fuzz/seeds.py
//! --regress`) is refused outside the fuzzer. A JSON input deeper than its decoder's cap must be refused before it reaches
//! `serde_json` (`bounded::vectors_parsed` unchanged): most decoders would refuse the parsed value too, which would hide a
//! missing bound. Positive control per file: the same input without its extra key `x` is accepted and parsed once. The
//! binary targets have no depth: `sealed` one byte short of its tag, `kem_pk` scheme 2 and 1,602 bytes, `mnemonic` past 1 KiB
//! and 24 words. UNAUDITED.
use scaas_ua::wallet::{
    bounded, kem_encaps, vectors_backup_payload, Error, EvmTx, Expect, Manifest, Result, Sealed, SealedContainer, TypedData,
    Vault, Wallet,
};
use serde_json::Value;

fn file(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/fuzz/regress/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// `dec` refuses the file before `serde_json`, and accepts it without `x` after one parse.
fn over_depth(name: &str, dec: impl Fn(&[u8]) -> Result<()>) {
    let b = file(name);
    let before = bounded::vectors_parsed();
    assert_eq!(dec(&b).err(), Some(Error::Argument), "{name}");
    assert_eq!(bounded::vectors_parsed(), before, "{name}: refused before serde_json");
    let mut v: Value = serde_json::from_slice(&b).unwrap();
    v.as_object_mut().unwrap().remove("x").unwrap();
    assert_eq!(dec(&serde_json::to_vec(&v).unwrap()), Ok(()), "{name} without x");
    assert_eq!(bounded::vectors_parsed(), before + 1, "{name} without x: parsed once");
}

#[test]
fn json_inputs_deeper_than_their_cap_are_refused_unparsed() {
    over_depth("typed_data/over-depth-9.json", |b| TypedData::from_json(b).map(|_| ()));
    over_depth("expect/over-depth-5.json", |b| Expect::from_json(b).map(|_| ()));
    over_depth("tx/over-depth-5.json", |b| EvmTx::from_json(b).map(|_| ()));
    over_depth("vault/over-depth-3.json", |b| Vault::from_json(b).map(|_| ()));
    over_depth("manifest/over-depth-4.json", |b| Manifest::from_json(b).map(|_| ()));
    over_depth("manifest/payload-over-depth-5.json", |b| vectors_backup_payload(b).map(|_| ()));
    over_depth("container/over-depth-8.json", |b| SealedContainer::from_json(b).map(|_| ()));
}

#[test]
fn json_inputs_longer_than_their_cap_are_refused_unparsed() {
    // the same files without `x`, padded with spaces to the cap (accepted) and one byte past it (refused, unparsed)
    type Dec<'a> = &'a dyn Fn(&[u8]) -> Result<()>;
    let cases: [(&str, usize, Dec); 7] = [
        ("typed_data/over-depth-9.json", 64 << 10, &|b| TypedData::from_json(b).map(|_| ())),
        ("expect/over-depth-5.json", 16 << 10, &|b| Expect::from_json(b).map(|_| ())),
        ("tx/over-depth-5.json", 16 << 10, &|b| EvmTx::from_json(b).map(|_| ())),
        ("vault/over-depth-3.json", 2 << 20, &|b| Vault::from_json(b).map(|_| ())),
        ("manifest/over-depth-4.json", 1 << 20, &|b| Manifest::from_json(b).map(|_| ())),
        ("manifest/payload-over-depth-5.json", 1 << 20, &|b| vectors_backup_payload(b).map(|_| ())),
        ("container/over-depth-8.json", 4 << 20, &|b| SealedContainer::from_json(b).map(|_| ())),
    ];
    for (name, cap, dec) in cases {
        let mut v: Value = serde_json::from_slice(&file(name)).unwrap();
        v.as_object_mut().unwrap().remove("x");
        let mut b = serde_json::to_vec(&v).unwrap();
        b.resize(cap, b' ');
        assert_eq!(dec(&b), Ok(()), "{name} at {cap} B");
        b.push(b' ');
        let before = bounded::vectors_parsed();
        assert_eq!(dec(&b).err(), Some(Error::Argument), "{name} at {cap} + 1 B");
        assert_eq!(bounded::vectors_parsed(), before, "{name} at {cap} + 1 B: unparsed");
    }
}

#[test]
fn sealed_short_of_its_tag_is_refused() {
    let b = file("sealed/short-tag.bin");
    assert_eq!(Sealed::from_wire(&b).err(), Some(Error::SealOpen));
    let mut full = b.clone();
    full.push(0);
    assert!(Sealed::from_wire(&full).is_ok(), "one byte more: the fixed fields and a 16-byte tag");
}

#[test]
fn sealed_past_its_plaintext_cap_does_not_open() {
    let b = file("sealed/short-tag.bin");
    let key = scaas_ua::wallet::KemKeyPair::generate_ephemeral().unwrap();
    let mut s = Sealed::from_wire(&[&b[..], &[0]].concat()).unwrap();
    s.ciphertext = vec![0; (1 << 20) + 16 + 1];
    assert_eq!(key.open("scaas/test/v1", b"", &s).err(), Some(Error::SealOpen));
}

#[test]
fn kem_pk_of_another_scheme_or_length_is_refused() {
    let s2 = file("kem_pk/scheme-2.bin");
    assert_eq!(kem_encaps(&s2).err(), Some(Error::KemCheck));
    assert_eq!(kem_encaps(&file("kem_pk/len-1602.bin")).err(), Some(Error::KemCheck));
    let mut s1 = s2.clone();
    s1[0] = 1;
    assert!(kem_encaps(&s1).is_ok(), "positive control: the same key at scheme 1");
}

#[test]
fn mnemonic_past_1_kib_or_24_words_is_refused() {
    let long = String::from_utf8(file("mnemonic/over-1025-bytes.txt")).unwrap();
    assert_eq!(long.len(), 1025);
    assert_eq!(Wallet::from_mnemonic(&long, "").err(), Some(Error::Argument));
    assert!(Wallet::from_mnemonic(&long[..1024], "").is_ok(), "positive control: 1,024 bytes");
    let words = String::from_utf8(file("mnemonic/over-25-words.txt")).unwrap();
    assert_eq!(words.split_whitespace().count(), 25);
    assert_eq!(Wallet::from_mnemonic(&words, "").err(), Some(Error::Argument));
}
