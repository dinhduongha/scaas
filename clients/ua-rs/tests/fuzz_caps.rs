// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T11: each fuzz target's input past its cap (`fuzz/regress/<target>/over-*`, written by `fuzz/seeds.py
//! --regress`) is refused outside the fuzzer. A JSON input deeper than its decoder's cap must be refused before it reaches
//! `serde_json` (`bounded::vectors_parsed` unchanged): most decoders would refuse the parsed value too, which would hide a
//! missing bound. Positive control per file: the same input without its extra key `x` is accepted and parsed once. The
//! binary targets have no depth: `sealed` one byte short of its tag, `kem_pk` scheme 2 and 1,602 bytes, `mnemonic` past 1 KiB
//! and 24 words. T12: the container open's JSON inputs (`expect_json`, `accepted_json`: 16 KiB, depth 4; `members_json`: 512 KiB,
//! depth 4, owner 2026-11-06) and
//! the `UASig` request (64 KiB, depth 6) of the C ABI. T14: the Zether command (1 MiB, depth 8) and cache box (2 MiB, depth 1). T15: the PQZ command (1 MiB, depth 8) and
//! cache box (2 MiB, depth 1). UNAUDITED.
use scaas_ua::wallet::{
    bounded, kem_encaps, vectors_backup_payload, AcceptedJson, ContainerExpectJson, Error, EvmTx, Expect, Manifest, MembersJson,
    Result, Sealed, SealedContainer, TypedData, UaSigRequest, Vault, Wallet,
};
use serde_json::Value;

/// Feature `vectors` (Codex C1, T15c2): key handles only after the test-only marker; every test here unlocks first.
fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}

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
    unlock();
    over_depth("typed_data/over-depth-9.json", |b| TypedData::from_json(b).map(|_| ()));
    over_depth("expect/over-depth-5.json", |b| Expect::from_json(b).map(|_| ()));
    over_depth("tx/over-depth-5.json", |b| EvmTx::from_json(b).map(|_| ()));
    over_depth("vault/over-depth-3.json", |b| Vault::from_json(b).map(|_| ()));
    over_depth("manifest/over-depth-4.json", |b| Manifest::from_json(b).map(|_| ()));
    over_depth("manifest/payload-over-depth-5.json", |b| vectors_backup_payload(b).map(|_| ()));
    over_depth("container/over-depth-8.json", |b| SealedContainer::from_json(b).map(|_| ()));
    over_depth("container_expect/over-depth-5.json", |b| ContainerExpectJson::from_json(b).map(|_| ()));
    over_depth("members/over-depth-5.json", |b| MembersJson::from_json(b).map(|_| ()));
    over_depth("accepted/over-depth-5.json", |b| AcceptedJson::from_json(b).map(|_| ()));
    over_depth("uasig/over-depth-7.json", |b| UaSigRequest::from_json(b).map(|_| ()));
}

#[test]
fn json_inputs_longer_than_their_cap_are_refused_unparsed() {
    unlock();
    // the same files without `x`, padded with spaces to the cap (accepted) and one byte past it (refused, unparsed)
    type Dec<'a> = &'a dyn Fn(&[u8]) -> Result<()>;
    let cases: [(&str, usize, Dec); 11] = [
        ("typed_data/over-depth-9.json", 64 << 10, &|b| TypedData::from_json(b).map(|_| ())),
        ("expect/over-depth-5.json", 16 << 10, &|b| Expect::from_json(b).map(|_| ())),
        ("tx/over-depth-5.json", 16 << 10, &|b| EvmTx::from_json(b).map(|_| ())),
        ("vault/over-depth-3.json", 2 << 20, &|b| Vault::from_json(b).map(|_| ())),
        ("manifest/over-depth-4.json", 1 << 20, &|b| Manifest::from_json(b).map(|_| ())),
        ("manifest/payload-over-depth-5.json", 1 << 20, &|b| vectors_backup_payload(b).map(|_| ())),
        ("container/over-depth-8.json", 4 << 20, &|b| SealedContainer::from_json(b).map(|_| ())),
        ("container_expect/over-depth-5.json", 16 << 10, &|b| ContainerExpectJson::from_json(b).map(|_| ())),
        ("members/over-depth-5.json", 512 << 10, &|b| MembersJson::from_json(b).map(|_| ())),
        ("accepted/over-depth-5.json", 16 << 10, &|b| AcceptedJson::from_json(b).map(|_| ())),
        ("uasig/over-depth-7.json", 64 << 10, &|b| UaSigRequest::from_json(b).map(|_| ())),
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
    unlock();
    let b = file("sealed/short-tag.bin");
    assert_eq!(Sealed::from_wire(&b).err(), Some(Error::SealOpen));
    let mut full = b.clone();
    full.push(0);
    assert!(Sealed::from_wire(&full).is_ok(), "one byte more: the fixed fields and a 16-byte tag");
}

#[test]
fn sealed_past_its_plaintext_cap_does_not_open() {
    unlock();
    let b = file("sealed/short-tag.bin");
    let key = scaas_ua::wallet::KemKeyPair::generate_ephemeral().unwrap();
    let mut s = Sealed::from_wire(&[&b[..], &[0]].concat()).unwrap();
    s.ciphertext = vec![0; (1 << 20) + 16 + 1];
    assert_eq!(key.open("scaas/test/v1", b"", &s).err(), Some(Error::SealOpen));
}

#[test]
fn kem_pk_of_another_scheme_or_length_is_refused() {
    unlock();
    let s2 = file("kem_pk/scheme-2.bin");
    assert_eq!(kem_encaps(&s2).err(), Some(Error::KemCheck));
    assert_eq!(kem_encaps(&file("kem_pk/len-1602.bin")).err(), Some(Error::KemCheck));
    let mut s1 = s2.clone();
    s1[0] = 1;
    assert!(kem_encaps(&s1).is_ok(), "positive control: the same key at scheme 1");
}

#[test]
fn mnemonic_past_1_kib_or_24_words_is_refused() {
    unlock();
    let long = String::from_utf8(file("mnemonic/over-1025-bytes.txt")).unwrap();
    assert_eq!(long.len(), 1025);
    assert_eq!(Wallet::from_mnemonic(&long, "").err(), Some(Error::Argument));
    assert!(Wallet::from_mnemonic(&long[..1024], "").is_ok(), "positive control: 1,024 bytes");
    let words = String::from_utf8(file("mnemonic/over-25-words.txt")).unwrap();
    assert_eq!(words.split_whitespace().count(), 25);
    assert_eq!(Wallet::from_mnemonic(&words, "").err(), Some(Error::Argument));
}

/// T12: the expectation, member keys and accepted lists read from the vector rows' JSON are the ones the open uses: each row of
/// `seal.json` with an `expect` reads, an approved set past 64 UAs, an index past `u16` and an unknown key do not.
#[test]
fn container_json_inputs_read_the_vector_rows() {
    unlock();
    let seal: Value = serde_json::from_slice(&std::fs::read(format!("{}/../../smartcontracts/vectors/ua/seal.json", env!("CARGO_MANIFEST_DIR"))).unwrap()).unwrap();
    let mut n = 0;
    for k in ["containers", "acceptance", "replay"] {
        for r in seal[k].as_array().unwrap() {
            assert!(ContainerExpectJson::from_json(r["expect"].to_string().as_bytes()).is_ok(), "{}", r["id"]);
            if let Some(m) = r.get("members") {
                let m2 = MembersJson::from_json(m.to_string().as_bytes()).unwrap();
                for (id, x) in m.as_object().unwrap() {
                    let id: [u8; 32] = hex::decode(&id[2..]).unwrap().try_into().unwrap();
                    assert_eq!(m2.lookup(id), Some((x["kind"].as_u64().unwrap() as u16, hex::decode(&x["keyData"].as_str().unwrap()[2..]).unwrap())));
                }
                assert_eq!(m2.lookup([0; 32]), None);
            }
            if let Some(a) = r.get("accepted").filter(|a| !a.is_null()) {
                let a2 = AcceptedJson::from_json(a.to_string().as_bytes()).unwrap();
                for (id, l) in a.as_object().unwrap() {
                    let id: [u8; 32] = hex::decode(&id[2..]).unwrap().try_into().unwrap();
                    for i in l.as_array().unwrap() {
                        assert!(a2.accepted(id, i.as_u64().unwrap() as u16));
                    }
                    assert!(!a2.accepted(id, 999));
                }
            }
            n += 1;
        }
    }
    assert_eq!(n, 4 + 29 + 9);
    let ua = format!("\"0x{}\"", "11".repeat(32));
    let set = |k: usize| format!("{{\"purpose\":\"scaas/backup/v1\",\"sender\":{{\"set\":[{}]}},\"recipient\":{{\"kemPkHash\":{ua}}}}}", vec![ua.clone(); k].join(","));
    assert!(ContainerExpectJson::from_json(set(64).as_bytes()).is_ok(), "64 UAs (control)");
    assert_eq!(ContainerExpectJson::from_json(set(65).as_bytes()).err(), Some(Error::Argument), "65 UAs");
    let extra = set(1).replacen('{', "{\"x\":1,", 1);
    assert_eq!(ContainerExpectJson::from_json(extra.as_bytes()).err(), Some(Error::Argument), "unknown key");
    assert!(AcceptedJson::from_json(format!("{{{ua}:[65535]}}").as_bytes()).is_ok(), "u16 (control)");
    assert_eq!(AcceptedJson::from_json(format!("{{{ua}:[65536]}}").as_bytes()).err(), Some(Error::Argument), "past u16");
}

/// T14: the Zether facade's command reader (1 MiB, depth 8) and cache-box reader (2 MiB, depth 1), each fuzz input behind its
/// index byte (`fuzz/seeds.py` names the commands in `COMMANDS`' order). Past a cap: refused before `serde_json`; without the
/// extra `x`: the command is accepted, the box parsed once and refused only by its tag (`Aead`: another wallet's key).
#[cfg(feature = "zether")]
#[test]
fn zether_inputs_past_their_caps_are_refused_unparsed() {
    unlock();
    use scaas_ua::facade::zether::{ZetherCmd, COMMANDS};
    // the spec's caps (§9.3) and the box's, stated here: not the crate's constants, which a changed cap would move too
    const CMD_MAX: usize = 1 << 20;
    const BOX_MAX: usize = 2 << 20;
    let src = std::fs::read_to_string(format!("{}/fuzz/seeds.py", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let list = &src[src.find("ZCMDS = [").unwrap() + 9..];
    let named: Vec<&str> = list[..list.find(']').unwrap()].split(',').map(|s| s.trim().trim_matches('"')).collect();
    assert_eq!(named, COMMANDS, "seeds.py's ZCMDS is COMMANDS");
    let w = Wallet::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow", "").unwrap();
    let k = w.zether_key(60, 0, 7).unwrap();
    let split = |name: &str| {
        let b = file(name);
        (b[0] as usize, b[1..].to_vec())
    };
    let without_x = |b: &[u8]| {
        let mut v: Value = serde_json::from_slice(b).unwrap();
        v.as_object_mut().unwrap().remove("x").unwrap();
        serde_json::to_vec(&v).unwrap()
    };
    // the command
    let (i, b) = split("zether_cmd/cmd-over-depth-9.bin");
    let cmd = COMMANDS[i];
    assert_eq!(cmd, "proveTransfer");
    let before = bounded::vectors_parsed();
    assert_eq!(ZetherCmd::from_json(cmd, &b).err(), Some(Error::Argument));
    assert_eq!(bounded::vectors_parsed(), before, "deeper than 8: refused before serde_json");
    let mut ok = without_x(&b);
    assert!(ZetherCmd::from_json(cmd, &ok).is_ok(), "without x");
    assert_eq!(bounded::vectors_parsed(), before + 1);
    ok.resize(CMD_MAX, b' ');
    assert!(ZetherCmd::from_json(cmd, &ok).is_ok(), "at 1 MiB");
    ok.push(b' ');
    let before = bounded::vectors_parsed();
    assert_eq!(ZetherCmd::from_json(cmd, &ok).err(), Some(Error::Argument), "1 MiB + 1");
    assert_eq!(bounded::vectors_parsed(), before, "1 MiB + 1: unparsed");
    // the fuzz finding: a float number (it did not read back to itself) is refused
    let (i, b) = split("zether_cmd/float-number.bin");
    assert_eq!(ZetherCmd::from_json(COMMANDS[i % (COMMANDS.len() + 1)], &b).err(), Some(Error::Argument), "float-number.bin");
    // the cache box
    let (i, b) = split("zether_cmd/box-over-depth-2.bin");
    assert_eq!(i, COMMANDS.len(), "the index after the last command");
    let before = bounded::vectors_parsed();
    assert_eq!(k.open_balance_cache(&b).err(), Some(Error::Argument));
    assert_eq!(bounded::vectors_parsed(), before, "deeper than 1: refused before serde_json");
    let mut ok = without_x(&b);
    assert_eq!(k.open_balance_cache(&ok).err(), Some(Error::Aead), "without x: parsed, another wallet's box");
    assert_eq!(bounded::vectors_parsed(), before + 1);
    ok.resize(BOX_MAX, b' ');
    assert_eq!(k.open_balance_cache(&ok).err(), Some(Error::Aead), "at 2 MiB");
    ok.push(b' ');
    let before = bounded::vectors_parsed();
    assert_eq!(k.open_balance_cache(&ok).err(), Some(Error::Argument), "2 MiB + 1");
    assert_eq!(bounded::vectors_parsed(), before, "2 MiB + 1: unparsed");
}

#[cfg(feature = "pqz")]
#[test]
fn pqz_inputs_past_their_caps_are_refused_unparsed() {
    unlock();
    use scaas_ua::facade::pqz::{PqzCmd, COMMANDS};
    // the spec's caps (§9.3) and the box's, stated here: not the crate's constants, which a changed cap would move too
    // T15e: the PQZ command cap is 4 MiB (a debit's raw words; spec no-decryption-oracle §4.3)
    const CMD_MAX: usize = 4 << 20;
    const BOX_MAX: usize = 2 << 20;
    let src = std::fs::read_to_string(format!("{}/fuzz/seeds.py", env!("CARGO_MANIFEST_DIR"))).unwrap();
    let list = &src[src.find("QCMDS = [").unwrap() + 9..];
    let named: Vec<&str> = list[..list.find(']').unwrap()].split(',').map(|s| s.trim().trim_matches('"')).collect();
    assert_eq!(named, COMMANDS, "seeds.py's QCMDS is COMMANDS");
    let w = Wallet::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow", "").unwrap();
    let k = w.pqz_key(0, 0).unwrap();
    let split = |name: &str| {
        let b = file(name);
        (b[0] as usize, b[1..].to_vec())
    };
    let without_x = |b: &[u8]| {
        let mut v: Value = serde_json::from_slice(b).unwrap();
        v.as_object_mut().unwrap().remove("x").unwrap();
        serde_json::to_vec(&v).unwrap()
    };
    // the command
    let (i, b) = split("pqz_cmd/cmd-over-depth-9.bin");
    let cmd = COMMANDS[i];
    assert_eq!(cmd, "proveRegister");
    let before = bounded::vectors_parsed();
    assert_eq!(PqzCmd::from_json(cmd, &b).err(), Some(Error::Argument));
    assert_eq!(bounded::vectors_parsed(), before, "deeper than 8: refused before serde_json");
    let mut ok = without_x(&b);
    assert!(PqzCmd::from_json(cmd, &ok).is_ok(), "without x");
    assert_eq!(bounded::vectors_parsed(), before + 1);
    ok.resize(CMD_MAX, b' ');
    assert!(PqzCmd::from_json(cmd, &ok).is_ok(), "at 4 MiB");
    ok.push(b' ');
    let before = bounded::vectors_parsed();
    assert_eq!(PqzCmd::from_json(cmd, &ok).err(), Some(Error::Argument), "4 MiB + 1");
    assert_eq!(bounded::vectors_parsed(), before, "4 MiB + 1: unparsed");
    // the cache box
    let (i, b) = split("pqz_cmd/box-over-depth-2.bin");
    assert_eq!(i, COMMANDS.len(), "the index after the last command");
    let before = bounded::vectors_parsed();
    assert_eq!(k.open_balance_cache(&b).err(), Some(Error::Argument));
    assert_eq!(bounded::vectors_parsed(), before, "deeper than 1: refused before serde_json");
    let mut ok = without_x(&b);
    assert_eq!(k.open_balance_cache(&ok).err(), Some(Error::Aead), "without x: parsed, opens under no key");
    assert_eq!(bounded::vectors_parsed(), before + 1);
    ok.resize(BOX_MAX, b' ');
    assert_eq!(k.open_balance_cache(&ok).err(), Some(Error::Aead), "at 2 MiB");
    ok.push(b' ');
    let before = bounded::vectors_parsed();
    assert_eq!(k.open_balance_cache(&ok).err(), Some(Error::Argument), "2 MiB + 1");
    assert_eq!(bounded::vectors_parsed(), before, "2 MiB + 1: unparsed");
}
