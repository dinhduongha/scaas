// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T2: the wallet core against smartcontracts/vectors/ua/keys.json (written by clientkeys
//! scripts/ua-wallet-vectors.mjs), the published BIP-32 / SLIP-10 / EIP-2333 vectors, zether-prover's R33 rows, the
//! bounded JSON reader and the secret store's revocation (spec §4, §8.2). The tests marked `vectors` read secrets through
//! the test-only hooks of feature `vectors`. UNAUDITED.
use scaas_ua::wallet::{bounded, Error, Network, Wallet};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!("{}/../../{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn keys() -> Value {
    load("smartcontracts/vectors/ua/keys.json")
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn u32_of(v: &Value) -> u32 {
    v.as_u64().unwrap() as u32
}
/// The wallet of a `mnemonics` row by id.
fn wallet(k: &Value, id: &str) -> Wallet {
    let m = arr(k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
const FALCON: [u16; 2] = [0x0132, 0x0135];

#[test]
fn keys_json_ua_rows() {
    let k = keys();
    let mut n = 0;
    let mut falcon = 0;
    for id in ["pq_kat", "bip39_test", "twelve_words", "non_ascii_passphrase"] {
        let w = wallet(&k, id);
        for r in arr(&k, "ua").iter().filter(|r| r["mnemonic"] == id) {
            let kind = r["kind"].as_u64().unwrap() as u16;
            let key = w.ua_key(kind, u32_of(&r["account"]), u32_of(&r["index"]));
            if FALCON.contains(&kind) {
                // Falcon key generation is PQClean's seeded keygen, vendored in T3b (MD-8); until then the kind is unavailable
                assert_eq!(key.err(), Some(Error::KindUnavailable), "{r}");
                falcon += 1;
                continue;
            }
            let key = key.unwrap_or_else(|e| panic!("{r}: {e}"));
            assert_eq!(hex::encode(key.key_data()), r["keyData"].as_str().unwrap().trim_start_matches("0x"), "{r}");
            assert_eq!(key.ua().map(|u| format!("0x{}", hex::encode(u))), r["ua"].as_str().map(str::to_owned), "{r}");
            assert_eq!(key.kind(), kind);
            n += 1;
        }
    }
    assert_eq!((n, falcon), (216 - 32, 32));
}

#[test]
fn keys_json_native_rows() {
    let k = keys();
    let mut n = 0;
    for id in ["pq_kat", "bip39_test", "twelve_words", "non_ascii_passphrase"] {
        let w = wallet(&k, id);
        for r in arr(&k, "native").iter().filter(|r| r["mnemonic"] == id) {
            let net = Network::from_name(r["network"].as_str().unwrap()).unwrap();
            let coin = r["coinType"].as_u64().map(|c| c as u32);
            let key = w.native_key(net, u32_of(&r["index"]), coin).unwrap();
            assert_eq!(hex::encode(key.public_key()), r["publicKey"].as_str().unwrap(), "{r}");
            n += 1;
        }
    }
    assert_eq!(n, arr(&k, "native").len());
}

/// Every refusal row, and its positive control one step inside the range.
#[test]
fn keys_json_refusals_are_argument() {
    let k = keys();
    let w = wallet(&k, "pq_kat");
    let rows = arr(&k, "refusals");
    assert_eq!(rows.len(), 19);
    for r in rows {
        assert_eq!(r["error"], "Argument");
        let got = match r["what"].as_str().unwrap() {
            "ua" => w.ua_key(r["kind"].as_u64().unwrap() as u16, u32_of(&r["account"]), u32_of(&r["index"])).err(),
            _ => {
                let net = Network::from_name(r["network"].as_str().unwrap()).unwrap();
                w.native_key(net, u32_of(&r["index"]), r["coinType"].as_u64().map(|c| c as u32)).err()
            }
        };
        assert_eq!(got.map(|e| e.code()), Some("Argument"), "{r}");
    }
    let top = (1u32 << 31) - 1;
    w.ua_key(0x0101, top, top).unwrap();
    w.ua_key(0x0131, top, top).unwrap();
    w.ua_key(0x0104, top, 0).unwrap();
    w.native_key(Network::Evm, top, None).unwrap();
    w.native_key(Network::Stellar, 0, Some(top)).unwrap();
}

#[test]
fn index_1_refused_for_eip2333_kinds() {
    let w = wallet(&keys(), "pq_kat");
    for kind in [0x0104, 0x0105, 0x0106, 0x0107, 0x0112] {
        w.ua_key(kind, 1, 0).unwrap(); // positive control: another account
        assert_eq!(w.ua_key(kind, 0, 1).err(), Some(Error::Argument), "{kind:#06x}");
    }
    w.ua_key(0x0101, 0, 1).unwrap(); // a UA-tree kind has an index level
}

#[test]
fn normalization_rows_nfkd() {
    let k = keys();
    for r in arr(&k, "normalization") {
        let same = arr(&k, "mnemonics").iter().find(|m| m["id"] == r["sameAs"]).unwrap();
        let a = Wallet::from_mnemonic(r["words"].as_str().unwrap(), r["passphrase"].as_str().unwrap()).unwrap();
        let b = Wallet::from_mnemonic(same["words"].as_str().unwrap(), same["passphrase"].as_str().unwrap()).unwrap();
        assert_eq!(a.ua_key(0x0102, 0, 0).unwrap().key_data(), b.ua_key(0x0102, 0, 0).unwrap().key_data(), "{}", r["id"]);
    }
    // case and spacing as clientkeys' normalizeMnemonic: upper case, runs of blanks, leading / trailing blanks
    let m = &arr(&k, "mnemonics")[0];
    let words = m["words"].as_str().unwrap();
    let loud = format!("  {}\t\n", words.to_uppercase().replace(' ', "   "));
    let a = Wallet::from_mnemonic(&loud, "").unwrap();
    let b = Wallet::from_mnemonic(words, "").unwrap();
    assert_eq!(a.ua_key(0x0103, 0, 0).unwrap().key_data(), b.ua_key(0x0103, 0, 0).unwrap().key_data());
}

#[test]
fn mnemonic_refusals_name_no_input() {
    let words = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
    Wallet::from_mnemonic(words, "").unwrap();
    let bad_checksum = words.replace("better", "bench");
    let unknown = words.replace("bench", "benchx");
    let long = format!("{words} {}", "abandon ".repeat(200));
    for bad in [bad_checksum.as_str(), unknown.as_str(), long.as_str(), "", "bench hurt jump"] {
        let e = Wallet::from_mnemonic(bad, "").err().unwrap();
        assert_eq!(e, Error::Argument);
        assert!(!e.to_string().contains("benchx") && !e.to_string().contains("bench"), "{e}");
    }
}

#[test]
fn bounded_json_refuses_depth_9() {
    let nest = |d: usize| format!("{}1{}", "[".repeat(d), "]".repeat(d));
    assert!(bounded::json(nest(8).as_bytes(), 1024, 8).is_ok());
    assert_eq!(bounded::json(nest(9).as_bytes(), 1024, 8).err(), Some(Error::Argument));
    let obj = |d: usize| format!("{}1{}", "{\"a\":".repeat(d), "}".repeat(d));
    assert!(bounded::json(obj(8).as_bytes(), 1024, 8).is_ok());
    assert_eq!(bounded::json(obj(9).as_bytes(), 1024, 8).err(), Some(Error::Argument));
    // brackets inside strings, escaped quotes, do not count
    let s = format!("[\"{}\\\"{}\"]", "[".repeat(20), "{".repeat(20));
    assert!(bounded::json(s.as_bytes(), 1024, 1).is_ok());
    // a deep input far past serde_json's own limit is refused before the parser recurses
    assert_eq!(bounded::json(nest(100_000).as_bytes(), 1 << 20, 8).err(), Some(Error::Argument));
    // the length bound before anything else
    assert!(bounded::json(b"[1, 2]", 6, 8).is_ok());
    assert_eq!(bounded::json(b"[1, 2]", 5, 8).err(), Some(Error::Argument));
    assert_eq!(bounded::json(b"[1, 2", 64, 8).err(), Some(Error::Argument));
}

#[test]
fn lock_revokes_every_handle_and_keeps_the_wallet_locked() {
    let w = wallet(&keys(), "pq_kat");
    let ua = w.ua_key(0x0102, 0, 0).unwrap();
    let native = w.native_key(Network::Solana, 0, None).unwrap();
    assert_eq!(w.ua_key(0x0102, 0, 0).unwrap().key_data(), ua.key_data()); // positive control: unlocked
    w.lock();
    assert_eq!(w.ua_key(0x0102, 0, 0).err(), Some(Error::WalletLocked));
    assert_eq!(w.native_key(Network::Solana, 0, None).err(), Some(Error::WalletLocked));
    // the public parts stay readable; every secret operation is KeyRevoked (checked through the hook below)
    assert_eq!(ua.key_data().len(), 32);
    assert_eq!(native.public_key().len(), 32);
    w.lock(); // twice is fine
}

#[test]
fn wallet_send_sync() {
    fn ok<T: Send + Sync>() {}
    ok::<Wallet>();
    ok::<scaas_ua::wallet::UaKey>();
    ok::<scaas_ua::wallet::NativeKey>();
}

#[test]
fn generate_is_24_words_and_the_backup_forgets() {
    let (w, mut backup) = Wallet::generate().unwrap();
    let entropy = backup.take().unwrap();
    assert_eq!(entropy.len(), 32);
    assert!(backup.take().is_none());
    let words = bip39::Mnemonic::from_entropy(&entropy).unwrap().to_string();
    assert_eq!(words.split(' ').count(), 24);
    let again = Wallet::from_mnemonic(&words, "").unwrap();
    assert_eq!(w.ua_key(0x0101, 0, 0).unwrap().key_data(), again.ua_key(0x0101, 0, 0).unwrap().key_data());
    let (other, _) = Wallet::generate().unwrap();
    assert_ne!(other.ua_key(0x0101, 0, 0).unwrap().key_data(), again.ua_key(0x0101, 0, 0).unwrap().key_data());
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::wallet::derive::{bip32, eip2333, hkdf_pq, slip10, Curve, HARDENED};

    fn unhex(v: &str) -> Vec<u8> {
        hex::decode(v.trim_start_matches("0x")).unwrap()
    }

    fn path(s: &str) -> Vec<u32> {
        s.split('/').skip(1).map(|c| c.strip_suffix('\'').map_or_else(|| c.parse().unwrap(), |h| h.parse::<u32>().unwrap() | HARDENED)).collect()
    }

    #[test]
    fn keys_json_mnemonic_rows_entropy_and_seed() {
        let k = keys();
        for m in arr(&k, "mnemonics") {
            let w = wallet(&k, m["id"].as_str().unwrap());
            assert_eq!(*w.vectors_entropy().unwrap(), unhex(m["entropy"].as_str().unwrap()), "{}", m["id"]);
            assert_eq!(w.vectors_seed().unwrap()[..], unhex(m["seed"].as_str().unwrap())[..], "{}", m["id"]);
        }
        for r in arr(&k, "normalization") {
            let w = Wallet::from_mnemonic(r["words"].as_str().unwrap(), r["passphrase"].as_str().unwrap()).unwrap();
            assert_eq!(w.vectors_seed().unwrap()[..], unhex(r["seed"].as_str().unwrap())[..], "{}", r["id"]);
        }
    }

    #[test]
    fn twelve_word_entropy_kept_at_16_bytes() {
        let k = keys();
        let w = wallet(&k, "twelve_words");
        assert_eq!(w.vectors_entropy().unwrap().len(), 16);
        assert_eq!(wallet(&k, "pq_kat").vectors_entropy().unwrap().len(), 32);
        // 15, 18, 21 words: each its own length (BIP-39), never padded
        for (words, len) in [(15, 20), (18, 24), (21, 28)] {
            let m = bip39::Mnemonic::from_entropy(&vec![0x5a; len]).unwrap().to_string();
            assert_eq!(m.split(' ').count(), words);
            assert_eq!(Wallet::from_mnemonic(&m, "").unwrap().vectors_entropy().unwrap().len(), len);
        }
    }

    /// The store holds the entropy at its length and the 64-byte seed, nothing else: no copy of the mnemonic (its word
    /// indices live in a `bip39::Mnemonic` that `from_mnemonic` drops, zeroized by the crate's `ZeroizeOnDrop`).
    #[test]
    fn mnemonic_is_not_cloned_and_dropped_after_from_mnemonic() {
        let k = keys();
        assert_eq!(wallet(&k, "twelve_words").vectors_arena_used().unwrap(), 16 + 64);
        let w = wallet(&k, "pq_kat");
        assert_eq!(w.vectors_arena_used().unwrap(), 32 + 64);
        let key = w.ua_key(0x0102, 0, 0).unwrap();
        assert_eq!(w.vectors_arena_used().unwrap(), 32 + 64 + 32);
        w.ua_key(0x0102, 0, 0).unwrap(); // the same key again: its slot, no second copy
        assert_eq!(w.vectors_arena_used().unwrap(), 32 + 64 + 32);
        drop(key);
    }

    /// The bytes a handle's operations read lie in the store's arena, not in the handle (spec §8.2).
    #[test]
    fn handle_holds_no_secret_bytes() {
        let w = wallet(&keys(), "pq_kat");
        for kind in [0x0101, 0x0102, 0x0103, 0x0104, 0x0106, 0x0108, 0x0110, 0x0131, 0x0133] {
            let key = w.ua_key(kind, 0, 0).unwrap();
            assert!(key.vectors_secret_in_arena().unwrap(), "{kind:#06x}");
            let secret = key.vectors_with_secret(|s| s.to_vec()).unwrap();
            assert!(!secret.is_empty() && secret.iter().any(|b| *b != 0));
            assert!(!key.key_data().windows(secret.len()).any(|x| x == secret), "{kind:#06x}");
        }
        let native = w.native_key(Network::Evm, 0, None).unwrap();
        assert!(native.vectors_secret_in_arena().unwrap());
    }

    #[test]
    fn lock_wipes_and_revokes_unlock_never_revives() {
        let k = keys();
        let m = &arr(&k, "mnemonics")[0];
        let w = wallet(&k, "pq_kat");
        let old = w.ua_key(0x0102, 0, 0).unwrap();
        let native = w.native_key(Network::Evm, 0, None).unwrap();
        let before = old.vectors_with_secret(|s| s.to_vec()).unwrap();
        w.lock();
        assert_eq!(old.vectors_with_secret(|s| s.len()).err(), Some(Error::KeyRevoked));
        assert_eq!(native.vectors_with_secret(|s| s.len()).err(), Some(Error::KeyRevoked));
        assert_eq!(w.vectors_seed().err(), Some(Error::WalletLocked));
        w.vectors_unlock(m["words"].as_str().unwrap(), "").unwrap();
        assert_eq!(old.vectors_with_secret(|s| s.len()).err(), Some(Error::KeyRevoked)); // still revoked, for good
        let new = w.ua_key(0x0102, 0, 0).unwrap();
        assert_eq!(new.vectors_with_secret(|s| s.to_vec()).unwrap(), before);
        assert_eq!(new.key_data(), old.key_data());
        // unlocking an unlocked wallet is refused (it would move the slots of live handles)
        assert_eq!(w.vectors_unlock(m["words"].as_str().unwrap(), "").err(), Some(Error::Argument));
    }

    #[test]
    fn wallet_dropped_with_children_retained() {
        let w = wallet(&keys(), "pq_kat");
        let key = w.ua_key(0x0131, 0, 0).unwrap();
        key.vectors_with_secret(|s| s.len()).unwrap();
        drop(w);
        assert_eq!(key.vectors_with_secret(|s| s.len()).err(), Some(Error::KeyRevoked));
        assert_eq!(key.kind(), 0x0131); // valid memory, freed after
    }

    /// `lock()` takes the write lock: it returns only after an operation in flight has left, and no operation starts after.
    #[test]
    fn lock_waits_for_an_operation_in_flight() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::{mpsc, Arc};
        let w = Arc::new(wallet(&keys(), "pq_kat"));
        let key = w.ua_key(0x0103, 0, 0).unwrap();
        let locked = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel::<()>();
        let (l2, w2) = (locked.clone(), w.clone());
        std::thread::scope(|s| {
            let (key, locked) = (&key, &locked);
            let op = s.spawn(move || {
                key.vectors_with_secret(|_| {
                    entered_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    locked.load(Ordering::SeqCst) // false: lock() has not returned while this runs
                })
            });
            entered_rx.recv().unwrap();
            let locker = s.spawn(move || {
                w2.lock();
                l2.store(true, Ordering::SeqCst);
            });
            release_tx.send(()).unwrap();
            assert_eq!(op.join().unwrap(), Ok(false));
            locker.join().unwrap();
        });
        assert!(locked.load(Ordering::SeqCst));
        assert_eq!(key.vectors_with_secret(|_| ()).err(), Some(Error::KeyRevoked));
    }

    /// BIP-32 test vector 1 (bip-0032.mediawiki), through the published extended keys.
    #[test]
    fn bip32_published_vector_1() {
        let seed = unhex("000102030405060708090a0b0c0d0e0f");
        for (p, xprv) in [
            ("m", "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"),
            ("m/0'/1/2'/2/1000000000", "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76"),
        ] {
            let want: bip32::XPrv = xprv.parse().unwrap();
            assert_eq!(*bip32(&seed, &path(p)).unwrap(), want.to_bytes(), "{p}");
        }
    }

    /// SLIP-10 (slip-0010.md at a00312491693714d9bc1b6e4cb5b2e356e6c511e): ed25519 vector 1, nist256p1 vector 1, the
    /// derivation retry (its retry is the non-hardened step m/28578'/33941) and the seed retry.
    #[test]
    fn slip10_published_vectors() {
        let v1 = unhex("000102030405060708090a0b0c0d0e0f");
        for (p, sk, cc) in [
            ("m", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7", "90046a93de5380a72b5e45010748567d5ea02bbf6522f979e05c0d8d8ca9fffb"),
            ("m/0'", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3", "8b59aa11380b624e81507a27fedda59fea6d0b779a778918a2fd3590e16e9c69"),
            ("m/0'/1'/2'/2'/1000000000'", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793", "68789923a0cac2cd5a29172a475fe9e0fb14cd6adb5ad98a3fa70333e7afa230"),
        ] {
            let out = slip10(Curve::Ed25519, &v1, &path(p)).unwrap();
            assert_eq!((hex::encode(&out[..32]), hex::encode(&out[32..])), (sk.into(), cc.into()), "ed25519 {p}");
        }
        assert_eq!(slip10(Curve::Ed25519, &v1, &path("m/0")).err(), Some(Error::Argument)); // hardened only
        let retry_seed = unhex("a7305bc8df8d0951f0cb224c0e95d7707cbdf2c6ce7e8d481fec69c7ff5e9446");
        for (seed, p, sk, cc) in [
            (&v1, "m", "612091aaa12e22dd2abef664f8a01a82cae99ad7441b7ef8110424915c268bc2", "beeb672fe4621673f722f38529c07392fecaa61015c80c34f29ce8b41b3cb6ea"),
            (&v1, "m/0'", "6939694369114c67917a182c59ddb8cafc3004e63ca5d3b84403ba8613debc0c", "3460cea53e6a6bb5fb391eeef3237ffd8724bf0a40e94943c98b83825342ee11"),
            (&v1, "m/0'/1", "284e9d38d07d21e4e281b645089a94f4cf5a5a81369acf151a1c3a57f18b2129", "4187afff1aafa8445010097fb99d23aee9f599450c7bd140b6826ac22ba21d0c"),
            (&v1, "m/0'/1/2'/2/1000000000", "21c4f269ef0a5fd1badf47eeacebeeaa3de22eb8e5b0adcd0f27dd99d34d0119", "b9b7b82d326bb9cb5b5b121066feea4eb93d5241103c9e7a18aad40f1dde8059"),
            (&v1, "m/28578'", "06f0db126f023755d0b8d86d4591718a5210dd8d024e3e14b6159d63f53aa669", "e94c8ebe30c2250a14713212f6449b20f3329105ea15b652ca5bdfc68f6c65c2"),
            (&v1, "m/28578'/33941", "092154eed4af83e078ff9b84322015aefe5769e31270f62c3f66c33888335f3a", "9e87fe95031f14736774cd82f25fd885065cb7c358c1edf813c72af535e83071"),
            (&retry_seed, "m", "3b8c18469a4634517d6d0b65448f8e6c62091b45540a1743c5846be55d47d88f", "7762f9729fed06121fd13f326884c82f59aa95c57ac492ce8c9654e60efd130c"),
        ] {
            let out = slip10(Curve::Nist256p1, seed, &path(p)).unwrap();
            assert_eq!((hex::encode(&out[..32]), hex::encode(&out[32..])), (sk.into(), cc.into()), "nist256p1 {p}");
        }
    }

    /// The four published EIP-2333 cases (master and one child each), BLS12-381 order and salt.
    #[test]
    fn eip2333_published_vectors() {
        for (seed, master, i, child) in [
            ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
             "0d7359d57963ab8fbbde1852dcf553fedbc31f464d80ee7d40ae683122b45070", 0u32, "2d18bd6c14e6d15bf8b5085c9b74f3daae3b03cc2014770a599d8c1539e50f8e"),
            ("3141592653589793238462643383279502884197169399375105820974944592",
             "41c9e07822b092a93fd6797396338c3ada4170cc81829fdfce6b5d34bd5e7ec7", 3141592653, "384843fad5f3d777ea39de3e47a8f999ae91f89e42bffa993d91d9782d152a0f"),
            ("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
             "3cfa341ab3910a7d00d933d8f7c4fe87c91798a0397421d6b19fd5b815132e80", 4294967295, "40e86285582f35b28821340f6a53b448588efa575bc4d88c32ef8567b8d9479b"),
            ("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
             "2a0e28ffa5fbbe2f8e7aad4ed94f745d6bf755c51182e119bb1694fe61d3afca", 42, "455c0dc9fccb3395825d92a60d2672d69416be1c2578a87a7a3d3ced11ebb88d"),
        ] {
            let seed = unhex(seed);
            let salt = b"BLS-SIG-KEYGEN-SALT-";
            assert_eq!(hex::encode(*eip2333::<ark_bls12_381::Fr>(&seed, &[], salt).unwrap()), master);
            assert_eq!(hex::encode(*eip2333::<ark_bls12_381::Fr>(&seed, &[i], salt).unwrap()), child);
        }
        assert_eq!(eip2333::<ark_bls12_381::Fr>(&[7; 31], &[], b"BLS-SIG-KEYGEN-SALT-").err(), Some(Error::Argument));
    }

    /// zether-prover's R33 conf keys (clients/zether-prover/vectors/r33_keys.json, its own EIP-2333 copy) are this EIP-2333
    /// on the Zether paths m/12381/<coin>/<account>/<use> (7: conf key, 8: disclosure key).
    #[test]
    fn eip2333_equals_zether_prover_on_the_zether_path() {
        let r = load("clients/zether-prover/vectors/r33_keys.json");
        let w = Wallet::from_mnemonic(r["mnemonic"].as_str().unwrap(), r["passphrase"].as_str().unwrap()).unwrap();
        let seed = w.vectors_seed().unwrap();
        assert_eq!(seed[..], unhex(r["seed"].as_str().unwrap())[..]);
        let coin = u32_of(&r["coin"]);
        let rows = arr(&r["bls12381"], "keys");
        assert!(rows.len() >= 2);
        for row in rows {
            let p = path(row["path"].as_str().unwrap()); // m/12381/<coin>/<account>/<use>, no hardened step
            assert!(p[0] == 12381 && p[1] == coin && (p[3] == 7 || p[3] == 8), "{}", row["path"]); // conf key, disclosure key
            let x = eip2333::<ark_bls12_381::Fr>(&seed[..], &p, b"BLS-SIG-KEYGEN-SALT-").unwrap();
            assert_eq!(format!("0x{}", hex::encode(*x)), row["x"].as_str().unwrap(), "{}", row["path"]);
        }
    }

    /// The PQ seed: HKDF-SHA256(seed, salt "scaas.ua.pq.v1", info utf8(tag) ‖ be32(account) ‖ be32(index)), as pq.js.
    #[test]
    fn hkdf_pq_seed_is_the_ml_dsa_key() {
        use ml_dsa::{Keypair, MlDsa65, Seed, SigningKey};
        let k = keys();
        let w = wallet(&k, "pq_kat");
        let seed = w.vectors_seed().unwrap();
        for (account, index) in [(0, 0), (1, 0), (0, 1), (1, 1)] {
            let xi = hkdf_pq(&seed[..], "scaas.ua.mldsa65.v1", account, index, 32).unwrap();
            let kp = SigningKey::<MlDsa65>::from_seed(&Seed::try_from(&xi[..]).unwrap());
            let row = arr(&k, "ua").iter().find(|r| r["mnemonic"] == "pq_kat" && r["kind"] == 0x0131 && r["account"] == account && r["index"] == index).unwrap();
            assert_eq!(hex::encode(kp.verifying_key().encode()), row["keyData"].as_str().unwrap().trim_start_matches("0x"));
        }
    }
}
