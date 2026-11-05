// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T7: the UA KEM key (spec §6.1, C-05, MD-11), the combiner, the encapsulation and decapsulation checks (§6.2),
//! against smartcontracts/vectors/ua/kem.json (written by clientkeys `kem.js`) and pq_external.json (ACVP ML-KEM-1024 `keyGen`,
//! `encapDecap`; RFC 7748). The `vectors` tests use the test-only entry points (fixed `m` and `e`, the ephemeral key from 96
//! given bytes, the raw ML-KEM and X25519 steps, the store's self-test count). UNAUDITED.
use scaas_ua::keccak256;
use scaas_ua::wallet::{is_kem_holder, kem_encaps, Error, KemKeyPair, Wallet};
use serde_json::Value;

fn path(f: &str) -> String {
    format!("{}/../../smartcontracts/vectors/ua/{f}", env!("CARGO_MANIFEST_DIR"))
}
fn load(f: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path(f)).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn num(v: &Value) -> u64 {
    match v {
        Value::String(s) => s.parse().unwrap(),
        v => v.as_u64().unwrap(),
    }
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// The KEM key a `{mnemonic, kind, account, index, version}` names, and its wallet (dropping it revokes the key).
fn kem_of(r: &Value) -> (Wallet, KemKeyPair) {
    let w = wallet(r["mnemonic"].as_str().unwrap());
    let key = w.ua_key(num(&r["kind"]) as u16, num(&r["account"]) as u32, num(&r["index"]) as u32);
    let kk = key.unwrap().kem_key(num(&r["version"])).unwrap();
    (w, kk)
}

/// kem.json `keys`: every row's UA and `kemPk` (both versions, accounts, indices, `u64::MAX`, a 12-word mnemonic), `kemPkHash`.
#[test]
fn kem_json_keys() {
    let v = load("kem.json");
    let mut n = 0;
    for r in arr(&v, "keys") {
        let w = wallet(r["mnemonic"].as_str().unwrap());
        let key = w.ua_key(num(&r["kind"]) as u16, num(&r["account"]) as u32, num(&r["index"]) as u32).unwrap();
        assert_eq!(key.ua().unwrap(), b32(&r["ua"]), "{r}");
        let kk = key.kem_key(num(&r["version"])).unwrap();
        assert_eq!(hex::encode(kk.kem_pk()), hex::encode(bytes(&r["kemPk"])), "{r}");
        assert_eq!(keccak256(&kk.kem_pk()), b32(&r["kemPkHash"]), "{r}");
        n += 1;
    }
    assert_eq!(n, 14);
}

/// kem.json `refusals`: a kind that is not a KEM holder is `KemHolder` (its UA key itself derives: control); an `msig` cannot be
/// asked (MD-11: no wallet handle of kind `0x0120` exists, and it is no KEM holder); a version ≥ 2^64 is not a `u64`.
#[test]
fn kem_json_refusals() {
    let v = load("kem.json");
    let w = wallet("pq_kat");
    let mut n = 0;
    for r in arr(&v, "refusals") {
        let kind = num(&r["kind"]) as u16;
        match (r["error"].as_str().unwrap(), kind) {
            ("KemHolder", 0x0120) => {
                assert!(!is_kem_holder(kind));
                assert!(w.ua_key(kind, 0, 0).is_err(), "no msig handle");
            }
            ("KemHolder", _) => {
                assert!(!is_kem_holder(kind));
                let key = w.ua_key(kind, 0, 0).unwrap();
                assert_eq!(key.kem_key(num(&r["version"])).err(), Some(Error::KemHolder), "{r}");
            }
            ("Argument", _) => assert!(r["version"].as_str().unwrap().parse::<u64>().is_err()),
            e => panic!("{e:?}"),
        }
        n += 1;
    }
    assert_eq!(n, 11);
    for kind in [0x0130, 0x0131, 0x0132, 0x0134, 0x0135] {
        assert!(is_kem_holder(kind));
    }
    assert!(!is_kem_holder(0x0133));
}

/// kem.json `decaps`: the row's `ss` (a flipped `mlkemCt` byte: ML-KEM's implicit rejection, another `ss` and no error), or
/// `KemCheck` (1,567-byte `mlkemCt`; small-order `E`); a 31-byte `x25519Eph` is not a `[u8; 32]`.
#[test]
fn kem_json_decaps() {
    let v = load("kem.json");
    let mut n = 0;
    for r in arr(&v, "decaps") {
        let (_w, kk) = kem_of(&r["key"]);
        let eph = bytes(&r["x25519Eph"]);
        let Ok(eph) = <[u8; 32]>::try_from(eph) else {
            assert_eq!(r["error"], "KemCheck", "{r}");
            n += 1;
            continue;
        };
        match kk.decaps(&bytes(&r["mlkemCt"]), &eph) {
            Ok(ss) => assert_eq!(*ss, b32(&r["ss"]), "{r}"),
            Err(e) => assert_eq!(e.code(), r["error"].as_str().unwrap_or("none"), "{r}"),
        }
        n += 1;
    }
    assert_eq!(n, 7);
}

/// A release encapsulation (OS randomness) to a derived key decapsulates to the same `ss`; two encapsulations differ.
#[test]
fn release_encaps_round_trip() {
    let w = wallet("pq_kat");
    let kk = w.ua_key(0x0134, 0, 0).unwrap().kem_key(3).unwrap();
    let (ct, eph, ss) = kem_encaps(&kk.kem_pk()).unwrap();
    assert_eq!((ct.len(), *kk.decaps(&ct, &eph).unwrap()), (1568, *ss));
    let (ct2, _, ss2) = kem_encaps(&kk.kem_pk()).unwrap();
    assert_ne!((ct, *ss), (ct2, *ss2));
}

/// kem.json `encapsRefusals` through the release call: `KemCheck` (modulus, length, scheme, all-zero `ss_X`); control: a
/// derived key's `kemPk` encapsulates.
#[test]
fn kem_json_encaps_refusals_release() {
    let v = load("kem.json");
    let good = bytes(&arr(&v, "keys")[0]["kemPk"]);
    assert!(kem_encaps(&good).is_ok());
    for r in arr(&v, "encapsRefusals") {
        assert_eq!(kem_encaps(&bytes(&r["kemPk"])).err(), Some(Error::KemCheck), "{r}");
    }
    assert_eq!(kem_encaps(&[]).err(), Some(Error::KemCheck));
}

/// Ephemeral keys (OS RNG, a store of their own): two differ, each decapsulates what is sealed to it.
#[test]
fn ephemeral_round_trip() {
    let (a, b) = (KemKeyPair::generate_ephemeral().unwrap(), KemKeyPair::generate_ephemeral().unwrap());
    assert_ne!(a.kem_pk(), b.kem_pk());
    let (ct, eph, ss) = kem_encaps(&a.kem_pk()).unwrap();
    assert_eq!(*a.decaps(&ct, &eph).unwrap(), *ss);
    assert_ne!(*b.decaps(&ct, &eph).unwrap(), *ss, "implicit rejection: another ss");
}

/// C-05: a handle of wallet A derives A's KEM key while a wallet B of another mnemonic is unlocked (no call can name B).
#[test]
fn kem_key_of_wallet_a_handle_is_a_derivation_while_wallet_b_unlocked() {
    let v = load("kem.json");
    let row = |m: &str| arr(&v, "keys").iter().find(|r| r["mnemonic"] == m && r["kind"] == 304 && r["version"] == 0).unwrap();
    let (a, b) = (wallet("pq_kat"), wallet("twelve_words"));
    let (ka, kb) = (a.ua_key(0x0130, 0, 0).unwrap(), b.ua_key(0x0130, 0, 0).unwrap());
    let (pa, pb) = (ka.kem_key(0).unwrap().kem_pk(), kb.kem_key(0).unwrap().kem_pk());
    assert_eq!(pa, bytes(&row("pq_kat")["kemPk"]));
    assert_eq!(pb, bytes(&row("twelve_words")["kemPk"]));
    assert_ne!(pa, pb);
}

/// §8.2: after `lock()` the UA handle's `kem_key` and the KEM handle's `decaps` are `KeyRevoked`, and stay so after unlock; a
/// new handle works.
#[test]
fn kem_handles_revoked_by_lock() {
    let w = wallet("pq_kat");
    let key = w.ua_key(0x0130, 0, 0).unwrap();
    let kk = key.kem_key(0).unwrap();
    let (ct, eph, ss) = kem_encaps(&kk.kem_pk()).unwrap();
    assert_eq!(*kk.decaps(&ct, &eph).unwrap(), *ss);
    w.lock();
    assert_eq!(key.kem_key(0).err(), Some(Error::KeyRevoked));
    assert_eq!(kk.decaps(&ct, &eph).err(), Some(Error::KeyRevoked));
    assert_eq!(w.ua_key(0x0130, 0, 0).err(), Some(Error::WalletLocked));
    #[cfg(feature = "vectors")]
    {
        let k = load("keys.json");
        let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == "pq_kat").unwrap();
        w.vectors_unlock(m["words"].as_str().unwrap(), "").unwrap();
        assert_eq!(key.kem_key(0).err(), Some(Error::KeyRevoked));
        assert_eq!(kk.decaps(&ct, &eph).err(), Some(Error::KeyRevoked));
        let fresh = w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
        assert_eq!(*fresh.decaps(&ct, &eph).unwrap(), *ss);
    }
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::wallet::kem;

    fn eph_key(r: &Value) -> KemKeyPair {
        KemKeyPair::vectors_ephemeral(&bytes(&r["ephemeralSeed"]).try_into().unwrap()).unwrap()
    }

    /// kem.json `encaps`: with the row's `m` and `e`, `(mlkemCt, x25519Eph, ss)` byte-equal; the recipient (a derived key or the
    /// ephemeral key of 96 given bytes) has the row's `kemPk` and decapsulates to `ss`.
    #[test]
    fn kem_json_encaps() {
        let v = load("kem.json");
        let mut n = 0;
        for r in arr(&v, "encaps") {
            let rc = &r["recipient"];
            let (_w, kk) = if rc["ephemeralSeed"].is_string() { (None, eph_key(rc)) } else { let (w, k) = kem_of(rc); (Some(w), k) };
            assert_eq!(kk.kem_pk(), bytes(&r["kemPk"]), "{}", r["id"]);
            let (ct, eph, ss) = kem::vectors_encaps(&bytes(&r["kemPk"]), &b32(&r["m"]), &b32(&r["e"])).unwrap();
            assert_eq!(hex::encode(&ct), hex::encode(bytes(&r["mlkemCt"])), "{}", r["id"]);
            assert_eq!((eph, *ss), (b32(&r["x25519Eph"]), b32(&r["ss"])), "{}", r["id"]);
            assert_eq!(*kk.decaps(&ct, &eph).unwrap(), *ss, "{}", r["id"]);
            n += 1;
        }
        assert_eq!(n, 3);
    }

    /// kem.json `encapsRefusals` with the row's `m` and `e`: `KemCheck`; control: the same `m`, `e` to a valid key.
    #[test]
    fn kem_json_encaps_refusals() {
        let v = load("kem.json");
        let good = bytes(&arr(&v, "keys")[0]["kemPk"]);
        for r in arr(&v, "encapsRefusals") {
            let (m, e) = (b32(&r["m"]), b32(&r["e"]));
            assert!(kem::vectors_encaps(&good, &m, &e).is_ok());
            assert_eq!(kem::vectors_encaps(&bytes(&r["kemPk"]), &m, &e).err(), Some(Error::KemCheck), "{}", r["id"]);
        }
    }

    /// The modulus check alone (FIPS 203 §7.2), not the crate's: control and one coefficient = q.
    #[test]
    fn ek_modulus_check() {
        let v = load("kem.json");
        let mut ek = bytes(&arr(&v, "keys")[0]["kemPk"])[1..1569].to_vec();
        assert!(kem::ek_modulus_ok(&ek));
        ek[0] = 0x01; // coefficient 0 = 0xd01 = 3329 = q
        ek[1] = (ek[1] & 0xf0) | 0x0d;
        assert!(!kem::ek_modulus_ok(&ek));
        assert!(!kem::ek_modulus_ok(&ek[..1567]));
    }

    /// ACVP ML-KEM-1024 `keyGen`: `KeyGen_internal(d, z)` gives the row's `ek` and expanded `dk`.
    #[test]
    fn acvp_mlkem_keygen() {
        let v = load("pq_external.json");
        let cases = arr(&v["acvp_mlkem_keygen"], "cases");
        for c in cases {
            let (ek, dk) = kem::vectors_mlkem_keygen(&b32(&c["d"]), &b32(&c["z"]));
            assert_eq!((hex::encode(ek), hex::encode(&*dk)), (hex::encode(bytes(&c["ek"])), hex::encode(bytes(&c["dk"]))), "tc {}", c["tc"]);
        }
        assert_eq!(cases.len(), 5);
    }

    /// ACVP ML-KEM-1024 `encapDecap`: encapsulation (`m` given), decapsulation (modified ciphertexts: implicit rejection), the
    /// §7.3 decapsulation-key check and the §7.2 encapsulation-key check against each row's `valid`.
    #[test]
    fn acvp_mlkem_encap_decap() {
        let v = &load("pq_external.json")["acvp_mlkem_encapdecap"];
        for c in arr(v, "encapsulation") {
            let (ct, k) = kem::vectors_mlkem_encaps(&bytes(&c["ek"]), &b32(&c["m"])).unwrap();
            assert_eq!((hex::encode(ct), *k), (hex::encode(bytes(&c["c"])), b32(&c["k"])), "tc {}", c["tc"]);
        }
        for c in arr(v, "decapsulation") {
            assert_eq!(*kem::vectors_mlkem_decaps(&bytes(&c["dk"]), &bytes(&c["c"])).unwrap(), b32(&c["k"]), "tc {}", c["tc"]);
        }
        let (mut dk_ok, mut ek_ok) = (0, 0);
        for c in arr(v, "dkCheck") {
            assert_eq!(kem::dk_check_ok(&bytes(&c["dk"])), c["valid"].as_bool().unwrap(), "tc {}", c["tc"]);
            dk_ok += c["valid"].as_bool().unwrap() as usize;
        }
        for c in arr(v, "ekCheck") {
            assert_eq!(kem::ek_modulus_ok(&bytes(&c["ek"])), c["valid"].as_bool().unwrap(), "tc {}", c["tc"]);
            ek_ok += c["valid"].as_bool().unwrap() as usize;
        }
        assert_eq!((dk_ok, ek_ok), (5, 5));
    }

    /// RFC 7748 §5.2 X25519 (both single multiplications, 1 and 1,000 iterations) and §6.1 Diffie-Hellman.
    #[test]
    fn rfc7748() {
        let v = &load("pq_external.json")["rfc7748"];
        for c in arr(v, "scalarMult") {
            assert_eq!(*kem::x25519(&b32(&c["k"]), &b32(&c["u"])), b32(&c["out"]));
        }
        for c in arr(v, "iterated") {
            let (mut k, mut u) = ([0u8; 32], [0u8; 32]);
            k[0] = 9;
            u[0] = 9;
            for _ in 0..num(&c["iterations"]) {
                let out = *kem::x25519(&k, &u);
                u = k;
                k = out;
            }
            assert_eq!(k, b32(&c["out"]), "{} iterations", c["iterations"]);
        }
        let dh = &v["dh"];
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert_eq!(*kem::x25519(&b32(&dh["a"]), &nine), b32(&dh["A"]));
        assert_eq!(*kem::x25519(&b32(&dh["b"]), &nine), b32(&dh["B"]));
        assert_eq!(*kem::x25519(&b32(&dh["a"]), &b32(&dh["B"])), b32(&dh["K"]));
        assert_eq!(*kem::x25519(&b32(&dh["b"]), &b32(&dh["A"])), b32(&dh["K"]));
    }

    /// FIPS 203 §7.3 self-test once per secret store per `(ua, version)` (spec §6.1): its record is the store's and goes with
    /// it (a second wallet of the same mnemonic runs its own; after lock / unlock the new store runs it again).
    #[test]
    fn self_test_runs_once_per_store() {
        let (a, b) = (wallet("pq_kat"), wallet("pq_kat"));
        assert_eq!(a.vectors_kem_self_tests().unwrap(), 0);
        let ka = a.ua_key(0x0130, 0, 0).unwrap();
        ka.kem_key(0).unwrap();
        ka.kem_key(0).unwrap();
        assert_eq!(a.vectors_kem_self_tests().unwrap(), 1);
        ka.kem_key(1).unwrap();
        a.ua_key(0x0131, 0, 0).unwrap().kem_key(0).unwrap();
        assert_eq!(a.vectors_kem_self_tests().unwrap(), 3);
        assert_eq!(b.vectors_kem_self_tests().unwrap(), 0);
        b.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
        assert_eq!((a.vectors_kem_self_tests().unwrap(), b.vectors_kem_self_tests().unwrap()), (3, 1));
        a.lock();
        let k = load("keys.json");
        let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == "pq_kat").unwrap();
        a.vectors_unlock(m["words"].as_str().unwrap(), "").unwrap();
        assert_eq!(a.vectors_kem_self_tests().unwrap(), 0);
        a.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
        assert_eq!(a.vectors_kem_self_tests().unwrap(), 1);
    }

    /// `dk` and `sk_X` live in the store's arena, outside the KEM handle; the ephemeral key's in a store of its own.
    #[test]
    fn kem_secret_in_arena() {
        let w = wallet("pq_kat");
        let kk = w.ua_key(0x0130, 0, 0).unwrap().kem_key(0).unwrap();
        assert!(kk.vectors_secret_in_arena().unwrap());
        drop(w);
        assert_eq!(kk.vectors_secret_in_arena().err(), Some(Error::KeyRevoked), "the wallet dropped: its store wiped");
        assert!(KemKeyPair::generate_ephemeral().unwrap().vectors_secret_in_arena().unwrap());
    }
}
