// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `scaas_ua::pqz3k` against the shared rows: pq_kat.json `pqzScopedSeeds` and `memoHashOpening` (clientkeys), opening.json's
//! `openKemSeeds` and leg seeds (pqz-ffi), typed_ops.json's `PqzRollOver` row (clientkeys; the contract pins its typehash).
use scaas_ua::{keccak256, pqz3k};
use serde_json::Value;

fn load(p: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{p}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn b(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn a<const N: usize>(v: &Value) -> [u8; N] {
    b(v).try_into().unwrap()
}
fn n(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_str().unwrap().parse().unwrap())
}

/// BIP-39's seed: PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048), 64 bytes (one block), here for the KAT only.
fn bip39_seed(mnemonic: &str) -> [u8; 64] {
    use hmac::{Hmac, Mac};
    let prf = |parts: &[&[u8]]| {
        let mut m = <Hmac<sha2::Sha512> as Mac>::new_from_slice(mnemonic.as_bytes()).unwrap();
        for p in parts {
            m.update(p);
        }
        let o: [u8; 64] = m.finalize().into_bytes().into();
        o
    };
    let mut u = prf(&[b"mnemonic", &1u32.to_be_bytes()]);
    let mut t = u;
    for _ in 1..2048 {
        u = prf(&[&u]);
        for (x, y) in t.iter_mut().zip(u) {
            *x ^= y;
        }
    }
    t
}

#[test]
fn scoped_seeds_and_memo_hash() {
    let k = load("ua/pq_kat.json");
    let seed = bip39_seed(k["mnemonic"].as_str().unwrap());
    let rows = k["pqzScopedSeeds"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    for r in rows {
        let tok = r.get("token").map(a::<20>);
        let got = pqz3k::pqz_scoped_key_seed(&seed, n(&r["account"]) as u32, n(&r["index"]) as u32, &a(&r["chainUid"]), tok.as_ref(),
            n(&r["version"]));
        assert_eq!(got, a::<32>(&r["seed32"]), "{}", r["keyClass"]);
    }
    for r in k["memoHashOpening"].as_array().unwrap() {
        let os: Vec<Vec<u8>> = r["openings"].as_array().unwrap().iter().map(b).collect();
        let refs: Vec<&[u8]> = os.iter().map(|o| &o[..]).collect();
        assert_eq!(pqz3k::opening_memo_hash(&b(&r["memo"]), &a(&r["ownTag"]), &refs), a::<32>(&r["memoHash"]));
    }
}

#[test]
fn open_kem_seeds_and_leg_seeds_equal_pqz_ffi() {
    let o = load("pqz/opening.json");
    let seed: [u8; 64] = a(&o["bip39_seed"]);
    for r in o["openKemSeeds"].as_array().unwrap() {
        let tok = b(&r["token"]);
        let t: Option<[u8; 20]> = (!tok.is_empty()).then(|| tok.try_into().unwrap());
        let got = pqz3k::open_kem_seed(&seed, &a(&r["ua"]), &a(&r["chainUid"]), t.as_ref(), n(&r["version"]));
        assert_eq!(got.to_vec(), b(&r["openKemSeed"]));
    }
    for r in o["rows"].as_array().unwrap() {
        assert_eq!(pqz3k::leg_seed(&a(&r["seed_enc"]), &a(&r["toUA"]), &a(&r["pk_t_keccak"])), a::<32>(&r["seed_leg"]));
    }
    // the class seeds: two chains, two tokens, versions 0 and 1 pairwise distinct
    let mut s = std::collections::HashSet::new();
    for cu in [[0xc1u8; 32], [0xc2; 32]] {
        for v in 0..2 {
            assert!(s.insert(pqz3k::pqz_scoped_key_seed(&seed, 0, 0, &cu, None, v)));
            for t in [[0xa1u8; 20], [0xa2; 20]] {
                assert!(s.insert(pqz3k::pqz_scoped_key_seed(&seed, 0, 0, &cu, Some(&t), v)));
            }
        }
    }
}

#[test]
fn roll_over_struct_hash_equals_typed_ops() {
    let r = &load("typed/typed_ops.json")["ops"]["PqzRollOver"];
    assert_eq!(keccak256(pqz3k::ROLL_OVER_TYPE.as_bytes()), a::<32>(&r["typehash"]));
    let m = &r["message"];
    let skip: Vec<u64> = m["skip"].as_array().unwrap().iter().map(n).collect();
    let h = pqz3k::roll_over_struct_hash(&a(&m["ua"]), n(&m["keyVersion"]), n(&m["rollSeq"]), n(&m["rolled"]), n(&m["n"]), &skip,
        &a(&m["entriesHash"]), n(&m["validUntilBlock"]), &a(&m["chainUid"]));
    assert_eq!(h, a::<32>(&r["structHash"]));
}

/// Owner ruling 2026-11-14 (CLI-SGN-51's Change; spec §13, §14.18): the handle's one entry is the binding's holder check; a
/// credit of another class, scope or key version (and any credit on a handle without the opening) is refused before the check
/// runs; the check gets this record's opening KEM seed; `Debug` shows no secret.
#[test]
fn key_handle_checks_never_decrypts() {
    use pqz3k::{KeyClass as K, OpeningCredit, PqzKeyHandle, Refused};
    let seed = [7u8; 64];
    let (ua, cu, t1, t2) = ([0x11u8; 32], [0xc1u8; 32], [0xa1u8; 20], [0xa2u8; 20]);
    let h2 = PqzKeyHandle::new(&seed, K::OffchainShared, &ua, &cu, None, 0, true).unwrap();
    let h3 = PqzKeyHandle::new(&seed, K::OffchainToken, &ua, &cu, Some(&t1), 0, true).unwrap();
    let h3off = PqzKeyHandle::new(&seed, K::OffchainToken, &ua, &cu, Some(&t1), 0, false).unwrap();
    let h1 = PqzKeyHandle::new(&seed, K::Registry, &ua, &cu, None, 0, false).unwrap();
    let (o, aad) = ([0u8; 1648], [0u8; 8]);
    let c = |class, scope, version| OpeningCredit { class, scope, version, opening: &o, aad: &aad };
    // the positive controls: the check runs with this record's opening KEM seed
    let mut ran = 0;
    let want2 = pqz3k::open_kem_seed(&seed, &ua, &cu, None, 0);
    assert_eq!(h2.check(&c(K::OffchainShared, [0; 20], 0), |s, _| { ran += 1; (s == &want2).then_some(5u128) }), Ok(Some(5)));
    let want3 = pqz3k::open_kem_seed(&seed, &ua, &cu, Some(&t1), 0);
    assert_eq!(h3.check(&c(K::OffchainToken, t1, 0), |s, _| { ran += 1; (s == &want3).then_some(6u128) }), Ok(Some(6)));
    assert_eq!(h2.check(&c(K::OffchainShared, [0; 20], 0), |_, _| { ran += 1; None::<u128> }), Ok(None), "skip");
    assert_eq!(ran, 3);
    // refused before the check runs
    let cases: [(&PqzKeyHandle, OpeningCredit, &str); 7] = [
        (&h2, c(K::OffchainToken, t1, 0), "a class-2 handle given a class-3 credit"),
        (&h3, c(K::OffchainShared, [0; 20], 0), "a class-3 handle given a class-2 credit"),
        (&h1, c(K::OffchainToken, t1, 0), "a class-1 handle given a class-3 credit"),
        (&h1, c(K::OffchainShared, [0; 20], 0), "a class-1 handle given a class-2 credit"),
        (&h3, c(K::OffchainToken, t2, 0), "another token"),
        (&h2, c(K::OffchainShared, [0; 20], 1), "another key version"),
        (&h3off, c(K::OffchainToken, t1, 0), "class 3 without the opening"),
    ];
    for (h, cr, what) in cases.iter() {
        assert_eq!(h.check(cr, |_, _| -> Option<u128> { panic!("{what}: the check ran") }), Err(Refused), "{what}");
    }
    // a handle's construction refuses the impossible classes; Debug shows no secret
    assert_eq!(PqzKeyHandle::new(&seed, K::OffchainShared, &ua, &cu, None, 0, false).err(), Some(Refused));
    assert_eq!(PqzKeyHandle::new(&seed, K::Registry, &ua, &cu, None, 0, true).err(), Some(Refused));
    assert_eq!(PqzKeyHandle::new(&seed, K::OffchainToken, &ua, &cu, None, 0, true).err(), Some(Refused));
    let d = format!("{h2:?}");
    assert!(d.contains("opening: true") && !d.contains("open_kem_seed"), "{d}");
}
