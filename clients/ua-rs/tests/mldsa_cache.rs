// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! NODE-JOB-29 (CTR-UA-23): `scaas_ua::mldsa_cache` against `smartcontracts/vectors/ua/mldsa_cache.json` (generated from
//! `@noble/post-quantum` only; the rows clientkeys' `test/ua-cache.test.js` reads): one `cacheExpandedKey(uint16,bytes,uint256)`
//! call per part of every key, the refusals by the registry's error names beside each kind's boundary, and the
//! cache-then-register order. UNAUDITED.
use scaas_ua::mldsa_cache::{
    cache_then_register, part_call, part_calls, parts, CacheError, CACHE_EXPANDED_KEY_SELECTOR,
};
use scaas_ua::ua_portable::{registration_args, RegistrationInput};
use serde_json::Value;

fn rows() -> Value {
    let path = format!(
        "{}/../../smartcontracts/vectors/ua/mldsa_cache.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap()).unwrap()["levels"]
        .clone()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn kind(name: &str) -> u16 {
    match name {
        "mldsa44" => 0x0130,
        "mldsa65" => 0x0131,
        "mldsa87" => 0x0134,
        _ => panic!("{name}"),
    }
}
fn word(d: &[u8], i: usize) -> u64 {
    let w = &d[4 + 32 * i..36 + 32 * i];
    assert!(w[..24].iter().all(|b| *b == 0));
    u64::from_be_bytes(w[24..].try_into().unwrap())
}

#[test]
fn every_row_one_call_per_part() {
    let levels = rows();
    let mut n = 0;
    for (name, level) in levels.as_object().unwrap() {
        for key in level["keys"].as_array().unwrap() {
            let (k, pk) = (kind(name), bytes(&key["pk"]));
            let want = key["parts_sha256"].as_array().unwrap().len();
            assert_eq!(parts(k) as usize, want, "{name}");
            let calls = part_calls(k, &pk).unwrap();
            assert_eq!(calls.len(), want, "{name}");
            for (part, d) in calls.iter().enumerate() {
                assert_eq!(d[..4], CACHE_EXPANDED_KEY_SELECTOR);
                assert_eq!(
                    CACHE_EXPANDED_KEY_SELECTOR,
                    [0x8b, 0x73, 0x88, 0x73],
                    "cast sig \"cacheExpandedKey(uint16,bytes,uint256)\""
                );
                assert_eq!(
                    [word(d, 0), word(d, 1), word(d, 2), word(d, 3)],
                    [k as u64, 96, part as u64, pk.len() as u64]
                );
                assert_eq!(&d[132..132 + pk.len()], &pk[..]);
                assert_eq!(d.len(), 132 + pk.len().next_multiple_of(32));
                assert!(d[132 + pk.len()..].iter().all(|b| *b == 0));
                n += 1;
            }
        }
    }
    assert_eq!(n, 12 * (1 + 2 + 3), "12 keys per level");
}

#[test]
fn refusals_by_the_registry_error_names() {
    for (k, len, n) in [
        (0x0130u16, 1312usize, 1u64),
        (0x0131, 1952, 2),
        (0x0134, 2592, 3),
    ] {
        let pk = vec![7u8; len];
        assert!(part_call(k, &pk, n - 1).is_ok(), "{k:#x}");
        assert_eq!(part_call(k, &pk, n), Err(CacheError::KeyCache(k)));
        assert_eq!(part_call(k, &pk[1..], 0), Err(CacheError::KeyData(k)));
        assert_eq!(
            part_call(k, &vec![7u8; len + 1], 0).unwrap_err().code(),
            "UAKeyData"
        );
    }
    for k in [0x0132u16, 0x0133, 0x0135, 0x0101, 0x0120] {
        assert_eq!(parts(k), 0);
        assert_eq!(
            part_call(k, &[7u8; 1952], 0).unwrap_err().code(),
            "UAKeyCache"
        );
        assert_eq!(part_calls(k, &[7u8; 1952]), Err(CacheError::KeyCache(k)));
    }
}

#[test]
fn cache_then_register_order() {
    let levels = rows();
    let pk = bytes(&levels["mldsa87"]["keys"][0]["pk"]);
    let i = RegistrationInput {
        kind: 0x0134,
        key_data: pk.clone(),
        pop: vec![1],
        ..Default::default()
    };
    let o = cache_then_register(&i).unwrap();
    assert_eq!(o.parts, part_calls(0x0134, &pk).unwrap());
    assert_eq!(o.parts.len(), 3);
    assert_eq!(o.registration, registration_args(&i).unwrap());
    let ed = RegistrationInput {
        kind: 0x0102,
        key_data: vec![1u8; 32],
        pop: vec![1],
        ..Default::default()
    };
    assert!(cache_then_register(&ed).unwrap().parts.is_empty());
    // a KEM key on a kind that may not hold one: the registration's own refusal
    let bad = RegistrationInput {
        kind: 0x0102,
        key_data: vec![1u8; 32],
        kem_pk: vec![1u8; 1601],
        ..Default::default()
    };
    assert_eq!(cache_then_register(&bad).unwrap_err().code(), "UAKemHolder");
}
