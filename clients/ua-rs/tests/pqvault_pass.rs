// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqVault plan V1 (spec §6.5, CLI-PQV-10): `argon2` (the pin of feature `pqvault`) reproduces clientkeys' Argon2id rows of
//! smartcontracts/vectors/pqvault/pass.json: RFC 9106's test vector first (secret and associated data), then `P_k` of set 1
//! (64 MiB, 3 passes, parallelism 4, 32 B, no secret, no associated data) for every row and the wrong-passphrase refusal row.
use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use serde_json::Value;

fn doc() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/pqvault/pass.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn num(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap()).unwrap()
}

/// `passKdf` 1, the only set this reproducer knows (the vectors' `sets`, checked below).
fn set1(passphrase: &str, salt: &[u8]) -> [u8; 32] {
    let params = ParamsBuilder::new()
        .m_cost(65_536)
        .t_cost(3)
        .p_cost(4)
        .output_len(32)
        .build()
        .unwrap();
    let mut out = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut out)
        .unwrap();
    out
}

#[test]
fn rfc9106_argon2id() {
    let v = &doc()["rfc9106"];
    let ad = unhex(&v["ad"]);
    let secret = unhex(&v["secret"]);
    let tag = unhex(&v["tag"]);
    assert_eq!(num(&v["version"]), 0x13);
    let params = ParamsBuilder::new()
        .m_cost(num(&v["m"]))
        .t_cost(num(&v["t"]))
        .p_cost(num(&v["p"]))
        .data(AssociatedData::new(&ad).unwrap())
        .output_len(tag.len())
        .build()
        .unwrap();
    let a = Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
    let mut out = vec![0u8; tag.len()];
    a.hash_password_into(&unhex(&v["password"]), &unhex(&v["salt"]), &mut out)
        .unwrap();
    assert_eq!(out, tag);
    // negative control: one byte of the associated data changed
    let mut ad2 = ad.clone();
    ad2[0] ^= 1;
    let p2 = ParamsBuilder::new()
        .m_cost(num(&v["m"]))
        .t_cost(num(&v["t"]))
        .p_cost(num(&v["p"]))
        .data(AssociatedData::new(&ad2).unwrap())
        .output_len(tag.len())
        .build()
        .unwrap();
    let mut out2 = vec![0u8; tag.len()];
    Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, p2)
        .unwrap()
        .hash_password_into(&unhex(&v["password"]), &unhex(&v["salt"]), &mut out2)
        .unwrap();
    assert_ne!(out2, tag);
}

#[test]
fn set_1_pinned() {
    let s = &doc()["sets"]["1"];
    assert_eq!(s["algorithm"], "argon2id");
    assert_eq!(
        (
            num(&s["version"]),
            num(&s["m"]),
            num(&s["t"]),
            num(&s["p"]),
            num(&s["dkLen"])
        ),
        (0x13, 65_536, 3, 4, 32)
    );
    assert_eq!(doc()["sets"].as_object().unwrap().len(), 1);
}

#[test]
fn pk_rows_of_set_1() {
    let d = doc();
    let rows = d["rows"].as_array().unwrap();
    assert!(!rows.is_empty());
    for r in rows {
        assert_eq!(num(&r["passKdf"]), 1);
        let pass = r["passphrase"].as_str().unwrap();
        assert_eq!(pass.as_bytes(), unhex(&r["passphraseUtf8"]).as_slice());
        assert_eq!(
            set1(pass, &unhex(&r["passSalt"])).as_slice(),
            unhex(&r["Pk"]).as_slice(),
            "{}",
            r["name"]
        );
    }
    // the wrong-passphrase row: its P_k is reproduced and differs from the right one of the same epoch
    let w = d["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["error"] == "PassphraseWrong")
        .unwrap();
    let right = rows.iter().find(|r| r["epoch"] == w["epoch"]).unwrap();
    let got = set1(
        w["passphrase"].as_str().unwrap(),
        &unhex(&right["passSalt"]),
    );
    assert_eq!(got.as_slice(), unhex(&w["Pk"]).as_slice());
    assert_ne!(got.as_slice(), unhex(&right["Pk"]).as_slice());
    // an unknown set: no row of the vectors' sets
    let u = d["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["error"] == "PassKdfUnknown")
        .unwrap();
    assert!(d["sets"].get(u["passKdf"].to_string()).is_none());
}
