// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T3b: the PQ signers (spec §3): ML-DSA-44/-65/-87 hedged (`Sign_internal(0x00 ‖ 0x00 ‖ pq_msg, rnd)`, `rnd` from
//! the OS RNG), SLH-DSA-SHA2-128s randomized (`slh_sign_internal(M', opt_rand)`), Falcon-padded-512 / -1024 over `ua_msg`
//! (PQClean, vendored, MD-8), against smartcontracts/vectors/ua/{pq_kat,sign,pq_external}.json (written by clientkeys) and the
//! both-ways fixture rs_signatures.json (written here, `--ignored regenerate`, read by clientkeys `npm test`). The `vectors`
//! tests use the test-only entry points (fixed randomness, raw keys). UNAUDITED.
use scaas_ua::pq;
use scaas_ua::wallet::{Error, Wallet};
use scaas_ua::{purpose_tag, ua_message};
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
fn kind_of(v: &Value) -> u16 {
    match v {
        Value::String(s) => u16::from_str_radix(s.trim_start_matches("0x"), 16).unwrap(),
        v => v.as_u64().unwrap() as u16,
    }
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// The PQ kinds: mldsa44, mldsa65, fndsa512, slhdsa128s, mldsa87, fndsa1024.
const PQ: [u16; 6] = [0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135];
/// Signature lengths per kind, Falcon padded.
const SIG_LEN: [(u16, usize); 6] = [(0x0130, 2420), (0x0131, 3309), (0x0132, 666), (0x0133, 7856), (0x0134, 4627), (0x0135, 1280)];
const FALCON: [u16; 2] = [0x0132, 0x0135];

/// pq_kat.json: every PQ kind's key of the SEP-0005 mnemonic (account 0, index 0), its UA (Falcon: PQClean's seeded keygen
/// equals noble's, T0 Q1).
#[test]
fn pq_kat_keys() {
    let v = load("pq_kat.json");
    let w = wallet("pq_kat");
    let mut n = 0;
    for (name, r) in v["kinds"].as_object().unwrap() {
        let key = w.ua_key(kind_of(&r["kind"]), 0, 0).unwrap();
        assert_eq!(hex::encode(key.key_data()), hex::encode(bytes(&r["pk"])), "{name}");
        assert_eq!(key.ua().unwrap(), b32(&r["ua"]), "{name}");
        n += 1;
    }
    assert_eq!(n, 6);
}

/// Every `sign.json` `ua` row of the PQ kinds: key data, `ua_msg`, the signed bytes (`pq_msg` for ML-DSA / SLH-DSA,
/// `ua_msg` for Falcon); the row's signature verifies (Rust verifies the JS signer), and the release signature of the same
/// request verifies, at the kind's length.
#[test]
fn sign_json_pq_rows() {
    let s = load("sign.json");
    let w = wallet("pq_kat");
    let mut n = 0;
    for r in arr(&s, "ua").iter().filter(|r| PQ.contains(&kind_of(&r["kind"]))) {
        let kind = kind_of(&r["kind"]);
        let key = w.ua_key(kind, 0, 0).unwrap();
        assert_eq!(key.key_data(), bytes(&r["keyData"]), "{r}");
        let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
        let ua_msg = ua_message(kind, &purpose, &digest).unwrap();
        assert_eq!(ua_msg, b32(&r["uaMsg"]), "{r}");
        assert_eq!(pq::signed_message(kind, &ua_msg), bytes(&r["signed"]), "{r}");
        assert!(pq::verify(kind, &key.key_data(), &ua_msg, &bytes(&r["signature"])), "{r}");
        let mine = key.sign_ua(&purpose, &digest).unwrap();
        assert_eq!(mine.len(), SIG_LEN.iter().find(|(k, _)| *k == kind).unwrap().1);
        assert!(pq::verify(kind, &key.key_data(), &ua_msg, &mine), "{r}");
        n += 1;
    }
    assert_eq!(n, 20);
}

/// A release signature is randomized for every PQ kind: two signatures of one request differ and both verify.
#[test]
fn two_release_signatures_differ() {
    let w = wallet("pq_kat");
    let (p, d) = (purpose_tag("metatx").unwrap(), [9u8; 32]);
    for kind in PQ {
        let key = w.ua_key(kind, 0, 0).unwrap();
        let (a, b) = (key.sign_ua(&p, &d).unwrap(), key.sign_ua(&p, &d).unwrap());
        assert_ne!(a, b, "{kind:#06x}");
        let m = ua_message(kind, &p, &d).unwrap();
        assert!(pq::verify(kind, &key.key_data(), &m, &a) && pq::verify(kind, &key.key_data(), &m, &b), "{kind:#06x}");
    }
}

/// What each scheme signs: Falcon `ua_msg` itself, ML-DSA / SLH-DSA `M' = 0x00 ‖ 0x00 ‖ pq_msg` (the empty context): a
/// release signature verifies over its own message and not over the other one.
#[test]
fn signed_bytes_per_scheme() {
    let w = wallet("pq_kat");
    let (p, d) = (purpose_tag("pop").unwrap(), [4u8; 32]);
    for kind in PQ {
        let key = w.ua_key(kind, 0, 0).unwrap();
        let sig = key.sign_ua(&p, &d).unwrap();
        let ua_msg = ua_message(kind, &p, &d).unwrap();
        let pq_msg = scaas_ua::keccak256(&[&scaas_ua::tag(kind).unwrap()[..], &ua_msg].concat()).to_vec();
        let (own, other) = if FALCON.contains(&kind) {
            (ua_msg.to_vec(), pq_msg)
        } else {
            ([&[0u8, 0][..], &pq_msg].concat(), [&[0u8, 1, 0][..], &pq_msg].concat()) // a one-byte context
        };
        assert!(pq::verify_raw(kind, &key.key_data(), &own, &sig), "{kind:#06x}");
        assert!(!pq::verify_raw(kind, &key.key_data(), &other, &sig), "{kind:#06x}");
    }
}

/// A revoked PQ handle signs nothing.
#[test]
fn locked_wallet_pq_handles_sign_nothing() {
    let w = wallet("pq_kat");
    let keys: Vec<_> = PQ.iter().map(|k| w.ua_key(*k, 0, 0).unwrap()).collect();
    let (p, d) = (purpose_tag("metatx").unwrap(), [1u8; 32]);
    w.lock();
    for key in keys {
        assert_eq!(key.sign_ua(&p, &d).err(), Some(Error::KeyRevoked));
    }
}

/// The both-ways fixture (spec §11): every row is the pq_kat wallet's key and request, and its signature verifies here;
/// the JS side verifies the same rows (`npm test`). Randomized kinds only: Falcon, hedged ML-DSA, randomized SLH-DSA, BIP-340
/// and scaas Schnorr (T3c) with an OS `aux`.
#[test]
fn rs_signatures_json_rows() {
    let f = load("rs_signatures.json");
    let w = wallet("pq_kat");
    let mut kinds = std::collections::BTreeSet::new();
    for r in arr(&f, "rows") {
        let kind = kind_of(&r["kind"]);
        let key = w.ua_key(kind, 0, 0).unwrap();
        assert_eq!(key.key_data(), bytes(&r["keyData"]), "{r}");
        let ua_msg = ua_message(kind, &b32(&r["purposeTag"]), &b32(&r["digest"])).unwrap();
        assert_eq!(ua_msg, b32(&r["uaMsg"]), "{r}");
        let pop = r["role"] == "pop";
        assert!(scaas_ua::verify::verify(kind, &key.key_data(), &ua_msg, &bytes(&r["signature"]), pop), "{r}");
        kinds.insert(kind);
    }
    assert_eq!(kinds.into_iter().collect::<Vec<_>>(), [0x0103, 0x0104, 0x0105, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135]);
    assert_eq!(arr(&f, "rows").len(), 18);
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::wallet::pqsign::sign_internal;

    /// `sign.json` `compare: bytes` rows (ML-DSA `rnd = 0`, SLH-DSA `opt_rand = PK.seed`) through `sign_ua`'s path with the
    /// fixed randomness, byte-equal.
    #[test]
    fn sign_json_pq_bytes_rows() {
        let s = load("sign.json");
        let w = wallet("pq_kat");
        let mut n = 0;
        for r in arr(&s, "ua").iter().filter(|r| PQ.contains(&kind_of(&r["kind"])) && r["compare"] == "bytes") {
            let kind = kind_of(&r["kind"]);
            let key = w.ua_key(kind, 0, 0).unwrap();
            let fixed = match (&r["fixed"]["rnd"], &r["fixed"]["optRand"]) {
                (Value::String(_), _) => bytes(&r["fixed"]["rnd"]),
                (_, Value::Null) => key.key_data()[..16].to_vec(), // PK.seed: FIPS 205's deterministic variant
                other => panic!("{other:?}"),
            };
            let sig = key.vectors_sign_ua_fixed(&b32(&r["purposeTag"]), &b32(&r["digest"]), &fixed).unwrap();
            assert_eq!(hex::encode(sig), hex::encode(bytes(&r["signature"])), "{r}");
            n += 1;
        }
        assert_eq!(n, 8);
    }

    /// pq_kat.json: the deterministic ML-DSA / SLH-DSA signature of each kind's `ua_msg`, byte-equal; Falcon's (noble's own
    /// fixed sampler stream) verifies.
    #[test]
    fn pq_kat_signatures() {
        let v = load("pq_kat.json");
        let w = wallet("pq_kat");
        let mut n = 0;
        for (name, r) in v["kinds"].as_object().unwrap() {
            let kind = kind_of(&r["kind"]);
            let key = w.ua_key(kind, 0, 0).unwrap();
            let ua_msg = b32(&r["ua_msg"]);
            assert!(pq::verify(kind, &key.key_data(), &ua_msg, &bytes(&r["sig"])), "{name}");
            if FALCON.contains(&kind) {
                continue;
            }
            let fixed = if kind == 0x0133 { key.key_data()[..16].to_vec() } else { vec![0u8; 32] };
            assert_eq!(hex::encode(key.vectors_sign_ua_msg(&ua_msg, &fixed).unwrap()), hex::encode(bytes(&r["sig"])), "{name}");
            n += 1;
        }
        assert_eq!(n, 4);
    }

    /// ACVP `sigGen` (pq_external.json): ML-DSA-44/-65/-87 and SLH-DSA-SHA2-128s, deterministic and with the case's
    /// randomness, `M'` as given (external and internal interfaces), byte-equal.
    #[test]
    fn acvp_siggen_rows() {
        let x = load("pq_external.json");
        let mut n = 0;
        for c in arr(&x["acvp_mldsa_siggen"], "cases").iter().chain(arr(&x["acvp_slhdsa_siggen"], "cases")) {
            let kind = match c["set"].as_str().unwrap() {
                "ML-DSA-44" => 0x0130,
                "ML-DSA-65" => 0x0131,
                "ML-DSA-87" => 0x0134,
                "SLH-DSA-SHA2-128s" => 0x0133,
                other => panic!("{other}"),
            };
            let rnd = match (c.get("rnd"), c.get("addRand")) {
                (Some(r), _) | (_, Some(r)) => Some(bytes(r)),
                _ => None,
            };
            assert_eq!(rnd.is_none(), c["deterministic"].as_bool().unwrap());
            let sig = sign_internal(kind, &bytes(&c["sk"]), &bytes(&c["mprime"]), rnd.as_deref()).unwrap();
            assert_eq!(hex::encode(sig), hex::encode(bytes(&c["sig"])), "{} tc {}", c["set"], c["tc"]);
            n += 1;
        }
        assert_eq!(n, 16);
    }

    /// Falcon with fixed randomness is a function of it: the same 88 bytes give the same signature, other bytes another one;
    /// both verify. Fixed randomness of the wrong length is refused.
    #[test]
    fn falcon_fixed_randomness() {
        let w = wallet("pq_kat");
        let (p, d) = (purpose_tag("metatx").unwrap(), [2u8; 32]);
        for kind in FALCON {
            let key = w.ua_key(kind, 0, 0).unwrap();
            let (a, b, c) = (
                key.vectors_sign_ua_fixed(&p, &d, &[1u8; 88]).unwrap(),
                key.vectors_sign_ua_fixed(&p, &d, &[1u8; 88]).unwrap(),
                key.vectors_sign_ua_fixed(&p, &d, &[2u8; 88]).unwrap(),
            );
            assert_eq!(a, b);
            assert_ne!(a, c);
            let m = ua_message(kind, &p, &d).unwrap();
            assert!(pq::verify(kind, &key.key_data(), &m, &a) && pq::verify(kind, &key.key_data(), &m, &c));
            assert_eq!(key.vectors_sign_ua_fixed(&p, &d, &[1u8; 87]).err(), Some(Error::Argument));
        }
        let key = w.ua_key(0x0131, 0, 0).unwrap();
        assert_eq!(key.vectors_sign_ua_fixed(&p, &d, &[0u8; 31]).err(), Some(Error::Argument));
    }

    /// The arena keeps what each signer rebuilds its key from: ML-DSA's 32-byte seed, SLH-DSA's 64-byte key (no keygen per
    /// signature), Falcon's PQClean secret key (header `0x50 + logn`); none of it inside the handle.
    #[test]
    fn arena_keeps_the_encoded_keys() {
        let w = wallet("pq_kat");
        for (kind, len, head) in [(0x0130, 32, None), (0x0133, 64, None), (0x0132, 1281, Some(0x59)), (0x0135, 2305, Some(0x5a))] {
            let key = w.ua_key(kind, 0, 0).unwrap();
            assert!(key.vectors_secret_in_arena().unwrap(), "{kind:#06x}");
            let s = key.vectors_with_secret(|s| s.to_vec()).unwrap();
            assert_eq!(s.len(), len, "{kind:#06x}");
            if let Some(h) = head {
                assert_eq!(s[0], h);
            }
            if kind == 0x0133 {
                assert_eq!(&s[32..], &key.key_data()[..], "SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root");
            }
        }
    }

    /// Writes rs_signatures.json (MD-7): release signatures (`sign_ua`, OS randomness) of the `sign.json` `verify` rows of the
    /// randomized kinds: `0x0103`, the scaas Schnorr kinds `0x0104` / `0x0105` (T3c) and the PQ kinds. A row that is still the
    /// same request and still verifies is kept, so a second run leaves the file unchanged. `cargo test --features vectors --test wallet_pq -- --ignored regenerate`
    #[test]
    #[ignore]
    fn regenerate() {
        let s = load("sign.json");
        let old = std::fs::read_to_string(path("rs_signatures.json")).ok().and_then(|t| serde_json::from_str::<Value>(&t).ok());
        let w = wallet("pq_kat");
        let mut rows = Vec::new();
        let signed_here = |r: &&Value| {
            r["compare"] == "verify" && (matches!(kind_of(&r["kind"]), 0x0103..=0x0105) || PQ.contains(&kind_of(&r["kind"])))
        };
        for r in arr(&s, "ua").iter().filter(signed_here) {
            let kind = kind_of(&r["kind"]);
            let key = w.ua_key(kind, r["account"].as_u64().unwrap() as u32, r["index"].as_u64().unwrap() as u32).unwrap();
            let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
            let ua_msg = ua_message(kind, &purpose, &digest).unwrap();
            let mut row = serde_json::json!({
                "kind": kind, "name": r["name"], "mnemonic": "pq_kat", "account": r["account"], "index": r["index"],
                "keyData": format!("0x{}", hex::encode(key.key_data())), "purpose": r["purpose"],
                "purposeVersion": r["purposeVersion"], "purposeTag": r["purposeTag"], "digest": r["digest"],
                "uaMsg": format!("0x{}", hex::encode(ua_msg)), "role": r["role"],
            });
            let pop = r["role"] == "pop";
            let kept = old.as_ref().and_then(|o| {
                arr(o, "rows").iter().find(|x| {
                    let mut x = (*x).clone();
                    let sig = x.as_object_mut().and_then(|m| m.remove("signature")).unwrap_or(Value::Null);
                    sig.is_string() && x == row && scaas_ua::verify::verify(kind, &key.key_data(), &ua_msg, &bytes(&sig), pop)
                })
            });
            let sig = match kept {
                Some(x) => x["signature"].clone(),
                None => Value::String(format!("0x{}", hex::encode(key.sign_ua(&purpose, &digest).unwrap()))),
            };
            row["signature"] = sig;
            rows.push(row);
        }
        let out = serde_json::json!({
            "note": "Written by clients/ua-rs (tests/wallet_pq.rs, `cargo test --features vectors --test wallet_pq -- --ignored \
                     regenerate`; ua-rs-sign T3b, T3c, MD-7); never edit by hand. Release signatures of ua-rs (`UaKey::sign_ua`, \
                     OS randomness: hedged ML-DSA, randomized SLH-DSA, Falcon-padded, BIP-340 and scaas Schnorr with an OS aux) \
                     over the requests of the sign.json `compare: verify` rows of the pq_kat wallet; read and verified by clientkeys \
                     (test/ua-wallet.test.js), so a bug shared by one crate's signer and verifier cannot pass. A re-run keeps \
                     every row that is still the same request and still verifies.",
            "rows": rows,
        });
        std::fs::write(path("rs_signatures.json"), serde_json::to_string_pretty(&out).unwrap() + "\n").unwrap();
    }
}
