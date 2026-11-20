// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T21: app-core key handles (feature `app-core`) reproduce clientkeys' rows
//! (smartcontracts/vectors/appcore/handles.json) through handles only, and refuse by name: another usage (`AppKeyUsage`), an
//! `aad` starting with the key-wrap constant, a handle of another scope (`AppHandleForeign`), the public MAC on a derived key,
//! past the arena's limit (`AppArenaFull`, a destroyed handle's slot reused); every handle revoked at the wallet's lock.
use scaas_ua::wallet::{
    AppKeys, Argon2Params, Error, KemKeyPair, KemWrap, KeyHandle, KeyUsage, Nonce, Wallet,
    APP_KEYS_MAX,
};
use serde_json::Value;

const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn v() -> Value {
    let f = format!(
        "{}/../../smartcontracts/vectors/appcore/handles.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn a12(v: &Value) -> [u8; 12] {
    unhex(v).try_into().unwrap()
}
fn keys() -> (Wallet, AppKeys) {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.app_keys();
    (w, k)
}
fn imp(k: &AppKeys, v: &Value, u: KeyUsage) -> KeyHandle {
    k.vectors_import(&a32(v), u).unwrap()
}
fn usage(n: u64) -> KeyUsage {
    match n {
        1 => KeyUsage::Derive,
        2 => KeyUsage::Data,
        _ => KeyUsage::KeyWrap,
    }
}

#[test]
fn derive_and_mac_rows() {
    let (_w, k) = keys();
    let v = v();
    for r in v["derive"].as_array().unwrap() {
        let hs: Vec<KeyHandle> = r["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| imp(&k, x, KeyUsage::Derive))
            .collect();
        let refs: Vec<&KeyHandle> = hs.iter().collect();
        let len = r["len"].as_u64().unwrap();
        // the usage asked for the output never changes its bytes (review K4)
        for u in [KeyUsage::Derive, KeyUsage::Data, KeyUsage::KeyWrap] {
            let out = k
                .derive(&refs, &unhex(&r["salt"]), &unhex(&r["info"]), u, len == 44)
                .unwrap();
            let okm = unhex(&r["okm"]);
            assert_eq!(k.vectors_reveal(&out).unwrap(), okm[..32], "{}", r["name"]);
            assert_eq!(
                k.vectors_nonce(&out).map(|n| n.to_vec()),
                (len == 44).then(|| okm[32..].to_vec())
            );
        }
    }
    for r in v["mac"].as_array().unwrap() {
        let key = imp(&k, &r["key"], KeyUsage::Derive);
        let out = k
            .mac_derive(&key, &unhex(&r["data"]), KeyUsage::Derive)
            .unwrap();
        let len = r["len"].as_u64().unwrap() as usize;
        assert_eq!(
            k.vectors_reveal(&out).unwrap()[..len],
            unhex(&r["out"])[..],
            "{}",
            r["name"]
        );
    }
    for r in v["macPublic"].as_array().unwrap() {
        let key = imp(&k, &r["key"], KeyUsage::Derive);
        let len = r["len"].as_u64().unwrap() as usize;
        assert_eq!(
            k.mac_public(&key, &unhex(&r["data"]), len).unwrap(),
            unhex(&r["out"])
        );
        assert_eq!(
            k.mac_public(&key, &unhex(&r["data"]), 9).err().unwrap(),
            Error::Argument
        );
        // never on a derived key, never on another usage
        let d = k.mac_derive(&key, b"x", KeyUsage::Derive).unwrap();
        assert_eq!(k.mac_public(&d, b"x", 8).err().unwrap(), Error::AppKeyUsage);
        let data = imp(&k, &r["key"], KeyUsage::Data);
        assert_eq!(
            k.mac_public(&data, b"x", 8).err().unwrap(),
            Error::AppKeyUsage
        );
    }
}

#[test]
fn seal_rows_and_usage_refusals() {
    let (_w, k) = keys();
    let v = v();
    for r in v["seal"].as_array().unwrap() {
        let key = imp(&k, &r["key"], KeyUsage::Data);
        let ct = k
            .vectors_seal(&key, &a12(&r["nonce"]), &unhex(&r["aad"]), &unhex(&r["pt"]))
            .unwrap();
        assert_eq!(ct, unhex(&r["ct"]), "{}", r["name"]);
    }
    for r in v["sealRandom"].as_array().unwrap() {
        let key = imp(&k, &r["key"], KeyUsage::Data);
        let pt = k
            .open(&key, Nonce::Random, &unhex(&r["aad"]), &unhex(&r["wire"]))
            .unwrap();
        assert_eq!(*pt, unhex(&r["pt"]));
        // a random-nonce round trip, and a wrong aad
        let w = k.seal(&key, Nonce::Random, b"a", b"pt").unwrap();
        assert_eq!(*k.open(&key, Nonce::Random, b"a", &w).unwrap(), b"pt");
        assert_eq!(
            k.open(&key, Nonce::Random, b"b", &w).err().unwrap(),
            Error::Aead
        );
    }
    let r = &v["seal"][0];
    let data = imp(&k, &r["key"], KeyUsage::Data);
    let kw = [&unhex(&v["keywrap"])[..], b"x"].concat();
    assert_eq!(
        k.seal(&data, Nonce::Random, &kw, b"pt").err().unwrap(),
        Error::AppKeyUsage
    );
    assert_eq!(
        k.open(&data, Nonce::Random, &kw, &[0; 40]).err().unwrap(),
        Error::AppKeyUsage
    );
    // seal and open by a Derive or KeyWrap handle refused; the control: the Data handle above
    for u in [KeyUsage::Derive, KeyUsage::KeyWrap] {
        let h = imp(&k, &r["key"], u);
        assert_eq!(
            k.seal(&h, Nonce::Random, b"", b"pt").err().unwrap(),
            Error::AppKeyUsage
        );
        assert_eq!(
            k.open(&h, Nonce::Random, b"", &[0; 40]).err().unwrap(),
            Error::AppKeyUsage
        );
    }
    // FromKey: the nonce a 44-byte derivation gave; FromHandle: HMAC(h, 0x03)[0:12]
    let base = imp(&k, &r["key"], KeyUsage::Derive);
    let dk = k
        .derive(
            &[&base],
            b"salt",
            b"scaas/app/v1/item",
            KeyUsage::Data,
            true,
        )
        .unwrap();
    let ct = k.seal(&dk, Nonce::FromKey, b"aad", b"item").unwrap();
    assert_eq!(*k.open(&dk, Nonce::FromKey, b"aad", &ct).unwrap(), b"item");
    let n = k.vectors_nonce(&dk).unwrap();
    assert_eq!(ct, k.vectors_seal(&dk, &n, b"aad", b"item").unwrap());
    let m = v["mac"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["len"] == 12)
        .unwrap();
    let ck = imp(&k, &m["key"], KeyUsage::Derive);
    let ct = k.seal(&data, Nonce::FromHandle(&ck), b"", b"msg").unwrap();
    assert_eq!(
        ct,
        k.vectors_seal(&data, &a12(&m["out"]), b"", b"msg").unwrap()
    );
    let no_nonce = imp(&k, &r["key"], KeyUsage::Data);
    assert_eq!(
        k.seal(&no_nonce, Nonce::FromKey, b"", b"x").err().unwrap(),
        Error::Argument
    );
}

#[test]
fn seal_key_rows() {
    let (_w, k) = keys();
    let v = v();
    for r in v["sealKey"].as_array().unwrap() {
        let u = usage(r["usage"].as_u64().unwrap());
        let under = imp(&k, &r["under"], KeyUsage::KeyWrap);
        let key = imp(&k, &r["key"], u);
        let wire = unhex(&r["wire"]);
        assert_eq!(
            k.vectors_seal_key(&under, &key, &a12(&r["nonce"]), &unhex(&r["aad"]))
                .unwrap(),
            wire,
            "{}",
            r["name"]
        );
        let back = k.open_key(&under, &wire, u, &unhex(&r["aad"])).unwrap();
        assert_eq!(back.usage(), u);
        assert!(k.same_key(&back, &key).unwrap());
        for other in [KeyUsage::Derive, KeyUsage::Data, KeyUsage::KeyWrap]
            .into_iter()
            .filter(|o| *o != u)
        {
            assert_eq!(
                k.open_key(&under, &wire, other, &unhex(&r["aad"]))
                    .err()
                    .unwrap(),
                Error::Aead,
                "{} as {other:?}",
                r["name"]
            );
        }
        // a Data open of the wire fails: its AAD is not producible by seal
        let as_data = imp(&k, &r["under"], KeyUsage::Data);
        let as_seal = k
            .vectors_seal(
                &as_data,
                &a12(&r["nonce"]),
                &unhex(&r["aad"]),
                &unhex(&r["key"]),
            )
            .unwrap();
        assert_ne!(as_seal, wire[12..]);
        assert_eq!(
            k.open(&as_data, Nonce::Random, &unhex(&r["aad"]), &wire)
                .err()
                .unwrap(),
            Error::Aead
        );
        // seal_key under a handle of another usage refused; the control: under a KeyWrap handle
        match u {
            KeyUsage::KeyWrap => assert!(k.seal_key(&key, &under, b"").is_ok()),
            _ => assert_eq!(
                k.seal_key(&key, &under, b"").err().unwrap(),
                Error::AppKeyUsage
            ),
        }
    }
}

#[test]
fn argon2_kem_and_root_rows() {
    let (w, k) = keys();
    let v = v();
    for r in v["argon2id"].as_array().unwrap() {
        let p = Argon2Params {
            m_kib: r["m"].as_u64().unwrap() as u32,
            t: r["t"].as_u64().unwrap() as u32,
            p: r["p"].as_u64().unwrap() as u32,
        };
        let h = k
            .argon2id(&unhex(&r["password"]), &unhex(&r["salt"]), p)
            .unwrap();
        assert_eq!(k.vectors_reveal(&h).unwrap(), unhex(&r["out"]));
        assert_eq!(h.usage(), KeyUsage::Derive);
    }
    let rc = &v["receiver"];
    let kem_pk = unhex(&rc["kemPk"]);
    // the receiver's KEM key: kemSeed = mlkemSeed (64) ‖ x25519Secret (32), as clientkeys' kemKey takes them
    let seed = {
        let f = format!(
            "{}/../../clients/clientkeys/scripts/appcore-vectors.mjs",
            env!("CARGO_MANIFEST_DIR")
        );
        assert!(std::fs::read_to_string(f).unwrap().contains("kem/mlkem"));
        let tag = |name: &str, i: u32| {
            scaas_ua::keccak256(format!("scaas/appcore/vectors/{name}/{i}").as_bytes())
        };
        let mut s = [0u8; 96];
        s[..32].copy_from_slice(&tag("kem/mlkem", 0));
        s[32..64].copy_from_slice(&tag("kem/mlkem", 1));
        s[64..].copy_from_slice(&tag("kem/x25519", 0));
        s
    };
    let kem = KemKeyPair::vectors_ephemeral(&seed).unwrap();
    assert_eq!(kem.kem_pk(), kem_pk);
    for r in v["kemWrap"].as_array().unwrap() {
        let key = imp(&k, &r["key"], KeyUsage::Derive);
        let (label, aad) = (unhex(&r["label"]), unhex(&r["aad"]));
        let wr = k
            .vectors_kem_wrap(
                &key,
                &label,
                &aad,
                &kem_pk,
                &a32(&r["m"]),
                &a32(&r["x25519Secret"]),
            )
            .unwrap();
        assert_eq!(wr.mlkem_ct, unhex(&r["mlkemCt"]), "{}", r["name"]);
        assert_eq!(wr.x25519_eph.to_vec(), unhex(&r["x25519Eph"]));
        assert_eq!(wr.sealed_key, unhex(&r["sealedKey"]));
        let back = k
            .kem_unwrap(&kem, &wr, &label, &aad, KeyUsage::Derive)
            .unwrap();
        assert!(k.same_key(&back, &key).unwrap());
        // the public MAC runs on an unwrapped key
        assert!(k.mac_public(&back, b"scaas/app/v1/hint", 8).is_ok());
        let mut other = label.clone();
        *other.last_mut().unwrap() ^= 1;
        assert_eq!(
            k.kem_unwrap(&kem, &wr, &other, &aad, KeyUsage::Derive)
                .err()
                .unwrap(),
            Error::Aead
        );
        let rnd = k.kem_wrap(&key, &label, &aad, &kem_pk).unwrap();
        assert!(k
            .same_key(
                &k.kem_unwrap(&kem, &rnd, &label, &aad, KeyUsage::Data)
                    .unwrap(),
                &key
            )
            .unwrap());
        let _: &KemWrap = &rnd;
    }
    // the app root: the wallet's seed; the vector's seed is fixed, so the row is checked through clientkeys' formula here
    let r = &v["appRoot"][0];
    let info = [
        &b"scaas/app/v1/root"[..],
        &unhex(&r["appId"]),
        &unhex(&r["ua"]),
    ]
    .concat();
    assert_eq!(
        scaas_ua::wallet::hkdf_sha256(&unhex(&r["seed"]), &[], &info, 32).unwrap()[..],
        unhex(&r["key"])[..]
    );
    let root = k.app_root_key(&a32(&r["appId"]), &a32(&r["ua"])).unwrap();
    let again = k.app_root_key(&a32(&r["appId"]), &a32(&r["ua"])).unwrap();
    assert!(k.same_key(&root, &again).unwrap());
    let other = k.app_root_key(&a32(&r["appId"]), &[1; 32]).unwrap();
    assert!(!k.same_key(&root, &other).unwrap());
    drop(w);
}

#[test]
fn scope_arena_and_lock() {
    let (w, k) = keys();
    let other = w.app_keys();
    let h = k.random_key(KeyUsage::Data).unwrap();
    assert_eq!(
        other.seal(&h, Nonce::Random, b"", b"x").err().unwrap(),
        Error::AppHandleForeign
    );
    assert_eq!(
        other
            .destroy(k.random_key(KeyUsage::Data).unwrap())
            .err()
            .unwrap(),
        Error::AppHandleForeign
    );
    assert!(k.seal(&h, Nonce::Random, b"", b"x").is_ok());
    assert_eq!(k.random_bytes(4097).err().unwrap(), Error::Argument);
    assert_eq!(k.random_bytes(16).unwrap().len(), 16);
    // the arena's limit: live handles (`h` and these), a destroyed or dropped one's slot reused
    let mut live = vec![];
    // bounded: a missing limit fails the assertion, never runs the arena out of memory
    let mut full = None;
    for _ in 0..APP_KEYS_MAX {
        match k.random_key(KeyUsage::Derive) {
            Ok(x) => live.push(x),
            Err(e) => {
                full = Some(e);
                break;
            }
        }
    }
    assert_eq!(
        (full, live.len() + 1),
        (Some(Error::AppArenaFull), APP_KEYS_MAX)
    );
    k.destroy(live.pop().unwrap()).unwrap();
    live.push(k.random_key(KeyUsage::Derive).unwrap());
    drop(live.pop());
    assert!(k.random_key(KeyUsage::Derive).is_ok());
    // the lock revokes every handle
    w.lock();
    assert_eq!(
        k.seal(&h, Nonce::Random, b"", b"x").err().unwrap(),
        Error::KeyRevoked
    );
}

// ------------------------------------------------------------------ app records (spec §12.4; plan T21 part 3)

use scaas_ua::wallet::{
    app_record_digest, is_scaas_purpose, sign_app_record, verify_app_record_key, AppPath, KeyRef,
    Signer, TypedData, SCAAS_DOMAIN_NAMES, SCAAS_PURPOSES,
};

fn src(rel: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/../../smartcontracts/evm/src/{rel}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

/// Drift (review r2 R14): the generated purpose list is exactly `UAKinds.sol`'s `PURPOSE_*` and `APP_PURPOSE_NS` constants, each
/// an ASCII `scaas.ua.purpose.*` string shorter than 64 bytes; the domain names hold the registry's two and every token's.
#[test]
fn refusal_lists_match_the_contracts() {
    let kinds = src("ua/UAKinds.sol");
    let mut found = vec![];
    for line in kinds.lines() {
        let l = line.trim();
        let Some(rest) = l.strip_prefix("bytes32 internal constant ") else {
            continue;
        };
        let (name, tail) = rest.split_once(" = keccak256(\"").unwrap_or(("", ""));
        if !(name.starts_with("PURPOSE_") || name == "APP_PURPOSE_NS") {
            continue;
        }
        found.push((
            name.to_string(),
            tail.split('"').next().unwrap().to_string(),
        ));
    }
    let listed: Vec<(String, String)> = SCAAS_PURPOSES
        .iter()
        .map(|(n, s)| (n.to_string(), s.to_string()))
        .collect();
    assert_eq!(
        found, listed,
        "run clients/ua-rs/scripts/gen_app_refusals.py"
    );
    for (n, s) in SCAAS_PURPOSES {
        assert!(
            s.is_ascii() && s.starts_with("scaas.ua.purpose.") && s.len() < 64,
            "{n}"
        );
    }
    // the domain names: every "SCaaS ..." literal of smartcontracts/evm/src (legacy/ apart), as the generator collects them
    fn walk(dir: &std::path::Path, out: &mut std::collections::BTreeSet<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() && p.file_name().unwrap() != "legacy" {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "sol") {
                let t = std::fs::read_to_string(&p).unwrap();
                for (i, _) in t.match_indices("\"SCaaS ") {
                    let rest = &t[i + 1..];
                    let end = rest.find('"').unwrap();
                    let lit = &rest[..end];
                    if lit.chars().all(|c| c.is_ascii_alphanumeric() || c == ' ') {
                        out.insert(lit.trim().to_string());
                    }
                }
            }
        }
    }
    let mut names = std::collections::BTreeSet::new();
    walk(
        std::path::Path::new(&format!(
            "{}/../../smartcontracts/evm/src",
            env!("CARGO_MANIFEST_DIR")
        )),
        &mut names,
    );
    assert_eq!(
        names.into_iter().collect::<Vec<_>>(),
        SCAAS_DOMAIN_NAMES
            .iter()
            .map(|n| n.to_string())
            .collect::<Vec<_>>(),
        "run clients/ua-rs/scripts/gen_app_refusals.py"
    );
    for n in [
        "SCaaS UARegistry",
        "SCaaS UA Portable",
        "SCaaS MetaToken",
        "SCaaS PqzToken",
        "SCaaS ZetherToken",
        "SCaaS Dex",
        "SCaaS PqChat",
    ] {
        assert!(SCAAS_DOMAIN_NAMES.contains(&n), "{n}");
    }
}

const APP: [u8; 32] = [0x5a; 32];

fn portable(app_id: &[u8; 32], name: &str, extra: Option<(&str, &str)>) -> TypedData {
    let mut domain =
        serde_json::json!({"name": name, "version": "1", "salt": format!("0x{}", hexs(app_id))});
    if let Some((k, v)) = extra {
        domain[k] = serde_json::json!(v);
    }
    TypedData::from_value_for_tests(domain)
}

fn chain_bound(name: &str, with_contract: bool) -> TypedData {
    let mut domain = serde_json::json!({"name": name, "version": "1", "chainId": "7622"});
    if with_contract {
        domain["verifyingContract"] =
            serde_json::json!("0x00000000000000000000000000000000000000aa");
    }
    TypedData::from_value_for_tests(domain)
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

trait ForTests {
    fn from_value_for_tests(domain: Value) -> TypedData;
}
impl ForTests for TypedData {
    fn from_value_for_tests(domain: Value) -> TypedData {
        let mut fields = vec![
            serde_json::json!({"name": "name", "type": "string"}),
            serde_json::json!({"name": "version", "type": "string"}),
        ];
        for (k, t) in [
            ("chainId", "uint256"),
            ("verifyingContract", "address"),
            ("salt", "bytes32"),
        ] {
            if domain.get(k).is_some() {
                fields.push(serde_json::json!({"name": k, "type": t}));
            }
        }
        let v = serde_json::json!({
            "types": {"EIP712Domain": fields, "Note": [{"name": "id", "type": "bytes32"}, {"name": "body", "type": "string"}]},
            "primaryType": "Note",
            "domain": domain,
            "message": {"id": format!("0x{}", "11".repeat(32)), "body": "hello"},
        });
        TypedData::from_json(&serde_json::to_vec(&v).unwrap()).unwrap()
    }
}

/// Each path: a positive control signed and verified by a UA key; then one change at a time, each refusal by name.
#[test]
fn app_record_paths_and_refusals() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    let KeyRef::Ua { kind, key_data } = key.key_ref() else {
        panic!()
    };
    let purpose = scaas_ua::keccak256(b"an app's own purpose");
    let a = AppPath::Portable { app_id: APP };
    let b = AppPath::ChainBound { purpose };
    // the controls
    let pa = portable(&APP, "My App", None);
    let sig = sign_app_record(&key, None, &a, &pa).unwrap();
    assert!(sig.key_data.is_empty() && sig.members.is_empty());
    assert!(verify_app_record_key(
        kind,
        &key_data,
        &a,
        &pa,
        &sig.signature
    ));
    let cb = chain_bound("My App", true);
    let sig_b = sign_app_record(&key, None, &b, &cb).unwrap();
    assert!(verify_app_record_key(
        kind,
        &key_data,
        &b,
        &cb,
        &sig_b.signature
    ));
    // a signature does not cross paths, apps or purposes
    assert!(!verify_app_record_key(
        kind,
        &key_data,
        &AppPath::Portable { app_id: [0x5b; 32] },
        &portable(&[0x5b; 32], "My App", None),
        &sig.signature
    ));
    assert!(!verify_app_record_key(
        kind,
        &key_data,
        &AppPath::ChainBound { purpose: [9; 32] },
        &cb,
        &sig_b.signature
    ));
    // path B: every SCaaS purpose constant, one row each, the seal purpose
    for (n, s) in SCAAS_PURPOSES {
        let p = AppPath::ChainBound {
            purpose: scaas_ua::keccak256(s.as_bytes()),
        };
        assert_eq!(
            sign_app_record(&key, None, &p, &cb).err(),
            Some(Error::AppPurposeRefused),
            "{n}"
        );
    }
    assert!(is_scaas_purpose(&scaas_ua::seal_purpose_tag()));
    assert!(!is_scaas_purpose(&purpose));
    // every SCaaS domain name, on both paths
    for n in SCAAS_DOMAIN_NAMES {
        assert_eq!(
            app_record_digest(&a, &portable(&APP, n, None)).err(),
            Some(Error::AppDomainRefused),
            "{n}"
        );
        assert_eq!(
            app_record_digest(&b, &chain_bound(n, true)).err(),
            Some(Error::AppDomainRefused),
            "{n}"
        );
    }
    // path A: another field set, another salt, app_id 0
    let with_chain = portable(&APP, "My App", Some(("chainId", "1")));
    assert_eq!(
        app_record_digest(&a, &with_chain).err(),
        Some(Error::AppDomainRefused)
    );
    assert_eq!(
        app_record_digest(&a, &portable(&[0x5b; 32], "My App", None)).err(),
        Some(Error::AppSaltMismatch)
    );
    assert_eq!(
        app_record_digest(
            &AppPath::Portable { app_id: [0; 32] },
            &portable(&[0; 32], "My App", None)
        )
        .err(),
        Some(Error::Argument)
    );
    // path B: a domain without its contract
    assert_eq!(
        app_record_digest(&b, &chain_bound("My App", false)).err(),
        Some(Error::AppDomainRefused)
    );
}
