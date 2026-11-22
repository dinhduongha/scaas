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

// --- verify_app_record (scaas-sdk spec §12.2, review r2 R7): derived, native and nested `msig` signers, as the registry judges ---

use scaas_ua::ua_portable::{check_authorization_current, InnerSig, MemberSig, UASig};
use scaas_ua::wallet::{msig_sig_app, ua_sig, verify_app_record, AppRecordState, Network, Slot};
use std::collections::HashMap;

const MSIG: u16 = 0x0120;

fn dom(generation: u32) -> scaas_ua::Domain {
    scaas_ua::Domain {
        generation,
        chain_id: 31337,
        registry: [0x5c; 20],
        chain_uid: [0x60; 32],
    }
}

fn id_of(k: &dyn Signer) -> ([u8; 32], u16, Vec<u8>) {
    let KeyRef::Ua { kind, key_data } = k.key_ref() else {
        panic!()
    };
    (
        scaas_ua::derive_ua(kind, &key_data, false).unwrap(),
        kind,
        key_data,
    )
}

fn native_id(w: &Wallet) -> [u8; 32] {
    let a = w
        .native_key(Network::Evm, 0, None)
        .unwrap()
        .address()
        .unwrap();
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(&unhex(&Value::String(a)));
    id
}

/// The registry's state of a few records: `(kind, keyData)` by id, every slot of every `msig` accepted unless `refused`.
struct St {
    recs: HashMap<[u8; 32], (u16, Vec<u8>)>,
    refused: Option<([u8; 32], u16)>,
}
impl St {
    fn check(
        &self,
        ua: &[u8; 32],
        path: &AppPath,
        td: &TypedData,
        sig: &UASig,
        d: Option<&scaas_ua::Domain>,
    ) -> bool {
        let members = |id: [u8; 32]| self.recs.get(&id).cloned();
        let accepted = |id: [u8; 32], i: u16| self.refused != Some((id, i));
        verify_app_record(
            ua,
            path,
            td,
            sig,
            &AppRecordState {
                members: &members,
                current: &|_| None,
                accepted: &accepted,
                domain: d,
            },
        )
    }
}

fn by_index(mut v: Vec<(u16, Slot<'_>)>) -> Vec<Slot<'_>> {
    v.sort_by_key(|x| x.0);
    v.into_iter().map(|x| x.1).collect()
}

fn slot(index: u16, sig: Vec<u8>) -> MemberSig {
    MemberSig {
        index,
        members: vec![],
        sig,
    }
}

/// The existing `msig` vectors (signatures.json `msig.sets`, purpose `metatx`, context A gen 1) through `scaas-ua`'s
/// `requireAuthorized` check, the one `verify_app_record` runs on path B: every set's verdict.
#[test]
fn msig_vector_sets_through_the_authorization_check() {
    let f = format!(
        "{}/../../smartcontracts/vectors/ua/signatures.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
    let m = &v["msig"];
    let c = &v["contexts"][m["context"].as_str().unwrap()];
    let d = scaas_ua::Domain {
        generation: m["generation"].as_u64().unwrap() as u32,
        chain_id: c["chainId"].as_u64().unwrap(),
        registry: unhex(&c["registry"]).try_into().unwrap(),
        chain_uid: a32(&c["chainUid"]),
    };
    let derived: HashMap<[u8; 32], (u16, Vec<u8>)> = v["derived"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| {
            (
                a32(&r["ua"]),
                (r["kind"].as_u64().unwrap() as u16, unhex(&r["keyData"])),
            )
        })
        .collect();
    let members = |id: [u8; 32]| derived.get(&id).cloned();
    let (kd, ua) = (unhex(&m["keyData"]), a32(&m["ua"]));
    let sets = m["sets"].as_array().unwrap();
    assert_eq!(sets.len(), 10);
    for s in sets {
        let slots: Vec<MemberSig> = s["uaSig"]["members"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| MemberSig {
                index: x["index"].as_u64().unwrap() as u16,
                members: x["members"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|y| InnerSig {
                        index: y["index"].as_u64().unwrap() as u16,
                        sig: unhex(&y["sig"]),
                    })
                    .collect(),
                sig: unhex(&x["sig"]),
            })
            .collect();
        let got = check_authorization_current(
            &kd,
            &ua,
            &scaas_ua::purpose_tag(s["purpose"].as_str().unwrap()).unwrap(),
            &a32(&s["digest"]),
            &slots,
            &d,
            &members,
            &|_| None,
            Some(&|_, _| true),
        );
        assert_eq!(got.is_ok(), s["valid"].as_bool().unwrap(), "{}", s["name"]);
    }
}

/// A positive control per signer kind and path, then one change at a time: a derived key (both paths), a native key (path B
/// only), an `msig` of a derived, a native and a nested `msig` member (path A by `msig_sig_app`, path B member by member).
#[test]
fn verify_app_record_signers() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k1 = w.ua_key(0x0108, 0, 0).unwrap();
    let k2 = w.ua_key(0x0102, 0, 0).unwrap();
    let k3 = w.ua_key(0x0103, 0, 0).unwrap();
    let nat = w.native_key(Network::Evm, 0, None).unwrap();
    let (id1, kind1, kd1) = id_of(&k1);
    let (id2, kind2, kd2) = id_of(&k2);
    let (id3, kind3, kd3) = id_of(&k3);
    let nid = native_id(&w);
    let purpose = scaas_ua::keccak256(b"an app's own purpose");
    let (a, b) = (
        AppPath::Portable { app_id: APP },
        AppPath::ChainBound { purpose },
    );
    let (pa, cb) = (portable(&APP, "My App", None), chain_bound("My App", true));
    let d1 = dom(1);
    // inner msig I = {k2, k3}, threshold 2; outer U = {k1 (1), native (1), I (1)}, threshold 2
    // members in id order (CTR-UA-09)
    let sorted = |mut m: Vec<(u16, [u8; 32], u16)>| {
        m.sort_by_key(|x| x.1);
        m
    };
    let im = sorted(vec![(kind2, id2, 1), (kind3, id3, 1)]);
    let inner_kd = scaas_ua::encode_msig(2, &im);
    let inner = scaas_ua::derive_ua(MSIG, &inner_kd, false).unwrap();
    let om = sorted(vec![(kind1, id1, 1), (1, nid, 1), (MSIG, inner, 1)]);
    let kd = scaas_ua::encode_msig(2, &om);
    let at =
        |m: &[(u16, [u8; 32], u16)], id: [u8; 32]| m.iter().position(|x| x.1 == id).unwrap() as u16;
    let (i1, i_n, i_i) = (at(&om, id1), at(&om, nid), at(&om, inner));
    let (j2, j3) = (at(&im, id2), at(&im, id3));
    let ua = scaas_ua::derive_ua(MSIG, &kd, false).unwrap();
    let st = St {
        recs: HashMap::from([
            (id1, (kind1, kd1.clone())),
            (id2, (kind2, kd2.clone())),
            (id3, (kind3, kd3)),
            (inner, (MSIG, inner_kd.clone())),
            (ua, (MSIG, kd.clone())),
        ]),
        refused: None,
    };

    // a derived key, both paths: path A without key data, path B with it
    let sa = sign_app_record(&k1, None, &a, &pa).unwrap();
    assert!(st.check(&id1, &a, &pa, &sa, None));
    let sb = sign_app_record(&k1, None, &b, &cb).unwrap();
    assert!(!sb.key_data.is_empty());
    assert!(st.check(&id1, &b, &cb, &sb, None));
    // another key of the kind signs with its own key data: refused for id1 (the key data hashes to another id)
    let k1b = w.ua_key(0x0108, 0, 1).unwrap();
    let sb2 = sign_app_record(&k1b, None, &b, &cb).unwrap();
    assert!(
        !st.check(&id1, &b, &cb, &sb2, None),
        "key data of another id"
    );
    assert!(
        !st.check(
            &id1,
            &b,
            &cb,
            &UASig {
                key_data: vec![],
                ..sb.clone()
            },
            None
        ),
        "no key data"
    );
    assert!(
        !st.check(
            &id1,
            &a,
            &pa,
            &UASig {
                key_data: kd1.clone(),
                ..sa.clone()
            },
            None
        ),
        "path A carries no key data"
    );
    assert!(
        !st.check(&id1, &a, &pa, &sb, None),
        "a path-B signature on path A"
    );
    assert!(!st.check(&id2, &a, &pa, &sa, None), "another UA");
    let unknown = St {
        recs: HashMap::new(),
        refused: None,
    };
    assert!(
        !unknown.check(&id1, &a, &pa, &sa, None),
        "an unregistered UA"
    );

    // a native key, path B over UAAuth in the registry's domain
    let sn = sign_app_record(&nat, Some(&d1), &b, &cb).unwrap();
    assert!(st.check(&nid, &b, &cb, &sn, Some(&d1)));
    assert!(
        !st.check(&nid, &b, &cb, &sn, Some(&dom(2))),
        "another registry generation"
    );
    assert!(!st.check(&nid, &b, &cb, &sn, None), "no domain read");
    assert!(
        !st.check(&nid, &a, &pa, &sn, Some(&d1)),
        "a native id has no portable record"
    );
    assert!(
        !st.check(
            &nid,
            &AppPath::ChainBound { purpose: [9; 32] },
            &cb,
            &sn,
            Some(&d1)
        ),
        "another purpose"
    );

    // the msig, path A: k1 and the nested msig (its k2, k3), minimal
    let inner_of = |id: [u8; 32]| (id == inner).then(|| inner_kd.clone());
    let mut leaves = vec![(j2, &k2 as &dyn Signer), (j3, &k3 as &dyn Signer)];
    leaves.sort_by_key(|x| x.0);
    let slots = by_index(vec![
        (
            i1,
            Slot::Member {
                index: i1,
                key: &k1,
            },
        ),
        (
            i_i,
            Slot::Msig {
                index: i_i,
                members: leaves,
            },
        ),
    ]);
    let ma = msig_sig_app(&kd, &|_| None, &inner_of, &APP, &pa, &slots).unwrap();
    assert!(st.check(&ua, &a, &pa, &ma, None));
    let refused = |id, i| St {
        recs: st.recs.clone(),
        refused: Some((id, i)),
    };
    assert!(
        !refused(ua, i1).check(&ua, &a, &pa, &ma, None),
        "an outer slot not accepted"
    );
    assert!(
        !refused(inner, j3).check(&ua, &a, &pa, &ma, None),
        "an inner slot not accepted"
    );
    let mut short = ma.clone();
    short
        .members
        .iter_mut()
        .find(|m| m.index == i_i)
        .unwrap()
        .members
        .pop();
    assert!(
        !st.check(&ua, &a, &pa, &short, None),
        "the inner msig below its threshold"
    );
    let mut one = ma.clone();
    one.members.pop();
    assert!(!st.check(&ua, &a, &pa, &one, None), "below the threshold");
    // path A: a native member signs the record's typed digest itself
    let two = by_index(vec![
        (
            i1,
            Slot::Member {
                index: i1,
                key: &k1,
            },
        ),
        (
            i_n,
            Slot::Member {
                index: i_n,
                key: &nat,
            },
        ),
    ]);
    let na = msig_sig_app(&kd, &|_| None, &inner_of, &APP, &pa, &two).unwrap();
    assert!(st.check(&ua, &a, &pa, &na, None));
    // three slots where two reach the threshold: not minimal
    let mut extra = na.clone();
    extra
        .members
        .push(ma.members.iter().find(|m| m.index == i_i).unwrap().clone());
    extra.members.sort_by_key(|m| m.index);
    assert!(!st.check(&ua, &a, &pa, &extra, None), "not minimal");

    // the msig, path B: md = memberDigest(ua, uaMessage(msig, purpose, digest)); k1 under `member`, the native one over UAAuth
    let digest = cb.digest().unwrap();
    let md = scaas_ua::member_digest(&ua, &scaas_ua::ua_message(MSIG, &purpose, &digest).unwrap());
    let member = scaas_ua::purpose_tag("member").unwrap();
    let s0 = ua_sig(&k1, None, &member, &md).unwrap().signature;
    let s1 = ua_sig(&nat, Some(&d1), &member, &md).unwrap().signature;
    let mut both = vec![slot(i1, s0.clone()), slot(i_n, s1)];
    both.sort_by_key(|m| m.index);
    let mb = UASig {
        key_data: vec![],
        signature: vec![],
        members: both,
    };
    assert!(st.check(&ua, &b, &cb, &mb, Some(&d1)));
    assert!(
        !st.check(&ua, &b, &cb, &mb, Some(&dom(2))),
        "the native member in another domain"
    );
    assert!(
        !refused(ua, i_n).check(&ua, &b, &cb, &mb, Some(&d1)),
        "a slot not accepted"
    );
    let lone = UASig {
        members: vec![slot(i1, s0)],
        ..mb.clone()
    };
    assert!(
        !st.check(&ua, &b, &cb, &lone, Some(&d1)),
        "below the threshold"
    );
    assert!(
        !st.check(&ua, &a, &pa, &mb, Some(&d1)),
        "a path-B msig signature on path A"
    );
}

// --- PqChat's signed records (scaas-sdk spec §12.5): smartcontracts/vectors/pqchat/ through scaas-ua's builder ---

use scaas_ua::wallet::pqchat;

fn pq(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqchat/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// Every signed record row: its struct hash, typed digest and `uaMessage` digest; the vector's signature verifies over it under
/// its signer's key; each session's and epoch's `wrapHashes` are the struct hashes of keys.json's wraps.
#[test]
fn pqchat_records_reproduce_the_vectors() {
    let (rec, top, keys) = (pq("records"), pq("topics"), pq("keys"));
    let signers: HashMap<String, Value> = rec["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| (s["name"].as_str().unwrap().to_string(), s.clone()))
        .collect();
    let rows = [
        (&rec, "session", "PqChatSession"),
        (&rec, "epoch", "PqChatEpoch"),
        (&rec, "leave", "PqChatLeave"),
        (&rec, "remove", "PqChatRemove"),
        (&rec, "message", "PqChatMessage"),
        (&top, "topic", "PqTopic"),
        (&top, "update", "PqTopicUpdate"),
        (&top, "writer", "PqTopicWriter"),
        (&top, "post", "PqTopicEntry"),
        (&top, "reply", "PqTopicEntry"),
        (&top, "edit", "PqTopicEdit"),
        (&top, "vote", "PqTopicVote"),
    ];
    assert_eq!(pqchat::RECORDS.len(), 11);
    assert_eq!(a32(&rec["purpose"]["hash"]), pqchat::purpose());
    for (v, row, name) in rows {
        let r = &v[row];
        let td = pqchat::typed(name, r["record"].clone()).unwrap();
        assert_eq!(td.struct_hash().unwrap(), a32(&r["hashStruct"]), "{row}");
        assert_eq!(td.digest().unwrap(), a32(&r["typed"]), "{row}");
        let kind = r["uaMessage"]["kind"].as_u64().unwrap() as u16;
        let m = scaas_ua::ua_message(kind, &pqchat::purpose(), &td.digest().unwrap()).unwrap();
        assert_eq!(m, a32(&r["uaMessage"]["digest"]), "{row}");
        if let Some(sig) = r.get("uaSig") {
            let pk = unhex(&signers[r["signer"].as_str().unwrap()]["publicKey"]);
            assert!(
                scaas_ua::verify::verify(kind, &pk, &m, &unhex(&sig["signature"]), true, false),
                "{row}"
            );
        }
    }
    for (row, prefix) in [("session", "session/"), ("epoch", "epoch-1/")] {
        let want: Vec<[u8; 32]> = keys["wraps"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|w| w["name"].as_str().unwrap().starts_with(prefix))
            .map(|w| pqchat::wrap_hash(w["wrap"].clone()).unwrap())
            .collect();
        let got: Vec<[u8; 32]> = rec[row]["record"]["wrapHashes"]
            .as_array()
            .unwrap()
            .iter()
            .map(a32)
            .collect();
        assert_eq!(got, want, "{row}");
    }
    // the ids: a session's by its creator and nonce, a topic's by its admin and nonce
    let s = &rec["session"]["record"];
    let w64 = |n: u64| {
        let mut w = [0u8; 32];
        w[24..].copy_from_slice(&n.to_be_bytes());
        w
    };
    assert_eq!(
        pqchat::id(
            "session",
            &[a32(&s["creator"]), w64(s["nonce"].as_u64().unwrap())]
        ),
        a32(&rec["session"]["id"])
    );
    let t = &top["topic"]["record"];
    assert_eq!(
        pqchat::id(
            "topic",
            &[a32(&t["admin"]), w64(t["nonce"].as_u64().unwrap())]
        ),
        a32(&top["topic"]["id"])
    );
}

/// A UA key signs a record (a control verifying under its key), and nothing but a record of `DS_C`.
#[test]
fn pqchat_sign_records_only() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.ua_key(0x0131, 0, 0).unwrap();
    let (_, kind, kd) = id_of(&k);
    let r = pq("records");
    let td = pqchat::typed("PqChatLeave", r["leave"]["record"].clone()).unwrap();
    let s = pqchat::sign(&k, &td).unwrap();
    assert!(s.key_data.is_empty() && s.members.is_empty());
    let m = scaas_ua::ua_message(kind, &pqchat::purpose(), &td.digest().unwrap()).unwrap();
    assert!(scaas_ua::verify::verify(
        kind,
        &kd,
        &m,
        &s.signature,
        true,
        false
    ));
    let wrap = pqchat::typed("Wrap", pq("keys")["wraps"][0]["wrap"].clone()).unwrap();
    assert_eq!(
        pqchat::sign(&k, &wrap).err(),
        Some(Error::Argument),
        "a nested struct"
    );
    let nat = w.native_key(Network::Evm, 0, None).unwrap();
    assert_eq!(
        pqchat::sign(&nat, &td).err(),
        Some(Error::Argument),
        "a native key"
    );
    assert!(pqchat::typed("Nope", Value::Null).is_err());
}

/// A UA key signs its contact card (a control verifying under its key); a native key does not; a malformed Matrix id is no card.
#[test]
fn pqchat_sign_card() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let k = w.ua_key(0x0131, 0, 0).unwrap();
    let (ua, kind, kd) = id_of(&k);
    let card = pqchat::Card {
        ua,
        kem_version: 1,
        matrix_id: "@alice:example.org".into(),
    };
    let s = pqchat::sign_card(&k, &card).unwrap();
    assert!(s.key_data.is_empty() && s.members.is_empty());
    let td = pqchat::card_typed(&card).unwrap();
    let m = scaas_ua::ua_message(kind, &pqchat::purpose(), &td.digest().unwrap()).unwrap();
    assert!(scaas_ua::verify::verify(
        kind,
        &kd,
        &m,
        &s.signature,
        true,
        false
    ));
    let nat = w.native_key(Network::Evm, 0, None).unwrap();
    assert_eq!(
        pqchat::sign_card(&nat, &card).err(),
        Some(Error::Argument),
        "a native key"
    );
    let bad = pqchat::Card {
        matrix_id: "alice:example.org".into(),
        ..card
    };
    assert_eq!(
        pqchat::sign_card(&k, &bad).err(),
        Some(Error::Argument),
        "a malformed Matrix id"
    );
}

// --- PqVault's dedicated signing path (owner 2026-11-22, CLI-PQV-12): smartcontracts/vectors/pqvault/records.json ---

use scaas_ua::wallet::{pqvault, SCAAS_APP_IDS};

fn pqv() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqvault/records.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

/// An `encodeType` string as JSON `types` entries.
fn types_of(enc: &str, out: &mut serde_json::Map<String, Value>) {
    let mut rest = enc;
    while let Some(open) = rest.find('(') {
        let close = open + rest[open..].find(')').unwrap();
        let fields: Vec<Value> = rest[open + 1..close]
            .split(',')
            .map(|f| {
                let (t, n) = f.split_once(' ').unwrap();
                serde_json::json!({"name": n, "type": t})
            })
            .collect();
        out.insert(rest[..open].to_string(), Value::Array(fields));
        rest = &rest[close + 1..];
    }
}

/// A record's typed data: its struct's type string `enc`, `domain` with its `EIP712Domain` type string `denc`.
fn pqv_typed(enc: &str, st: &str, record: &Value, denc: &str, domain: &Value) -> TypedData {
    let mut types = serde_json::Map::new();
    types_of(enc, &mut types);
    types_of(denc, &mut types);
    let v =
        serde_json::json!({"types": types, "primaryType": st, "domain": domain, "message": record});
    TypedData::from_json(&serde_json::to_vec(&v).unwrap()).unwrap()
}

/// A vault mode's path, domain and domain type string: 0 `DS_V` portable under `APP_ID`, 1 `DS_B` chain-bound under `P_V`.
fn pqv_mode(d: &Value, mode: u64) -> (AppPath, Value, String) {
    let (k, path) = match mode {
        0 => (
            "V",
            AppPath::Portable {
                app_id: pqvault::app_id(),
            },
        ),
        _ => (
            "B",
            AppPath::ChainBound {
                purpose: pqvault::purpose(),
            },
        ),
    };
    let x = &d["domains"][k];
    let mut dom = serde_json::json!({"name": x["name"], "version": x["version"]});
    for f in ["salt", "chainId", "verifyingContract"] {
        if let Some(v) = x.get(f) {
            dom[f] = v.clone();
        }
    }
    (path, dom, x["type"].as_str().unwrap().to_string())
}

/// Every record row of the vectors through `pqvault`: its typed digest in its vault's domain, its committed signature
/// verified on its path; the generic path refuses every one of them (`AppDomainRefused`); the pinned constants.
#[test]
fn pqvault_records_reproduce_the_vectors() {
    let d = pqv();
    assert_eq!(pqvault::app_id(), a32(&d["purpose"]["appId"]));
    assert_eq!(pqvault::purpose(), a32(&d["purpose"]["purpose"]));
    assert_eq!(pqvault::RECORDS.len(), 7);
    for (n, s) in pqvault::RECORDS {
        assert_eq!(d["typehashes"][n]["type"], *s, "{n}");
        assert_eq!(
            scaas_ua::keccak256(s.as_bytes()),
            a32(&d["typehashes"][n]["hash"]),
            "{n}"
        );
    }
    let signers: HashMap<String, (u16, Vec<u8>)> = d["signers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["ua"].as_str().unwrap().to_string(),
                (s["kind"].as_u64().unwrap() as u16, unhex(&s["publicKey"])),
            )
        })
        .collect();
    let by_name = |n: &str| {
        d["signers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|s| s["name"] == n)
            .unwrap()["ua"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let st = St {
        recs: signers
            .iter()
            .map(|(u, r)| (a32(&Value::String(u.clone())), r.clone()))
            .collect(),
        refused: None,
    };
    let mut n = 0;
    for v in d["vaults"].as_array().unwrap() {
        let (path, dom, denc) = pqv_mode(&d, v["mode"].as_u64().unwrap());
        for r in v["records"].as_array().unwrap() {
            let s = r["struct"].as_str().unwrap();
            let enc = d["typehashes"][s]["type"].as_str().unwrap();
            let td = pqv_typed(enc, s, &r["record"], &denc, &dom);
            assert_eq!(
                pqvault::digest(&path, &td).unwrap(),
                a32(&r["typed"]),
                "{}",
                r["name"]
            );
            // the generic path: refused by the domain's name (positive twin: the dedicated digest above)
            assert_eq!(
                app_record_digest(&path, &td).err(),
                Some(Error::AppDomainRefused),
                "{}",
                r["name"]
            );
            let ua = a32(&Value::String(by_name(r["signer"].as_str().unwrap())));
            let sig = UASig {
                key_data: unhex(&r["uaSig"]["keyData"]),
                signature: unhex(&r["uaSig"]["signature"]),
                members: vec![],
            };
            let ok = |sig: &UASig| {
                let members = |id: [u8; 32]| st.recs.get(&id).cloned();
                pqvault::verify(
                    &ua,
                    &path,
                    &td,
                    sig,
                    &AppRecordState {
                        members: &members,
                        current: &|_| None,
                        accepted: &|_, _| true,
                        domain: None,
                    },
                )
            };
            assert!(ok(&sig), "{}", r["name"]);
            let mut bad = sig.clone();
            bad.signature[5] ^= 1;
            assert!(!ok(&bad), "{}: a changed signature", r["name"]);
            n += 1;
        }
    }
    assert_eq!(n, 23);
}

/// Each refusal one change at a time beside its control: the generic path in PqVault's domain or under its purpose; the
/// dedicated path outside PqVault's domains, structs and paths, and with a key that has no portable record.
#[test]
fn pqvault_sign_refusals() {
    let d = pqv();
    let w = Wallet::from_mnemonic(d["pqvAccount"]["mnemonic"].as_str().unwrap(), "").unwrap();
    let key = w.ua_key(0x0132, 0x7071_7600, 0).unwrap();
    let (ua, kind, kd) = id_of(&key);
    let item = d["vaults"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|v| v["records"].as_array().unwrap().iter())
        .find(|r| r["struct"] == "PqVaultItem")
        .unwrap()["record"]
        .clone();
    let enc = d["typehashes"]["PqVaultItem"]["type"].as_str().unwrap();
    let (pa, dv, venc) = pqv_mode(&d, 0);
    let (pb, db, benc) = pqv_mode(&d, 1);
    let tv = pqv_typed(enc, "PqVaultItem", &item, &venc, &dv);
    let tb = pqv_typed(enc, "PqVaultItem", &item, &benc, &db);
    let members = |id: [u8; 32]| (id == ua).then(|| (kind, kd.clone()));
    let state = AppRecordState {
        members: &members,
        current: &|_| None,
        accepted: &|_, _| true,
        domain: None,
    };
    // the controls: both paths sign and verify
    let sv = pqvault::sign(&key, None, &pa, &tv).unwrap();
    assert!(sv.key_data.is_empty() && sv.members.is_empty());
    assert!(pqvault::verify(&ua, &pa, &tv, &sv, &state));
    let sb = pqvault::sign(&key, None, &pb, &tb).unwrap();
    assert!(pqvault::verify(&ua, &pb, &tb, &sb, &state));
    // the generic path: PqVault's domain on either path
    assert_eq!(
        sign_app_record(&key, None, &pa, &tv).err(),
        Some(Error::AppDomainRefused)
    );
    assert_eq!(
        sign_app_record(&key, None, &pb, &tb).err(),
        Some(Error::AppDomainRefused)
    );
    // the generic path under PqVault's app id or purpose with an app's own domain name (control: another app id)
    let mine = portable(&pqvault::app_id(), "My App", None);
    assert_eq!(
        sign_app_record(&key, None, &pa, &mine).err(),
        Some(Error::AppPurposeRefused)
    );
    assert_eq!(
        sign_app_record(&key, None, &pb, &chain_bound("My App", true)).err(),
        Some(Error::AppPurposeRefused)
    );
    assert!(is_scaas_purpose(&pqvault::purpose()));
    assert!(sign_app_record(
        &key,
        None,
        &AppPath::Portable { app_id: APP },
        &portable(&APP, "My App", None)
    )
    .is_ok());
    // the dedicated path: another domain name, version or salt, on each path
    for (k, v, mode) in [
        ("name", serde_json::json!("SCaaS PqChat"), 0),
        ("name", serde_json::json!("My App"), 0),
        ("version", serde_json::json!("2"), 0),
        (
            "salt",
            serde_json::json!(format!("0x{}", "11".repeat(32))),
            0,
        ),
        ("name", serde_json::json!("SCaaS PqChat"), 1),
        ("name", serde_json::json!("My App"), 1),
        ("version", serde_json::json!("2"), 1),
    ] {
        let (p, base, denc, s) = if mode == 0 {
            (&pa, &dv, &venc, &sv)
        } else {
            (&pb, &db, &benc, &sb)
        };
        let mut dom = base.clone();
        dom[k] = v;
        let t = pqv_typed(enc, "PqVaultItem", &item, denc, &dom);
        assert_eq!(
            pqvault::sign(&key, None, p, &t).err(),
            Some(Error::AppDomainRefused),
            "{k} {mode}"
        );
        assert!(!pqvault::verify(&ua, p, &t, s, &state), "{k} {mode}");
    }
    let mut extra = db.clone();
    extra["salt"] = dv["salt"].clone();
    let t = pqv_typed(
        enc,
        "PqVaultItem",
        &item,
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)",
        &extra,
    );
    assert_eq!(
        pqvault::sign(&key, None, &pb, &t).err(),
        Some(Error::AppDomainRefused),
        "DS_B with a salt"
    );
    // the dedicated path: a domain on the other path, the chain-bound path under the app id, another app
    assert_eq!(
        pqvault::sign(&key, None, &pb, &tv).err(),
        Some(Error::AppDomainRefused)
    );
    assert_eq!(
        pqvault::sign(&key, None, &pa, &tb).err(),
        Some(Error::AppDomainRefused)
    );
    let under_id = AppPath::ChainBound {
        purpose: pqvault::app_id(),
    };
    assert_eq!(
        pqvault::sign(&key, None, &under_id, &tb).err(),
        Some(Error::AppDomainRefused)
    );
    assert!(!pqvault::verify(&ua, &under_id, &tb, &sb, &state));
    assert_eq!(
        pqvault::sign(&key, None, &AppPath::Portable { app_id: APP }, &tv).err(),
        Some(Error::AppDomainRefused)
    );
    // the dedicated path: a struct that is not PqVault's, a PqVault name with other fields, a nested one alone
    let note = TypedData::from_json(
        &serde_json::to_vec(&serde_json::json!({
            "types": {"EIP712Domain": [{"name": "name", "type": "string"}, {"name": "version", "type": "string"},
                {"name": "salt", "type": "bytes32"}], "Note": [{"name": "id", "type": "bytes32"}]},
            "primaryType": "Note", "domain": dv, "message": {"id": format!("0x{}", "11".repeat(32))},
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        pqvault::sign(&key, None, &pa, &note).err(),
        Some(Error::Argument)
    );
    let wide = enc.replace("uint64 nonce", "uint256 nonce");
    let t = pqv_typed(&wide, "PqVaultItem", &item, &venc, &dv);
    assert_eq!(
        pqvault::sign(&key, None, &pa, &t).err(),
        Some(Error::Argument),
        "another field type"
    );
    let mk = pqv_typed(
        d["typehashes"]["MemberKey"]["type"].as_str().unwrap(),
        "MemberKey",
        &serde_json::json!({"ua": format!("0x{}", "11".repeat(32)), "keyId": 1, "via": format!("0x{}", "00".repeat(32))}),
        &venc,
        &dv,
    );
    assert_eq!(
        pqvault::sign(&key, None, &pa, &mk).err(),
        Some(Error::Argument),
        "a nested struct"
    );
    // a key with no portable record (a native EVM key) on the portable path
    let nat = w.native_key(Network::Evm, 0, None).unwrap();
    assert_eq!(
        pqvault::sign(&nat, None, &pa, &tv).err(),
        Some(Error::Argument)
    );
}

/// Drift: `SCAAS_APP_IDS` is exactly `PqVaultTypes.sol`'s `APP_ID` (the generator's list), its hash `pqvault::app_id()`.
#[test]
fn scaas_app_ids_match_the_contracts() {
    let t = src("pqvault/PqVaultTypes.sol");
    assert!(t.contains("bytes32 internal constant APP_ID = keccak256(\"scaas.pqvault.v1\");"));
    assert_eq!(
        SCAAS_APP_IDS,
        &[("PqVaultTypes.APP_ID", "scaas.pqvault.v1")]
    );
    assert_eq!(
        scaas_ua::keccak256(SCAAS_APP_IDS[0].1.as_bytes()),
        pqvault::app_id()
    );
}
