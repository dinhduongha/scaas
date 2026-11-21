// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Fable code review of PqVault V1-V8, F5 (controller call 2026-11-21): a second implementation of the key schedule, before the
//! SDK's app-core surface exists. ua-rs's own KEM (`kem.rs`), HKDF, AES-256-GCM and AES-256-GCM-SIV (`aead.rs`), the PQ
//! derivation (`derive.rs`) and the registry digests (`lib.rs`) reproduce smartcontracts/vectors/pqvault/keys.json (KEM keys,
//! wraps, K_v, kInfo, sealedInfo, kPrev and keyWrap), items.json (okm, bk, n, the AAD, the padded plaintext, the ciphertext,
//! kFile and the file key's keyWrap) and records.json's `pqvAccount` and `nativeMember` rows. Each check has a control: one
//! changed byte gives another value.
use scaas_ua::wallet::derive::{ua_key_data, ua_secret};
use scaas_ua::wallet::kem::vectors_encaps;
use scaas_ua::wallet::{aead_open, aead_seal, hkdf_sha256, Alg, KemKeyPair};
use serde_json::Value;

fn load(f: &str) -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/pqvault")
        .join(f);
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn unhex(v: &Value) -> Vec<u8> {
    let s = v.as_str().unwrap().trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn b32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}

fn b12(b: &[u8]) -> [u8; 12] {
    b.try_into().unwrap()
}

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap()
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

fn hkdf(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    hkdf_sha256(ikm, salt, info, len).unwrap().to_vec()
}

const KEYWRAP: &[u8] = b"scaas/ua/v1/keywrap";

/// KEM keys from their 96 seed bytes; every wrap: the encapsulation with the row's `m` and `e`, `kek`, `sealedKey`
/// (AES-256-GCM, nonce 0), and the member's decapsulation back to `K_e`.
#[test]
fn kem_keys_and_wraps() {
    let k = load("keys.json");
    let mut keys = std::collections::HashMap::new();
    for r in k["kemKeys"].as_array().unwrap() {
        let seed: [u8; 96] = cat(&[&unhex(&r["mlkemSeed"]), &unhex(&r["x25519Secret"])])
            .try_into()
            .unwrap();
        let kp = KemKeyPair::vectors_ephemeral(&seed).unwrap();
        assert_eq!(kp.kem_pk(), unhex(&r["kemPk"]), "{}", r["name"]);
        assert_eq!(
            scaas_ua::keccak256(&kp.kem_pk()).to_vec(),
            unhex(&r["kemPkHash"])
        );
        keys.insert(r["name"].as_str().unwrap().to_string(), kp);
    }
    let rows = k["wraps"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    for w in rows {
        let kp = &keys[w["kemKey"].as_str().unwrap()];
        let kem_pk = kp.kem_pk();
        let (ct, big_e, ss) =
            vectors_encaps(&kem_pk, &b32(&w["mlkemM"]), &b32(&w["x25519Secret"])).unwrap();
        assert_eq!(ss.to_vec(), unhex(&w["ss"]), "{}", w["name"]);
        assert_eq!(ct, unhex(&w["wrap"]["mlkemCt"]));
        assert_eq!(big_e.to_vec(), unhex(&w["wrap"]["x25519Eph"]));
        let (vid, eid, member) = (
            unhex(&w["vaultId"]),
            unhex(&w["epochId"]),
            unhex(&w["member"]),
        );
        let key_id = u(&w["keyId"]).to_be_bytes();
        let info = cat(&[
            b"scaas/pqvault/v1/wrap",
            &vid,
            &eid,
            &member,
            &key_id,
            &[1],
            &scaas_ua::keccak256(&kem_pk),
        ]);
        let kek: [u8; 32] = hkdf(&*ss, &[], &info, 32).try_into().unwrap();
        assert_eq!(kek.to_vec(), unhex(&w["kek"]), "{}", w["name"]);
        let aad = cat(&[&vid, &eid, &member, &key_id]);
        let sealed = aead_seal(Alg::Aes256Gcm, &kek, &[0; 12], &aad, &unhex(&w["Ke"])).unwrap();
        assert_eq!(sealed, unhex(&w["sealedKey"]), "{}", w["name"]);
        let back = kp.decaps(&ct, &big_e).unwrap();
        assert_eq!(*back, *ss, "the member decapsulates the same ss");
        let opened = aead_open(Alg::Aes256Gcm, &kek, &[0; 12], &aad, &sealed).unwrap();
        assert_eq!(opened.to_vec(), unhex(&w["Ke"]));
        // control: another keyId in the info gives another kek
        let other = cat(&[
            b"scaas/pqvault/v1/wrap",
            &vid,
            &eid,
            &member,
            &(u(&w["keyId"]) + 1).to_be_bytes(),
            &[1],
        ]);
        assert_ne!(hkdf(&*ss, &[], &other, 32), kek.to_vec());
    }
}

/// Every epoch: `K_v` (with `P_k` or without), `kInfo`, `sealedInfo` opened to the padded JSON and sealed back, and a `prev`'s
/// `kPrev` and `keyWrap` (the key-wrap AAD with the usage byte `Derive` = 1).
#[test]
fn epochs_kv_sealed_info_prev() {
    let k = load("keys.json");
    let epochs = k["epochs"].as_array().unwrap();
    assert_eq!(epochs.len(), 6);
    let kv_of = |name: &str| -> Vec<u8> {
        unhex(&epochs.iter().find(|e| e["name"] == name).unwrap()["Kv"])
    };
    for e in epochs {
        let (vid, eid) = (unhex(&e["vaultId"]), unhex(&e["epochId"]));
        let pass_kdf = u(&e["passKdf"]) as u16;
        let ikm = match &e["Pk"] {
            Value::Null => unhex(&e["Ke"]),
            pk => cat(&[&unhex(&e["Ke"]), &unhex(pk)]),
        };
        let kv = hkdf(
            &ikm,
            &[],
            &cat(&[
                b"scaas/pqvault/v1/vkey",
                &vid,
                &eid,
                &pass_kdf.to_be_bytes(),
            ]),
            32,
        );
        assert_eq!(kv, unhex(&e["Kv"]), "{}", e["name"]);
        let k_info: [u8; 32] = hkdf(&kv, &[], &cat(&[b"scaas/pqvault/v1/info", &vid, &eid]), 32)
            .try_into()
            .unwrap();
        assert_eq!(k_info.to_vec(), unhex(&e["kInfo"]));
        let sealed = unhex(&e["sealedInfo"]);
        let pt = aead_open(
            Alg::Aes256GcmSiv,
            &k_info,
            &b12(&sealed[..12]),
            &[],
            &sealed[12..],
        )
        .unwrap();
        assert_eq!(pt.to_vec(), unhex(&e["pt"]), "{}", e["name"]);
        let json = e["json"].as_str().unwrap().as_bytes();
        assert_eq!(&pt[..4], &(json.len() as u32).to_be_bytes());
        assert_eq!(&pt[4..4 + json.len()], json);
        assert!(
            pt[4 + json.len()..].iter().all(|b| *b == 0) && [1024, 4096, 16384].contains(&pt.len()), // F12: at least the 1,024-B bucket
        );
        let again = aead_seal(
            Alg::Aes256GcmSiv,
            &k_info,
            &b12(&unhex(&e["infoNonce"])),
            &[],
            &pt,
        )
        .unwrap();
        assert_eq!(cat(&[&unhex(&e["infoNonce"]), &again]), sealed);
        if let Some(p) = e["prev"].as_object() {
            let prev_eid = unhex(&p["epochId"]);
            let k_prev: [u8; 32] = hkdf(
                &kv,
                &[],
                &cat(&[b"scaas/pqvault/v1/prev", &vid, &eid, &prev_eid]),
                32,
            )
            .try_into()
            .unwrap();
            assert_eq!(k_prev.to_vec(), unhex(&p["kPrev"]));
            let aad = cat(&[KEYWRAP, &[1], &vid, &eid, &prev_eid]);
            let wrapped = aead_seal(
                Alg::Aes256GcmSiv,
                &k_prev,
                &b12(&unhex(&p["nonce"])),
                &aad,
                &kv_of(p["epoch"].as_str().unwrap()),
            )
            .unwrap();
            assert_eq!(cat(&[&unhex(&p["nonce"]), &wrapped]), unhex(&p["keyWrap"]));
            assert_eq!(unhex(&p["keyWrap"]).len(), 60);
            // control: the usage byte `Data` (2) does not open it
            let data_aad = cat(&[KEYWRAP, &[2], &vid, &eid, &prev_eid]);
            assert!(aead_open(
                Alg::Aes256GcmSiv,
                &k_prev,
                &b12(&unhex(&p["nonce"])),
                &data_aad,
                &wrapped
            )
            .is_err());
        }
    }
}

/// `abi.encode(vaultId, epochId, itemId, uint32 version, author, homeChain, address homeVaultContract)`, 224 bytes.
fn item_aad(r: &Value) -> Vec<u8> {
    let mut v = [0u8; 32];
    v[28..].copy_from_slice(&(u(&r["version"]) as u32).to_be_bytes());
    let mut a = [0u8; 32];
    a[12..].copy_from_slice(&unhex(&r["homeVaultContract"]));
    cat(&[
        &unhex(&r["vaultId"]),
        &unhex(&r["epochId"]),
        &unhex(&r["itemId"]),
        &v,
        &unhex(&r["author"]),
        &unhex(&r["homeChain"]),
        &a,
    ])
}

/// Every item version: `okm` (salt `r`), `bk`, `n`, the AAD, the padded plaintext and the ciphertext; a file item's `kFile`
/// and its key's keyWrap (usage `Data` = 2).
#[test]
fn items_keys_aad_ciphertexts() {
    let v = load("items.json");
    let items = v["items"].as_array().unwrap();
    assert_eq!(items.len(), 15); // F9: + a tombstone per shared vault, the 4,096-B and 16,384-B buckets
    for r in items {
        let (vid, eid, iid) = (
            unhex(&r["vaultId"]),
            unhex(&r["epochId"]),
            unhex(&r["itemId"]),
        );
        let ver = (u(&r["version"]) as u32).to_be_bytes();
        let kv = unhex(&r["Kv"]);
        let info = cat(&[
            b"scaas/pqvault/v1/item",
            &vid,
            &eid,
            &iid,
            &ver,
            &unhex(&r["author"]),
        ]);
        let okm = hkdf(&kv, &unhex(&r["r"]), &info, 44);
        assert_eq!(okm, unhex(&r["okm"]), "{}", r["name"]);
        let bk: [u8; 32] = okm[..32].try_into().unwrap();
        assert_eq!(bk.to_vec(), unhex(&r["bk"]));
        assert_eq!(okm[32..].to_vec(), unhex(&r["n"]));
        let aad = item_aad(r);
        assert_eq!(aad, unhex(&r["aad"]));
        assert_eq!(aad.len(), 224);
        let pt = unhex(&r["pt"]);
        let json = r["json"].as_str().unwrap().as_bytes();
        assert_eq!(&pt[..4], &(json.len() as u32).to_be_bytes());
        assert_eq!(&pt[4..4 + json.len()], json);
        let ct = aead_seal(Alg::Aes256GcmSiv, &bk, &b12(&okm[32..]), &aad, &pt).unwrap();
        assert_eq!(
            cat(&[&unhex(&r["r"]), &ct]),
            unhex(&r["ciphertext"]),
            "{}",
            r["name"]
        );
        // control: another version in the AAD does not open it
        let mut bad = r.clone();
        bad["version"] = Value::from(u(&r["version"]) + 1);
        assert!(aead_open(
            Alg::Aes256GcmSiv,
            &bk,
            &b12(&okm[32..]),
            &item_aad(&bad),
            &ct
        )
        .is_err());
        if let Some(f) = r.get("file") {
            let k_file: [u8; 32] = hkdf(
                &kv,
                &[],
                &cat(&[b"scaas/pqvault/v1/file", &vid, &eid, &iid, &ver]),
                32,
            )
            .try_into()
            .unwrap();
            assert_eq!(k_file.to_vec(), unhex(&f["kFile"]));
            let kw = unhex(&r["content"]["keyWrap"]);
            let aad = cat(&[KEYWRAP, &[2], &vid, &eid, &iid, &ver]);
            let key =
                aead_open(Alg::Aes256GcmSiv, &k_file, &b12(&kw[..12]), &aad, &kw[12..]).unwrap();
            assert_eq!(key.to_vec(), unhex(&f["key"]));
        }
    }
    assert!(items.iter().any(|r| r.get("file").is_some()));
}

/// `PQV_ACCOUNT`: the 24-word seed, `ua_secret(seed, FN-DSA-512, 0x70717600, i)` (`xi`), its key data and UA.
#[test]
fn pqv_account_rows() {
    let rec = load("records.json");
    let d = &rec["pqvAccount"];
    assert_eq!(u(&d["account"]), 0x7071_7600);
    let w = scaas_ua::wallet::Wallet::from_mnemonic(d["mnemonic"].as_str().unwrap(), "").unwrap();
    let seed = unhex(&d["seed"]);
    for r in d["rows"].as_array().unwrap() {
        let (kind, index) = (u(&r["kind"]) as u16, u(&r["index"]) as u32);
        assert_eq!(kind, 0x0132);
        let xi = ua_secret(&seed, kind, 0x7071_7600, index).unwrap();
        assert_eq!(xi.to_vec(), unhex(&r["xi"]), "index {index}");
        assert_eq!(ua_key_data(kind, &xi).unwrap(), unhex(&r["publicKey"]));
        let key = w.ua_key(kind, 0x7071_7600, index).unwrap();
        assert_eq!(key.ua().unwrap().to_vec(), unhex(&r["ua"]));
        assert_ne!(
            ua_secret(&seed, kind, 0x7071_7601, index).unwrap().to_vec(),
            unhex(&r["xi"]),
            "control: another account"
        );
    }
}

/// A native `msig` member: mode 0 signs the record's typed digest itself; mode 1 `UAAuth(member, purpose(member),
/// memberDigest(msig, uaMessage(msig, P_V, typed)))` in the registry's chain-bound domain.
#[test]
fn native_member_digests() {
    let rec = load("records.json");
    let n = &rec["nativeMember"];
    let typed = |name: &str| -> [u8; 32] {
        for v in rec["vaults"].as_array().unwrap() {
            for r in v["records"].as_array().unwrap() {
                if r["name"] == name {
                    return b32(&r["typed"]);
                }
            }
        }
        panic!("{name}")
    };
    assert_eq!(
        b32(&n["mode0"]["digest"]),
        typed(n["mode0"]["record"].as_str().unwrap())
    );
    let p_v = b32(&rec["purpose"]["purpose"]);
    let msig = b32(&n["msig"]);
    let t1 = typed(n["mode1"]["record"].as_str().unwrap());
    let md = scaas_ua::member_digest(&msig, &scaas_ua::ua_message(0x0120, &p_v, &t1).unwrap());
    assert_eq!(md.to_vec(), unhex(&n["mode1"]["memberDigest"]));
    let rd = &n["registryDomain"];
    let dom = scaas_ua::Domain {
        generation: u(&rd["generation"]) as u32,
        chain_id: u(&rd["chainId"]),
        registry: unhex(&rd["registry"]).try_into().unwrap(),
        chain_uid: b32(&rd["chainUid"]),
    };
    let mut id = [0u8; 32];
    id[12..].copy_from_slice(&unhex(&n["address"]));
    let member = scaas_ua::purpose_tag("member").unwrap();
    assert_eq!(
        scaas_ua::ua_auth_digest(&dom, &id, &member, &md).to_vec(),
        unhex(&n["mode1"]["digest"])
    );
    assert_ne!(
        scaas_ua::ua_auth_digest(&dom, &id, &p_v, &md).to_vec(),
        unhex(&n["mode1"]["digest"]),
        "control: purpose"
    );
}
