// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqVault plan V9 (spec §6, §7; CLI-PQV-12): the rows of `smartcontracts/vectors/pqvault/{keys,items,pass}.json` reproduced
//! through the SDK's generic app-core surface only (no `scaas-ua` call, no PqVault name below the test): the KEM wraps and
//! their unwrap, `K_v` from `K_e` and the passphrase's Argon2id (RFC 8265 OpaqueString, then NFC), `sealedInfo`, `prev`'s
//! key wrap (`seal_key` / `open_key`), item versions (HKDF key and nonce from one output, AES-256-GCM-SIV), a `file` item's
//! key sealed under `kFile`, and the usage refusals of spec §6.10. A row's error that is `pqvault-core`'s (a length, the
//! padding, a wrong passphrase, an unknown `passKdf`) is checked as the SDK's answer it rests on.
#![cfg(feature = "vectors")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use scaas_sdk::app_core::{AppCore, AppDesc, AppKey, AppKeyUsage, AppNonce, AppWrap};
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{Limits, RuntimeChoice, Sdk, SdkConfig, SdkError};
use scaas_ua::wallet::SecretBytes;
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
/// PqVault's label prefix: the app core declares it; nothing below the SDK knows it
const PQV: &str = "scaas/pqvault/v1/";
/// set 1 of pass.json (checked below): 64 MiB, 3 passes, parallelism 4
const SET1: (u32, u32, u32) = (65_536, 3, 4);

fn doc(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqvault/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn unhex(v: &Value) -> Vec<u8> {
    let h = v.as_str().unwrap().trim_start_matches("0x");
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}
fn a32(v: &Value) -> [u8; 32] {
    unhex(v).try_into().unwrap()
}
fn a12(v: &Value) -> [u8; 12] {
    unhex(v).try_into().unwrap()
}
fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}
fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}
fn lbl(s: &str) -> Vec<u8> {
    format!("{PQV}{s}").into_bytes()
}
fn row<'a>(v: &'a Value, key: &str, name: &str) -> &'a Value {
    v[key]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap_or_else(|| panic!("{key}/{name}"))
}

/// One live scope declares a prefix at a time (spec §12.3): each test holds this lock.
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn core() -> (Arc<AppCore>, String) {
    let s = Sdk::open(SdkConfig {
        profiles: vec![],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: None,
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = s
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let app_id = format!("0x{}", hex(&unhex(&doc("records")["purpose"]["appId"])));
    let a = AppCore::new(
        s,
        AppDesc {
            app_id: Some(app_id),
            name: "PqVault".into(),
            class: None,
            labels: vec![PQV.into()],
        },
    )
    .unwrap();
    (a, seed)
}
/// `P_k` by the SDK's passphrase Argon2id at set 1, its bytes
async fn pk(a: &Arc<AppCore>, seed: &str, pass: &[u8], salt: Vec<u8>) -> Result<Vec<u8>, SdkError> {
    let h = a
        .argon2id_passphrase(seed.into(), sec(pass), salt, SET1.0, SET1.1, SET1.2)
        .await?;
    a.vectors_reveal(h)
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// `K_v` of an epoch row: `K_e` and `P_k` imported (their own rows check them), HKDF under `vkey`
fn vault_key(a: &AppCore, seed: &str, e: &Value) -> Arc<AppKey> {
    let ke = a
        .vectors_import(seed, a32(&e["Ke"]), AppKeyUsage::Derive)
        .unwrap();
    let pass_kdf = u16::try_from(e["passKdf"].as_u64().unwrap()).unwrap();
    let mut keys = vec![ke];
    if pass_kdf != 0 {
        keys.push(
            a.vectors_import(seed, a32(&e["Pk"]), AppKeyUsage::Derive)
                .unwrap(),
        );
    }
    let ctx = [
        unhex(&e["vaultId"]),
        unhex(&e["epochId"]),
        pass_kdf.to_be_bytes().to_vec(),
    ]
    .concat();
    a.derive(keys, vec![], lbl("vkey"), ctx, AppKeyUsage::Derive, false)
        .unwrap()
}

/// keys.json `wraps`: each wrap rebuilt with its fixed `m` and X25519 secret (the KDF info `label ‖ aad ‖ 0x01 ‖
/// keccak256(kemPk)` built by the SDK, spec §6.2), and unwrapped by the member's KEM key back to `K_e`.
#[tokio::test(flavor = "multi_thread")]
async fn wraps_and_unwraps() {
    let _one = ONE.lock().await;
    let (a, seed) = core().await;
    let k = doc("keys");
    let rows = k["wraps"].as_array().unwrap();
    assert_eq!(rows.len(), 12);
    for w in rows {
        let kem = row(&k, "kemKeys", w["kemKey"].as_str().unwrap());
        let ke = a
            .vectors_import(&seed, a32(&w["Ke"]), AppKeyUsage::Derive)
            .unwrap();
        let aad = [
            unhex(&w["vaultId"]),
            unhex(&w["epochId"]),
            unhex(&w["member"]),
            w["keyId"].as_u64().unwrap().to_be_bytes().to_vec(),
        ]
        .concat();
        let got = a
            .vectors_kem_wrap(
                ke,
                unhex(&kem["kemPk"]),
                lbl("wrap"),
                aad.clone(),
                a32(&w["mlkemM"]),
                a32(&w["x25519Secret"]),
            )
            .unwrap();
        let want = AppWrap {
            mlkem_ct: unhex(&w["wrap"]["mlkemCt"]),
            x25519_eph: unhex(&w["wrap"]["x25519Eph"]),
            sealed_key: unhex(&w["wrap"]["sealedKey"]),
        };
        assert_eq!(got, want, "{}", w["name"]);
        let kem_seed = [unhex(&kem["mlkemSeed"]), unhex(&kem["x25519Secret"])].concat();
        let back = a
            .vectors_kem_unwrap(
                &seed,
                kem_seed.clone(),
                want.clone(),
                lbl("wrap"),
                aad.clone(),
                AppKeyUsage::Derive,
            )
            .unwrap();
        assert_eq!(a.vectors_reveal(back).unwrap(), unhex(&w["Ke"]));
        // one change: the wrap's AAD names another key id
        let mut other = aad.clone();
        *other.last_mut().unwrap() ^= 1;
        assert_eq!(
            code(a.vectors_kem_unwrap(
                &seed,
                kem_seed,
                want,
                lbl("wrap"),
                other,
                AppKeyUsage::Derive
            )),
            "Aead"
        );
    }
    // outside the declared prefix: refused before any KEM work
    let ke = a
        .vectors_import(&seed, a32(&rows[0]["Ke"]), AppKeyUsage::Derive)
        .unwrap();
    let kem = row(&k, "kemKeys", rows[0]["kemKey"].as_str().unwrap());
    assert_eq!(
        code(a.vectors_kem_wrap(
            ke,
            unhex(&kem["kemPk"]),
            b"scaas/other/v1/wrap".to_vec(),
            vec![],
            [1; 32],
            [2; 32]
        )),
        "AppLabelRefused"
    );
}

/// pass.json: set 1 pinned; every `P_k` row and every normalization row (NFC and NFD give one `P_k`; the refusals) by
/// the SDK's passphrase Argon2id; the wrong passphrase's `P_k` differs.
#[tokio::test(flavor = "multi_thread")]
async fn passphrase_rows() {
    let _one = ONE.lock().await;
    let (a, seed) = core().await;
    let p = doc("pass");
    let s = &p["sets"]["1"];
    assert_eq!(
        (
            s["m"].as_u64(),
            s["t"].as_u64(),
            s["p"].as_u64(),
            s["dkLen"].as_u64()
        ),
        (Some(65_536), Some(3), Some(4), Some(32))
    );
    for r in p["rows"].as_array().unwrap() {
        let got = pk(
            &a,
            &seed,
            r["passphrase"].as_str().unwrap().as_bytes(),
            unhex(&r["passSalt"]),
        )
        .await
        .unwrap();
        assert_eq!(got, unhex(&r["Pk"]), "{}", r["name"]);
    }
    let n = &p["normalization"];
    let salt = unhex(&n["passSalt"]);
    for r in n["rows"].as_array().unwrap() {
        let nfd = r["nfd"].as_str().unwrap();
        assert_eq!(nfd.as_bytes(), unhex(&r["nfdUtf8"]).as_slice());
        // the NFD form gives the row's P_k (the NFC form's), not the raw NFD bytes' Argon2id
        let got = pk(&a, &seed, nfd.as_bytes(), salt.clone()).await.unwrap();
        assert_eq!(got, unhex(&r["Pk"]), "{}", r["name"]);
        assert_ne!(got, unhex(&r["rawNfdArgon2"]), "{}", r["name"]);
        let plain = a
            .argon2id(
                seed.clone(),
                sec(nfd.as_bytes()),
                salt.clone(),
                SET1.0,
                SET1.1,
                SET1.2,
            )
            .await
            .unwrap();
        assert_eq!(a.vectors_reveal(plain).unwrap(), unhex(&r["rawNfdArgon2"]));
    }
    // PassphraseInvalid rows: the SDK refuses them (`Argument`), each beside a valid twin
    for r in n["refusals"].as_array().unwrap() {
        let input = r["input"].as_str().unwrap();
        assert_eq!(
            code(pk(&a, &seed, input.as_bytes(), salt.clone()).await),
            "Argument",
            "{}",
            r["name"]
        );
    }
    assert_eq!(
        code(pk(&a, &seed, b"two lines here", salt.clone()).await),
        "Ok"
    );
    assert_eq!(
        code(pk(&a, &seed, &[0xff, 0x61], salt.clone()).await),
        "Argument"
    );
    // the wrong passphrase: its own P_k, other than the epoch's
    let w = p["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["error"] == "PassphraseWrong")
        .unwrap();
    let right = row(&p, "rows", w["epoch"].as_str().unwrap());
    let got = pk(
        &a,
        &seed,
        w["passphrase"].as_str().unwrap().as_bytes(),
        unhex(&right["passSalt"]),
    )
    .await
    .unwrap();
    assert_eq!(got, unhex(&w["Pk"]));
    assert_ne!(got, unhex(&right["Pk"]));
}

/// keys.json `epochs` and `refusals`: `K_v`, `kInfo`, `sealedInfo` (fixed nonce, then opened), `prev`'s `kPrev` and its
/// 60-B key wrap (fixed nonce, then opened back into a `Derive` handle equal to the earlier `K_v`).
#[tokio::test(flavor = "multi_thread")]
async fn epochs_info_and_prev() {
    let _one = ONE.lock().await;
    let (a, seed) = core().await;
    let k = doc("keys");
    let epochs = k["epochs"].as_array().unwrap();
    assert_eq!(epochs.len(), 6);
    for e in epochs {
        let kv = vault_key(&a, &seed, e);
        assert_eq!(
            a.vectors_reveal(kv.clone()).unwrap(),
            unhex(&e["Kv"]),
            "{}",
            e["name"]
        );
        let ids = [unhex(&e["vaultId"]), unhex(&e["epochId"])].concat();
        let kinfo = a
            .derive(
                vec![kv.clone()],
                vec![],
                lbl("info"),
                ids.clone(),
                AppKeyUsage::Data,
                false,
            )
            .unwrap();
        assert_eq!(a.vectors_reveal(kinfo.clone()).unwrap(), unhex(&e["kInfo"]));
        let ct = a
            .vectors_seal(kinfo.clone(), a12(&e["infoNonce"]), vec![], unhex(&e["pt"]))
            .unwrap();
        assert_eq!(
            [unhex(&e["infoNonce"]), ct].concat(),
            unhex(&e["sealedInfo"])
        );
        let pt = a
            .open(
                kinfo.clone(),
                AppNonce::Random,
                vec![],
                unhex(&e["sealedInfo"]),
            )
            .unwrap();
        assert_eq!(pt.with(|b| b.to_vec()), unhex(&e["pt"]));
        if e["prev"].is_null() {
            continue;
        }
        let pv = &e["prev"];
        let prev_e = row(&k, "epochs", pv["epoch"].as_str().unwrap());
        let kv_prev = vault_key(&a, &seed, prev_e);
        let ctx = [ids.clone(), unhex(&pv["epochId"])].concat();
        let kprev = a
            .derive(
                vec![kv.clone()],
                vec![],
                lbl("prev"),
                ctx.clone(),
                AppKeyUsage::KeyWrap,
                false,
            )
            .unwrap();
        assert_eq!(
            a.vectors_reveal(kprev.clone()).unwrap(),
            unhex(&pv["kPrev"])
        );
        let wire = a
            .vectors_seal_key(
                kprev.clone(),
                kv_prev.clone(),
                a12(&pv["nonce"]),
                ctx.clone(),
            )
            .unwrap();
        assert_eq!(wire, unhex(&pv["keyWrap"]));
        let back = a
            .open_key(kprev.clone(), wire, AppKeyUsage::Derive, ctx.clone())
            .unwrap();
        assert!(a.same_key(back, kv_prev).unwrap());
        // the sealedInfo's JSON names the same key wrap
        let info: Value = serde_json::from_str(e["json"].as_str().unwrap()).unwrap();
        assert_eq!(info["prev"]["keyWrap"], pv["keyWrap"]);
    }
    // refusals: a wrong prev key opens and then fails the named epoch's sealedInfo; a key wrap under another K_v fails
    let r0 = &k["refusals"][0];
    let e1 = row(&k, "epochs", r0["epoch"].as_str().unwrap());
    let kv1 = vault_key(&a, &seed, e1);
    let ctx = [
        unhex(&e1["vaultId"]),
        unhex(&e1["epochId"]),
        unhex(&r0["prevEpochId"]),
    ]
    .concat();
    let kprev = a
        .derive(
            vec![kv1.clone()],
            vec![],
            lbl("prev"),
            ctx.clone(),
            AppKeyUsage::KeyWrap,
            false,
        )
        .unwrap();
    let wrong = a
        .open_key(
            kprev,
            unhex(&r0["keyWrap"]),
            AppKeyUsage::Derive,
            ctx.clone(),
        )
        .unwrap();
    assert_eq!(
        a.vectors_reveal(wrong.clone()).unwrap(),
        unhex(&r0["wrongKv"])
    );
    let e0 = row(&k, "epochs", r0["prevEpoch"].as_str().unwrap());
    let ids0 = [unhex(&e0["vaultId"]), unhex(&e0["epochId"])].concat();
    let kinfo0 = a
        .derive(
            vec![wrong],
            vec![],
            lbl("info"),
            ids0,
            AppKeyUsage::Data,
            false,
        )
        .unwrap();
    assert_eq!(
        code(a.open(kinfo0, AppNonce::Random, vec![], unhex(&e0["sealedInfo"]))),
        "Aead"
    );
    let r1 = &k["refusals"][1];
    let other = a
        .vectors_import(&seed, a32(&r1["Kv"]), AppKeyUsage::Derive)
        .unwrap();
    let pv = &e1["prev"];
    let ctx = [
        unhex(&e1["vaultId"]),
        unhex(&e1["epochId"]),
        unhex(&pv["epochId"]),
    ]
    .concat();
    let kprev = a
        .derive(
            vec![other],
            vec![],
            lbl("prev"),
            ctx.clone(),
            AppKeyUsage::KeyWrap,
            false,
        )
        .unwrap();
    assert_eq!(
        code(a.open_key(kprev, unhex(&pv["keyWrap"]), AppKeyUsage::Derive, ctx)),
        "Aead"
    );
}

/// keys.json `usages` (spec §6.10): each refusal by name, beside the call that succeeds.
#[tokio::test(flavor = "multi_thread")]
async fn usage_refusals() {
    let _one = ONE.lock().await;
    let (a, seed) = core().await;
    let k = doc("keys");
    let e1 = row(&k, "epochs", "shared0/epoch-1");
    let pv = &e1["prev"];
    let kv = vault_key(&a, &seed, e1);
    let ctx = [
        unhex(&e1["vaultId"]),
        unhex(&e1["epochId"]),
        unhex(&pv["epochId"]),
    ]
    .concat();
    let kprev = a
        .derive(
            vec![kv.clone()],
            vec![],
            lbl("prev"),
            ctx.clone(),
            AppKeyUsage::KeyWrap,
            false,
        )
        .unwrap();
    let wire = unhex(&pv["keyWrap"]);
    let data = a
        .vectors_import(&seed, a32(&pv["kPrev"]), AppKeyUsage::Data)
        .unwrap();
    let want: Vec<(&str, &str)> = k["usages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| (u["name"].as_str().unwrap(), u["error"].as_str().unwrap()))
        .collect();
    let got = [
        code(a.open(kprev.clone(), AppNonce::Random, ctx.clone(), wire.clone())),
        code(a.open(kv.clone(), AppNonce::Random, vec![], wire.clone())),
        code(a.seal(kv.clone(), AppNonce::Random, vec![], b"x".to_vec())),
        code(a.open_key(data.clone(), wire.clone(), AppKeyUsage::Derive, ctx.clone())),
        code(a.derive(
            vec![data.clone()],
            vec![],
            lbl("info"),
            vec![],
            AppKeyUsage::Data,
            false,
        )),
        code(a.open(data.clone(), AppNonce::Random, ctx.clone(), wire.clone())),
        code(a.seal(
            data.clone(),
            AppNonce::Random,
            [b"scaas/ua/v1/keywrap".to_vec(), vec![1]].concat(),
            b"x".to_vec(),
        )),
    ];
    for (i, g) in got.iter().enumerate() {
        assert_eq!(*g, sdk_code(want[i].1), "{}", want[i].0);
    }
    // the twins: each handle in its own usage succeeds
    assert_eq!(
        code(a.open_key(kprev.clone(), wire, AppKeyUsage::Derive, ctx.clone())),
        "Ok"
    );
    assert_eq!(
        code(a.seal(data.clone(), AppNonce::Random, ctx.clone(), b"x".to_vec())),
        "Ok"
    );
    assert_eq!(
        code(a.derive(
            vec![kv],
            vec![],
            lbl("info"),
            vec![],
            AppKeyUsage::Data,
            false
        )),
        "Ok"
    );
    // a seal output under kPrev's bytes as Data does not open as a key wrap
    let u = &k["usages"][7];
    let sealed = [
        unhex(&u["sealOutput"])[..12].to_vec(),
        a.vectors_seal(
            data.clone(),
            unhex(&u["sealOutput"])[..12].try_into().unwrap(),
            unhex(&u["ctx"]),
            unhex(&u["plaintext"]),
        )
        .unwrap(),
    ]
    .concat();
    assert_eq!(sealed, unhex(&u["sealOutput"]));
    assert_eq!(
        code(a.open_key(kprev, sealed, AppKeyUsage::Derive, unhex(&u["ctx"]))),
        sdk_code(u["error"].as_str().unwrap())
    );
}

/// items.json: every item version (`okm`'s key and nonce from one HKDF, the AES-256-GCM-SIV ciphertext after `r`, opened
/// back), each `file` item's key sealed under `kFile` (usage `Data` in the AAD), and the refusal rows against the base item.
#[tokio::test(flavor = "multi_thread")]
async fn item_versions() {
    let _one = ONE.lock().await;
    let (a, seed) = core().await;
    let it = doc("items");
    let items = it["items"].as_array().unwrap();
    // 15 + the item layer's 4 rows (CLI-PQV-16 H1-H3: card, identity, a hidden note, custom fields with history)
    // + the Arweave `file` row (C14, owner 2026-11-28)
    assert_eq!(items.len(), 20);
    let ids = |x: &Value| {
        [
            unhex(&x["vaultId"]),
            unhex(&x["epochId"]),
            unhex(&x["itemId"]),
            u32::try_from(x["version"].as_u64().unwrap())
                .unwrap()
                .to_be_bytes()
                .to_vec(),
        ]
        .concat()
    };
    let bk_of = |x: &Value| {
        let kv = a
            .vectors_import(&seed, a32(&x["Kv"]), AppKeyUsage::Derive)
            .unwrap();
        a.derive(
            vec![kv],
            unhex(&x["r"]),
            lbl("item"),
            [ids(x), unhex(&x["author"])].concat(),
            AppKeyUsage::Data,
            true,
        )
        .unwrap()
    };
    let mut files = 0;
    for x in items {
        let bk = bk_of(x);
        assert_eq!(
            a.vectors_reveal(bk.clone()).unwrap(),
            unhex(&x["bk"]),
            "{}",
            x["name"]
        );
        let ct = a
            .seal(
                bk.clone(),
                AppNonce::FromKey,
                unhex(&x["aad"]),
                unhex(&x["pt"]),
            )
            .unwrap();
        assert_eq!(
            [unhex(&x["r"]), ct.clone()].concat(),
            unhex(&x["ciphertext"]),
            "{}",
            x["name"]
        );
        let pt = a.open(bk, AppNonce::FromKey, unhex(&x["aad"]), ct).unwrap();
        assert_eq!(pt.with(|b| b.to_vec()), unhex(&x["pt"]));
        if x["file"].is_null() {
            continue;
        }
        files += 1;
        let kv = a
            .vectors_import(&seed, a32(&x["Kv"]), AppKeyUsage::Derive)
            .unwrap();
        let kfile = a
            .derive(
                vec![kv],
                vec![],
                lbl("file"),
                ids(x),
                AppKeyUsage::KeyWrap,
                false,
            )
            .unwrap();
        assert_eq!(
            a.vectors_reveal(kfile.clone()).unwrap(),
            unhex(&x["file"]["kFile"])
        );
        let wire = unhex(&x["content"]["keyWrap"]);
        // the key's usage: `File` (4) for an Arweave file (C14), else the earlier `Data` (2)
        let usage = if x["file"]["usage"] == 4 {
            AppKeyUsage::File
        } else {
            AppKeyUsage::Data
        };
        let fk = a
            .vectors_import(&seed, a32(&x["file"]["key"]), usage)
            .unwrap();
        let again = a
            .vectors_seal_key(
                kfile.clone(),
                fk.clone(),
                wire[..12].try_into().unwrap(),
                ids(x),
            )
            .unwrap();
        assert_eq!(again, wire, "{}", x["name"]);
        let back = a.open_key(kfile, wire, usage, ids(x)).unwrap();
        assert!(a.same_key(back, fk.clone()).unwrap());
        // an Arweave row's file: the wrapped key opens the object its `ctSha256` names (review F-7)
        if let Some(file) = x["file"].get("file") {
            let c = &x["content"];
            let obj = object_of(&a32(&x["file"]["key"]), &unhex(file));
            let pt = a
                .open_file(
                    fk,
                    obj,
                    c["size"].as_u64().unwrap(),
                    unhex(&c["sha256"]),
                    unhex(&c["ctSha256"]),
                )
                .unwrap();
            assert_eq!(pt.with(|b| b.to_vec()), unhex(file), "{}", x["name"]);
        }
    }
    assert_eq!(files, 3);
    // refusals against the base item, one change each: a length outside 32..=16,416 B never reaches the SDK
    // (pqvault-core's CiphertextLength); a non-zero padding byte opens (pqvault-core's unpad refuses it); an AAD word
    // changed, or the key of another epoch, fails the tag; the base itself opens
    let r = &it["refusals"];
    let base = row(&it, "items", r["base"].as_str().unwrap());
    let base_ct = unhex(&base["ciphertext"])[16..].to_vec();
    let fields = [
        "vaultId",
        "epochId",
        "itemId",
        "version",
        "author",
        "homeChain",
        "homeVaultContract",
    ];
    assert_eq!(
        code(a.open(
            bk_of(base),
            AppNonce::FromKey,
            unhex(&base["aad"]),
            base_ct.clone()
        )),
        "Ok"
    );
    for x in r["rows"].as_array().unwrap() {
        let name = x["name"].as_str().unwrap();
        match x["error"].as_str().unwrap() {
            "CiphertextLength" => {
                let n = unhex(&x["ciphertext"]).len();
                assert!(!(32..=16_416).contains(&n), "{name}");
            }
            "Padding" => {
                let ct = unhex(&x["ciphertext"])[16..].to_vec();
                let pt = a
                    .open(bk_of(base), AppNonce::FromKey, unhex(&base["aad"]), ct)
                    .unwrap()
                    .with(|b| b.to_vec());
                let len = u32::from_be_bytes(pt[..4].try_into().unwrap()) as usize;
                assert!(pt[4 + len..].iter().any(|b| *b != 0), "{name}");
            }
            e => {
                let mut aad = unhex(&base["aad"]);
                let mut key_of = base.clone();
                if let Some(o) = x["aad"].as_object() {
                    let (f, v) = o.iter().next().unwrap();
                    let i = fields.iter().position(|g| g == f).unwrap();
                    let mut w = [0u8; 32];
                    match v.as_u64() {
                        Some(n) => w[24..].copy_from_slice(&n.to_be_bytes()),
                        None => {
                            let b = unhex(v);
                            w[32 - b.len()..].copy_from_slice(&b);
                        }
                    }
                    aad[32 * i..32 * (i + 1)].copy_from_slice(&w);
                } else {
                    key_of["Kv"] = x["Kv"].clone();
                }
                let got = a.open(bk_of(&key_of), AppNonce::FromKey, aad, base_ct.clone());
                assert_eq!(code(got), sdk_code(e), "{name}");
            }
        }
    }
}

/// A vector's error name as the SDK's code: `KeyWrapAad` (a seal whose AAD leads with the key-wrap label) is the SDK's
/// `AppKeyUsage`, `AeadOpen` its `Aead`.
fn sdk_code(e: &str) -> &str {
    match e {
        "KeyWrapAad" => "AppKeyUsage",
        "AeadOpen" => "Aead",
        x => x,
    }
}

/// The object of `file` under `key` (CLI-UAL-65): `size` (8 B, big-endian) ‖ file ‖ zeros to its bucket, AES-256-GCM, nonce 0.
fn object_of(key: &[u8; 32], file: &[u8]) -> Vec<u8> {
    let b = scaas_ua::file::bucket(file.len() as u64, scaas_ua::file::CAP).unwrap() as usize;
    let mut frame = vec![0u8; b];
    frame[..8].copy_from_slice(&(file.len() as u64).to_be_bytes());
    frame[8..8 + file.len()].copy_from_slice(file);
    scaas_ua::wallet::aead_seal(scaas_ua::wallet::Alg::Aes256Gcm, key, &[0; 12], &[], &frame)
        .unwrap()
}
