// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `smartcontracts/vectors/pqvault/` through `pqvault-core` (plan V10; CLI-PQV-09): every record's typed digest as the SDK's
//! PqVault signing call computes it over `pqvault-core`'s typed JSON, in both domains; ids, scopes, wrap hashes and
//! `sigHash`; the key schedule of `keys.rs` (the vectors' `K_e` and `P_k` imported through the SDK's test entries, every
//! derived key compared in `scaas-ua`); `sealedInfo`, `prev`, items and their refusals. No `scaas-ua` call here.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "../../scaas-sdk/tests/common/prepared.rs"]
mod prepared;
use pqvault_core::content;
use pqvault_core::keys::{self, ItemAt};
use pqvault_core::records::*;
use pqvault_core::{Error, Item, PqVault};
use prepared::SignPrepared as _;
use scaas_sdk::app_core::{AppCore, AppKey, AppKeyUsage, AppPath, SecretBytes};
use scaas_sdk::op::KeyRef;
use scaas_sdk::vault::{ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasRows, Limits, RuntimeChoice, Sdk, SdkConfig,
};
use serde_json::Value;
use std::sync::Arc;
use zeroize::Zeroizing;

pub const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn doc(f: &str) -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/pqvault/{f}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn ub(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap(), 1 << 20).unwrap()
}
fn b32(v: &Value) -> B32 {
    B32(ub(v).try_into().unwrap())
}
fn addr(v: &Value) -> Addr {
    Addr(ub(v).try_into().unwrap())
}
fn sec(b: &[u8]) -> Arc<SecretBytes> {
    let s = SecretBytes::new(b.len()).unwrap();
    s.with_mut(|m| m.copy_from_slice(b));
    Arc::new(s)
}

/// One live PqVault scope at a time (spec §12.3): each test holds this lock.
static ONE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// An SDK with the repository seed imported, a profile `local` of chain 31337 (no factory: no read on the chain-bound
/// signing path), PqVault's scope.
async fn setup() -> (Arc<Sdk>, Arc<AppCore>, String) {
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(31337),
        chain_uid: format!("0x{}", "11".repeat(32)),
        rpc: vec![EndpointConfig {
            url: "http://127.0.0.1:9".into(),
            class: scaas_rpc::Class::Named,
            label: None,
            auth: None,
        }],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: vec![],
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Depth(0),
        tx_gas_cap: None,
        tokens: vec![],
        gas: GasRows::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![],
        wrappers: vec![],
        l1_fee: None,
        pinned_reads: true,
        disabled_kinds: vec![],
        family_params: None,
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
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
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec("river-otter-7 ünï".as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let core = PqVault::scope(&sdk).unwrap();
    (sdk, core, seed)
}

fn imp(a: &AppCore, seed: &str, v: &Value, u: AppKeyUsage) -> Arc<AppKey> {
    a.vectors_import(seed, ub(v).try_into().unwrap(), u)
        .unwrap()
}

fn parse<R: serde::de::DeserializeOwned>(v: &Value) -> R {
    serde_json::from_value(v.clone()).unwrap()
}

async fn digest<R: Record>(a: &Arc<AppCore>, seed: &str, r: &R, d: Domain) -> String {
    let key = KeyRef::Ua {
        seed: seed.into(),
        kind: pqvault_core::FNDSA512,
        account: 0,
        index: 0,
    };
    let path = match d {
        Domain::Portable => AppPath::Portable,
        Domain::ChainBound { .. } => AppPath::ChainBound {
            chain: "local".into(),
            purpose: None,
        },
    };
    a.sign_pqvault_record(key, path, None, typed_json(r, d).unwrap())
        .await
        .unwrap()
        .digest
}

/// records.json: each record parsed into `pqvault-core`'s struct, written back to the same JSON, its typed digest (the SDK
/// over our typed JSON) the row's `typed`, its id and scope recomputed, its `sigHash`; the two `vaultId`s of one creator and
/// nonce in modes 0 and 1; a flipped mode gives another digest.
#[tokio::test(flavor = "multi_thread")]
async fn records_ids_scopes_and_digests() {
    let _one = ONE.lock().await;
    let (_sdk, a, seed) = setup().await;
    let d = doc("records");
    let b = &d["domains"]["B"];
    assert_eq!(
        hex(&pqvault_core::app_id()),
        d["purpose"]["appId"].as_str().unwrap()
    );
    let mut n = 0;
    // every vault's records, then CTR-PQV-18's `createTreeKem` (groupMode 1 in mode 0; `verify` refuses it: tests/core.rs)
    let tk = serde_json::json!({"mode": 0, "vaultId": d["createTreeKem"]["id"], "records": [d["createTreeKem"].clone()]});
    for v in d["vaults"].as_array().unwrap().iter().chain([&tk]) {
        let mode = v["mode"].as_u64().unwrap();
        let dom = if mode == 0 {
            Domain::Portable
        } else {
            Domain::ChainBound {
                chain_id: b["chainId"].as_u64().unwrap(),
                instance: addr(&b["verifyingContract"]),
            }
        };
        let vid = b32(&v["vaultId"]);
        for r in v["records"].as_array().unwrap() {
            let rec = &r["record"];
            let name = r["name"].as_str().unwrap();
            let (got, id, scope) = match r["struct"].as_str().unwrap() {
                "PqVaultCreate" => {
                    let x: VaultCreate = parse(rec);
                    assert_eq!(
                        serde_json::to_value(&x).unwrap()["nonce"],
                        rec["nonce"].to_string()
                    );
                    let id = vault_id(
                        x.creator,
                        x.nonce.0,
                        mode as u8,
                        x.home_chain,
                        x.home_vault_contract,
                    );
                    assert_eq!(id, vid, "{name}");
                    (
                        digest(&a, &seed, &x, dom).await,
                        Some(id),
                        scope_vault(x.creator),
                    )
                }
                "PqVaultEpoch" => {
                    let x: VaultEpoch = parse(rec);
                    let id = epoch_id(x.vault_id, x.author, x.nonce.0);
                    (
                        digest(&a, &seed, &x, dom).await,
                        Some(id),
                        scope_epoch(x.vault_id, x.author),
                    )
                }
                "PqVaultLeave" => {
                    let x: VaultLeave = parse(rec);
                    (
                        digest(&a, &seed, &x, dom).await,
                        None,
                        scope_epoch(x.vault_id, x.member),
                    )
                }
                "PqVaultRemove" => {
                    let x: VaultRemove = parse(rec);
                    (
                        digest(&a, &seed, &x, dom).await,
                        None,
                        scope_epoch(x.vault_id, x.admin),
                    )
                }
                "PqVaultItem" => {
                    let x: ItemRecord = parse(rec);
                    let id = item_id(x.vault_id, x.author, x.nonce.0);
                    (
                        digest(&a, &seed, &x, dom).await,
                        Some(id),
                        scope_item(x.vault_id, x.author),
                    )
                }
                "PqVaultEdit" => {
                    let x: EditRecord = parse(rec);
                    (
                        digest(&a, &seed, &x, dom).await,
                        None,
                        scope_item(vid, x.author),
                    )
                }
                "PqVaultBatch" => {
                    let x: BatchRecord = parse(rec);
                    let id = batch_id(x.vault_id, x.author, x.nonce.0);
                    for (i, it) in x.items.iter().enumerate() {
                        assert_eq!(
                            item_id(vid, x.author, it.nonce.0),
                            b32(&r["itemIds"][i]),
                            "{name}"
                        );
                    }
                    (
                        digest(&a, &seed, &x, dom).await,
                        Some(id),
                        scope_item(x.vault_id, x.author),
                    )
                }
                s => panic!("{s}"),
            };
            assert_eq!(got, r["typed"].as_str().unwrap(), "{name}");
            if let Some(id) = id {
                assert_eq!(
                    Some(id),
                    r.get("id").or(r.get("batchId")).map(b32),
                    "{name}"
                );
            }
            assert_eq!(scope, b32(&r["scope"]), "{name}");
            let sig = sig_of(&serde_json::json!({
                "keyData": r["uaSig"]["keyData"], "signature": r["uaSig"]["signature"], "members": r["uaSig"]["members"]
            }))
            .unwrap();
            assert_eq!(sig_hash(&sig), b32(&r["sigHash"]), "{name}");
            n += 1;
        }
    }
    assert_eq!(n, 24);
    let m = &d["modes"];
    let ids: Vec<B32> = m["sameCreatorNonce"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            let id = vault_id(
                b32(&m["creator"]),
                m["nonce"].as_u64().unwrap(),
                x["mode"].as_u64().unwrap() as u8,
                b32(&x["homeChain"]),
                addr(&x["homeVaultContract"]),
            );
            assert_eq!(id, b32(&x["vaultId"]));
            id
        })
        .collect();
    assert_ne!(ids[0], ids[1]);
    // the msig blob's sigHash: an msig's members in the UASig
    let mb = &d["extra"]["msigBlob"];
    assert_eq!(
        sig_hash(&sig_of(&mb["uaSig"]).unwrap()),
        b32(&mb["sigHash"])
    );
    let big = &d["extra"]["bigNonce"];
    let x: Num = parse(&big["nonce"]);
    assert_eq!(
        vault_id(
            b32(&big["creator"]),
            x.0,
            0,
            b32(&big["homeChain"]),
            addr(&big["homeVaultContract"])
        ),
        b32(&big["vaultId"])
    );
}

/// keys.json: every wrap's hash; `K_v` from the vectors' `K_e` and `P_k` by `keys::vault_key`; `sealedInfo` opened by
/// `keys::open_info` into the row's JSON and a fresh one sealed by `keys::seal_info` opening back; `prev` opened by
/// `keys::open_prev` into the earlier `K_v`, and `keys::seal_prev` opening back; a key wrap under another `K_v` refused.
#[tokio::test(flavor = "multi_thread")]
async fn key_schedule() {
    let _one = ONE.lock().await;
    let (_sdk, a, seed) = setup().await;
    let k = doc("keys");
    for w in k["wraps"].as_array().unwrap() {
        let x: Wrap = parse(&w["wrap"]);
        assert_eq!(wrap_hash(&x), b32(&w["hashStruct"]), "{}", w["name"]);
    }
    let kv_of = |e: &Value| {
        let pk = (e["passKdf"].as_u64().unwrap() != 0)
            .then(|| imp(&a, &seed, &e["Pk"], AppKeyUsage::Derive));
        let ke = imp(&a, &seed, &e["Ke"], AppKeyUsage::Derive);
        keys::vault_key(
            &a,
            ke,
            pk,
            b32(&e["vaultId"]),
            b32(&e["epochId"]),
            e["passKdf"].as_u64().unwrap() as u16,
        )
        .unwrap()
    };
    let epochs = k["epochs"].as_array().unwrap();
    for e in epochs {
        let (vid, eid) = (b32(&e["vaultId"]), b32(&e["epochId"]));
        let kv = kv_of(e);
        assert_eq!(
            a.vectors_reveal(kv.clone()).unwrap(),
            ub(&e["Kv"]),
            "{}",
            e["name"]
        );
        let info = keys::open_info(&a, &kv, vid, eid, &ub(&e["sealedInfo"])).unwrap();
        assert_eq!(
            content::canonical(&info).unwrap(),
            e["json"].as_str().unwrap()
        );
        assert_eq!(
            &content::pad_info(e["json"].as_str().unwrap().as_bytes()).unwrap()[..],
            &ub(&e["pt"])[..]
        );
        let again = keys::seal_info(&a, &kv, vid, eid, &info).unwrap();
        assert_eq!(again.len(), ub(&e["sealedInfo"]).len());
        assert_eq!(
            keys::open_info(&a, &kv, vid, eid, &again),
            Some(info.clone())
        );
        // one change: another epoch's id
        assert_eq!(keys::open_info(&a, &kv, vid, B32([0x77; 32]), &again), None);
        if e["prev"].is_null() {
            continue;
        }
        let pv = &e["prev"];
        let pe = epochs.iter().find(|x| x["name"] == pv["epoch"]).unwrap();
        let pid = b32(&pv["epochId"]);
        let back = keys::open_prev(&a, &kv, vid, eid, pid, &ub(&pv["keyWrap"])).unwrap();
        assert!(a.same_key(back, kv_of(pe)).unwrap());
        let wire = keys::seal_prev(&a, &kv, vid, eid, pid, kv_of(pe)).unwrap();
        assert_eq!(wire.len(), 60);
        let back = keys::open_prev(&a, &kv, vid, eid, pid, &wire).unwrap();
        assert!(a.same_key(back, kv_of(pe)).unwrap());
        // the wrap under another epoch's K_v does not open
        assert!(keys::open_prev(&a, &kv_of(pe), vid, eid, pid, &wire).is_none());
    }
    let r1 = &k["refusals"][1];
    let e1 = epochs
        .iter()
        .find(|x| x["name"] == "shared0/epoch-1")
        .unwrap();
    let other = imp(&a, &seed, &r1["Kv"], AppKeyUsage::Derive);
    assert!(keys::open_prev(
        &a,
        &other,
        b32(&e1["vaultId"]),
        b32(&e1["epochId"]),
        b32(&e1["prev"]["epochId"]),
        &ub(&e1["prev"]["keyWrap"])
    )
    .is_none());
}

/// items.json: each version opened by `keys::decrypt_item` into its content, typed by the item layer (CLI-PQV-16 H1); the
/// generator's canonical bytes read by `Item::from_canonical` and written back by `Item::plaintext` byte for byte (the stored
/// format unchanged by the typed layer); its AAD `item_aad`; a fresh encryption opening back; a file item's key opening under `kFile`; every refusal row
/// the one `Unreadable`, beside the base that opens.
#[tokio::test(flavor = "multi_thread")]
async fn item_versions_and_refusals() {
    let _one = ONE.lock().await;
    let (_sdk, a, seed) = setup().await;
    let it = doc("items");
    let at = |x: &Value| ItemAt {
        vault: b32(&x["vaultId"]),
        epoch: b32(&x["epochId"]),
        item: b32(&x["itemId"]),
        version: x["version"].as_u64().unwrap() as u32,
        author: b32(&x["author"]),
        home_chain: b32(&x["homeChain"]),
        home: addr(&x["homeVaultContract"]),
    };
    for x in it["items"].as_array().unwrap() {
        let name = x["name"].as_str().unwrap();
        let kv = imp(&a, &seed, &x["Kv"], AppKeyUsage::Derive);
        let p = at(x);
        assert_eq!(
            item_aad(
                p.vault,
                p.epoch,
                p.item,
                p.version,
                p.author,
                p.home_chain,
                p.home
            ),
            ub(&x["aad"]),
            "{name}"
        );
        let item = Item::from_canonical(x["json"].as_str().unwrap().as_bytes()).unwrap();
        assert_eq!(&item.plaintext().unwrap()[..], &ub(&x["pt"])[..], "{name}");
        assert_eq!(
            serde_json::from_slice::<Value>(&item.canonical().unwrap()).unwrap(),
            x["content"],
            "{name}"
        );
        let got = keys::decrypt_item(&a, &kv, &p, &ub(&x["ciphertext"])).unwrap();
        assert_eq!(got, item, "{name}");
        let ct = keys::encrypt_item(&a, &seed, &kv, &p, Zeroizing::new(ub(&x["pt"]))).unwrap();
        assert_eq!(ct.len(), ub(&x["ciphertext"]).len());
        assert_eq!(keys::decrypt_item(&a, &kv, &p, &ct).unwrap(), item);
        if let Some(f) = x.get("file").filter(|f| !f.is_null()) {
            let wire = ub(&x["content"]["keyWrap"]);
            let fk = keys::open_file_key(&a, &kv, &p, &wire).unwrap();
            assert!(a
                .same_key(fk.clone(), imp(&a, &seed, &f["key"], AppKeyUsage::Data))
                .unwrap());
            let again = keys::seal_file_key(&a, &kv, &p, fk).unwrap();
            assert!(keys::open_file_key(&a, &kv, &p, &again).is_ok());
            // the file key does not open as a prev key wrap (another label), nor under another version's kFile
            let mut q = p;
            q.version += 1;
            assert!(matches!(
                keys::open_file_key(&a, &kv, &q, &wire),
                Err(Error::Unreadable)
            ));
        }
    }
    let r = &it["refusals"];
    let base = it["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["name"] == r["base"])
        .unwrap();
    let kv = imp(&a, &seed, &base["Kv"], AppKeyUsage::Derive);
    let fields = [
        "vaultId",
        "epochId",
        "itemId",
        "version",
        "author",
        "homeChain",
        "homeVaultContract",
    ];
    let mut n = 0;
    for x in r["rows"].as_array().unwrap() {
        let mut row = base.clone();
        let ct = x
            .get("ciphertext")
            .map_or_else(|| ub(&base["ciphertext"]), ub);
        let mut key = kv.clone();
        if let Some(o) = x["aad"].as_object() {
            let (f, v) = o.iter().next().unwrap();
            assert!(fields.contains(&f.as_str()));
            row[f] = v.clone();
        } else if !x["Kv"].is_null() {
            key = imp(&a, &seed, &x["Kv"], AppKeyUsage::Derive);
        }
        let got = keys::decrypt_item(&a, &key, &at(&row), &ct);
        assert!(matches!(got, Err(Error::Unreadable)), "{}", x["name"]);
        n += 1;
    }
    assert!(n >= 5);
    assert!(keys::decrypt_item(&a, &kv, &at(base), &ub(&base["ciphertext"])).is_ok());
}

/// pass.json through `keys::pass_key`: set 1's `P_k` rows (compared in `scaas-ua`), an unknown set refused, none required.
#[tokio::test(flavor = "multi_thread")]
async fn passphrase_keys() {
    let _one = ONE.lock().await;
    let (_sdk, a, seed) = setup().await;
    let p = doc("pass");
    let r = &p["rows"][0];
    let salt = b32(&r["passSalt"]);
    let pass = sec(r["passphrase"].as_str().unwrap().as_bytes());
    let pk = keys::pass_key(&a, &seed, 1, Some(&pass), salt)
        .await
        .unwrap()
        .unwrap();
    assert!(a
        .same_key(pk, imp(&a, &seed, &r["Pk"], AppKeyUsage::Derive))
        .unwrap());
    assert!(keys::pass_key(&a, &seed, 0, None, B32::default())
        .await
        .unwrap()
        .is_none());
    assert!(matches!(
        keys::pass_key(&a, &seed, 2, Some(&pass), salt).await,
        Err(Error::PassKdfUnknown)
    ));
    assert!(matches!(
        keys::pass_key(&a, &seed, 1, None, salt).await,
        Err(Error::PassphraseRequired)
    ));
    assert!(matches!(
        keys::pass_key(&a, &seed, 1, Some(&sec(b"a\x07b")), salt).await,
        Err(Error::PassphraseInvalid)
    ));
}
