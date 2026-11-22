// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! P6h (3), CLI-SGN-52: [`Wallet::seal_pq_key`] (the key worker: the registry-class leaf `seed32` derived in the arena and sealed
//! as vault v2, label `pqz:registry:<account>:<index>:<version>`) and [`PqzKey::open_leaf`] (the Zether worker / `pqz-cli` side:
//! the leaf alone into its own store, never the seed), against smartcontracts/vectors/ua/pqz_leaf.json (written by clientkeys
//! scripts/pqz-leaf-vectors.mjs). Every refusal of `open_leaf` is `VaultOpen`, each beside its control. UNAUDITED.
use scaas_ua::facade::pqz::{pqz_leaf_label, AllowSecretExport, PqzKey};
use scaas_ua::wallet::{Error, PrfEnvelope, Unlock, Wallet};
use serde_json::Value;

fn unlock() {
    #[cfg(feature = "vectors")]
    scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);
}
fn load() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/ua/pqz_leaf.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn h32(v: &Value) -> [u8; 32] {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap()
}
fn at(v: &Value) -> (u32, u32, u64) {
    let n = |k: &str| v[k].as_u64().unwrap();
    (n("account") as u32, n("index") as u32, n("version"))
}
/// `open_leaf` of a row's vault JSON at `open` with its `unlock` (`{pin}` or `{prfOutput}`).
fn open(vault: &Value, open: &Value, u: &Value) -> Result<PqzKey, Error> {
    let (a, i, v) = at(open);
    let json = vault.to_string();
    match u.get("prfOutput") {
        Some(p) => PqzKey::open_leaf(json.as_bytes(), Unlock::Prf(&h32(p)), a, i, v),
        None => PqzKey::open_leaf(
            json.as_bytes(),
            Unlock::VaultPassphrase(u["pin"].as_str().unwrap()),
            a,
            i,
            v,
        ),
    }
}

#[test]
fn leaf_label_is_clientkeys() {
    assert_eq!(pqz_leaf_label(0, 0, 0), "pqz:registry:0:0:0");
    assert_eq!(
        pqz_leaf_label(3, 7, u64::MAX),
        "pqz:registry:3:7:18446744073709551615"
    );
}

/// Every leaf row opens; its key is the wallet's own key at that account, index and version (the same `pk`), and the leaf is
/// the wallet's `seed32` there.
#[test]
fn pqz_leaf_json_leaves_open() {
    unlock();
    let f = load();
    let w = Wallet::from_mnemonic(f["mnemonic"].as_str().unwrap(), "").unwrap();
    let leaves = f["leaves"].as_array().unwrap();
    assert!(leaves.len() >= 5);
    for r in leaves {
        let (a, i, v) = at(r);
        assert_eq!(pqz_leaf_label(a, i, v), r["label"].as_str().unwrap());
        let leaf = w
            .export_pqz_leaf_raw_version(a, i, v, AllowSecretExport)
            .unwrap();
        assert_eq!(*leaf, h32(&r["seed32"]), "{}", r["id"]);
        let k = open(&r["vault"], r, &r["unlock"]).unwrap();
        assert_eq!(k.pk(), w.pqz_key_version(a, i, v).unwrap().pk(), "{}", r["id"]);
        assert_eq!((k.account(), k.index()), (a, i));
    }
}

/// Every refusal row is `VaultOpen`, and its control (one change back) opens to the control's `seed32`.
#[test]
fn pqz_leaf_json_refusals() {
    unlock();
    let f = load();
    let w = Wallet::from_mnemonic(f["mnemonic"].as_str().unwrap(), "").unwrap();
    let rows = f["refusals"].as_array().unwrap();
    assert_eq!(rows.len(), 17);
    for x in rows {
        assert_eq!(x["error"], "VaultOpen");
        let e = open(&x["vault"], &x["open"], &x["unlock"]).err();
        assert_eq!(e, Some(Error::VaultOpen), "{}", x["id"]);
        let c = &x["control"];
        let k = open(&c["vault"], &c["open"], &c["unlock"])
            .unwrap_or_else(|e| panic!("control {}: {e:?}", x["id"]));
        if h32(&c["seed32"]) != [0u8; 32] {
            let (a, i, v) = at(&c["open"]);
            assert_eq!(k.pk(), w.pqz_key_version(a, i, v).unwrap().pk(), "control {}", x["id"]);
        }
    }
}

/// A truncated vault JSON (the blob itself cut) is `VaultOpen` too, beside the whole JSON opening.
#[test]
fn truncated_json_is_vault_open() {
    unlock();
    let f = load();
    let r = &f["leaves"][0];
    let json = r["vault"].to_string();
    let u = Unlock::VaultPassphrase(r["unlock"]["pin"].as_str().unwrap());
    assert!(PqzKey::open_leaf(json.as_bytes(), u, 0, 0, 0).is_ok());
    for cut in [1, json.len() / 2, json.len() - 1] {
        let e = PqzKey::open_leaf(&json.as_bytes()[..cut], u, 0, 0, 0).err();
        assert_eq!(e, Some(Error::VaultOpen), "cut at {cut}");
    }
    let deep = format!("{}{}", "[".repeat(64), "]".repeat(64));
    assert_eq!(
        PqzKey::open_leaf(deep.as_bytes(), u, 0, 0, 0).err(),
        Some(Error::VaultOpen)
    );
}

/// `seal_pq_key` seals the wallet's own leaf under the leaf label and the wallet's vault id; clientkeys' opener and this one
/// read it (the label and payload are the rows'), and the PRF envelope opens it too.
#[test]
fn seal_pq_key_round_trip() {
    unlock();
    let f = load();
    let w = Wallet::from_mnemonic(f["mnemonic"].as_str().unwrap(), "").unwrap();
    let pass = "river-otter-7 ünï";
    let out = [9u8; 32];
    let prf = PrfEnvelope {
        output: &out,
        credential_id: "Y3JlZGVudGlhbC0x",
        salt: &[1, 2, 3],
    };
    for (a, i, v) in [(0, 0, 0), (1, 2, 0), (0, 0, 1)] {
        let vault = w.seal_pq_key(a, i, v, pass, Some(&prf)).unwrap();
        assert_eq!(vault.label(), pqz_leaf_label(a, i, v));
        assert_eq!(vault.id(), w.vault_id().unwrap());
        let json = vault.to_json();
        let leaf = w
            .export_pqz_leaf_raw_version(a, i, v, AllowSecretExport)
            .unwrap();
        assert!(!json.contains(&hex::encode(*leaf)));
        let want = w.pqz_key_version(a, i, v).unwrap().pk();
        for u in [Unlock::VaultPassphrase(pass), Unlock::Prf(&out)] {
            let k = PqzKey::open_leaf(json.as_bytes(), u, a, i, v).unwrap();
            assert_eq!(k.pk(), want);
        }
        assert_eq!(
            PqzKey::open_leaf(json.as_bytes(), Unlock::VaultPassphrase(pass), a, i, v + 1).err(),
            Some(Error::VaultOpen)
        );
    }
    // the new-passphrase policy and the hardened range, as seal_vault and pqz_key
    assert_eq!(w.seal_pq_key(0, 0, 0, "1234567", None).err(), Some(Error::Argument));
    assert_eq!(w.seal_pq_key(1 << 31, 0, 0, pass, None).err(), Some(Error::Argument));
    assert_eq!(w.seal_pq_key(0, 1 << 31, 0, pass, None).err(), Some(Error::Argument));
}

/// A locked wallet seals nothing; a leaf opened before the lock keeps its own store (it never held the wallet's seed).
#[test]
fn locked_wallet_and_own_store() {
    unlock();
    let f = load();
    let w = Wallet::from_mnemonic(f["mnemonic"].as_str().unwrap(), "").unwrap();
    let pass = "river-otter-7 ünï";
    let json = w.seal_pq_key(0, 0, 0, pass, None).unwrap().to_json();
    let k = PqzKey::open_leaf(json.as_bytes(), Unlock::VaultPassphrase(pass), 0, 0, 0).unwrap();
    let cache = k.seal_balance_cache(b"{}").unwrap();
    w.lock();
    assert_eq!(w.seal_pq_key(0, 0, 0, pass, None).err(), Some(Error::WalletLocked));
    assert_eq!(&*k.open_balance_cache(cache.as_bytes()).unwrap(), b"{}");
}
