// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T2a: the same-DEK re-seal (spec §6.10): clientkeys' rows (smartcontracts/vectors/keystore/reseal.json) open by
//! passphrase and by PRF and keep both envelopes; `Vault::reseal_data` and `Wallet::reseal_label_vault` keep them too; the DEK
//! held from opening until `lock`.
use scaas_ua::wallet::{Error, PrfEnvelope, Unlock, Vault, Wallet};
use serde_json::Value;
use std::path::Path;

const MNEMONIC: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
const PASS: &str = "river-otter-7 ünï";

fn rows() -> Vec<Value> {
    let p = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../smartcontracts/vectors/keystore/reseal.json");
    let v: Value = serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap();
    v["reseals"].as_array().unwrap().clone()
}

fn vault(v: &Value) -> Vault {
    Vault::from_json(serde_json::to_string(v).unwrap().as_bytes()).unwrap()
}

fn prf32(r: &Value) -> Option<[u8; 32]> {
    r["prfOutput"]
        .as_str()
        .map(|h| hex::decode(&h[2..]).unwrap().try_into().unwrap())
}

/// What `vault` holds, opened into a fresh wallet (the rows hold manifests).
fn opened(v: &Vault, unlock: Unlock) -> Result<String, Error> {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    w.open_label_vault(v, unlock)?;
    Ok(w.manifest().to_json())
}

fn text(h: &Value) -> String {
    String::from_utf8(hex::decode(&h.as_str().unwrap()[2..]).unwrap()).unwrap()
}

#[test]
fn clientkeys_rows_open_both_ways_and_keep_the_envelopes() {
    let rows = rows();
    assert_eq!(rows.len(), 2);
    for r in &rows {
        let (before, after) = (vault(&r["vault"]), vault(&r["resealed"]));
        assert_eq!(r["resealed"]["pin"], r["vault"]["pin"]);
        assert_eq!(r["resealed"]["prf"], r["vault"]["prf"]);
        assert_ne!(r["resealed"]["data"], r["vault"]["data"]);
        assert_eq!(
            opened(&after, Unlock::VaultPassphrase(PASS)).unwrap(),
            text(&r["plaintext"]),
            "{}",
            r["id"]
        );
        assert_eq!(
            opened(&before, Unlock::VaultPassphrase(PASS)).unwrap(),
            text(&r["before"]),
            "{}",
            r["id"]
        );
        if let Some(p) = prf32(r) {
            assert_eq!(
                opened(&after, Unlock::Prf(&p)).unwrap(),
                text(&r["plaintext"]),
                "{}",
                r["id"]
            );
        }
        // ua-rs's own re-seal of the row's vault: the same envelopes, opens to the new payload
        let mine = before
            .reseal_data(
                Unlock::VaultPassphrase(PASS),
                text(&r["plaintext"]).as_bytes(),
            )
            .unwrap();
        let (m, b): (Value, Value) = (
            serde_json::from_str(&mine.to_json()).unwrap(),
            r["vault"].clone(),
        );
        assert_eq!((&m["pin"], &m["prf"]), (&b["pin"], &b["prf"]));
        assert_eq!(
            opened(&mine, Unlock::VaultPassphrase(PASS)).unwrap(),
            text(&r["plaintext"])
        );
        assert_eq!(
            before
                .reseal_data(Unlock::VaultPassphrase("river-otter-8"), b"x")
                .err(),
            Some(Error::VaultOpen)
        );
    }
}

const PRF: [u8; 32] = [7; 32];
fn envelope() -> PrfEnvelope<'static> {
    PrfEnvelope {
        output: &PRF,
        credential_id: "Yw",
        salt: &[9; 32],
    }
}

#[test]
fn reseal_keeps_the_prf_envelope() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let v1 = w
        .seal_label_vault("manifest", PASS, Some(&envelope()))
        .unwrap();
    w.ua_key(0x0100 + 1, 0, 0).unwrap(); // a manifest change: a UA entry
    let v2 = w.reseal_label_vault("manifest").unwrap();
    let (a, b): (Value, Value) = (
        serde_json::from_str(&v1.to_json()).unwrap(),
        serde_json::from_str(&v2.to_json()).unwrap(),
    );
    assert_eq!(
        (&a["pin"], &a["prf"]),
        (&b["pin"], &b["prf"]),
        "both envelopes kept"
    );
    assert!(b["prf"].is_object());
    assert_eq!(
        opened(&v2, Unlock::Prf(&PRF)).unwrap(),
        w.manifest().to_json(),
        "the change opens by PRF"
    );
    assert_ne!(
        opened(&v1, Unlock::Prf(&PRF)).unwrap(),
        w.manifest().to_json()
    );
    // the negative control: sealing the label anew (today's path without the passkey at hand) drops the PRF envelope
    let fresh: Value = serde_json::from_str(
        &w.seal_label_vault("manifest", PASS, None)
            .unwrap()
            .to_json(),
    )
    .unwrap();
    assert!(fresh.get("prf").is_none());
    // a vault opened (not sealed) here holds its DEK as well
    let w2 = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    assert_eq!(
        w2.reseal_label_vault("manifest").err(),
        Some(Error::Argument),
        "nothing held before opening"
    );
    w2.open_label_vault(&v2, Unlock::Prf(&PRF)).unwrap();
    let v3: Value =
        serde_json::from_str(&w2.reseal_label_vault("manifest").unwrap().to_json()).unwrap();
    assert_eq!((&v3["pin"], &v3["prf"]), (&a["pin"], &a["prf"]));
}

#[test]
fn dek_wiped_at_lock() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let v = w
        .seal_label_vault("manifest", PASS, Some(&envelope()))
        .unwrap();
    assert!(
        w.reseal_label_vault("manifest").is_ok(),
        "control: held while open"
    );
    w.lock();
    assert_eq!(
        w.reseal_label_vault("manifest").err(),
        Some(Error::WalletLocked)
    );
    let seed = w.seal_vault(PASS, None).err();
    assert_eq!(seed, Some(Error::WalletLocked));
    let entropy = Wallet::from_mnemonic(MNEMONIC, "")
        .unwrap()
        .seal_vault(PASS, None)
        .unwrap();
    w.unlock(&entropy, Unlock::VaultPassphrase(PASS), "")
        .unwrap();
    assert_eq!(
        w.reseal_label_vault("manifest").err(),
        Some(Error::Argument),
        "the new arena holds no DEK of before"
    );
    w.open_label_vault(&v, Unlock::Prf(&PRF)).unwrap();
    assert!(
        w.reseal_label_vault("manifest").is_ok(),
        "held again once reopened"
    );
}

/// scaas-sdk T7: `Vault::without_prf` (`disable_prf_unlock`) and `Vault::prf_params` (what the authenticator is asked with).
#[test]
fn without_prf_and_prf_params() {
    let w = Wallet::from_mnemonic(MNEMONIC, "").unwrap();
    let v = w
        .seal_label_vault("manifest", PASS, Some(&envelope()))
        .unwrap();
    assert_eq!(v.prf_params(), Some(("Yw".to_owned(), vec![9; 32])));
    assert!(opened(&v, Unlock::Prf(&PRF)).is_ok(), "control");
    let n = v.without_prf();
    assert_eq!(n.prf_params(), None);
    assert!(opened(&n, Unlock::VaultPassphrase(PASS)).is_ok());
    assert!(opened(&n, Unlock::Prf(&PRF)).is_err());
}
