// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T5: `Wallet::bip85_child` against clientkeys' rows (smartcontracts/vectors/keys/bip85.json; clientkeys checks the
//! BIP's own vectors), `bip85Next` raised and never reused, the manifest written with and without it.
use scaas_ua::wallet::{Manifest, Wallet};
use serde_json::Value;

fn rows() -> Value {
    let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../smartcontracts/vectors/keys/bip85.json");
    serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap()
}

fn words(b: &mut scaas_ua::wallet::SeedBackup) -> String {
    b.reveal().unwrap().to_string()
}

#[test]
fn children_0_to_2_and_the_high_water_mark() {
    let v = rows();
    let parent = Wallet::from_mnemonic(v["mnemonic"].as_str().unwrap(), "").unwrap();
    let main: Vec<&Value> = v["children"].as_array().unwrap().iter().filter(|c| c["bip39Passphrase"] == "").collect();
    for c in &main {
        assert_eq!(parent.manifest().bip85_next, c["index"].as_u64().unwrap() as u32);
        let (child, mut backup) = parent.bip85_child().unwrap();
        assert_eq!(words(&mut backup), c["words"].as_str().unwrap(), "child {}", c["index"]);
        assert_eq!(child.word_count(), Ok(24));
    }
    assert_eq!(parent.manifest().bip85_next, 3, "raised, never lowered");
    // a hidden set's parent gives other children
    let hidden = Wallet::from_mnemonic(v["mnemonic"].as_str().unwrap(), "hidden ünï").unwrap();
    let (_, mut b) = hidden.bip85_child().unwrap();
    let h0 = v["children"].as_array().unwrap().iter().find(|c| c["bip39Passphrase"] != "" && c["index"] == 0).unwrap();
    assert_eq!(words(&mut b), h0["words"].as_str().unwrap());
    parent.lock();
    assert_eq!(parent.bip85_child().err(), Some(scaas_ua::wallet::Error::WalletLocked));
}

#[test]
fn manifest_rows_with_and_without_bip85_next() {
    let v = rows();
    for r in v["manifests"].as_array().unwrap() {
        let json = r["json"].as_str().unwrap();
        let m = Manifest::from_json(json.as_bytes()).unwrap();
        assert_eq!(m.bip85_next as u64, r["bip85Next"].as_u64().unwrap());
        assert_eq!(m.to_json(), json, "the bytes kept");
    }
    // refused: a written zero, an index of 2^31
    let base = v["manifests"][0]["json"].as_str().unwrap().trim_end_matches('}').to_owned();
    for bad in [",\"bip85Next\":0}", ",\"bip85Next\":2147483648}", ",\"bip85Next\":\"1\"}"] {
        assert!(Manifest::from_json(format!("{base}{bad}").as_bytes()).is_err(), "{bad}");
    }
}

#[test]
fn bip85_next_survives_a_manifest_reseal() {
    let w = Wallet::from_mnemonic(rows()["mnemonic"].as_str().unwrap(), "").unwrap();
    w.seal_label_vault("manifest", "river-otter-7", None).unwrap();
    w.bip85_child().unwrap();
    let v = w.reseal_label_vault("manifest").unwrap();
    let other = Wallet::from_mnemonic(rows()["mnemonic"].as_str().unwrap(), "").unwrap();
    other.open_label_vault(&v, scaas_ua::wallet::Unlock::VaultPassphrase("river-otter-7")).unwrap();
    assert_eq!(other.manifest().bip85_next, 1);
}
