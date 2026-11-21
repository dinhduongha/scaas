// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T42 (decisions CLI-SDK-33 (31)): what the core holds without any `fam-*` feature, and what a family that is off
//! refuses. Run it core only (`--no-default-features --features wallet`, the `ua-core` gate step) and in the default build
//! (every family on: the controls). In the core build: every seed-derived UA kind of `sign.json` is derived from its BIP-39
//! mnemonic (BIP-32, SLIP-10, EIP-2333, the PQ seeds), signs and verifies, its published signature verifies; BIP-85 children
//! derive; every network of a family that is off and the EVM transaction are `FeatureMissing`. UNAUDITED.
#![cfg(feature = "wallet")]
use scaas_ua::ua_message;
use scaas_ua::verify::verify;
use scaas_ua::wallet::{Error, EvmTx, Network, Wallet};
use serde_json::Value;
use std::collections::BTreeSet;

fn load(path: &str) -> Value {
    let p = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn wallet(id: &str) -> Wallet {
    let k = load("ua/keys.json");
    let m = k["mnemonics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|m| m["id"] == id)
        .unwrap();
    Wallet::from_mnemonic(
        m["words"].as_str().unwrap(),
        m["passphrase"].as_str().unwrap(),
    )
    .unwrap()
}

/// Every seed-derived UA kind: derived, signed and verified with no family; a changed byte does not verify (the negative
/// control); the published signature verifies.
#[test]
fn every_seed_kind_derives_signs_and_verifies() {
    let rows = load("ua/sign.json");
    let mut kinds = BTreeSet::new();
    for r in rows["ua"].as_array().unwrap() {
        let kind = r["kind"].as_u64().unwrap() as u16;
        let w = wallet(r["mnemonic"].as_str().unwrap());
        let (a, i) = (
            r["account"].as_u64().unwrap() as u32,
            r["index"].as_u64().unwrap() as u32,
        );
        let key = w.ua_key(kind, a, i).unwrap();
        assert_eq!(key.key_data(), bytes(&r["keyData"]), "{r}");
        let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
        let msg = ua_message(kind, &purpose, &digest).unwrap();
        let pop = r["role"] == "pop";
        assert!(verify(kind, &key.key_data(), &msg, &bytes(&r["signature"]), pop, false), "{r}");
        let mut sig = key.sign_ua(&purpose, &digest).unwrap();
        assert!(verify(kind, &key.key_data(), &msg, &sig, pop, false), "{r}");
        sig[0] ^= 1;
        assert!(!verify(kind, &key.key_data(), &msg, &sig, pop, false), "{r}");
        kinds.insert(kind);
    }
    // the seed-derived kinds: P-256, ed25519, BIP-340, the two Schnorr and the two BLS kinds, secp256k1, the PQ kinds
    let want: BTreeSet<u16> = [
        0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0130, 0x0131, 0x0132,
        0x0133, 0x0134, 0x0135,
    ]
    .into();
    assert_eq!(kinds, want);
}

/// BIP-85 children with no family: clientkeys' rows (`keys/bip85.json`), each child's words and its own UA key.
#[test]
fn bip85_children_derive() {
    let v = load("keys/bip85.json");
    let parent = Wallet::from_mnemonic(v["mnemonic"].as_str().unwrap(), "").unwrap();
    let main: Vec<&Value> = v["children"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["bip39Passphrase"] == "")
        .collect();
    assert!(!main.is_empty());
    for c in main {
        let (child, mut backup) = parent.bip85_child().unwrap();
        assert_eq!(backup.reveal().unwrap().to_string(), c["words"].as_str().unwrap());
        assert!(child.ua_key(0x0102, 0, 0).is_ok());
    }
}

/// A network of a family that is off is `FeatureMissing` before anything is derived; one that is on derives (in the
/// default build every one does: the control).
#[test]
fn a_family_that_is_off_is_feature_missing() {
    let w = wallet("pq_kat");
    for n in Network::all() {
        let got = match n {
            Network::Polkadot => w.polkadot_key("//a").map(|_| ()),
            _ => w.native_key(n, 0, None).map(|_| ()),
        };
        if n.built() {
            assert_eq!(got, Ok(()), "{n:?}");
        } else {
            assert_eq!(got, Err(Error::FeatureMissing), "{n:?}");
        }
    }
    let json = br#"{"type":0,"chainId":"7622","nonce":"0","gasPrice":"1","gasLimit":"21000","to":"0x5ca00000000000000000000000000000000000c0","value":"1","data":"0x"}"#;
    if Network::Evm.built() {
        assert!(EvmTx::from_json(json).unwrap().sighash().is_ok());
    } else {
        assert_eq!(
            EvmTx::from_json(json).err(),
            Some(Error::FeatureMissing),
            "the EVM transaction is fam-evm's"
        );
    }
}

/// This build's rows, read here (the oracle `Network::built` is held to).
fn on(feature: &str) -> bool {
    match feature {
        "fam-evm" => cfg!(feature = "fam-evm"),
        "fam-hedera" => cfg!(feature = "fam-hedera"),
        "fam-cosmos" => cfg!(feature = "fam-cosmos"),
        "fam-sui" => cfg!(feature = "fam-sui"),
        "fam-soroban" => cfg!(feature = "fam-soroban"),
        "fam-ton" => cfg!(feature = "fam-ton"),
        "fam-aptos" => cfg!(feature = "fam-aptos"),
        "fam-solana" => cfg!(feature = "fam-solana"),
        "fam-btc" => cfg!(feature = "fam-btc"),
        "fam-near" => cfg!(feature = "fam-near"),
        "fam-dot" => cfg!(feature = "fam-dot"),
        f => panic!("{f}: not a network's row"),
    }
}

/// The rule's map: each network names its `fam-<row>` feature and `built` follows that feature of this build.
#[test]
fn every_network_names_its_feature() {
    for n in Network::all() {
        assert_eq!(n.built(), on(n.feature()), "{n:?}");
    }
    assert_eq!(Network::HederaEcdsa.feature(), "fam-evm", "Hedera's EVM side");
    assert_eq!(Network::HederaEd25519.feature(), "fam-hedera");
    assert_eq!(Network::Stellar.feature(), "fam-soroban");
    assert_eq!(Network::Polkadot.feature(), "fam-dot");
    assert_eq!(Network::BitcoinP2tr.feature(), "fam-btc");
}
