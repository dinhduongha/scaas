//! Task 16: the scaas-node NEAR adapter hand-encodes the Borsh transaction and its ed25519 signature (no NEAR SDK in
//! the node). This test builds the same signed transaction with `near-primitives` / `near-crypto` 0.38.0 (nearcore's
//! own types) and pins it in `vectors/near-tx.json`; `scaas-node/src/adapters/near.rs` (`tx_matches_near_primitives`)
//! reproduces the bytes. `WRITE_NEAR_TX=1` rewrites the file's derived fields from the inputs; a plain run checks them.
//!
//! The lane key is the ART24 test mnemonic ("abandon" × 23 + "art") at `m/44'/397'/0'/0'/0'` (SLIP-10, the node's
//! `keys::lane_path("near", 0)`); the call is `mtx_pay` of the shared `pay` vector with a deposit of 2^127 + 1
//! yoctoNEAR (a u128 above 2^64).
use near_crypto::{ED25519SecretKey, PublicKey, SecretKey};
use near_primitives::action::{Action, FunctionCallAction};
use near_primitives::hash::CryptoHash;
use near_primitives::transaction::{SignedTransaction, Transaction, TransactionV0};
use near_primitives::types::{Balance, Gas};
use serde_json::Value;

const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");
const TX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-tx.json");

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

fn h0x(b: &[u8]) -> String {
    format!("0x{}", hex::encode(b))
}

#[test]
fn node_tx_vector() {
    let d: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
    let pay = d["metaops"]["vectors"].as_array().unwrap().iter().find(|m| m["name"] == "pay").unwrap();
    let auth = &pay["auth"];
    // mtx_pay args: Borsh(MetaOp) (the encoding without the 15-byte label) ‖ Borsh(Auth::Ed25519 { key, sig })
    let args = [&hx(&pay["encoding"])[15..], &[0u8], &hx(&auth["key"]), &hx(&auth["sig"])].concat();

    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(TX).unwrap()).unwrap();
    let (seed, pk) = (hx(&v["seed"]), hx(&v["public_key"]));
    let sk = SecretKey::ED25519(ED25519SecretKey([&seed[..], &pk[..]].concat().try_into().unwrap()));
    assert_eq!(sk.public_key(), PublicKey::ED25519(pk.as_slice().try_into().unwrap()));
    let signer = hex::encode(&pk); // implicit account
    assert_eq!(v["signer"].as_str(), Some(signer.as_str()));
    let deposit: u128 = v["deposit"].as_str().unwrap().parse().unwrap();
    assert_eq!(deposit, (1u128 << 127) + 1);
    let tx = Transaction::V0(TransactionV0 {
        signer_id: signer.parse().unwrap(),
        public_key: sk.public_key(),
        nonce: v["nonce"].as_u64().unwrap(),
        receiver_id: v["receiver"].as_str().unwrap().parse().unwrap(),
        block_hash: CryptoHash(hx(&v["block_hash"]).try_into().unwrap()),
        actions: vec![Action::FunctionCall(Box::new(FunctionCallAction {
            method_name: v["method"].as_str().unwrap().into(),
            args: args.clone(),
            gas: Gas::from_gas(v["gas"].as_u64().unwrap()),
            deposit: Balance::from_yoctonear(deposit),
        }))],
    });
    let (hash, _) = tx.get_hash_and_size();
    let sig = sk.sign(hash.as_ref());
    let signed = SignedTransaction::new(sig.clone(), tx.clone());
    let sig_bytes = borsh::to_vec(&sig).unwrap();
    assert_eq!(sig_bytes[0], 0, "ed25519 signature tag");
    let got = [
        ("args", h0x(&args)),
        ("transaction", h0x(&borsh::to_vec(&tx).unwrap())),
        ("hash", h0x(hash.as_ref())),
        ("signature", h0x(&sig_bytes[1..])),
        ("signed", h0x(&borsh::to_vec(&signed).unwrap())),
    ];
    if std::env::var("WRITE_NEAR_TX").is_ok() {
        for (k, g) in &got {
            v[*k] = Value::String(g.clone());
        }
        std::fs::write(TX, serde_json::to_string_pretty(&v).unwrap() + "\n").unwrap();
    }
    for (k, g) in &got {
        assert_eq!(v[*k].as_str(), Some(g.as_str()), "{k}");
    }
    assert_eq!(signed.get_hash(), hash);
}
