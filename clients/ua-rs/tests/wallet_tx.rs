// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T5: EVM transactions of types 0-3 (spec §5.5; CLI-SGN-40: no type 4, never chain id 0) against
//! smartcontracts/vectors/ua/sign.json (written by clientkeys `evmTransaction` / `signTransaction`): the unsigned bytes, the
//! sighash, `(yParity, r, s)` and the signed envelope byte for byte (RFC 6979, low-s); the EIP-155 published example; the
//! refusals; chain separation. UNAUDITED.
use scaas_ua::verify::native_ecdsa;
use scaas_ua::wallet::{Error, EvmTx, Network, Wallet};
use serde_json::{json, Value};

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn tx(v: &Value) -> Result<EvmTx, Error> {
    EvmTx::from_json(&serde_json::to_vec(v).unwrap())
}
fn wallet() -> Wallet {
    let k = load("ua/keys.json");
    let m = k["mnemonics"].as_array().unwrap().iter().find(|m| m["id"] == "pq_kat").unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
fn addr20(a: &str) -> [u8; 20] {
    hex::decode(a.trim_start_matches("0x")).unwrap().try_into().unwrap()
}
/// `r`, `s` and `yParity` as the 65 bytes `native_ecdsa` takes (`v = 27 + yParity`).
fn sig65(r: &[u8; 32], s: &[u8; 32], y_parity: u8) -> Vec<u8> {
    [&r[..], &s[..], &[27 + y_parity]].concat()
}

/// One row: the unsigned bytes and sighash from the named fields, then the wallet's EVM key signs it byte for byte.
fn check_row(w: &Wallet, r: &Value, unsigned: Option<&Value>) {
    let t = tx(&r["tx"]).unwrap_or_else(|e| panic!("{}: {e:?}", r["tx"]));
    assert_eq!(t.tx_type(), r["tx"]["type"].as_u64().unwrap() as u8);
    if let Some(u) = unsigned {
        assert_eq!(t.unsigned().unwrap(), bytes(u), "{}", r["tx"]);
    }
    assert_eq!(t.sighash().unwrap(), b32(&r["sighash"]), "{}", r["tx"]);
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    let s = key.sign_transaction(&t).unwrap();
    assert_eq!(s.tx_type, t.tx_type());
    assert_eq!(s.sighash, b32(&r["sighash"]));
    assert_eq!(s.y_parity, r["yParity"].as_u64().unwrap() as u8, "{}", r["tx"]);
    assert_eq!(s.r, b32(&r["r"]), "{}", r["tx"]);
    assert_eq!(s.s, b32(&r["s"]), "{}", r["tx"]);
    assert_eq!(s.raw, bytes(&r["raw"]), "{}", r["tx"]);
}

/// `sign.json` `tx.rows`: every type 0-3, a create, a 2^256 - 1 value, a 2^64 - 1 nonce, an access list, blob hashes.
#[test]
fn sign_json_tx_rows_per_type() {
    let v = load("ua/sign.json");
    let w = wallet();
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    let mut types = std::collections::BTreeSet::new();
    let rows = v["tx"]["rows"].as_array().unwrap();
    for r in rows {
        assert_eq!(r["signer"]["mnemonic"], "pq_kat");
        assert_eq!(r["signer"]["network"], "evm");
        assert_eq!(r["signer"]["index"], 0);
        assert_eq!(evm.address().unwrap().to_lowercase(), r["signer"]["address"].as_str().unwrap().to_lowercase());
        check_row(&w, r, Some(&r["unsigned"]));
        types.insert(r["tx"]["type"].as_u64().unwrap());
    }
    assert_eq!(types.into_iter().collect::<Vec<_>>(), vec![0, 1, 2, 3]);
    assert_eq!(rows.len(), 6);
}

/// The EIP-155 example (source and sha256 in the row): the signing data, the signing hash and, with the published key, the
/// signed transaction (`v = 37`).
#[test]
fn eip155_published_row() {
    let v = load("ua/sign.json");
    let p = v["tx"]["published"].as_array().unwrap();
    assert_eq!(p.len(), 1);
    let p = &p[0];
    assert!(p["source"].as_str().unwrap().ends_with("eip-155.md"));
    assert_eq!(p["v"], 37);
    let t = tx(&p["tx"]).unwrap();
    assert_eq!(t.unsigned().unwrap(), bytes(&p["signingData"]));
    assert_eq!(t.sighash().unwrap(), b32(&p["signingHash"]));
    #[cfg(feature = "vectors")]
    {
        let s = t.vectors_sign_with_secret(&bytes(&p["privateKey"])).unwrap();
        assert_eq!(s.raw, bytes(&p["signedTx"]));
        assert_eq!(s.y_parity, 0);
        let dec = |x: &Value| {
            let n = x.as_str().unwrap();
            let mut w = [0u8; 32];
            for c in n.bytes() {
                let mut carry = u32::from(c - b'0');
                for b in w.iter_mut().rev() {
                    let x = u32::from(*b) * 10 + carry;
                    *b = x as u8;
                    carry = x >> 8;
                }
            }
            w
        };
        assert_eq!(s.r, dec(&p["r"]));
        assert_eq!(s.s, dec(&p["s"]));
    }
}

/// `sign.json` `tx.refusals`: each an otherwise valid transaction with one change (type 4 with and without its list, no
/// `chainId`, chain id 0, a field of another type, no `to`, a type-3 create, no blob hash, nonce 2^64, value 2^256, a 19-byte
/// `to`, a hex value): `Argument`, nothing signed.
#[test]
fn sign_json_tx_refusals() {
    let v = load("ua/sign.json");
    let refusals = v["tx"]["refusals"].as_array().unwrap();
    assert_eq!(refusals.len(), 12);
    for r in refusals {
        assert_eq!(tx(&r["tx"]).err(), Some(Error::Argument), "{}", r["id"]);
    }
}

/// Plan T5: a legacy transaction is EIP-155 or nothing. Positive control first (the row as written), then one change each:
/// `chainId` removed, `chainId` 0, and a chain id 0 built in Rust (refused at signing, nothing signed).
#[test]
fn legacy_without_chain_id_refused() {
    let v = load("ua/sign.json");
    let row = &v["tx"]["rows"][0];
    assert_eq!(row["tx"]["type"], 0);
    let w = wallet();
    check_row(&w, row, Some(&row["unsigned"]));
    let mut no_id = row["tx"].clone();
    no_id.as_object_mut().unwrap().remove("chainId");
    assert_eq!(tx(&no_id).err(), Some(Error::Argument));
    let mut zero = row["tx"].clone();
    zero["chainId"] = json!("0");
    assert_eq!(tx(&zero).err(), Some(Error::Argument));
    let EvmTx::Legacy { nonce, gas_price, gas_limit, to, value, data, .. } = tx(&row["tx"]).unwrap() else { panic!() };
    let built = EvmTx::Legacy { chain_id: 0, nonce, gas_price, gas_limit, to, value, data };
    assert_eq!(built.sighash().err(), Some(Error::Argument));
    let key = w.native_key(Network::Evm, 0, None).unwrap();
    assert_eq!(key.sign_transaction(&built).err(), Some(Error::Argument));
}

/// A type-3 transaction built in Rust with no blob hash is refused as the JSON form is (no create: `to` is not optional).
#[test]
fn blob_tx_without_hashes_refused_when_built() {
    let v = load("ua/sign.json");
    let row = v["tx"]["rows"].as_array().unwrap().iter().find(|r| r["tx"]["type"] == 3).unwrap();
    let EvmTx::Eip4844 { chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list,
        max_fee_per_blob_gas, .. } = tx(&row["tx"]).unwrap() else { panic!() };
    let built = EvmTx::Eip4844 { chain_id, nonce, max_priority_fee_per_gas, max_fee_per_gas, gas_limit, to, value, data, access_list,
        max_fee_per_blob_gas, blob_versioned_hashes: vec![] };
    assert_eq!(built.sighash().err(), Some(Error::Argument));
}

/// chainSeparation (owner 2026-11-05): types 0 and 2 on 7622 and 22776 are byte-equal to clientkeys, and a signature for one
/// chain does not recover to the key over the other chain's sighash (positive control: over its own).
#[test]
fn chain_separation_tx_rows() {
    let v = load("ua/sign.json");
    let cs = &v["chainSeparation"];
    let w = wallet();
    let address = addr20(cs["key"]["evm"]["address"].as_str().unwrap());
    let rows = cs["tx"].as_array().unwrap();
    assert_eq!(rows.len(), 4);
    for r in rows {
        check_row(&w, r, None);
    }
    let mut n = 0;
    for x in cs["refusals"].as_array().unwrap().iter().filter(|x| x["what"] == "tx") {
        let pick = |chain: &Value| rows.iter().find(|r| r["type"] == x["type"] && r["chainId"] == *chain).unwrap();
        let (signed, other) = (pick(&x["signedFor"]), pick(&x["checkedAgainst"]));
        let sig = sig65(&b32(&signed["r"]), &b32(&signed["s"]), signed["yParity"].as_u64().unwrap() as u8);
        assert!(native_ecdsa(&address, &b32(&signed["sighash"]), &sig));
        assert!(!native_ecdsa(&address, &b32(&other["sighash"]), &sig));
        n += 1;
    }
    assert_eq!(n, 4);
}

/// Only a secp256k1 native key signs a transaction: the ed25519 networks are refused (`Argument`), the EVM key signs (positive
/// control); what it signs recovers to its address.
#[test]
fn ed25519_native_key_refused() {
    let v = load("ua/sign.json");
    let t = tx(&v["tx"]["rows"][3]["tx"]).unwrap();
    let w = wallet();
    let evm = w.native_key(Network::Evm, 0, None).unwrap();
    let s = evm.sign_transaction(&t).unwrap();
    assert!(native_ecdsa(&addr20(&evm.address().unwrap()), &s.sighash, &sig65(&s.r, &s.s, s.y_parity)));
    for net in [Network::Solana, Network::Stellar, Network::Sui, Network::Aptos, Network::Ton, Network::HederaEd25519] {
        let key = w.native_key(net, 0, None).unwrap();
        assert_eq!(key.sign_transaction(&t).err(), Some(Error::Argument), "{net:?}");
    }
}

/// The transaction JSON is read through `bounded::json` at 16 KiB (spec §9.3): a transaction of exactly 16 KiB is read, one
/// byte more is refused.
#[test]
fn tx_json_capped_at_16_kib() {
    let v = load("ua/sign.json");
    let mut t = v["tx"]["rows"][0]["tx"].clone();
    t["data"] = json!("0x");
    let base = serde_json::to_vec(&t).unwrap().len();
    let fill = (16 * 1024 - base) / 2 * 2;
    t["data"] = json!(format!("0x{}", "ab".repeat(fill / 2)));
    let mut s = serde_json::to_vec(&t).unwrap();
    while s.len() < 16 * 1024 {
        s.insert(0, b' ');
    }
    assert_eq!(s.len(), 16 * 1024);
    assert!(EvmTx::from_json(&s).is_ok());
    s.insert(0, b' ');
    assert_eq!(EvmTx::from_json(&s).err(), Some(Error::Argument));
}
