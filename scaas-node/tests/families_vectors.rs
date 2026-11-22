// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The families' rows of smartcontracts/vectors/families/ (written by clientkeys, read by ua-rs too) against this node's
//! adapters: Solana's program addresses and the SCaaS Account of an owner (`adapters::solana::{find_pda, account_of}`), Sui's
//! derived `Account<T>` id (`adapters::sui::derive_account`).
use scaas_node::adapters::solana::{account_of, find_pda, key};
use serde_json::Value;

fn rows(family: &str) -> Value {
    let p = format!(
        "{}/../smartcontracts/vectors/families/{family}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn solana_program_addresses_and_accounts() {
    let v = rows("solana");
    for r in v["pda"].as_array().unwrap() {
        let seeds: Vec<Vec<u8>> = r["seeds"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| alloy::hex::decode(s.as_str().unwrap().trim_start_matches("0x")).unwrap())
            .collect();
        let s: Vec<&[u8]> = seeds.iter().map(|x| x.as_slice()).collect();
        let (a, bump) = find_pda(&s, &key(r["program"].as_str().unwrap()).unwrap());
        assert_eq!(a, key(r["address"].as_str().unwrap()).unwrap());
        assert_eq!(bump as u64, r["bump"].as_u64().unwrap());
    }
    let acct = v["account"].as_array().unwrap();
    assert_eq!(acct.len(), 4);
    for r in acct {
        let p = key(r["program"].as_str().unwrap()).unwrap();
        let o = key(r["owner"].as_str().unwrap()).unwrap();
        assert_eq!(
            account_of(&p, &o),
            key(r["account"].as_str().unwrap()).unwrap()
        );
    }
}

/// Soroban's ledger keys and entries (SDK plan T24.soroban) decoded by the stellar-xdr crate the node uses: each key is the
/// LedgerKey its row names, each entry the LedgerEntryData of its key holding its amount; each refused entry still decodes
/// (the reader's refusals are of form, not of XDR) unless it is malformed XDR.
#[test]
fn soroban_keys_and_entries() {
    use stellar_xdr::{
        ContractDataDurability, LedgerEntryData, LedgerKey, Limits, ReadXdr, ScAddress, ScVal,
    };
    let v = rows("soroban");
    let lim = || Limits::len(1 << 16);
    let keys: Vec<LedgerKey> = v["keys"]
        .as_array()
        .unwrap()
        .iter()
        .map(|k| LedgerKey::from_xdr_base64(k["key"].as_str().unwrap(), lim()).unwrap())
        .collect();
    assert!(matches!(&keys[0], LedgerKey::Account(_)));
    for (k, row) in keys[1..].iter().zip(&v["keys"].as_array().unwrap()[1..]) {
        let LedgerKey::ContractData(d) = k else {
            panic!("{row}")
        };
        assert_eq!(d.durability, ContractDataDurability::Persistent);
        assert!(matches!(d.contract, ScAddress::Contract(_)));
        let ScVal::Vec(Some(items)) = &d.key else {
            panic!("{row}")
        };
        let want = if row["holder"].as_str().unwrap().starts_with("0x") {
            "UaBalance"
        } else {
            "Balance"
        };
        assert!(
            matches!(&items[0], ScVal::Symbol(s) if s.to_string() == want),
            "{row}"
        );
        assert_eq!(items.len(), 2);
    }
    for e in v["entries"].as_array().unwrap() {
        let d = LedgerEntryData::from_xdr_base64(e["xdr"].as_str().unwrap(), lim()).unwrap();
        let amount = match d {
            LedgerEntryData::Account(a) => a.balance.to_string(),
            LedgerEntryData::ContractData(c) => match c.val {
                ScVal::I128(p) => (((p.hi as i128) << 64) | p.lo as i128).to_string(),
                ScVal::Map(Some(m)) => match &m[0].val {
                    ScVal::I128(p) => (((p.hi as i128) << 64) | p.lo as i128).to_string(),
                    x => panic!("{x:?}"),
                },
                x => panic!("{x:?}"),
            },
            x => panic!("{x:?}"),
        };
        assert_eq!(amount, e["amount"].as_str().unwrap(), "{}", e["what"]);
    }
}

/// Sui's derived `Account<T>` ids (SDK plan T24.sui) by the node's `derive_account`: every row, the Move test's pair first.
#[test]
fn sui_derived_accounts() {
    let v = rows("sui");
    let acct = v["account"].as_array().unwrap();
    assert!(acct.len() >= 4);
    let a =
        |r: &Value, k: &str| scaas_node::adapters::sui::parse_addr(r[k].as_str().unwrap()).unwrap();
    for r in acct {
        assert_eq!(
            scaas_node::adapters::sui::derive_account(&a(r, "registry"), &a(r, "owner")),
            a(r, "account")
        );
    }
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// Plan 2026-11-17-scaas-sdk T27.soroban: each op row's `signed_op` through the adapter's own `host_call` (the entry it builds
/// from the named payload), its preimage rebuilt with stellar-xdr from that entry equal to the row's, the subject's signature
/// valid over its `sha256`.
#[test]
fn soroban_op_envelopes_through_the_adapter() {
    use ed25519_dalek::{Signature, VerifyingKey};
    use sha2::Digest;
    use stellar_xdr::{
        AccountId, HashIdPreimage, HashIdPreimageSorobanAuthorization, Limits, PublicKey,
        ScAddress, SorobanCredentials, Uint256, WriteXdr,
    };
    let v = rows("soroban");
    let nid: [u8; 32] =
        sha2::Sha256::digest(v["ops"][0]["shown"]["passphrase"].as_str().unwrap()).into();
    assert_eq!(v["ops"].as_array().unwrap().len(), 3);
    for o in v["ops"].as_array().unwrap() {
        let (call, auth) = scaas_node::adapters::soroban::host_call(&o["signed_op"]).unwrap();
        assert_eq!(auth.len(), 1);
        let SorobanCredentials::Address(c) = &auth[0].credentials else {
            panic!("address credentials")
        };
        let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id: nid.into(),
            nonce: c.nonce,
            signature_expiration_ledger: c.signature_expiration_ledger,
            invocation: auth[0].root_invocation.clone(),
        })
        .to_xdr(Limits::none())
        .unwrap();
        assert_eq!(pre, unhex(o["preimage"].as_str().unwrap()), "{}", o["kind"]);
        assert_eq!(
            call.function_name.0.as_slice(),
            o["kind"].as_str().unwrap().as_bytes()
        );
        let ScAddress::Account(AccountId(PublicKey::PublicKeyTypeEd25519(Uint256(pk)))) = c.address
        else {
            panic!("a G… subject")
        };
        let d: [u8; 32] = sha2::Sha256::digest(&pre).into();
        let sig = Signature::from_slice(&unhex(o["signature"].as_str().unwrap())).unwrap();
        VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_strict(&d, &sig)
            .unwrap();
    }
}

/// Plan T41.soroban: each native row decodes as a stellar-xdr `Transaction` and encodes back to its bytes, its id is the crate's
/// `hash`, its envelope's one signature is the source's over it; the self-relay's auth entry is the one the adapter builds from
/// T27's named `signed_op`, and its `SorobanTransactionData` the row's `dataXdr`.
#[test]
fn soroban_native_transactions_through_the_official_xdr() {
    use ed25519_dalek::{Signature, VerifyingKey};
    use stellar_xdr::{
        Limits, MuxedAccount, OperationBody, ReadXdr, SorobanTransactionData, Transaction,
        TransactionEnvelope, TransactionExt, Uint256, WriteXdr,
    };
    let p = format!(
        "{}/../smartcontracts/vectors/native/soroban-tx.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let n: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    let fam = rows("soroban");
    let nid: [u8; 32] = unhex(n["networkId"].as_str().unwrap()).try_into().unwrap();
    assert_eq!(n["rows"].as_array().unwrap().len(), 5);
    for r in n["rows"].as_array().unwrap() {
        let b = unhex(r["tx"].as_str().unwrap());
        let tx = Transaction::from_xdr(&b, Limits::none()).unwrap();
        assert_eq!(tx.to_xdr(Limits::none()).unwrap(), b, "{}", r["what"]);
        assert_eq!(
            tx.hash(nid).unwrap().to_vec(),
            unhex(r["hash"].as_str().unwrap())
        );
        let TransactionEnvelope::Tx(e) =
            TransactionEnvelope::from_xdr(unhex(r["envelope"].as_str().unwrap()), Limits::none())
                .unwrap()
        else {
            panic!("a v1 envelope")
        };
        let MuxedAccount::Ed25519(Uint256(pk)) = e.tx.source_account else {
            panic!("a G… source")
        };
        let sig = Signature::from_slice(e.signatures[0].signature.0.as_slice()).unwrap();
        VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_strict(&tx.hash(nid).unwrap(), &sig)
            .unwrap();
        if let OperationBody::InvokeHostFunction(op) = &tx.operations[0].body {
            let pay = fam["ops"]
                .as_array()
                .unwrap()
                .iter()
                .find(|o| o["kind"] == "pay")
                .unwrap();
            let (_, auth) = scaas_node::adapters::soroban::host_call(&pay["signed_op"]).unwrap();
            if r["op"]["invoke"]["auth"][0]["source"] == true {
                // owner 2026-11-22: a self-paid pay, SourceAccount credentials over the same invocation, the subject its source
                assert!(matches!(
                    op.auth[0].credentials,
                    stellar_xdr::SorobanCredentials::SourceAccount
                ));
                assert_eq!(op.auth[0].root_invocation, auth[0].root_invocation);
                assert_eq!(r["source"], pay["signed_op"]["from"]);
            } else {
                assert_eq!(
                    op.auth.as_slice(),
                    auth.as_slice(),
                    "the adapter's own entry"
                );
            }
            let TransactionExt::V1(d) = &tx.ext else {
                panic!("soroban data")
            };
            let want = SorobanTransactionData::from_xdr(
                unhex(r["dataXdr"].as_str().unwrap()),
                Limits::none(),
            )
            .unwrap();
            assert_eq!(d, &want);
        }
    }
}
