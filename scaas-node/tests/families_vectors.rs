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
