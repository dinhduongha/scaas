// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The families' rows of smartcontracts/vectors/families/ (written by clientkeys, read by ua-rs too) against this node's
//! adapters: Solana's program addresses and the SCaaS Account of an owner (`adapters::solana::{find_pda, account_of}`).
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
        assert_eq!(account_of(&p, &o), key(r["account"].as_str().unwrap()).unwrap());
    }
}
