// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan 2026-11-17-scaas-sdk T24.solana: `families::solana` against every row of smartcontracts/vectors/families/solana.json
//! (written by clientkeys), the refusals beside their controls.
use scaas_ua::families::solana::{account_of, find_pda, on_curve};
use serde_json::Value;

fn rows() -> Value {
    let p = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../smartcontracts/vectors/families/solana.json"
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}
fn hexb(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
/// base58 (Bitcoin alphabet) to 32 bytes, for the test only
fn b58(s: &Value) -> [u8; 32] {
    const A: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let s = s.as_str().unwrap();
    let mut n = vec![0u8; 32];
    for c in s.bytes() {
        let mut carry = A.iter().position(|&a| a == c).unwrap() as u32;
        for b in n.iter_mut().rev() {
            carry += (*b as u32) * 58;
            *b = carry as u8;
            carry >>= 8;
        }
        assert_eq!(carry, 0);
    }
    n.try_into().unwrap()
}

#[test]
fn pda_rows() {
    let v = rows();
    let pda = v["pda"].as_array().unwrap();
    assert!(pda.len() >= 7 && pda.iter().any(|r| r["bump"].as_u64().unwrap() < 255));
    for r in pda {
        let seeds: Vec<Vec<u8>> = r["seeds"].as_array().unwrap().iter().map(hexb).collect();
        let s: Vec<&[u8]> = seeds.iter().map(|x| x.as_slice()).collect();
        let (a, bump) = find_pda(&s, &b58(&r["program"])).unwrap();
        assert_eq!(
            (a, bump as u64),
            (b58(&r["address"]), r["bump"].as_u64().unwrap())
        );
        assert!(!on_curve(&a));
    }
}

#[test]
fn account_rows() {
    let v = rows();
    for r in v["account"].as_array().unwrap() {
        let (p, o) = (b58(&r["program"]), b58(&r["owner"]));
        assert_eq!(account_of(&p, &o).unwrap(), b58(&r["account"]));
        assert_eq!(
            find_pda(&[b"acct", &o], &p).unwrap().1 as u64,
            r["bump"].as_u64().unwrap()
        );
    }
}

#[test]
fn refusals_beside_controls() {
    let p = [7u8; 32];
    let empty: &[u8] = &[];
    assert!(find_pda(&[empty; 16], &p).is_none());
    assert!(find_pda(&[empty; 15], &p).is_some());
    assert!(find_pda(&[&[0u8; 33]], &p).is_none());
    assert!(find_pda(&[&[0u8; 32]], &p).is_some());
    // the rows' refused inputs: the program row of 31 bytes is a type error here; the seed rows are refused
    for r in rows()["refused"].as_array().unwrap() {
        let seeds: Vec<Vec<u8>> = r["seeds"].as_array().unwrap().iter().map(hexb).collect();
        let s: Vec<&[u8]> = seeds.iter().map(|x| x.as_slice()).collect();
        if let Ok(prog) = <[u8; 32]>::try_from(hexb(&r["program"])) {
            assert!(find_pda(&s, &prog).is_none(), "{}", r["why"]);
        }
    }
    // the base point is on the curve
    let mut g = [0x66u8; 32];
    g[0] = 0x58;
    assert!(on_curve(&g));
}
