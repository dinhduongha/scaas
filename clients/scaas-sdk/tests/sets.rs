// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T1 `sets` (`--test sets` at every PQZ set): the build's one set bit is the set `scaas-ua` proves, and another set is
//! `PqzSetMismatch` by that name through the SDK's error.

use scaas_sdk::{bits, Sdk, SdkError};

#[test]
fn one_set_bit_and_it_is_the_build_set() {
    let names = [
        (bits::PQZ_SET_N2048_KMAX1024, "n2048-kmax1024"),
        (bits::PQZ_SET_N2304_KMAX4096, "n2304-kmax4096"),
        (bits::PQZ_SET_N2560_KMAX16384, "n2560-kmax16384"),
        (bits::PQZ_SET_N2816_KMAX65536, "n2816-kmax65536"),
    ];
    let f = Sdk::features();
    let on: Vec<_> = names
        .iter()
        .filter(|(b, _)| f & b != 0)
        .map(|(_, n)| *n)
        .collect();
    assert_eq!(on.len(), 1, "{on:?}");
    assert_eq!(on[0], scaas_ua::facade::pqz::pqz_set().name);
    assert_ne!(f & bits::PQZ, 0);
}

#[test]
fn another_set_is_pqz_set_mismatch() {
    let mine = scaas_ua::facade::pqz::pqz_set();
    assert!(scaas_ua::facade::pqz::check_set(&mine).is_ok(), "control");
    let mut other = mine.clone();
    other.pqzl_id[0] ^= 1;
    let e: SdkError = scaas_ua::facade::pqz::check_set(&other).unwrap_err().into();
    assert_eq!(e.code(), "PqzSetMismatch");
}
