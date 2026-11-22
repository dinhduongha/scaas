// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sui (plan 2026-11-17-scaas-sdk T24.sui): the id of an owner's `Account<T>` under the token's `Registry<T>`,
//! `sui::derived_object::derive_address(registry, owner)` (NET-SUI-03), as scaas-node `adapters/sui.rs` `derive_account` and
//! clientkeys `src/fam/sui.js`; rows in `smartcontracts/vectors/families/sui.json`. UNAUDITED.
use blake2::Digest as _;

/// `bcs(TypeTag)` of `0x2::derived_object::DerivedObjectKey<address>`: Struct (7), the address `0x2`, the module and the name
/// (each its length byte), one type argument, `address` (4).
const KEY_TYPE: [u8; 67] = {
    let mut t = [0u8; 67];
    t[0] = 7;
    t[32] = 2;
    let tail = *b"\x0ederived_object\x10DerivedObjectKey\x01\x04";
    let mut i = 0;
    while i < tail.len() {
        t[33 + i] = tail[i];
        i += 1;
    }
    t
};

/// `derive_address(registry, owner)` = blake2b-256(0xf0 ‖ registry ‖ u64le(32) ‖ owner ‖ [`KEY_TYPE`]): the child-object
/// intent, the parent, the key's BCS length and bytes (an address), the key's type tag.
pub fn account_of(registry: &[u8; 32], owner: &[u8; 32]) -> [u8; 32] {
    let mut h = blake2::Blake2b::<blake2::digest::consts::U32>::new();
    h.update([0xf0]);
    h.update(registry);
    h.update(32u64.to_le_bytes());
    h.update(owner);
    h.update(KEY_TYPE);
    h.finalize().into()
}
