//! `UaRegistry` (spec §3, §4): the UA records of a Soroban network and the per-kind verifiers. T2 holds the digests
//! (`digest`), the verifiers (`verify`, `webauthn`) and the `MemberSig[]` decoder (`abi`); the contract entries are T3.
//! `ua_message` is always computed here, never taken from an argument, and the SDK's `hazmat` feature is never enabled
//! (spec §2): the host-hash-only `Hash<32>` type carries it into the verifiers.
#![no_std]
#![cfg_attr(not(test), allow(dead_code))] // T2 has no entries yet: T3 calls these from `register` / `require_authorized`
use soroban_sdk::contracterror;

pub(crate) mod abi;
pub(crate) mod digest;
pub(crate) mod verify;
pub(crate) mod webauthn;

/// SOR-D16. A host crypto failure (ed25519 / P-256 / ML-DSA verify) is a host error, not `Pop` (plan finding F1).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    KindDisabled = 1,
    KeyData = 2,
    IdInNativeSpace = 3,
    AlreadyRegistered = 4,
    KeyInUse = 5,
    MemberUnknown = 6,
    Attrs = 7,
    Pop = 8,
    NotRegistered = 9,
    Unauthorized = 10,
    NotVerifiable = 11,
    RelayerNotListed = 12,
}

#[cfg(test)]
mod test_verify;
