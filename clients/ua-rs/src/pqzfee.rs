// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Round 3t (CTR-PQZ-36, verifier fee spec 2026-11-11 §5.1, §7.2, §12): the `GovernanceRouter`'s `UASetVerifierFee`, its
//! struct hash and digest in the router's domain (`MetaTxLib.canon`'s zeroing of an unbound `relayer` / `feeRecipient`; ua-rs
//! signs every kind), and a debit's public fee word `txFee + verifierFee + M·d` (display and the node / verifier parity: a
//! wallet's witness takes word 256 of the token's statement view, never this sum). Pinned by
//! `smartcontracts/vectors/typed/typed_ops.json` (clientkeys) and `pqz/verifier_fee.json` (its forge writer). The contract
//! decides; nothing here is a check of record. UNAUDITED.
use crate::regulated::Envelope;
use crate::{address_word, keccak, keccak256, word};

const ENVELOPE: &str =
    "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient";

/// `UASetVerifierFee(…)`.
pub fn set_verifier_fee_type() -> String {
    format!("UASetVerifierFee(bytes32 from,address target,uint64 next,{ENVELOPE})")
}

/// `hashStruct(UASetVerifierFee)`: `next` the new fee; the envelope's `fee` the relay fee.
pub fn set_verifier_fee_struct_hash(e: &Envelope, target: &[u8; 20], next: u64) -> [u8; 32] {
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let w = [keccak256(set_verifier_fee_type().as_bytes()), e.from, address_word(target), word(next), e.batch, e.nonce,
        e.valid_until, word(e.mode as u64), canon(e.mode & 1 != 0, &e.relayer), e.fee, canon(e.mode & 2 != 0, &e.fee_recipient)];
    keccak(&w.iter().map(|x| &x[..]).collect::<Vec<_>>())
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`, the router's domain (`regulated::router_domain_separator`).
pub fn digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], domain_separator, struct_hash])
}

/// A debit's fee word (header word 256): `txFee = confidentialFee` with a beneficiary else 0, plus the verifier fee in force
/// (`OFFCHAIN`; 0 on `PRECOMPILE`), plus `legs · decoyFee` (op 7). `None` at `2^64` or more, as the token refuses it.
pub fn pqz_fee_word(confidential_fee: u64, with_beneficiary: bool, verifier_fee: u64, legs: u64, decoy_fee: u64) -> Option<u64> {
    let tx = if with_beneficiary { confidential_fee as u128 } else { 0 };
    let w = tx + verifier_fee as u128 + legs as u128 * decoy_fee as u128;
    u64::try_from(w).ok()
}
