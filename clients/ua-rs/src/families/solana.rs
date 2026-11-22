// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Solana (plan 2026-11-17-scaas-sdk T24.solana): `Pubkey::find_program_address` and the SCaaS Account of an owner (seeds
//! `["acct", owner]` under the program), as scaas-node `adapters/solana.rs` `find_pda` / `account_of` and clientkeys
//! `src/fam/solana.js`; rows in `smartcontracts/vectors/families/solana.json`. UNAUDITED.
use curve25519_dalek::edwards::CompressedEdwardsY;
use sha2::{Digest, Sha256};

/// Solana's bounds: at most 16 seeds with the bump among them, each of at most 32 bytes (`MAX_SEEDS`, `MAX_SEED_LEN`).
pub const MAX_SEEDS: usize = 16;
pub const MAX_SEED_LEN: usize = 32;

/// On the ed25519 curve as Solana decides (`CompressedEdwardsY::decompress().is_some()`).
pub fn on_curve(b: &[u8; 32]) -> bool {
    CompressedEdwardsY(*b).decompress().is_some()
}

/// `Pubkey::find_program_address(seeds, program)`: the first bump from 255 down whose
/// `sha256(seeds ‖ bump ‖ program ‖ "ProgramDerivedAddress")` is off the curve, with that bump. `None`: more than 15 seeds,
/// a seed above 32 bytes, or no bump (as Solana's `try_find_program_address`).
pub fn find_pda(seeds: &[&[u8]], program: &[u8; 32]) -> Option<([u8; 32], u8)> {
    if seeds.len() >= MAX_SEEDS || seeds.iter().any(|s| s.len() > MAX_SEED_LEN) {
        return None;
    }
    (0..=255u8).rev().find_map(|bump| {
        let mut h = Sha256::new();
        seeds.iter().for_each(|s| h.update(s));
        h.update([bump]);
        h.update(program);
        h.update(b"ProgramDerivedAddress");
        let a: [u8; 32] = h.finalize().into();
        (!on_curve(&a)).then_some((a, bump))
    })
}

/// The SCaaS Account of `owner` under `program` (NET-SOL: seeds `["acct", owner]`).
pub fn account_of(program: &[u8; 32], owner: &[u8; 32]) -> Option<[u8; 32]> {
    find_pda(&[b"acct", owner], program).map(|(a, _)| a)
}
