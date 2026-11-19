// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! What the Zether and the PQZ reading layers share (spec §9.4): the word type, the read's purpose (R1), slot arithmetic, one
//! storage word at the read's block (R4), the factory index's record (R5). UNAUDITED.
use alloy::primitives::{Address, B256, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{ReadAt, ReadError};
use scaas_rpc::Purpose;

pub(crate) type W = [u8; 32];

/// R1: every read of the reading layers feeds a decryption.
pub(crate) const PURPOSE: Purpose = Purpose::FeedsDecryption;
/// `OpenFactory._rec` (slot 8, two words; word 1: `contractClass(16) ‖ kind(16) ‖ …` from the low end), class TOKEN; held to the
/// pin `test/zether/ZetherStateVectors.t.sol` by zether-prover's `zether-read-balance` and ua-rs's `pqz-read`.
pub(crate) const REC_SLOT: u64 = 8;
pub(crate) const CLASS_TOKEN: u16 = 1;

/// `a + i` (mod 2^256), big-endian.
pub(crate) fn add(a: &W, i: u64) -> W {
    U256::from_be_bytes(*a)
        .wrapping_add(U256::from(i))
        .to_be_bytes::<32>()
}

pub(crate) fn be(n: u64) -> W {
    U256::from(n).to_be_bytes::<32>()
}

/// `keccak256(key ‖ base)`: a mapping's value slot.
pub(crate) fn map_slot(key: &W, base: &W) -> W {
    scaas_ua::keccak256(&[key.as_slice(), base.as_slice()].concat())
}

pub(crate) fn pad(a: &[u8; 20]) -> W {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}

/// `_rec[token]`'s word 1 slot.
pub(crate) fn rec_slot(token: &[u8; 20]) -> W {
    add(&map_slot(&pad(token), &be(REC_SLOT)), 1)
}

/// `(contractClass, kind)` of `_rec[token]`'s word 1.
pub(crate) fn class_kind(rec: &W) -> (u16, u16) {
    (u16::from_be_bytes([rec[30], rec[31]]), u16::from_be_bytes([rec[28], rec[29]]))
}

/// One storage word at the read's block (R4).
pub(crate) async fn word(pool: &EvmPool, at: &ReadAt<B256>, who: Address, slot: &W) -> Result<W, ReadError> {
    Ok(pool
        .storage_at(at, who, U256::from_be_bytes(*slot))
        .await?
        .to_be_bytes::<32>())
}
