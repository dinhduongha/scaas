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
    (
        u16::from_be_bytes([rec[30], rec[31]]),
        u16::from_be_bytes([rec[28], rec[29]]),
    )
}

/// One storage word at the read's block (R4).
pub(crate) async fn word(
    pool: &EvmPool,
    at: &ReadAt<B256>,
    who: Address,
    slot: &W,
) -> Result<W, ReadError> {
    Ok(pool
        .storage_at(at, who, U256::from_be_bytes(*slot))
        .await?
        .to_be_bytes::<32>())
}

/// `holderOf(bytes32)`'s selector.
const HOLDER_OF: [u8; 4] = [0xfe, 0x6a, 0x9a, 0x8c];
/// `kindHome(uint16)`'s selector.
const KIND_HOME: [u8; 4] = [0x0b, 0x2e, 0xb5, 0xcc];

/// Where `ua`'s record and its PQZ attachment are held on the line of `reg`, the registry the token's `ChainEnv` names
/// (CTR-UA-70, accounts.md "Off-chain readers"; the round's review F2; an address, not a confidential word, so one `eth_call` at the
/// read's block, CLI-UAL-34's storage rule kept for every word):
/// `holderOf(ua)` once on `reg` at the read's block (one walk), `(holder, PQZ home)`: the record is read at the holder, the
/// PQZ attachment at the home, else at the holder. No holder (a native-space id, or an id no generation holds): `reg`, whose
/// records then show the absence. A registry without the view (a revert, or an answer of another length: code from before the
/// line) holds its own records: `(reg, reg)`. A failed node is the read's error.
pub(crate) async fn held_at(
    pool: &EvmPool,
    at: &ReadAt<B256>,
    reg: Address,
    ua: &W,
) -> Result<(Address, Address), ReadError> {
    let data = [&HOLDER_OF[..], &ua[..]].concat();
    match pool.call_at(at, reg, data.into()).await {
        Ok(r) => match (r.len(), r.get(12..32), r.get(76..96)) {
            (96, Some(h), Some(p)) => {
                let (holder, home) = (Address::from_slice(h), Address::from_slice(p));
                let held = if holder.is_zero() { reg } else { holder };
                Ok((held, if home.is_zero() { held } else { home }))
            }
            _ => Ok((reg, reg)),
        },
        Err(ReadError::Revert { .. }) => Ok((reg, reg)),
        Err(e) => Err(e),
    }
}

/// Where kind `kind`'s list lives on `reg`'s line (`kindHome(kind)`, CTR-UA-29: a kind's list is in its home), else `reg`
/// (no home, or a registry without the view).
pub(crate) async fn kind_home(
    pool: &EvmPool,
    at: &ReadAt<B256>,
    reg: Address,
    kind: u16,
) -> Result<Address, ReadError> {
    let mut data = KIND_HOME.to_vec();
    data.extend_from_slice(&[0u8; 30]);
    data.extend_from_slice(&kind.to_be_bytes());
    match pool.call_at(at, reg, data.into()).await {
        Ok(r) => match (r.len(), r.get(12..32)) {
            (32, Some(h)) if h.iter().any(|b| *b != 0) => Ok(Address::from_slice(h)),
            _ => Ok(reg),
        },
        Err(ReadError::Revert { .. }) => Ok(reg),
        Err(e) => Err(e),
    }
}
