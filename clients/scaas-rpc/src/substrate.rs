// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Substrate JSON-RPC (SDK plan T32's read part; decisions CLI-SDK-32's Change of 2026-11-22) on the family client: one code
//! path for Polkadot Hub's Substrate side and the relay chain alike, the profile naming which by its genesis hash. The network
//! identity is `chain_getBlockHash(0)`; the head is the finalized head (`chain_getFinalizedHead`, its number by
//! `chain_getHeader`); storage is read at a block hash (`state_getStorage`), and `System.Account`'s value is decoded by a bounded
//! SCALE reader of the fixed `AccountInfo` layout. The storage key is the caller's (`scaas-ua`'s `system_account_key`). No key,
//! no signing (CLI-RPC-01). UNAUDITED.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::json;
use web_time::Instant;

/// `frame_system::AccountInfo<u32, pallet_balances::AccountData<u128>>`: four `u32` counters, then `free`, `reserved`, `frozen`
/// and `flags` as `u128`, little-endian: 80 bytes exactly.
pub const ACCOUNT_INFO_LEN: usize = 80;

/// `System.Account`'s value of one account (an account with no entry holds zeros).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct AccountInfo {
    pub nonce: u32,
    pub consumers: u32,
    pub providers: u32,
    pub sufficients: u32,
    pub free: u128,
    pub reserved: u128,
    pub frozen: u128,
    pub flags: u128,
}

impl AccountInfo {
    /// The SCALE value `b`, exactly [`ACCOUNT_INFO_LEN`] bytes; `None` for any other length.
    pub fn decode(b: &[u8]) -> Option<Self> {
        if b.len() != ACCOUNT_INFO_LEN {
            return None;
        }
        let u32_at = |i: usize| Some(u32::from_le_bytes(b.get(i..i + 4)?.try_into().ok()?));
        let u128_at = |i: usize| Some(u128::from_le_bytes(b.get(i..i + 16)?.try_into().ok()?));
        Some(Self {
            nonce: u32_at(0)?,
            consumers: u32_at(4)?,
            providers: u32_at(8)?,
            sufficients: u32_at(12)?,
            free: u128_at(16)?,
            reserved: u128_at(32)?,
            frozen: u128_at(48)?,
            flags: u128_at(64)?,
        })
    }
}

/// The family client of one Substrate chain, named by its genesis hash.
pub struct Substrate {
    pub client: Client,
    genesis: String,
}

impl Substrate {
    /// The client of `client`'s endpoints, each of which must name `genesis` (`0x` + 64 hex) as its block 0.
    pub fn new(client: Client, genesis: &str) -> Self {
        Self {
            client,
            genesis: genesis.to_ascii_lowercase(),
        }
    }

    /// Endpoint `i`'s finalized head: its hash (`0x` + 64 hex, lower case) and its header's number (a hex `u64`).
    pub async fn finalized(&self, i: usize) -> Result<(String, u64), FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.finalized_unchecked(i).await
    }

    async fn finalized_unchecked(&self, i: usize) -> Result<(String, u64), FamilyError> {
        let v = self
            .client
            .rpc_at(i, "chain_getFinalizedHead", json!([]))
            .await?;
        let hash = v
            .as_str()
            .filter(|h| is_hash(h))
            .ok_or_else(|| malformed(i, "a finalized head that is not a 32-byte hash"))?
            .to_ascii_lowercase();
        let h = self
            .client
            .rpc_at(i, "chain_getHeader", json!([hash]))
            .await?;
        let n = h["number"]
            .as_str()
            .and_then(|n| n.strip_prefix("0x"))
            .and_then(|n| u64::from_str_radix(n, 16).ok())
            .ok_or_else(|| malformed(i, "a header without a u64 number"))?;
        Ok((hash, n))
    }

    /// `System.Account` of the account whose storage key is `key`, read on endpoint `i` at block `at`: its decoded
    /// `AccountInfo`, zeros for no entry (`null`); a value other than `0x` + 160 hex digits is `AnswerMalformed`.
    pub async fn account(
        &self,
        i: usize,
        key: &[u8],
        at: &str,
    ) -> Result<AccountInfo, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        let v = self
            .client
            .rpc_at(i, "state_getStorage", json!([hex(key), at]))
            .await?;
        if v.is_null() {
            return Ok(AccountInfo::default());
        }
        v.as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .and_then(unhex)
            .and_then(|b| AccountInfo::decode(&b))
            .ok_or_else(|| malformed(i, "an AccountInfo that is not 80 bytes of hex"))
    }

    /// Endpoint `i`'s block hash at height `n` (`chain_getBlockHash`, lower case), `None` where it has none.
    pub async fn block_hash(&self, i: usize, n: u64) -> Result<Option<String>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.hash_unchecked(i, n).await
    }

    /// [`Substrate::block_hash`] without the identity check (the probe's own read).
    async fn hash_unchecked(&self, i: usize, n: u64) -> Result<Option<String>, FamilyError> {
        let v = self
            .client
            .rpc_at(i, "chain_getBlockHash", json!([n]))
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        v.as_str()
            .filter(|h| is_hash(h))
            .map(|h| Some(h.to_ascii_lowercase()))
            .ok_or_else(|| malformed(i, "a block hash that is not 32 bytes"))
    }
}

fn is_hash(h: &str) -> bool {
    h.len() == 66 && h.starts_with("0x") && h.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| s.get(i..i + 2).and_then(|d| u8::from_str_radix(d, 16).ok()))
        .collect()
}

fn malformed(i: usize, why: &str) -> FamilyError {
    FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}

impl Probe for Substrate {
    type Hash = String;
    /// `chain_getBlockHash(0)` against the configured genesis.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        match self.hash_unchecked(i, 0).await.map_err(|e| unread(i, e))? {
            Some(g) => Ok(g == self.genesis),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "no block 0",
            )),
        }
    }
    /// The finalized head's number.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.finalized_unchecked(i)
            .await
            .map(|(_, n)| n)
            .map_err(|e| unread(i, e))
    }
    async fn named(
        &self,
        i: usize,
        _: BlockChoice,
        d: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        self.head(i, d).await
    }
    async fn header(
        &self,
        i: usize,
        n: u64,
        _: Option<Instant>,
    ) -> Result<String, EndpointFailure> {
        self.hash_unchecked(i, n)
            .await
            .map_err(|e| unread(i, e))?
            .ok_or_else(|| {
                EndpointFailure::new(i, FailureKind::AnswerMalformed, "no block at that height")
            })
    }
}
