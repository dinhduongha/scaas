// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! History (spec §8.4): an account's events on the profile's listed tokens read from chain logs through `scaas-rpc`'s
//! `logs_range` (both bounds, at most one span window of `LOG_RANGE_MAX` blocks per call, `Purpose::Plain`), the SDK paging
//! backwards itself from the profile's final block, newest first; the first page carries the account's operations of §13.4. No
//! indexer. A watched account's new items arrive as `Event::HistoryAdded` (`crate::watch`). UNAUDITED.
use super::balances::id_word;
use super::tokens::token;
use super::Wallet;
use crate::op::{evm, final_number, hex, state};
use crate::SdkError;
use alloy::primitives::{Address, B256};
use alloy::rpc::types::Filter;
use scaas_rpc::evm::{EvmPool, LOG_RANGE_MAX};
use scaas_rpc::Purpose;
use std::collections::HashSet;

/// A position in a chain's logs: a page holds items strictly older than it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub block: u64,
    pub log_index: u64,
}

/// One log naming the account in an indexed field.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct HistoryItem {
    pub block: u64,
    pub tx_hash: String,
    pub log_index: u64,
    /// the token that emitted it, `0x` + 40 hex lower case
    pub contract: String,
    /// `UATransfer`, `Transfer`, `PaymentSettled`, `Wrapped`, `Unwrapped`, `UnwrappedToUA`, else `unknown`
    pub event: String,
    pub topics: Vec<String>,
    pub data: String,
}

/// One of the account's operations in `sdk.state` (spec §13.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct OpItem {
    pub op: String,
    pub entry: String,
    /// `signed`, `sent`, `landed`, `reverted`, `consumed`, `expired`
    pub state: String,
    pub landed_block: Option<u64>,
}

/// A page of history.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct HistoryPage {
    pub items: Vec<HistoryItem>,
    /// on the first page (`before` none) only
    pub ops: Vec<OpItem>,
    /// where the next page starts; `None` after block 0
    pub next: Option<Cursor>,
}

const EVENTS: [(&str, &str); 6] = [
    ("UATransfer", "UATransfer(bytes32,bytes32,uint256)"),
    ("Transfer", "Transfer(address,address,uint256)"),
    (
        "PaymentSettled",
        "PaymentSettled(address,address,uint256,uint256,address,bytes32)",
    ),
    ("Wrapped", "Wrapped(address,address,uint256,uint256)"),
    (
        "Unwrapped",
        "Unwrapped(address,address,address,uint256,uint256)",
    ),
    (
        "UnwrappedToUA",
        "UnwrappedToUA(address,address,bytes32,uint256,uint256)",
    ),
];

fn event_name(topic0: Option<&B256>) -> String {
    EVENTS
        .iter()
        .find(|(_, sig)| topic0.is_some_and(|t| t.0 == scaas_ua::keccak256(sig.as_bytes())))
        .map_or("unknown", |(n, _)| n)
        .into()
}

/// The logs of `tokens` in `[from, to]` (one span window) whose indexed field 1, 2 or 3 is `word`, newest first.
pub(crate) async fn scan(
    pool: &EvmPool,
    tokens: &[Address],
    word: B256,
    from: u64,
    to: u64,
) -> Result<Vec<HistoryItem>, SdkError> {
    let (mut seen, mut out) = (HashSet::new(), vec![]);
    for pos in 1..=3 {
        let f = Filter::new().address(tokens.to_vec());
        let f = match pos {
            1 => f.topic1(word),
            2 => f.topic2(word),
            _ => f.topic3(word),
        };
        for l in pool.logs_range(from, to, f, Purpose::Plain).await?.value {
            // a log without its position is no item (a pending log; the read is at the final block)
            let (Some(block), Some(log_index)) = (l.block_number, l.log_index) else {
                continue;
            };
            if seen.insert((block, log_index)) {
                out.push(HistoryItem {
                    block,
                    tx_hash: l.tx_hash.map(|h| hex(&h.0)).unwrap_or_default(),
                    log_index,
                    contract: hex(l.address.as_slice()),
                    event: event_name(l.topics.first()),
                    topics: l.topics.iter().map(|t| hex(&t.0)).collect(),
                    data: hex(&l.data),
                });
            }
        }
    }
    out.sort_by_key(|i| std::cmp::Reverse((i.block, i.log_index)));
    Ok(out)
}

/// The profile's listed tokens of `chain`, each checked once per session (`ProfileMismatch`).
pub(crate) async fn listed(sdk: &crate::Sdk, chain: &str) -> Result<Vec<Address>, SdkError> {
    let (profile, _, _) = evm(sdk, chain)?;
    let mut out = Vec::with_capacity(profile.tokens.len());
    for t in &profile.tokens {
        let i = token(sdk, chain, &t.address).await?;
        out.push(i.address.parse().map_err(|_| SdkError::Argument)?);
    }
    Ok(out)
}

impl Wallet {
    /// The history of `account` (a `0x` 20-byte address or a `0x` 32-byte UA) on `chain`: one span window per call, at or
    /// below the profile's final block, strictly older than `before`, at most `limit` items, newest first. Writes nothing (no
    /// cursor: a hidden set's account may be read). `ChainUnknown`, `ProfileMismatch`, `Argument` (`limit` 0, a bad id).
    pub async fn history(
        &self,
        account: String,
        chain: String,
        before: Option<Cursor>,
        limit: u32,
    ) -> Result<HistoryPage, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                if limit == 0 {
                    return Err(SdkError::Argument);
                }
                let (word, _) = id_word(&account)?;
                let (profile, _, pool) = evm(&sdk, &chain)?;
                let tokens = listed(&sdk, &chain).await?;
                let fin = final_number(&pool, &profile).await?;
                let top = before.map_or(fin, |c| c.block.min(fin));
                let from = top.saturating_sub(LOG_RANGE_MAX - 1);
                let mut items = scan(&pool, &tokens, B256::from(word), from, top).await?;
                items.retain(|i| {
                    before.is_none_or(|c| (i.block, i.log_index) < (c.block, c.log_index))
                });
                let next = if items.len() > limit as usize {
                    items.truncate(limit as usize);
                    items.last().map(|i| Cursor {
                        block: i.block,
                        log_index: i.log_index,
                    })
                } else {
                    from.checked_sub(1).map(|block| Cursor {
                        block,
                        log_index: u64::MAX,
                    })
                };
                let ops = if before.is_none() {
                    state::rows(&sdk)
                        .await?
                        .into_iter()
                        .filter(|r| r.chain == chain && r.from.eq_ignore_ascii_case(&account))
                        .map(|r| OpItem {
                            op: r.op,
                            entry: r.entry,
                            state: r.state,
                            landed_block: r.landed.map(|l| l.0),
                        })
                        .collect()
                } else {
                    vec![]
                };
                Ok(HistoryPage { items, ops, next })
            })
            .await
    }
}
