// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Balances (spec §8.1): the native balance and every listed token's balance (`balanceOfUA`: a derived UA's ledger, a native
//! id's ERC-20 balance) read at **one** block under the list's policy (`read_at_block`, `Purpose::Plain`), decimal strings of
//! the smallest unit. Confidential balances are the reading layer's (plan T15), never this.
use super::tokens::{selector, token};
use super::Wallet;
use crate::op::{evm, unhex};
use crate::SdkError;
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::pool::{BlockChoice, ReadError};
use scaas_rpc::Purpose;

/// One token's balance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenBalance {
    pub address: String,
    pub display: String,
    pub decimals: u8,
    /// the smallest unit, decimal
    pub amount: String,
}

/// An account's balances at one block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Balances {
    pub block: u64,
    /// the native balance of an address or a native id (`None` for a derived UA: it holds no native coin)
    pub native: Option<String>,
    pub tokens: Vec<TokenBalance>,
}

/// The word of an id (a `0x` 20-byte address zero-padded, CTR-UA-03, or a `0x` 32-byte UA) and, for a native id, its address
/// (`Argument`: an id of another length).
pub(crate) fn id_word(id: &str) -> Result<([u8; 32], Option<Address>), SdkError> {
    let raw = unhex(&id.to_ascii_lowercase())?;
    let word: [u8; 32] = match raw.len() {
        20 => {
            let mut w = [0u8; 32];
            w.get_mut(12..)
                .ok_or(SdkError::Internal)?
                .copy_from_slice(&raw);
            w
        }
        32 => raw.try_into().map_err(|_| SdkError::Argument)?,
        _ => return Err(SdkError::Argument),
    };
    let native = match (word.get(..12), word.get(12..)) {
        (Some(h), Some(a)) if h.iter().all(|b| *b == 0) => Some(Address::from_slice(a)),
        _ => None,
    };
    Ok((word, native))
}

impl Wallet {
    /// The balances of `id` (a `0x` 20-byte address or a `0x` 32-byte UA) on `chain` at one block. `ChainUnknown`,
    /// `ProfileMismatch` (a listed token's `chainUid()`), `Argument` (an id of another length).
    pub async fn balances(&self, id: String, chain: String) -> Result<Balances, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (word, native) = id_word(&id)?;
                let (profile, _, pool) = evm(&sdk, &chain)?;
                let mut infos = Vec::with_capacity(profile.tokens.len());
                for t in &profile.tokens {
                    infos.push(token(&sdk, &chain, &t.address).await?);
                }
                let addrs: Vec<Address> = infos
                    .iter()
                    .map(|i| i.address.parse().map_err(|_| SdkError::Argument))
                    .collect::<Result<_, _>>()?;
                let mut data = selector("balanceOfUA(bytes32)");
                data.extend_from_slice(&word);
                let (pool, addrs, data) = (&pool, &addrs, &data);
                let a = pool
                    .read_at_block(BlockChoice::default(), Purpose::Plain, |at| async move {
                        let n = match native {
                            Some(a) => Some(pool.balance_at(&at, a).await?),
                            None => None,
                        };
                        let mut out = Vec::with_capacity(addrs.len());
                        for t in addrs {
                            let w = pool.call_at(&at, *t, Bytes::from(data.clone())).await?;
                            if w.len() != 32 {
                                return Err(ReadError::Failure(scaas_rpc::EndpointFailure::new(
                                    at.endpoint,
                                    scaas_rpc::FailureKind::AnswerMalformed,
                                    "a balance of no word",
                                )));
                            }
                            out.push(U256::from_be_slice(&w));
                        }
                        Ok((n, out))
                    })
                    .await?;
                let (n, amounts) = a.value;
                Ok(Balances {
                    block: a.number,
                    native: n.map(|v| v.to_string()),
                    tokens: infos
                        .into_iter()
                        .zip(amounts)
                        .map(|(i, v)| TokenBalance {
                            address: i.address,
                            display: i.display,
                            decimals: i.decimals,
                            amount: v.to_string(),
                        })
                        .collect(),
                })
            })
            .await
    }
}
