// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Balances (spec §8.1): the native balance and every listed token's balance (`balanceOfUA`: a derived UA's ledger, a native
//! id's ERC-20 balance) read at **one** block under the list's policy (`read_at_block`, `Purpose::Plain`), decimal strings of
//! the smallest unit. Confidential balances are the reading layer's (plan T15), never this.
use super::Wallet;
use crate::SdkError;
#[cfg(feature = "evm")]
use {
    super::tokens::{selector, token},
    crate::op::{evm, unhex},
    alloy::primitives::{Address, Bytes, U256},
    scaas_rpc::pool::{BlockChoice, ReadError},
    scaas_rpc::Purpose,
};

/// One token's balance.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct TokenBalance {
    pub address: String,
    pub display: String,
    pub decimals: u8,
    /// the smallest unit, decimal; empty when `unknown` is set
    pub amount: String,
    /// set when the balance cannot be read, with its reason (owner 2026-11-23, T26 B2-15: a frozen TON jetton wallet,
    /// `frozen`): the amount is unknown, never a false 0
    pub unknown: Option<String>,
}

/// An account's balances at one block.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[serde(deny_unknown_fields)]
pub struct Balances {
    pub block: u64,
    /// the native balance of an address or a native id (`None` for a derived UA: it holds no native coin)
    pub native: Option<String>,
    pub tokens: Vec<TokenBalance>,
}

/// The word of an id (a `0x` 20-byte address zero-padded, CTR-UA-03, or a `0x` 32-byte UA) and, for a native id, its address
/// (`Argument`: an id of another length).
#[cfg(feature = "evm")]
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
    /// The balances of `id` on `chain` at one block. EVM: `id` a `0x` 20-byte address or a `0x` 32-byte UA; another family
    /// (spec §8.7): the family's printed form, or a `0x` 32-byte UA id where the family keeps a UA ledger, read at one final
    /// height. `ChainUnknown`, `ProfileMismatch` (a listed token's `chainUid()`), `Argument` (an id of another form),
    /// `FeatureMissing` (a family this build does not read).
    pub async fn balances(&self, id: String, chain: String) -> Result<Balances, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let c = &sdk.chain(&chain)?;
                if c.profile.family != crate::Family::Evm {
                    return super::families::balances(&sdk, &chain, &id).await;
                }
                // no EVM profile opens without `evm` (`Sdk::open`)
                #[cfg(not(feature = "evm"))]
                let r = Err(SdkError::FeatureMissing);
                // an SS58 id on a profile with a Substrate side (Polkadot Hub): its native DOT (T32's read part)
                #[cfg(feature = "evm")]
                let r = if !id.starts_with("0x")
                    && matches!(
                        c.profile.family_params,
                        Some(crate::FamilyParams::Substrate { .. })
                    ) {
                    super::families::substrate_balances(c, &id).await
                } else {
                    evm_balances(&sdk, &chain, &id).await
                };
                r
            })
            .await
    }
}

/// [`Wallet::balances`] of an EVM profile.
#[cfg(feature = "evm")]
async fn evm_balances(sdk: &crate::Sdk, chain: &str, id: &str) -> Result<Balances, SdkError> {
    let (word, native) = id_word(id)?;
    let (profile, _, pool) = evm(sdk, chain)?;
    let mut infos = Vec::with_capacity(profile.tokens.len());
    for t in &profile.tokens {
        infos.push(token(sdk, chain, &t.address).await?);
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
                unknown: None,
            })
            .collect(),
    })
}
