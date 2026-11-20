// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The governance-delay sentence (plan T18b; owner 2026-11-18, "as proposed"; set-auditor closing review P3-5, spec
//! 2026-11-17-set-auditor §4 O13): which of a power bit's delay sentences a wallet shows. The marks are
//! `smartcontracts/vectors/governance/governance_bits.json`'s (a bit whose `sentences` hold `atOnce`, `singleKey`, `locked`);
//! the values are read on chain at one block: the token's `factory()` and that factory's `noticePeriod()`, the token's
//! `grantDelay()`, `lockedFeatures()` and `admin()`. The delay is the longer of the notice period and the grant delay; 0 is
//! `AtOnce`. A read that fails is an error, never a guessed `AtOnce`. UNAUDITED.
use super::Admin;
use crate::op::{addr20, evm};
use crate::wallet::tokens::{selector, word};
use crate::SdkError;
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use scaas_rpc::evm::EvmPool;
use serde_json::Value;

const BITS: &str =
    include_str!("../../../../smartcontracts/vectors/governance/governance_bits.json");

/// The holder's kind as the app read it from the registry (`singleKey` is per holder: spec set-auditor §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
pub enum HolderKind {
    /// a single key (one signer)
    SingleKey,
    /// a threshold (`msig`) UA
    Threshold,
    /// a native id with code
    Contract,
}

/// One delay sentence of a power bit, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
pub enum DelaySentence {
    /// `atOnce`: the delay is 0, a holder's change applies at once
    AtOnce,
    /// the change applies after `delay` seconds, the longer of the factory's notice period and the token's grant delay
    After { delay: u64 },
    /// `singleKey`: the holder is a single key
    SingleKey,
    /// `locked`: the bit is locked and the admin is gone; nobody can revoke its holders
    Locked,
    /// a bit of the table without delay sentences
    NoDelay,
    /// a bit the table does not know
    Unknown,
}

/// The marks of `bit` in the table: `None` for a bit the table does not know; else whether it has the delay sentences.
fn marks(bit: u16) -> Result<Option<bool>, SdkError> {
    let v: Value = serde_json::from_str(BITS).map_err(|_| SdkError::Internal)?;
    let row = v
        .get("bits")
        .and_then(Value::as_array)
        .ok_or(SdkError::Internal)?
        .iter()
        .find(|b| b.get("bit").and_then(Value::as_u64) == Some(u64::from(bit)));
    Ok(row.map(|b| {
        let s = b.get("sentences");
        ["atOnce", "singleKey", "locked"]
            .iter()
            .all(|k| s.and_then(|s| s.get(k)).is_some())
    }))
}

async fn read(pool: &EvmPool, to: [u8; 20], sig: &str) -> Result<Vec<u8>, SdkError> {
    let tx = alloy::rpc::types::TransactionRequest::default()
        .with_to(Address::from(to))
        .with_input(Bytes::from(selector(sig)));
    let b = pool.call_tx(tx).await.map_err(crate::op::sim)?;
    word(&b, 0)?;
    Ok(b.to_vec())
}

fn small(w: &[u8]) -> Result<u64, SdkError> {
    crate::wallet::tokens::small(word(w, 0)?)
}

impl Admin {
    /// The delay sentences of power bit `bit` of `token` (spec set-auditor §4): `Unknown` for a bit the table does not know,
    /// `NoDelay` for one without delay sentences; else `AtOnce` or `After { delay }`, then `SingleKey` when the holder is a
    /// single key, then `Locked` while the bit is locked and the admin is 0. Every value is read; a failed read is the error.
    pub async fn governance_delay(
        &self,
        chain: String,
        token: String,
        bit: u16,
        holder: Option<HolderKind>,
    ) -> Result<Vec<DelaySentence>, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                match marks(bit)? {
                    None => return Ok(vec![DelaySentence::Unknown]),
                    Some(false) => return Ok(vec![DelaySentence::NoDelay]),
                    Some(true) => {}
                }
                let token = addr20(&token.to_ascii_lowercase())?;
                let (_, _, pool) = evm(&sdk, &chain)?;
                let f = read(&pool, token, "factory()").await?;
                let factory: [u8; 20] = word(&f, 0)?
                    .get(12..)
                    .and_then(|a| a.try_into().ok())
                    .ok_or(SdkError::Argument)?;
                let notice = small(&read(&pool, factory, "noticePeriod()").await?)?;
                let grant = small(&read(&pool, token, "grantDelay()").await?)?;
                let locked = read(&pool, token, "lockedFeatures()").await?;
                let admin = read(&pool, token, "admin()").await?;
                let delay = notice.max(grant);
                let mut out = vec![if delay == 0 {
                    DelaySentence::AtOnce
                } else {
                    DelaySentence::After { delay }
                }];
                if holder == Some(HolderKind::SingleKey) {
                    out.push(DelaySentence::SingleKey);
                }
                // bit `bit` of the 256-bit word, big-endian
                let byte = locked
                    .get(31 - usize::from(bit / 8))
                    .ok_or(SdkError::Argument)?;
                let admin_gone = word(&admin, 0)?.iter().all(|b| *b == 0);
                if byte & (1 << (bit % 8)) != 0 && admin_gone {
                    out.push(DelaySentence::Locked);
                }
                Ok(out)
            })
            .await
    }
}
