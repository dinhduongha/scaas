// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The governance-delay sentence (plan T18b; owner 2026-11-18, "as proposed"; set-auditor closing review P3-5, spec
//! 2026-11-17-set-auditor §4 O13): which of a power bit's delay sentences a wallet shows. The marks are
//! `smartcontracts/vectors/governance/governance_bits.json`'s (a bit whose `sentences` hold `atOnce`, `singleKey`, `locked`);
//! the values are read on chain as one logical read (one endpoint, the profile's final block; T26 A2-2): the token's
//! `factory()`, which must be the profile's factory, that factory's `infoOf(token)` (class TOKEN, else `TokenUncatalogued`:
//! T26 A2-3) and `noticePeriod()`, the token's `grantDelay()`, `lockedFeatures()` and `admin()`. The delay is the longer of the notice period and the grant delay; 0 is
//! `AtOnce`. A read that fails is an error, never a guessed `AtOnce`. UNAUDITED.
use super::Admin;
use crate::op::{addr20, evm, final_block};
use crate::wallet::tokens::{selector, word};
use crate::SdkError;
use alloy::primitives::{Address, Bytes};
use scaas_rpc::Purpose;
use serde_json::Value;

/// The factory's class of a token (`ContractClass.TOKEN`; `confidential::words::CLASS_TOKEN`, a module `admin` builds without).
const CLASS_TOKEN: u64 = 1;

const BITS: &str =
    include_str!("../../../../smartcontracts/vectors/governance/governance_bits.json");

/// The holder's kind as the app read it from the registry (`singleKey` is per holder: spec set-auditor §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum HolderKind {
    /// a single key (one signer)
    SingleKey,
    /// a threshold (`msig`) UA
    Threshold,
    /// a native id with code
    Contract,
}

/// One delay sentence of a power bit, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
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
                let (profile, _, pool) = evm(&sdk, &chain)?;
                // T26 A2-3: a token the profile's factory catalogued as a token, else no sentence is built from it
                let factory = profile
                    .factory
                    .as_deref()
                    .ok_or(SdkError::TokenUncatalogued)
                    .and_then(|f| addr20(&f.to_ascii_lowercase()))?;
                let mut arg = [0u8; 32];
                arg[12..].copy_from_slice(&token);
                let info = [selector("infoOf(address)").to_vec(), arg.to_vec()].concat();
                // T26 A2-2: one logical read, on one endpoint at the profile's final block
                let calls: [([u8; 20], Vec<u8>); 6] = [
                    (token, selector("factory()").to_vec()),
                    (factory, info),
                    (factory, selector("noticePeriod()").to_vec()),
                    (token, selector("grantDelay()").to_vec()),
                    (token, selector("lockedFeatures()").to_vec()),
                    (token, selector("admin()").to_vec()),
                ];
                let r = pool
                    .read_at_block(final_block(&profile), Purpose::Plain, |at| {
                        let (pool, calls) = (pool.clone(), calls.clone());
                        async move {
                            let mut out = Vec::with_capacity(calls.len());
                            for (to, data) in calls {
                                out.push(
                                    pool.call_at(&at, Address::from(to), Bytes::from(data))
                                        .await?
                                        .to_vec(),
                                );
                            }
                            Ok(out)
                        }
                    })
                    .await?
                    .value;
                let [f, info, notice, grant, locked, admin] = &r[..] else {
                    return Err(SdkError::Internal);
                };
                // `Created(address addr, bytes32 creatorId, uint16 contractClass, …)`: the class in word 2
                if word(f, 0)?.get(12..) != Some(&factory[..])
                    || small(info.get(64..).unwrap_or_default())? != CLASS_TOKEN
                {
                    return Err(SdkError::TokenUncatalogued);
                }
                let (notice, grant) = (small(notice)?, small(grant)?);
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
