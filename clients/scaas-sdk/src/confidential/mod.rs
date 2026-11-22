// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `confidential` (spec §9, CLI-SDK-10; plans T15, T16): Zether (feature `zether`) and PQZ (feature `pqz`) keys, balances and
//! operations over the SDK's reading layers ([`read`] for Zether, [`pqz`]'s for PQZ, spec §9.4), and the PQZ verdicts
//! ([`verdict`], spec §9.3). Zether and PQZ are separate: separate keys, words, facades and features. The key stays in `ua-rs`'s Zether facade: every decryption and proof runs in its JSON `call`, whose
//! requests carry no key (CLI-UAL-06), over words the reading layer read at one final block. A decryption runs only after the
//! read returned and its result goes to the caller (the holder) only: nothing the SDK sends, reads next or retries depends on
//! it (spec §9.5). UNAUDITED.
#[cfg(feature = "pqz")]
pub(crate) mod pqz;
#[cfg(feature = "pqz")]
mod pqz_debit;
#[cfg(feature = "zether")]
pub(crate) mod read;
#[cfg(feature = "pqz")]
mod verdict;
pub(crate) mod words;
#[cfg(feature = "zether")]
mod zether;

#[cfg(feature = "pqz")]
pub use pqz::*;
#[cfg(feature = "pqz")]
pub use pqz_debit::*;
#[cfg(feature = "pqz")]
pub use verdict::PqzVerdictRequest;
#[cfg(feature = "zether")]
pub use zether::*;

#[cfg(feature = "zether")]
use crate::vault::OpenSeed;
use crate::Sdk;
#[cfg(feature = "zether")]
use crate::SdkError;
#[cfg(feature = "zether")]
use scaas_ua::facade::zether::{ZetherKey, USE_CONF};
#[cfg(feature = "zether")]
use serde_json::{json, Value};
use std::sync::Arc;

/// The UA kind `zether-bls12381`.
#[cfg(feature = "zether")]
pub(crate) const ZETHER_KIND: u16 = 0x0141;

/// The Zether key's `<coin>` on an EVM chain: the network's SLIP-44, EVM 60 (CLI-SGN-10).
#[cfg(feature = "zether")]
pub(crate) const COIN_EVM: u32 = 60;

/// The confidential module.
#[derive(Clone)]
pub struct Confidential {
    pub(crate) sdk: Arc<Sdk>,
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Sdk {
    /// The confidential module (spec §9).
    pub fn confidential(self: &Arc<Self>) -> Arc<Confidential> {
        Arc::new(Confidential { sdk: self.clone() })
    }
}

#[cfg(feature = "zether")]
/// A Zether key's public parts.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZetherKeyInfo {
    /// the UA of kind `zether-bls12381` (0x0141), `0x` + 64 hex
    pub ua: String,
    /// `Y = [x]G`, 128 bytes, `0x` hex
    pub y: String,
}

#[cfg(feature = "zether")]
/// A balance read (spec §9.4).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZetherBalanceRequest {
    pub seed: String,
    pub account: u32,
    pub chain: String,
    /// the token, `0x` + 40 hex
    pub token: String,
    /// the pending balance (received, not rolled over) instead of the spendable one
    pub pending: bool,
    /// the BSGS table and bound bits (`None`: the facade's defaults for this target)
    pub table_bits: Option<u32>,
    pub bound_bits: Option<u32>,
}

#[cfg(feature = "zether")]
/// A decrypted balance, for the holder only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZetherBalance {
    /// the smallest unit, decimal
    pub amount: String,
    /// the final block the words were read at
    pub block: u64,
    /// the account's `accSeq` at that block (what a balance cache stores)
    pub acc_seq: u64,
}

#[cfg(feature = "zether")]
/// The conf key (`m/12381/60/<account>/7`) of an open seed, kept beside its seed.
pub(crate) fn handle(
    sdk: &Sdk,
    seed: &str,
    account: u32,
) -> Result<(Arc<OpenSeed>, ZetherKey), SdkError> {
    let s = sdk.open_seed(seed)?;
    let k = s.wallet.zether_key(COIN_EVM, account, USE_CONF)?;
    Ok((s, k))
}

#[cfg(feature = "zether")]
/// The value at `path` in a facade answer (`Internal`: absent).
pub(crate) fn at<'a>(v: &'a Value, path: &[&str]) -> Result<&'a Value, SdkError> {
    path.iter()
        .try_fold(v, |v, k| v.get(*k).ok_or(SdkError::Internal))
}

#[cfg(feature = "zether")]
/// `v`'s field `k` set to `x` (`Internal`: not an object).
pub(crate) fn set(v: &mut Value, k: &str, x: Value) -> Result<(), SdkError> {
    v.as_object_mut()
        .ok_or(SdkError::Internal)?
        .insert(k.into(), x);
    Ok(())
}

#[cfg(feature = "zether")]
/// `cmd` of the facade on `req` off the async workers, the seed kept open meanwhile; its JSON answer.
pub(crate) async fn call(
    sdk: &Sdk,
    key: (Arc<OpenSeed>, ZetherKey),
    cmd: &'static str,
    req: Value,
) -> Result<Value, SdkError> {
    let body = serde_json::to_vec(&req).map_err(|_| SdkError::Internal)?;
    let out = sdk
        .heavy(move || {
            let (_seed, k) = key;
            Ok(k.call(cmd, &body)?)
        })
        .await?;
    serde_json::from_str(&out).map_err(|_| SdkError::Internal)
}

#[cfg(feature = "zether")]
impl Confidential {
    /// The Zether key of `seed` / `account` (spec §9.1): its UA and `Y`. `WalletLocked`.
    pub async fn zether_key(&self, seed: String, account: u32) -> Result<ZetherKeyInfo, SdkError> {
        let (_s, k) = handle(&self.sdk, &seed, account)?;
        Ok(ZetherKeyInfo {
            ua: crate::op::hex(&k.ua()),
            y: crate::op::hex(&k.y()),
        })
    }

    /// The holder's Zether balance on `token` (spec §9.4): the words read at the profile's final block under requirements 1 to
    /// 7, then decrypted by the facade. A word set that does not check or decrypt is refused here (`Argument`) and nothing is
    /// read again. `WalletLocked`, `ChainUnknown`, `ProfileMismatch`, the pool's codes.
    pub async fn zether_balance(
        &self,
        req: ZetherBalanceRequest,
    ) -> Result<ZetherBalance, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let key = handle(&sdk, &req.seed, req.account)?;
                let r = read::zether(
                    &sdk,
                    &req.chain,
                    &req.token,
                    Some(&key.1.y()),
                    key.1.ua(),
                    &[],
                )
                .await?;
                let mut words = r.words;
                for (k, v) in [("tableBits", req.table_bits), ("boundBits", req.bound_bits)] {
                    if let Some(v) = v {
                        set(&mut words, k, json!(v))?;
                    }
                }
                let cmd = if req.pending {
                    "pendingBalance"
                } else {
                    "balance"
                };
                let out = call(&sdk, key, cmd, words).await?;
                Ok(ZetherBalance {
                    amount: at(&out, &["amount"])?
                        .as_str()
                        .ok_or(SdkError::Internal)?
                        .to_string(),
                    block: r.block,
                    acc_seq: at(&out, &["state", "accSeq"])?
                        .as_u64()
                        .ok_or(SdkError::Internal)?,
                })
            })
            .await
    }
}
