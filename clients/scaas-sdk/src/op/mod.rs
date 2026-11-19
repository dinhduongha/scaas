// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Operations (spec §13; CLI-SDK-08, CLI-SDK-09, CLI-SDK-18; plan T10): prepare → review → quote → sign → write ahead → send →
//! follow. A module's `prepare_<op>` builds a [`Draft`] from its request's named fields; [`Op::prepare`] reads the lane nonce and
//! the chain's time, builds the typed data with `scaas-ua`, and keeps an opaque [`Prepared`] in the SDK's table. `submit` signs
//! exactly that value under its `scaas-ua` check, writes the row (state `signed`) to `sdk.state`, and returns the operation's id;
//! the send runs on as a task and reports as `Event::OpState`. An operation ends only on a chain fact. UNAUDITED.
pub(crate) mod external;
mod follow;
pub(crate) mod gas;
mod prepared;
pub(crate) mod quote;
pub(crate) mod state;
pub(crate) mod submit;
#[cfg(test)]
mod tests;

pub use crate::events::{InFlight, OpState};
pub use gas::{GasFrom, GasSources};
pub(crate) use prepared::{domain_name, field, Draft, ExpectFn};
pub use prepared::{Prepared, ReviewField, Source};
pub use quote::{SubmitPath, SubmitQuote};

use crate::{ChainProfile, Sdk, SdkError};
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::evm::{EvmPool, SimError};
use scaas_rpc::pool::BlockChoice;
use scaas_rpc::Purpose;
use scaas_ua::wallet::{NativeKey, Network, UaKey};
use std::sync::Arc;

/// A key the SDK signs with, by reference (spec §5): the seed's open wallet holds it, or, for [`KeyRef::Key`], the platform's
/// authenticator (a passkey or a secure-element key, a row of the seed: owner 2026-11-19, S1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyRef {
    Ua {
        seed: String,
        kind: u16,
        account: u32,
        index: u32,
    },
    Native {
        seed: String,
        /// a `scaas-ua` network name (`evm` for a payer)
        network: String,
        index: u32,
    },
    /// an imported classical key (spec §6.7, `vault.import_key`): the seed's vault `native-import:<network>:<index>`
    Imported {
        seed: String,
        network: String,
        index: u32,
    },
    /// the stored key row `id` of seed `seed` (`AccountRow::Key`: a passkey `webauthn-p256` with its credential id, a
    /// secure-element `p256` key with its handle), signing through the `Authenticator` (`external`)
    Key { seed: String, id: String },
}

/// The operations module.
pub struct Op {
    pub(crate) sdk: Arc<Sdk>,
}

impl Sdk {
    /// The operations module (spec §13).
    pub fn op(self: &Arc<Self>) -> Arc<Op> {
        Arc::new(Op { sdk: self.clone() })
    }
}

/// A key of an open seed, kept beside its seed (a dropped wallet revokes its handles).
pub(crate) enum Key {
    Ua(#[allow(dead_code)] Arc<crate::vault::OpenSeed>, UaKey),
    Native(#[allow(dead_code)] Arc<crate::vault::OpenSeed>, NativeKey),
    /// the Zether UA (`0x0141`, index 0): the facade's key, signing only the digest `submit` approved (plan T15)
    #[cfg(feature = "zether")]
    Zether(
        #[allow(dead_code)] Arc<crate::vault::OpenSeed>,
        crate::confidential::ZetherSigner,
    ),
    /// a stored key row: its public parts, and a key that refuses every request (it signs only through `external::sign`)
    External(external::ExternalRow, scaas_ua::wallet::ExternalKey<'static>),
}

impl Key {
    pub(crate) fn signer(&self) -> &dyn scaas_ua::wallet::Signer {
        match self {
            Key::Ua(_, k) => k,
            Key::Native(_, k) => k,
            #[cfg(feature = "zether")]
            Key::Zether(_, k) => k,
            Key::External(_, k) => k,
        }
    }
}

/// `r`'s key: `WalletLocked` for a locked seed, `Argument` for an unknown network.
pub(crate) fn key(sdk: &Sdk, r: &KeyRef) -> Result<Key, SdkError> {
    Ok(match r {
        KeyRef::Ua {
            seed,
            kind,
            account,
            index,
        } => {
            #[cfg(feature = "zether")]
            if *kind == crate::confidential::ZETHER_KIND {
                if *index != 0 {
                    return Err(SdkError::Argument);
                }
                let (s, k) = crate::confidential::handle(sdk, seed, *account)?;
                return Ok(Key::Zether(s, crate::confidential::ZetherSigner::new(k)));
            }
            let s = sdk.open_seed(seed)?;
            let k = s.wallet.ua_key(*kind, *account, *index)?;
            Key::Ua(s, k)
        }
        KeyRef::Native {
            seed,
            network,
            index,
        } => {
            let n = Network::from_name(network).ok_or(SdkError::Argument)?;
            let s = sdk.open_seed(seed)?;
            let k = s.wallet.native_key(n, *index, None)?;
            Key::Native(s, k)
        }
        KeyRef::Imported {
            seed,
            network,
            index,
        } => {
            let n = Network::from_name(network).ok_or(SdkError::Argument)?;
            let s = sdk.open_seed(seed)?;
            let k = s.wallet.imported_key(n, *index)?;
            Key::Native(s, k)
        }
        // a stored key row is read from the keystore: `key_opened`
        KeyRef::Key { .. } => return Err(SdkError::Argument),
    })
}

/// `r`'s key after opening its vault when the session opens vaults on first use (an imported key under passkey unlock).
pub(crate) async fn key_opened(sdk: &Sdk, r: &KeyRef) -> Result<Key, SdkError> {
    if let KeyRef::Imported {
        seed,
        network,
        index,
    } = r
    {
        sdk.open_on_use(seed, &format!("native-import:{network}:{index}"))
            .await?;
    }
    if let KeyRef::Key { seed, id } = r {
        drop(sdk.open_seed(seed)?); // a row is trusted once its seed's MAC verified (unlocked)
        let row = sdk.entry(seed).await?.accounts.into_iter().find_map(|a| match a {
            crate::vault::AccountRow::Key {
                id: i,
                kind,
                key_data,
                credential_id,
                handle,
                ua,
                ..
            } if i == *id => Some((kind, key_data, credential_id, handle, ua)),
            _ => None,
        });
        let (kind, key_data, credential_id, handle, ua) = row.ok_or(SdkError::Argument)?;
        let row = external::ExternalRow {
            kind: u16::try_from(kind).map_err(|_| SdkError::Argument)?,
            key_data: unhex(&key_data)?,
            ua: unhex(&ua)?.try_into().map_err(|_| SdkError::Argument)?,
            credential_id: credential_id.as_deref().map(unhex).transpose()?,
            handle,
        };
        let refuse = scaas_ua::wallet::ExternalKey::new(row.key_ref(), |_| Err(scaas_ua::wallet::Error::ExternalSignature));
        return Ok(Key::External(row, refuse));
    }
    key(sdk, r)
}

/// An EVM chain's profile, chain id and the session's pool (`ChainUnknown`; `Argument` without a chain id).
pub(crate) fn evm(sdk: &Sdk, chain: &str) -> Result<(ChainProfile, u64, Arc<EvmPool>), SdkError> {
    sdk.evm(chain)
}

pub(crate) fn sim(e: SimError) -> SdkError {
    match e {
        SimError::Revert(_) => SdkError::Rpc(scaas_rpc::RpcError::Revert {
            endpoint: 0,
            data: vec![],
            reason: String::new(),
        }),
        SimError::Transport(_) => SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        }),
    }
}

pub(crate) fn hex(b: &[u8]) -> String {
    let mut s = String::from("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

pub(crate) fn unhex(s: &str) -> Result<Vec<u8>, SdkError> {
    let h = s.strip_prefix("0x").ok_or(SdkError::Argument)?;
    if h.len() % 2 != 0 || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(SdkError::Argument);
    }
    (0..h.len())
        .step_by(2)
        .map(|i| {
            h.get(i..i + 2)
                .and_then(|p| u8::from_str_radix(p, 16).ok())
                .ok_or(SdkError::Argument)
        })
        .collect()
}

pub(crate) fn dec(v: &serde_json::Value) -> Result<U256, SdkError> {
    match v {
        serde_json::Value::Number(n) => n.as_u64().map(U256::from).ok_or(SdkError::Argument),
        serde_json::Value::String(s) => U256::from_str_radix(s, 10).map_err(|_| SdkError::Argument),
        _ => Err(SdkError::Argument),
    }
}

pub(crate) fn addr20(s: &str) -> Result<[u8; 20], SdkError> {
    unhex(s)?.try_into().map_err(|_| SdkError::Argument)
}

/// The lane view's calldata: `mtxNonce(address,uint256)` on `SmartKeyAccount`, `mtxNonce(bytes32,uint256)` elsewhere.
pub(crate) fn nonce_call(kind: &str, from: &[u8], batch: U256) -> Bytes {
    let sig: &[u8] = if kind == "account" {
        b"mtxNonce(address,uint256)"
    } else {
        b"mtxNonce(bytes32,uint256)"
    };
    let mut d = scaas_ua::keccak256(sig)
        .get(..4)
        .unwrap_or_default()
        .to_vec();
    let mut w = [0u8; 32];
    let at = 32usize.saturating_sub(from.len());
    if let Some(t) = w.get_mut(at..) {
        t.copy_from_slice(from.get(..32 - at).unwrap_or_default());
    }
    d.extend_from_slice(&w);
    d.extend_from_slice(&batch.to_be_bytes::<32>());
    Bytes::from(d)
}

/// The lane's next nonce now (failed over).
pub(crate) async fn lane_nonce(
    pool: &EvmPool,
    contract: Address,
    kind: &str,
    from: &[u8],
    batch: U256,
) -> Result<U256, SdkError> {
    use alloy::network::TransactionBuilder;
    let tx = alloy::rpc::types::TransactionRequest::default()
        .with_to(contract)
        .with_input(nonce_call(kind, from, batch));
    let w = pool.call_tx(tx).await.map_err(sim)?;
    if w.len() != 32 {
        return Err(SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        }));
    }
    Ok(U256::from_be_slice(&w))
}

/// The head's number and timestamp: the chain's time, the signing check's `now` (one read at `latest`).
pub(crate) async fn head(pool: &EvmPool) -> Result<(u64, u64), SdkError> {
    let a = pool
        .read_at_block(BlockChoice::Latest, Purpose::Plain, |at| async move {
            Ok((at.number, pool.timestamp_at(&at).await?))
        })
        .await?;
    Ok(a.value)
}

/// The number of the profile's final block now (one read): the first block an operation signed after it may land in.
pub(crate) async fn final_number(pool: &EvmPool, p: &ChainProfile) -> Result<u64, SdkError> {
    let a = pool
        .read_at_block(
            final_block(p),
            Purpose::Plain,
            |at| async move { Ok(at.number) },
        )
        .await?;
    Ok(a.value)
}

/// The profile's final block (spec §13.5).
pub(crate) fn final_block(p: &ChainProfile) -> BlockChoice {
    match p.finality {
        crate::Finality::Finalized => BlockChoice::Finalized,
        crate::Finality::Depth(n) => BlockChoice::Depth(n),
    }
}
