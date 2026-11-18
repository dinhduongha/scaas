// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Operations (spec §13; CLI-SDK-08, CLI-SDK-09, CLI-SDK-18; plan T10): prepare → review → quote → sign → write ahead → send →
//! follow. A module's `prepare_<op>` builds a [`Draft`] from its request's named fields; [`Op::prepare`] reads the lane nonce and
//! the chain's time, builds the typed data with `scaas-ua`, and keeps an opaque [`Prepared`] in the SDK's table. `submit` signs
//! exactly that value under its `scaas-ua` check, writes the row (state `signed`) to `sdk.state`, and returns the operation's id;
//! the send runs on as a task and reports as `Event::OpState`. An operation ends only on a chain fact. UNAUDITED.
mod follow;
pub(crate) mod gas;
mod prepared;
pub(crate) mod quote;
pub(crate) mod state;
pub(crate) mod submit;
#[cfg(test)]
mod tests;

pub use crate::events::{InFlight, OpState};
#[allow(unused_imports)] // the modules' `prepare_<op>` (plan T12 on)
pub(crate) use prepared::Draft;
pub use prepared::{Prepared, ReviewField, Source};
pub use quote::{SubmitPath, SubmitQuote};

use crate::{ChainProfile, Sdk, SdkError};
use alloy::primitives::{Address, Bytes, U256};
use scaas_rpc::evm::{EvmPool, SimError};
use scaas_rpc::pool::BlockChoice;
use scaas_rpc::Purpose;
use scaas_ua::wallet::{NativeKey, Network, UaKey};
use std::sync::Arc;

/// A key the SDK signs with, by reference (spec §5): the seed's open wallet holds it. The passkey, secure-element and imported
/// keys join with the tasks that sign with them (plan T13).
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
}

impl Key {
    pub(crate) fn signer(&self) -> &dyn scaas_ua::wallet::Signer {
        match self {
            Key::Ua(_, k) => k,
            Key::Native(_, k) => k,
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
    })
}

/// An EVM chain's profile, chain id and pool (`ChainUnknown`; `Argument` without a chain id).
pub(crate) fn evm(sdk: &Sdk, chain: &str) -> Result<(ChainProfile, u64, EvmPool), SdkError> {
    let c = sdk
        .chains
        .iter()
        .find(|c| c.profile.key == chain)
        .ok_or(SdkError::ChainUnknown)?;
    let id = c.profile.chain_id.ok_or(SdkError::Argument)?;
    let uid: alloy::primitives::B256 = c
        .profile
        .chain_uid
        .parse()
        .map_err(|_| SdkError::Argument)?;
    let pool = EvmPool::connect(
        crate::list(&c.profile.rpc, c.profile.rpc_policy)?,
        id,
        Some(uid),
    )?;
    Ok((c.profile.clone(), id, pool))
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

/// The profile's final block (spec §13.5).
pub(crate) fn final_block(p: &ChainProfile) -> BlockChoice {
    match p.finality {
        crate::Finality::Finalized => BlockChoice::Finalized,
        crate::Finality::Depth(n) => BlockChoice::Depth(n),
    }
}
