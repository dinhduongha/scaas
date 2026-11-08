// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The chain behind a small trait: `eth_call` and `eth_getCode` at the latest state. The service reads everything it
//! checks through it; the tests answer it with fixed views.

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::TransactionRequest;
use alloy::transports::TransportError;
use async_trait::async_trait;

#[derive(Debug)]
pub enum ChainError {
    /// the call reverted (its revert data, possibly empty)
    Revert(Bytes),
    /// the RPC did not answer
    Rpc(String),
}

#[async_trait]
pub trait Chain: Send + Sync {
    async fn call(&self, to: Address, data: Bytes) -> Result<Bytes, ChainError>;
    async fn code(&self, at: Address) -> Result<Bytes, ChainError>;
}

/// The operator's JSON-RPC endpoint.
pub struct Rpc(DynProvider);

impl Rpc {
    pub fn connect(url: &str) -> anyhow::Result<Self> {
        Ok(Self(ProviderBuilder::new().disable_recommended_fillers().connect_http(url.parse()?).erased()))
    }

    pub async fn chain_id(&self) -> anyhow::Result<u64> {
        Ok(self.0.get_chain_id().await?)
    }
}

/// A JSON-RPC error answer is the call's revert (`execution reverted`, with or without data); anything else is the RPC's.
fn classify(e: TransportError) -> ChainError {
    match e.as_error_resp() {
        Some(p) => ChainError::Revert(p.as_revert_data().unwrap_or_default()),
        None => ChainError::Rpc(e.to_string()),
    }
}

#[async_trait]
impl Chain for Rpc {
    async fn call(&self, to: Address, data: Bytes) -> Result<Bytes, ChainError> {
        self.0.call(TransactionRequest::default().with_to(to).with_input(data)).await.map_err(classify)
    }

    async fn code(&self, at: Address) -> Result<Bytes, ChainError> {
        self.0.get_code_at(at).await.map_err(|e| ChainError::Rpc(e.to_string()))
    }
}
