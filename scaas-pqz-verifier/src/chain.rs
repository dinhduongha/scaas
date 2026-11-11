// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The chain behind a small trait: a list of nodes ([ARCH-POS-15](../../docs/decisions.md#ARCH-POS-15)), each read by
//! `eth_call` and `eth_getCode` at a block the caller names. The service reads one request from one node at one block and
//! fails over in the configured order; the tests answer it with fixed views.

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockId, TransactionRequest};
use alloy::transports::TransportError;
use anyhow::Context;
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
    /// How many nodes, asked in order `0..nodes()`.
    fn nodes(&self) -> usize;
    /// Node `node`'s latest block number.
    async fn head(&self, node: usize) -> Result<u64, ChainError>;
    async fn call(&self, node: usize, block: u64, to: Address, data: Bytes) -> Result<Bytes, ChainError>;
    async fn code(&self, node: usize, block: u64, at: Address) -> Result<Bytes, ChainError>;
}

/// The operator's JSON-RPC endpoints (`rpc_urls`), in order.
pub struct Rpc(Vec<DynProvider>);

impl Rpc {
    /// Every endpoint must answer `chain_id` (`eth_chainId`) now, or the service does not start (Fable C-6).
    pub async fn connect(urls: &[String], chain_id: u64) -> anyhow::Result<Self> {
        let mut nodes = Vec::new();
        for (i, u) in urls.iter().enumerate() {
            let p = ProviderBuilder::new().disable_recommended_fillers().connect_http(u.parse()?).erased();
            let id = p.get_chain_id().await.with_context(|| format!("rpc_urls[{i}]: eth_chainId"))?;
            anyhow::ensure!(id == chain_id, "rpc_urls[{i}] answers chain {id}, the config pins {chain_id}");
            nodes.push(p);
        }
        Ok(Self(nodes))
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
    fn nodes(&self) -> usize {
        self.0.len()
    }

    async fn head(&self, node: usize) -> Result<u64, ChainError> {
        self.0[node].get_block_number().await.map_err(|e| ChainError::Rpc(e.to_string()))
    }

    async fn call(&self, node: usize, block: u64, to: Address, data: Bytes) -> Result<Bytes, ChainError> {
        let tx = TransactionRequest::default().with_to(to).with_input(data);
        self.0[node].call(tx).block(BlockId::number(block)).await.map_err(classify)
    }

    async fn code(&self, node: usize, block: u64, at: Address) -> Result<Bytes, ChainError> {
        self.0[node].get_code_at(at).block_id(BlockId::number(block)).await.map_err(|e| ChainError::Rpc(e.to_string()))
    }
}
