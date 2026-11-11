// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The chain behind a small trait: a list of nodes ([ARCH-POS-15](../../docs/decisions.md#ARCH-POS-15)), each read by
//! `eth_call` and `eth_getCode` at a block the caller names. The service reads one request from one node at one block and
//! fails over in the configured order; the tests answer it with fixed views.

use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{BlockId, TransactionRequest};
use alloy::transports::TransportError;
use async_trait::async_trait;
use std::future::Future;
use std::time::Duration;

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

/// The longest one RPC read may take; past it the node counts as not answering, so the request fails over (Fable R-1).
pub const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// The operator's JSON-RPC endpoints (`rpc_urls`), in order, each read under `timeout`.
pub struct Rpc {
    nodes: Vec<DynProvider>,
    timeout: Duration,
}

/// `f` within `t`, else the node's failure (`ChainError::Rpc`).
async fn timed<T>(t: Duration, f: impl Future<Output = Result<T, ChainError>>) -> Result<T, ChainError> {
    tokio::time::timeout(t, f).await.unwrap_or_else(|_| Err(ChainError::Rpc(format!("no answer within {t:?}"))))
}

impl Rpc {
    /// Every endpoint must answer `chain_id` (`eth_chainId`) within `RPC_TIMEOUT` now, or the service does not start
    /// (Fable C-6).
    pub async fn connect(urls: &[String], chain_id: u64) -> anyhow::Result<Self> {
        Self::connect_within(urls, chain_id, RPC_TIMEOUT).await
    }

    /// As [`Rpc::connect`], each read under `timeout` (the tests' short one).
    pub async fn connect_within(urls: &[String], chain_id: u64, timeout: Duration) -> anyhow::Result<Self> {
        let mut nodes = Vec::new();
        for (i, u) in urls.iter().enumerate() {
            let p = ProviderBuilder::new().disable_recommended_fillers().connect_http(u.parse()?).erased();
            let id = timed(timeout, async { p.get_chain_id().await.map_err(|e| ChainError::Rpc(e.to_string())) })
                .await
                .map_err(|e| anyhow::anyhow!("rpc_urls[{i}]: eth_chainId: {e:?}"))?;
            anyhow::ensure!(id == chain_id, "rpc_urls[{i}] answers chain {id}, the config pins {chain_id}");
            nodes.push(p);
        }
        Ok(Self { nodes, timeout })
    }
}

/// A revert only when the answer says so: revert data, or a message that starts `execution reverted`; any other error
/// answer (`header not found`, a pruned state, a rate limit) and no answer are the node's, so the request fails over
/// (Fable R-2).
fn classify(e: TransportError) -> ChainError {
    match e.as_error_resp() {
        Some(p) => match p.as_revert_data() {
            Some(d) => ChainError::Revert(d),
            None if p.message.starts_with("execution reverted") => ChainError::Revert(Bytes::new()),
            None => ChainError::Rpc(e.to_string()),
        },
        None => ChainError::Rpc(e.to_string()),
    }
}

#[async_trait]
impl Chain for Rpc {
    fn nodes(&self) -> usize {
        self.nodes.len()
    }

    async fn head(&self, node: usize) -> Result<u64, ChainError> {
        timed(self.timeout, async { self.nodes[node].get_block_number().await.map_err(|e| ChainError::Rpc(e.to_string())) }).await
    }

    async fn call(&self, node: usize, block: u64, to: Address, data: Bytes) -> Result<Bytes, ChainError> {
        let tx = TransactionRequest::default().with_to(to).with_input(data);
        timed(self.timeout, async { self.nodes[node].call(tx).block(BlockId::number(block)).await.map_err(classify) }).await
    }

    async fn code(&self, node: usize, block: u64, at: Address) -> Result<Bytes, ChainError> {
        let f = async {
            self.nodes[node].get_code_at(at).block_id(BlockId::number(block)).await.map_err(|e| ChainError::Rpc(e.to_string()))
        };
        timed(self.timeout, f).await
    }
}
