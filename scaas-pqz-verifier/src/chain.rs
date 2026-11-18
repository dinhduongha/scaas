// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The chain behind a small trait: a list of nodes ([ARCH-POS-15](../../docs/decisions.md#ARCH-POS-15)), each read by
//! `eth_call` and `eth_getCode` at a block the caller names. The service reads one request from one node at one block and
//! fails over in the configured order; the tests answer it with fixed views.

use alloy::network::TransactionBuilder;
use alloy::primitives::B256;
use alloy::primitives::{Address, Bytes};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::{BlockId, RpcBlockHash, TransactionRequest};
use alloy::transports::TransportError;
use async_trait::async_trait;
use scaas_rpc::evm::EvmPool;
use scaas_rpc::{Endpoint, NodeList, Policy};
use std::future::Future;
use std::time::Duration;

#[derive(Debug)]
pub enum ChainError {
    /// the call reverted (its revert data, possibly empty)
    Revert(Bytes),
    /// the RPC did not answer
    Rpc(String),
}

/// The block a read names: a number (the failover path, as before) or a header's hash (EIP-1898 with `requireCanonical`, every
/// read of an agreed request, CLI-RPC-12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Block {
    Number(u64),
    Hash(B256),
}

impl Block {
    pub fn id(self) -> BlockId {
        match self {
            Block::Number(n) => BlockId::number(n),
            Block::Hash(h) => BlockId::Hash(RpcBlockHash {
                block_hash: h,
                require_canonical: Some(true),
            }),
        }
    }
}

#[async_trait]
pub trait Chain: Send + Sync {
    /// How many nodes, asked in order `0..nodes()`.
    fn nodes(&self) -> usize;
    /// Node `node`'s latest block number.
    async fn head(&self, node: usize) -> Result<u64, ChainError>;
    /// Node `node`'s header hash at `number`.
    async fn header(&self, node: usize, number: u64) -> Result<B256, ChainError>;
    async fn call(
        &self,
        node: usize,
        block: Block,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, ChainError>;
    async fn code(&self, node: usize, block: Block, at: Address) -> Result<Bytes, ChainError>;
}

/// The longest one RPC read may take; past it the node counts as not answering, so the request fails over (Fable R-1).
pub const RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// The operator's JSON-RPC endpoints (`rpc_urls`), in order, each read under `timeout`: per-index access to
/// `scaas_rpc::evm::EvmPool`'s providers, on the crate's bounded transport (CLI-RPC-07: an answer above 16 MiB or deeper than
/// 64 is that node's failure; no redirect is followed). The service's own failover stays `Service::on_nodes`.
pub struct Rpc {
    pool: EvmPool,
    timeout: Duration,
}

/// `f` within `t`, else the node's failure (`ChainError::Rpc`).
async fn timed<T>(
    t: Duration,
    f: impl Future<Output = Result<T, ChainError>>,
) -> Result<T, ChainError> {
    tokio::time::timeout(t, f)
        .await
        .unwrap_or_else(|_| Err(ChainError::Rpc(format!("no answer within {t:?}"))))
}

impl Rpc {
    /// Every endpoint must answer `chain_id` (`eth_chainId`) within `RPC_TIMEOUT` now, or the service does not start
    /// (Fable C-6).
    pub async fn connect(urls: &[String], chain_id: u64) -> anyhow::Result<Self> {
        Self::connect_within(urls, chain_id, RPC_TIMEOUT).await
    }

    /// As [`Rpc::connect`], and every endpoint's block 0 is the pinned `chain_uid` (T13 S11, CLI-RPC-03: the pool's identity
    /// check, run at start; an endpoint without block 0 is refused, `ChainIdentityUnreadable`). The service starts with this.
    pub async fn connect_pinned(
        urls: &[String],
        chain_id: u64,
        chain_uid: B256,
    ) -> anyhow::Result<Self> {
        let rpc = Self::build(urls, chain_id, Some(chain_uid), RPC_TIMEOUT)?;
        for i in 0..urls.len() {
            let pool = &rpc.pool;
            timed(RPC_TIMEOUT, async {
                pool.pool()
                    .admit(pool, i, None)
                    .await
                    .map_err(|e| ChainError::Rpc(e.to_string()))
            })
            .await
            .map_err(|e| anyhow::anyhow!("rpc_urls[{i}]: chain identity: {e:?}"))?;
        }
        Ok(rpc)
    }

    /// As [`Rpc::connect`], each read under `timeout` (the tests' short one).
    pub async fn connect_within(
        urls: &[String],
        chain_id: u64,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let Self { pool, timeout } = Self::build(urls, chain_id, None, timeout)?;
        for i in 0..urls.len() {
            let p = pool.endpoint(i, None);
            let id = timed(timeout, async {
                p.get_chain_id()
                    .await
                    .map_err(|e| ChainError::Rpc(e.to_string()))
            })
            .await
            .map_err(|e| anyhow::anyhow!("rpc_urls[{i}]: eth_chainId: {e:?}"))?;
            anyhow::ensure!(
                id == chain_id,
                "rpc_urls[{i}] answers chain {id}, the config pins {chain_id}"
            );
        }
        Ok(Self { pool, timeout })
    }

    fn build(
        urls: &[String],
        chain_id: u64,
        chain_uid: Option<B256>,
        timeout: Duration,
    ) -> anyhow::Result<Self> {
        let ms = u64::try_from(timeout.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);
        let endpoints = urls
            .iter()
            .enumerate()
            .map(|(i, u)| Endpoint::named(u).map_err(|e| anyhow::anyhow!("rpc_urls[{i}]: {e}")))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let list = NodeList::new(
            endpoints,
            Policy::Failover,
            ms,
            ms,
            scaas_rpc::endpoint::READ_TIMEOUT_MS,
        )
        .map_err(|e| anyhow::anyhow!("rpc_urls: {e}"))?;
        let pool = EvmPool::connect(list, chain_id, chain_uid)
            .map_err(|e| anyhow::anyhow!("rpc_urls: {e}"))?;
        Ok(Self { pool, timeout })
    }

    fn node(&self, node: usize) -> DynProvider {
        self.pool.endpoint(node, None)
    }
}

/// The crate's classifier (CLI-RPC-50 Q5, `scaas_rpc::evm::classify`): revert data, a "revert", or an execution error that is
/// not a node's own limit is a revert, its data kept as bytes (possibly empty); any other error answer (`header not found`, a
/// pruned state, a rate limit, a node's own timeout) and no answer are the node's, so the request fails over.
fn classify(e: TransportError) -> ChainError {
    match scaas_rpc::evm::classify(&e) {
        scaas_rpc::evm::SimError::Revert(_) => {
            ChainError::Revert(scaas_rpc::evm::revert_data(&e).unwrap_or_default())
        }
        scaas_rpc::evm::SimError::Transport(_) => ChainError::Rpc(e.to_string()),
    }
}

#[async_trait]
impl Chain for Rpc {
    fn nodes(&self) -> usize {
        self.pool.list().len()
    }

    async fn head(&self, node: usize) -> Result<u64, ChainError> {
        timed(self.timeout, async {
            self.node(node)
                .get_block_number()
                .await
                .map_err(|e| ChainError::Rpc(e.to_string()))
        })
        .await
    }

    async fn header(&self, node: usize, number: u64) -> Result<B256, ChainError> {
        let f = async {
            let b = self
                .node(node)
                .get_block_by_number(number.into())
                .await
                .map_err(|e| ChainError::Rpc(e.to_string()))?
                .ok_or_else(|| ChainError::Rpc(format!("no block {number}")))?;
            if b.header.number != number {
                return Err(ChainError::Rpc(format!(
                    "asked block {number}, answered {}",
                    b.header.number
                )));
            }
            Ok(b.header.hash)
        };
        timed(self.timeout, f).await
    }

    async fn call(
        &self,
        node: usize,
        block: Block,
        to: Address,
        data: Bytes,
    ) -> Result<Bytes, ChainError> {
        let tx = TransactionRequest::default().with_to(to).with_input(data);
        timed(self.timeout, async {
            self.node(node)
                .call(tx)
                .block(block.id())
                .await
                .map_err(classify)
        })
        .await
    }

    async fn code(&self, node: usize, block: Block, at: Address) -> Result<Bytes, ChainError> {
        let f = async {
            self.node(node)
                .get_code_at(at)
                .block_id(block.id())
                .await
                .map_err(|e| ChainError::Rpc(e.to_string()))
        };
        timed(self.timeout, f).await
    }
}
