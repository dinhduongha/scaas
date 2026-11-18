// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sui JSON-RPC (spec §5.3 sui row, plan T20) on the family client: the calls, a checkpoint's digest behind `final_head`,
//! the network identity (`sui_getChainIdentifier`, compared with the first endpoint's: the configuration names no chain
//! identifier, as EVM without a pinned `chain_uid` compares with the first endpoint's block 0, CLI-RPC-03) and the head (the
//! latest checkpoint's sequence number) for the failover's floor. Objects, coins, dry runs and events are the caller's to read.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use std::sync::OnceLock;
use web_time::Instant;

/// The family client of one Sui network.
pub struct Sui {
    pub client: Client,
    /// the reference chain identifier: the configured one (T24.11), else the first endpoint's, once read
    first: OnceLock<String>,
}

impl Sui {
    pub fn new(client: Client) -> Self {
        Self::pinned(client, None)
    }

    /// The client of a network named by its chain identifier (T24.11, owner 2026-11-18): every endpoint, the first included, is
    /// checked against `chain_identifier` before its first read; `None` is [`Sui::new`] (the first endpoint's is the reference).
    pub fn pinned(client: Client, chain_identifier: Option<&str>) -> Self {
        let first = OnceLock::new();
        if let Some(c) = chain_identifier {
            let _ = first.set(c.to_string());
        }
        Self { client, first }
    }

    /// One JSON-RPC call to endpoint `i`.
    pub async fn call(&self, i: usize, method: &str, params: Value) -> Result<Value, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.client.rpc_at(i, method, params).await
    }

    /// The digest (base58, as Sui writes it) of checkpoint `seq` on endpoint `i`.
    pub async fn checkpoint_digest(&self, i: usize, seq: u64) -> Result<String, FamilyError> {
        let c = self
            .call(i, "sui_getCheckpoint", json!([seq.to_string()]))
            .await?;
        c["digest"].as_str().map(str::to_string).ok_or_else(|| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                &format!("checkpoint {seq} without digest"),
            ))
        })
    }

    /// The latest checkpoint's sequence number on endpoint `i`.
    pub async fn latest_checkpoint(&self, i: usize) -> Result<u64, FamilyError> {
        let v = self
            .call(i, "sui_getLatestCheckpointSequenceNumber", json!([]))
            .await?;
        num(&v).ok_or_else(|| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "not a checkpoint sequence number",
            ))
        })
    }

    async fn chain_identifier(&self, i: usize) -> Result<String, EndpointFailure> {
        let v = self
            .client
            .rpc_at(i, "sui_getChainIdentifier", json!([]))
            .await
            .map_err(|e| unread(i, e))?;
        v.as_str().map(str::to_string).ok_or_else(|| {
            EndpointFailure::new(i, FailureKind::IdentityUnread, "not a chain identifier")
        })
    }
}

/// A number Sui writes as a string (u64 fields) or as a number.
fn num(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

impl Probe for Sui {
    type Hash = String;
    /// `sui_getChainIdentifier` against the configured one (T24.11), else against the first endpoint's (read first; unread, no
    /// later endpoint is this network yet; the first endpoint is then its own reference).
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let want = match self.first.get() {
            Some(w) => w.clone(),
            None => {
                let w = self.chain_identifier(0).await.map_err(|e| {
                    EndpointFailure::new(
                        i,
                        FailureKind::IdentityUnread,
                        &format!("the first endpoint's chain identifier: {}", e.text()),
                    )
                })?;
                self.first.get_or_init(|| w).clone()
            }
        };
        Ok(self.chain_identifier(i).await? == want)
    }
    /// The latest checkpoint's sequence number.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.latest_checkpoint(i).await.map_err(|e| unread(i, e))
    }
    async fn named(
        &self,
        i: usize,
        _: BlockChoice,
        d: Option<Instant>,
    ) -> Result<u64, EndpointFailure> {
        self.head(i, d).await
    }
    async fn header(
        &self,
        i: usize,
        n: u64,
        _: Option<Instant>,
    ) -> Result<String, EndpointFailure> {
        self.checkpoint_digest(i, n).await.map_err(|e| unread(i, e))
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
