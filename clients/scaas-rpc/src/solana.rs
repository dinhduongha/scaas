// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Solana JSON-RPC (spec §5.3 solana row, plan T16) on the family client: the calls, the finalized slot and block reads behind
//! `final_head` (the lowest finalized slot across endpoints, the block produced at or before it, its hash's quorum), the
//! network identity (`getGenesisHash`) and the head (`getSlot`) for the failover's floor. Account data, transaction status
//! classes and messages are the caller's to read.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// The family client of one Solana cluster, named by its genesis hash (base58).
pub struct Solana {
    pub client: Client,
    genesis: String,
}

/// A finalized block: its slot and its blockhash (base58).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    pub slot: u64,
    pub hash: String,
}

impl Solana {
    pub fn new(client: Client, genesis_b58: &str) -> Self {
        Self {
            client,
            genesis: genesis_b58.into(),
        }
    }

    /// One JSON-RPC call to endpoint `i`.
    pub async fn call(&self, i: usize, method: &str, params: Value) -> Result<Value, FamilyError> {
        self.client.rpc_at(i, method, params).await
    }

    /// The `finalized` slot of endpoint `i`.
    pub async fn finalized_slot(&self, i: usize) -> Result<u64, FamilyError> {
        let v = self
            .call(i, "getSlot", json!([{"commitment": "finalized"}]))
            .await?;
        v.as_u64().ok_or_else(|| bad(i, "getSlot: not a slot"))
    }

    /// The blockhash (base58) of the finalized block at `slot` on endpoint `i`.
    pub async fn blockhash_at(&self, i: usize, slot: u64) -> Result<String, FamilyError> {
        let b = self
            .call(
                i,
                "getBlock",
                json!([slot, {"commitment": "finalized", "transactionDetails": "none",
                "rewards": false, "maxSupportedTransactionVersion": 1}]),
            )
            .await?;
        b["blockhash"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| bad(i, &format!("getBlock {slot}: no blockhash")))
    }

    /// The last block produced at or before `slot` (within 2048 slots) on endpoint `i`, and its blockhash.
    pub async fn produced_at_or_before(&self, i: usize, slot: u64) -> Result<Block, FamilyError> {
        let blocks = self
            .call(
                i,
                "getBlocks",
                json!([slot.saturating_sub(2048), slot, {"commitment": "finalized"}]),
            )
            .await?;
        let s = blocks
            .as_array()
            .and_then(|a| a.last())
            .and_then(Value::as_u64)
            .ok_or_else(|| {
                bad(
                    i,
                    &format!("no block produced in the 2048 slots up to {slot}"),
                )
            })?;
        Ok(Block {
            slot: s,
            hash: self.blockhash_at(i, s).await?,
        })
    }
}

impl Probe for Solana {
    type Hash = String;
    /// `getGenesisHash` against the configured cluster.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let v = self
            .call(i, "getGenesisHash", json!([]))
            .await
            .map_err(|e| unread(i, e))?;
        match v.as_str() {
            Some(g) => Ok(g == self.genesis),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "getGenesisHash: not a hash",
            )),
        }
    }
    /// `getSlot` (processed): the endpoint's head.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        let v = self
            .call(i, "getSlot", json!([]))
            .await
            .map_err(|e| unread(i, e))?;
        v.as_u64().ok_or_else(|| {
            EndpointFailure::new(i, FailureKind::AnswerMalformed, "getSlot: not a slot")
        })
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
        self.blockhash_at(i, n).await.map_err(|e| unread(i, e))
    }
}

fn bad(i: usize, why: &str) -> FamilyError {
    FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
