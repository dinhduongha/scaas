// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! NEAR JSON-RPC (spec §5.3 near row, plan T17) on the family client: the calls, the quorum read (`agreed`: endpoint 0's
//! answer, which further endpoints must repeat on a picked part), the final block's head quorum, the network identity
//! (`status`'s `genesis_hash`) and the head (the final block's height) for the failover's floor. Views, outcomes and actions are
//! the caller's to read.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// The family client of one NEAR network, named by its genesis hash (base58).
pub struct Near {
    pub client: Client,
    genesis: String,
}

pub use crate::family::AgreedError;

impl Near {
    pub fn new(client: Client, genesis_b58: &str) -> Self {
        Self {
            client,
            genesis: genesis_b58.into(),
        }
    }

    /// One JSON-RPC call to endpoint `i`.
    pub async fn call(&self, i: usize, method: &str, params: Value) -> Result<Value, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.client.rpc_at(i, method, params).await
    }

    /// Endpoint 0's answer; with `quorum > 1`, further endpoints must give the same `pick` until `quorum` agree (endpoint 0
    /// counts; an endpoint that fails counts as not agreeing).
    pub async fn agreed(
        &self,
        method: &str,
        params: Value,
        pick: fn(&Value) -> Value,
        quorum: usize,
    ) -> Result<Value, AgreedError> {
        let v = self
            .call(0, method, params.clone())
            .await
            .map_err(AgreedError::First)?;
        if quorum > 1 {
            let want = pick(&v);
            let mut agree = 1;
            for i in 1..self.client.len() {
                if matches!(self.call(i, method, params.clone()).await, Ok(o) if pick(&o) == want) {
                    agree += 1;
                }
            }
            if agree < quorum {
                return Err(AgreedError::Quorum { agree, quorum });
            }
        }
        Ok(v)
    }

    /// The `final` block's header on endpoint `i`: (height, hash).
    pub async fn final_header(&self, i: usize) -> Result<(u64, String), FamilyError> {
        let b = self.call(i, "block", json!({"finality": "final"})).await?;
        header(i, &b)
    }

    /// The block at `height` on endpoint `i`: (height, hash).
    pub async fn header_at(&self, i: usize, height: u64) -> Result<(u64, String), FamilyError> {
        let b = self.call(i, "block", json!({"block_id": height})).await?;
        header(i, &b)
    }
}

/// A block's `(height, hash)`.
pub fn header(i: usize, b: &Value) -> Result<(u64, String), FamilyError> {
    let h = &b["header"];
    match (h["height"].as_u64(), h["hash"].as_str()) {
        (Some(n), Some(x)) => Ok((n, x.to_string())),
        _ => Err(FamilyError::Failure(EndpointFailure::new(
            i,
            FailureKind::AnswerMalformed,
            "a block without height or hash",
        ))),
    }
}

impl Probe for Near {
    type Hash = String;
    /// `status`'s `genesis_hash` against the configured network.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let s = self
            .client
            .rpc_at(i, "status", json!([]))
            .await
            .map_err(|e| unread(i, e))?;
        match s["genesis_hash"].as_str() {
            Some(g) => Ok(g == self.genesis),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "status without genesis_hash",
            )),
        }
    }
    /// The final block's height.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.final_header(i)
            .await
            .map(|h| h.0)
            .map_err(|e| unread(i, e))
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
        self.header_at(i, n)
            .await
            .map(|h| h.1)
            .map_err(|e| unread(i, e))
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
