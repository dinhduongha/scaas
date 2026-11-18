// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Soroban RPC (spec §5.3 soroban row, plan T15) on the family client: the JSON-RPC calls, the ledger reads (`getLatestLedger`,
//! `getLedgers`), the network identity (`getNetwork`'s passphrase) and the head for the failover's floor. The XDR inside the
//! answers (account entries, results) is the caller's to decode.
use crate::family::{Client, FamilyError};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// A ledger: its sequence and its hash (`0x` + lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ledger {
    pub sequence: u64,
    pub hash: String,
}

/// The family client of one Soroban network, named by its passphrase (the identity every endpoint must answer).
pub struct Soroban {
    pub client: Client,
    passphrase: String,
}

impl Soroban {
    pub fn new(client: Client, passphrase: &str) -> Self {
        Self {
            client,
            passphrase: passphrase.into(),
        }
    }

    /// One JSON-RPC call to endpoint `i`.
    pub async fn call(&self, i: usize, method: &str, params: Value) -> Result<Value, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.client.rpc_at(i, method, params).await
    }

    /// `getLedgers` of ledger `seq` on endpoint `i`: its hash (an endpoint without it is an error).
    pub async fn ledger_hash(&self, i: usize, seq: u64) -> Result<String, FamilyError> {
        let r = self
            .call(
                i,
                "getLedgers",
                json!({"startLedger": seq, "pagination": {"limit": 1}}),
            )
            .await?;
        let l = &r["ledgers"][0];
        let bad = |why: &str| {
            FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
        };
        if l["sequence"].as_u64() != Some(seq) {
            return Err(bad(&format!("ledger {seq} not available")));
        }
        let h = l["hash"]
            .as_str()
            .ok_or_else(|| bad(&format!("ledger {seq} without hash")))?;
        Ok(format!("0x{}", h.to_lowercase()))
    }

    /// `getLatestLedger` on endpoint `i`.
    pub async fn latest_ledger(&self, i: usize) -> Result<Ledger, FamilyError> {
        let r = self.call(i, "getLatestLedger", json!({})).await?;
        let bad = |why: &str| {
            FamilyError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
        };
        let sequence = r["sequence"]
            .as_u64()
            .ok_or_else(|| bad("getLatestLedger without sequence"))?;
        let id = r["id"]
            .as_str()
            .ok_or_else(|| bad("getLatestLedger without id"))?;
        Ok(Ledger {
            sequence,
            hash: format!("0x{}", id.to_lowercase()),
        })
    }

    /// Endpoint 0's latest ledger and how many endpoints, endpoint 0 included, give the same hash at its sequence (the node's
    /// head quorum; an endpoint that fails counts as not agreeing).
    pub async fn head_agreement(&self) -> Result<(Ledger, usize), FamilyError> {
        let head = self.latest_ledger(0).await?;
        let mut agree = 1;
        for i in 1..self.client.len() {
            if self.ledger_hash(i, head.sequence).await.ok().as_deref() == Some(head.hash.as_str())
            {
                agree += 1;
            }
        }
        Ok((head, agree))
    }
}

impl Probe for Soroban {
    type Hash = String;
    /// `getNetwork`'s passphrase against the configured one.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let r = self
            .client
            .rpc_at(i, "getNetwork", json!({}))
            .await
            .map_err(|e| unread(i, e))?;
        match r["passphrase"].as_str() {
            Some(p) => Ok(p == self.passphrase),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "getNetwork without passphrase",
            )),
        }
    }
    /// `getLatestLedger`'s sequence.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        self.latest_ledger(i)
            .await
            .map(|l| l.sequence)
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
        self.ledger_hash(i, n).await.map_err(|e| unread(i, e))
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
