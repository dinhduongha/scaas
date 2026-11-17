// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! TON Center v3 (spec §5.3 ton row, plan T22) on the family client: a GET with its query and a JSON POST under `/api/v3/`,
//! an answer other than 2xx as `FamilyError::Status` with its text, and the head (`masterchainInfo`'s last seqno) for the
//! failover's floor. TON Center names no network, so the identity is the profile constant (NET-ALL-22, CLI-RPC-03): every
//! endpoint of the configured list is taken as this network. Get-method stacks, BOCs and transactions are the caller's to read.
use crate::family::{Client, FamilyError, ANSWER_MAX};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::Value;
use web_time::Instant;

/// The family client of one TON network's TON Center v3 endpoints.
pub struct Ton {
    pub client: Client,
}

impl Ton {
    pub fn new(client: Client) -> Self {
        Self { client }
    }

    /// GET `/api/v3/{path}` with `query` on endpoint `i`.
    pub async fn get(
        &self,
        i: usize,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Value, FamilyError> {
        let mut p = format!("/api/v3/{path}");
        if !query.is_empty() {
            let q: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())))
                .finish();
            p = format!("{p}?{q}");
        }
        self.request(i, reqwest::Method::GET, &p, None).await
    }

    /// POST `body` (JSON) to `/api/v3/{path}` on endpoint `i`.
    pub async fn post(&self, i: usize, path: &str, body: &Value) -> Result<Value, FamilyError> {
        let b = serde_json::to_vec(body).map_err(|e| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::Transport,
                &e.to_string(),
            ))
        })?;
        self.request(
            i,
            reqwest::Method::POST,
            &format!("/api/v3/{path}"),
            Some(b),
        )
        .await
    }

    async fn request(
        &self,
        i: usize,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> Result<Value, FamilyError> {
        let (status, b) = self
            .client
            .raw_at(i, method, path, body, "application/json", ANSWER_MAX)
            .await?;
        if !(200..300).contains(&status) {
            return Err(FamilyError::Status {
                status,
                message: crate::error::endpoint_text(&String::from_utf8_lossy(&b)),
            });
        }
        crate::http::decode(&b, ANSWER_MAX)
            .map_err(|k| FamilyError::Failure(EndpointFailure::new(i, k, "the answer")))
    }

    /// `masterchainInfo`'s last block on endpoint `i`.
    pub async fn masterchain_last(&self, i: usize) -> Result<Value, FamilyError> {
        let v = self.get(i, "masterchainInfo", &[]).await?;
        v.get("last").cloned().ok_or_else(|| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "masterchainInfo without last",
            ))
        })
    }
}

impl Probe for Ton {
    type Hash = String;
    /// The profile constant (NET-ALL-22): TON Center exposes no network id, the configured list names the network.
    async fn same_chain(&self, _: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        Ok(true)
    }
    /// `masterchainInfo`'s last seqno.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        let last = self.masterchain_last(i).await.map_err(|e| unread(i, e))?;
        last.get("seqno").and_then(Value::as_u64).ok_or_else(|| {
            EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "masterchainInfo.last.seqno",
            )
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
        let v = self
            .get(
                i,
                "blocks",
                &[
                    ("workchain", "-1".into()),
                    ("shard", "8000000000000000".into()),
                    ("seqno", n.to_string()),
                ],
            )
            .await
            .map_err(|e| unread(i, e))?;
        v.pointer("/blocks/0/root_hash")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                EndpointFailure::new(i, FailureKind::AnswerMalformed, "no masterchain block")
            })
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
