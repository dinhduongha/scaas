// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Algorand algod REST (spec §5.3 algorand row, plan T18) on the family client: a GET whose answer comes back raw (msgpack
//! blocks; JSON elsewhere), a POST with its content type, a block's hash, the network identity (`/v2/transactions/params`'s
//! `genesis-hash`) and the head (`/v2/status`'s `last-round`) for the failover's floor. An answer other than a 2xx is
//! `FamilyError::Status`, its message for the caller's classes. Transactions, boxes and msgpack stay the caller's to read.
use crate::family::{Client, FamilyError, ANSWER_MAX};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::Value;
use web_time::Instant;

/// The family client of one Algorand network, named by its genesis hash (base64).
pub struct Algorand {
    pub client: Client,
    genesis: String,
}

impl Algorand {
    pub fn new(client: Client, genesis_b64: &str) -> Self {
        Self {
            client,
            genesis: genesis_b64.into(),
        }
    }

    /// GET `path` with `query` on endpoint `i`: a 2xx's bytes as sent; any other status `FamilyError::Status` with algod's
    /// `message` (else the body's first 300 characters).
    pub async fn get_raw(
        &self,
        i: usize,
        path: &str,
        query: &[(&str, String)],
    ) -> Result<Vec<u8>, FamilyError> {
        let mut p = path.to_string();
        if !query.is_empty() {
            let q: String = url::form_urlencoded::Serializer::new(String::new())
                .extend_pairs(query.iter().map(|(k, v)| (*k, v.as_str())))
                .finish();
            p = format!("{p}?{q}");
        }
        let (status, b) = self
            .client
            .raw_at(
                i,
                reqwest::Method::GET,
                &p,
                None,
                "application/json",
                ANSWER_MAX,
            )
            .await?;
        answer(status, b)
    }

    /// GET `path` on endpoint `i`, parsed as JSON.
    pub async fn get(&self, i: usize, path: &str) -> Result<Value, FamilyError> {
        json(i, &self.get_raw(i, path, &[]).await?)
    }

    /// POST `body` as `ctype` to `path` on endpoint `i`, the answer parsed as JSON.
    pub async fn post(
        &self,
        i: usize,
        path: &str,
        body: Vec<u8>,
        ctype: &str,
    ) -> Result<Value, FamilyError> {
        let (status, b) = self
            .client
            .raw_at(
                i,
                reqwest::Method::POST,
                path,
                Some(body),
                ctype,
                ANSWER_MAX,
            )
            .await?;
        json(i, &answer(status, b)?)
    }

    /// `/v2/blocks/{round}/hash` on endpoint `i`: the block's hash as algod writes it.
    pub async fn block_hash(&self, i: usize, round: u64) -> Result<String, FamilyError> {
        let v = self.get(i, &format!("/v2/blocks/{round}/hash")).await?;
        v["blockHash"].as_str().map(str::to_string).ok_or_else(|| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                &format!("block {round} without blockHash"),
            ))
        })
    }
}

/// A 2xx's bytes, else the status and algod's message.
fn answer(status: u16, body: Vec<u8>) -> Result<Vec<u8>, FamilyError> {
    if (200..300).contains(&status) {
        return Ok(body);
    }
    let message = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["message"].as_str().map(str::to_string))
        .unwrap_or_else(|| String::from_utf8_lossy(&body).chars().take(300).collect());
    Err(FamilyError::Status {
        status,
        message: crate::error::endpoint_text(&message),
    })
}

fn json(i: usize, b: &[u8]) -> Result<Value, FamilyError> {
    crate::http::decode(b, ANSWER_MAX)
        .map_err(|k| FamilyError::Failure(EndpointFailure::new(i, k, "the answer")))
}

impl Probe for Algorand {
    type Hash = String;
    /// `/v2/transactions/params`'s `genesis-hash` against the configured network.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let v = self
            .get(i, "/v2/transactions/params")
            .await
            .map_err(|e| unread(i, e))?;
        match v["genesis-hash"].as_str() {
            Some(g) => Ok(g == self.genesis),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "params without genesis-hash",
            )),
        }
    }
    /// `/v2/status`'s `last-round`.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        let v = self.get(i, "/v2/status").await.map_err(|e| unread(i, e))?;
        v["last-round"].as_u64().ok_or_else(|| {
            EndpointFailure::new(i, FailureKind::AnswerMalformed, "status without last-round")
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
        self.block_hash(i, n).await.map_err(|e| unread(i, e))
    }
}

/// A family error as the pool's endpoint failure.
fn unread(i: usize, e: FamilyError) -> EndpointFailure {
    match e {
        FamilyError::Failure(f) => f,
        e => EndpointFailure::new(i, FailureKind::Transport, &e.to_string()),
    }
}
