// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Aptos fullnode REST and the Indexer API (spec §5.3 aptos row, plan T19) on the family client: a GET whose 404 is an
//! answer (none), a POST whose status and JSON come back for the caller's classes (views, simulate), the send's status and
//! text, the quorum read (`agreed`), a block by height, the Indexer API's GraphQL (its own endpoint and credential), the
//! network identity (ledger info `chain_id`) and the head (ledger info `block_height`) for the failover's floor. Views'
//! values, transactions and events are the caller's to read.
use crate::family::{AgreedError, Client, FamilyError, ANSWER_MAX};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::{json, Value};
use web_time::Instant;

/// The family client of one Aptos network (its REST endpoints), named by its chain id, and its Indexer API.
pub struct Aptos {
    pub client: Client,
    pub indexer: Client,
    chain_id: u8,
    /// the indexer named this network (its `ledger_infos` `chain_id`), kept for the process
    indexer_known: std::sync::atomic::AtomicBool,
}

impl Aptos {
    pub fn new(client: Client, indexer: Client, chain_id: u8) -> Self {
        Self {
            client,
            indexer,
            chain_id,
            indexer_known: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// GET `path` of endpoint `i`: a 2xx's JSON (bounded: 16 MiB, depth 64), `None` for a 404 (whatever its body), any other
    /// 4xx `FamilyError::Status` with its body's text.
    pub async fn get_at(&self, i: usize, path: &str) -> Result<Option<Value>, FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
        self.fetch(i, path).await
    }

    /// [`Aptos::get_at`] without the identity check (the probe's own reads).
    async fn fetch(&self, i: usize, path: &str) -> Result<Option<Value>, FamilyError> {
        let (status, b) = self
            .client
            .raw_at(
                i,
                reqwest::Method::GET,
                path,
                None,
                "application/json",
                ANSWER_MAX,
            )
            .await?;
        match status {
            200..=299 => crate::http::decode(&b, ANSWER_MAX)
                .map(Some)
                .map_err(|k| FamilyError::Failure(EndpointFailure::new(i, k, "the answer"))),
            404 => Ok(None),
            _ => Err(FamilyError::Status {
                status,
                message: crate::error::endpoint_text(&String::from_utf8_lossy(&b)),
            }),
        }
    }

    /// POST `body` as `ctype` to `path` of endpoint `i`: the status (2xx or 4xx; a 5xx is the endpoint's failure) and the
    /// answer as JSON (bounded: 16 MiB, depth 64), for the caller's classes (a view's abort, a simulate's refusal).
    pub async fn post_json(
        &self,
        i: usize,
        path: &str,
        body: Vec<u8>,
        ctype: &str,
    ) -> Result<(u16, Value), FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
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
        let v = crate::http::decode(&b, ANSWER_MAX)
            .map_err(|k| FamilyError::Failure(EndpointFailure::new(i, k, "the answer")))?;
        Ok((status, v))
    }

    /// POST `body` as `ctype` to `path` of endpoint `i`: the status and the answer's text (the send's classes).
    pub async fn post_text(
        &self,
        i: usize,
        path: &str,
        body: Vec<u8>,
        ctype: &str,
    ) -> Result<(u16, String), FamilyError> {
        crate::family::admit_first(&self.client, self, i).await?;
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
        Ok((status, String::from_utf8_lossy(&b).into_owned()))
    }

    /// Endpoint 0's answer to GET `path` (a 404 is `First(Status 404)`); with `quorum > 1`, further endpoints must give the
    /// same `pick` until `quorum` agree (endpoint 0 counts; an endpoint that fails or has none counts as not agreeing).
    pub async fn agreed(
        &self,
        path: &str,
        pick: fn(&Value) -> Value,
        quorum: usize,
    ) -> Result<Value, AgreedError> {
        let v = self
            .get_at(0, path)
            .await
            .and_then(|v| v.ok_or_else(not_found))
            .map_err(AgreedError::First)?;
        if quorum > 1 {
            let want = pick(&v);
            let mut agree = 1;
            for i in 1..self.client.len() {
                if matches!(self.get_at(i, path).await, Ok(Some(o)) if pick(&o) == want) {
                    agree += 1;
                }
            }
            if agree < quorum {
                return Err(AgreedError::Quorum { agree, quorum });
            }
        }
        Ok(v)
    }

    /// The block at `height` on endpoint `i`.
    pub async fn block(&self, i: usize, height: u64) -> Result<Value, FamilyError> {
        self.get_at(i, &format!("/blocks/by_height/{height}"))
            .await?
            .ok_or_else(not_found)
    }

    /// The Indexer API's answer (its `data`) to `query`, through `Client::graphql_at`: its `errors` are `FamilyError::Graphql`,
    /// an answer without `data` its `AnswerMalformed` (review T26 B-9, CLI-RPC-07). Before its first query the indexer names its
    /// network (`ledger_infos`' `chain_id`, CLI-RPC-03), kept for the process: another is `WrongChain`, none `IdentityUnread`.
    pub async fn graphql(&self, query: &str, variables: Value) -> Result<Value, FamilyError> {
        use std::sync::atomic::Ordering::Relaxed;
        if !self.indexer_known.load(Relaxed) {
            let d = self
                .indexer
                .graphql_at(0, "{ ledger_infos(limit: 1) { chain_id } }", json!({}))
                .await?;
            let failure = |k, why| FamilyError::Failure(EndpointFailure::new(0, k, why));
            match num(&d["ledger_infos"][0]["chain_id"]) {
                Some(c) if c == u64::from(self.chain_id) => self.indexer_known.store(true, Relaxed),
                Some(_) => {
                    return Err(failure(
                        FailureKind::WrongChain,
                        "the indexer of another network",
                    ))
                }
                None => {
                    return Err(failure(
                        FailureKind::IdentityUnread,
                        "the indexer names no chain id",
                    ))
                }
            }
        }
        self.indexer.graphql_at(0, query, variables).await
    }
}

fn not_found() -> FamilyError {
    FamilyError::Status {
        status: 404,
        message: "not found".into(),
    }
}

/// A number Aptos writes as a string (u64 fields) or as a number.
fn num(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

impl Probe for Aptos {
    type Hash = String;
    /// Ledger info's `chain_id` against the configured network.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let v = self.ledger(i).await?;
        match v["chain_id"].as_u64() {
            Some(c) => Ok(c == u64::from(self.chain_id)),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "ledger info without chain_id",
            )),
        }
    }
    /// Ledger info's `block_height`.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        num(&self.ledger(i).await?["block_height"]).ok_or_else(|| {
            EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "ledger info without block_height",
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
        let b = self.block(i, n).await.map_err(|e| unread(i, e))?;
        b["block_hash"].as_str().map(str::to_string).ok_or_else(|| {
            EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                "a block without block_hash",
            )
        })
    }
}

impl Aptos {
    /// Ledger info (`GET` the REST root) of endpoint `i`.
    async fn ledger(&self, i: usize) -> Result<Value, EndpointFailure> {
        self.fetch(i, "")
            .await
            .and_then(|v| v.ok_or_else(not_found))
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
