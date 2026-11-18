// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Cosmos (spec §5.3 cosmos row, plan T21) on the family client: the CometBFT RPC endpoints (`status`, `block`,
//! `block_results`: each answer's `result`) and the REST gateways (`params.rest`, a list: owner 2026-11-18), whose GET and POST
//! give each answer's status and JSON for the caller's classes (a smart query's error, a refused simulate, a broadcast's code).
//! The failover of `build`'s reads runs over the REST gateways: their identity is `node_info`'s network (the chain id), their
//! head the latest block's height. Protobuf, events and the transaction classes are the caller's to read.
use crate::family::{Client, FamilyError, ANSWER_MAX};
use crate::pool::{BlockChoice, Probe};
use crate::{EndpointFailure, FailureKind};
use serde_json::Value;
use web_time::Instant;

/// One Cosmos network: its CometBFT RPC endpoints and its REST gateways.
pub struct Cosmos {
    pub rpc: Client,
    pub rest: Rest,
}

/// The REST gateways of one Cosmos network, named by its chain id.
pub struct Rest {
    pub client: Client,
    chain_id: String,
}

impl Cosmos {
    pub fn new(rpc: Client, rest: Client, chain_id: &str) -> Self {
        Self {
            rpc,
            rest: Rest {
                client: rest,
                chain_id: chain_id.into(),
            },
        }
    }

    /// CometBFT RPC `path` (with its query) on endpoint `i`: its `result`; a status other than 200 or an `error` member is
    /// `FamilyError::Rpc` (the error, else the answer, whole).
    pub async fn rpc_at(&self, i: usize, path: &str) -> Result<Value, FamilyError> {
        let (status, v) = json_at(&self.rpc, i, reqwest::Method::GET, path, None).await?;
        if status != 200 || v.get("error").is_some_and(|e| !e.is_null()) {
            return Err(FamilyError::Rpc {
                method: path.into(),
                error: v.get("error").cloned().unwrap_or(v),
            });
        }
        Ok(v["result"].clone())
    }
}

impl Rest {
    /// GET `path` on gateway `i`: the status and the JSON (`null` for no body).
    pub async fn get(&self, i: usize, path: &str) -> Result<(u16, Value), FamilyError> {
        json_at(&self.client, i, reqwest::Method::GET, path, None).await
    }

    /// POST `body` (JSON) to `path` on gateway `i`: the status and the JSON.
    pub async fn post(
        &self,
        i: usize,
        path: &str,
        body: &Value,
    ) -> Result<(u16, Value), FamilyError> {
        let b = serde_json::to_vec(body).map_err(|e| {
            FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::Transport,
                &e.to_string(),
            ))
        })?;
        json_at(&self.client, i, reqwest::Method::POST, path, Some(b)).await
    }

    /// A 2xx answer of gateway `i` to `path`, else the endpoint's failure `kind`.
    async fn ok(&self, i: usize, path: &str, kind: FailureKind) -> Result<Value, EndpointFailure> {
        match self.get(i, path).await {
            Ok((200..=299, v)) => Ok(v),
            Ok((s, _)) => Err(EndpointFailure::new(i, kind, &format!("{path}: HTTP {s}"))),
            Err(FamilyError::Failure(f)) => Err(f),
            Err(e) => Err(EndpointFailure::new(
                i,
                FailureKind::Transport,
                &e.to_string(),
            )),
        }
    }
}

/// One request: its status (any: the gateway's error answer is its JSON at a 4xx or a 5xx, a refused simulate a 500 with its
/// code) and its JSON (bounded: 16 MiB, depth 64; an empty body is `null`; a body that is not JSON is the endpoint's failure).
async fn json_at(
    c: &Client,
    i: usize,
    method: reqwest::Method,
    path: &str,
    body: Option<Vec<u8>>,
) -> Result<(u16, Value), FamilyError> {
    let (status, b) = c
        .raw_any_at(i, method, path, body, "application/json", ANSWER_MAX)
        .await?;
    if b.iter().all(u8::is_ascii_whitespace) {
        return Ok((status, Value::Null));
    }
    let v = crate::http::decode(&b, ANSWER_MAX)
        .map_err(|k| FamilyError::Failure(EndpointFailure::new(i, k, "the answer")))?;
    Ok((status, v))
}

const NODE_INFO: &str = "/cosmos/base/tendermint/v1beta1/node_info";
const LATEST: &str = "/cosmos/base/tendermint/v1beta1/blocks/latest";

impl Probe for Rest {
    type Hash = String;
    /// `node_info`'s `default_node_info.network` against the configured chain id.
    async fn same_chain(&self, i: usize, _: Option<Instant>) -> Result<bool, EndpointFailure> {
        let v = self.ok(i, NODE_INFO, FailureKind::IdentityUnread).await?;
        match v["default_node_info"]["network"].as_str() {
            Some(n) => Ok(n == self.chain_id),
            None => Err(EndpointFailure::new(
                i,
                FailureKind::IdentityUnread,
                "node_info without default_node_info.network",
            )),
        }
    }
    /// The latest block's height.
    async fn head(&self, i: usize, _: Option<Instant>) -> Result<u64, EndpointFailure> {
        let v = self.ok(i, LATEST, FailureKind::AnswerMalformed).await?;
        v["block"]["header"]["height"]
            .as_str()
            .and_then(|h| h.parse().ok())
            .ok_or_else(|| {
                EndpointFailure::new(
                    i,
                    FailureKind::AnswerMalformed,
                    "latest block without a height",
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
        let path = format!("/cosmos/base/tendermint/v1beta1/blocks/{n}");
        let v = self.ok(i, &path, FailureKind::AnswerMalformed).await?;
        v["block_id"]["hash"]
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| {
                EndpointFailure::new(i, FailureKind::AnswerMalformed, "a block without hash")
            })
    }
}
