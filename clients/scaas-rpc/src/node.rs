// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The scaas-node client (CLI-RPC-10, spec §6): the gateway routes the node serves, named-field bodies serialised once and never
//! rewritten, the node's error contract read by `code` (else the legacy `error` string), per-endpoint credentials (bearer or
//! NODE-GW-02's HMAC), no redirects, bounded answers. A client call exists only for a route the node serves.

use crate::endpoint::NodeList;
use crate::error::{EndpointFailure, RpcError};
use crate::http::Http;
use serde_json::Value;
use std::sync::Arc;

/// The body cap of `/v1/op`, `/v1/ua-metatx` and the DEX routes (the gateway's `DefaultBodyLimit`).
pub const BODY_MAX: usize = 64 << 10;
/// A gateway answer's cap.
pub const ANSWER_MAX: usize = 1 << 20;

/// One gateway's answer to a submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeOutcome {
    /// `202 {"status": "queued", "intent_id"?}`, or `200` (a duplicate)
    Queued { status: u16, intent_id: Option<String> },
    /// the node's error contract (`NodeRefused`)
    Refused(RpcError),
    /// transport, timeout, a 3xx (never followed), a 5xx, `RPC_UNAVAILABLE`, a malformed answer
    Unreachable(EndpointFailure),
}

/// `POST /v1/ua-metatx`'s body: `{chain, token, contract?, struct?, m, auth}`, `m` and `auth` the values `ua-rs` builds.
#[derive(Debug, Clone, serde::Serialize)]
pub struct UaMetaTxReq {
    pub chain: u64,
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract: Option<String>,
    #[serde(rename = "struct", skip_serializing_if = "Option::is_none")]
    pub struct_: Option<String>,
    pub m: Value,
    pub auth: Value,
}

/// The client of a list of scaas-node gateways, each with its own credential.
#[derive(Clone)]
pub struct NodeClient {
    list: Arc<NodeList>,
    http: Http,
}

impl std::fmt::Debug for NodeClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeClient").field("list", &self.list).finish()
    }
}

fn object(v: &Value, what: &str) -> Result<(), RpcError> {
    if v.is_object() {
        Ok(())
    } else {
        Err(RpcError::argument(&format!("{what} is not a JSON object")))
    }
}

impl NodeClient {
    pub fn new(list: NodeList) -> Result<Self, RpcError> {
        Ok(Self { http: Http::new(list.timeout_ms)?, list: Arc::new(list) })
    }

    pub fn list(&self) -> &NodeList {
        &self.list
    }

    /// `POST /v1/op {chain, op}` to gateway `i`: `op` the object `ua-rs` built, serialised once, byte for byte.
    pub async fn submit_op_at(&self, i: usize, chain: u64, op: &Value) -> Result<NodeOutcome, RpcError> {
        object(op, "op")?;
        let body = format!(r#"{{"chain":{chain},"op":{}}}"#, serde_json::to_string(op).expect("a Value serialises")).into_bytes();
        self.submit_at(i, "/v1/op", body).await
    }

    /// `POST /v1/ua-metatx` to gateway `i`.
    pub async fn submit_ua_metatx_at(&self, i: usize, req: &UaMetaTxReq) -> Result<NodeOutcome, RpcError> {
        object(&req.m, "m")?;
        object(&req.auth, "auth")?;
        self.submit_at(i, "/v1/ua-metatx", serde_json::to_vec(req).expect("a request serialises")).await
    }

    /// `POST /v1/dex/orders` (`{chain, sellToken, order, signature | auth}`, the gateway's body) to gateway `i`.
    pub async fn dex_place_at(&self, i: usize, req: &Value) -> Result<NodeOutcome, RpcError> {
        self.dex_post(i, "/v1/dex/orders", req).await
    }
    /// `POST /v1/dex/cancel` (`{chain, orderHash, signature | auth}`).
    pub async fn dex_cancel_at(&self, i: usize, req: &Value) -> Result<NodeOutcome, RpcError> {
        self.dex_post(i, "/v1/dex/cancel", req).await
    }
    /// `POST /v1/dex/cancel-all` (`{chain, sellToken, from, batch, minNonce, signature | auth}`).
    pub async fn dex_cancel_all_at(&self, i: usize, req: &Value) -> Result<NodeOutcome, RpcError> {
        self.dex_post(i, "/v1/dex/cancel-all", req).await
    }

    async fn dex_post(&self, i: usize, route: &str, req: &Value) -> Result<NodeOutcome, RpcError> {
        object(req, "the DEX request")?;
        self.submit_at(i, route, serde_json::to_vec(req).expect("a Value serialises")).await
    }

    /// `GET /v1/dex/markets?chain=`, failed over.
    pub async fn dex_markets(&self, chain: u64) -> Result<Value, RpcError> {
        self.get(&format!("/v1/dex/markets?chain={chain}")).await
    }
    /// `GET /v1/dex/depth?chain=&market=&levels=`, failed over.
    pub async fn dex_depth(&self, chain: u64, market: i64, levels: Option<usize>) -> Result<Value, RpcError> {
        let l = levels.map(|l| format!("&levels={l}")).unwrap_or_default();
        self.get(&format!("/v1/dex/depth?chain={chain}&market={market}{l}")).await
    }
    /// `GET /v1/dex/trades?chain=&market=`, failed over.
    pub async fn dex_trades(&self, chain: u64, market: i64) -> Result<Value, RpcError> {
        self.get(&format!("/v1/dex/trades?chain={chain}&market={market}")).await
    }
    /// `GET /v1/dex/ticker?chain=&market=`, failed over.
    pub async fn dex_ticker(&self, chain: u64, market: i64) -> Result<Value, RpcError> {
        self.get(&format!("/v1/dex/ticker?chain={chain}&market={market}")).await
    }
    /// `GET /v1/dex/orders?chain=&maker=` (an id or an address), failed over.
    pub async fn dex_orders(&self, chain: u64, maker: &str) -> Result<Value, RpcError> {
        if !maker.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(RpcError::argument("maker is an id or an address in hex"));
        }
        self.get(&format!("/v1/dex/orders?chain={chain}&maker={maker}")).await
    }

    /// One submit to gateway `i`: the body cap first (nothing sent above it), then the answer by the node's contract.
    async fn submit_at(&self, i: usize, route: &str, body: Vec<u8>) -> Result<NodeOutcome, RpcError> {
        if body.len() > BODY_MAX {
            return Err(RpcError::BodyTooLarge { len: body.len(), cap: BODY_MAX });
        }
        Ok(match self.http.request(&self.list, i, reqwest::Method::POST, route, Some(body), ANSWER_MAX, None).await {
            Err(f) => NodeOutcome::Unreachable(f),
            Ok((status, v)) => answer(i, status, v),
        })
    }

    /// A read route, failed over in list order: the first gateway that answers a 2xx; a 4xx is the node's refusal, final.
    async fn get(&self, path: &str) -> Result<Value, RpcError> {
        let mut last = None;
        for i in 0..self.list.len() {
            match self.http.request(&self.list, i, reqwest::Method::GET, path, None, ANSWER_MAX, None).await {
                Ok((s, v)) if (200..300).contains(&s) => return Ok(v),
                Ok((s, v)) => match answer(i, s, v) {
                    NodeOutcome::Refused(e) => return Err(e),
                    NodeOutcome::Unreachable(f) => last = Some(f),
                    NodeOutcome::Queued { .. } => unreachable!("not a 2xx"),
                },
                Err(f) => last = Some(f),
            }
        }
        Err(RpcError::EndpointAllFailed { last, failover_revert: None })
    }
}

/// The node's answer by its contract (NODE-GW-06): 2xx `queued`; an error read by `code`, else the legacy `error` string, with
/// `detail` and `revert_data`; `RPC_UNAVAILABLE` is unreachable.
fn answer(i: usize, status: u16, v: Value) -> NodeOutcome {
    if (200..300).contains(&status) {
        return NodeOutcome::Queued { status, intent_id: v["intent_id"].as_str().map(str::to_string) };
    }
    let code = v["code"].as_str().or(v["error"].as_str()).unwrap_or("").to_string();
    if code == "RPC_UNAVAILABLE" {
        return NodeOutcome::Unreachable(EndpointFailure::new(i, crate::FailureKind::Http, &format!("HTTP {status} RPC_UNAVAILABLE")));
    }
    let text = |k: &str| v[k].as_str().map(crate::error::endpoint_text);
    NodeOutcome::Refused(RpcError::NodeRefused {
        status,
        code: crate::error::endpoint_text(&code),
        detail: text("detail"),
        revert_data: v["revert_data"].as_str().map(str::to_string).filter(|d| d.starts_with("0x") && d.len() <= 2 * ANSWER_MAX),
    })
}
