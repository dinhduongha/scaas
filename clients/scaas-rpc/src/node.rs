// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The scaas-node client (CLI-RPC-10, spec §6): the gateway routes the node serves, named-field bodies serialised once and never
//! rewritten, the node's error contract read by `code` (else the legacy `error` string), per-endpoint credentials (bearer or
//! NODE-GW-02's HMAC), no redirects, bounded answers. A client call exists only for a route the node serves.

use crate::endpoint::NodeList;
use crate::error::{EndpointFailure, RpcError};
use crate::http::Http;
use serde_json::Value;
use std::sync::Arc;

/// The body cap of `/v1/ua-metatx` and the DEX routes (the gateway's `DefaultBodyLimit`).
pub const BODY_MAX: usize = 64 << 10;
/// The body cap of a job submission, `/v1/op` (NODE-GW-08, the node's `OP_BODY_MAX`): the largest PQZ debit as JSON (its proof
/// and ciphertexts at most pqz-stmt's `MAX_INPUT`, 524,288 B, as hex, with the signatures and named fields) with ≈ 20 % headroom.
pub const OP_BODY_MAX: usize = 1_310_720;

/// The body cap of `route`.
fn cap_of(route: &str) -> usize {
    if route == "/v1/op" {
        OP_BODY_MAX
    } else {
        BODY_MAX
    }
}
/// A gateway answer's cap.
pub const ANSWER_MAX: usize = 1 << 20;

/// One gateway's answer to a submit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeOutcome {
    /// `202 {"status": "queued", "intent_id"?}`, or `200` (a duplicate)
    Queued {
        status: u16,
        intent_id: Option<String>,
    },
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
        f.debug_struct("NodeClient")
            .field("list", &self.list)
            .finish()
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
        Ok(Self {
            http: Http::new(list.timeout_ms)?,
            list: Arc::new(list),
        })
    }

    pub fn list(&self) -> &NodeList {
        &self.list
    }

    /// `POST /v1/op {chain, op}` to gateway `i`: `op` the object `ua-rs` built, serialised once, byte for byte.
    pub async fn submit_op_at(
        &self,
        i: usize,
        chain: u64,
        op: &Value,
    ) -> Result<NodeOutcome, RpcError> {
        object(op, "op")?;
        let body = format!(
            r#"{{"chain":{chain},"op":{}}}"#,
            serde_json::to_string(op).expect("a Value serialises")
        )
        .into_bytes();
        self.submit_at(i, "/v1/op", body).await
    }

    /// `POST /v1/ua-metatx` to gateway `i`.
    pub async fn submit_ua_metatx_at(
        &self,
        i: usize,
        req: &UaMetaTxReq,
    ) -> Result<NodeOutcome, RpcError> {
        object(&req.m, "m")?;
        object(&req.auth, "auth")?;
        self.submit_at(
            i,
            "/v1/ua-metatx",
            serde_json::to_vec(req).expect("a request serialises"),
        )
        .await
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
        self.submit_at(
            i,
            route,
            serde_json::to_vec(req).expect("a Value serialises"),
        )
        .await
    }

    /// `GET /v1/dex/markets?chain=`, failed over.
    pub async fn dex_markets(&self, chain: u64) -> Result<Value, RpcError> {
        self.get(&format!("/v1/dex/markets?chain={chain}")).await
    }
    /// `GET /v1/dex/depth?chain=&market=&levels=`, failed over.
    pub async fn dex_depth(
        &self,
        chain: u64,
        market: i64,
        levels: Option<usize>,
    ) -> Result<Value, RpcError> {
        let l = levels.map(|l| format!("&levels={l}")).unwrap_or_default();
        self.get(&format!("/v1/dex/depth?chain={chain}&market={market}{l}"))
            .await
    }
    /// `GET /v1/dex/trades?chain=&market=`, failed over.
    pub async fn dex_trades(&self, chain: u64, market: i64) -> Result<Value, RpcError> {
        self.get(&format!("/v1/dex/trades?chain={chain}&market={market}"))
            .await
    }
    /// `GET /v1/dex/ticker?chain=&market=`, failed over.
    pub async fn dex_ticker(&self, chain: u64, market: i64) -> Result<Value, RpcError> {
        self.get(&format!("/v1/dex/ticker?chain={chain}&market={market}"))
            .await
    }
    /// `GET /v1/dex/orders?chain=&maker=` (an id or an address), failed over.
    pub async fn dex_orders(&self, chain: u64, maker: &str) -> Result<Value, RpcError> {
        if !maker.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(RpcError::argument("maker is an id or an address in hex"));
        }
        self.get(&format!("/v1/dex/orders?chain={chain}&maker={maker}"))
            .await
    }

    /// `GET /v1/gateway` of gateway `i` alone (NODE-GW-05): what it announces, never another gateway's answer (a client checks
    /// each gateway's `chain_uid` against its own pinned profile before it posts there).
    pub async fn gateway_at(&self, i: usize) -> Result<Value, RpcError> {
        let failed = |f| RpcError::EndpointAllFailed {
            last: Some(f),
            failover_revert: None,
        };
        match self
            .http
            .request(
                &self.list,
                i,
                reqwest::Method::GET,
                "/v1/gateway",
                None,
                ANSWER_MAX,
                None,
            )
            .await
        {
            Ok((s, v)) if (200..300).contains(&s) => Ok(v),
            Ok((s, v)) => match answer(i, s, v) {
                NodeOutcome::Refused(e) => Err(e),
                NodeOutcome::Unreachable(f) => Err(failed(f)),
                NodeOutcome::Queued { .. } => Err(RpcError::argument("not a 2xx")),
            },
            Err(f) => Err(failed(f)),
        }
    }

    /// One submit to gateway `i`: the body cap first (nothing sent above it), then the answer by the node's contract.
    async fn submit_at(
        &self,
        i: usize,
        route: &str,
        body: Vec<u8>,
    ) -> Result<NodeOutcome, RpcError> {
        if body.len() > cap_of(route) {
            return Err(RpcError::BodyTooLarge {
                len: body.len(),
                cap: cap_of(route),
            });
        }
        Ok(
            match self
                .http
                .request(
                    &self.list,
                    i,
                    reqwest::Method::POST,
                    route,
                    Some(body),
                    ANSWER_MAX,
                    None,
                )
                .await
            {
                Err(f) => NodeOutcome::Unreachable(f),
                // T13 S14: a submit route's 2xx carries the job's state (`queued`, or a duplicate's stored state, NODE-GW-06);
                // any other 2xx JSON is no answer of the node's
                Ok((status, v))
                    if (200..300).contains(&status)
                        && matches!(route, "/v1/op" | "/v1/ua-metatx")
                        && !v["status"].is_string() =>
                {
                    NodeOutcome::Unreachable(EndpointFailure::new(
                        i,
                        crate::FailureKind::AnswerMalformed,
                        &format!("HTTP {status} without the job's status"),
                    ))
                }
                Ok((status, v)) => answer(i, status, v),
            },
        )
    }

    /// A read route, failed over in list order: the first gateway that answers a 2xx; a 4xx is the node's refusal, final.
    async fn get(&self, path: &str) -> Result<Value, RpcError> {
        let mut last = None;
        for i in 0..self.list.len() {
            match self
                .http
                .request(
                    &self.list,
                    i,
                    reqwest::Method::GET,
                    path,
                    None,
                    ANSWER_MAX,
                    None,
                )
                .await
            {
                Ok((s, v)) if (200..300).contains(&s) => return Ok(v),
                Ok((s, v)) => match answer(i, s, v) {
                    NodeOutcome::Refused(e) => return Err(e),
                    NodeOutcome::Unreachable(f) => last = Some(f),
                    NodeOutcome::Queued { .. } => unreachable!("not a 2xx"),
                },
                Err(f) => last = Some(f),
            }
        }
        Err(RpcError::EndpointAllFailed {
            last,
            failover_revert: None,
        })
    }
}

/// The longest `revert_data` kept from a gateway (T13 S4): a custom error with 127 words of arguments.
const REVERT_DATA_MAX: usize = 4096;

/// The node's answer by its contract (NODE-GW-06): 2xx `queued`; an error read by `code`, else the legacy `error` string, with
/// `detail` and `revert_data`; `RPC_UNAVAILABLE` is unreachable.
fn answer(i: usize, status: u16, v: Value) -> NodeOutcome {
    if (200..300).contains(&status) {
        return NodeOutcome::Queued {
            status,
            // T13 S4: the gateway's text (CLI-RPC-11)
            intent_id: v["intent_id"].as_str().map(crate::error::endpoint_text),
        };
    }
    let code = v["code"]
        .as_str()
        .or(v["error"].as_str())
        .unwrap_or("")
        .to_string();
    if code == "RPC_UNAVAILABLE" {
        return NodeOutcome::Unreachable(EndpointFailure::new(
            i,
            crate::FailureKind::Http,
            &format!("HTTP {status} RPC_UNAVAILABLE"),
        ));
    }
    let text = |k: &str| v[k].as_str().map(crate::error::endpoint_text);
    NodeOutcome::Refused(RpcError::NodeRefused {
        status,
        code: crate::error::endpoint_text(&code),
        detail: text("detail"),
        revert_data: v["revert_data"]
            .as_str()
            .map(str::to_string)
            // T13 S4: hex only, at most REVERT_DATA_MAX bytes, else none (never cut: cut data is another error)
            .filter(|d| {
                d.strip_prefix("0x").is_some_and(|h| {
                    h.len() % 2 == 0
                        && h.len() <= 2 * REVERT_DATA_MAX
                        && h.bytes().all(|b| b.is_ascii_hexdigit())
                })
            }),
    })
}

// ---------------------------------------------------------------- plan T11: several nodes (spec §6.4, §4.8)

pub use crate::endpoint::Fanout;

/// The merge of one submit to several gateways (CLI-RPC-08): neither arm is final.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// at least one gateway queued it
    Queued {
        by: Vec<usize>,
        refused: Vec<(usize, RpcError)>,
        unreachable: Vec<(usize, EndpointFailure)>,
    },
    /// none did: every gateway's outcome
    NotQueued { outcomes: Vec<(usize, NodeOutcome)> },
}

impl SubmitOutcome {
    /// Never: a refusal can be a dishonest node's, a queue is no landing (CLI-RPC-09).
    pub fn is_terminal(&self) -> bool {
        false
    }
}

/// What one gateway reports of a submitted operation (its job states, job-api.md): `mined` / `final`, `dead`, still in its
/// pipeline, or it does not know the intent; `None` in [`NodeClient::merged_state`] is a gateway that could not be asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentState {
    Mined,
    Dead,
    InFlight,
    Unknown,
}

/// The merged state over several gateways (CLI-RPC-09): never terminal. `Landed`: a gateway reports it mined (the caller then
/// reads the chain facts); `GivenUpByEveryNode`: every gateway the bytes were sent to reports `dead` or does not know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MergedState {
    Landed { by: Vec<usize> },
    InFlight,
    GivenUpByEveryNode,
}

impl MergedState {
    /// Never: only the chain's facts end a relayed operation.
    pub fn is_terminal(&self) -> bool {
        false
    }
}

impl NodeClient {
    /// `POST /v1/op {chain, op}`: the same bytes to the gateways `fanout` selects, concurrently, merged.
    pub async fn submit_op(
        &self,
        chain: u64,
        op: &Value,
        fanout: Fanout,
    ) -> Result<SubmitOutcome, RpcError> {
        object(op, "op")?;
        let body = format!(
            r#"{{"chain":{chain},"op":{}}}"#,
            serde_json::to_string(op).expect("a Value serialises")
        )
        .into_bytes();
        self.fan(fanout, "/v1/op", body).await
    }

    /// `POST /v1/ua-metatx`: the same bytes to the gateways `fanout` selects.
    pub async fn submit_ua_metatx(
        &self,
        req: &UaMetaTxReq,
        fanout: Fanout,
    ) -> Result<SubmitOutcome, RpcError> {
        object(&req.m, "m")?;
        object(&req.auth, "auth")?;
        self.fan(
            fanout,
            "/v1/ua-metatx",
            serde_json::to_vec(req).expect("a request serialises"),
        )
        .await
    }

    async fn fan(
        &self,
        fanout: Fanout,
        route: &str,
        body: Vec<u8>,
    ) -> Result<SubmitOutcome, RpcError> {
        if body.len() > cap_of(route) {
            return Err(RpcError::BodyTooLarge {
                len: body.len(),
                cap: cap_of(route),
            });
        }
        let to: Vec<usize> = match fanout {
            Fanout::First => vec![0],
            Fanout::All => (0..self.list.len()).collect(),
        };
        let outcomes = futures::future::join_all(to.iter().map(|&i| {
            let body = body.clone();
            async move { (i, self.submit_at(i, route, body).await) }
        }))
        .await;
        let outcomes: Vec<(usize, NodeOutcome)> = outcomes
            .into_iter()
            .map(|(i, o)| (i, o.expect("the cap is checked once")))
            .collect();
        let by: Vec<usize> = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, NodeOutcome::Queued { .. }))
            .map(|(i, _)| *i)
            .collect();
        if by.is_empty() {
            return Ok(SubmitOutcome::NotQueued { outcomes });
        }
        let (mut refused, mut unreachable) = (vec![], vec![]);
        for (i, o) in outcomes {
            match o {
                NodeOutcome::Refused(e) => refused.push((i, e)),
                NodeOutcome::Unreachable(f) => unreachable.push((i, f)),
                NodeOutcome::Queued { .. } => {}
            }
        }
        Ok(SubmitOutcome::Queued {
            by,
            refused,
            unreachable,
        })
    }

    /// The merge over `sent_to`, every gateway the bytes were sent to (whatever it answered at submit); `states` what each one
    /// reports now (`None`: not reachable). Pure; never terminal.
    pub fn merged_state(sent_to: &[usize], states: &[(usize, Option<IntentState>)]) -> MergedState {
        let of = |i: usize| states.iter().find(|(j, _)| *j == i).and_then(|(_, s)| *s);
        let by: Vec<usize> = sent_to
            .iter()
            .copied()
            .filter(|&i| of(i) == Some(IntentState::Mined))
            .collect();
        if !by.is_empty() {
            return MergedState::Landed { by };
        }
        if !sent_to.is_empty()
            && sent_to
                .iter()
                .all(|&i| matches!(of(i), Some(IntentState::Dead | IntentState::Unknown)))
        {
            return MergedState::GivenUpByEveryNode;
        }
        MergedState::InFlight
    }
}

// ---------------------------------------------------------------- the PQZ verifier client (spec §6.1; owner 2026-11-19, C1)

/// `POST /v1/pqz-verdict` of a PQZ verifier (`scaas-pqz-verifier`'s HTTP door, CTR-PQZ-29).
pub const VERDICT_ROUTE: &str = "/v1/pqz-verdict";
/// `POST /v1/pqz-verdict/probe`: whether a verifier would serve a token's verifier-mode operation.
pub const PROBE_ROUTE: &str = "/v1/pqz-verdict/probe";
/// The body cap of a verdict request: a statement and a PQZ proof of the largest set fit (the verifier's own `body_limit()`
/// refuses above its set's figure). ponytail: one cap for every set; the verifier's per-set limit is the real bound.
pub const VERDICT_BODY_MAX: usize = 8 << 20;

/// What `strict_majority` compares of a verdict answer: its `pqzVerdict` without `validUntil`, which each verifier sets from
/// its own clock (F14, review 2026-11-20); the group's answer with the smallest `validUntil` is returned.
fn verdict_compared(v: &Value) -> Value {
    let mut c = v["pqzVerdict"].clone();
    if let Some(o) = c.as_object_mut() {
        o.remove("validUntil");
    }
    c
}

/// A verdict answer's `validUntil` (a number or a decimal string); `u64::MAX` when absent or unreadable (never preferred).
fn valid_until(v: &Value) -> u64 {
    let x = &v["pqzVerdict"]["validUntil"];
    x.as_u64()
        .or_else(|| x.as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(u64::MAX)
}

/// The client of a list of PQZ verifiers, each endpoint with its own credential (spec §6.1, §6.3: no redirect followed, answers
/// bounded by [`ANSWER_MAX`] and depth). ARCH-POS-15 by the list's policy: `failover` (the default) takes the first endpoint's
/// 2xx answer in list order, moving on past an unreachable one (transport, timeout, 3xx, 5xx: the verifier's `BUSY`,
/// `RPC_UNAVAILABLE`), and a 4xx is the verifier's refusal, final (`NodeRefused` by its `error` code, never retried elsewhere);
/// `strict_majority` asks every endpoint and needs more than half of them to give a 2xx answer equal in what is compared (a
/// verdict's `pqzVerdict` without `validUntil`, the signature apart, and of the group the answer that expires first; a probe's
/// whole answer), else `EndpointNoMajority`. The answer is returned as the verifier sent it: the caller checks the verdict's typed data and its signer before it attaches it.
#[derive(Clone)]
pub struct VerifierClient {
    list: Arc<NodeList>,
    http: Http,
}

impl std::fmt::Debug for VerifierClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierClient")
            .field("list", &self.list)
            .finish()
    }
}

impl VerifierClient {
    pub fn new(list: NodeList) -> Result<Self, RpcError> {
        Ok(Self {
            http: Http::new(list.timeout_ms)?,
            list: Arc::new(list),
        })
    }

    /// `POST /v1/pqz-verdict` with `req` (the verifier's named fields), serialised once and sent byte for byte: its
    /// `{pqzVerdict, pqzVerdictSig}`.
    pub async fn verdict(&self, req: &Value) -> Result<Value, RpcError> {
        self.post(VERDICT_ROUTE, req, verdict_compared).await
    }

    /// `POST /v1/pqz-verdict/probe` with `req`: the verifier's answer.
    pub async fn probe(&self, req: &Value) -> Result<Value, RpcError> {
        self.post(PROBE_ROUTE, req, Value::clone).await
    }

    async fn post(
        &self,
        route: &str,
        req: &Value,
        compared: fn(&Value) -> Value,
    ) -> Result<Value, RpcError> {
        object(req, "the verifier request")?;
        let body = serde_json::to_vec(req).expect("a Value serialises");
        if body.len() > VERDICT_BODY_MAX {
            return Err(RpcError::BodyTooLarge {
                len: body.len(),
                cap: VERDICT_BODY_MAX,
            });
        }
        let n = self.list.len();
        let majority = self.list.policy == crate::Policy::StrictMajority;
        let (mut last, mut failures, mut answers) = (None, vec![], Vec::<(Value, Value)>::new());
        for i in 0..n {
            let a = self
                .http
                .request(
                    &self.list,
                    i,
                    reqwest::Method::POST,
                    route,
                    Some(body.clone()),
                    ANSWER_MAX,
                    None,
                )
                .await;
            let f = match a {
                Ok((s, v)) if (200..300).contains(&s) && v.is_object() => {
                    if !majority {
                        return Ok(v);
                    }
                    answers.push((compared(&v), v));
                    continue;
                }
                Ok((s, _)) if (200..300).contains(&s) => EndpointFailure::new(
                    i,
                    crate::FailureKind::AnswerMalformed,
                    "a 2xx answer that is not an object",
                ),
                Ok((s, v)) => match answer(i, s, v) {
                    NodeOutcome::Refused(e) if !majority => return Err(e),
                    NodeOutcome::Refused(e) => {
                        EndpointFailure::new(i, crate::FailureKind::Http, e.code())
                    }
                    NodeOutcome::Unreachable(f) => f,
                    NodeOutcome::Queued { .. } => unreachable!("not a 2xx"),
                },
                Err(f) => f,
            };
            failures.push(f.clone());
            last = Some(f);
        }
        if !majority {
            return Err(RpcError::EndpointAllFailed {
                last,
                failover_revert: None,
            });
        }
        let need = n / 2 + 1;
        let mut largest = 0;
        for (c, _) in &answers {
            let group = answers.iter().filter(|(d, _)| d == c);
            let k = group.clone().count();
            if k >= need {
                // the group's answer that expires first: each verifier sets `validUntil` from its own clock
                if let Some((_, v)) = group.min_by_key(|(_, v)| valid_until(v)) {
                    return Ok(v.clone());
                }
            }
            largest = largest.max(k);
        }
        Err(RpcError::EndpointNoMajority {
            n,
            need,
            largest,
            failures,
        })
    }
}
