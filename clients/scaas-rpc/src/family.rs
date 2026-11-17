// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The non-EVM families' transport (spec §5.3, plan T15–T22): one endpoint list, one bounded client (16 MiB, depth 64, no
//! redirect, each endpoint's own credential only), a request to endpoint `i` (JSON-RPC, REST GET, REST POST), and the pool's
//! failover for the reads that may fail over (step (b)). Each family module (`soroban`, `solana`, …) names its methods, its
//! identity read and its head read on top of it.
use crate::endpoint::{Endpoint, NodeList, Policy};
use crate::error::{EndpointFailure, FailureKind, RpcError};
use crate::http::Http;
use crate::pool::{Answer, Pool, Probe, ReadError};
use crate::Purpose;
use serde_json::Value;
use std::future::Future;
use std::sync::Arc;

/// The family clients' request timeout: today's adapters' 20 s, kept (spec §11.1 step 2), not the list's `timeout_ms`.
pub const FAMILY_TIMEOUT_MS: u64 = 20_000;
/// The longest answer a family endpoint may send (CLI-RPC-07).
pub const ANSWER_MAX: usize = 16 << 20;

/// Why a quorum read (`agreed`) gave no answer: endpoint 0's own error, or too few endpoints repeating it.
#[derive(Debug, Clone, PartialEq)]
pub enum AgreedError {
    First(FamilyError),
    Quorum { agree: usize, quorum: usize },
}

/// A family request's failure: the endpoint's (transport, HTTP, timeout, too large, too deep, malformed), its own JSON-RPC
/// error object kept whole, or a REST answer's status other than 2xx with its message (capped), for the family to classify.
#[derive(Debug, Clone, PartialEq)]
pub enum FamilyError {
    Failure(EndpointFailure),
    Rpc { method: String, error: Value },
    Status { status: u16, message: String },
}

impl FamilyError {
    /// The JSON-RPC error object, if the endpoint answered one.
    pub fn rpc_error(&self) -> Option<&Value> {
        match self {
            FamilyError::Rpc { error, .. } => Some(error),
            _ => None,
        }
    }
}

impl std::fmt::Display for FamilyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FamilyError::Failure(e) => write!(f, "{e}"),
            // the text a caller logs: the endpoint's words, capped and redacted (CLI-RPC-11)
            FamilyError::Rpc { method, error } => {
                write!(
                    f,
                    "{method}: {}",
                    crate::error::endpoint_text(&error.to_string())
                )
            }
            FamilyError::Status { status, message } => write!(f, "HTTP {status}: {message}"),
        }
    }
}

impl std::error::Error for FamilyError {}

impl From<EndpointFailure> for FamilyError {
    fn from(f: EndpointFailure) -> Self {
        FamilyError::Failure(f)
    }
}

/// One family's endpoint list and its client.
pub struct Client {
    list: Arc<NodeList>,
    http: Http,
    pool: Pool,
}

impl Client {
    /// The client of `list` (its `timeout_ms` bounds each request).
    pub fn new(list: NodeList) -> Result<Self, RpcError> {
        Ok(Self {
            http: Http::new(list.timeout_ms)?,
            pool: Pool::new(&list, false),
            list: Arc::new(list),
        })
    }

    /// The client of plain URLs (the node's `rpc_urls`: named endpoints), each with the same `auth` header when given (step (a):
    /// the family key goes to exactly the endpoints it went to), each request bounded by [`FAMILY_TIMEOUT_MS`].
    pub fn of_urls(
        urls: &[String],
        auth: Option<crate::endpoint::EndpointAuth>,
    ) -> Result<Self, RpcError> {
        let e = urls
            .iter()
            .map(|u| Endpoint::new(u, crate::Class::Named, None, auth.clone()))
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(NodeList::new(
            e,
            Policy::Failover,
            FAMILY_TIMEOUT_MS,
            FAMILY_TIMEOUT_MS,
            crate::endpoint::READ_TIMEOUT_MS,
        )?)
    }

    pub fn list(&self) -> &NodeList {
        &self.list
    }
    pub fn len(&self) -> usize {
        self.list.len()
    }
    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }
    pub fn pool(&self) -> &Pool {
        &self.pool
    }

    /// One JSON-RPC call to endpoint `i`: its `result`, or its error object (`FamilyError::Rpc`), or the endpoint's failure. A
    /// 2xx or 4xx answer is read (JSON-RPC servers answer errors either way); a 5xx, a 3xx and an answer with neither member are
    /// failures.
    pub async fn rpc_at(
        &self,
        i: usize,
        method: &str,
        params: Value,
    ) -> Result<Value, FamilyError> {
        let body =
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let (_, mut v) = self
            .http
            .request(
                &self.list,
                i,
                reqwest::Method::POST,
                "",
                Some(serde_json::to_vec(&body).expect("a Value serialises")),
                ANSWER_MAX,
                None,
            )
            .await?;
        if let Some(e) = v.get_mut("error").filter(|e| !e.is_null()) {
            return Err(FamilyError::Rpc {
                method: method.into(),
                error: e.take(),
            });
        }
        match v.get_mut("result") {
            Some(r) => Ok(r.take()),
            None => Err(FamilyError::Failure(EndpointFailure::new(
                i,
                FailureKind::AnswerMalformed,
                &format!("{method}: no result"),
            ))),
        }
    }

    /// GET `path` of endpoint `i` (2xx only), parsed.
    pub async fn get_at(&self, i: usize, path: &str) -> Result<Value, FamilyError> {
        Ok(self
            .http
            .get_json(&self.list, i, path, ANSWER_MAX, None)
            .await?)
    }

    /// GET `path` of endpoint `i`: its status and its parsed body, for a 2xx or a 4xx (a REST API's "not found" is an answer).
    pub async fn get_status_at(&self, i: usize, path: &str) -> Result<(u16, Value), FamilyError> {
        Ok(self
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
            .await?)
    }

    /// One request to `path` of endpoint `i` whose answer comes back raw (its status and bytes; a 5xx is the endpoint's
    /// failure), `body` sent as `ctype`; no JSON nesting scan (a binary answer has its reader's own bound).
    pub async fn raw_at(
        &self,
        i: usize,
        method: reqwest::Method,
        path: &str,
        body: Option<Vec<u8>>,
        ctype: &str,
        cap: usize,
    ) -> Result<(u16, Vec<u8>), FamilyError> {
        Ok(self
            .http
            .raw(&self.list, i, method, path, body, ctype, cap, None)
            .await?)
    }

    /// POST a JSON `body` to `path` of endpoint `i` (2xx only), parsed.
    pub async fn post_at(&self, i: usize, path: &str, body: &Value) -> Result<Value, FamilyError> {
        Ok(self
            .http
            .post_json(&self.list, i, Some(path), body, ANSWER_MAX, None)
            .await?)
    }

    /// ARCH-POS-15 (CLI-RPC-04): `f` on endpoint 0, then on each next endpoint that is this network (`probe.same_chain`) and not
    /// behind the head endpoint 0 last showed ([`Pool::saw_block`]); a later endpoint's `ReadError::Revert` is no verdict.
    pub async fn failover<T, P, F, Fut>(&self, probe: &P, f: F) -> Result<Answer<T>, RpcError>
    where
        P: Probe,
        F: Fn(usize) -> Fut,
        Fut: Future<Output = Result<T, ReadError>>,
    {
        self.pool.failover(probe, Purpose::Plain, f).await
    }
}

#[cfg(test)]
mod tests {
    /// Spec §11.1 step 2: the family clients keep today's 20 s per request.
    #[test]
    fn a_family_request_is_bounded_by_20_s() {
        let c = super::Client::of_urls(&["http://a.example".into()], None).unwrap();
        assert_eq!(c.list().timeout_ms, 20_000);
    }
}
