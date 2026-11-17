// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The bounded HTTP transport (CLI-RPC-07, spec §7): every answer is read in chunks up to its call's byte cap (an announced
//! `Content-Length` above it stops before reading), its JSON nesting checked by a flat scan (`scaas_ua::json::depth_within`, at
//! most [`DEPTH_MAX`]), and only then parsed, once. No redirect is followed (F8: a 3xx is the endpoint's HTTP failure). Each
//! request's timeout is min(the client's timeout, the deadline's remainder), one clock (`web-time`); the transport never sleeps.
//! An endpoint's credential goes to that endpoint only. Errors carry no URL (CLI-RPC-11).

use crate::endpoint::{EndpointAuth, NodeList};
use crate::error::{EndpointFailure, FailureKind};
use serde_json::Value;
use web_time::{Duration, Instant};

/// The default answer cap (16 MiB, the reference reader's `MAX_ANSWER`).
pub const ANSWER_MAX: usize = 16 << 20;
/// The deepest JSON nesting of an answer.
pub const DEPTH_MAX: usize = 64;

/// A JSON-RPC error answer: the endpoint's own words, kept for the caller to classify (its text capped and redacted).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    pub data: Option<Value>,
}

/// The checks between the bytes and the parser: the length cap, the depth scan, one parse.
pub fn decode(bytes: &[u8], cap: usize) -> Result<Value, FailureKind> {
    if bytes.len() > cap {
        return Err(FailureKind::AnswerTooLarge);
    }
    match scaas_ua::json::depth_within(bytes, DEPTH_MAX) {
        Ok(()) => {}
        Err(scaas_ua::json::DepthError::Deep) => return Err(FailureKind::AnswerTooDeep),
        Err(scaas_ua::json::DepthError::Unbalanced) => return Err(FailureKind::AnswerMalformed),
    }
    serde_json::from_slice(bytes).map_err(|_| FailureKind::AnswerMalformed)
}

/// One HTTP client of the crate: no redirects, a timeout per request.
#[derive(Clone)]
pub struct Http {
    client: reqwest::Client,
    timeout: Duration,
}

impl Http {
    /// Each request is bounded by `timeout_ms` (and by a read's deadline when it has one).
    pub fn new(timeout_ms: u64) -> Result<Self, crate::RpcError> {
        #[cfg(not(target_arch = "wasm32"))]
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none()).build()
            .map_err(|_| crate::RpcError::argument("the HTTP client could not be built"))?;
        #[cfg(target_arch = "wasm32")]
        let client = reqwest::Client::new();
        Ok(Self {
            client,
            timeout: Duration::from_millis(timeout_ms),
        })
    }

    /// The request's timeout: the client's, or what is left of `deadline` when less; `Timeout` when nothing is left.
    fn timeout_for(&self, i: usize, deadline: Option<Instant>) -> Result<Duration, EndpointFailure> {
        match deadline {
            None => Ok(self.timeout),
            Some(d) => {
                let left = d.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(EndpointFailure::new(i, FailureKind::Timeout, "the read's deadline passed"));
                }
                Ok(left.min(self.timeout))
            }
        }
    }

    /// POST `body` (JSON bytes) to endpoint `i` of `list` (its URL joined with `path` when given); the answer's bytes once they pass
    /// the length cap and the depth scan.
    pub async fn post_bytes(&self, list: &NodeList, i: usize, path: Option<&str>, body: Vec<u8>, cap: usize,
        deadline: Option<Instant>) -> Result<Vec<u8>, EndpointFailure> {
        self.send(list, i, reqwest::Method::POST, path, Some(body), cap, deadline).await
    }

    /// POST a JSON value; the answer parsed.
    pub async fn post_json(&self, list: &NodeList, i: usize, path: Option<&str>, body: &Value, cap: usize,
        deadline: Option<Instant>) -> Result<Value, EndpointFailure> {
        let b = self.post_bytes(list, i, path, serde_json::to_vec(body).expect("a Value serialises"), cap, deadline).await?;
        decode(&b, cap).map_err(|k| self.fail(list, i, k, "the answer"))
    }

    /// GET `path` of endpoint `i`; the answer parsed.
    pub async fn get_json(&self, list: &NodeList, i: usize, path: &str, cap: usize, deadline: Option<Instant>)
        -> Result<Value, EndpointFailure> {
        let b = self.send(list, i, reqwest::Method::GET, Some(path), None, cap, deadline).await?;
        decode(&b, cap).map_err(|k| self.fail(list, i, k, "the answer"))
    }

    /// One JSON-RPC call: `Ok(Ok(result))`, `Ok(Err(the endpoint's error answer))`, or the endpoint's failure (an answer with
    /// neither `result` nor `error` is malformed).
    pub async fn json_rpc(&self, list: &NodeList, i: usize, method: &str, params: Value, cap: usize, deadline: Option<Instant>)
        -> Result<Result<Value, JsonRpcError>, EndpointFailure> {
        let body = serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let v = self.post_json(list, i, None, &body, cap, deadline).await?;
        rpc_answer(v).map_err(|k| self.fail(list, i, k, "a JSON-RPC answer with neither result nor error"))
    }

    fn fail(&self, list: &NodeList, i: usize, kind: FailureKind, text: &str) -> EndpointFailure {
        EndpointFailure::new(i, kind, text).with_label(list.endpoints().get(i).and_then(|e| e.label_str()))
    }

    /// One request whose 2xx or 4xx answer is read and parsed (a gateway's error contract is in a 4xx body); a 3xx, a 5xx and
    /// every transport failure are the endpoint's failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn request(&self, list: &NodeList, i: usize, method: reqwest::Method, path: &str, body: Option<Vec<u8>>, cap: usize,
        deadline: Option<Instant>) -> Result<(u16, Value), EndpointFailure> {
        let (status, b) = self.send_any(list, i, method, Some(path), body, cap, deadline).await?;
        if status >= 500 {
            return Err(self.fail(list, i, FailureKind::Http, &format!("HTTP {status}")));
        }
        let v = match decode(&b, cap) {
            Ok(v) => v,
            Err(_) if status >= 400 => Value::Null,
            Err(k) => return Err(self.fail(list, i, k, "the answer")),
        };
        Ok((status, v))
    }

    #[allow(clippy::too_many_arguments)]
    async fn send(&self, list: &NodeList, i: usize, method: reqwest::Method, path: Option<&str>, body: Option<Vec<u8>>, cap: usize,
        deadline: Option<Instant>) -> Result<Vec<u8>, EndpointFailure> {
        let (status, b) = self.send_any(list, i, method, path, body, cap, deadline).await?;
        if !(200..300).contains(&status) {
            return Err(self.fail(list, i, FailureKind::Http, &format!("HTTP {status}")));
        }
        Ok(b)
    }

    /// The request of endpoint `i`: its URL (joined with `path`), the timeout, the body, and its own credential only (F8): a
    /// bearer, its API key header, or NODE-GW-02's HMAC over `ts "." nonce "." METHOD " " path?query "\n" body`.
    #[allow(clippy::too_many_arguments)]
    fn build(&self, list: &NodeList, i: usize, method: reqwest::Method, path: Option<&str>, body: Option<Vec<u8>>,
        deadline: Option<Instant>) -> Result<(url::Url, reqwest::RequestBuilder), EndpointFailure> {
        let e = list.endpoints().get(i).ok_or_else(|| self.fail(list, i, FailureKind::Transport, "no such endpoint"))?;
        let timeout = self.timeout_for(i, deadline)?;
        let url = match path {
            Some(p) => e.url().join(p).map_err(|_| self.fail(list, i, FailureKind::Transport, "a path that does not join"))?,
            None => e.url().clone(),
        };
        let body = body.unwrap_or_default();
        let mut req = self.client.request(method.clone(), url.clone()).timeout(timeout);
        // the credential of this endpoint only (F8)
        match e.auth() {
            None => {}
            Some(EndpointAuth::Bearer(s)) => req = req.bearer_auth(s.expose()),
            Some(EndpointAuth::Header { name, value }) => req = req.header(name.as_str(), value.expose()),
            Some(EndpointAuth::Hmac(secret)) => {
                use base64::Engine as _;
                use hmac::Mac as _;
                let ts = web_time::SystemTime::now().duration_since(web_time::UNIX_EPOCH).map_or(0, |d| d.as_secs()).to_string();
                let mut n = [0u8; 16];
                getrandom::getrandom(&mut n).map_err(|_| self.fail(list, i, FailureKind::Transport, "no OS randomness"))?;
                let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(n);
                let target = match url.query() {
                    Some(q) => format!("{}?{q}", url.path()),
                    None => url.path().to_string(),
                };
                let mut mac = <hmac::Hmac<sha2::Sha256>>::new_from_slice(secret.expose().as_bytes()).expect("any key length");
                mac.update(format!("{ts}.{nonce}.{} {target}\n", method.as_str()).as_bytes());
                mac.update(&body);
                let sig: String = mac.finalize().into_bytes().iter().map(|b| format!("{b:02x}")).collect();
                req = req.header("x-scaas-timestamp", ts).header("x-scaas-nonce", nonce).header("x-scaas-signature", sig);
            }
        }
        if !body.is_empty() {
            req = req.header(reqwest::header::CONTENT_TYPE, "application/json").body(body);
        }
        Ok((url, req))
    }

    /// The answer of any status but a 3xx (never followed), read up to `cap`, its nesting checked.
    #[cfg(not(target_arch = "wasm32"))]
    #[allow(clippy::too_many_arguments)]
    async fn send_any(&self, list: &NodeList, i: usize, method: reqwest::Method, path: Option<&str>, body: Option<Vec<u8>>, cap: usize,
        deadline: Option<Instant>) -> Result<(u16, Vec<u8>), EndpointFailure> {
        let (_, req) = self.build(list, i, method, path, body, deadline)?;
        let net = |err: reqwest::Error| {
            let kind = if err.is_timeout() { FailureKind::Timeout } else { FailureKind::Transport };
            self.fail(list, i, kind, &err.without_url().to_string())
        };
        let mut r = req.send().await.map_err(net)?;
        let status = r.status().as_u16();
        if (300..400).contains(&status) {
            return Err(self.fail(list, i, FailureKind::Http, &format!("HTTP {status}")));
        }
        if r.content_length().is_some_and(|n| n > cap as u64) {
            return Err(self.fail(list, i, FailureKind::AnswerTooLarge, &format!("an announced answer above {cap} bytes")));
        }
        let mut buf = Vec::new();
        while let Some(c) = r.chunk().await.map_err(net)? {
            if buf.len() + c.len() > cap {
                return Err(self.fail(list, i, FailureKind::AnswerTooLarge, &format!("an answer above {cap} bytes")));
            }
            buf.extend_from_slice(&c);
        }
        if let Err(k) = depth(&buf) {
            return Err(self.fail(list, i, k, "the answer's nesting"));
        }
        Ok((status, buf))
    }

    /// wasm32: compiles, never sends (the fetch transport is plan T12's).
    #[cfg(target_arch = "wasm32")]
    #[allow(clippy::too_many_arguments)]
    async fn send_any(&self, list: &NodeList, i: usize, method: reqwest::Method, path: Option<&str>, body: Option<Vec<u8>>,
        _cap: usize, deadline: Option<Instant>) -> Result<(u16, Vec<u8>), EndpointFailure> {
        let _ = self.build(list, i, method, path, body, deadline)?;
        Err(self.fail(list, i, FailureKind::Transport, "no wasm32 transport yet"))
    }
}

fn depth(buf: &[u8]) -> Result<(), FailureKind> {
    match scaas_ua::json::depth_within(buf, DEPTH_MAX) {
        Ok(()) => Ok(()),
        Err(scaas_ua::json::DepthError::Deep) => Err(FailureKind::AnswerTooDeep),
        Err(scaas_ua::json::DepthError::Unbalanced) => Err(FailureKind::AnswerMalformed),
    }
}

/// A JSON-RPC answer's `result`, or its `error` as the endpoint's words (text capped and redacted).
pub fn rpc_answer(mut v: Value) -> Result<Result<Value, JsonRpcError>, FailureKind> {
    if let Some(e) = v.get_mut("error").filter(|e| !e.is_null()) {
        let code = e["code"].as_i64().ok_or(FailureKind::AnswerMalformed)?;
        let message = crate::error::endpoint_text(e["message"].as_str().unwrap_or_default());
        let data = e.get_mut("data").map(Value::take).filter(|d| !d.is_null());
        return Ok(Err(JsonRpcError { code, message, data }));
    }
    match v.get_mut("result") {
        Some(r) => Ok(Ok(r.take())),
        None => Err(FailureKind::AnswerMalformed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
        /// No answer panics the reader: random bytes of random lengths up to 64 KiB, under a cap below and above their length.
        #[test]
        fn no_answer_panics(bytes in proptest::collection::vec(any::<u8>(), 0..65_536), cap in 0usize..70_000) {
            let r = decode(&bytes, cap);
            if bytes.len() > cap {
                prop_assert_eq!(r, Err(FailureKind::AnswerTooLarge));
            }
            if let Ok(v) = decode(&bytes, usize::MAX) {
                let _ = rpc_answer(v);
            }
        }

        /// The same over JSON-shaped noise: brackets, quotes and escapes, which reach the depth scan and the parser.
        #[test]
        fn no_json_shaped_answer_panics(s in "[\\[\\]{}\"\\\\:,0-9a-z ]{0,4096}") {
            if let Ok(v) = decode(s.as_bytes(), ANSWER_MAX) {
                let _ = rpc_answer(v);
            }
        }
    }
}

/// The alloy transport of `EvmPool` (F5): a `tower::Service<RequestPacket>` that posts with the crate's client (no redirects,
/// the request's timeout, endpoint `i`'s own credential) and reads the answer through the bounded reader before alloy's
/// `ResponsePacket` decode sees a byte. A failure is the endpoint's `EndpointFailure` inside a transport error.
#[cfg(feature = "evm")]
#[derive(Clone)]
pub struct BoundedRpc {
    http: Http,
    list: std::sync::Arc<NodeList>,
    i: usize,
    cap: usize,
    deadline: Option<Instant>,
}

#[cfg(feature = "evm")]
impl BoundedRpc {
    pub fn new(http: Http, list: std::sync::Arc<NodeList>, i: usize, cap: usize, deadline: Option<Instant>) -> Self {
        Self { http, list, i, cap, deadline }
    }
}

#[cfg(feature = "evm")]
impl tower::Service<alloy::rpc::json_rpc::RequestPacket> for BoundedRpc {
    type Response = alloy::rpc::json_rpc::ResponsePacket;
    type Error = alloy::transports::TransportError;
    type Future = alloy::transports::TransportFut<'static>;

    fn poll_ready(&mut self, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: alloy::rpc::json_rpc::RequestPacket) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            use alloy::transports::{TransportError, TransportErrorKind};
            let body = serde_json::to_vec(&req).map_err(TransportError::ser_err)?;
            let bytes = this.http.post_bytes(&this.list, this.i, None, body, this.cap, this.deadline).await
                .map_err(TransportErrorKind::custom)?;
            serde_json::from_slice(&bytes).map_err(|e| TransportError::deser_err(e, String::from_utf8_lossy(&bytes)))
        })
    }
}
