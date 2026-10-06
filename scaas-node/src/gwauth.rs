//! Xác thực gateway (R54, GA 2.1#8). Lớp middleware riêng, bọc ngoài `gateway::router` — route không
//! cần biết. `none` chỉ được phép khi gateway bind loopback (kiểm ở `Config::validate`).
//!
//! - `bearer`: `Authorization: Bearer <secret>`, so sánh constant-time.
//! - `hmac`: `X-SCaaS-Timestamp` (unix s, lệch ≤ 300 s), `X-SCaaS-Nonce` (1–64 ký tự `[A-Za-z0-9_-]`, nhớ
//!   tới khi timestamp hết hạn ⇒ không phát lại — review S20), `X-SCaaS-Signature = hex(HMAC-SHA256(secret,
//!   ts ‖ "." ‖ nonce ‖ "." ‖ METHOD ‖ " " ‖ path?query ‖ "\n" ‖ body))`. Method + đường dẫn nằm trong chuỗi ký:
//!   chữ ký cho `/v1/metatx` không dùng được cho route khác. URI không chứa dấu cách/xuống dòng ⇒ không mơ hồ.
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::submit::now;

const SKEW: u64 = 300;
const MAX_BODY: usize = 64 * 1024;
const BODY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Trần đồng thời NGOÀI lớp xác thực: request chưa xác thực cũng không giữ quá chừng này task/bộ đệm.
const MAX_INFLIGHT: usize = 64;

#[derive(Clone)]
pub enum Auth {
    None,
    Bearer(Arc<Vec<u8>>),
    Hmac { secret: Arc<Vec<u8>>, seen: Arc<Mutex<HashMap<String, u64>>> },
}

impl Auth {
    pub fn from_mode(mode: &str, secret: Option<Vec<u8>>) -> anyhow::Result<Self> {
        Ok(match (mode, secret) {
            ("none", _) => Auth::None,
            ("bearer", Some(s)) if s.len() >= 16 => Auth::Bearer(Arc::new(s)),
            ("hmac", Some(s)) if s.len() >= 16 => Auth::Hmac { secret: Arc::new(s), seen: Arc::default() },
            ("bearer" | "hmac", _) => anyhow::bail!("gateway_auth {mode} needs a secret of at least 16 bytes"),
            (other, _) => anyhow::bail!("gateway_auth must be none|bearer|hmac, got {other}"),
        })
    }
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn deny(why: &'static str) -> Response {
    (StatusCode::UNAUTHORIZED, axum::Json(serde_json::json!({"error": why}))).into_response()
}

fn header<'a>(req: &'a Request, name: &str) -> Option<&'a str> {
    req.headers().get(name).and_then(|v| v.to_str().ok())
}

pub async fn check(State(auth): State<Auth>, req: Request, next: Next) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await;
    }
    match &auth {
        Auth::None => next.run(req).await,
        Auth::Bearer(secret) => {
            let ok = header(&req, "authorization")
                .and_then(|h| h.strip_prefix("Bearer "))
                .is_some_and(|t| ct_eq(t.as_bytes(), secret));
            if ok { next.run(req).await } else { deny("unauthorized") }
        }
        Auth::Hmac { secret, seen } => {
            let (Some(ts), Some(nonce), Some(sig)) = (
                header(&req, "x-scaas-timestamp").map(str::to_owned),
                header(&req, "x-scaas-nonce").map(str::to_owned),
                header(&req, "x-scaas-signature").map(str::to_owned),
            ) else {
                return deny("missing signature headers");
            };
            let Ok(t) = ts.parse::<u64>() else { return deny("bad timestamp") };
            let n = now();
            if t.saturating_add(SKEW) < n || t > n.saturating_add(SKEW) {
                return deny("stale request");
            }
            if nonce.is_empty() || nonce.len() > 64 || !nonce.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                return deny("bad nonce");
            }
            let (parts, body) = req.into_parts();
            let Ok(Ok(bytes)) = tokio::time::timeout(BODY_TIMEOUT, to_bytes(body, MAX_BODY)).await else {
                return deny("body too large or too slow");
            };
            let Ok(want) = alloy::hex::decode(sig.trim()) else { return deny("bad signature") };
            let mut mac = <Hmac<Sha256>>::new_from_slice(secret).expect("hmac key");
            mac.update(ts.as_bytes());
            mac.update(b".");
            mac.update(nonce.as_bytes());
            mac.update(b".");
            mac.update(parts.method.as_str().as_bytes());
            mac.update(b" ");
            mac.update(parts.uri.path_and_query().map_or("/", |p| p.as_str()).as_bytes());
            mac.update(b"\n");
            mac.update(&bytes);
            if mac.verify_slice(&want).is_err() {
                return deny("bad signature");
            }
            {
                let mut s = seen.lock().expect("nonce cache");
                s.retain(|_, exp| *exp > n);
                if s.contains_key(&nonce) {
                    return deny("replayed request");
                }
                // Nhớ tới khi chính timestamp này hết hạn (review S1-5), không tính từ lúc nhận.
                s.insert(nonce, t.saturating_add(SKEW + 1));
            }
            next.run(Request::from_parts(parts, Body::from(bytes))).await
        }
    }
}

/// Bọc router gateway bằng lớp xác thực, rồi trần đồng thời ở ngoài cùng (review S1-6).
pub fn wrap(router: axum::Router, auth: Auth) -> axum::Router {
    router
        .layer(axum::middleware::from_fn_with_state(auth, check))
        .layer(tower::limit::GlobalConcurrencyLimitLayer::new(MAX_INFLIGHT))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use tower::ServiceExt;

    fn app(auth: Auth) -> axum::Router {
        wrap(
            axum::Router::new()
                .route("/healthz", get(|| async { "ok" }))
                .route("/v1/x", post(|body: String| async move { body })),
            auth,
        )
    }

    fn sign(secret: &[u8], ts: &str, nonce: &str, body: &str) -> String {
        sign_at(secret, ts, nonce, "/v1/x", body)
    }

    fn sign_at(secret: &[u8], ts: &str, nonce: &str, path: &str, body: &str) -> String {
        let mut mac = <Hmac<Sha256>>::new_from_slice(secret).unwrap();
        mac.update(format!("{ts}.{nonce}.POST {path}\n{body}").as_bytes());
        alloy::hex::encode(mac.finalize().into_bytes())
    }

    async fn status(app: &axum::Router, req: Request) -> StatusCode {
        app.clone().oneshot(req).await.unwrap().status()
    }

    #[tokio::test]
    async fn bearer() {
        let app = app(Auth::from_mode("bearer", Some(b"0123456789abcdef-secret".to_vec())).unwrap());
        let mk = |h: Option<&str>| {
            let mut b = Request::builder().method("POST").uri("/v1/x");
            if let Some(h) = h {
                b = b.header("authorization", h);
            }
            b.body(Body::from("{}")).unwrap()
        };
        assert_eq!(status(&app, mk(Some("Bearer 0123456789abcdef-secret"))).await, StatusCode::OK);
        assert_eq!(status(&app, mk(Some("Bearer 0123456789abcdef-secreT"))).await, StatusCode::UNAUTHORIZED);
        assert_eq!(status(&app, mk(None)).await, StatusCode::UNAUTHORIZED);
        let health = Request::builder().uri("/healthz").body(Body::empty()).unwrap();
        assert_eq!(status(&app, health).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn hmac_replay_stale_and_tamper() {
        let secret = b"0123456789abcdef-hmac".to_vec();
        let app = app(Auth::from_mode("hmac", Some(secret.clone())).unwrap());
        let ts = now().to_string();
        let mk = |ts: &str, nonce: &str, body: &str, sig: &str| {
            Request::builder()
                .method("POST")
                .uri("/v1/x")
                .header("x-scaas-timestamp", ts)
                .header("x-scaas-nonce", nonce)
                .header("x-scaas-signature", sig)
                .body(Body::from(body.to_string()))
                .unwrap()
        };
        let good = sign(&secret, &ts, "n1", "{\"a\":1}");
        assert_eq!(status(&app, mk(&ts, "n1", "{\"a\":1}", &good)).await, StatusCode::OK);
        assert_eq!(status(&app, mk(&ts, "n1", "{\"a\":1}", &good)).await, StatusCode::UNAUTHORIZED, "replay");
        let tampered = sign(&secret, &ts, "n2", "{\"a\":1}");
        assert_eq!(status(&app, mk(&ts, "n2", "{\"a\":2}", &tampered)).await, StatusCode::UNAUTHORIZED);
        let old = (now() - 3600).to_string();
        let s_old = sign(&secret, &old, "n3", "{}");
        assert_eq!(status(&app, mk(&old, "n3", "{}", &s_old)).await, StatusCode::UNAUTHORIZED, "stale");
        // a signature for another route does not authorize this one
        let other = sign_at(&secret, &ts, "n4", "/v1/y", "{}");
        assert_eq!(status(&app, mk(&ts, "n4", "{}", &other)).await, StatusCode::UNAUTHORIZED, "path bound");
        // a timestamp near u64::MAX must not overflow the skew check
        let huge = u64::MAX.to_string();
        let s_huge = sign(&secret, &huge, "n5", "{}");
        assert_eq!(status(&app, mk(&huge, "n5", "{}", &s_huge)).await, StatusCode::UNAUTHORIZED);
        // missing headers, bad nonce charset
        let bare = Request::builder().method("POST").uri("/v1/x").body(Body::from("{}")).unwrap();
        assert_eq!(status(&app, bare).await, StatusCode::UNAUTHORIZED);
        let s_dot = sign(&secret, &ts, "a.b", "{}");
        assert_eq!(status(&app, mk(&ts, "a.b", "{}", &s_dot)).await, StatusCode::UNAUTHORIZED);
        let fresh = sign(&secret, &ts, "n6", "{}");
        assert_eq!(status(&app, mk(&ts, "n6", "{}", &fresh)).await, StatusCode::OK);
    }

    #[test]
    fn short_secrets_and_unknown_modes_are_refused() {
        assert!(Auth::from_mode("bearer", Some(b"short".to_vec())).is_err());
        assert!(Auth::from_mode("hmac", None).is_err());
        assert!(Auth::from_mode("jwt", None).is_err());
    }
}
