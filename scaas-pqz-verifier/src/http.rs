// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The HTTP door (spec §11.2): `POST /v1/pqz-verdict`, `POST /v1/pqz-verdict/probe`. Per client address a rate limit,
//! then a place in a bounded queue; the body bounded by length and depth before it is decoded; named fields only. A
//! refusal is a named JSON error, never a signature.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::{ConnectInfo, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{body_limit, refuse, Config, Refusal, Service, Signed, MAX_DEPTH};

struct App {
    svc: Arc<Service>,
    queue: Arc<Semaphore>,
    per_minute: u32,
    rate: Mutex<(Instant, HashMap<IpAddr, u32>)>,
}

pub fn router(svc: Arc<Service>, cfg: &Config) -> Router {
    let app = App {
        svc,
        queue: Arc::new(Semaphore::new(cfg.queue)),
        per_minute: cfg.rate_per_minute,
        rate: Mutex::new((Instant::now(), HashMap::new())),
    };
    Router::new()
        .route("/v1/pqz-verdict", post(verdict))
        .route("/v1/pqz-verdict/probe", post(probe))
        .with_state(Arc::new(app))
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let status = match self.error {
            "BODY_TOO_LARGE" => StatusCode::PAYLOAD_TOO_LARGE,
            "RATE_LIMITED" => StatusCode::TOO_MANY_REQUESTS,
            "BUSY" | "RPC_UNAVAILABLE" | "VERIFIER_FAULT" | "SIGNER_FAULT" => StatusCode::SERVICE_UNAVAILABLE,
            "JSON_TOO_DEEP" | "BAD_REQUEST" | "UNKNOWN_ENTRY" => StatusCode::BAD_REQUEST,
            _ => StatusCode::UNPROCESSABLE_ENTITY,
        };
        (status, Json(self)).into_response()
    }
}

impl App {
    /// A fixed one-minute window per client address, then a place in the queue (`BUSY` when full).
    fn admit(&self, ip: IpAddr) -> Result<OwnedSemaphorePermit, Refusal> {
        {
            let mut r = self.rate.lock().unwrap();
            if r.0.elapsed() >= Duration::from_secs(60) {
                *r = (Instant::now(), HashMap::new());
            }
            let n = r.1.entry(ip).or_insert(0);
            if *n >= self.per_minute {
                return Err(refuse("RATE_LIMITED", format!("{ip}: {} per minute", self.per_minute)));
            }
            *n += 1;
        }
        self.queue.clone().try_acquire_owned().map_err(|_| refuse("BUSY", "the queue is full"))
    }
}

/// Containers nested in `b`, the request object included, outside strings; false once over `MAX_DEPTH` below it.
fn depth_ok(b: &[u8]) -> bool {
    let (mut depth, mut in_str, mut esc) = (0usize, false, false);
    for &c in b {
        if in_str {
            match (esc, c) {
                (true, _) => esc = false,
                (false, b'\\') => esc = true,
                (false, b'"') => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            b'"' => in_str = true,
            b'{' | b'[' => {
                depth += 1;
                if depth > MAX_DEPTH + 1 {
                    return false;
                }
            }
            b'}' | b']' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// The body within `body_limit()` and `MAX_DEPTH`, both checked before any decoding; then the named fields.
async fn decode<T: serde::de::DeserializeOwned>(b: Body) -> Result<T, Refusal> {
    let limit = body_limit();
    let bytes = axum::body::to_bytes(b, limit).await.map_err(|_| refuse("BODY_TOO_LARGE", format!("over {limit} B")))?;
    if !depth_ok(&bytes) {
        return Err(refuse("JSON_TOO_DEEP", format!("nested over {MAX_DEPTH} below the request object")));
    }
    serde_json::from_slice(&bytes).map_err(|e| refuse("BAD_REQUEST", e.to_string()))
}

async fn verdict(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, b: Body)
    -> Result<Json<Signed>, Refusal>
{
    let _slot = app.admit(peer.ip())?;
    Ok(Json(app.svc.verdict(decode(b).await?).await?))
}

async fn probe(State(app): State<Arc<App>>, ConnectInfo(peer): ConnectInfo<SocketAddr>, b: Body)
    -> Result<Json<Signed>, Refusal>
{
    let _slot = app.admit(peer.ip())?;
    Ok(Json(app.svc.probe(decode(b).await?).await?))
}
