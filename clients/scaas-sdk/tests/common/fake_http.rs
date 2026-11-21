// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! A fake HTTP endpoint on 127.0.0.1:0 for the non-EVM families' reads (plan T24; local only): every request `(method, path,
//! body)` goes to the test's handler, which answers `(status, body bytes)`; each request is recorded. `DOWN` is an endpoint
//! nothing listens on.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// An endpoint that refuses every connection (port 9 of the loopback: discard, not served by the tests).
pub const DOWN: &str = "http://127.0.0.1:9";

pub type Handler = Arc<dyn Fn(&str, &str, &[u8]) -> (u16, Vec<u8>) + Send + Sync>;

/// The requests an endpoint received, as `(method, path, body)`.
pub type Seen = Arc<Mutex<Vec<(String, String, String)>>>;

/// Serves `h` on 127.0.0.1:0; returns the base URL and the requests it receives.
pub async fn serve(h: Handler) -> (String, Seen) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let seen: Seen = Arc::default();
    let s2 = seen.clone();
    tokio::spawn(async move {
        while let Ok((mut s, _)) = l.accept().await {
            let (h, seen) = (h.clone(), s2.clone());
            tokio::spawn(async move {
                let mut buf = Vec::new();
                loop {
                    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
                        let mut chunk = [0u8; 8192];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                        continue;
                    };
                    let head = String::from_utf8_lossy(&buf[..end]).to_string();
                    let mut words = head.split_whitespace();
                    let method = words.next().unwrap_or("GET").to_string();
                    let path = words.next().unwrap_or("/").to_string();
                    let len: usize = head
                        .to_ascii_lowercase()
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    while buf.len() < end + 4 + len {
                        let mut chunk = [0u8; 8192];
                        match s.read(&mut chunk).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => buf.extend_from_slice(&chunk[..n]),
                        }
                    }
                    let body = buf[end + 4..end + 4 + len].to_vec();
                    buf.drain(..end + 4 + len);
                    seen.lock().unwrap().push((
                        method.clone(),
                        path.clone(),
                        String::from_utf8_lossy(&body).to_string(),
                    ));
                    let (status, out) = h(&method, &path, &body);
                    let resp = format!(
                        "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                        out.len()
                    );
                    if s.write_all(resp.as_bytes()).await.is_err()
                        || s.write_all(&out).await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (url, seen)
}
