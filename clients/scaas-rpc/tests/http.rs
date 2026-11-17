// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T2: the bounded transport against in-process fakes on 127.0.0.1:0 (CLI-RPC-07, F8, CLI-RPC-11). Each refusal has its
//! control beside it.
use scaas_rpc::http::{Http, ANSWER_MAX};
use scaas_rpc::{Class, Endpoint, EndpointAuth, FailureKind, NodeList, Policy, Secret};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn list(urls: &[String]) -> NodeList {
    NodeList::from_urls(urls).unwrap()
}

/// A raw HTTP fake: reads one request (headers, then `Content-Length` bytes), writes `head`, then `body` (counting the body bytes
/// written), then holds the connection open.
async fn raw(head: String, body: Vec<u8>) -> (String, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let written: Arc<AtomicUsize> = Default::default();
    let w = written.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let (head, body, w) = (head.clone(), body.clone(), w.clone());
            tokio::spawn(async move {
                let mut req = vec![0u8; 65_536];
                let mut n = 0;
                while !req[..n].windows(4).any(|x| x == b"\r\n\r\n") {
                    match c.read(&mut req[n..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                }
                if c.write_all(head.as_bytes()).await.is_err() {
                    return;
                }
                for chunk in body.chunks(8_192) {
                    if c.write_all(chunk).await.is_err() {
                        return;
                    }
                    w.fetch_add(chunk.len(), SeqCst);
                }
                let mut sink = [0u8; 1];
                let _ = c.read(&mut sink).await; // held until the client closes
            });
        }
    });
    (url, written)
}

fn chunked(body: &[u8]) -> (String, Vec<u8>) {
    let mut b = Vec::new();
    for c in body.chunks(4_096) {
        b.extend_from_slice(format!("{:x}\r\n", c.len()).as_bytes());
        b.extend_from_slice(c);
        b.extend_from_slice(b"\r\n");
    }
    b.extend_from_slice(b"0\r\n\r\n");
    ("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ntransfer-encoding: chunked\r\n\r\n".into(), b)
}

/// A JSON body of exactly `n` bytes: a string padded with spaces.
fn json_of_len(n: usize) -> Vec<u8> {
    let mut b = b"\"x\"".to_vec();
    b.resize(n, b' ');
    b
}

/// An axum fake answering every POST with `f(headers, body)` (status, body), counting the requests.
async fn fake(f: fn(&axum::http::HeaderMap, &[u8]) -> (u16, Vec<u8>)) -> (String, Arc<AtomicUsize>, Arc<Mutex<Vec<axum::http::HeaderMap>>>) {
    let n: Arc<AtomicUsize> = Default::default();
    let seen: Arc<Mutex<Vec<axum::http::HeaderMap>>> = Default::default();
    let (n2, s2) = (n.clone(), seen.clone());
    let app = axum::Router::new().fallback(move |h: axum::http::HeaderMap, b: axum::body::Bytes| {
        let (n2, s2) = (n2.clone(), s2.clone());
        async move {
            n2.fetch_add(1, SeqCst);
            s2.lock().unwrap().push(h.clone());
            let (status, body) = f(&h, &b);
            (axum::http::StatusCode::from_u16(status).unwrap(), [("content-type", "application/json")], body)
        }
    });
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, n, seen)
}

async fn post(url: &str, cap: usize) -> Result<Value, scaas_rpc::EndpointFailure> {
    Http::new(5_000).unwrap().post_json(&list(&[url.to_string()]), 0, None, &json!({"q": 1}), cap, None).await
}

#[tokio::test]
async fn an_announced_length_above_the_cap_is_refused_unread() {
    let cap = 1_000;
    let (url, written) = raw(format!("HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n", cap + 1), vec![]).await;
    let t = web_time::Instant::now();
    let e = post(&url, cap).await.unwrap_err();
    assert_eq!(e.kind, FailureKind::AnswerTooLarge, "{e}");
    assert!(t.elapsed() < web_time::Duration::from_secs(4), "refused before reading, not after the timeout");
    assert_eq!(written.load(SeqCst), 0, "no body byte was needed");
    let (ok, _) = raw(format!("HTTP/1.1 200 OK\r\ncontent-length: {cap}\r\n\r\n"), json_of_len(cap)).await;
    assert!(post(&ok, cap).await.is_ok(), "control: announced at the cap");
}

#[tokio::test]
async fn an_unannounced_body_above_the_cap_is_refused() {
    let cap = 50_000;
    let (head, body) = chunked(&json_of_len(cap + 1));
    let (url, _) = raw(head, body).await;
    assert_eq!(post(&url, cap).await.unwrap_err().kind, FailureKind::AnswerTooLarge);
}

#[tokio::test]
async fn a_body_at_the_cap_is_read() {
    let cap = 50_000;
    let (head, body) = chunked(&json_of_len(cap));
    let (url, _) = raw(head, body).await;
    assert_eq!(post(&url, cap).await.unwrap(), json!("x"));
}

#[tokio::test]
async fn a_depth_of_65_is_too_deep_and_64_read() {
    let nest = |d: usize| format!("{}{}", "[".repeat(d), "]".repeat(d)).into_bytes();
    let (deep, _) = raw("HTTP/1.1 200 OK\r\ncontent-length: 130\r\n\r\n".into(), nest(65)).await;
    assert_eq!(post(&deep, ANSWER_MAX).await.unwrap_err().kind, FailureKind::AnswerTooDeep);
    let (ok, _) = raw("HTTP/1.1 200 OK\r\ncontent-length: 128\r\n\r\n".into(), nest(64)).await;
    assert!(post(&ok, ANSWER_MAX).await.is_ok(), "control: 64");
}

#[tokio::test]
async fn an_unbalanced_body_is_malformed() {
    for body in [&b"]]"[..], b"{\"a\": 1}}", b"not json"] {
        let (url, _) = raw(format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", body.len()), body.to_vec()).await;
        assert_eq!(post(&url, ANSWER_MAX).await.unwrap_err().kind, FailureKind::AnswerMalformed, "{}", String::from_utf8_lossy(body));
    }
    let (ok, _) = raw("HTTP/1.1 200 OK\r\ncontent-length: 8\r\n\r\n".into(), b"{\"a\": 1}".to_vec()).await;
    assert_eq!(post(&ok, ANSWER_MAX).await.unwrap(), json!({"a": 1}), "control");
}

#[tokio::test]
async fn a_hung_endpoint_times_out() {
    let hung = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", hung.local_addr().unwrap());
    tokio::spawn(async move {
        let mut held = vec![];
        while let Ok((c, _)) = hung.accept().await {
            held.push(c);
        }
    });
    let t = web_time::Instant::now();
    let (h, l, body) = (Http::new(200).unwrap(), list(&[url]), json!({}));
    let read = h.post_json(&l, 0, None, &body, ANSWER_MAX, None);
    let e = tokio::time::timeout(std::time::Duration::from_secs(10), read).await.expect("the transport's timeout ends it").unwrap_err();
    assert_eq!(e.kind, FailureKind::Timeout, "{e}");
    assert!(t.elapsed() < web_time::Duration::from_secs(3), "{:?}", t.elapsed());
    // a read's deadline shorter than the client's timeout bounds the request too
    let (slow, _, _) = fake(|_, _| (200, b"1".to_vec())).await;
    assert!(Http::new(200).unwrap().post_json(&list(std::slice::from_ref(&slow)), 0, None, &json!({}), ANSWER_MAX, None).await.is_ok(), "control");
    let past = web_time::Instant::now();
    let e = Http::new(5_000).unwrap().post_json(&list(&[slow]), 0, None, &json!({}), ANSWER_MAX, Some(past)).await.unwrap_err();
    assert_eq!(e.kind, FailureKind::Timeout, "a passed deadline sends nothing");
}

#[tokio::test]
async fn any_http_error_status_is_http() {
    for status in [500u16, 429, 401, 404] {
        let (url, _, _) = match status {
            500 => fake(|_, _| (500, b"{}".to_vec())).await,
            429 => fake(|_, _| (429, b"{}".to_vec())).await,
            401 => fake(|_, _| (401, b"{}".to_vec())).await,
            _ => fake(|_, _| (404, b"{}".to_vec())).await,
        };
        let e = post(&url, ANSWER_MAX).await.unwrap_err();
        assert_eq!(e.kind, FailureKind::Http, "{status}");
        assert!(e.text().contains(&status.to_string()), "{e}");
    }
    let (ok, _, _) = fake(|_, _| (200, b"{}".to_vec())).await;
    assert!(post(&ok, ANSWER_MAX).await.is_ok(), "control: 200");
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let (second, second_n, _) = fake(|_, _| (200, b"{}".to_vec())).await;
    let head = format!("HTTP/1.1 307 Temporary Redirect\r\nlocation: {second}/\r\ncontent-length: 0\r\n\r\n");
    let (first, _) = raw(head, vec![]).await;
    let l = NodeList::new(vec![Endpoint::new(&first, Class::Named, None, Some(EndpointAuth::Bearer(Secret::new("S1")))).unwrap()],
        Policy::Failover, 5_000, 5_000, 5_000).unwrap();
    let e = Http::new(5_000).unwrap().post_json(&l, 0, None, &json!({}), ANSWER_MAX, None).await.unwrap_err();
    assert_eq!(e.kind, FailureKind::Http, "{e}");
    assert!(!e.text().contains("127.0.0.1"), "no URL in the error: {e}");
    assert_eq!(second_n.load(SeqCst), 0, "the redirect target is never asked");
    assert!(post(&second, ANSWER_MAX).await.is_ok(), "control: the target answers when asked");
}

#[tokio::test]
async fn the_credential_goes_to_its_endpoint_only() {
    let (a, _, a_seen) = fake(|_, _| (200, b"{}".to_vec())).await;
    let (b, _, b_seen) = fake(|_, _| (200, b"{}".to_vec())).await;
    let (c, _, c_seen) = fake(|_, _| (200, b"{}".to_vec())).await;
    let l = NodeList::new(vec![
        Endpoint::new(&a, Class::Named, None, Some(EndpointAuth::Bearer(Secret::new("BEARER-A")))).unwrap(),
        Endpoint::new(&b, Class::Default, None, None).unwrap(),
        Endpoint::new(&c, Class::Named, None, Some(EndpointAuth::Header { name: "X-API-Key".into(), value: Secret::new("KEY-C") })).unwrap(),
    ], Policy::Failover, 5_000, 5_000, 5_000).unwrap();
    let h = Http::new(5_000).unwrap();
    for i in 0..3 {
        h.post_json(&l, i, None, &json!({}), ANSWER_MAX, None).await.unwrap();
    }
    let a_h = a_seen.lock().unwrap()[0].clone();
    assert_eq!(a_h.get("authorization").unwrap(), "Bearer BEARER-A", "control: its own");
    assert!(a_h.get("x-api-key").is_none());
    let b_h = b_seen.lock().unwrap()[0].clone();
    assert!(b_h.get("authorization").is_none() && b_h.get("x-api-key").is_none(), "none to an endpoint without one");
    let c_h = c_seen.lock().unwrap()[0].clone();
    assert_eq!(c_h.get("x-api-key").unwrap(), "KEY-C");
    assert!(c_h.get("authorization").is_none(), "not the first endpoint's");
}

#[tokio::test]
async fn a_json_rpc_error_keeps_code_message_data() {
    let (url, _, _) = fake(|_, _| (200, br#"{"jsonrpc":"2.0","id":1,"error":{"code":3,"message":"execution reverted","data":"0xdeadbeef"}}"#.to_vec())).await;
    let h = Http::new(5_000).unwrap();
    let e = h.json_rpc(&list(&[url]), 0, "eth_call", json!([]), ANSWER_MAX, None).await.unwrap().unwrap_err();
    assert_eq!((e.code, e.message.as_str(), e.data), (3, "execution reverted", Some(json!("0xdeadbeef"))));
    let (ok, _, _) = fake(|_, _| (200, br#"{"jsonrpc":"2.0","id":1,"result":"0x5"}"#.to_vec())).await;
    assert_eq!(h.json_rpc(&list(&[ok]), 0, "eth_chainId", json!([]), ANSWER_MAX, None).await.unwrap(), Ok(json!("0x5")), "control");
    let (neither, _, _) = fake(|_, _| (200, br#"{"jsonrpc":"2.0","id":1}"#.to_vec())).await;
    assert_eq!(h.json_rpc(&list(&[neither]), 0, "x", json!([]), ANSWER_MAX, None).await.unwrap_err().kind, FailureKind::AnswerMalformed);
}
