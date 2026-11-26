// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! chains-arweave plan T19 (feature `arweave`): the gateway reader (CLI-RPC-13) and the bundler uploader (CLI-RPC-14) against
//! in-process fakes on 127.0.0.1:0, and NODE-SPN-05's payer route by its shape. Each refusal has its control beside it.
#![cfg(all(feature = "arweave", feature = "node-client"))]
use axum::http::HeaderMap;
use scaas_rpc::arweave::{BundlerOutcome, Bundlers, Gateways, Upload, READ_MAX};
use scaas_rpc::node::NodeClient;
use scaas_rpc::{
    Class, Endpoint, EndpointAuth, Fanout, NodeList, Policy, Purpose, RpcError, Secret,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const NET: &str = "arweave.N.1";
type Seen = Arc<Mutex<Vec<(String, String, HeaderMap, Vec<u8>)>>>;
type Handler = Arc<dyn Fn(&str, &str, &[u8]) -> (u16, Vec<u8>) + Send + Sync>;

/// An axum fake answering `h(method, path, body)`, recording every request.
async fn serve(h: Handler) -> (String, Seen) {
    let seen: Seen = Default::default();
    let s2 = seen.clone();
    let app = axum::Router::new().fallback(
        move |m: axum::http::Method, u: axum::http::Uri, hd: HeaderMap, b: axum::body::Bytes| {
            let (h, s2) = (h.clone(), s2.clone());
            async move {
                s2.lock()
                    .unwrap()
                    .push((m.to_string(), u.path().to_string(), hd, b.to_vec()));
                let (status, body) = h(m.as_str(), u.path(), &b);
                (axum::http::StatusCode::from_u16(status).unwrap(), body)
            }
        },
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

fn info(net: &str, height: u64) -> Vec<u8> {
    json!({"network": net, "height": height})
        .to_string()
        .into_bytes()
}
fn obj(seed: u8) -> Vec<u8> {
    (0..65_552u32).map(|i| (i as u8) ^ seed).collect()
}
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
const ID: &str = "XzcPGO5O_Pdpy7opN5gi5VVyMU2XDP4eVKwlpfz13ZY";

/// A gateway: `/info` with `net` and `tip`, `/raw/<ID>` with `body`, GraphQL with the item in `block`.
async fn gateway(net: &'static str, tip: u64, body: Vec<u8>, block: Option<u64>) -> (String, Seen) {
    serve(Arc::new(move |_, path, _| match path {
        "/info" => (200, info(net, tip)),
        p if p == format!("/raw/{ID}") => (200, body.clone()),
        "/graphql" => {
            let b = block.map_or(Value::Null, |h| json!({"height": h}));
            (
                200,
                json!({"data": {"transactions": {"edges": [{"node": {"id": ID, "block": b}}]}}})
                    .to_string()
                    .into_bytes(),
            )
        }
        _ => (404, vec![]),
    }))
    .await
}

fn gws(urls: &[(String, Class)], policy: Policy, ops: &[&str]) -> Gateways {
    let e = urls
        .iter()
        .map(|(u, c)| Endpoint::new(u, *c, None, None).unwrap())
        .collect();
    let list = NodeList::new(e, policy, 2_000, 2_000, 5_000).unwrap();
    Gateways::new(list, ops.iter().map(|s| s.to_string()).collect(), NET).unwrap()
}
fn named(u: &str) -> (String, Class) {
    (u.to_string(), Class::Named)
}
fn raw_count(s: &Seen) -> usize {
    s.lock()
        .unwrap()
        .iter()
        .filter(|r| r.1.starts_with("/raw/"))
        .count()
}
fn eq_check(want: [u8; 32]) -> impl Fn(&[u8]) -> bool + Sync {
    move |b: &[u8]| sha(b) == want
}

#[tokio::test]
async fn a_read_returns_the_exact_object_without_a_range() {
    let o = obj(1);
    let (u, seen) = gateway(NET, 100, o.clone(), None).await;
    let g = gws(&[named(&u)], Policy::Failover, &["a"]);
    let got = g
        .data(
            ID,
            o.len() as u64,
            Purpose::FeedsDecryption,
            &eq_check(sha(&o)),
        )
        .await
        .unwrap();
    assert_eq!(got, o);
    for (_, path, h, _) in seen.lock().unwrap().iter() {
        assert!(h.get("range").is_none(), "no Range on {path}");
    }
}

#[tokio::test]
async fn the_id_and_the_length_are_checked_before_any_request() {
    let (u, seen) = gateway(NET, 100, obj(1), None).await;
    let g = gws(&[named(&u)], Policy::Failover, &["a"]);
    let any = |_: &[u8]| true;
    for bad in ["", "ar://x", &ID[..42], &format!("{}B", &ID[..42])] {
        assert_eq!(
            g.data(bad, 65_552, Purpose::Plain, &any)
                .await
                .unwrap_err()
                .code(),
            "Argument",
            "{bad}"
        );
    }
    assert_eq!(
        g.data(ID, READ_MAX + 1, Purpose::Plain, &any)
            .await
            .unwrap_err()
            .code(),
        "Argument"
    );
    assert!(seen.lock().unwrap().is_empty(), "no request");
    assert!(
        g.data(ID, 65_552, Purpose::Plain, &any).await.is_ok(),
        "control"
    );
}

#[tokio::test]
async fn a_gateway_of_another_network_is_dropped_and_failover_moves_on() {
    let o = obj(2);
    let (bad, bad_seen) = gateway("arweave.other", 100, o.clone(), None).await;
    let (good, _) = gateway(NET, 100, o.clone(), None).await;
    let g = gws(&[named(&bad), named(&good)], Policy::Failover, &["a", "b"]);
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::Plain, &|_| true)
            .await
            .unwrap(),
        o
    );
    assert_eq!(raw_count(&bad_seen), 0, "never read from");
}

#[tokio::test]
async fn failover_moves_past_a_body_that_fails_the_check() {
    let o = obj(3);
    let (liar, liar_seen) = gateway(NET, 100, obj(4), None).await;
    let (good, _) = gateway(NET, 100, o.clone(), None).await;
    let g = gws(&[named(&liar), named(&good)], Policy::Failover, &["a", "b"]);
    assert_eq!(
        g.data(
            ID,
            o.len() as u64,
            Purpose::FeedsDecryption,
            &eq_check(sha(&o))
        )
        .await
        .unwrap(),
        o
    );
    assert_eq!(raw_count(&liar_seen), 1);
    // only the liar: every gateway failed, AnswerRefused named
    let g1 = gws(&[named(&liar)], Policy::Failover, &["a"]);
    match g1
        .data(ID, o.len() as u64, Purpose::Plain, &eq_check(sha(&o)))
        .await
        .unwrap_err()
    {
        RpcError::EndpointAllFailed { last: Some(f), .. } => {
            assert_eq!(f.kind, scaas_rpc::FailureKind::AnswerRefused)
        }
        e => panic!("{e:?}"),
    }
}

#[tokio::test]
async fn a_body_longer_or_shorter_than_len_is_refused() {
    let o = obj(5);
    for (body, what) in [
        (o[..o.len() - 1].to_vec(), "shorter"),
        ([&o[..], &[0]].concat(), "longer"),
    ] {
        let (u, _) = gateway(NET, 100, body, None).await;
        let g = gws(&[named(&u)], Policy::Failover, &["a"]);
        assert!(
            g.data(ID, o.len() as u64, Purpose::Plain, &|_| true)
                .await
                .is_err(),
            "{what}"
        );
    }
}

/// A raw fake answering `/info` properly and `/raw/` with `head` and then holding the connection without a body.
async fn raw_head(head: String) -> (String, Arc<AtomicUsize>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    let written: Arc<AtomicUsize> = Default::default();
    let w = written.clone();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            let (head, w) = (head.clone(), w.clone());
            tokio::spawn(async move {
                let mut req = vec![0u8; 8192];
                let mut n = 0;
                while !req[..n].windows(4).any(|x| x == b"\r\n\r\n") {
                    match c.read(&mut req[n..]).await {
                        Ok(0) | Err(_) => return,
                        Ok(k) => n += k,
                    }
                }
                let line = String::from_utf8_lossy(&req[..n]).to_string();
                if line.starts_with("GET /info") {
                    let b = info(NET, 100);
                    let _ = c
                        .write_all(
                            format!("HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n", b.len())
                                .as_bytes(),
                        )
                        .await;
                    let _ = c.write_all(&b).await;
                    return;
                }
                let _ = c.write_all(head.as_bytes()).await;
                // the body is never written: a client that waits for it hangs to its timeout
                let mut sink = [0u8; 1];
                let _ = c.read(&mut sink).await;
                w.fetch_add(0, SeqCst);
            });
        }
    });
    (url, written)
}

#[tokio::test]
async fn an_announced_length_other_than_len_is_refused_unread() {
    let len = 65_552u64;
    let (u, _) = raw_head(format!(
        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
        len + 1
    ))
    .await;
    let g = gws(&[named(&u)], Policy::Failover, &["a"]);
    let t = std::time::Instant::now();
    assert!(g.data(ID, len, Purpose::Plain, &|_| true).await.is_err());
    assert!(
        t.elapsed() < std::time::Duration::from_millis(1_500),
        "refused at the header, not at the timeout"
    );
    // control: the announced length equal to len waits for the body (the request's 2 s timeout)
    let (u2, _) = raw_head(format!("HTTP/1.1 200 OK\r\ncontent-length: {len}\r\n\r\n")).await;
    let g2 = gws(&[named(&u2)], Policy::Failover, &["a"]);
    let t = std::time::Instant::now();
    assert!(g2.data(ID, len, Purpose::Plain, &|_| true).await.is_err());
    assert!(
        t.elapsed() >= std::time::Duration::from_millis(1_500),
        "control: it read on"
    );
}

/// T26 B-21: a strict-majority read asks one gateway at a time and stops once a group has its majority, keeping one copy:
/// the third gateway is never asked when the first two agree; a first answer outvoted is replaced by the majority's bytes,
/// read again from a member. Control: the agreed object either way.
#[tokio::test]
async fn strict_majority_keeps_one_copy() {
    let o = obj(6);
    let raw = |s: &Seen| {
        s.lock()
            .unwrap()
            .iter()
            .filter(|r| r.0.contains("/raw/") || r.1.contains("/raw/"))
            .count()
    };
    let (a, sa) = gateway(NET, 100, o.clone(), None).await;
    let (b, sb) = gateway(NET, 100, o.clone(), None).await;
    let (c, sc) = gateway(NET, 100, obj(7), None).await;
    let g = gws(
        &[named(&a), named(&b), named(&c)],
        Policy::StrictMajority,
        &["a", "b", "c"],
    );
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::Plain, &|_| true)
            .await
            .unwrap(),
        o
    );
    assert_eq!(
        (raw(&sa), raw(&sb), raw(&sc)),
        (1, 1, 0),
        "the third never asked"
    );
    let g = gws(
        &[named(&c), named(&a), named(&b)],
        Policy::StrictMajority,
        &["c", "a", "b"],
    );
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::Plain, &|_| true)
            .await
            .unwrap(),
        o,
        "control: the first outvoted, the majority's bytes"
    );
}

#[tokio::test]
async fn strict_majority_by_sha256() {
    let o = obj(6);
    let (a, _) = gateway(NET, 100, o.clone(), None).await;
    let (b, _) = gateway(NET, 100, o.clone(), None).await;
    let (c, _) = gateway(NET, 100, obj(7), None).await;
    let g = gws(
        &[named(&a), named(&b), named(&c)],
        Policy::StrictMajority,
        &["a", "b", "c"],
    );
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::FeedsDecryption, &|_| true)
            .await
            .unwrap(),
        o
    );
    let (d, _) = gateway(NET, 100, obj(8), None).await;
    let g = gws(
        &[named(&a), named(&c), named(&d)],
        Policy::StrictMajority,
        &["a", "c", "d"],
    );
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::FeedsDecryption, &|_| true)
            .await
            .unwrap_err()
            .code(),
        "EndpointNoMajority"
    );
}

#[tokio::test]
async fn the_decryption_mark() {
    let o = obj(9);
    let (disc, disc_seen) = gateway(NET, 100, o.clone(), None).await;
    let (good, _) = gateway(NET, 100, o.clone(), None).await;
    // failover: a discovered gateway is skipped for a read that feeds a decryption, read for a plain one
    let g = gws(
        &[(disc.clone(), Class::Discovered), named(&good)],
        Policy::Failover,
        &["a", "b"],
    );
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::FeedsDecryption, &|_| true)
            .await
            .unwrap(),
        o
    );
    assert_eq!(raw_count(&disc_seen), 0);
    assert_eq!(
        g.data(ID, o.len() as u64, Purpose::Plain, &|_| true)
            .await
            .unwrap(),
        o
    );
    assert_eq!(raw_count(&disc_seen), 1, "control: a plain read uses it");
    let only = gws(
        &[(disc.clone(), Class::Discovered)],
        Policy::Failover,
        &["a"],
    );
    assert_eq!(
        only.data(ID, o.len() as u64, Purpose::FeedsDecryption, &|_| true)
            .await
            .unwrap_err()
            .code(),
        "NoTrustedEndpoint"
    );
    // agreement: a discovered member needs n >= 3
    let two = gws(
        &[(disc.clone(), Class::Discovered), named(&good)],
        Policy::StrictMajority,
        &["a", "b"],
    );
    assert_eq!(
        two.data(ID, o.len() as u64, Purpose::FeedsDecryption, &|_| true)
            .await
            .unwrap_err()
            .code(),
        "AgreementNeedsThree"
    );
    let (third, _) = gateway(NET, 100, o.clone(), None).await;
    let three = gws(
        &[(disc, Class::Discovered), named(&good), named(&third)],
        Policy::StrictMajority,
        &["a", "b", "c"],
    );
    assert!(
        three
            .data(ID, o.len() as u64, Purpose::FeedsDecryption, &|_| true)
            .await
            .is_ok(),
        "control"
    );
}

#[tokio::test]
async fn status_is_bounded() {
    let big = serve(Arc::new(|_, path, _| match path {
        "/info" => (200, info(NET, 100)),
        _ => (
            200,
            format!("{{\"data\": \"{}\"}}", "x".repeat(70_000)).into_bytes(),
        ),
    }))
    .await;
    let g = gws(&[named(&big.0)], Policy::Failover, &["a"]);
    assert!(g.status_at(0, ID).await.is_err(), "above 64 KiB");
    let deep = serve(Arc::new(|_, path, _| match path {
        "/info" => (200, info(NET, 100)),
        _ => (
            200,
            format!("{}{}", "[".repeat(70), "]".repeat(70)).into_bytes(),
        ),
    }))
    .await;
    let g = gws(&[named(&deep.0)], Policy::Failover, &["a"]);
    assert!(g.status_at(0, ID).await.is_err(), "deeper than 64");
    let (ok, _) = gateway(NET, 160, obj(1), Some(100)).await;
    let g = gws(&[named(&ok)], Policy::Failover, &["a"]);
    let s = g.status_at(0, ID).await.unwrap();
    assert_eq!((s.block, s.tip), (Some(100), 160), "control");
}

#[tokio::test]
async fn settled_needs_two_operators_the_depth_and_the_bytes() {
    let o = obj(10);
    let h = sha(&o);
    let len = o.len() as u64;
    let (a, _) = gateway(NET, 200, o.clone(), Some(100)).await;
    let (b, _) = gateway(NET, 200, o.clone(), Some(100)).await;
    // one gateway
    assert!(!gws(&[named(&a)], Policy::Failover, &["x"])
        .settled(ID, len, 50, &h)
        .await
        .unwrap());
    // two of one operator
    assert!(!gws(&[named(&a), named(&b)], Policy::Failover, &["x", "x"])
        .settled(ID, len, 50, &h)
        .await
        .unwrap());
    // shallower than depth
    let (s1, _) = gateway(NET, 120, o.clone(), Some(100)).await;
    let (s2, _) = gateway(NET, 120, o.clone(), Some(100)).await;
    assert!(
        !gws(&[named(&s1), named(&s2)], Policy::Failover, &["x", "y"])
            .settled(ID, len, 50, &h)
            .await
            .unwrap()
    );
    // the bytes read back differ
    let (w1, _) = gateway(NET, 200, obj(11), Some(100)).await;
    let (w2, _) = gateway(NET, 200, obj(11), Some(100)).await;
    assert!(
        !gws(&[named(&w1), named(&w2)], Policy::Failover, &["x", "y"])
            .settled(ID, len, 50, &h)
            .await
            .unwrap()
    );
    // a discovered gateway never counts
    assert!(!gws(
        &[named(&a), (b.clone(), Class::Discovered)],
        Policy::Failover,
        &["x", "y"]
    )
    .settled(ID, len, 50, &h)
    .await
    .unwrap());
    // all three conditions
    assert!(gws(&[named(&a), named(&b)], Policy::Failover, &["x", "y"])
        .settled(ID, len, 50, &h)
        .await
        .unwrap());
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn item() -> (Vec<u8>, String) {
    let f = format!(
        "{}/../../smartcontracts/vectors/arweave/items.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let v: Value = serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap();
    let r = &v["items"][0];
    (
        unhex(r["item"].as_str().unwrap()),
        r["id"].as_str().unwrap().to_string(),
    )
}

async fn bundler(status: u16, receipt_id: Option<String>) -> (String, Seen) {
    serve(Arc::new(move |_, _, _| {
        let b = receipt_id
            .as_ref()
            .map_or(b"{\"error\":\"no\"}".to_vec(), |id| {
                json!({"id": id, "owner": "o"}).to_string().into_bytes()
            });
        (status, b)
    }))
    .await
}
fn bl(urls: &[&str]) -> Bundlers {
    let e = urls
        .iter()
        .map(|u| Endpoint::new(u, Class::Default, None, None).unwrap())
        .collect();
    Bundlers::new(
        NodeList::new(e, Policy::Failover, 2_000, 2_000, 5_000).unwrap(),
        1 << 17,
    )
    .unwrap()
}

#[tokio::test]
async fn an_upload_posts_the_same_bytes_and_checks_the_receipt_id() {
    let (it, id) = item();
    let (a, a_seen) = bundler(200, Some(id.clone())).await;
    let (b, b_seen) = bundler(200, Some("A".repeat(43))).await;
    let up = bl(&[&a, &b]).upload(&it, Fanout::All, None).await.unwrap();
    let Upload::Sent { id: got, outcomes } = &up else {
        panic!("{up:?}")
    };
    assert_eq!(got, &id);
    assert!(matches!(outcomes[0].1, BundlerOutcome::Accepted { .. }));
    assert!(
        matches!(&outcomes[1].1, BundlerOutcome::Refused { reason, .. } if reason.contains("another id"))
    );
    for s in [&a_seen, &b_seen] {
        let r = &s.lock().unwrap()[0];
        assert_eq!((r.0.as_str(), r.1.as_str(), &r.3), ("POST", "/tx", &it));
        assert_eq!(r.2["content-type"], "application/octet-stream");
    }
    // only the other id: rejected
    let only = bl(&[&b]).upload(&it, Fanout::First, None).await.unwrap();
    assert!(matches!(only, Upload::Rejected { .. }));
    // a tampered item is refused before any request
    let mut bad = it.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert_eq!(
        bl(&[&a])
            .upload(&bad, Fanout::All, None)
            .await
            .unwrap_err()
            .code(),
        "Argument"
    );
    assert_eq!(a_seen.lock().unwrap().len(), 1, "nothing sent for it");
}

#[tokio::test]
async fn http_402_is_payment_required_and_x_paid_by_goes_to_that_bundler_only() {
    let (it, id) = item();
    let (p, p_seen) = bundler(402, None).await;
    let up = bl(&[&p]).upload(&it, Fanout::All, None).await.unwrap();
    assert!(up.payment_required());
    let (a, a_seen) = bundler(200, Some(id.clone())).await;
    let (b, b_seen) = bundler(200, Some(id.clone())).await;
    let up = bl(&[&a, &b])
        .upload(&it, Fanout::All, Some((1, "PAYER_addr-1")))
        .await
        .unwrap();
    assert!(!up.payment_required(), "control");
    assert!(
        a_seen.lock().unwrap()[0].2.get("x-paid-by").is_none(),
        "not to bundler 0"
    );
    assert_eq!(b_seen.lock().unwrap()[0].2["x-paid-by"], "PAYER_addr-1");
    assert!(p_seen.lock().unwrap()[0].2.get("x-paid-by").is_none());
}

#[tokio::test]
async fn no_redirect_is_followed_and_errors_carry_no_url() {
    let (it, id) = item();
    let (target, t_seen) = bundler(200, Some(id)).await;
    let t2 = target.clone();
    let (r, _) = serve(Arc::new(move |_, _, _| (307, t2.clone().into_bytes()))).await;
    let up = bl(&[&r]).upload(&it, Fanout::All, None).await.unwrap();
    let Upload::Rejected { outcomes, .. } = &up else {
        panic!("{up:?}")
    };
    assert!(matches!(outcomes[0].1, BundlerOutcome::Unreachable(_)));
    assert!(
        t_seen.lock().unwrap().is_empty(),
        "the redirect's target never reached"
    );
    let host = r.trim_start_matches("http://");
    assert!(!format!("{up:?}").contains(host), "no URL in the outcome");
    let (g, _) = gateway("arweave.other", 100, obj(1), None).await;
    let e = gws(&[named(&g)], Policy::Failover, &["a"])
        .data(ID, 65_552, Purpose::Plain, &|_| true)
        .await
        .unwrap_err();
    assert!(!format!("{e:?} {e}").contains(g.trim_start_matches("http://")));
}

#[tokio::test]
async fn the_payer_route_by_nodes_shape() {
    let (u, seen) = serve(Arc::new(|_, path, _| match path {
        "/v1/arweave/payer" => (
            200,
            json!({"paidBy": "payer-ADDR_1", "expiresAt": 1_800_000_000u64})
                .to_string()
                .into_bytes(),
        ),
        _ => (404, vec![]),
    }))
    .await;
    let auth = EndpointAuth::Bearer(Secret::new("CRED"));
    let n = NodeClient::new(
        NodeList::new(
            vec![Endpoint::new(&u, Class::Named, None, Some(auth)).unwrap()],
            Policy::Failover,
            2_000,
            2_000,
            5_000,
        )
        .unwrap(),
    )
    .unwrap();
    let a = n.arweave_payer(ID, 2, 1 << 17).await.unwrap().unwrap();
    assert_eq!(
        (a.paid_by.as_str(), a.expires_at),
        ("payer-ADDR_1", 1_800_000_000)
    );
    let r = seen.lock().unwrap()[0].clone();
    assert_eq!(
        r.2["authorization"], "Bearer CRED",
        "the gateway credential"
    );
    let body: Value = serde_json::from_slice(&r.3).unwrap();
    assert_eq!(
        body,
        json!({"address": ID, "signatureType": 2, "bucket": 131072}),
        "named fields only"
    );
    // the route off: no payer
    let (off, _) = serve(Arc::new(|_, _, _| (404, vec![]))).await;
    let n = NodeClient::new(NodeList::from_urls(&[off]).unwrap()).unwrap();
    assert_eq!(n.arweave_payer(ID, 2, 1 << 17).await.unwrap(), None);
    // a budget refused by name
    let (busy, _) = serve(Arc::new(|_, _, _| {
        (
            429,
            json!({"code": "PAYER_BUDGET"}).to_string().into_bytes(),
        )
    }))
    .await;
    let n = NodeClient::new(NodeList::from_urls(&[busy]).unwrap()).unwrap();
    match n.arweave_payer(ID, 2, 1 << 17).await.unwrap_err() {
        RpcError::NodeRefused { code, .. } => assert_eq!(code, "PAYER_BUDGET"),
        e => panic!("{e:?}"),
    }
    // malformed requests never leave
    assert_eq!(
        n.arweave_payer("a b", 2, 1 << 17).await.unwrap_err().code(),
        "Argument"
    );
    assert_eq!(
        n.arweave_payer(ID, 1, 1 << 17).await.unwrap_err().code(),
        "Argument"
    );
    assert_eq!(
        n.arweave_payer(ID, 2, 3).await.unwrap_err().code(),
        "Argument"
    );
}
