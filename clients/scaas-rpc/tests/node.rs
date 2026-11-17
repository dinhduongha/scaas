// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T10 / T11: the scaas-node client against fake gateways on 127.0.0.1:0 (CLI-RPC-10, F8). The node's own conformance test
//! is `scaas-node/tests/rpc_client.rs`.
use scaas_rpc::node::{NodeClient, NodeOutcome, UaMetaTxReq, BODY_MAX};
use scaas_rpc::{Class, Endpoint, EndpointAuth, NodeList, Policy, RpcError, Secret};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

/// What a fake gateway saw: method, path?query, headers, body.
#[derive(Clone, Debug)]
struct Seen {
    path: String,
    headers: axum::http::HeaderMap,
    body: Vec<u8>,
}

type Answer = Arc<dyn Fn(&str, &[u8]) -> (u16, Value) + Send + Sync>;

async fn gateway(answer: Answer) -> (String, Arc<Mutex<Vec<Seen>>>) {
    let seen: Arc<Mutex<Vec<Seen>>> = Default::default();
    let s2 = seen.clone();
    let app = axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: axum::body::Bytes| {
            let (s2, answer) = (s2.clone(), answer.clone());
            async move {
                let path = uri
                    .path_and_query()
                    .map(|p| p.to_string())
                    .unwrap_or_default();
                s2.lock().unwrap().push(Seen {
                    path: path.clone(),
                    headers,
                    body: body.to_vec(),
                });
                let (status, v) = answer(&path, &body);
                let mut r = axum::response::Response::new(axum::body::Body::from(
                    serde_json::to_vec(&v).unwrap(),
                ));
                *r.status_mut() = axum::http::StatusCode::from_u16(status).unwrap();
                if status / 100 == 3 {
                    r.headers_mut()
                        .insert("location", "http://127.0.0.1:9/".parse().unwrap());
                }
                r
            }
        },
    );
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    (url, seen)
}

fn queued() -> Answer {
    Arc::new(|_, _| (202, json!({"status": "queued"})))
}

fn client(urls: &[(&str, Option<EndpointAuth>)]) -> NodeClient {
    let e = urls
        .iter()
        .map(|(u, a)| Endpoint::new(u, Class::Named, None, a.clone()).unwrap())
        .collect();
    NodeClient::new(NodeList::new(e, Policy::Failover, 5_000, 5_000, 10_000).unwrap()).unwrap()
}

fn op() -> Value {
    json!({"kind": "UATransfer", "token": "0x00000000000000000000000000000000000000aa", "args": {"to": "0x01", "amount": "5"},
        "envelope": {"nonce": "0", "validUntil": "99"}, "auth": {"keyData": "0x", "signature": "0x01", "members": []}})
}

#[tokio::test]
async fn bodies_are_sent_byte_for_byte() {
    let (g, seen) = gateway(queued()).await;
    let c = client(&[(&g, None)]);
    let o = op();
    c.submit_op_at(0, 7622, &o).await.unwrap();
    let want = format!(
        r#"{{"chain":7622,"op":{}}}"#,
        serde_json::to_string(&o).unwrap()
    );
    let s = seen.lock().unwrap()[0].clone();
    assert_eq!(
        (s.path.as_str(), String::from_utf8(s.body).unwrap()),
        ("/v1/op", want)
    );
    let m = UaMetaTxReq {
        chain: 7622,
        token: "0xaa".into(),
        contract: None,
        struct_: Some("transfer".into()),
        m: json!({"from": "0x01", "to": "0x02"}),
        auth: json!({"signature": "0x01"}),
    };
    c.submit_ua_metatx_at(0, &m).await.unwrap();
    let s = seen.lock().unwrap()[1].clone();
    assert_eq!(s.path, "/v1/ua-metatx");
    assert_eq!(s.body, serde_json::to_vec(&m).unwrap());
    let body: Value = serde_json::from_slice(&s.body).unwrap();
    assert_eq!(body["struct"], "transfer");
    assert!(
        body.get("contract").is_none(),
        "an absent field is not sent"
    );
}

#[tokio::test]
async fn an_op_that_is_not_an_object_is_argument() {
    let (g, seen) = gateway(queued()).await;
    let c = client(&[(&g, None)]);
    for bad in [json!("0xdeadbeef"), json!([1, 2]), json!(null)] {
        assert_eq!(
            c.submit_op_at(0, 1, &bad).await.unwrap_err().code(),
            "Argument",
            "{bad}"
        );
    }
    assert!(seen.lock().unwrap().is_empty());
    assert!(c.submit_op_at(0, 1, &op()).await.is_ok(), "control");
}

#[tokio::test]
async fn a_body_above_64_kib_is_refused_unsent() {
    let (g, seen) = gateway(queued()).await;
    let c = client(&[(&g, None)]);
    let mut big = op();
    big["pad"] = json!("x".repeat(BODY_MAX));
    assert!(matches!(
        c.submit_op_at(0, 1, &big).await,
        Err(RpcError::BodyTooLarge { cap: 65536, .. })
    ));
    assert!(seen.lock().unwrap().is_empty(), "nothing sent");
    let mut fits = op();
    fits["pad"] = json!("x".repeat(BODY_MAX - 400));
    assert!(
        c.submit_op_at(0, 1, &fits).await.is_ok(),
        "control: below the cap"
    );
}

#[tokio::test]
async fn queued_202_and_duplicate_200() {
    let (q, _) = gateway(Arc::new(|_, _| {
        (202, json!({"status": "queued", "intent_id": "i-1"}))
    }))
    .await;
    let (d, _) = gateway(Arc::new(|_, _| (200, json!({"status": "queued"})))).await;
    let c = client(&[(&q, None), (&d, None)]);
    assert_eq!(
        c.submit_op_at(0, 1, &op()).await.unwrap(),
        NodeOutcome::Queued {
            status: 202,
            intent_id: Some("i-1".into())
        }
    );
    assert_eq!(
        c.submit_op_at(1, 1, &op()).await.unwrap(),
        NodeOutcome::Queued {
            status: 200,
            intent_id: None
        }
    );
}

#[tokio::test]
async fn an_error_is_read_by_code_else_by_error_string() {
    let (coded, _) = gateway(Arc::new(|_, _| {
        (
            400,
            json!({"error": "free text", "code": "HEX_ARGS_REFUSED", "detail": "args"}),
        )
    }))
    .await;
    let (legacy, _) = gateway(Arc::new(|_, _| {
        (400, json!({"error": "token not served by this relayer"}))
    }))
    .await;
    let (busy, _) = gateway(Arc::new(|_, _| (503, json!({"error": "submit busy"})))).await;
    let c = client(&[(&coded, None), (&legacy, None), (&busy, None)]);
    match c.submit_op_at(0, 1, &op()).await.unwrap() {
        NodeOutcome::Refused(RpcError::NodeRefused {
            status: 400,
            code,
            detail,
            ..
        }) => {
            assert_eq!(
                (code.as_str(), detail.as_deref()),
                ("HEX_ARGS_REFUSED", Some("args"))
            );
        }
        o => panic!("{o:?}"),
    }
    match c.submit_op_at(1, 1, &op()).await.unwrap() {
        NodeOutcome::Refused(RpcError::NodeRefused { code, .. }) => {
            assert_eq!(code, "token not served by this relayer")
        }
        o => panic!("{o:?}"),
    }
    assert!(
        matches!(
            c.submit_op_at(2, 1, &op()).await.unwrap(),
            NodeOutcome::Unreachable(_)
        ),
        "a 5xx is unreachable"
    );
}

#[tokio::test]
async fn revert_data_is_kept() {
    let (g, _) = gateway(Arc::new(|_, _| (400, json!({"error": "simulation: MetaTxBadNonce", "code": "SIM_REVERTED", "revert_data": "0xdeadbeef"})))).await;
    match client(&[(&g, None)])
        .submit_op_at(0, 1, &op())
        .await
        .unwrap()
    {
        NodeOutcome::Refused(RpcError::NodeRefused { revert_data, .. }) => {
            assert_eq!(revert_data.as_deref(), Some("0xdeadbeef"))
        }
        o => panic!("{o:?}"),
    }
}

/// NODE-GW-02's HMAC: `X-Scaas-Timestamp`, a 16-byte base64url `X-Scaas-Nonce`, `X-Scaas-Signature = hex(HMAC-SHA256(secret, ts
/// "." nonce "." METHOD " " path?query "\n" body))`, recomputed here; another body gives another signature.
#[tokio::test]
async fn hmac_headers_follow_node_gw_02() {
    use hmac::{Hmac, Mac};
    let (g, seen) = gateway(queued()).await;
    let secret = "0123456789abcdef-secret";
    let c = client(&[(&g, Some(EndpointAuth::Hmac(Secret::new(secret))))]);
    c.submit_op_at(0, 1, &op()).await.unwrap();
    c.submit_op_at(0, 2, &op()).await.unwrap();
    let all = seen.lock().unwrap().clone();
    let mac = |s: &Seen| {
        let h = |k: &str| s.headers.get(k).unwrap().to_str().unwrap().to_string();
        let (ts, nonce) = (h("x-scaas-timestamp"), h("x-scaas-nonce"));
        assert_eq!(nonce.len(), 22, "16 bytes in base64url without padding");
        assert!(nonce
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(ts.parse::<u64>().unwrap().abs_diff(now) <= 5);
        let mut m = <Hmac<sha2::Sha256>>::new_from_slice(secret.as_bytes()).unwrap();
        m.update(format!("{ts}.{nonce}.POST {}\n", s.path).as_bytes());
        m.update(&s.body);
        (
            alloy::hex::encode(m.finalize().into_bytes()),
            h("x-scaas-signature"),
            nonce,
        )
    };
    let (want, got, n0) = mac(&all[0]);
    assert_eq!(got, want);
    let (want1, got1, n1) = mac(&all[1]);
    assert_eq!(got1, want1);
    assert_ne!(got, got1, "another body, another signature");
    assert_ne!(n0, n1, "a fresh nonce");
    assert!(all[0].headers.get("authorization").is_none());
}

#[tokio::test]
async fn a_second_gateway_receives_no_credential_of_the_first() {
    let (a, a_seen) = gateway(Arc::new(|_, _| (503, json!({"error": "submit busy"})))).await;
    let (b, b_seen) = gateway(Arc::new(|_, _| (200, json!({"markets": []})))).await;
    let c = client(&[
        (
            &a,
            Some(EndpointAuth::Bearer(Secret::new("FIRST-SECRET-0123"))),
        ),
        (&b, None),
    ]);
    assert_eq!(
        c.dex_markets(7622).await.unwrap(),
        json!({"markets": []}),
        "the read fails over"
    );
    assert_eq!(
        a_seen.lock().unwrap()[0]
            .headers
            .get("authorization")
            .unwrap(),
        "Bearer FIRST-SECRET-0123",
        "control: its own"
    );
    let h = &b_seen.lock().unwrap()[0].headers;
    assert!(
        h.get("authorization").is_none() && h.get("x-scaas-signature").is_none(),
        "{h:?}"
    );
}

#[tokio::test]
async fn a_redirect_from_a_gateway_is_unreachable_and_not_followed() {
    let (target, target_seen) = gateway(queued()).await;
    let t2 = target.clone();
    let (r, _) = gateway(Arc::new(move |_, _| (307, json!({"location": t2})))).await;
    assert!(matches!(
        client(&[(&r, None)])
            .submit_op_at(0, 1, &op())
            .await
            .unwrap(),
        NodeOutcome::Unreachable(_)
    ));
    assert!(target_seen.lock().unwrap().is_empty());
}

#[tokio::test]
async fn secrets_never_in_debug() {
    let c = client(&[
        (
            "https://gw.example/PATHSECRET",
            Some(EndpointAuth::Bearer(Secret::new("BEARERSECRET"))),
        ),
        (
            "https://gw2.example",
            Some(EndpointAuth::Hmac(Secret::new("HMACSECRET-0123456"))),
        ),
    ]);
    let d = format!("{c:?}");
    for s in ["PATHSECRET", "BEARERSECRET", "HMACSECRET", "gw.example"] {
        assert!(!d.contains(s), "{s} in {d}");
    }
}

#[tokio::test]
async fn dex_reads_name_their_query() {
    let (g, seen) = gateway(Arc::new(|_, _| (200, json!({})))).await;
    let c = client(&[(&g, None)]);
    c.dex_depth(7, 2, Some(5)).await.unwrap();
    c.dex_trades(7, 2).await.unwrap();
    c.dex_ticker(7, 2).await.unwrap();
    c.dex_orders(7, "0xab").await.unwrap();
    let paths: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(
        paths,
        [
            "/v1/dex/depth?chain=7&market=2&levels=5",
            "/v1/dex/trades?chain=7&market=2",
            "/v1/dex/ticker?chain=7&market=2",
            "/v1/dex/orders?chain=7&maker=0xab"
        ]
    );
    assert_eq!(
        c.dex_orders(7, "0xab&x=1").await.unwrap_err().code(),
        "Argument"
    );
}

// ---------------------------------------------------------------- plan T11: several nodes

use scaas_rpc::node::{Fanout, IntentState, MergedState, SubmitOutcome};

#[tokio::test]
async fn the_same_bytes_to_every_selected_node() {
    let (a, sa) = gateway(queued()).await;
    let (b, sb) = gateway(queued()).await;
    let (c, sc) = gateway(queued()).await;
    let cl = client(&[(&a, None), (&b, None), (&c, None)]);
    cl.submit_op(7622, &op(), Fanout::All).await.unwrap();
    let bodies: Vec<Vec<u8>> = [sa, sb, sc]
        .iter()
        .map(|s| s.lock().unwrap()[0].body.clone())
        .collect();
    assert!(bodies.iter().all(|b| *b == bodies[0]), "byte for byte");
    let (d, sd) = gateway(queued()).await;
    let (e, se) = gateway(queued()).await;
    client(&[(&d, None), (&e, None)])
        .submit_op(7622, &op(), Fanout::First)
        .await
        .unwrap();
    assert_eq!(
        (sd.lock().unwrap().len(), se.lock().unwrap().len()),
        (1, 0),
        "First: endpoint 0 only"
    );
}

#[tokio::test]
async fn one_queued_is_queued() {
    let (a, _) = gateway(Arc::new(|_, _| (400, json!({"error": "RELAYER_NOT_OURS"})))).await;
    let (b, _) = gateway(queued()).await;
    let cl = client(&[(&a, None), (&b, None), ("http://127.0.0.1:9", None)]);
    match cl.submit_op(1, &op(), Fanout::All).await.unwrap() {
        SubmitOutcome::Queued {
            by,
            refused,
            unreachable,
        } => {
            assert_eq!(by, vec![1]);
            assert_eq!(refused.iter().map(|r| r.0).collect::<Vec<_>>(), vec![0]);
            assert_eq!(unreachable.iter().map(|r| r.0).collect::<Vec<_>>(), vec![2]);
        }
        o => panic!("{o:?}"),
    }
}

#[tokio::test]
async fn all_refused_is_not_queued_and_not_final() {
    let (a, _) = gateway(Arc::new(|_, _| (400, json!({"error": "expired"})))).await;
    let (b, _) = gateway(Arc::new(|_, _| (400, json!({"error": "expired"})))).await;
    let o = client(&[(&a, None), (&b, None)])
        .submit_op(1, &op(), Fanout::All)
        .await
        .unwrap();
    assert!(
        matches!(o, SubmitOutcome::NotQueued { ref outcomes } if outcomes.len() == 2),
        "{o:?}"
    );
    assert!(!o.is_terminal());
}

#[test]
fn a_node_that_timed_out_on_submit_keeps_it_in_flight() {
    // A queued it, B's answer was lost (unreachable at submit) but B queued it; A now reports dead, B still works on it
    let sent_to = [0, 1];
    let s = NodeClient::merged_state(
        &sent_to,
        &[
            (0, Some(IntentState::Dead)),
            (1, Some(IntentState::InFlight)),
        ],
    );
    assert_eq!(s, MergedState::InFlight);
    let s = NodeClient::merged_state(&sent_to, &[(0, Some(IntentState::Dead)), (1, None)]);
    assert_eq!(
        s,
        MergedState::InFlight,
        "an unreachable node keeps it in flight"
    );
}

#[test]
fn all_dead_is_given_up_not_failed() {
    let s = NodeClient::merged_state(
        &[0, 1, 2],
        &[
            (0, Some(IntentState::Dead)),
            (1, Some(IntentState::Unknown)),
            (2, Some(IntentState::Dead)),
        ],
    );
    assert_eq!(s, MergedState::GivenUpByEveryNode);
    assert!(!s.is_terminal());
    let s = NodeClient::merged_state(
        &[0, 1, 2],
        &[
            (0, Some(IntentState::Dead)),
            (1, Some(IntentState::Unknown)),
        ],
    );
    assert_eq!(s, MergedState::InFlight, "control: one node not heard");
}

#[test]
fn one_mined_is_landed() {
    let s = NodeClient::merged_state(
        &[0, 1],
        &[(0, Some(IntentState::Dead)), (1, Some(IntentState::Mined))],
    );
    assert_eq!(s, MergedState::Landed { by: vec![1] });
    assert!(!s.is_terminal());
}

#[tokio::test]
async fn reads_fail_over() {
    let (b, _) = gateway(Arc::new(|_, _| (200, json!({"trades": []})))).await;
    let cl = client(&[("http://127.0.0.1:9", None), (&b, None)]);
    assert_eq!(cl.dex_trades(1, 0).await.unwrap(), json!({"trades": []}));
    let (refuse, _) = gateway(Arc::new(|_, _| (400, json!({"error": "unknown market"})))).await;
    let cl = client(&[(&refuse, None), (&b, None)]);
    assert_eq!(
        cl.dex_trades(1, 0).await.unwrap_err().code(),
        "NodeRefused",
        "a refusal is the node's answer, not a failover"
    );
}
