// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T10 / T11: the scaas-node client against fake gateways on 127.0.0.1:0 (CLI-RPC-10, F8). The node's own conformance test
//! is `scaas-node/tests/rpc_client.rs`.
use scaas_rpc::node::{NodeClient, NodeOutcome, UaMetaTxReq, BODY_MAX, OP_BODY_MAX};
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

/// NODE-GW-08: `/v1/op` takes a body of `OP_BODY_MAX` bytes and refuses one byte more unsent; `/v1/ua-metatx` keeps
/// `BODY_MAX` (64 KiB). Each bound with its positive control.
#[tokio::test]
async fn each_route_refuses_a_body_above_its_cap_unsent() {
    let (g, seen) = gateway(queued()).await;
    let c = client(&[(&g, None)]);
    // `{"chain":1,"op":` + the op + `}`: the op's own JSON is the body less 17 bytes
    let sized = |len: usize| {
        let mut o = op();
        o["pad"] = json!("");
        let base = serde_json::to_string(&o).unwrap().len() + 17;
        o["pad"] = json!("x".repeat(len - base));
        o
    };
    assert!(matches!(
        c.submit_op_at(0, 1, &sized(OP_BODY_MAX + 1)).await,
        Err(RpcError::BodyTooLarge {
            cap: 1_310_720,
            len: 1_310_721
        })
    ));
    assert!(seen.lock().unwrap().is_empty(), "nothing sent");
    assert!(
        c.submit_op_at(0, 1, &sized(OP_BODY_MAX)).await.is_ok(),
        "control: at the cap"
    );
    let req = |pad: usize| UaMetaTxReq {
        chain: 7622,
        token: "0xaa".into(),
        contract: None,
        struct_: Some("transfer".into()),
        m: json!({"from": "0x01", "to": "0x02"}),
        auth: json!({"signature": "0x01", "pad": "x".repeat(pad)}),
    };
    let n = serde_json::to_vec(&req(0)).unwrap().len();
    assert!(matches!(
        c.submit_ua_metatx_at(0, &req(BODY_MAX + 1 - n)).await,
        Err(RpcError::BodyTooLarge { cap: 65536, .. })
    ));
    assert!(
        c.submit_ua_metatx_at(0, &req(BODY_MAX - n)).await.is_ok(),
        "control: at the cap"
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

/// T13 S4 (CLI-RPC-11): a gateway's `intent_id` is endpoint text (cut to 256 bytes, control characters removed); its
/// `revert_data` is kept only as hex of at most 4 KiB (else none). Controls: `queued_202_and_duplicate_200`,
/// `revert_data_is_kept`.
#[tokio::test]
async fn a_gateways_intent_id_and_revert_data_are_bounded() {
    let (q, _) = gateway(Arc::new(|_, _| {
        (
            202,
            json!({"status": "queued", "intent_id": format!("i\u{1b}[2J{}", "z".repeat(1 << 16))}),
        )
    }))
    .await;
    match client(&[(&q, None)])
        .submit_op_at(0, 1, &op())
        .await
        .unwrap()
    {
        NodeOutcome::Queued {
            intent_id: Some(id),
            ..
        } => {
            assert!(
                id.len() <= 256 && id.starts_with("i[2Jzzz"),
                "{} bytes",
                id.len()
            )
        }
        o => panic!("{o:?}"),
    }
    for bad in ["0xzz".to_string(), format!("0x{}", "ab".repeat(4097))] {
        let (g, _) = gateway(Arc::new(move |_, _| {
            (
                400,
                json!({"code": "SIM_REVERTED", "revert_data": bad.clone()}),
            )
        }))
        .await;
        match client(&[(&g, None)])
            .submit_op_at(0, 1, &op())
            .await
            .unwrap()
        {
            NodeOutcome::Refused(RpcError::NodeRefused { revert_data, .. }) => {
                assert_eq!(revert_data, None)
            }
            o => panic!("{o:?}"),
        }
    }
    let (g, _) = gateway(Arc::new(|_, _| {
        (
            400,
            json!({"code": "SIM_REVERTED", "revert_data": format!("0x{}", "ab".repeat(4096))}),
        )
    }))
    .await;
    match client(&[(&g, None)])
        .submit_op_at(0, 1, &op())
        .await
        .unwrap()
    {
        NodeOutcome::Refused(RpcError::NodeRefused { revert_data, .. }) => {
            assert_eq!(revert_data.map(|d| d.len()), Some(2 + 8192))
        }
        o => panic!("{o:?}"),
    }
}

/// NODE-GW-02's HMAC: `X-Scaas-Timestamp`, a 16-byte base64url `X-Scaas-Nonce`, `X-Scaas-Signature = hex(HMAC-SHA256(secret, ts
/// "." nonce "." METHOD " " path?query "\n" body))`, recomputed here; another body gives another signature.
#[tokio::test]
async fn hmac_headers_follow_node_gw_02() {
    use hmac::{Hmac, KeyInit, Mac};
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

/// T13 S14: a route goes under the gateway's path prefix with the gateway's query kept, so two gateways under one host with
/// different prefixes reach their own routes; a submit route's 2xx without the job's `status` is no answer of the node's.
/// Controls: a duplicate's 200 with its stored state is `Queued`; `queued_202_and_duplicate_200`.
#[tokio::test]
async fn a_route_keeps_the_gateways_prefix_and_a_submit_2xx_needs_the_status() {
    let (g, seen) = gateway(queued()).await;
    let (a, b) = (format!("{g}/a/"), format!("{g}/b?k=1"));
    let c = client(&[(&a, None), (&b, None)]);
    c.submit_op_at(0, 1, &op()).await.unwrap();
    c.submit_op_at(1, 1, &op()).await.unwrap();
    let paths: Vec<String> = seen
        .lock()
        .unwrap()
        .iter()
        .map(|s| s.path.clone())
        .collect();
    assert_eq!(paths, ["/a/v1/op", "/b/v1/op?k=1"]);
    let (r, seen) = gateway(Arc::new(|_, _| (200, json!({"markets": []})))).await;
    client(&[(&format!("{r}/p?k=1"), None)])
        .dex_markets(7)
        .await
        .unwrap();
    assert_eq!(
        seen.lock().unwrap()[0].path,
        "/p/v1/dex/markets?k=1&chain=7"
    );
    let (h, _) = gateway(Arc::new(|_, _| (200, json!({"ok": true})))).await;
    let o = client(&[(&h, None)])
        .submit_op_at(0, 1, &op())
        .await
        .unwrap();
    assert!(matches!(o, NodeOutcome::Unreachable(_)), "{o:?}");
    let (d, _) = gateway(Arc::new(|_, _| (200, json!({"status": "mined"})))).await;
    let o = client(&[(&d, None)])
        .submit_op_at(0, 1, &op())
        .await
        .unwrap();
    assert!(
        matches!(o, NodeOutcome::Queued { status: 200, .. }),
        "control: {o:?}"
    );
}

// ---------------------------------------------------------------- the PQZ verifier client (owner 2026-11-19, C1)

fn verifiers(urls: &[&str], policy: Policy) -> scaas_rpc::node::VerifierClient {
    let e = urls
        .iter()
        .map(|u| Endpoint::new(u, Class::Named, None, None).unwrap())
        .collect();
    scaas_rpc::node::VerifierClient::new(NodeList::new(e, policy, 5_000, 5_000, 10_000).unwrap())
        .unwrap()
}

fn verdict(epoch: u64) -> Answer {
    Arc::new(move |path, _| match path {
        "/v1/pqz-verdict" => (
            200,
            json!({"pqzVerdict": {"pqzVerifierEpoch": epoch, "validUntil": "99"}, "pqzVerdictSig": {"signature": format!("0x{epoch:02x}")}}),
        ),
        "/v1/pqz-verdict/probe" => (200, json!({"serves": true, "epoch": epoch})),
        _ => (404, json!({"error": "UNKNOWN_ROUTE"})),
    })
}

#[tokio::test]
async fn verifier_routes_bodies_and_failover() {
    // the first verifier unreachable (503 BUSY), the second answers: failover takes the second, the body byte for byte
    let (busy, seen_busy) = gateway(Arc::new(|_, _| (503, json!({"error": "BUSY"})))).await;
    let (good, seen) = gateway(verdict(7)).await;
    let c = verifiers(&[&busy, &good], Policy::Failover);
    let req = json!({"token": "0x00000000000000000000000000000000000000aa", "entry": "UAPqzTransferSingle", "proof": "0x01"});
    let v = c.verdict(&req).await.unwrap();
    assert_eq!(v["pqzVerdict"]["pqzVerifierEpoch"], 7);
    let first = seen.lock().unwrap()[0].clone();
    assert_eq!(first.path, "/v1/pqz-verdict");
    assert_eq!(first.body, serde_json::to_vec(&req).unwrap());
    assert_eq!(seen_busy.lock().unwrap().len(), 1);
    assert_eq!(c.probe(&req).await.unwrap()["serves"], true);
    assert_eq!(seen.lock().unwrap()[1].path, "/v1/pqz-verdict/probe");
    // not an object: Argument, nothing sent
    assert_eq!(c.verdict(&json!([1])).await.unwrap_err().code(), "Argument");
    assert_eq!(seen.lock().unwrap().len(), 2);
}

#[tokio::test]
async fn a_verifier_refusal_is_final_under_failover() {
    // a 4xx is the verifier's named refusal: never asked of the next one
    let (no, _) = gateway(Arc::new(|_, _| {
        (422, json!({"error": "PROOF_INVALID", "detail": "x"}))
    }))
    .await;
    let (good, seen) = gateway(verdict(1)).await;
    let c = verifiers(&[&no, &good], Policy::Failover);
    let e = c.verdict(&json!({"a": 1})).await.unwrap_err();
    assert!(
        matches!(&e, RpcError::NodeRefused { code, .. } if code == "PROOF_INVALID"),
        "{e:?}"
    );
    assert!(seen.lock().unwrap().is_empty());
    // every one unreachable: EndpointAllFailed
    let (down, _) = gateway(Arc::new(|_, _| (500, json!({})))).await;
    let c = verifiers(&[&down], Policy::Failover);
    assert_eq!(
        c.verdict(&json!({"a": 1})).await.unwrap_err().code(),
        "EndpointAllFailed"
    );
}

#[tokio::test]
async fn verifier_strict_majority_compares_the_verdict() {
    // three verifiers of one key: two equal verdicts (their signatures differ) are a majority
    let (a, _) = gateway(verdict(3)).await;
    let (b, _) = gateway(Arc::new(|path, _| {
        if path == "/v1/pqz-verdict" {
            (200, json!({"pqzVerdict": {"pqzVerifierEpoch": 3, "validUntil": "99"}, "pqzVerdictSig": {"signature": "0xff"}}))
        } else {
            (200, json!({"serves": true, "epoch": 3}))
        }
    }))
    .await;
    let (c3, _) = gateway(verdict(4)).await;
    let c = verifiers(&[&a, &b, &c3], Policy::StrictMajority);
    assert_eq!(
        c.verdict(&json!({"a": 1})).await.unwrap()["pqzVerdict"]["pqzVerifierEpoch"],
        3
    );
    assert_eq!(c.probe(&json!({"a": 1})).await.unwrap()["epoch"], 3);
    // F14: two verifiers whose clocks differ set another `validUntil`: still a majority; M3: the group's median answer
    let (d, _) = gateway(Arc::new(|path, _| {
        if path == "/v1/pqz-verdict" {
            (200, json!({"pqzVerdict": {"pqzVerifierEpoch": 3, "validUntil": "98"}, "pqzVerdictSig": {"signature": "0xee"}}))
        } else {
            (200, json!({"serves": true, "epoch": 3}))
        }
    }))
    .await;
    let c = verifiers(&[&d, &a], Policy::StrictMajority);
    let v = c.verdict(&json!({"a": 1})).await.unwrap();
    assert_eq!(
        v["pqzVerdict"]["validUntil"], "99",
        "of two the later (the median of an even group is its upper)"
    );
    // M3: one replica whose clock is behind (a verdict already expired) does not decide: the median of three agreeing
    let (late, _) = gateway(Arc::new(|path, _| {
        if path == "/v1/pqz-verdict" {
            (200, json!({"pqzVerdict": {"pqzVerifierEpoch": 3, "validUntil": "10"}, "pqzVerdictSig": {"signature": "0xdd"}}))
        } else {
            (200, json!({"serves": true, "epoch": 3}))
        }
    }))
    .await;
    let (b3, _) = gateway(verdict(3)).await;
    for order in [[&late, &d, &b3], [&d, &late, &b3], [&b3, &d, &late]] {
        let v = verifiers(&order.map(String::as_str), Policy::StrictMajority)
            .verdict(&json!({"a": 1}))
            .await
            .unwrap();
        assert_eq!(
            v["pqzVerdict"]["validUntil"], "98",
            "the median, whatever the order"
        );
        assert_eq!(v["pqzVerdictSig"]["signature"], "0xee");
    }
    // two of three disagree and the third refuses: no majority
    let (no, _) = gateway(Arc::new(|_, _| (422, json!({"error": "PROOF_INVALID"})))).await;
    let c = verifiers(&[&a, &c3, &no], Policy::StrictMajority);
    let e = c.verdict(&json!({"a": 1})).await.unwrap_err();
    assert!(
        matches!(
            e,
            RpcError::EndpointNoMajority {
                n: 3,
                need: 2,
                largest: 1,
                ..
            }
        ),
        "{e:?}"
    );
}

#[tokio::test]
async fn a_verifier_redirect_is_not_followed_and_answers_are_bounded() {
    let (r, _) = gateway(Arc::new(|_, _| (302, json!({})))).await;
    let c = verifiers(&[&r], Policy::Failover);
    assert_eq!(
        c.verdict(&json!({"a": 1})).await.unwrap_err().code(),
        "EndpointAllFailed"
    );
    let big = "x".repeat(scaas_rpc::node::ANSWER_MAX + 1);
    let (g, _) = gateway(Arc::new(move |_, _| (200, json!({"pqzVerdict": big})))).await;
    let c = verifiers(&[&g], Policy::Failover);
    assert_eq!(
        c.verdict(&json!({"a": 1})).await.unwrap_err().code(),
        "EndpointAllFailed"
    );
    // a body above the cap: refused, nothing sent
    let (g, seen) = gateway(verdict(1)).await;
    let c = verifiers(&[&g], Policy::Failover);
    let huge = json!({"proof": "0".repeat(scaas_rpc::node::VERDICT_BODY_MAX)});
    assert_eq!(c.verdict(&huge).await.unwrap_err().code(), "BodyTooLarge");
    assert!(seen.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------- `POST /v1/ops` (plan T28)

fn family_op() -> Value {
    json!({"family": "sui", "contract": "0x2", "from": "0x3", "op_kind": "pay", "payload": "0x01", "signature": "0x02",
        "public_key": null, "auth_kind": "seed", "valid_until": 99})
}

/// Plan T28: `submit_ops` sends `{chain, op}` to `/v1/ops` byte for byte, the same bytes to every selected gateway, merged as
/// `submit_op`'s: one `queued` is queued, a refusal and an unreachable gateway kept apart, never counted as accepting; an op that
/// is not an object is `Argument`, nothing sent.
#[tokio::test]
async fn submit_ops_sends_the_same_bytes_and_merges() {
    let (a, sa) = gateway(Arc::new(|_, _| {
        (
            400,
            json!({"error": "TOKEN_NOT_SERVED", "code": "TOKEN_NOT_SERVED"}),
        )
    }))
    .await;
    let (b, sb) = gateway(Arc::new(|_, _| {
        (202, json!({"status": "queued", "intent_id": "0x77"}))
    }))
    .await;
    let cl = client(&[(&a, None), (&b, None), ("http://127.0.0.1:9", None)]);
    let o = family_op();
    match cl.submit_ops("sui:testnet", &o, Fanout::All).await.unwrap() {
        SubmitOutcome::Queued {
            by,
            refused,
            unreachable,
        } => {
            assert_eq!(by, vec![1]);
            assert_eq!(refused.iter().map(|r| r.0).collect::<Vec<_>>(), vec![0]);
            assert_eq!(unreachable.iter().map(|r| r.0).collect::<Vec<_>>(), vec![2]);
        }
        x => panic!("{x:?}"),
    }
    let want = serde_json::to_vec(&json!({"chain": "sui:testnet", "op": o})).unwrap();
    for s in [sa, sb] {
        let s = s.lock().unwrap()[0].clone();
        assert_eq!((s.path.as_str(), &s.body), ("/v1/ops", &want));
    }
    // only unreachable gateways: not queued, not final
    let o2 = client(&[("http://127.0.0.1:9", None)])
        .submit_ops("sui:testnet", &family_op(), Fanout::All)
        .await
        .unwrap();
    assert!(matches!(o2, SubmitOutcome::NotQueued { .. }), "{o2:?}");
    assert!(!o2.is_terminal());
    let (g, seen) = gateway(queued()).await;
    assert_eq!(
        client(&[(&g, None)])
            .submit_ops_at(0, "sui:testnet", &json!([1]))
            .await
            .unwrap_err()
            .code(),
        "Argument"
    );
    assert!(seen.lock().unwrap().is_empty(), "nothing sent");
    // a 2xx without the job's status is no node answer
    let (h, _) = gateway(Arc::new(|_, _| (200, json!({"ok": true})))).await;
    let x = client(&[(&h, None)])
        .submit_ops_at(0, "sui:testnet", &family_op())
        .await
        .unwrap();
    assert!(matches!(x, NodeOutcome::Unreachable(_)), "{x:?}");
}
