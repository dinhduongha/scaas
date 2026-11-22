// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-rpc plan T10: the crate's scaas-node client against this node's own gateway (`gateway::router`, served on 127.0.0.1:0
//! with a fake chain RPC): every body the client sends reaches the node's handlers and is answered exactly as the same JSON
//! posted in-process (`tower::ServiceExt::oneshot`, as the gateway's own tests post), each refusal decodes to `NodeRefused` with
//! the node's text, and the client's HMAC passes `gwauth`'s check (a one-byte change of the secret fails it).
use std::sync::{Arc, RwLock};

use alloy::primitives::{Address, B256};
use axum::body::Body;
use axum::http::Request;
use scaas_node::config::ChainCfg;
use scaas_node::gateway::{router, AppState, GwChain};
use scaas_rpc::node::{NodeClient, NodeOutcome, UaMetaTxReq};
use scaas_rpc::{Class, Endpoint, EndpointAuth, NodeList, Policy, RpcError, Secret};
use serde_json::{json, Value};
use tokio::sync::mpsc;
use tower::ServiceExt;

const CHAIN: u64 = 7;
const TOKEN: Address = Address::repeat_byte(0xcd);

/// The gateway of chain 7 serving `TOKEN`, its chain RPC a fake that refuses every simulation; its lane receiver kept open.
fn app() -> (axum::Router, mpsc::Receiver<scaas_node::submit::Work>) {
    let cfg = ChainCfg {
        evm_chain_number: CHAIN,
        rpc_urls: vec!["http://127.0.0.1:9".into()],
        chain_uid: Some(B256::repeat_byte(0x24)),
        ..Default::default()
    };
    let tokens = Arc::new(RwLock::new(vec![TOKEN]));
    let (tx, rx) = mpsc::channel(4);
    let gw = GwChain {
        chain: Arc::new(
            scaas_node::chain::Chain::with_signer(
                &cfg,
                alloy::signers::local::PrivateKeySigner::random(),
            )
            .unwrap(),
        ),
        tx,
        tokens: tokens.clone(),
        dex: None,
        breaker: None,
        fee_recipient: None,
        guard: Arc::new(scaas_node::guard::Guard::new(&cfg, tokens).unwrap()),
    };
    (
        router(AppState {
            chains: Arc::new([(CHAIN, gw)].into_iter().collect()),
            ..Default::default()
        }),
        rx,
    )
}

async fn serve(app: axum::Router) -> String {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", l.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
    url
}

fn client(url: &str, auth: Option<EndpointAuth>) -> NodeClient {
    NodeClient::new(
        NodeList::new(
            vec![Endpoint::new(url, Class::Named, None, auth).unwrap()],
            Policy::Failover,
            5_000,
            5_000,
            10_000,
        )
        .unwrap(),
    )
    .unwrap()
}

/// The same JSON posted in-process: `(status, body)`.
async fn oneshot(app: axum::Router, method: &str, uri: &str, body: Option<&Value>) -> (u16, Value) {
    let req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json")
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or_else(Body::empty),
        )
        .unwrap();
    let r = app.oneshot(req).await.unwrap();
    let s = r.status().as_u16();
    (
        s,
        serde_json::from_slice(&axum::body::to_bytes(r.into_body(), 1 << 20).await.unwrap())
            .unwrap_or(Value::Null),
    )
}

/// A refusal as the client decodes it, against the node's own answer to the same JSON.
fn same_refusal(o: NodeOutcome, direct: (u16, Value)) {
    match o {
        NodeOutcome::Refused(RpcError::NodeRefused { status, code, .. }) => {
            assert_eq!(status, direct.0, "{direct:?}");
            // an extractor's rejection (axum's 422 text) has no JSON error: the client reads no code, the node gives none
            assert_eq!(
                code,
                direct.1["error"].as_str().unwrap_or_default(),
                "the node's text"
            );
        }
        NodeOutcome::Unreachable(f) => assert!(direct.0 >= 500, "{f} vs {direct:?}"),
        o => panic!("{o:?} vs {direct:?}"),
    }
}

/// `UAMetaTransfer` on ids, its `auth` a `UASig` (the gateway's own test body, `gateway.rs` `ua_body`'s shape).
fn ua_req(valid_until: &str, struct_: Option<&str>) -> UaMetaTxReq {
    let z = format!("{:#x}", Address::ZERO);
    UaMetaTxReq {
        chain: CHAIN,
        token: format!("{TOKEN:#x}"),
        contract: None,
        struct_: struct_.map(str::to_string),
        m: json!({"from": format!("{:#x}", B256::ZERO), "to": format!("{:#x}", B256::ZERO), "value": "1",
            "entryRef": format!("{:#x}", B256::ZERO), "batch": "0", "nonce": "0", "validUntil": valid_until, "mode": 0,
            "relayer": z, "fee": "0", "feeRecipient": z}),
        auth: json!({"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}),
    }
}

#[tokio::test]
async fn the_clients_bodies_reach_the_nodes_handlers() {
    let (a, _rx) = app();
    let url = serve(a).await;
    let c = client(&url, None);
    // /v1/ua-metatx: expired; struct = call refused by name (HEX_DATA_REFUSED); a live one reaches the simulation (the fake
    // chain is down: the node's 503)
    for req in [
        ua_req("1", None),
        ua_req("4000000000", Some("call")),
        ua_req("4000000000", Some("transfer")),
    ] {
        let direct = oneshot(
            app().0,
            "POST",
            "/v1/ua-metatx",
            Some(&serde_json::to_value(&req).unwrap()),
        )
        .await;
        same_refusal(c.submit_ua_metatx_at(0, &req).await.unwrap(), direct);
    }
    // /v1/op: a named entry on a token this node does not serve, and one with hex args
    let ops = [
        json!({"kind": "UABurn", "token": format!("{:#x}", Address::repeat_byte(0xee)), "args": {}}),
        json!({"kind": "UABurn", "token": format!("{TOKEN:#x}"), "data": "0x1234"}),
    ];
    for op in ops {
        let direct = oneshot(
            app().0,
            "POST",
            "/v1/op",
            Some(&json!({"chain": CHAIN, "op": op})),
        )
        .await;
        same_refusal(c.submit_op_at(0, CHAIN, &op).await.unwrap(), direct);
    }
    // the DEX routes on a chain without a DEX
    let place =
        json!({"chain": CHAIN, "sellToken": format!("{TOKEN:#x}"), "order": {}, "auth": {}});
    let direct = oneshot(app().0, "POST", "/v1/dex/orders", Some(&place)).await;
    same_refusal(c.dex_place_at(0, &place).await.unwrap(), direct);
    let cancel = json!({"chain": CHAIN, "orderHash": format!("{:#x}", B256::ZERO), "auth": {}});
    let direct = oneshot(app().0, "POST", "/v1/dex/cancel", Some(&cancel)).await;
    same_refusal(c.dex_cancel_at(0, &cancel).await.unwrap(), direct);
    let all = json!({"chain": CHAIN, "sellToken": format!("{TOKEN:#x}"), "from": format!("{:#x}", B256::ZERO), "batch": "0",
        "minNonce": "1", "auth": {}});
    let direct = oneshot(app().0, "POST", "/v1/dex/cancel-all", Some(&all)).await;
    same_refusal(c.dex_cancel_all_at(0, &all).await.unwrap(), direct);
    let direct = oneshot(
        app().0,
        "GET",
        &format!("/v1/dex/markets?chain={CHAIN}"),
        None,
    )
    .await;
    match c.dex_markets(CHAIN).await.unwrap_err() {
        RpcError::NodeRefused { status, code, .. } => assert_eq!(
            (status, code.as_str()),
            (direct.0, direct.1["error"].as_str().unwrap_or_default())
        ),
        e => panic!("{e:?}"),
    }
}

/// NODE-GW-02: the client's HMAC passes `gwauth`; a secret one byte off is `bad signature` (401); the control reaches the handler.
#[tokio::test]
async fn the_hmac_signer_passes_gwauth() {
    let secret = b"0123456789abcdef0123".to_vec();
    let auth = scaas_node::gwauth::Auth::from_mode("hmac", Some(secret.clone())).unwrap();
    let url = serve(scaas_node::gwauth::wrap(app().0, auth)).await;
    let req = ua_req("1", None);
    let ok = client(
        &url,
        Some(EndpointAuth::Hmac(Secret::new(
            String::from_utf8(secret.clone()).unwrap(),
        ))),
    );
    let direct = oneshot(
        app().0,
        "POST",
        "/v1/ua-metatx",
        Some(&serde_json::to_value(&req).unwrap()),
    )
    .await;
    same_refusal(ok.submit_ua_metatx_at(0, &req).await.unwrap(), direct);
    let mut wrong = secret;
    wrong[0] ^= 1;
    let bad = client(
        &url,
        Some(EndpointAuth::Hmac(Secret::new(
            String::from_utf8(wrong).unwrap(),
        ))),
    );
    match bad.submit_ua_metatx_at(0, &req).await.unwrap() {
        NodeOutcome::Refused(RpcError::NodeRefused {
            status: 401, code, ..
        }) => assert_eq!(code, "bad signature"),
        o => panic!("{o:?}"),
    }
    let none = client(&url, None);
    assert!(matches!(
        none.submit_ua_metatx_at(0, &req).await.unwrap(),
        NodeOutcome::Refused(RpcError::NodeRefused { status: 401, .. })
    ));
}
