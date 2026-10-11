//! R54 (GA 2.1#8, spec T15): mọi decoder nhận dữ liệu không tin cậy — body gateway, payload job từ
//! Odoo, mã hoá meta-tx — không bao giờ panic; dữ liệu xấu là `Err`.
use scaas_node::dex::WireOrder;
use scaas_node::metatx::Mtx;
use scaas_node::odoo::Job;
use scaas_node::submit::work_from_job;
use proptest::prelude::*;
use serde_json::{json, Value};

fn any_json() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(|n| json!(n)),
        ".{0,80}".prop_map(Value::String),
        "0x[0-9a-fA-F]{0,140}".prop_map(Value::String),
    ];
    leaf.prop_recursive(3, 32, 8, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..6).prop_map(Value::Array),
            prop::collection::btree_map("[a-zA-Z_]{1,12}", inner, 0..12)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

/// Either struct's fields (`MetaTransaction` has `data`, `MetaTransfer` has `to`/`value`/`entryRef`), sometimes with a
/// stray key.
fn metatx_fields() -> impl Strategy<Value = Value> {
    let s = || prop_oneof!["0x[0-9a-fA-F]{0,70}", "[0-9]{0,90}", ".{0,20}"];
    (s(), s(), s(), s(), s(), s(), s(), s(), any::<u32>(), s(), s(), s()).prop_map(
        |(from, to, value, data, batch, nonce, vu, relayer, mode, fee, fr, extra)| {
            let shape = extra.len();
            let mut v = json!({"from": from, "batch": batch, "nonce": nonce, "validUntil": vu, "mode": mode,
                               "relayer": relayer, "fee": fee, "feeRecipient": fr});
            if shape & 1 == 0 {
                v["data"] = json!(data);
            } else {
                v["to"] = json!(to);
                v["value"] = json!(value);
                v["entryRef"] = json!(extra.clone());
            }
            if shape & 6 == 6 {
                v["x"] = json!(extra);
            }
            v
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2000, ..ProptestConfig::default() })]

    #[test]
    fn wire_metatx_never_panics(v in metatx_fields(), kind in prop_oneof![Just("call".to_string()),
                                Just("transfer".to_string()), ".{0,8}"]) {
        let _ = Mtx::from_wire(Some(&kind), &v);
        let _ = Mtx::from_wire(None, &v);
    }

    #[test]
    fn job_payloads_never_panic(v in any_json(), m in metatx_fields(), sig in ".{0,300}", kind in ".{0,8}") {
        let _ = serde_json::from_value::<Job>(v.clone());
        let shaped = json!({"id": 1, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "signature": sig,
                            "struct": kind, "metatx": m, "call": v});
        if let Ok(job) = serde_json::from_value::<Job>(shaped) {
            let _ = work_from_job(&job);
        }
    }

    /// A DEX order (NODE-DEX-15) from a gateway body or the client's book: any strings ⇒ `Err`, never a panic.
    #[test]
    fn dex_wire_order_never_panics(f in prop::collection::vec(prop_oneof!["0x[0-9a-fA-F]{0,70}", "[0-9]{0,90}", ".{0,20}"], 12),
                                   flags in any::<u8>()) {
        let w = WireOrder { from: f[0].clone(), receive_token: f[1].clone(), amount: f[2].clone(), receive_amount: f[3].clone(),
            min_fill: f[4].clone(), fee: f[5].clone(), relayer: f[6].clone(), dex: f[7].clone(), destination: f[8].clone(),
            flags, batch: f[9].clone(), nonce: f[10].clone(), valid_until: f[11].clone() };
        let _ = w.to_sol();
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 300, ..ProptestConfig::default() })]

    /// Body gateway bất kỳ (JSON hợp lệ hay không) ⇒ 4xx, không bao giờ panic/500.
    #[test]
    fn gateway_bodies_never_panic(v in any_json(), m in metatx_fields(), raw in ".{0,200}") {
        use axum::body::Body;
        use axum::http::Request;
        use tower::ServiceExt;
        let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
        let app = scaas_node::gateway::router(scaas_node::gateway::AppState::default());
        let shaped = json!({"chain": 1, "token": "0xcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd", "m": m, "signature": "0x00",
                            "struct": "call"});
        for path in ["/v1/metatx", "/v1/dex/orders"] {
            for body in [v.to_string(), shaped.to_string(), raw.clone()] {
                let req = Request::builder().method("POST").uri(path)
                    .header("content-type", "application/json").body(Body::from(body)).unwrap();
                let st = rt.block_on(app.clone().oneshot(req)).unwrap().status();
                prop_assert!(st.is_client_error(), "{path}: {st}");
            }
        }
    }
}
