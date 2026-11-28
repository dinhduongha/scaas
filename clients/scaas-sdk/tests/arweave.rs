// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! chains-arweave plan T20 (feature `arweave`, with or without the EVM part): `upload_file`, `keep_up` and `fetch_file` against
//! in-process fakes of gateways, bundlers and the node's payer route (NODE-SPN-05's shape), with a test clock. The items are
//! clientkeys' rows (smartcontracts/vectors/arweave/upload.json's `sealForArweave`, their objects rebuilt here), so the set
//! without `app-core` needs no key. With `app-core`, `seal_for_arweave` and `open_file` through an app core, and (with
//! `vectors`) the counting signer spy. Each refusal has its control beside it.
#![cfg(feature = "arweave")]
use scaas_sdk::arweave::{
    ArweaveConfig, ArweaveFiles, KeptUpload, Paid, Payer, UploadState, REPOST_AFTER,
    SELF_PAY_NOTICE,
};
use scaas_sdk::SdkError;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};

#[path = "common/fake_http.rs"]
mod fake_http;

/// A request as the fakes record it: method, path, header lines (lower case), body.
type Req = (String, String, String, Vec<u8>);
type Seen = Arc<Mutex<Vec<Req>>>;
type Handler = Arc<dyn Fn(&Req) -> (u16, Vec<u8>) + Send + Sync>;

/// `common/fake_http.rs`'s endpoint, each request kept whole (its headers and body bytes too).
async fn serve(h: Handler) -> (String, Seen) {
    let seen: Seen = Default::default();
    let s2 = seen.clone();
    let (url, _) =
        fake_http::serve_head(Arc::new(move |m: &str, p: &str, head: &str, b: &[u8]| {
            let r = (m.to_string(), p.to_string(), head.to_string(), b.to_vec());
            let out = h(&r);
            s2.lock().unwrap().push(r);
            out
        }))
        .await;
    (url, seen)
}

fn vec(p: &str) -> Value {
    let f = format!(
        "{}/../../smartcontracts/vectors/{p}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(f).unwrap()).unwrap()
}
fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim_start_matches("0x");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
/// clientkeys' `rnd(name, n)`.
fn rnd(name: &str, n: usize) -> Vec<u8> {
    let mut out = vec![];
    let mut i = 0;
    while out.len() < n {
        out.extend(scaas_ua::keccak256(
            format!("scaas/arweave/vectors/{name}/{i}").as_bytes(),
        ));
        i += 1;
    }
    out.truncate(n);
    out
}

/// A `sealForArweave` row's item (header ‖ object), the object rebuilt under the row's file key, and its fields.
struct Row {
    item: Vec<u8>,
    object: Vec<u8>,
    id: String,
    url: String,
    size: u64,
    ct: [u8; 32],
}
fn row(name: &str) -> Row {
    let v = vec("arweave/upload.json");
    let r = v["sealForArweave"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .unwrap()
        .clone();
    let size = r["size"].as_u64().unwrap();
    let file = rnd(r["fileSeed"].as_str().unwrap(), size as usize);
    let b = scaas_ua::file::bucket(size, scaas_ua::file::CAP).unwrap() as usize;
    let mut frame = vec![0u8; b];
    frame[..8].copy_from_slice(&size.to_be_bytes());
    frame[8..8 + file.len()].copy_from_slice(&file);
    let key: [u8; 32] = unhex(r["fileKey"].as_str().unwrap()).try_into().unwrap();
    let object = scaas_ua::wallet::aead_seal(
        scaas_ua::wallet::Alg::Aes256Gcm,
        &key,
        &[0; 12],
        &[],
        &frame,
    )
    .unwrap();
    let item = [unhex(r["header"].as_str().unwrap()), object.clone()].concat();
    Row {
        item,
        object,
        id: r["id"].as_str().unwrap().into(),
        url: r["url"].as_str().unwrap().into(),
        size,
        ct: unhex(r["ctSha256"].as_str().unwrap()).try_into().unwrap(),
    }
}

/// A bundler accepting with a receipt for `id`, or answering `status`.
async fn bundler(status: u16, id: String) -> (String, Seen) {
    serve(Arc::new(move |_| match status {
        200 => (
            200,
            json!({"id": id, "owner": "o"}).to_string().into_bytes(),
        ),
        s => (s, b"{}".to_vec()),
    }))
    .await
}

/// A gateway serving `object` under `id`, the item in `block`, at tip `tip`.
async fn gateway(id: String, object: Vec<u8>, block: Option<u64>, tip: u64) -> (String, Seen) {
    serve(Arc::new(move |r| match r.1.as_str() {
        "/info" => (
            200,
            json!({"network": "arweave.N.1", "height": tip})
                .to_string()
                .into_bytes(),
        ),
        p if p == format!("/raw/{id}") => (200, object.clone()),
        "/graphql" => {
            let b = block.map_or(Value::Null, |h| json!({"height": h}));
            (
                200,
                json!({"data": {"transactions": {"edges": [{"node": {"id": id, "block": b}}]}}})
                    .to_string()
                    .into_bytes(),
            )
        }
        _ => (404, vec![]),
    }))
    .await
}

fn cfg(gws: &[String], bundlers: &[String], payer: Payer) -> ArweaveConfig {
    let entries = |u: &[String], class: &str| {
        Value::Array(
            u.iter()
                .map(|u| json!({"url": u, "class": class}))
                .collect(),
        )
    };
    let gws: Vec<String> = if gws.is_empty() {
        vec![fake_http::DOWN.into()]
    } else {
        gws.to_vec()
    };
    let mut c: ArweaveConfig = serde_json::from_value(json!({
        "gateways": {"rpc": entries(&gws, "default")},
        "operators": (0..gws.len()).map(|i| format!("op{i}")).collect::<Vec<_>>(),
        "bundlers": {"rpc": entries(bundlers, "default")},
        "max_object": (1u64 << 17) + 16,
    }))
    .unwrap();
    c.payer = payer;
    c
}
fn files(c: &ArweaveConfig) -> ArweaveFiles {
    ArweaveFiles::new(c, |k| (k == "PAYER_CRED").then(|| "cred-1".to_string())).unwrap()
}
fn header<'a>(r: &'a Req, k: &str) -> Option<&'a str> {
    r.2.lines()
        .find_map(|l| l.strip_prefix(&format!("{k}:")).map(str::trim))
}

#[tokio::test]
async fn the_smallest_bucket_goes_on_the_free_tier_without_x_paid_by() {
    let r = row("type 2");
    let (b, seen) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[], &[b], Payer::None));
    let o = f.upload_file(r.item.clone()).await.unwrap();
    assert_eq!(
        (o.id.as_str(), o.url.as_str(), &o.paid),
        (r.id.as_str(), r.url.as_str(), &Paid::FreeTier)
    );
    let req = &seen.lock().unwrap()[0];
    assert_eq!(
        (req.0.as_str(), req.1.as_str(), &req.3),
        ("POST", "/tx", &r.item)
    );
    assert!(header(req, "x-paid-by").is_none());
}

#[tokio::test]
async fn only_an_item_ua_rs_built_is_posted() {
    let r = row("type 2");
    let (b, seen) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[], &[b], Payer::None));
    let mut bad = r.item.clone();
    *bad.last_mut().unwrap() ^= 1;
    assert!(
        matches!(f.upload_file(bad).await, Err(SdkError::ArweaveItem)),
        "a tampered kept item"
    );
    // valid ANS-104 over the same object with a tag or a target (upload.json's notC9 rows): not C9, refused
    for n in vec("arweave/upload.json")["notC9"].as_array().unwrap() {
        let item = [unhex(n["header"].as_str().unwrap()), r.object.clone()].concat();
        assert!(
            scaas_ua::arweave::DataItem::parse(item.clone()).is_ok(),
            "the row is a valid item"
        );
        assert!(
            matches!(f.upload_file(item).await, Err(SdkError::ArweaveItem)),
            "{} (not C9)",
            n["name"]
        );
    }
    assert!(seen.lock().unwrap().is_empty(), "nothing posted");
    assert!(f.upload_file(r.item).await.is_ok(), "control");
}

#[tokio::test]
async fn a_larger_bucket_without_a_payer_is_payer_unavailable() {
    let r = row("type 2, the 2^17 bucket");
    let (b, seen) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[], std::slice::from_ref(&b), Payer::None));
    assert!(matches!(
        f.upload_file(r.item.clone()).await,
        Err(SdkError::PayerUnavailable)
    ));
    assert!(seen.lock().unwrap().is_empty());
    // the operator's route off (404): no payer either
    let (node, _) = serve(Arc::new(|_| (404, vec![]))).await;
    let p = Payer::Operator {
        node: serde_json::from_value(json!({"rpc_urls": [node]})).unwrap(),
    };
    let f = files(&cfg(&[], &[b], p));
    assert!(matches!(
        f.upload_file(r.item).await,
        Err(SdkError::PayerUnavailable)
    ));
}

fn operator(node: &str) -> Payer {
    Payer::Operator {
        node: serde_json::from_value(json!({"rpc": [{"url": node, "api_key_env": "PAYER_CRED"}]}))
            .unwrap(),
    }
}
async fn payer_node() -> (String, Seen) {
    serve(Arc::new(|_| {
        (
            200,
            json!({"paidBy": "OPERATOR-payer", "expiresAt": 1_800_000_000u64})
                .to_string()
                .into_bytes(),
        )
    }))
    .await
}

#[tokio::test]
async fn the_operator_path_sends_named_fields_and_x_paid_by_to_that_bundler() {
    let r = row("type 2, the 2^17 bucket");
    let (node, node_seen) = payer_node().await;
    let (b, b_seen) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[], &[b], operator(&node)));
    let o = f.upload_file(r.item.clone()).await.unwrap();
    assert_eq!(
        o.paid,
        Paid::Operator {
            paid_by: "OPERATOR-payer".into()
        }
    );
    assert_eq!(o.notice, None);
    let q = &node_seen.lock().unwrap()[0];
    assert_eq!(
        header(q, "authorization"),
        Some("bearer cred-1"),
        "the gateway credential from its env var"
    );
    let body: Value = serde_json::from_slice(&q.3).unwrap();
    let keys: Vec<&String> = body.as_object().unwrap().keys().collect();
    assert_eq!(
        keys,
        ["address", "bucket", "signatureType"],
        "no UA, no signature, no file bytes"
    );
    assert_eq!(
        (body["bucket"].as_u64(), body["signatureType"].as_u64()),
        (Some(1 << 17), Some(2))
    );
    assert_eq!(
        header(&b_seen.lock().unwrap()[0], "x-paid-by"),
        Some("operator-payer"),
        "(header lines lower-cased by the fake)"
    );
}

#[tokio::test]
async fn self_pay_signs_nothing_more_warns_and_surfaces_402() {
    let r = row("type 2, the 2^17 bucket");
    let (b, seen) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(
        &[],
        &[b],
        Payer::SelfPay {
            paid_by: Some("USER-wallet".into()),
        },
    ));
    let o = f.upload_file(r.item.clone()).await.unwrap();
    assert_eq!((o.paid, o.notice), (Paid::SelfPay, Some(SELF_PAY_NOTICE)));
    assert_eq!(
        header(&seen.lock().unwrap()[0], "x-paid-by"),
        Some("user-wallet")
    );
    assert_eq!(
        &seen.lock().unwrap()[0].3,
        &r.item,
        "the uploader's own item, the same bytes"
    );
    let (p, _) = bundler(402, r.id.clone()).await;
    let f = files(&cfg(&[], &[p], Payer::SelfPay { paid_by: None }));
    assert!(matches!(
        f.upload_file(r.item).await,
        Err(SdkError::PaymentRequired)
    ));
}

#[tokio::test]
async fn kept_until_settled_reposted_at_24h_72h_7d_then_unsettled() {
    let r = row("type 2");
    let (b, b_seen) = bundler(200, r.id.clone()).await;
    // two gateways of two operators that never see the item in a block
    let (g1, _) = gateway(r.id.clone(), r.object.clone(), None, 500).await;
    let (g2, _) = gateway(r.id.clone(), r.object.clone(), None, 500).await;
    let f = files(&cfg(&[g1, g2], &[b], Payer::None));
    f.upload_file(r.item.clone()).await.unwrap();
    let t0 = 1_000_000;
    let mut k = KeptUpload {
        item: r.item.clone(),
        sent_at: t0,
        reposts: 0,
    };
    let mut states = vec![];
    for t in [
        t0 + 1,
        t0 + REPOST_AFTER[0] - 1,
        t0 + REPOST_AFTER[0],
        t0 + REPOST_AFTER[1],
        t0 + REPOST_AFTER[2],
        t0 + 99 * 86_400,
    ] {
        states.push(f.keep_up(&mut k, t).await.unwrap());
    }
    use UploadState::*;
    assert_eq!(
        states,
        [Pending, Pending, Reposted, Reposted, Unsettled, Unsettled]
    );
    let posts = b_seen.lock().unwrap();
    assert_eq!(posts.len(), 4, "the send and three re-posts, no more");
    assert!(
        posts.iter().all(|p| p.3 == r.item),
        "the same bytes every time: never re-signed, never another key"
    );
    assert_eq!(k.item, r.item, "the bytes kept");
}

#[tokio::test]
async fn a_settled_item_is_settled_only_by_two_operators_at_depth() {
    let r = row("type 2");
    let (b, _) = bundler(200, r.id.clone()).await;
    let (g1, _) = gateway(r.id.clone(), r.object.clone(), Some(100), 200).await;
    let (g2, _) = gateway(r.id.clone(), r.object.clone(), Some(100), 200).await;
    let f = files(&cfg(
        &[g1.clone(), g2],
        std::slice::from_ref(&b),
        Payer::None,
    ));
    let mut k = KeptUpload {
        item: r.item.clone(),
        sent_at: 0,
        reposts: 0,
    };
    assert_eq!(f.keep_up(&mut k, 10).await.unwrap(), UploadState::Settled);
    // the first gateway's word alone is not settlement: the item stays kept
    let one = files(&cfg(&[g1], &[b], Payer::None));
    assert_eq!(one.keep_up(&mut k, 10).await.unwrap(), UploadState::Pending);
}

#[tokio::test]
async fn a_repost_refused_for_payment_asks_the_payer_again_for_the_same_address() {
    let r = row("type 2, the 2^17 bucket");
    let (node, node_seen) = payer_node().await;
    let n = Arc::new(Mutex::new(0usize));
    let n2 = n.clone();
    let id = r.id.clone();
    // the send accepted, the first re-post 402 (the approval expired), the next accepted
    let (b, _) = serve(Arc::new(move |_| {
        let mut c = n2.lock().unwrap();
        *c += 1;
        if *c == 2 {
            (402, b"{}".to_vec())
        } else {
            (200, json!({"id": id}).to_string().into_bytes())
        }
    }))
    .await;
    let (g1, _) = gateway(r.id.clone(), r.object.clone(), None, 500).await;
    let (g2, _) = gateway(r.id.clone(), r.object.clone(), None, 500).await;
    let f = files(&cfg(&[g1, g2], &[b], operator(&node)));
    f.upload_file(r.item.clone()).await.unwrap();
    let mut k = KeptUpload {
        item: r.item.clone(),
        sent_at: 0,
        reposts: 0,
    };
    assert_eq!(
        f.keep_up(&mut k, REPOST_AFTER[0]).await.unwrap(),
        UploadState::Reposted
    );
    assert_eq!(
        f.keep_up(&mut k, REPOST_AFTER[1]).await.unwrap(),
        UploadState::Reposted
    );
    let asks = node_seen.lock().unwrap();
    assert_eq!(asks.len(), 3, "an approval per post");
    let addr = |i: usize| serde_json::from_slice::<Value>(&asks[i].3).unwrap()["address"].clone();
    assert!(
        addr(0) == addr(1) && addr(1) == addr(2),
        "the same upload address"
    );
}

#[tokio::test]
async fn fetch_refuses_a_bad_url_and_a_size_above_the_cap_before_any_request() {
    let r = row("type 2");
    let (g, seen) = gateway(r.id.clone(), r.object.clone(), None, 1).await;
    let (b, _) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[g], &[b], Payer::None));
    for u in [
        &r.url[..r.url.len() - 1],
        "AR://x",
        "https://a.example/x",
        &format!("{}/x", r.url),
    ] {
        assert!(
            matches!(f.fetch_file(u, r.size, r.ct).await, Err(SdkError::Argument)),
            "{u}"
        );
    }
    assert!(matches!(
        f.fetch_file(&r.url, scaas_ua::file::CAP, r.ct).await,
        Err(SdkError::FileTooLarge)
    ));
    assert!(seen.lock().unwrap().is_empty(), "no request");
    assert_eq!(
        f.fetch_file(&r.url, r.size, r.ct).await.unwrap(),
        r.object,
        "control"
    );
}

#[tokio::test]
async fn bytes_that_fail_ct_sha256_are_file_hash_mismatch() {
    let r = row("type 2");
    let mut wrong = r.object.clone();
    wrong[0] ^= 1;
    let (g, _) = gateway(r.id.clone(), wrong, None, 1).await;
    let (b, _) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[g], &[b], Payer::None));
    assert!(matches!(
        f.fetch_file(&r.url, r.size, r.ct).await,
        Err(SdkError::FileHashMismatch)
    ));
}

/// C14: a PqVault item naming an object is written only after one gateway read passed: until a gateway serves it, the read
/// fails and the app core writes nothing; then it passes.
#[tokio::test]
async fn a_vault_item_waits_for_one_gateway_read() {
    let r = row("type 2");
    let served = Arc::new(Mutex::new(false));
    let (s2, id, obj) = (served.clone(), r.id.clone(), r.object.clone());
    let (g, _) = serve(Arc::new(move |q| match q.1.as_str() {
        "/info" => (
            200,
            json!({"network": "arweave.N.1", "height": 1})
                .to_string()
                .into_bytes(),
        ),
        p if p == format!("/raw/{id}") && *s2.lock().unwrap() => (200, obj.clone()),
        _ => (404, vec![]),
    }))
    .await;
    let (b, _) = bundler(200, r.id.clone()).await;
    let f = files(&cfg(&[g], &[b], Payer::None));
    assert!(
        f.fetch_file(&r.url, r.size, r.ct).await.is_err(),
        "not yet readable: no vault item"
    );
    *served.lock().unwrap() = true;
    assert!(
        f.fetch_file(&r.url, r.size, r.ct).await.is_ok(),
        "one gateway read passed"
    );
}

/// With `app-core`: `seal_for_arweave` gives the `ar://` url before any upload; the fetched object opens by `open_file`, and
/// its plaintext is refused for another `size` or `sha256`; with `vectors` a counting spy sees one signature per item and none
/// on a re-post.
#[cfg(feature = "app-core")]
mod app {
    use super::*;
    use scaas_sdk::app_core::{AppCore, AppDesc};
    use scaas_sdk::op::KeyRef;

    use scaas_sdk::vault::{ImportWords, MemoryStore};
    use scaas_sdk::{
        ChainProfile, EndpointConfig, Family, Finality, Limits, RuntimeChoice, Sdk, SdkConfig,
    };
    use scaas_ua::wallet::SecretBytes;

    fn sec(s: &str) -> Arc<SecretBytes> {
        Arc::new(
            SecretBytes::from_zeroizing(zeroize::Zeroizing::new(s.as_bytes().to_vec())).unwrap(),
        )
    }

    /// An SDK with one seed (tests/app_core.rs's local profile: no chain is read) and an app core with an `app_id`.
    async fn core() -> (Arc<AppCore>, KeyRef) {
        core_labelled("scaas/arweave-test/v1/").await
    }

    /// An app core under its own label: two cores of one process never share one (`AppLabelRefused`).
    async fn core_labelled(label: &str) -> (Arc<AppCore>, KeyRef) {
        let profile = ChainProfile {
            key: "local".into(),
            family: Family::Evm,
            chain_id: Some(31337),
            chain_uid: format!("0x{}", "60".repeat(32)),
            rpc: vec![EndpointConfig {
                url: fake_http::DOWN.into(),
                class: scaas_rpc::Class::Named,
                label: None,
                auth: None,
            }],
            rpc_policy: scaas_rpc::Policy::Failover,
            gateways: vec![],
            registry: Some("0x5ca00000000000000000000000000000000000a1".into()),
            factory: None,
            router: None,
            finality: Finality::Finalized,
            tx_gas_cap: None,
            gas: Default::default(),
            max_valid_secs: None,
            verifiers: vec![],
            verifier_policy: scaas_rpc::Policy::Failover,
            gas_opt_in: vec![],
            dexes: vec![],
            wrappers: vec![],
            tokens: vec![],
            l1_fee: None,
            pinned_reads: true,
            disabled_kinds: vec![],
            family_params: None,
        };
        let sdk = Sdk::open(SdkConfig {
            profiles: vec![profile],
            store: MemoryStore::new(),
            authenticator: None,
            rp_id: None,
            runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
            limits: Limits::default(),
            clock: None,
            gas_tables: vec![],
        })
        .await
        .unwrap();
        let seed = sdk
            .vault()
            .import_words(ImportWords {
                label: "main".into(),
                words: sec("bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better"),
                vault_passphrase: sec("river-otter-7 ünï"),
            })
            .await
            .unwrap()
            .id;
        let app = AppCore::new(
            sdk,
            AppDesc {
                app_id: Some(format!("0x{}", "ab".repeat(32))),
                name: "arweave test".into(),
                class: None,
                labels: vec![label.into()],
            },
        )
        .unwrap();
        (
            app,
            KeyRef::Ua {
                seed,
                kind: 0x0108,
                account: 0,
                index: 0,
            },
        )
    }

    /// pqvault-files review F-1: a file `open_file` could not hand back (above `SECRET_MAX`, 16 MiB) is refused, even under a
    /// profile whose largest request would take it; one byte less is sealed.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_file_above_what_open_file_returns_is_refused() {
        let (app, account) = core_labelled("scaas/arweave-test-cap/v1/").await;
        let max = scaas_ua::wallet::SECRET_MAX;
        assert!(matches!(
            app.seal_for_arweave(account.clone(), vec![7; max + 1], 2, (1 << 26) + 16),
            Err(SdkError::FileTooLarge)
        ));
        let KeyRef::Ua { seed, .. } = &account else {
            unreachable!()
        };
        assert!(matches!(
            app.seal_file(seed, vec![7; max + 1]),
            Err(SdkError::FileTooLarge)
        ));
        let a = app.seal_file(seed, vec![7; max]).unwrap();
        assert_eq!(a.size, max as u64);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn seal_upload_fetch_open() {
        let (app, account) = core().await;
        let before = spy();
        let a = app
            .seal_for_arweave(account, b"an attachment".to_vec(), 2, (1 << 17) + 16)
            .unwrap();
        assert_eq!(spy(), before.map(|n| n + 1), "one signature per item");
        assert!(a.url.starts_with("ar://"));
        let (b, b_seen) = bundler(200, a.url[5..].to_string()).await;
        assert!(
            b_seen.lock().unwrap().is_empty(),
            "the url is known before any upload"
        );
        let object = a.item[a.item.len() - (1 << 16) - 16..].to_vec();
        let (g1, _) = gateway(a.url[5..].to_string(), object.clone(), None, 500).await;
        let (g2, _) = gateway(a.url[5..].to_string(), object.clone(), None, 500).await;
        let f = files(&cfg(&[g1, g2], &[b], Payer::None));
        f.upload_file(a.item.clone()).await.unwrap();
        let mut k = KeptUpload {
            item: a.item.clone(),
            sent_at: 0,
            reposts: 0,
        };
        assert_eq!(
            f.keep_up(&mut k, REPOST_AFTER[0]).await.unwrap(),
            UploadState::Reposted
        );
        assert_eq!(spy(), before.map(|n| n + 1), "no signature on a re-post");
        let ct: [u8; 32] = a.ct_sha256.clone().try_into().unwrap();
        let got = f.fetch_file(&a.url, a.size, ct).await.unwrap();
        let pt = app
            .open_file(
                a.key.clone(),
                got.clone(),
                a.size,
                a.sha256.clone(),
                a.ct_sha256.clone(),
            )
            .unwrap();
        pt.with(|b| assert_eq!(b, b"an attachment"));
        assert!(app
            .open_file(
                a.key.clone(),
                got.clone(),
                a.size + 1,
                a.sha256.clone(),
                a.ct_sha256.clone()
            )
            .is_err());
        assert!(app
            .open_file(a.key, got, a.size, vec![0; 32], a.ct_sha256.clone())
            .is_err());
    }

    /// The process count of `UploadSign`'s signatures (feature `vectors`), else none.
    fn spy() -> Option<u64> {
        #[cfg(feature = "vectors")]
        return Some(scaas_ua::wallet::vectors_sign_count());
        #[cfg(not(feature = "vectors"))]
        None
    }
}
