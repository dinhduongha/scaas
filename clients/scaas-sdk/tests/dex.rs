// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T17: `dex` (spec §10) against the fake chain and gateway of `tests/common/fake_chain.rs` (local only). The token-side
//! rows (`UAWrapOrder`, `CancelUAOrder`, `CancelUAWrapOrder`) and `CancelDexOrder` are prepared from the rows of
//! `smartcontracts/vectors/typed/typed_ops.json` with the row's key imported: each operation's id is the row's digest. Every
//! refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, keccak_hex, serve, Fake, Gw, CHAIN_ID};
use scaas_sdk::dex::*;
use scaas_sdk::op::{KeyRef, Source};
use scaas_sdk::vault::{ImportKey, ImportWords, MemoryStore};
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasRows, Limits, ListedDex, ListedToken,
    PositionReader, RuntimeChoice, Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Value};
use std::sync::Arc;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";
/// the vector rows' contracts: a SCaaS token per kind, the trade order's DEX, the outside order's DEX, a wrapper
const TOKEN: &str = "0x5ca00000000000000000000000000000000000a1";
const DEX: &str = "0x5ca00000000000000000000000000000000000b4";
const DEX_OUT: &str = "0x5ca00000000000000000000000000000000000a6";
const OUTSIDE: &str = "0x5ca00000000000000000000000000000000000b5";
const RECEIVE: &str = "0x5ca00000000000000000000000000000000000b3";
const WRAPPER: &str = "0x5ca00000000000000000000000000000000000b2";
const FACTORY: &str = "0x5ca000000000000000000000000000000000f0f0";
const UNLISTED: &str = "0x5ca00000000000000000000000000000000000dd";
const RELAYER: &str = "0x000000000000000000000000000000000000beef";
const KINDS: [(&str, &str); 3] = [
    ("token", "SCaaS MetaToken"),
    ("zether", "SCaaS ZetherToken"),
    ("pqz", "SCaaS PqzToken"),
];

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn load() -> Value {
    let p = format!(
        "{}/../../smartcontracts/vectors/typed/typed_ops.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

fn word(hex: &str) -> String {
    format!("{:0>64}", hex.trim_start_matches("0x"))
}

fn sel(sig: &str) -> String {
    keccak_hex(sig.as_bytes())[..10].to_string()
}

struct T {
    sdk: Arc<Sdk>,
    chain: Fake,
    signer: KeyRef,
    v: Value,
}

/// An SDK over a fake chain: the rows' token contracts by kind, both DEXes listed (the trade order's with its liquidity mark),
/// the rows' wrapper listed, a factory that catalogues the rows' tokens and not `OUTSIDE`; `gateways` gateways, the first
/// `dead` of them refusing connections.
async fn setup(gateways: usize, dead: usize) -> T {
    let v = load();
    let salt = v["ops"]["UABurn"]["domains"]["token"]["domain"]["salt"]
        .as_str()
        .unwrap()
        .to_string();
    let chain = fake();
    {
        let mut c = chain.lock().unwrap();
        for (k, name) in KINDS {
            let at = v["ops"]["CancelUAOrder"]["domains"][k]["domain"]["verifyingContract"]
                .as_str()
                .unwrap();
            c.domains.insert(at.into(), (name.into(), salt.clone()));
            c.answers.push((
                FACTORY.into(),
                format!("{}{}", sel("versionOf(address)"), word(at)),
                format!("0x{}{}", word("1"), word("1")),
            ));
            // the order lane's floor
            c.answers.push((
                at.into(),
                sel("minNonce(bytes32,uint256)"),
                format!("0x{}", word("5")),
            ));
        }
        for d in [DEX, DEX_OUT] {
            c.domains
                .insert(d.into(), ("SCaaS Dex".into(), salt.clone()));
            c.answers
                .push((d.into(), sel("factory()"), format!("0x{}", word(FACTORY))));
            c.answers.push((
                d.into(),
                sel("minNonce(address,uint256)"),
                format!("0x{}", word("9")),
            ));
        }
        c.answers.push((
            FACTORY.into(),
            sel("versionOf(address)"),
            format!("0x{}{}", word("0"), word("0")),
        ));
        c.gw_info["chains"][0]["chain_uid"] = json!(salt);
        c.genesis = salt.clone();
    }
    let url = serve(chain.clone()).await;
    let mut gws = vec![];
    for i in 0..gateways {
        if i < dead {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            gws.push(endpoint(&format!("http://{}", l.local_addr().unwrap())));
        } else {
            gws.push(endpoint(&serve(chain.clone()).await));
        }
    }
    let profile = ChainProfile {
        key: "local".into(),
        family: Family::Evm,
        chain_id: Some(CHAIN_ID),
        chain_uid: salt,
        rpc: vec![endpoint(&url)],
        rpc_policy: scaas_rpc::Policy::Failover,
        gateways: gws,
        registry: None,
        factory: None,
        router: None,
        finality: Finality::Finalized,
        tx_gas_cap: Some(1 << 24),
        tokens: vec![ListedToken {
            address: TOKEN.into(),
            symbol: "VND".into(),
            decimals: 0,
        }],
        gas: GasRows::default(),
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
        dexes: vec![
            ListedDex {
                address: DEX.into(),
                liquidity: true,
                position_readers: vec![PositionReader {
                    manager: "0x5ca00000000000000000000000000000000000c1".into(),
                    reader: "0x5ca00000000000000000000000000000000000c2".into(),
                }],
            },
            ListedDex {
                address: DEX_OUT.into(),
                liquidity: false,
                position_readers: vec![],
            },
        ],
        wrappers: vec![WRAPPER.into()],
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
        clock: Some(Arc::new(|| 1_800_000_000)),
        gas_tables: vec![],
    })
    .await
    .unwrap();
    let seed = sdk
        .vault()
        .import_words(ImportWords {
            label: "main".into(),
            words: sec(REPO.as_bytes()),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap()
        .id;
    let private = alloy::hex::decode(&v["key"]["private"].as_str().unwrap()[2..]).unwrap();
    let k = sdk
        .vault()
        .import_key(ImportKey {
            seed: seed.clone(),
            network: "evm".into(),
            secret: sec(&private),
            vault_passphrase: sec(PASS.as_bytes()),
        })
        .await
        .unwrap();
    T {
        sdk,
        chain,
        signer: KeyRef::Imported {
            seed,
            network: "evm".into(),
            index: k.index,
        },
        v,
    }
}

fn order(t: &T, sell: &str, dex: &str) -> TradeOrder {
    TradeOrder {
        signer: t.signer.clone(),
        chain: "local".into(),
        sell_token: sell.into(),
        dex: dex.into(),
        receive_token: RECEIVE.into(),
        amount: "1000".into(),
        receive_amount: "2000".into(),
        min_fill: "250".into(),
        fee: "3000".into(),
        relayer: RELAYER.into(),
        destination: None,
        flags: 0,
        batch: "7".into(),
        nonce: None,
        valid_until: 1_800_000_300,
    }
}

fn requests(t: &T) -> usize {
    t.chain.lock().unwrap().requests.len()
}

#[tokio::test(flavor = "multi_thread")]
async fn dex_not_on_profile_list_is_refused() {
    let t = setup(1, 0).await;
    let before = requests(&t);
    let r = t
        .sdk
        .dex()
        .prepare_trade_order(order(&t, TOKEN, UNLISTED))
        .await;
    assert_eq!(code(r), "DexNotListed");
    assert_eq!(requests(&t), before, "nothing read before the list check");
    // control: a listed DEX
    let p = t
        .sdk
        .dex()
        .prepare_trade_order(order(&t, TOKEN, DEX))
        .await
        .unwrap();
    assert!(p
        .review()
        .iter()
        .any(|f| f.name == "dex" && f.display == "listed"));
    // the liquidity order and the cancel-all hold the same list; a DEX without its liquidity mark is refused too
    let l = liquidity(&t, UNLISTED);
    assert_eq!(
        code(t.sdk.dex().prepare_liquidity_order(l).await),
        "DexNotListed"
    );
    let l = liquidity(&t, DEX_OUT);
    assert_eq!(
        code(t.sdk.dex().prepare_liquidity_order(l).await),
        "DexNotListed"
    );
    let all = CancelAll {
        signer: t.signer.clone(),
        chain: "local".into(),
        sell_token: TOKEN.into(),
        dex: UNLISTED.into(),
        batch: "7".into(),
        min_nonce: None,
    };
    assert_eq!(code(t.sdk.dex().cancel_all(all).await), "DexNotListed");
}

#[tokio::test(flavor = "multi_thread")]
async fn min_fill_shown_as_signed() {
    let t = setup(1, 0).await;
    let p = t
        .sdk
        .dex()
        .prepare_trade_order(order(&t, TOKEN, DEX))
        .await
        .unwrap();
    let f = p
        .review()
        .into_iter()
        .find(|f| f.name == "minFill")
        .unwrap();
    assert_eq!((f.value.as_str(), f.source), ("250", Source::Signed));
    // the nonce is the lane's floor read on the sell token, `from` the signer's 32-byte id
    let r = p.review();
    let get = |n: &str| r.iter().find(|f| f.name == n).unwrap().value.clone();
    assert_eq!(get("nonce"), "5");
    assert_eq!(get("from"), t.v["key"]["ua"].as_str().unwrap());
}

#[tokio::test(flavor = "multi_thread")]
async fn reads_fail_over_across_the_gateway_list() {
    let t = setup(2, 1).await;
    let dex = t.sdk.dex();
    let m: Value = serde_json::from_str(&dex.markets("local".into()).await.unwrap()).unwrap();
    assert_eq!(
        m["route"],
        json!(format!("/v1/dex/markets?chain={CHAIN_ID}"))
    );
    let d: Value =
        serde_json::from_str(&dex.depth("local".into(), 3, Some(500)).await.unwrap()).unwrap();
    assert_eq!(
        d["route"],
        json!(format!(
            "/v1/dex/depth?chain={CHAIN_ID}&market=3&levels=200"
        ))
    );
    for (r, route) in [
        (dex.trades("local".into(), 3).await, "trades"),
        (dex.ticker("local".into(), 3).await, "ticker"),
    ] {
        let v: Value = serde_json::from_str(&r.unwrap()).unwrap();
        assert!(v["route"]
            .as_str()
            .unwrap()
            .starts_with(&format!("/v1/dex/{route}?")));
    }
    let maker = t.v["key"]["ua"].as_str().unwrap().to_string();
    let o: Value =
        serde_json::from_str(&dex.orders("local".into(), maker.clone()).await.unwrap()).unwrap();
    assert_eq!(
        o["route"],
        json!(format!("/v1/dex/orders?chain={CHAIN_ID}&maker={maker}"))
    );
    // every gateway down: no answer
    let t2 = setup(2, 2).await;
    assert_eq!(
        code(t2.sdk.dex().markets("local".into()).await),
        "EndpointAllFailed"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn place_posts_the_named_order_signed_in_its_form() {
    let t = setup(2, 1).await;
    let dex = t.sdk.dex();
    let p = dex
        .prepare_trade_order(order(&t, TOKEN, DEX))
        .await
        .unwrap();
    let hash = dex.place(p.clone()).await.unwrap();
    assert_eq!(hash, p.id());
    let (body, path) = {
        let c = t.chain.lock().unwrap();
        (
            c.bodies.last().cloned().unwrap(),
            c.gw_paths.last().cloned().unwrap(),
        )
    };
    assert_eq!(path, "/v1/dex/orders");
    let b: Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        (b["chain"].clone(), b["sellToken"].clone()),
        (json!(CHAIN_ID), json!(TOKEN))
    );
    // the node's `WireOrder`: these 13 names, no other; a SCaaS sell token's `auth` (a UASig), no `signature`
    let mut names: Vec<_> = b["order"].as_object().unwrap().keys().cloned().collect();
    names.sort();
    assert_eq!(
        names,
        [
            "amount",
            "batch",
            "destination",
            "dex",
            "fee",
            "flags",
            "from",
            "minFill",
            "nonce",
            "receiveAmount",
            "receiveToken",
            "relayer",
            "validUntil"
        ]
    );
    assert_eq!(b["order"]["minFill"], "250");
    assert!(b["auth"]["signature"].as_str().unwrap().len() > 2 && b.get("signature").is_none());
    // an outside sell token: a `DexOrder` in the DEX's domain, `from` the EVM address, the nonce the DEX's floor, `signature`
    let p = dex
        .prepare_trade_order(order(&t, OUTSIDE, DEX_OUT))
        .await
        .unwrap();
    dex.place(p).await.unwrap();
    let b: Value =
        serde_json::from_str(&t.chain.lock().unwrap().bodies.last().cloned().unwrap()).unwrap();
    assert_eq!(b["order"]["from"], t.v["key"]["address"]);
    assert_eq!(b["order"]["nonce"], "9");
    assert!(b["signature"].as_str().unwrap().len() == 132 && b.get("auth").is_none());
    // a gateway that announces another `chain_uid` is not used: nothing posted
    let p = dex
        .prepare_trade_order(order(&t, TOKEN, DEX))
        .await
        .unwrap();
    let (uid, n) = {
        let mut c = t.chain.lock().unwrap();
        let uid = c.gw_info["chains"][0]["chain_uid"].clone();
        c.gw_info["chains"][0]["chain_uid"] = json!(fake_chain::hash_of(9));
        (uid, c.bodies.len())
    };
    assert_eq!(code(dex.place(p).await), "ProfileMismatch");
    {
        let mut c = t.chain.lock().unwrap();
        assert_eq!(c.bodies.len(), n);
        c.gw_info["chains"][0]["chain_uid"] = uid;
    }
    // a refusing venue: the node's code, final
    t.chain.lock().unwrap().gw = Gw::Refuse;
    let p = dex
        .prepare_trade_order(order(&t, TOKEN, DEX))
        .await
        .unwrap();
    match dex.place(p).await {
        Err(SdkError::Rpc(scaas_rpc::RpcError::NodeRefused { code, .. })) => {
            assert_eq!(code, "DEX_NOT_LISTED")
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cancel_all_posts_the_lane_floor_plus_one() {
    let t = setup(1, 0).await;
    let h = t
        .sdk
        .dex()
        .cancel_all(CancelAll {
            signer: t.signer.clone(),
            chain: "local".into(),
            sell_token: TOKEN.into(),
            dex: DEX.into(),
            batch: "7".into(),
            min_nonce: None,
        })
        .await
        .unwrap();
    let c = t.chain.lock().unwrap();
    assert_eq!(c.gw_paths.last().unwrap(), "/v1/dex/cancel-all");
    let b: Value = serde_json::from_str(c.bodies.last().unwrap()).unwrap();
    assert_eq!(
        (b["minNonce"].clone(), b["batch"].clone()),
        (json!("6"), json!("7"))
    );
    assert_eq!(b["from"], t.v["key"]["ua"]);
    assert!(b["auth"].is_object() && h.len() == 66);
}

/// Each row's struct prepared from its named fields: the operation's id is the row's digest, on every domain kind.
#[tokio::test(flavor = "multi_thread")]
async fn cancel_and_wrap_rows_equal_the_vectors() {
    let t = setup(1, 0).await;
    let dex = t.sdk.dex();
    let s = |v: &Value| v.as_str().map_or_else(|| v.to_string(), String::from);
    let terms = |o: &Value| OrderTerms {
        from: s(&o["from"]),
        receive_token: s(&o["receiveToken"]),
        amount: s(&o["amount"]),
        receive_amount: s(&o["receiveAmount"]),
        min_fill: s(&o["minFill"]),
        fee: s(&o["fee"]),
        relayer: s(&o["relayer"]),
        dex: s(&o["dex"]),
        destination: s(&o["destination"]),
        flags: o["flags"].as_u64().unwrap() as u8,
        batch: s(&o["batch"]),
        nonce: s(&o["nonce"]),
        valid_until: s(&o["validUntil"]),
    };
    let wterms = |o: &Value| WrapOrderTerms {
        from: s(&o["from"]),
        wrapped_token: s(&o["wrappedToken"]),
        amount: s(&o["amount"]),
        min_minted: s(&o["minMinted"]),
        min_fill: s(&o["minFill"]),
        fee: s(&o["fee"]),
        relayer: s(&o["relayer"]),
        destination: s(&o["destination"]),
        flags: o["flags"].as_u64().unwrap() as u8,
        batch: s(&o["batch"]),
        nonce: s(&o["nonce"]),
        valid_until: s(&o["validUntil"]),
    };
    let ops = &t.v["ops"];
    for (k, _) in KINDS {
        let at = |n: &str| s(&ops[n]["domains"][k]["domain"]["verifyingContract"]);
        let digest = |n: &str| s(&ops[n]["domains"][k]["digest"]);
        let m = &ops["CancelUAOrder"]["message"]["order"];
        let p = dex
            .prepare_cancel_order(CancelOrder {
                signer: t.signer.clone(),
                chain: "local".into(),
                sell_token: at("CancelUAOrder"),
                order: terms(m),
            })
            .await
            .unwrap();
        assert_eq!(
            (p.id(), p.entry()),
            (digest("CancelUAOrder"), "mtxCancelOrder".into()),
            "{k}"
        );
        let m = &ops["CancelUAWrapOrder"]["message"]["order"];
        let p = dex
            .prepare_cancel_wrap_order(CancelWrapOrder {
                signer: t.signer.clone(),
                chain: "local".into(),
                token: at("CancelUAWrapOrder"),
                order: wterms(m),
            })
            .await
            .unwrap();
        assert_eq!(p.id(), digest("CancelUAWrapOrder"), "{k}");
        let m = &ops["UAWrapOrder"]["message"];
        let req = WrapOrder {
            signer: t.signer.clone(),
            chain: "local".into(),
            token: at("UAWrapOrder"),
            wrapped_token: s(&m["wrappedToken"]),
            amount: s(&m["amount"]),
            min_minted: s(&m["minMinted"]),
            min_fill: s(&m["minFill"]),
            fee: s(&m["fee"]),
            relayer: s(&m["relayer"]),
            destination: None,
            flags: 0,
            batch: s(&m["batch"]),
            nonce: Some(s(&m["nonce"])),
            valid_until: s(&m["validUntil"]).parse().unwrap(),
        };
        let p = dex.prepare_wrap_order(req.clone()).await.unwrap();
        assert_eq!(
            (p.id(), p.entry()),
            (digest("UAWrapOrder"), "mtxWrapOrder".into()),
            "{k}"
        );
        assert!(p
            .review()
            .iter()
            .any(|f| f.name == "target" && f.value == WRAPPER));
        // a wrapper off the profile's list
        let off = WrapOrder {
            wrapped_token: UNLISTED.into(),
            ..req
        };
        assert_eq!(code(dex.prepare_wrap_order(off).await), "DexNotListed");
    }
    // the outside order's cancel on its DEX (listed), and refused on an unlisted DEX; a UA cancel whatever its DEX
    let m = &ops["CancelDexOrder"]["message"]["order"];
    let req = CancelOrder {
        signer: t.signer.clone(),
        chain: "local".into(),
        sell_token: s(&m["sellToken"]),
        order: terms(&m["order"]),
    };
    let p = dex.prepare_cancel_order(req.clone()).await.unwrap();
    assert_eq!(
        (p.id(), p.entry()),
        (
            s(&ops["CancelDexOrder"]["domains"]["dex"]["digest"]),
            "mtxCancelOrders".into()
        )
    );
    let mut off = req.clone();
    off.order.dex = UNLISTED.into();
    assert_eq!(code(dex.prepare_cancel_order(off).await), "DexNotListed");
    let mut ua = terms(&ops["CancelUAOrder"]["message"]["order"]);
    ua.dex = UNLISTED.into();
    let r = dex
        .prepare_cancel_order(CancelOrder {
            signer: t.signer.clone(),
            chain: "local".into(),
            sell_token: TOKEN.into(),
            order: ua,
        })
        .await;
    assert_eq!(code(r), "Ok");
    // another signer's order: refused
    let mut other = req;
    other.order.from = "0x00000000000000000000000000000000000000aa".into();
    assert_eq!(code(dex.prepare_cancel_order(other).await), "Argument");
}

fn liquidity(t: &T, dex: &str) -> LiquidityOrder {
    LiquidityOrder {
        signer: t.signer.clone(),
        chain: "local".into(),
        dex: dex.into(),
        inputs: vec![LiquidityToken {
            token: TOKEN.into(),
            amount: "1000".into(),
        }],
        outputs: vec![LiquidityToken {
            token: RECEIVE.into(),
            amount: "0".into(),
        }],
        position_manager: None,
        position_reader: None,
        position_in: "0".into(),
        position_pool: None,
        tick_lower: 0,
        tick_upper: 0,
        min_liquidity: "0".into(),
        recipient: None,
        fee: "3000".into(),
        relayer: RELAYER.into(),
        flags: 0,
        batch: "1".into(),
        nonce: "1".into(),
        valid_until: 1_800_000_300,
        extra_tokens: vec![],
        partial: false,
    }
}

/// M16 (review 2026-11-20): a `bls12381-multi` group signs by its members' aggregate only: as an order's or a lane's signer
/// it is refused at prepare (`Argument`), before any read; the same requests by the EVM key are the controls.
#[tokio::test(flavor = "multi_thread")]
async fn a_group_is_no_order_signer() {
    let t = setup(1, 0).await;
    let KeyRef::Imported { seed, .. } = t.signer.clone() else {
        panic!()
    };
    let group = KeyRef::BlsMulti {
        seed,
        account: 0,
        index: 0,
        key_data: "0x00".into(),
    };
    let dex = t.sdk.dex();
    let n = t.chain.lock().unwrap().requests.len();
    let mut o = order(&t, TOKEN, DEX);
    o.signer = group.clone();
    assert_eq!(code(dex.prepare_trade_order(o).await), "Argument");
    let mut l = liquidity(&t, DEX);
    l.signer = group.clone();
    assert_eq!(code(dex.prepare_liquidity_order(l).await), "Argument");
    assert_eq!(t.chain.lock().unwrap().requests.len(), n, "nothing read");
    assert_eq!(
        code(dex.prepare_trade_order(order(&t, TOKEN, DEX)).await),
        "Ok"
    );
    assert_eq!(
        code(dex.prepare_liquidity_order(liquidity(&t, DEX)).await),
        "Ok"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn liquidity_order_signs_under_its_check() {
    let t = setup(1, 0).await;
    let dex = t.sdk.dex();
    let p = dex
        .prepare_liquidity_order(liquidity(&t, DEX))
        .await
        .unwrap();
    let s = dex.sign_order(p.clone()).await.unwrap();
    assert_eq!(s.order_hash, p.id());
    let auth: Value = serde_json::from_str(&s.signature).unwrap();
    // T9 (review 2026-11-20): the native key's signature recovers its address over the order's own digest (a native key
    // signs a `trade` struct's digest bare), not over another one
    let addr: [u8; 20] = alloy::hex::decode(&t.v["key"]["address"].as_str().unwrap()[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let sig = alloy::hex::decode(&auth["signature"].as_str().unwrap()[2..]).unwrap();
    let d: [u8; 32] = alloy::hex::decode(&p.id()[2..])
        .unwrap()
        .try_into()
        .unwrap();
    assert!(
        scaas_ua::verify::native_ecdsa(&addr, &d, &sig),
        "over the order's digest"
    );
    let mut other = d;
    other[0] ^= 1;
    assert!(
        !scaas_ua::verify::native_ecdsa(&addr, &other, &sig),
        "control: another digest"
    );
    // not placed by the venue route: its job is the planner's
    assert_eq!(code(dex.place(p).await), "Argument");
}
