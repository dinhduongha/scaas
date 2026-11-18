// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Plan T12: the `wallet` operations (spec §8.3, §21) against the fake chain and gateway of `tests/common/fake_chain.rs` (local
//! only). Every wallet `(struct, kind)` pair of `smartcontracts/vectors/typed/typed_ops.json` is prepared from the row's named
//! fields with the row's key imported (`vault.import_key`), so the subject is the row's native id: the review lists every
//! signed field with the row's value, the operation's id is the row's digest, and the signed calldata the SDK simulates at
//! submit is the row's `calldata` (an RFC 6979 signature: the row's). Every refusal beside its control.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::panic
)]

#[path = "common/fake_chain.rs"]
mod fake_chain;

use fake_chain::{fake, serve, Fake, CHAIN_ID};
use scaas_sdk::op::{KeyRef, Prepared, Source, SubmitPath};
use scaas_sdk::vault::{ImportKey, ImportWords, MemoryStore};
use scaas_sdk::wallet::*;
use scaas_sdk::{
    ChainProfile, EndpointConfig, Family, Finality, GasRow, Limits, ListedToken, RuntimeChoice,
    Sdk, SdkConfig, SdkError,
};
use scaas_ua::wallet::SecretBytes;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;
use zeroize::Zeroizing;

const PASS: &str = "river-otter-7 ünï";
const REPO: &str = "bench hurt jump file august wise shallow faculty impulse spring exact slush thunder author capable act festival slice deposit sauce coconut afford frown better";

fn code<T>(r: Result<T, SdkError>) -> &'static str {
    r.map_or_else(|e| e.code(), |_| "Ok")
}

fn root(p: &str) -> String {
    format!("{}/../../{p}", env!("CARGO_MANIFEST_DIR"))
}

fn load(p: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(root(p)).unwrap()).unwrap()
}

fn s(v: &Value) -> String {
    v.as_str().map_or_else(|| v.to_string(), String::from)
}

fn sec(b: &[u8]) -> Arc<SecretBytes> {
    Arc::new(SecretBytes::from_zeroizing(Zeroizing::new(b.to_vec())).unwrap())
}

const KINDS: [(&str, &str); 4] = [
    ("token", "SCaaS MetaToken"),
    ("zether", "SCaaS ZetherToken"),
    ("pqz", "SCaaS PqzToken"),
    ("wallet", "SCaaS MandateWallet"),
];

struct T {
    sdk: Arc<Sdk>,
    chain: Fake,
    /// the vector key, imported
    signer: KeyRef,
    payer: KeyRef,
}

/// An SDK over a fake chain whose contracts are the vector rows' (domain names by kind, the vectors' salt as `chain_uid`), the
/// vector key imported into a seed.
async fn setup(gateways: usize) -> T {
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let d = &v["ops"]["UABurn"]["domains"]["token"]["domain"];
    let salt = d["salt"].as_str().unwrap().to_string();
    let chain = fake();
    {
        let mut c = chain.lock().unwrap();
        for (k, name) in KINDS {
            let at = v["ops"]["UACancelNonce"]["domains"][k]["domain"]["verifyingContract"]
                .as_str()
                .unwrap();
            c.domains.insert(at.into(), (name.into(), salt.clone()));
        }
        c.gw_info["chains"][0]["chain_uid"] = json!(salt);
        c.genesis = salt.clone();
    }
    let url = serve(chain.clone()).await;
    let mut gws = vec![];
    for _ in 0..gateways {
        gws.push(endpoint(&serve(chain.clone()).await));
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
            address: "0x5ca00000000000000000000000000000000000a1".into(),
            symbol: "VND".into(),
            decimals: 0,
        }],
        gas: gas_rows(),
    };
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: MemoryStore::new(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
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
            seed: seed.clone(),
            network: "evm".into(),
            index: k.index,
        },
        payer: KeyRef::Native {
            seed,
            network: "evm".into(),
            index: 0,
        },
    }
}

fn endpoint(url: &str) -> EndpointConfig {
    EndpointConfig {
        url: url.into(),
        class: scaas_rpc::Class::Named,
        label: None,
        auth: None,
    }
}

fn envelope(m: &Value) -> Envelope {
    Envelope {
        // a struct without an envelope of its own (a payment nested, a relay fee) reads none of these
        valid_until: s(&m["validUntil"]).parse().unwrap_or_default(),
        mode: m["mode"].as_u64().unwrap_or_default() as u32,
        relayer: Some(s(&m["relayer"])),
        fee: s(&m["fee"]),
        fee_recipient: Some(s(&m["feeRecipient"])),
    }
}

fn pay_meta(x: &Value) -> PayMeta {
    assert_eq!(x["schema"], 0, "the vector rows' meta has no body");
    PayMeta {
        salt: Some(s(&x["salt"])),
        pay_no: Some(s(&x["payNo"])),
        save: x["save"].as_bool().unwrap(),
        body: PayBody::None,
    }
}

/// The row `name` on `kind` prepared through its public entry point from the row's named fields.
async fn prepare_row(
    t: &T,
    name: &str,
    d: &Value,
    m: &Value,
    opaque: bool,
) -> Result<Arc<Prepared>, SdkError> {
    let w = t.sdk.wallet();
    let (signer, chain, contract) = (
        t.signer.clone(),
        "local".to_string(),
        s(&d["domain"]["verifyingContract"]),
    );
    let (batch, env) = (s(&m["batch"]), envelope(m));
    let f = |k: &str| s(&m[k]);
    match name {
        "UACancelNonce" => {
            w.prepare_cancel_nonce(CancelNonce {
                signer,
                chain,
                contract,
                batch,
                lane: f("lane"),
                envelope: env,
            })
            .await
        }
        "UABurn" => {
            w.prepare_burn(Burn {
                signer,
                chain,
                contract,
                batch,
                amount: f("amount"),
                envelope: env,
            })
            .await
        }
        "Wrap" => {
            w.prepare_wrap(Wrap {
                signer,
                chain,
                contract,
                batch,
                amount: f("amount"),
                envelope: env,
            })
            .await
        }
        "WrapLeg" => {
            w.prepare_wrap_leg(WrapLeg {
                signer,
                chain,
                contract,
                batch,
                underlying: f("underlying"),
                amount: f("amount"),
                envelope: env,
            })
            .await
        }
        "UAUnwrap" => {
            w.prepare_unwrap(Unwrap {
                signer,
                chain,
                contract,
                batch,
                wrapped: f("wrapped"),
                recipient: f("recipient"),
                min_out: f("minOut"),
                envelope: env,
            })
            .await
        }
        "UAUnwrapLeg" => {
            w.prepare_unwrap_leg(UnwrapLeg {
                signer,
                chain,
                contract,
                batch,
                underlying: f("underlying"),
                wrapped: f("wrapped"),
                recipient: f("recipient"),
                min_out: f("minOut"),
                envelope: env,
            })
            .await
        }
        "AddReserve" => {
            w.prepare_add_reserve(AddReserve {
                signer,
                chain,
                contract,
                batch,
                underlying: f("underlying"),
                amount: f("amount"),
                envelope: env,
            })
            .await
        }
        "WrapToUA" => {
            w.prepare_wrap_to_ua(WrapToUa {
                signer,
                chain,
                contract,
                batch,
                underlying: f("underlying"),
                amount: f("amount"),
                to: f("to"),
                envelope: env,
            })
            .await
        }
        "UAUnwrapToUA" => {
            w.prepare_unwrap_to_ua(UnwrapToUa {
                signer,
                chain,
                contract,
                batch,
                underlying: f("underlying"),
                wrapped: f("wrapped"),
                to: f("to"),
                min_out: f("minOut"),
                envelope: env,
            })
            .await
        }
        "UASetMandate" => {
            w.prepare_set_mandate(SetMandate {
                signer,
                chain,
                contract,
                batch,
                token: f("token"),
                delegate: f("delegate"),
                max_per_payment: f("maxPerPayment"),
                max_per_period: f("maxPerPeriod"),
                period_seconds: f("periodSeconds"),
                expiry: f("expiry"),
                envelope: env,
            })
            .await
        }
        "UASetPayee" => {
            w.prepare_set_payee(SetPayee {
                signer,
                chain,
                contract,
                batch,
                token: f("token"),
                payee: f("payee"),
                allowed: m["allowed"].as_bool().unwrap(),
                envelope: env,
            })
            .await
        }
        "UARevokeMandate" => {
            w.prepare_revoke_mandate(RevokeMandate {
                signer,
                chain,
                contract,
                batch,
                token: f("token"),
                envelope: env,
            })
            .await
        }
        "UADelegateRevoke" => {
            w.prepare_delegate_revoke(DelegateRevoke {
                signer,
                chain,
                contract,
                batch,
                token: f("token"),
                epoch: f("epoch"),
                envelope: env,
            })
            .await
        }
        "UAPayUnderMandate" => {
            w.prepare_pay_under_mandate(PayUnderMandate {
                signer,
                chain,
                wallet: contract,
                token: f("token"),
                payee: f("payee"),
                amount: f("amount"),
                epoch: f("epoch"),
                batch,
                meta: pay_meta(&d["extra"]["meta"]),
                envelope: env,
            })
            .await
        }
        "UAExecute" => {
            #[cfg(feature = "opaque-calls")]
            let allow = opaque.then(AllowOpaqueCall::new);
            #[cfg(not(feature = "opaque-calls"))]
            let allow = {
                let _ = opaque;
                None
            };
            w.prepare_execute(Execute {
                signer,
                chain,
                wallet: contract,
                batch,
                envelope: env,
                call: ExecuteCall::Opaque {
                    target: f("target"),
                    value: f("value"),
                    data: f("data"),
                    allow,
                },
            })
            .await
        }
        "UARelayFee" => {
            w.prepare_relay_fee(RelayFee {
                signer,
                chain,
                token: contract,
                target: f("target"),
                call_data: s(&d["relayedCall"]),
                payee: f("payee"),
                value: f("value"),
                batch,
                valid_until: f("validUntil").parse().unwrap(),
                relayer: f("relayer"),
            })
            .await
        }
        "UAPayWithTax" => {
            let p = &m["payment"];
            w.prepare_pay_with_tax(PayWithTax {
                signer,
                chain,
                token: contract,
                to: s(&p["to"]),
                value: s(&p["value"]),
                meta: pay_meta(&d["extra"]["meta"]),
                tax_mode: m["taxMode"].as_u64().unwrap() as u8,
                tax: f("tax"),
                envelope: envelope(p),
            })
            .await
        }
        "UAPayeeFee" => {
            let p = &m["payment"];
            w.prepare_payee_fee(PayeeFee {
                signer,
                chain,
                token: contract,
                payment: Payment {
                    from: s(&p["from"]),
                    to: s(&p["to"]),
                    value: s(&p["value"]),
                    valid_until: s(&p["validUntil"]).parse().unwrap(),
                    relayer: s(&p["relayer"]),
                },
                meta: pay_meta(&d["extra"]["meta"]),
                payer_auth: PayerAuth {
                    key_data: "0x".into(),
                    signature: s(&d["extra"]["payerSig"]),
                },
                fee: f("fee"),
                fee_recipient: f("feeRecipient"),
                valid_until: f("validUntil").parse().unwrap(),
            })
            .await
        }
        other => panic!("{other}: not a wallet row"),
    }
}

/// Every leaf of `m` by path, values as text, hex lower case.
fn leaves(prefix: &str, m: &Value, out: &mut Vec<(String, String)>) {
    match m {
        Value::Object(o) => {
            for (k, v) in o {
                let p = if prefix.is_empty() {
                    k.clone()
                } else {
                    format!("{prefix}.{k}")
                };
                leaves(&p, v, out);
            }
        }
        v => out.push((prefix.into(), s(v).to_ascii_lowercase())),
    }
}

/// The bodies the fake got, JSON-RPC and gateway, that carry `hex` (no `0x`).
/// A gas row for every entry and domain kind (the transfer on ids too), signed by a native EVM key (the tests' imported key),
/// on a fresh lane or not (owner 2026-11-19, ruling B: the profile's own rows).
fn gas_rows() -> Vec<GasRow> {
    let mut keys: Vec<(String, String)> = scaas_ua::wallet::entries::entry_rows()
        .into_iter()
        .flat_map(|r| {
            r.kinds
                .iter()
                .map(move |k| (r.entry.to_string(), k.to_string()))
        })
        .collect();
    keys.extend(
        ["token", "zether", "pqz"].map(|k| ("mtxExecuteTransfer".to_string(), k.to_string())),
    );
    keys.into_iter()
        .flat_map(|(entry, kind)| {
            [true, false].map(|fresh| GasRow {
                entry: entry.clone(),
                kind: kind.clone(),
                signer: 0,
                fresh,
                gas: 100_000,
            })
        })
        .collect()
}

/// `carried`, waited for (≤ 5 s): the simulation and the send run after `submit` returns (ruling A).
async fn carried_soon(t: &T, hex: &str) -> bool {
    for _ in 0..100 {
        if carried(t, hex) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

fn carried(t: &T, hex: &str) -> bool {
    let c = t.chain.lock().unwrap();
    c.requests
        .iter()
        .chain(c.bodies.iter())
        .any(|b| b.to_ascii_lowercase().contains(hex))
}

/// The wallet rows of spec §21: on `token`, `zether`, `pqz` and on `wallet`.
const WALLET_ROWS: [&str; 18] = [
    "UACancelNonce",
    "UABurn",
    "Wrap",
    "WrapLeg",
    "UAUnwrap",
    "UAUnwrapLeg",
    "AddReserve",
    "WrapToUA",
    "UAUnwrapToUA",
    "UAPayeeFee",
    "UARelayFee",
    "UAPayWithTax",
    "UASetMandate",
    "UASetPayee",
    "UARevokeMandate",
    "UAPayUnderMandate",
    "UADelegateRevoke",
    "UAExecute",
];

#[tokio::test(flavor = "multi_thread")]
async fn every_wallet_pair_is_its_vector() {
    let t = setup(0).await;
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let mut walked = 0;
    for (name, o) in v["ops"].as_object().unwrap() {
        if !WALLET_ROWS.contains(&name.as_str()) {
            continue;
        }
        for (kind, _) in KINDS {
            let Some(d) = o["domains"].get(kind) else {
                continue;
            };
            let m = &o["message"];
            walked += 1;
            if name == "UAExecute" && !cfg!(feature = "opaque-calls") {
                // the row's data is a filler, no decoded call: refused without the marker (the decoded half: below)
                assert_eq!(
                    code(prepare_row(&t, name, d, m, true).await),
                    "OpaqueCallRefused"
                );
                continue;
            }
            let p = prepare_row(&t, name, d, m, true)
                .await
                .unwrap_or_else(|e| panic!("{name} on {kind}: {e:?}"));
            assert_eq!(
                p.id(),
                d["digest"].as_str().unwrap(),
                "{name} on {kind}: the digest"
            );
            assert_eq!(
                p.entry(),
                d["abi"].as_str().unwrap().split('(').next().unwrap(),
                "{name} on {kind}"
            );
            // the review: every signed field of the struct with the row's value
            let r = p.review();
            let mut want = vec![];
            leaves("", m, &mut want);
            for (n, val) in want {
                let f = r
                    .iter()
                    .find(|f| f.name == n)
                    .unwrap_or_else(|| panic!("{name} on {kind}: {n} not reviewed"));
                assert_eq!(f.source, Source::Signed, "{name} on {kind}: {n}");
                let got = f.value.to_ascii_lowercase();
                // an unbound relayer / fee recipient is 0 as signed (the vectors' messages are canonical)
                assert_eq!(got, val, "{name} on {kind}: {n}");
            }
            // sign once at submit: the simulated calldata is the row's (the row's RFC 6979 signature in it)
            let q = t
                .sdk
                .op()
                .quote(
                    p.clone(),
                    SubmitPath::SelfRelay {
                        payer: t.payer.clone(),
                    },
                )
                .await
                .unwrap();
            let sig = &d["signature"].as_str().unwrap()[2..];
            assert!(
                !carried(&t, sig),
                "{name} on {kind}: no signature at quote time"
            );
            t.sdk
                .op()
                .submit(p, q)
                .await
                .unwrap_or_else(|e| panic!("{name} on {kind}: {e:?}"));
            assert!(
                carried_soon(&t, &d["calldata"].as_str().unwrap()[2..]).await,
                "{name} on {kind}: the row's calldata"
            );
        }
    }
    assert_eq!(walked, 43, "the wallet pairs of spec §21");
}

#[tokio::test(flavor = "multi_thread")]
async fn unbound_relayer_is_zero() {
    let t = setup(0).await;
    let burn = |mode: u32, who: &str| Burn {
        signer: t.signer.clone(),
        chain: "local".into(),
        contract: "0x5ca00000000000000000000000000000000000a1".into(),
        batch: "7".into(),
        amount: "5".into(),
        envelope: Envelope {
            valid_until: 1_800_000_300,
            mode,
            relayer: Some(who.into()),
            fee: "0".into(),
            fee_recipient: Some(who.into()),
        },
    };
    let zero = "0x0000000000000000000000000000000000000000";
    let beef = "0x00000000000000000000000000000000deadbeef";
    let a = t.sdk.wallet().prepare_burn(burn(0, beef)).await.unwrap();
    let b = t.sdk.wallet().prepare_burn(burn(0, zero)).await.unwrap();
    assert_eq!(
        a.id(),
        b.id(),
        "an unbound relayer and fee recipient are 0 in what is signed"
    );
    for n in ["relayer", "feeRecipient"] {
        assert_eq!(
            a.review().iter().find(|f| f.name == n).unwrap().value,
            zero,
            "{n} reviewed as signed"
        );
    }
    // control: mode 3 binds both
    let c = t.sdk.wallet().prepare_burn(burn(3, beef)).await.unwrap();
    assert_ne!(c.id(), b.id());
    assert_eq!(
        c.review()
            .iter()
            .find(|f| f.name == "relayer")
            .unwrap()
            .value,
        beef
    );
}

/// A `paymeta.json` row's meta in the request's named form.
fn meta_of(r: &Value) -> PayMeta {
    let b = alloy::hex::decode(&r["body"].as_str().unwrap()[2..]).unwrap();
    let w = |i: usize| b[32 * i..32 * (i + 1)].to_vec();
    let num = |x: &[u8]| x.iter().fold(0u64, |a, y| a << 8 | u64::from(*y));
    let body = match r["schema"].as_u64().unwrap() {
        0 => PayBody::None,
        1 => PayBody::Note {
            note: String::from_utf8(b.clone()).unwrap(),
        },
        2 => {
            let len = num(&w(2)) as usize;
            PayBody::CreditorRef {
                creditor_ref: String::from_utf8(b[96..96 + len].to_vec()).unwrap(),
                due_date: num(&w(1)),
            }
        }
        3 => PayBody::BoundCall {
            chain_id: num(&w(0)).to_string(),
            target: format!("0x{}", alloy::hex::encode(w(1))),
            call_hash: format!("0x{}", alloy::hex::encode(w(2))),
        },
        _ => PayBody::Ciphertext {
            ciphertext: s(&r["body"]),
        },
    };
    PayMeta {
        salt: Some(s(&r["salt"])),
        pay_no: Some(s(&r["payNo"])),
        save: r["save"].as_bool().unwrap(),
        body,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn pay_with_paymeta_v3() {
    let t = setup(1).await;
    let rows = load("smartcontracts/vectors/metatx/paymeta.json");
    let pay = |meta: PayMeta| Pay {
        signer: t.signer.clone(),
        chain: "local".into(),
        token: "0x5ca00000000000000000000000000000000000a1".into(),
        to: format!("0x{}", "0b".repeat(32)),
        value: "250".into(),
        meta,
        envelope: Envelope {
            valid_until: 1_800_000_300,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    for r in rows.as_array().unwrap() {
        let name = r["name"].as_str().unwrap();
        let res = t.sdk.wallet().prepare_pay(pay(meta_of(r))).await;
        if !r["accepted"].as_bool().unwrap() {
            assert_eq!(
                code(res),
                "Argument",
                "{name}: refused before anything is signed"
            );
            continue;
        }
        let p = res.unwrap();
        assert_eq!(p.entry(), "mtxPay");
        let rv = p.review();
        let get = |n: &str| {
            rv.iter()
                .find(|f| f.name == n)
                .unwrap_or_else(|| panic!("{name}: {n} not reviewed"))
                .clone()
        };
        assert_eq!(
            get("entryRef").value,
            r["payId"].as_str().unwrap(),
            "{name}: entryRef = metaPayId(meta)"
        );
        assert_eq!(
            get("save").value,
            r["save"].to_string(),
            "{name}: save reviewed"
        );
        assert_eq!(get("save").source, Source::Signed);
        assert_eq!(get("schema").value, r["schema"].to_string());
        let pay_no = get("payNo");
        assert_eq!(pay_no.value, r["payNo"].as_str().unwrap());
        if name.contains("uuidv7")
            || name == "structured_reference"
            || name == "encrypted_illustrative"
        {
            assert_eq!(
                pay_no.display, "019a6e3c-5f00-7a3b-8c4d-5e6f708192a3",
                "{name}: payNo as UUID text"
            );
        }
        if r["schema"] != 0 {
            assert!(
                rv.iter().any(|f| f.name.starts_with("body.")),
                "{name}: the body reviewed"
            );
        }
    }
    // one through the gateway: `mtxPay` with its meta by name, signed under `Expect::PayMeta`
    let p = t
        .sdk
        .wallet()
        .prepare_pay(pay(meta_of(&rows[2])))
        .await
        .unwrap();
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::Gateway)
        .await
        .unwrap();
    t.sdk.op().submit(p, q).await.unwrap();
    let body = body_at(&t, 0).await;
    assert_eq!(body["op"]["entry"], "mtxPay");
    assert_eq!(body["op"]["args"]["meta"]["save"], true);
}

async fn body_at(t: &T, n: usize) -> Value {
    for _ in 0..100 {
        if let Some(b) = t.chain.lock().unwrap().bodies.get(n) {
            return serde_json::from_str(b).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("no gateway body {n}");
}

#[tokio::test(flavor = "multi_thread")]
async fn transfer_on_ids_is_its_vector_and_posts_ua_metatx() {
    // owner 2026-11-18, ruling 6: `metatx3.json`'s native transfer row, by the vector key
    let t = setup(1).await;
    let v = load("smartcontracts/vectors/ua/metatx3.json");
    let row = v["transfer"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "native")
        .unwrap();
    let m = &row["typedData"]["message"];
    let p = t
        .sdk
        .wallet()
        .prepare_transfer(Transfer {
            signer: t.signer.clone(),
            chain: "local".into(),
            token: s(&row["typedData"]["domain"]["verifyingContract"]),
            to: s(&m["to"]),
            value: s(&m["value"]),
            entry_ref: Some(s(&m["entryRef"])),
            envelope: envelope(m),
        })
        .await
        .unwrap();
    assert_eq!(p.id(), row["digest"].as_str().unwrap(), "the row's digest");
    assert_eq!(p.entry(), "mtxExecuteTransfer");
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::Gateway)
        .await
        .unwrap();
    t.sdk.op().submit(p, q).await.unwrap();
    let body = body_at(&t, 0).await;
    assert_eq!(t.chain.lock().unwrap().gw_paths[0], "/v1/ua-metatx");
    assert_eq!(body["struct"], "transfer");
    assert_eq!(body["chain"], CHAIN_ID);
    assert_eq!(
        body["auth"]["signature"], row["auth"],
        "the row's signature"
    );
    // control: a zero entryRef is no payment lane
    let zero = Transfer {
        signer: t.signer.clone(),
        chain: "local".into(),
        token: s(&row["typedData"]["domain"]["verifyingContract"]),
        to: s(&m["to"]),
        value: "1".into(),
        entry_ref: Some(format!("0x{}", "00".repeat(32))),
        envelope: envelope(m),
    };
    assert_eq!(
        code(t.sdk.wallet().prepare_transfer(zero).await),
        "Argument"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn ua_execute_decoded_only() {
    let t = setup(0).await;
    let wallet = "0x5ca00000000000000000000000000000000000a4";
    let token = "0x5ca00000000000000000000000000000000000a1";
    let exec = |call: ExecuteCall| Execute {
        signer: t.signer.clone(),
        chain: "local".into(),
        wallet: wallet.into(),
        call,
        batch: "7".into(),
        envelope: Envelope {
            valid_until: 1_800_000_300,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    let opaque = |allow| ExecuteCall::Opaque {
        target: token.into(),
        value: "0".into(),
        data: "0xdeadbeef00".into(),
        allow,
    };
    assert_eq!(
        code(t.sdk.wallet().prepare_execute(exec(opaque(None))).await),
        "OpaqueCallRefused",
        "an undecoded call"
    );
    // a decoded call: reviewed field by field, signed
    let p = t
        .sdk
        .wallet()
        .prepare_execute(exec(ExecuteCall::Transfer {
            token: token.into(),
            to: "0x00000000000000000000000000000000000000aa".into(),
            amount: "77".into(),
        }))
        .await
        .unwrap();
    assert!(!p.opaque());
    let r = p.review();
    for (n, want) in [
        ("call", "transfer"),
        ("call.token", token),
        ("call.amount", "77"),
    ] {
        assert_eq!(r.iter().find(|f| f.name == n).unwrap().value, want, "{n}");
    }
    assert!(
        r.iter()
            .any(|f| f.name == "token" && f.value == token && f.display == "listed VND"),
        "the token touched, marked"
    );
    let q = t
        .sdk
        .op()
        .quote(
            p.clone(),
            SubmitPath::SelfRelay {
                payer: t.payer.clone(),
            },
        )
        .await
        .unwrap();
    t.sdk.op().submit(p, q).await.unwrap();
    #[cfg(feature = "opaque-calls")]
    {
        let p = t
            .sdk
            .wallet()
            .prepare_execute(exec(opaque(Some(AllowOpaqueCall::new()))))
            .await
            .unwrap();
        assert!(p.opaque(), "under the marker: flagged");
        assert_eq!(
            p.review()
                .iter()
                .find(|f| f.name == "call.selector")
                .unwrap()
                .value,
            "0xdeadbeef"
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn domain_kind_from_the_contract() {
    let t = setup(0).await;
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let m = v["ops"]["UABurn"]["message"].clone();
    let burn = |contract: &str| Burn {
        signer: t.signer.clone(),
        chain: "local".into(),
        contract: contract.into(),
        batch: s(&m["batch"]),
        amount: s(&m["amount"]),
        envelope: envelope(&m),
    };
    let zether = "0x5ca00000000000000000000000000000000000a2";
    let p = t.sdk.wallet().prepare_burn(burn(zether)).await.unwrap();
    assert_eq!(
        p.id(),
        v["ops"]["UABurn"]["domains"]["zether"]["digest"]
            .as_str()
            .unwrap(),
        "control: the zether domain"
    );
    // a struct the contract's domain has no row for: a burn on the mandate wallet
    let wallet = "0x5ca00000000000000000000000000000000000a4";
    assert_eq!(
        code(t.sdk.wallet().prepare_burn(burn(wallet)).await),
        "Argument"
    );
    // a domain salted for another chain
    t.chain.lock().unwrap().domains.get_mut(zether).unwrap().1 = format!("0x{}", "61".repeat(32));
    assert_eq!(
        code(t.sdk.wallet().prepare_burn(burn(zether)).await),
        "ProfileMismatch"
    );
}
