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
    ChainProfile, EndpointConfig, Family, Finality, GasBase, GasRows, GasVerify, Limits,
    ListedToken, RuntimeChoice, Sdk, SdkConfig, SdkError,
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

const REGISTRY: &str = "0x5ca00000000000000000000000000000000004e6";

struct T {
    sdk: Arc<Sdk>,
    chain: Fake,
    store: Arc<MemoryStore>,
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
        // the registry holds every receiver here (a pay to a derived UA needs a registry: owner 2026-11-19, R3)
        let sel = fake_chain::keccak_hex(b"isRegistered(bytes32)")[..10].to_string();
        c.answers.push((REGISTRY.into(), sel, format!("0x{}1", "0".repeat(63))));
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
        registry: Some(REGISTRY.into()),
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
        max_valid_secs: None,
        verifiers: vec![],
        verifier_policy: scaas_rpc::Policy::Failover,
        gas_opt_in: vec![],
    };
    let store = MemoryStore::new();
    let sdk = Sdk::open(SdkConfig {
        profiles: vec![profile],
        store: store.clone(),
        authenticator: None,
        rp_id: None,
        runtime: RuntimeChoice::Adopt(tokio::runtime::Handle::current()),
        limits: Limits::default(),
        clock: Some(std::sync::Arc::new(|| 1_800_000_000)),
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
        store,
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

/// A signed operation of another party as a row of `sdk.state` (public data, the row's own form): its contract and calldata,
/// its job `op` naming `token` (a relay fee's paid call). Returns its id.
async fn plant_row(t: &T, contract: &str, calldata: &str) -> String {
    use scaas_sdk::vault::{SecureStore, StorePolicy};
    let op = "0f0f0f0f-0f0f-4f0f-8f0f-0f0f0f0f0f0f";
    let row = json!({"op": op, "chain": "local", "entry": "mtxBurn", "struct": "UABurn", "kind": "token", "contract": contract,
        "from": "", "batch": "", "nonce": "", "valid_until": 0, "digest": format!("0x{}", "00".repeat(32)),
        "op_json": {"entry": "mtxBurn", "contract": "token", "token": contract, "struct": "UABurn"}, "calldata": calldata,
        "raw": null, "tx_id": null, "tx_nonce": null, "path": "gateway", "payer": null, "from_block": 0, "state": "sent",
        "detail": "Queued", "landed": null, "relayer_bound": false});
    // under the store's lock, as the SDK's own writes of `sdk.state` (a send task may be writing a row)
    let _lock = t.store.lock("sdk.state".into()).await.unwrap();
    let item = t
        .store
        .get("sdk.state".into(), String::new())
        .await
        .unwrap();
    let mut st = item.as_ref().map_or(json!({"rev": 0, "ops": []}), |i| {
        serde_json::from_slice(&i.bytes).unwrap()
    });
    let ops = st["ops"].as_array_mut().unwrap();
    ops.retain(|r| r["op"] != op);
    ops.push(row);
    st["rev"] = json!(st["rev"].as_u64().unwrap() + 1);
    let bytes = serde_json::to_vec(&st).unwrap();
    t.store
        .put_if(
            "sdk.state".into(),
            item.map(|i| i.rev),
            bytes,
            StorePolicy::default(),
        )
        .await
        .unwrap();
    op.into()
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
            let call = plant_row(t, &f("target"), &s(&d["relayedCall"])).await;
            w.prepare_relay_fee(RelayFee {
                signer,
                chain,
                token: contract,
                call,
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
fn gas_rows() -> GasRows {
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
    let base = keys
        .into_iter()
        .flat_map(|(entry, kind)| {
            [true, false].map(|fresh| GasBase {
                entry: entry.clone(),
                kind: kind.clone(),
                fresh,
                gas: 100_000,
            })
        })
        .collect();
    GasRows {
        base,
        verify: vec![GasVerify { signer: 0, gas: 0 }],
    }
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
    // owner 2026-11-19, ruling D: a plain transfer, entryRef 0 on the lane the caller names, the lane's nonce read
    let token = s(&row["typedData"]["domain"]["verifyingContract"]);
    t.chain.lock().unwrap().nonces.insert(token.clone(), 4);
    let req = Transfer {
        signer: t.signer.clone(),
        chain: "local".into(),
        token: token.clone(),
        to: s(&m["to"]),
        value: s(&m["value"]),
        batch: "9".into(),
        envelope: envelope(m),
    };
    let p = t.sdk.wallet().prepare_transfer(req.clone()).await.unwrap();
    // the digest: the row's UAMetaTransfer (its domain, typehash and envelope) with entryRef 0, lane 9, nonce 4
    let mut want = m.clone();
    want["entryRef"] = json!(format!("0x{}", "00".repeat(32)));
    want["batch"] = json!("9");
    want["nonce"] = json!("4");
    let d = &row["typedData"]["domain"];
    let uid: [u8; 32] = alloy::hex::decode(&s(&d["salt"])[2..])
        .unwrap()
        .try_into()
        .unwrap();
    let to20: [u8; 20] = alloy::hex::decode(&token[2..]).unwrap().try_into().unwrap();
    let td = scaas_ua::wallet::scaas_typed_data(
        "UAMetaTransfer",
        Some("SCaaS MetaToken"),
        &to20,
        CHAIN_ID,
        &uid,
        &want,
    )
    .unwrap();
    assert_eq!(
        p.id(),
        format!("0x{}", alloy::hex::encode(td.digest().unwrap())),
        "entryRef 0, the named lane"
    );
    assert_eq!(p.entry(), "mtxExecuteTransfer");
    // a retry of the same request reads the same lane nonce: the same operation (at most one of the two lands)
    let again = t.sdk.wallet().prepare_transfer(req).await.unwrap();
    assert_eq!(again.id(), p.id(), "idempotent by its lane");
    let p = again; // the table keeps the latest of one id
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
        body["m"]["entryRef"],
        json!(format!("0x{}", "00".repeat(32))),
        "not a payment"
    );
    assert_eq!(body["m"]["batch"], json!("9"));
}

/// Owner 2026-11-19, ruling F: a relay fee's gateway job carries the operation it pays for as `call` (`scaas-ua`
/// `relay_fee_op`): the paid operation's job op, `target` and `callDataHash` taken from it; an unknown operation is `Argument`.
#[tokio::test(flavor = "multi_thread")]
async fn relay_fee_job_carries_its_call() {
    let t = setup(1).await;
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let d = &v["ops"]["UARelayFee"]["domains"]["token"];
    let m = &v["ops"]["UARelayFee"]["message"];
    let call = plant_row(&t, &s(&m["target"]), &s(&d["relayedCall"])).await;
    let req = |call: String| RelayFee {
        signer: t.signer.clone(),
        chain: "local".into(),
        token: s(&d["domain"]["verifyingContract"]),
        call,
        payee: s(&m["payee"]),
        value: s(&m["value"]),
        batch: s(&m["batch"]),
        valid_until: s(&m["validUntil"]).parse().unwrap(),
        relayer: s(&m["relayer"]),
    };
    assert_eq!(
        code(
            t.sdk
                .wallet()
                .prepare_relay_fee(req("0f0f0f0f-0000-4000-8000-000000000000".into()))
                .await
        ),
        "Argument",
        "no such operation"
    );
    let p = t.sdk.wallet().prepare_relay_fee(req(call)).await.unwrap();
    assert_eq!(
        p.id(),
        s(&d["digest"]),
        "the row's digest (its callDataHash the paid call's)"
    );
    let q = t
        .sdk
        .op()
        .quote(p.clone(), SubmitPath::Gateway)
        .await
        .unwrap();
    t.sdk.op().submit(p, q).await.unwrap();
    let body = body_at(&t, 0).await;
    assert_eq!(body["op"]["entry"], "mtxRelayFee");
    assert_eq!(
        body["op"]["call"]["token"],
        json!(s(&m["target"])),
        "the paid call rides along"
    );
    assert!(
        body["op"]["args"].get("target").is_none()
            && body["op"]["args"].get("callDataHash").is_none()
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

/// Owner 2026-11-19, ruling D: a pay whose request leaves the salt out derives it from the request, so a retry of the same pay
/// is the same operation on the same pay lane; another payment number (or amount) is another lane.
#[tokio::test(flavor = "multi_thread")]
async fn pay_salt_derived_from_the_request() {
    let t = setup(0).await;
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let d = &v["ops"]["UABurn"]["domains"]["token"];
    let pay = |pay_no: Option<String>, value: &str| Pay {
        signer: t.signer.clone(),
        chain: "local".into(),
        token: s(&d["domain"]["verifyingContract"]),
        to: format!("0x{}", "00".repeat(31) + "aa"),
        value: value.into(),
        meta: PayMeta {
            salt: None,
            pay_no,
            save: false,
            body: PayBody::Note {
                note: "rent".into(),
            },
        },
        envelope: Envelope {
            valid_until: 1_800_000_300,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    let a = t.sdk.wallet().prepare_pay(pay(None, "5")).await.unwrap();
    let b = t.sdk.wallet().prepare_pay(pay(None, "5")).await.unwrap();
    assert_eq!(a.id(), b.id(), "a retry: the same pay lane and operation");
    let lane = |p: &Prepared| {
        p.review()
            .into_iter()
            .find(|f| f.name == "batch")
            .unwrap()
            .value
    };
    let other = t
        .sdk
        .wallet()
        .prepare_pay(pay(Some(format!("0x{}", "01".repeat(32))), "5"))
        .await
        .unwrap();
    assert_ne!(
        lane(&other),
        lane(&b),
        "another payment number: another lane"
    );
    let more = t.sdk.wallet().prepare_pay(pay(None, "6")).await.unwrap();
    assert_ne!(lane(&more), lane(&b), "another amount: another lane");
}

/// Closing review P2-4: a PERCENT envelope (`UABurn`'s row: mode 0x13, rate 5000 on 135000) is reviewed and quoted as the amount
/// the relayer takes, 675, never as its rate; it signs under that cap (the row's vector, `every_wallet_pair_is_its_vector`).
#[tokio::test(flavor = "multi_thread")]
async fn percent_fee_is_reviewed_as_its_amount() {
    let t = setup(1).await;
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let m = v["ops"]["UABurn"]["message"].clone();
    let d = &v["ops"]["UABurn"]["domains"]["token"];
    let p = t
        .sdk
        .wallet()
        .prepare_burn(Burn {
            signer: t.signer.clone(),
            chain: "local".into(),
            contract: s(&d["domain"]["verifyingContract"]),
            batch: s(&m["batch"]),
            amount: s(&m["amount"]),
            envelope: envelope(&m),
        })
        .await
        .unwrap();
    let due = p
        .review()
        .into_iter()
        .find(|f| f.name == "fee.due")
        .unwrap();
    assert_eq!(due.value, "675");
    let q = t.sdk.op().quote(p, SubmitPath::Gateway).await.unwrap();
    assert_eq!(
        q.fee_to_relayer, "675",
        "the quote's fee is the amount, not the rate 5000"
    );
}

/// Plan T13 `execute_decoded_only` on a `SmartKeyAccount` (as T12's on a mandate wallet): an undecoded call is
/// `OpaqueCallRefused`; a decoded `transfer` or a guardian's `initiateRecovery(key)` is reviewed field by field and signed
/// under `Expect::Execute` (`scaas-ua` rebuilds the call's bytes); with `opaque-calls` and the marker, flagged; another
/// contract's domain is `Argument`.
#[tokio::test(flavor = "multi_thread")]
async fn smart_execute_decoded_only() {
    use scaas_sdk::account::{SmartCall, SmartOp, SubjectKeyArgs};
    let t = setup(0).await;
    let v = load("smartcontracts/vectors/typed/typed_ops.json");
    let d = &v["ops"]["Execute"]["domains"]["account"]["domain"];
    let account = d["verifyingContract"].as_str().unwrap().to_ascii_lowercase();
    {
        let mut c = t.chain.lock().unwrap();
        let salt = c.genesis.clone();
        c.domains
            .insert(account.clone(), ("SCaaS SmartKeyAccount".into(), salt));
    }
    let token = "0x5ca00000000000000000000000000000000000a1";
    let op = |account: &str| SmartOp {
        signer: t.signer.clone(),
        key_index: Some("0".into()),
        chain: "local".into(),
        account: account.into(),
        batch: "3".into(),
        envelope: Envelope {
            valid_until: 1_800_000_300,
            mode: 0,
            relayer: None,
            fee: "0".into(),
            fee_recipient: None,
        },
    };
    let opaque = |allow| SmartCall::Opaque {
        target: token.into(),
        value: "0".into(),
        data: "0xdeadbeef00".into(),
        allow,
    };
    let acc = t.sdk.account();
    assert_eq!(
        code(acc.prepare_smart_execute(op(&account), opaque(None)).await),
        "OpaqueCallRefused",
        "an undecoded call"
    );
    let transfer = SmartCall::Transfer {
        token: token.into(),
        to: "0x00000000000000000000000000000000000000aa".into(),
        amount: "77".into(),
    };
    assert_eq!(
        code(acc.prepare_smart_execute(op(token), transfer.clone()).await),
        "Argument",
        "a token's domain is not an account's"
    );
    let p = acc.prepare_smart_execute(op(&account), transfer).await.unwrap();
    assert_eq!(p.entry(), "mtxExecute");
    assert!(!p.opaque());
    let r = p.review();
    assert_eq!(r.iter().find(|f| f.name == "call.amount").unwrap().value, "77");
    assert_eq!(r.iter().find(|f| f.name == "from").unwrap().value, account, "from: the account itself");
    // a guardian's recovery of another account, decoded
    let new_key = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000bb").unwrap();
    let guarded = "0x00000000000000000000000000000000000000cc";
    let p = acc
        .prepare_initiate_recovery(op(&account), guarded.into(), new_key.clone())
        .await
        .unwrap();
    let r = p.review();
    for (n, want) in [
        ("call", "initiateRecovery"),
        ("call.account", guarded),
        ("call.key.x", new_key.x.as_str()),
        ("target", guarded),
    ] {
        assert_eq!(r.iter().find(|f| f.name == n).unwrap().value, want, "{n}");
    }
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
    // the key index read from the account (owner 2026-11-19, S3, P2): slot 0 another key, slot 1 removed (zero), slot 2 the
    // signer's; the entry is signed as `keyIndex` 2. With two slots the signer is in none: `SignerNotAccountKey`.
    let sel = |s: &str| fake_chain::keccak_hex(s.as_bytes())[..10].to_string();
    let words = |k: &SubjectKeyArgs| {
        let w = [&k.x, &k.y, &k.rp_id_hash, &k.origin_hash].map(|x| x[2..].to_string()).concat();
        format!("0x{:064x}{w}", k.kind)
    };
    let me = SubjectKeyArgs::secp256k1(v["key"]["address"].as_str().unwrap()).unwrap();
    let other = SubjectKeyArgs::secp256k1("0x00000000000000000000000000000000000000dd").unwrap();
    let slots = |next: u64| {
        let at = |i: u64| format!("{}{i:064x}", sel("keyAt(uint256)"));
        let mut c = t.chain.lock().unwrap();
        c.answers.retain(|(to, _, _)| *to != account);
        for (d, out) in [
            (sel("nextKeyIndex()"), format!("0x{next:064x}")),
            (at(0), words(&other)),
            (at(1), format!("0x{}", "0".repeat(320))),
            (at(2), words(&me)),
        ] {
            c.answers.push((account.clone(), d, out));
        }
    };
    let read = |account: &str| SmartOp { key_index: None, ..op(account) };
    let transfer = SmartCall::Transfer {
        token: token.into(),
        to: "0x00000000000000000000000000000000000000aa".into(),
        amount: "78".into(),
    };
    slots(2);
    assert_eq!(
        code(acc.prepare_smart_execute(read(&account), transfer.clone()).await),
        "SignerNotAccountKey",
        "no slot holds the signer"
    );
    slots(3);
    let p = acc.prepare_smart_execute(read(&account), transfer).await.unwrap();
    let payer = SubmitPath::SelfRelay { payer: t.payer.clone() };
    let q = t.sdk.op().quote(p.clone(), payer).await.unwrap();
    t.sdk.op().submit(p, q).await.unwrap();
    let sig_head = format!("{:064x}{:064x}{:064x}", 2, 0x60, 0x80);
    assert!(carried_soon(&t, &sig_head).await, "AccountSig keyIndex 2");
    #[cfg(feature = "opaque-calls")]
    {
        let p = acc
            .prepare_smart_execute(op(&account), opaque(Some(AllowOpaqueCall::new())))
            .await
            .unwrap();
        assert!(p.opaque(), "under the marker: flagged");
    }
}
