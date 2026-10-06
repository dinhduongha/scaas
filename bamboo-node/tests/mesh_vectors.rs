//! Vector chuẩn của envelope `scaas-intent/1.2` (spec mesh §4.6, §13.2). File `tests/vectors/mesh-envelope-v1.2.json`
//! sinh bằng `cargo test --test mesh_vectors -- --ignored regenerate`; test không-ignored chạy mọi case qua `accept()`
//! và chuẩn hoá R84 và so với `expect`. Một phần `expect` được ghim độc lập (KAT forge, vector chéo Move/Python của
//! adapter) chứ không lấy từ chính `accept()` — xem `pins()`.
use std::collections::HashMap;

use alloy::primitives::Address;
use bamboo_node::adapters::{aptos, solana, sui, ton};
use bamboo_node::mesh::accept::{accept, ChainInfo, Ctx, MeshParams, PolicyRow, Seen, Source};
use bamboo_node::mesh::{envelope, hubsig, PeerClass};
use bamboo_node::metatx::{self, Domain, WireMetaTx};
use bamboo_node::signer::{Curve, LocalSigner, Signer};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors/mesh-envelope-v1.2.json");
const NOW: u64 = 1_800_000_000;
const FEE_RECIPIENT: &str = "0x000000000000000000000000000000000000c01d";
const EVM_LANE: &str = "0x000000000000000000000000000000000000beef"; // = relayer của KAT
const UNREGISTERED: &str = "0x00000000000000000000000000000000000bad00";

// Vector chéo của adapter (cùng bytes ở Move/Python/program) — xem test trong src/adapters/*.rs.
const SUI_PAYLOAD: &str = "1062616d626f6f2e6d6574616f702e7631086c6f63616c6e6574d4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382006a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71000000000000000000000000000000000000000000000000000000000000beef6400000000000000000000000000000020010101010101010101010101010101010101010101010101010101010101010120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000";
const SUI_DIGEST: &str = "0xb1e94f8ff971d3a06b4ef18ac50c0283320db9eeca1171831ce52612d5708799";
const SUI_SIGNATURE: &str = "AEKwatGlEwsMK2lb91bMHMY/KA1dGEh3oqEJBZ0K/X6o3SGonMkOLSBcyNljeDrNj11RBGwPwRhYgxriKwCfmg3Vv0o/zOcXsDiLzCdJ68FIrZlpsj9F7htgX9WHeFdqxA==";
const SUI_REGISTRY: &str = "0x7c9575082976f063e7bfa16aa86ca20e1675b50efa7d5a64d1fa66ce127f5fdf";
const SUI_ALICE: &str = "0x6a749c33bda66662e3709eea404a27dbb2b27d7a58bc0a1248d12436fb2fae71";
const SUI_ALICE_ACCOUNT: &str = "0xd4793a1919a40ebfe5587a3a49fe89bb64c54bd49c75ab2a08ac0d5636706382";
const APTOS_PAYLOAD: &str = "1062616d626f6f2e6d6574616f702e76310436b4b7af3521c75d6e1f93e651cb3b9a14ff91b066e6fc351d813869a15611730f52836b9e4baedcc626ae27b9dbad9b9e1ed624576d899f41168bb985c3a39200376a224a674671b33d8dfb3ba382aca22eeffb39bbcb285ec45e8407cad34faa000000000000000000000000000000000000000000000000000000000000beef6400000000000000000000000000000020010101010101010101010101010101010101010101010101010101010101010120a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000";
const APTOS_DIGEST: &str = "0xf5512204d143f77ecd5e79965fd9e7e6f99515937590eff22a908d6afa62b918";
const APTOS_BLOB: &str = "39736080a62599783da42d8ea087b6cdac7597fe8985e2dbd238099d5ae5c75d10b9ec13b4a3543d4a105a4f854f115f10ed530f17f302d7969ec7b191ae78034150544f530a6d6573736167653a2062616d626f6f2e6d6574616f702e76313a3078663535313232303464313433663737656364356537393936356664396537653666393935313539333735393065666632326139303864366166613632623931380a6e6f6e63653a2061316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131613161316131";
const APTOS_ALICE_PK: &str = "d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4";
const APTOS_PACKAGE: &str = "0xb0b";
const SOL_PROGRAM: &str = "BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d";
const SOL_NETWORK: &str = "9Bjy32z5orwpyvcJehikjj76VQtVLtc7WdCmTyN3FsWY";
const SOL_ALICE: &str = "FPP21sbqhr2LPjSnJkw5NBetPubeFG4PsQFBxHj8noTq";
const SOL_BOB: &str = "GwCXyJ8AesaucFMTUSZmiFVMhVngpeBxaBC7mQJiZct3";
const SOL_USD: &str = "E5XS6w9DtMRaPTk38iGhD3iSwDJzYUNkKtmUqEpNpUsf";
const SOL_DIGEST: &str = "0x8c2886f0dc1cb1e4a1397ae40e940913961b041c6c36b3e882c1cd016ed08cd3";
const SOL_PAYLOAD: &str = concat!(
    "62616d626f6f2e6d6574616f702e7631799de2ace2cd00af66fcc120fa522604d115bf9af9c6fb2780d6594260fdb729afa497f9db8f42",
    "d70fb0ef45b544030815b53b0ec8812ced192f3f6df4d896f1c250a9ebc1dc2e6299d0873da3edfd78261d872701b4dc7ad557d9eabe3b",
    "ce8e00d5bf4a3fcce717b0388bcc2749ebc148ad9969b23f45ee1b605fd58778576ac4ecc1b58727f3f12b3194881a9ecb9de0b28ce7b2",
    "07230d8e930fe1bce75e256c64000000000000000000000000000000010101010101010101010101010101010101010101010101010101",
    "0101010101a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a10000000000000000e8030000000000000000",
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    "00000000000000",
);
const SOL_BLOB: &str = "00008278a07e2a5e0c47ab6b2c9e0287af6c9eedf30159108af21c66884b0a763f313fa1a4638e1b04d99085479a7238521f58a99ea3033b7a0a8f9bc9edeb1f9d08";
const COSMOS_DIGEST: &str = "0xe9ce621f85e6efbebf377dfcbf8db84b22ddd69f739466be318f7783ec2b5bda";
/// Vector Sui/Aptos/Solana hết hạn ở giây 1000, Cosmos ở 2 000 000 000: case dùng `now` riêng để giữ nguyên bytes.
const NOW_EARLY: u64 = 700;
const NOW_COSMOS: u64 = 2_000_000_000 - 300;

fn hex0x(b: &[u8]) -> String {
    format!("0x{}", alloy::hex::encode(b))
}

fn read(path: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path).expect(path)).expect("json")
}

fn kat() -> Value {
    read(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/evm/test/vectors/metatx_kat.json"))
}

fn ton_vectors() -> Value {
    read(concat!(env!("CARGO_MANIFEST_DIR"), "/../smartcontracts/ton/vectors/ton-vectors.json"))
}

fn cosmos_vector(k: &str) -> String {
    let v = include_str!("../../smartcontracts/cosmos/tests/tests/vector.txt");
    v.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap().to_string()
}

// ------------------------------------------------------------------ checker (shared with the generator)

struct Nobody;
impl Seen for Nobody {
    fn seen(&self, _: &[u8; 32], _: &[u8; 32]) -> bool {
        false
    }
}

fn strs(v: &Value) -> Vec<String> {
    v.as_array().into_iter().flatten().map(|s| s.as_str().unwrap().to_string()).collect()
}

/// Bảng policy mặc định của file: `full`/`submit` trên mọi token đã đăng ký (R86); case có `policy` thì thay hẳn.
fn default_policy(f: &Value) -> Vec<PolicyRow> {
    let mut rows = Vec::new();
    for (chain, toks) in f["tokens"].as_object().unwrap() {
        for t in strs(toks) {
            rows.push(json!({"chain_key": chain, "contract": t, "selector": "*", "support": "full", "submit": true,
                             "pool_visibility": "open", "min_fee": "0", "fee_recipient_allow": "any"}));
        }
    }
    serde_json::from_value(Value::Array(rows)).unwrap()
}

fn observed(f: &Value, c: &Value) -> Value {
    let now = c["now"].as_u64().unwrap_or(f["now"].as_u64().unwrap());
    let public = c["chain_profile"].as_str().unwrap_or("public") == "public";
    let mut chains = HashMap::new();
    for (key, toks) in f["tokens"].as_object().unwrap() {
        let p = &f["chain_params"][key];
        let wallet_codes = p["wallet_codes"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(m, w)| {
                let h: [u8; 32] = alloy::hex::decode(w["hash"].as_str().unwrap()).unwrap().try_into().unwrap();
                (m.clone(), (h, w["depth"].as_u64().unwrap() as u16))
            })
            .collect();
        let evm = key.starts_with("evm:") || key.starts_with("hedera:");
        chains.insert(key.clone(), ChainInfo {
            public,
            tokens: strs(toks),
            lanes: strs(&f["lanes"][key]),
            fee_recipient: evm.then(|| f["fee_recipient"].as_str().unwrap().to_string()),
            program: p["program"].as_str().map(str::to_string),
            wallet_codes,
        });
    }
    let policies = match c.get("policy") {
        Some(p) => serde_json::from_value(p.clone()).unwrap(),
        None => default_policy(f),
    };
    let p = &f["params"];
    let params = MeshParams {
        max_hops: p["max_hops"].as_u64().unwrap(),
        clock_skew_secs: p["clock_skew_secs"].as_u64().unwrap(),
        max_valid_for_secs: p["max_valid_for_secs"].as_u64().unwrap(),
        exclusive_ms: p["exclusive_ms"].as_u64().unwrap(),
    };
    let self_id: [u8; 32] = alloy::hex::decode(f["self_id"].as_str().unwrap()).unwrap().try_into().unwrap();
    let ctx = Ctx { now, params, self_id, chains: &chains, policies: &policies, seen: &Nobody };
    let class = match c["from_peer_class"].as_str().unwrap() {
        "open" => PeerClass::Open,
        _ => PeerClass::Private,
    };
    let bytes = match c["envelope_raw"].as_str() {
        Some(raw) => raw.as_bytes().to_vec(),
        None => serde_json::to_vec(&c["envelope"]).unwrap(),
    };
    match accept(&bytes, Source::Peer(class), &ctx) {
        Err(code) => json!({"accept": false, "code": code.as_str()}),
        Ok(a) => {
            let d = &a.decoded;
            let env = &a.envelope;
            let msg = hubsig::env_msg(env, &d.intent_id, &a.body_hash).unwrap();
            // R84: đúng thứ submitter sẽ mã hoá — trường không ràng buộc bị ghi đè, digest giữ nguyên.
            let submit = d.evm.as_ref().map(|e| {
                let mut m = e.meta.clone();
                metatx::normalize(&mut m, Some(f["fee_recipient"].as_str().unwrap().parse::<Address>().unwrap()));
                serde_json::to_value(WireMetaTx::from_sol(&m)).unwrap()
            });
            json!({
                "accept": true,
                "intent_id": hex0x(&d.intent_id),
                "body_hash": hex0x(&a.body_hash),
                "hub_msg": hex0x(&msg),
                "hub_sig": env.hub.sig,
                "from": d.from, "lane": d.lane, "nonce": d.nonce, "valid_until": d.valid_until, "token": d.token,
                "selector": d.selector,
                "fee_effective": d.fee_effective.to_string(),
                "visibility": a.visibility,
                "exclusive_until": a.exclusive_until,
                "state": a.state,
                "may_submit": a.may_submit,
                "submit_meta_tx": submit,
            })
        }
    }
}

/// Ghim độc lập với `accept()`: digest của KAT forge, của vector chéo adapter, và body_hash của dạng đã sắp.
fn pins(f: &Value) {
    let case = |n: &str| f["cases"].as_array().unwrap().iter().find(|c| c["name"] == n).unwrap_or_else(|| panic!("case {n}"));
    let e = |n: &str, k: &str| case(n)["expect"][k].clone();
    assert_eq!(e("03a_evm_restrict_relayer_our_lane_kat", "intent_id"), kat()["digest"].as_str().unwrap().to_lowercase());
    assert_eq!(e("02_evm_garbage_unbound_fields", "intent_id"), e("01_evm_open_fixed_fee", "intent_id"));
    let s = e("02_evm_garbage_unbound_fields", "submit_meta_tx");
    assert_eq!((s["feeRecipient"].as_str().unwrap(), s["relayer"].as_str().unwrap()), (FEE_RECIPIENT, &*format!("{:#x}", Address::ZERO)));
    for (n, d) in [("09_cosmos_pay", COSMOS_DIGEST), ("10a_sui_pay", SUI_DIGEST), ("11a_aptos_pay", APTOS_DIGEST),
                   ("12a_ton_pay", ton_vectors()["metaop"]["digest"].as_str().unwrap()), ("13a_solana_pay", SOL_DIGEST)] {
        assert_eq!(e(n, "intent_id"), d, "{n}");
        assert_eq!(e(n, "may_submit"), true, "{n}");
    }
    for n in ["10b_sui_foreign_account", "11b_aptos_foreign_account", "12b_ton_foreign_wallet", "13b_solana_foreign_account"] {
        assert_eq!((e(n, "accept"), e(n, "may_submit")), (json!(true), json!(false)), "{n}");
    }
    // vector 32: body_hash = sha256 của dạng ĐÃ SẮP (cùng body với case 01, gửi khoá ngược thứ tự).
    let body = &case("01_evm_open_fixed_fee")["envelope"]["evm"];
    let sorted = sorted_by_hand(body);
    assert_eq!(e("32_unsorted_body_keys", "body_hash"), hex0x(&Sha256::digest(sorted.as_bytes())));
    assert!(case("32_unsorted_body_keys")["envelope_raw"].as_str().unwrap().contains(&unsorted(body)), "wire really unsorted");
}

/// Serializer viết tay (không qua `serde_json::to_string`), khoá sắp bytewise — để vector 32 không tự kiểm chính nó.
fn sorted_by_hand(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let mut ks: Vec<&String> = m.keys().collect();
            ks.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            let parts: Vec<String> = ks.iter().map(|k| format!("\"{k}\":{}", sorted_by_hand(&m[*k]))).collect();
            format!("{{{}}}", parts.join(","))
        }
        Value::String(s) => format!("\"{s}\""), // chỉ hex/decimal/từ khoá ở body EVM: không cần escape
        x => x.to_string(),
    }
}

/// Khoá theo thứ tự ngược ở mọi cấp.
fn unsorted(v: &Value) -> String {
    match v {
        Value::Object(m) => {
            let parts: Vec<String> = m.iter().rev().map(|(k, x)| format!("\"{k}\":{}", unsorted(x))).collect();
            format!("{{{}}}", parts.join(","))
        }
        x => x.to_string(),
    }
}

#[test]
fn vectors() {
    let f = read(FILE);
    assert_eq!(f["spec"], envelope::SPEC);
    let cases = f["cases"].as_array().unwrap();
    let mut numbers: Vec<u32> = cases.iter().map(|c| c["name"].as_str().unwrap()[..2].parse().unwrap()).collect();
    numbers.dedup();
    assert_eq!(numbers, (1..=32).collect::<Vec<_>>(), "spec §4.6: cases 1–32, in order");
    for c in cases {
        assert_eq!(observed(&f, c), c["expect"], "case {}", c["name"]);
    }
    pins(&f);
}

// ------------------------------------------------------------------ generator

fn hub_key() -> SigningKey {
    SigningKey::from_bytes(&[1; 32])
}

/// Điền `hub.{id,pubkey,sig}` theo `hub_msg` của chính envelope (visibility/exclusive/body như đang có).
fn seal(env: &mut Value) {
    seal_with(env, &hub_key())
}

fn seal_with(env: &mut Value, key: &SigningKey) {
    let pk = key.verifying_key().to_bytes();
    env["hub"]["id"] = json!(alloy::hex::encode(hubsig::peer_id(&pk)));
    env["hub"]["pubkey"] = json!(alloy::hex::encode(pk));
    env["hub"]["sig"] = json!("00".repeat(64));
    let parsed: envelope::Envelope = serde_json::from_value(env.clone()).unwrap();
    let body = parsed.evm.as_ref().or(parsed.op.as_ref()).unwrap();
    let body_hash: [u8; 32] = Sha256::digest(envelope::canonical_body(body).unwrap()).into();
    let id: [u8; 32] = alloy::hex::decode(&parsed.intent_id).unwrap().try_into().unwrap();
    let msg = hubsig::env_msg(&parsed, &id, &body_hash).unwrap();
    env["hub"]["sig"] = json!(alloy::hex::encode(hubsig::sign(key, &msg)));
}

fn alice_evm() -> LocalSigner {
    let mut k = [0u8; 32];
    k[29..].copy_from_slice(&[0x0a, 0x11, 0xce]); // 0xA11CE, khoá của MetaTxKat.t.sol
    LocalSigner::new(Curve::Secp256k1, &k).unwrap()
}

fn evm_id(chain_key: &str, contract: &str, name: &str, m: &WireMetaTx) -> [u8; 32] {
    let domain = Domain {
        name: name.into(),
        version: "1".into(),
        chain_id: chain_key.split_once(':').unwrap().1.parse().unwrap(),
        verifying_contract: contract.parse().unwrap(),
    };
    metatx::digest(&domain, &m.to_sol().unwrap()).0
}

fn evm_env_named(chain_key: &str, contract: &str, name: &str, m: &WireMetaTx, sig_kind: &str, signature: Option<String>) -> Value {
    let id = evm_id(chain_key, contract, name, m);
    let signature = signature.unwrap_or_else(|| hex0x(&alice_evm().sign(&id).unwrap()));
    let mut env = json!({
        "spec": envelope::SPEC, "intent_id": hex0x(&id), "chain_key": chain_key,
        "family": chain_key.split_once(':').unwrap().0, "contract": contract, "visibility": "open",
        "evm": {"domain": {"name": name, "version": "1"}, "meta_tx": m, "signature": signature, "sig_kind": sig_kind},
        "hub": {"published_at": NOW}, "hop_count": 0,
    });
    seal(&mut env);
    env
}

fn evm_env(chain_key: &str, contract: &str, m: &WireMetaTx) -> Value {
    evm_env_named(chain_key, contract, "Bamboo MetaToken", m, "eoa", None)
}

#[allow(clippy::too_many_arguments)]
fn op_env(chain_key: &str, contract: &str, id: &[u8], payload: &[u8], signature: &str, public_key: Value, extra: Value, now: u64) -> Value {
    let mut env = json!({
        "spec": envelope::SPEC, "intent_id": hex0x(id), "chain_key": chain_key,
        "family": chain_key.split_once(':').unwrap().0, "contract": contract, "visibility": "open",
        "op": {"op_kind": "pay", "payload": hex0x(payload), "signature": signature, "public_key": public_key,
               "auth_kind": "wallet", "extra": extra},
        "hub": {"published_at": now}, "hop_count": 0,
    });
    seal(&mut env);
    env
}

fn case(name: &str, env: Value, expect: Value) -> Value {
    json!({"name": name, "from_peer_class": "open", "chain_profile": "public", "envelope": env, "expect": expect})
}

fn with(mut c: Value, k: &str, v: Value) -> Value {
    c[k] = v;
    c
}

fn reject(code: &str) -> Value {
    json!({"accept": false, "code": code})
}

#[test]
#[ignore]
fn regenerate() {
    let k = kat();
    let ks = |f: &str| k[f].as_str().unwrap().to_lowercase();
    let token = ks("verifying_contract");
    let zero = format!("{:#x}", Address::ZERO);
    let base = WireMetaTx {
        from: ks("from"), to: ks("to"), value: ks("value"), data: ks("data"), batch: ks("batch"), nonce: "0".into(),
        valid_until: (NOW + 300).to_string(), mode: 0x20, relayer: zero.clone(), fee: "5000".into(), fee_recipient: zero.clone(),
    };
    let m = |f: &dyn Fn(&mut WireMetaTx)| {
        let mut x = base.clone();
        f(&mut x);
        x
    };
    let e1 = evm_env("evm:9000", &token, &base);
    let mut cases = vec![
        case("01_evm_open_fixed_fee", e1.clone(), json!({"accept": true, "fee_effective": "5000", "selector": "0x8609cad1",
             "may_submit": true, "state": "submittable"})),
        case("02_evm_garbage_unbound_fields", evm_env("evm:9000", &token, &m(&|x| {
            x.relayer = "0x00000000000000000000000000000000deadbeef".into();
            x.fee_recipient = "0x000000000000000000000000000000000bad0bad".into();
        })), json!({"accept": true, "may_submit": true})),
    ];
    // 03a: KAT forge nguyên văn (chữ ký do forge ký) — MODE_RESTRICT_RELAYER, relayer = lane của ta.
    let kat_m = WireMetaTx {
        from: ks("from"), to: ks("to"), value: ks("value"), data: ks("data"), batch: ks("batch"), nonce: ks("nonce"),
        valid_until: ks("valid_until"), mode: ks("mode").parse().unwrap(), relayer: ks("relayer"), fee: ks("fee"),
        fee_recipient: ks("fee_recipient"),
    };
    cases.push(case("03a_evm_restrict_relayer_our_lane_kat",
        evm_env_named("evm:9000", &token, k["domain_name"].as_str().unwrap(), &kat_m, "eoa", Some(ks("signature"))),
        json!({"accept": true, "may_submit": true, "fee_effective": "0"})));
    cases.push(case("03b_evm_restrict_relayer_foreign_lane", evm_env("evm:9000", &token, &m(&|x| {
        x.mode = 0x21;
        x.relayer = "0x000000000000000000000000000000000000cafe".into();
    })), json!({"accept": true, "may_submit": false})));
    cases.push(case("04_evm_restrict_relayer_zero", evm_env("evm:9000", &token, &m(&|x| x.mode = 0x21)), reject("RELAYER_BOUND_ZERO")));
    cases.push(case("05_evm_empty_data", evm_env("evm:9000", &token, &m(&|x| x.data = "0x".into())),
        json!({"accept": true, "selector": "0x"})));
    let wallet = m(&|x| x.from = "0x0000000000000000000000000000000000001271".into());
    let e6 = evm_env_named("evm:9000", &token, "Bamboo MetaToken", &wallet, "erc1271", Some(format!("0x{}", "ab".repeat(96))));
    cases.push(case("06_evm_erc1271_no_local_recover", e6.clone(), json!({"accept": true, "may_submit": true})));
    // 07: cùng chữ ký case 01 nhưng s → n − s (v lật): khôi phục đúng người ký, contract vẫn từ chối.
    let mut e7 = e1.clone();
    let sig = alloy::hex::decode(e1["evm"]["signature"].as_str().unwrap()).unwrap();
    let n = alloy::primitives::U256::from_str_radix("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16).unwrap();
    let s = alloy::primitives::U256::from_be_slice(&sig[32..64]);
    let mut high = sig.clone();
    high[32..64].copy_from_slice(&(n - s).to_be_bytes::<32>());
    high[64] ^= 1;
    e7["evm"]["signature"] = json!(hex0x(&high));
    seal(&mut e7);
    cases.push(case("07_evm_high_s", e7, reject("BAD_SIGNATURE")));
    cases.push(case("08_hedera_296", evm_env("hedera:296", &token, &base), json!({"accept": true, "may_submit": true})));

    // 09–13: payload/digest của vector chéo adapter; từ 10 đến 13 kèm bản sinh đôi với account của người khác.
    let cosmos_payload = cosmos_vector("payload");
    let cosmos_pk = {
        let seed = bamboo_node::keys::Seed::from_words(&format!("{}art", "abandon ".repeat(23)), None).unwrap();
        let (curve, key) = bamboo_node::keys::lane_secret(&seed, "cosmos", 0).unwrap();
        alloy::hex::encode(LocalSigner::new(curve, &key).unwrap().public_key())
    };
    cases.push(with(case("09_cosmos_pay", op_env("cosmos:bamboo-1", &cosmos_vector("contract"),
        &Sha256::digest(cosmos_payload.as_bytes()), cosmos_payload.as_bytes(), &cosmos_vector("sig"), json!(cosmos_pk), json!({}), NOW_COSMOS),
        json!({"accept": true, "from": cosmos_vector("from"), "lane": format!("0x{}", "11".repeat(32)), "nonce": "0",
               "valid_until": 2_000_000_000u64, "token": cosmos_vector("contract")})), "now", json!(NOW_COSMOS)));

    let sui_extra = json!({"coin_type": "0x2::sui::SUI", "registry": SUI_REGISTRY});
    let sui_payload = alloy::hex::decode(SUI_PAYLOAD).unwrap();
    let e10 = op_env("sui:localnet", SUI_ALICE_ACCOUNT, &sui::personal_digest(&sui_payload), &sui_payload, SUI_SIGNATURE,
        Value::Null, sui_extra.clone(), NOW_EARLY);
    cases.push(with(case("10a_sui_pay", e10.clone(), json!({"accept": true, "from": SUI_ALICE, "lane": format!("0x{}", "a1".repeat(32)),
        "nonce": "0", "valid_until": 1000, "token": SUI_REGISTRY})), "now", json!(NOW_EARLY)));
    let mut op = sui::MetaOp::decode(&sui_payload).unwrap();
    op.contract = sui::parse_addr(&bamboo_node::mesh::digest::sui_account(SUI_REGISTRY, "0xb0b").unwrap()).unwrap();
    let twin = op.encode();
    cases.push(with(case("10b_sui_foreign_account", op_env("sui:localnet", &sui::addr_hex(&op.contract), &sui::personal_digest(&twin),
        &twin, SUI_SIGNATURE, Value::Null, sui_extra.clone(), NOW_EARLY), json!({"accept": true, "may_submit": false})), "now", json!(NOW_EARLY)));

    let aptos_payload = alloy::hex::decode(APTOS_PAYLOAD).unwrap();
    let mut op = aptos::MetaOp::decode(&aptos_payload).unwrap();
    let asset = aptos::addr_hex(&op.asset);
    let pkg = aptos::parse_addr(APTOS_PACKAGE).unwrap();
    assert_eq!(aptos::account_of(&pkg, &op.from), op.contract);
    cases.push(with(case("11a_aptos_pay", op_env("aptos:4", &aptos::addr_hex(&op.contract), &aptos::sha3(&aptos_payload), &aptos_payload,
        APTOS_BLOB, json!(APTOS_ALICE_PK), json!({"asset": asset}), NOW_EARLY),
        json!({"accept": true, "from": aptos::addr_hex(&op.from), "lane": format!("0x{}", "a1".repeat(32)), "nonce": "0",
               "valid_until": 1000, "token": asset})), "now", json!(NOW_EARLY)));
    op.contract = aptos::account_of(&pkg, &aptos::parse_addr("0xb0b0").unwrap());
    let twin = op.encode();
    cases.push(with(case("11b_aptos_foreign_account", op_env("aptos:4", &aptos::addr_hex(&op.contract), &aptos::sha3(&twin), &twin,
        APTOS_BLOB, json!(APTOS_ALICE_PK), json!({"asset": asset}), NOW_EARLY), json!({"accept": true, "may_submit": false})),
        "now", json!(NOW_EARLY)));

    let tv = ton_vectors();
    let ts = |p: &str| tv.pointer(p).unwrap().as_str().unwrap().to_string();
    let ton_boc = alloy::hex::decode(ts("/metaop/boc")).unwrap();
    let cell = ton::boc_parse(&ton_boc).unwrap();
    let mo = ton::parse_metaop(&cell).unwrap();
    let master = ton::Addr::parse(&ts("/jetton/master")).unwrap();
    let code: [u8; 32] = alloy::hex::decode(ts("/jetton/wallet_code_hash")).unwrap().try_into().unwrap();
    let depth = tv.pointer("/jetton/wallet_code_depth").unwrap().as_u64().unwrap() as u16;
    assert_eq!(ton::jetton_wallet_address(&mo.from, &master, &code, depth).unwrap(), mo.contract, "vector: contract = payer's wallet");
    let sig = alloy::hex::decode(ts("/sign_data/signature")).unwrap();
    let ton_sig = json!({"kind": "ton_connect", "signature": ton::b64encode(&sig), "timestamp": tv.pointer("/sign_data/timestamp").unwrap(),
        "domain": ts("/sign_data/domain"), "state_init": ton::b64encode(&alloy::hex::decode(ts("/payer_w5/state_init_boc")).unwrap())}).to_string();
    let ton_extra = json!({"jetton_master": master.raw()});
    cases.push(case("12a_ton_pay", op_env("ton:-239", &mo.contract.raw(), &mo.digest, &ton_boc, &ton_sig, Value::Null, ton_extra.clone(), NOW),
        json!({"accept": true, "from": mo.from.raw(), "lane": hex0x(&mo.lane), "nonce": "0", "valid_until": NOW + 300,
               "token": master.raw()})));
    let rebuild = |contract: &ton::Addr| {
        ton::Builder::new().bytes(b"bamboo.metaop.v1").int(mo.network as i64, 32).uint(mo.op as u128, 8).uint(mo.amount, 128)
            .uint(mo.nonce as u128, 64).uint(mo.valid_until as u128, 64).addr(Some(contract))
            .reference(ton::Builder::new().addr(Some(&mo.from)).addr(Some(&mo.to)).addr(mo.relayer.as_ref()).end().unwrap())
            .reference(ton::Builder::new().bytes(&mo.pay_ref).bytes(&mo.lane).bytes(&mo.extra).end().unwrap())
            .end().unwrap()
    };
    assert_eq!(rebuild(&mo.contract).hash(), mo.digest, "the TON builder reproduces the vector cell");
    let other = ton::jetton_wallet_address(&ton::Addr { wc: 0, hash: [0x33; 32] }, &master, &code, depth).unwrap();
    let twin = rebuild(&other);
    cases.push(case("12b_ton_foreign_wallet", op_env("ton:-239", &other.raw(), &twin.hash(), &ton::boc_serialize(&twin), &ton_sig,
        Value::Null, ton_extra, NOW), json!({"accept": true, "may_submit": false})));

    let sol_payload = alloy::hex::decode(SOL_PAYLOAD).unwrap();
    let mut op = solana::MetaOp::decode(&sol_payload).unwrap();
    let program = solana::key(SOL_PROGRAM).unwrap();
    let sol_chain = format!("solana:{SOL_NETWORK}");
    let sol_extra = json!({"asset": SOL_USD, "token_program": solana::TOKEN_PROGRAM});
    let alice_pk = alloy::hex::encode(solana::key(SOL_ALICE).unwrap());
    cases.push(with(case("13a_solana_pay", op_env(&sol_chain, &solana::b58(&op.contract), &Sha256::digest(&sol_payload), &sol_payload,
        SOL_BLOB, json!(alice_pk), sol_extra.clone(), NOW_EARLY),
        json!({"accept": true, "from": SOL_ALICE, "lane": format!("0x{}", "a1".repeat(32)), "nonce": "0", "valid_until": 1000,
               "token": SOL_USD})), "now", json!(NOW_EARLY)));
    op.contract = solana::account_of(&program, &solana::key(SOL_BOB).unwrap());
    let twin = op.encode();
    cases.push(with(case("13b_solana_foreign_account", op_env(&sol_chain, &solana::b58(&op.contract), &Sha256::digest(&twin), &twin,
        SOL_BLOB, json!(alice_pk), sol_extra, NOW_EARLY), json!({"accept": true, "may_submit": false})), "now", json!(NOW_EARLY)));

    let mut e14 = op_env("soroban:testnet", "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", &[0x5e; 32], b"xdr", "00", Value::Null, json!({}), NOW);
    e14["family"] = json!("soroban");
    cases.push(case("14_soroban_not_on_the_bus", e14, reject("FAMILY_NOT_SUPPORTED")));
    cases.push(case("15a_spec_1_1", with(e1.clone(), "spec", json!("scaas-intent/1.1")), reject("UNSUPPORTED_SPEC")));
    cases.push(case("15b_spec_2_0", with(e1.clone(), "spec", json!("scaas-intent/2.0")), reject("UNSUPPORTED_SPEC")));
    // Tên cũ của bản nháp spec: không có node nào từng nói nó.
    cases.push(case("15c_spec_old_name", with(e1.clone(), "spec", json!("bamboo-intent/1.2")), reject("UNSUPPORTED_SPEC")));
    cases.push(case("16_unknown_top_level_field", with(e1.clone(), "x_future", json!({"anything": [1, 2]})),
        json!({"accept": true, "may_submit": true})));
    cases.push(case("17_hop_limit", with(e1.clone(), "hop_count", json!(4)), reject("HOP_LIMIT")));
    cases.push(case("18a_valid_too_long", evm_env("evm:9000", &token, &m(&|x| x.valid_until = (NOW + 3601).to_string())),
        reject("VALID_TOO_LONG")));
    cases.push(case("18b_expired_inside_skew", evm_env("evm:9000", &token, &m(&|x| x.valid_until = (NOW + 10).to_string())),
        reject("EXPIRED")));
    let mut e19 = e1.clone();
    let mut id = alloy::hex::decode(e1["intent_id"].as_str().unwrap()).unwrap();
    id[31] ^= 1;
    e19["intent_id"] = json!(hex0x(&id));
    seal(&mut e19);
    cases.push(case("19_digest_mismatch", e19, reject("DIGEST_MISMATCH")));
    let mut e20 = with(e1.clone(), "visibility", json!("private"));
    seal(&mut e20);
    cases.push(case("20_visibility_downgraded_after_signing", with(e20.clone(), "visibility", json!("open")), reject("BAD_HUB_SIG")));
    let other_peer = alloy::hex::encode(hubsig::peer_id(&SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()));
    let mut e21 = with(e1.clone(), "exclusive", json!({"relayer_id": other_peer, "until": NOW + 5}));
    seal(&mut e21);
    let mut t21 = e21.clone();
    t21["exclusive"]["until"] = json!(NOW + 6);
    cases.push(case("21_exclusive_until_changed", t21, reject("BAD_HUB_SIG")));
    let mut e22 = e1.clone();
    e22["hub"]["pubkey"] = json!(alloy::hex::encode(SigningKey::from_bytes(&[3; 32]).verifying_key().to_bytes()));
    cases.push(case("22_pubkey_not_hub_id", e22, reject("BAD_HUB_SIG")));
    cases.push(case("23_private_from_open_peer", e20, reject("PRIVATE_FROM_OPEN_PEER")));
    let mut e24 = with(e1.clone(), "exclusive", json!({"relayer_id": other_peer, "until": NOW + 11}));
    seal(&mut e24);
    cases.push(case("24a_exclusive_over_clamp_ignored", e24, json!({"accept": true, "exclusive_until": null, "state": "submittable"})));
    cases.push(case("24b_exclusive_for_another_peer_honored", e21,
        json!({"accept": true, "exclusive_until": NOW + 5, "state": "pooled", "may_submit": true})));
    cases.push(with(case("25_open_label_on_private_chain", e1.clone(), reject("PRIVATE_FROM_OPEN_PEER")), "chain_profile", json!("private")));
    let mut t26 = e1.clone();
    t26["evm"]["sig_kind"] = json!("erc1271");
    cases.push(case("26a_sig_kind_flipped", t26, reject("BAD_HUB_SIG")));
    let mut t26 = e6;
    t26["evm"]["signature"] = json!(format!("0x{}", "cd".repeat(96)));
    cases.push(case("26b_erc1271_signature_swapped", t26, reject("BAD_HUB_SIG")));
    let mut t27 = e10;
    t27["op"]["extra"]["coin_type"] = json!("0x2::fake::FAKE");
    cases.push(with(case("27_non_evm_extra_changed", t27, reject("BAD_HUB_SIG")), "now", json!(NOW_EARLY)));
    let mut e28 = e1.clone();
    e28["hub"]["published_at"] = json!(NOW - 3000);
    seal(&mut e28);
    cases.push(case("28a_old_published_at_catch_up", e28, json!({"accept": true, "may_submit": true})));
    let mut e28 = e1.clone();
    e28["hub"]["published_at"] = json!(NOW + 60);
    seal(&mut e28);
    cases.push(case("28b_published_in_the_future", e28, reject("BAD_ENVELOPE")));
    let pol = |contract: &str, min_fee: &str| json!([{"chain_key": "evm:9000", "contract": contract, "selector": "*", "support": "full",
        "submit": true, "pool_visibility": "open", "min_fee": min_fee, "fee_recipient_allow": "any"}]);
    cases.push(with(case("29_none_mode_huge_fee", evm_env("evm:9000", &token, &m(&|x| {
        x.mode = 0x00;
        x.fee = format!("1{}", "0".repeat(30));
    })), json!({"accept": true, "fee_effective": "0", "may_submit": false})), "policy", pol(&token, "1")));
    cases.push(with(case("30_unregistered_contract", evm_env("evm:9000", UNREGISTERED, &base),
        json!({"accept": true, "token": UNREGISTERED, "may_submit": false})), "policy", pol(UNREGISTERED, "0")));
    let mut e31 = evm_env_named("evm:9000", &token, "Bamboo MetaToken", &base, "eoa", None);
    e31["evm"]["domain"]["name"] = json!("Bamboo MetaTokén");
    cases.push(case("31_non_ascii_body_string", e31, reject("BAD_ENVELOPE")));
    // 32: cùng envelope case 01, mọi khoá viết ngược thứ tự trên dây.
    let raw = unsorted(&e1);
    cases.push(json!({"name": "32_unsorted_body_keys", "from_peer_class": "open", "chain_profile": "public",
                      "envelope_raw": raw, "expect": {"accept": true}}));

    let tokens = json!({
        "evm:9000": [token], "hedera:296": [token],
        "cosmos:bamboo-1": [cosmos_vector("contract")], "sui:localnet": [SUI_REGISTRY], "aptos:4": [asset],
        "ton:-239": [master.raw()], sol_chain.clone(): [SOL_USD],
    });
    let lanes = json!({
        "evm:9000": [EVM_LANE], "hedera:296": [EVM_LANE], "cosmos:bamboo-1": ["wasm1xvenxvenxvenxvenxvenxvenxvenxvenkz5vxp"],
        "sui:localnet": [format!("0x{}", "77".repeat(32))], "aptos:4": [format!("0x{}", "77".repeat(32))],
        "ton:-239": [format!("0:{}", "77".repeat(32))], sol_chain.clone(): [SOL_BOB],
    });
    let mut f = json!({
        "spec": envelope::SPEC,
        "comment": "Spec mesh §4.6. Generated by `cargo test --test mesh_vectors -- --ignored regenerate`. A case's `now` overrides the file's (the Sui/Aptos/Solana/Cosmos cross-language payloads keep their original valid_until). `chain_profile` applies to every chain of the case. `policy`, when present, replaces the default table (full/submit/open, min_fee 0, on every registered token). `envelope_raw` is sent as bytes.",
        "hub_key_seed": alloy::hex::encode([1u8; 32]),
        "self_id": alloy::hex::encode(hubsig::peer_id(&SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes())),
        "now": NOW,
        "fee_recipient": FEE_RECIPIENT,
        "params": {"max_hops": 4, "clock_skew_secs": 30, "max_valid_for_secs": 3600, "exclusive_ms": 10000},
        "tokens": tokens,
        "lanes": lanes,
        "chain_params": {"aptos:4": {"program": APTOS_PACKAGE}, sol_chain: {"program": SOL_PROGRAM},
                         "ton:-239": {"wallet_codes": {master.raw(): {"hash": alloy::hex::encode(code), "depth": depth}}}},
        "cases": [],
    });
    for c in &mut cases {
        let got = observed(&f, c);
        for (k, want) in c["expect"].as_object().unwrap() {
            assert_eq!(&got[k], want, "case {} field {k}: {got}", c["name"]);
        }
        c["expect"] = got;
    }
    f["cases"] = Value::Array(cases);
    std::fs::write(FILE, serde_json::to_string_pretty(&f).unwrap() + "\n").unwrap();
    pins(&f);
}
