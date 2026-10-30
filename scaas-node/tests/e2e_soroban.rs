//! cargo test --test e2e_soroban -- --ignored --nocapture
//!
//! Needs a running `stellar/quickstart` (core + rpc + friendbot) and the stellar CLI ≥ 30 — env `STELLAR_URL` (the RPC),
//! `STELLAR_PASSPHRASE`, `STELLAR_FRIENDBOT`, `STELLAR_BIN` (defaults in `soroban_common`: the local quickstart) — and
//! the `wasm32v1-none` target. `smartcontracts/soroban/scripts/e2e-local.sh` runs this file too.
//! Chứng minh trên ledger thật với contract thật (R65, R62):
//! 1. hai lane từ mnemonic 24 từ; chủ thể là ví seed `m/44'/148'/9'` (R32) chỉ KÝ auth entry, không gửi tx;
//! 2. anti-lock: X (token 1) bị giữ, Y (token 2) qua `lane_step` thành công, rồi X thành công;
//! 3. phát lại X ⇒ mô phỏng từ chối (nonce đã dùng) ⇒ job chết, không tốn phí;
//! 4. fee-bump: lane 0 trả phí cho tx của lane 1;
//! 5. `index_step` đưa `PaymentSettled` + `MetaTransactionExecuted` (digest khớp) về Odoo giả.
mod soroban_common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use scaas_node::adapter::{index_step, lane_step, ChainAdapter};
use scaas_node::adapters::soroban::SorobanAdapter;
use scaas_node::signer::{LocalSigner, Signer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use soroban_common::*;
use stellar_xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization, Int128Parts, InvokeContractArgs, Limits, ScSymbol, ScVal,
    SorobanAuthorizedFunction, SorobanAuthorizedInvocation, WriteXdr,
};

/// Đúng phép dựng của Odoo `fam_soroban.build_terms` (vector chéo ghim ở ba phía).
struct Signed {
    job: Value,
    digest: String,
}

#[allow(clippy::too_many_arguments)]
fn sign_pay(subject: &LocalSigner, token: &str, to: &str, amount: i128, pay_ref: [u8; 32], nonce: i64, exp: u32, id: i64) -> Signed {
    let from = g(subject);
    let valid_until = now() + 600;
    let args = vec![
        addr(&from),
        addr(to),
        ScVal::I128(Int128Parts { hi: (amount >> 64) as i64, lo: amount as u64 }),
        ScVal::Bytes(pay_ref.to_vec().try_into().unwrap()),
        ScVal::U64(valid_until),
    ];
    let call = InvokeContractArgs {
        contract_address: token.parse().unwrap(),
        function_name: ScSymbol("pay".try_into().unwrap()),
        args: args.clone().try_into().unwrap(),
    };
    let pre = HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
        network_id: Hash(network()),
        nonce,
        signature_expiration_ledger: exp,
        invocation: SorobanAuthorizedInvocation { function: SorobanAuthorizedFunction::ContractFn(call), sub_invocations: Default::default() },
    })
    .to_xdr(Limits::none())
    .unwrap();
    let sig = subject.sign(&Sha256::digest(&pre)).unwrap();
    let dv = ScVal::Vec(Some(
        vec![
            ScVal::Symbol(ScSymbol("scaas_metaop_v1".try_into().unwrap())),
            ScVal::Bytes(network().to_vec().try_into().unwrap()),
            addr(token),
            ScVal::Symbol(ScSymbol("pay".try_into().unwrap())),
            ScVal::Vec(Some(args.try_into().unwrap())),
        ]
        .try_into()
        .unwrap(),
    ));
    let digest = format!("0x{}", alloy::hex::encode(Sha256::digest(dv.to_xdr(Limits::none()).unwrap())));
    let job = json!({"id": id, "kind": "signed_op", "op": {
        "family": "soroban", "contract": token, "from": from, "op_kind": "pay",
        "payload": alloy::hex::encode(&pre), "signature": alloy::hex::encode(&sig), "public_key": from,
        "auth_kind": "seed", "digest": digest, "valid_until": valid_until, "extra": {}}});
    Signed { job, digest }
}

#[tokio::test]
#[ignore]
async fn soroban_payments_anti_lock_fee_bump_and_finality() {
    let (lane0, lane1, deployer, payee, subject) = (key(0), key(1), key(7), key(8), key(9));
    for k in [&lane0, &lane1, &deployer, &subject] {
        fund(&g(k)).await;
    }
    let (t1, t2) = (deploy_token(&secret(7), &g(&deployer), None), deploy_token(&secret(7), &g(&deployer), None));
    for t in [&t1, &t2] {
        cli(&["contract", "invoke", "--id", t, "--source-account", &secret(7), "--", "mint", "--to", &g(&subject), "--amount", "1000000"]);
    }

    let state = Arc::new(Mutex::new(FakeOdoo { tokens: vec![t1.clone(), t2.clone()], ..Default::default() }));
    let start = latest_ledger().await;
    state.lock().unwrap().indexed_block = start - 1;
    let odoo = odoo_at(start_fake(state.clone()).await);
    let signers = [key(0), key(1)];
    let adapter = SorobanAdapter::new(&chain_cfg(false), &signers).unwrap();
    assert_eq!(adapter.lanes()[1].address, g(&lane1));
    let seq0 = adapter.sequence(0).await.unwrap();

    let exp = start as u32 + 1000;
    let x = sign_pay(&subject, &t1, &g(&payee), 1_000, [0xA1; 32], 0x1111_2222, exp, 1);
    let y = sign_pay(&subject, &t2, &g(&payee), 2_000, [0xB2; 32], -0x3333_4444, exp, 2);

    // Anti-lock (R62): X is withheld; Y on the other contract goes through lane 1.
    state.lock().unwrap().jobs.push(y.job.clone());
    assert!(lane_step(&adapter, &odoo, 1, "n#1").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 2), "mined", "{:?}", state.lock().unwrap().reports);
    // Then X lands, on lane 0.
    state.lock().unwrap().jobs.push(x.job.clone());
    assert!(lane_step(&adapter, &odoo, 0, "n#0").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 1), "mined", "{:?}", state.lock().unwrap().reports);
    assert_eq!(report_of(&state.lock().unwrap(), 1, "signed")["signer_address"], json!(g(&lane0)));
    assert_eq!(adapter.sequence(0).await.unwrap(), seq0 + 1, "the lane's own sequence advanced; the subject sent nothing");

    // Replaying X: the host refuses the spent (address, nonce) at simulation — dead, no fee spent.
    let mut replay = x.job.clone();
    replay["id"] = json!(3);
    state.lock().unwrap().jobs.push(replay);
    assert!(lane_step(&adapter, &odoo, 0, "n#0").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 3), "dead");
    assert_eq!(adapter.sequence(0).await.unwrap(), seq0 + 1);

    // Fee-bump: lane 0 pays for lane 1's tx.
    let bumped = SorobanAdapter::new(&chain_cfg(true), &signers).unwrap();
    let z = sign_pay(&subject, &t1, &g(&payee), 3_000, [0xC3; 32], 77, exp, 4);
    state.lock().unwrap().jobs.push(z.job.clone());
    assert!(lane_step(&bumped, &odoo, 1, "n#1").await.unwrap());
    assert_eq!(last_state(&state.lock().unwrap(), 4), "mined", "{:?}", state.lock().unwrap().reports);

    // Finality: index up to the head; the indexed events carry the digests the subject signed for.
    let mined = latest_ledger().await;
    for _ in 0..60 {
        let _ = index_step(&adapter, &odoo).await.unwrap();
        if state.lock().unwrap().indexed_block >= mined {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let o = state.lock().unwrap();
    assert!(o.indexed_block >= mined);
    assert!(o.refused.is_empty(), "{:?}", o.refused);
    let paid: Vec<_> = o.ingested.iter().filter(|e| e["event"] == "PaymentSettled").collect();
    let executed: Vec<_> = o.ingested.iter().filter(|e| e["event"] == "MetaTransactionExecuted").collect();
    assert_eq!(paid.len(), 3, "{:?}", o.ingested);
    let refs: Vec<_> = paid.iter().map(|e| e["entry_ref"].as_str().unwrap().to_string()).collect();
    for r in ["a1", "b2", "c3"] {
        assert!(refs.contains(&format!("0x{}", r.repeat(32))), "{refs:?}");
    }
    let digests: Vec<_> = executed.iter().map(|e| e["digest"].as_str().unwrap().to_string()).collect();
    for d in [&x.digest, &y.digest, &z.digest] {
        assert!(digests.contains(d), "{digests:?}");
    }
    for e in o.ingested.iter() {
        assert_eq!(e["from"], json!(g(&subject)));
        assert!(e["block_hash"].as_str().unwrap().len() == 66 && e["tx_hash"].as_str().unwrap().starts_with("0x"));
    }
    let y_tx = report_of(&o, 2, "signed")["tx_hash"].clone();
    assert!(paid.iter().any(|e| e["tx_hash"] == y_tx && e["amount"] == "2000" && e["contract"] == json!(t2)));
}
