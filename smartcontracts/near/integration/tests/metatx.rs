//! Task 6 (spec §2 rows 4–7, 10, 12, 15; §3.4, §3.7; CTR-MTX-26, CTR-MTX-16): the value entries `mtx_pay`,
//! `mtx_pay_meta`, `mtx_transfer`, `mtx_execute_transfer` — lanes per payer `(from, lane)`, events, storage paid from
//! the attached deposit once per call, the passkey-for-value policy (ruling R8). One sandbox per test.
mod common;
use common::*;
use near_workspaces::operations::Function;
use near_workspaces::types::Gas;
use scaas_near_common::hash::{hex, meta_pay_id, pay_lane};
use scaas_near_token::{lane_bytes, ACCOUNT_STORAGE_BYTES, UA_STORAGE_BYTES};
use serde_json::{json, Value};

const PAYMETA: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../vectors/metatx/paymeta.json");
const SHAPE: &str = "pay-meta shape (pay_ref = metaPayId(salt, meta), lane = payLane(pay_ref), nonce 0)";
const TO_SELF: &str = "token refuses a transfer to the token itself";
const NONCE: &str = "wrong lane nonce";
const RELAYER: &str = "relayer is not the predecessor";
const POLICY: &str = "POLICY_PASSKEY_FOR_VALUE: value ops need a passkey signature";
const SHORT: &str = "The attached deposit is less than the storage cost of the new record";

fn x(b: &[u8]) -> String {
    format!("0x{}", hex(b))
}

fn unhex(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

/// `paymeta.json` rows: (name, salt, meta).
fn paymeta() -> Vec<(String, [u8; 32], Vec<u8>)> {
    let rows: Value = serde_json::from_str(&std::fs::read_to_string(PAYMETA).unwrap()).unwrap();
    rows.as_array()
        .unwrap()
        .iter()
        .map(|r| {
            let (salt, meta) = (unhex(&r["salt"]).try_into().unwrap(), unhex(&r["meta"]));
            assert_eq!(meta_pay_id(&salt, &meta).to_vec(), unhex(&r["payId"]));
            (r["name"].as_str().unwrap().to_string(), salt, meta)
        })
        .collect()
}

fn meta_params(salt: &[u8; 32], meta: &[u8]) -> Vec<u8> {
    [b(salt), b(&meta.to_vec())].concat()
}

/// Index of the first log with `"event":"<name>"`.
fn at(out: &ExecutionFinalResult, name: &str) -> usize {
    let tag = format!(r#""event":"{name}""#);
    out.logs().iter().position(|l| l.contains(&tag)).unwrap_or_else(|| panic!("no {name} in {:?}", out.logs()))
}

impl T {
    /// A value op (codes 0, 4, 5) of `from`; `extra` is payer-chosen (zero here).
    fn vop(&self, code: u8, from: &Holder, to: &Holder, amount: u128, pay_ref: [u8; 32], lane: [u8; 32], nonce: u64) -> MetaOp {
        MetaOp { amount, pay_ref, lane, extra: [0; 32], ..self.op(code, from, to, nonce, &[]) }
    }

    /// A pay-meta op of `from` for `(salt, meta)` (lane and nonce derived).
    fn meta_op(&self, from: &Holder, to: &Holder, amount: u128, salt: &[u8; 32], meta: &[u8]) -> MetaOp {
        let id = meta_pay_id(salt, meta);
        self.vop(OP_PAY, from, to, amount, id, pay_lane(&id), 0)
    }

    /// Admin mint to alice (the token is its own admin in `setup`), then `transfer_to_ua` to a new UA `h`.
    async fn fund(&self, h: &Holder, amount: u128) {
        let dep = NearToken::from_millinear(100);
        let first = if self.registered(&self.alice).await { NearToken::from_yoctonear(1) } else { dep };
        let out = self.token.call("mint").args_json(json!({"to": self.alice.id(), "amount": amount.to_string()}))
            .deposit(first).transact().await.unwrap();
        assert!(out.is_success(), "{:?}", out.failures());
        if let Holder::Ua(id) = h {
            let out = self.alice.call(self.token.id(), "transfer_to_ua")
                .args_json(json!({"id": id.to_vec(), "amount": amount.to_string()}))
                .deposit(dep).transact().await.unwrap();
            assert!(out.is_success(), "{:?}", out.failures());
        }
    }

    async fn balance(&self, h: &Holder) -> u128 {
        let v: String = match h {
            Holder::Near(a) => self.token.view("ft_balance_of").args_json(json!({"account_id": a})).await.unwrap().json().unwrap(),
            Holder::Ua(id) => self.token.view("ua_balance_of").args_json(json!({"id": id.to_vec()})).await.unwrap().json().unwrap(),
        };
        v.parse().unwrap()
    }

    async fn lane_nonce(&self, h: &Holder, lane: [u8; 32]) -> u64 {
        self.token.view("lane_nonce").args(b(&(h.clone(), lane))).await.unwrap().borsh().unwrap()
    }

    async fn registered(&self, a: &Account) -> bool {
        let v: Value =
            self.token.view("storage_balance_of").args_json(json!({"account_id": a.id()})).await.unwrap().json().unwrap();
        !v.is_null()
    }

    async fn yocto(&self, a: &Account) -> u128 {
        a.view_account().await.unwrap().balance.as_yoctonear()
    }
}

/// The record a lazily opened single-key UA writes.
fn opened(s: &Signer, h: &Holder) -> u64 {
    record_bytes(h, &Subject { keys: vec![s.key()], ..Default::default() })
}

#[tokio::test]
async fn pay_meta_emits_meta_then_settled() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 1_000).await;
    let rows = paymeta();
    assert_eq!(rows.len(), 6);
    for (name, salt, meta) in &rows {
        let op = t.meta_op(&h, &bob, 10, salt, meta);
        let (c, out) = t.exec(&t.relayer, "mtx_pay_meta", &op, &erin.sign(&op, ORIGIN), &meta_params(salt, meta)).await;
        assert_eq!(c.error, None, "{name}");
        assert!(out.is_success(), "{name}: {:?}", out.failures());
        println!("mtx_pay_meta {name}: meta {} B, {:.3} Tgas", meta.len(), out.total_gas_burnt.as_gas() as f64 / 1e12);
        let (m, e, s) = (at(&out, "payment_meta"), at(&out, "meta_transaction_executed"), at(&out, "payment_settled"));
        assert!(m < s && e < s, "{name}: order {m} {e} {s}");
        let logs = out.logs();
        assert!(logs[m].contains(&format!(r#""pay_ref":"{}","meta":"{}""#, x(&op.pay_ref), x(meta))), "{}", logs[m]);
        let settled = format!(r#""from":"{h}","to":"{bob}","amount":"10","pay_ref":"{}""#, x(&op.pay_ref));
        assert!(logs[s].contains(&settled), "{}", logs[s]);
        let exe = format!(
            r#""from":"{h}","relayer":"{}","lane":"{}","nonce":0,"digest":"{}""#,
            t.relayer.id(),
            x(&op.lane),
            x(&op.digest())
        );
        assert!(logs[e].contains(&exe), "{}", logs[e]);
        assert_eq!(t.lane_nonce(&h, op.lane).await, 1, "{name}");
    }
    assert_eq!(t.balance(&bob).await, 60);
    assert_eq!(t.balance(&h).await, 940);
}

#[tokio::test]
async fn near_pay_meta_mismatch_and_replay() {
    let t = setup().await;
    let (erin, mallory, carol) = (Signer::ed("erin"), Signer::ed("mallory"), Signer::ed("carol"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    t.fund(&mallory.ua(), 1).await;
    t.fund(&carol.ua(), 100).await;
    let (_, salt, meta) = paymeta().remove(0);
    let good = t.meta_op(&h, &bob, 10, &salt, &meta);
    let a = erin.sign(&good, ORIGIN);
    let mut bad_salt = salt;
    bad_salt[0] ^= 1;
    t.refused(&t.relayer, "mtx_pay_meta", &good, &a, &meta_params(&bad_salt, &meta), SHAPE).await;
    t.refused(&t.relayer, "mtx_pay_meta", &good, &a, &meta_params(&salt, &[&meta[..], &[0]].concat()), SHAPE).await;
    let fs: [fn(&mut MetaOp); 2] = [|o| o.lane = [9; 32], |o| o.nonce = 1];
    for f in fs {
        let mut op = good.clone();
        f(&mut op);
        t.refused(&t.relayer, "mtx_pay_meta", &op, &erin.sign(&op, ORIGIN), &meta_params(&salt, &meta), SHAPE).await;
    }
    // an attacker's minimal pre-burn of the victim's payId uses the attacker's own lane: the victim still pays
    let burn = t.meta_op(&mallory.ua(), &bob, 1, &salt, &meta);
    t.ok(&t.relayer, "mtx_pay_meta", &burn, &mallory.sign(&burn, ORIGIN), &meta_params(&salt, &meta)).await;
    t.ok(&t.relayer, "mtx_pay_meta", &good, &a, &meta_params(&salt, &meta)).await;
    // a second pay-meta of the same (from, pay_ref), even a new signature, is refused; so is the plain pay of it
    t.refused(&t.relayer, "mtx_pay_meta", &good, &a, &meta_params(&salt, &meta), NONCE).await;
    let again = MetaOp { amount: 11, ..good.clone() };
    t.refused(&t.relayer, "mtx_pay_meta", &again, &erin.sign(&again, ORIGIN), &meta_params(&salt, &meta), NONCE).await;
    t.refused(&t.relayer, "mtx_pay", &again, &erin.sign(&again, ORIGIN), &[], NONCE).await;
    // the signed op is the plain pay: a plain pay of the payId consumes the lane the pay-meta needs
    let plain = t.meta_op(&carol.ua(), &bob, 5, &salt, &meta);
    let pa = carol.sign(&plain, ORIGIN);
    t.ok(&t.relayer, "mtx_pay", &plain, &pa, &[]).await;
    t.refused(&t.relayer, "mtx_pay_meta", &plain, &pa, &meta_params(&salt, &meta), NONCE).await;
    assert_eq!((t.balance(&bob).await, t.balance(&h).await), (16, 90));
}

#[tokio::test]
async fn pay_once_per_lane() {
    let t = setup().await;
    let (erin, carol) = (Signer::ed("erin"), Signer::ed("carol"));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    t.fund(&carol.ua(), 100).await;
    let lane = [0xa1; 32];
    let op0 = t.vop(OP_PAY, &h, &bob, 10, [1; 32], lane, 0);
    let a0 = erin.sign(&op0, ORIGIN);
    t.ok(&t.relayer, "mtx_pay", &op0, &a0, &[]).await;
    t.refused(&t.relayer, "mtx_pay", &op0, &a0, &[], NONCE).await;
    let op2 = t.vop(OP_PAY, &h, &bob, 10, [2; 32], lane, 2);
    t.refused(&t.relayer, "mtx_pay", &op2, &erin.sign(&op2, ORIGIN), &[], NONCE).await;
    let op1 = t.vop(OP_PAY, &h, &bob, 10, [2; 32], lane, 1);
    t.ok(&t.relayer, "mtx_pay", &op1, &erin.sign(&op1, ORIGIN), &[]).await;
    assert_eq!(t.lane_nonce(&h, lane).await, 2);
    // lanes are per payer: another payer's nonce 0 on the same lane id
    let c0 = t.vop(OP_PAY, &carol.ua(), &bob, 10, [1; 32], lane, 0);
    t.ok(&t.relayer, "mtx_pay", &c0, &carol.sign(&c0, ORIGIN), &[]).await;
    // a lane is shared by every value entry of its payer
    let tr = t.vop(OP_EXECUTE_TRANSFER, &h, &bob, 1, [0; 32], lane, 1);
    t.refused(&t.relayer, "mtx_execute_transfer", &tr, &erin.sign(&tr, ORIGIN), &[], NONCE).await;
    assert_eq!((t.balance(&bob).await, t.balance(&h).await), (30, 80));
}

#[tokio::test]
async fn relayer_bound_to_predecessor() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    let mut op = t.vop(OP_PAY, &h, &bob, 10, [1; 32], [0xa5; 32], 0);
    op.relayer = Some(t.relayer.id().as_str().parse().unwrap());
    let a = erin.sign(&op, ORIGIN);
    t.refused(&t.bob, "mtx_pay", &op, &a, &[], RELAYER).await;
    t.ok(&t.relayer, "mtx_pay", &op, &a, &[]).await;
}

#[tokio::test]
async fn near_wrapper_bound_pay_refused_direct() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    let token = Some(t.id().as_str().parse().unwrap());
    let op = MetaOp { relayer: token.clone(), ..t.vop(OP_PAY, &h, &bob, 10, [1; 32], [0xa5; 32], 0) };
    t.refused(&t.relayer, "mtx_pay", &op, &erin.sign(&op, ORIGIN), &[], RELAYER).await;
    let (_, salt, meta) = paymeta().remove(0);
    let op = MetaOp { relayer: token, ..t.meta_op(&h, &bob, 10, &salt, &meta) };
    t.refused(&t.relayer, "mtx_pay_meta", &op, &erin.sign(&op, ORIGIN), &meta_params(&salt, &meta), RELAYER).await;
    assert_eq!(t.balance(&h).await, 100);
}

#[tokio::test]
async fn pay_to_token_itself_refused() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let h = erin.ua();
    t.fund(&h, 100).await;
    let me = Holder::Near(t.id().as_str().parse().unwrap());
    let (_, salt, meta) = paymeta().remove(0);
    let cases = [
        ("mtx_pay", t.vop(OP_PAY, &h, &me, 10, [1; 32], [1; 32], 0), vec![]),
        ("mtx_transfer", t.vop(OP_TRANSFER, &h, &me, 10, [0; 32], [1; 32], 0), vec![]),
        ("mtx_execute_transfer", t.vop(OP_EXECUTE_TRANSFER, &h, &me, 10, [1; 32], [1; 32], 0), vec![]),
        ("mtx_pay_meta", t.meta_op(&h, &me, 10, &salt, &meta), meta_params(&salt, &meta)),
    ];
    for (entry, op, p) in cases {
        t.refused(&t.relayer, entry, &op, &erin.sign(&op, ORIGIN), &p, TO_SELF).await;
    }
    assert_eq!(t.balance(&h).await, 100);
}

#[tokio::test]
async fn transfer_to_unregistered_native_registers_from_deposit() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let h = erin.ua();
    t.fund(&h, 100).await;
    let fresh = t.w.dev_create_account().await.unwrap();
    assert!(!t.registered(&fresh).await);
    let to = t.near(&fresh);
    let op = t.vop(OP_TRANSFER, &h, &to, 40, [0; 32], [0x10; 32], 0);
    let cost = t.byte_cost().await;
    let (c, out) = t.exec(&t.relayer, "mtx_transfer", &op, &erin.sign(&op, ORIGIN), &[]).await;
    let bytes = opened(&erin, &h) + lane_bytes(&h) + ACCOUNT_STORAGE_BYTES;
    assert_eq!(c, Check { error: None, storage_needed: (bytes as u128 * cost).into() });
    assert!(out.is_success(), "{:?}", out.failures());
    assert!(t.registered(&fresh).await);
    assert_eq!(t.balance(&to).await, 40);
    assert!(out.logs().iter().any(|l| l.contains(r#""event":"ft_transfer""#) && l.contains(fresh.id().as_str())));
    assert!(!out.logs().iter().any(|l| l.contains("payment_settled")), "a transfer has no pay_ref");
    // a pay_ref on mtx_transfer is refused; mtx_execute_transfer carries one and settles it
    let op = t.vop(OP_TRANSFER, &h, &to, 1, [7; 32], [0x10; 32], 1);
    t.refused(&t.relayer, "mtx_transfer", &op, &erin.sign(&op, ORIGIN), &[], "mtx_transfer carries no pay_ref").await;
    let op = t.vop(OP_EXECUTE_TRANSFER, &h, &to, 1, [7; 32], [0x10; 32], 1);
    let (_, out) = t.exec(&t.relayer, "mtx_execute_transfer", &op, &erin.sign(&op, ORIGIN), &[]).await;
    assert!(out.is_success() && out.logs()[at(&out, "payment_settled")].contains(&x(&[7; 32])));
    let op = t.vop(OP_EXECUTE_TRANSFER, &h, &to, 1, [0; 32], [0x10; 32], 2);
    let (_, out) = t.exec(&t.relayer, "mtx_execute_transfer", &op, &erin.sign(&op, ORIGIN), &[]).await;
    assert!(out.is_success() && !out.logs().iter().any(|l| l.contains("payment_settled")));
    // each entry takes only its own op code; a pay needs a pay_ref
    let op = t.vop(OP_TRANSFER, &h, &to, 1, [0; 32], [0x10; 32], 3);
    t.refused(&t.relayer, "mtx_execute_transfer", &op, &erin.sign(&op, ORIGIN), &[], "wrong op code").await;
    let op = t.vop(OP_PAY, &h, &to, 1, [0; 32], [0x10; 32], 3);
    t.refused(&t.relayer, "mtx_pay", &op, &erin.sign(&op, ORIGIN), &[], "mtx_pay needs a pay_ref").await;
    assert_eq!(t.balance(&to).await, 42);
}

#[tokio::test]
async fn near_valid_until_is_seconds() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    let ns = t.w.view_block().await.unwrap().timestamp();
    let now = ns / 1_000_000_000;
    println!("block timestamp {ns} ns = {now} s");
    let mut op = t.vop(OP_PAY, &h, &bob, 10, [1; 32], [1; 32], 0);
    op.valid_until = now - 1;
    t.refused(&t.relayer, "mtx_pay", &op, &erin.sign(&op, ORIGIN), &[], "expired").await;
    op.valid_until = now + 60; // a ms or ns reading of block time would still refuse it
    let (c, out) = t.exec(&t.relayer, "mtx_pay", &op, &erin.sign(&op, ORIGIN), &[]).await;
    let at_s = t.w.view_block().await.unwrap().timestamp() / 1_000_000_000;
    assert_eq!(c.error, None);
    assert!(out.is_success(), "{:?} (block now {at_s} s)", out.failures());
}

#[tokio::test]
async fn near_check_storage_needed_is_exact() {
    let t = setup().await;
    let cost = t.byte_cost().await;
    let k = NearToken::from_near(1).as_yoctonear();
    let (_, _, meta) = paymeta().remove(1);
    for (n, entry) in ["mtx_pay", "mtx_pay_meta", "mtx_transfer", "mtx_execute_transfer"].into_iter().enumerate() {
        let (p1, p2) = (Signer::ed(&format!("{entry}-1")), Signer::ed(&format!("{entry}-2")));
        // even entries pay a new UA, odd ones a new native account
        let fresh = t.w.dev_create_account().await.unwrap();
        let (to, recv) = if n % 2 == 0 {
            (Signer::ed(&format!("{entry}-to")).ua(), UA_STORAGE_BYTES)
        } else {
            (t.near(&fresh), ACCOUNT_STORAGE_BYTES)
        };
        let op_of = |s: &Signer, lane: u8| match entry {
            "mtx_pay" => t.vop(OP_PAY, &s.ua(), &to, 10, [lane; 32], [lane; 32], 0),
            "mtx_pay_meta" => t.meta_op(&s.ua(), &to, 10, &[lane; 32], &meta),
            "mtx_transfer" => t.vop(OP_TRANSFER, &s.ua(), &to, 10, [0; 32], [lane; 32], 0),
            _ => t.vop(OP_EXECUTE_TRANSFER, &s.ua(), &to, 10, [lane; 32], [lane; 32], 0),
        };
        let params = |lane: u8| if entry == "mtx_pay_meta" { meta_params(&[lane; 32], &meta) } else { vec![] };
        for s in [&p1, &p2] {
            t.fund(&s.ua(), 100).await;
        }
        // p1 first: lazy open + lane + the receiver; one yocto short panics, + k refunds k
        let op = op_of(&p1, 1);
        let a = p1.sign(&op, ORIGIN);
        let c = t.check(&t.relayer, entry, &op, &a, &params(1)).await;
        let bytes = opened(&p1, &p1.ua()) + lane_bytes(&p1.ua()) + recv;
        assert_eq!(c, Check { error: None, storage_needed: (bytes as u128 * cost).into() }, "{entry}");
        let args = [b(&op), b(&a), params(1)].concat();
        let out = t.call(&t.relayer, entry, args.clone(), c.storage_needed.0 - 1).await;
        assert!(format!("{:?}", out.failures()).contains(SHORT), "{entry}: {:?}", out.failures());
        assert_eq!(t.lane_nonce(&p1.ua(), op.lane).await, 0, "{entry}");
        let (u0, y0) = (t.usage().await, t.yocto(&t.relayer).await);
        let out = t.call(&t.relayer, entry, args, c.storage_needed.0 + k).await;
        assert!(out.is_success(), "{entry}: {:?}", out.failures());
        let spent = y0 - t.yocto(&t.relayer).await;
        assert!(spent >= c.storage_needed.0 && spent < c.storage_needed.0 + k / 20, "{entry}: excess kept, spent {spent}");
        let grew = t.usage().await - u0;
        println!("{entry}: first op {bytes} B charged ({grew} B measured), {} yocto", c.storage_needed.0);
        if n % 2 == 0 {
            assert_eq!(grew, bytes, "{entry}: measured bytes");
        } else {
            assert!(grew <= bytes && grew > bytes - recv, "{entry}: {grew}"); // NEP-145 charges the 64-char id
        }
        // p2 to the now-existing receiver: lazy open + lane, attached exactly storage_needed
        let op = op_of(&p2, 2);
        let a = p2.sign(&op, ORIGIN);
        let c = t.check(&t.relayer, entry, &op, &a, &params(2)).await;
        let bytes = opened(&p2, &p2.ua()) + lane_bytes(&p2.ua());
        assert_eq!(c.storage_needed.0, bytes as u128 * cost, "{entry}");
        let u0 = t.usage().await;
        let out = t.call(&t.relayer, entry, [b(&op), b(&a), params(2)].concat(), c.storage_needed.0).await;
        assert!(out.is_success(), "{entry}: {:?}", out.failures());
        assert_eq!(t.usage().await - u0, bytes, "{entry}");
        // p2's next op on a used lane of an open record: nothing new, 0 attached
        let mut op = op_of(&p2, 2);
        op.nonce = 1;
        if entry == "mtx_pay_meta" {
            continue; // a pay-meta lane is used once
        }
        let a = p2.sign(&op, ORIGIN);
        let c = t.check(&t.relayer, entry, &op, &a, &[]).await;
        assert_eq!(c, Check { error: None, storage_needed: 0.into() }, "{entry}");
        let out = t.call(&t.relayer, entry, [b(&op), b(&a)].concat(), 0).await;
        assert!(out.is_success(), "{entry}: {:?}", out.failures());
    }
}

#[tokio::test]
async fn batch_of_actions_atomic() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    let lane = [0xb1; 32];
    let dep = NearToken::from_millinear(100);
    let action = |op: &MetaOp| {
        Function::new("mtx_pay").args([b(op), b(&erin.sign(op, ORIGIN))].concat()).deposit(dep).gas(Gas::from_tgas(100))
    };
    let op0 = t.vop(OP_PAY, &h, &bob, 10, [1; 32], lane, 0);
    let bad = t.vop(OP_PAY, &h, &bob, 10, [2; 32], lane, 5);
    let out = t.relayer.batch(t.token.id()).call(action(&op0)).call(action(&bad)).transact().await.unwrap();
    assert!(format!("{:?}", out.failures()).contains(NONCE), "{:?}", out.failures());
    assert_eq!(t.lane_nonce(&h, lane).await, 0);
    assert_eq!(t.subject(&h).await, None, "the lazy open is undone too");
    assert_eq!((t.balance(&h).await, t.balance(&bob).await), (100, 0));
    assert!(!t.registered(&t.bob).await);
    let op1 = t.vop(OP_PAY, &h, &bob, 10, [2; 32], lane, 1);
    let out = t.relayer.batch(t.token.id()).call(action(&op0)).call(action(&op1)).transact().await.unwrap();
    assert!(out.is_success(), "{:?}", out.failures());
    println!("batch of two mtx_pay: {:.3} Tgas", out.total_gas_burnt.as_gas() as f64 / 1e12);
    assert_eq!(t.lane_nonce(&h, lane).await, 2);
    assert_eq!((t.balance(&h).await, t.balance(&bob).await), (80, 20));
}

/// Ruling R8 (NET-ALL-23 item 3): with POLICY_PASSKEY_FOR_VALUE set, every value entry needs a passkey signature;
/// wallet keys still authorise key ops.
#[tokio::test]
async fn policy_passkey_for_value() {
    let t = setup().await;
    let (erin, pk) = (Signer::ed("erin"), Signer::pk(4, RP));
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 100).await;
    let p = b(&(pk.key(), Some(ORIGIN.to_string())));
    let op = t.op(OP_ADD_KEY, &h, &h, 0, &p);
    t.ok(&t.relayer, "mtx_add_key", &op, &erin.sign(&op, ORIGIN), &p).await;
    let op = t.op(OP_SET_GUARDIAN, &h, &h, 1, &[KEYOP_SET_POLICY, POLICY_PASSKEY_FOR_VALUE]);
    t.ok(&t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &b(&POLICY_PASSKEY_FOR_VALUE)).await;
    let (_, salt, meta) = paymeta().remove(0);
    let cases = [
        ("mtx_pay", t.vop(OP_PAY, &h, &bob, 10, [1; 32], [1; 32], 0), vec![]),
        ("mtx_transfer", t.vop(OP_TRANSFER, &h, &bob, 10, [0; 32], [2; 32], 0), vec![]),
        ("mtx_execute_transfer", t.vop(OP_EXECUTE_TRANSFER, &h, &bob, 10, [1; 32], [3; 32], 0), vec![]),
        ("mtx_pay_meta", t.meta_op(&h, &bob, 10, &salt, &meta), meta_params(&salt, &meta)),
    ];
    for (entry, op, p) in &cases {
        t.refused(&t.relayer, entry, op, &erin.sign(op, ORIGIN), p, POLICY).await;
    }
    for (entry, op, p) in &cases {
        t.ok(&t.relayer, entry, op, &pk.sign(op, ORIGIN), p).await;
    }
    assert_eq!((t.balance(&h).await, t.balance(&bob).await), (60, 40));
    // the wallet key still authorises a key op
    t.set_guardian(&t.relayer, &erin, &h, 2, Some(bob.clone())).await;
}

/// No contract cap on `meta` (metatx-split §6.2: bounded by the chain): the largest `meta` that settles is set by
/// NEAR's per-receipt log limit (the hex `payment_meta` log); measured and pinned here.
#[tokio::test]
async fn pay_meta_size_bound_measured() {
    let t = setup().await;
    let erin = Signer::ed("erin");
    let (h, bob) = (erin.ua(), t.near(&t.bob));
    t.fund(&h, 1_000).await;
    let salt = [0x42; 32];
    let (mut lo, mut hi) = (4_192usize, 16_384usize); // long_body_4096 settles (pay_meta_emits_meta_then_settled)
    let (mut last, mut settled, mut failed_lane) = (String::new(), 0u128, [0; 32]);
    while hi - lo > 1 {
        let mid = (lo + hi) / 2;
        let meta = vec![0x5a; mid];
        let op = t.meta_op(&h, &bob, 1, &salt, &meta);
        let (c, out) = t.exec(&t.relayer, "mtx_pay_meta", &op, &erin.sign(&op, ORIGIN), &meta_params(&salt, &meta)).await;
        assert_eq!(c.error, None);
        if out.is_success() {
            (lo, settled) = (mid, settled + 1);
        } else {
            (last, hi, failed_lane) = (format!("{:?}", out.failures()), mid, op.lane);
        }
    }
    // a failed pay-meta leaves its lane unused and moves nothing (its logs stay in the failed outcome: NET-NEAR-07)
    assert_eq!(t.lane_nonce(&h, failed_lane).await, 0);
    assert_eq!((t.balance(&h).await, t.balance(&bob).await), (1_000 - settled, settled));
    println!("largest meta that settles: {lo} B; {} B fails: {last}", lo + 1);
    assert!(last.contains("exceeds the limit 16384"), "{last}");
    assert!(last.contains("payment_meta"), "a failed receipt keeps its logs (NET-NEAR-07): {last}");
    assert_eq!(lo, MAX_META_SETTLED);
}

/// Measured by `pay_meta_size_bound_measured` (ed25519 UA payer, dev-account payee and relayer): the receipt's logs
/// (`payment_meta` carries `meta` as hex) reach NEAR's 16,384 B log limit at 7,541 B of `meta`.
const MAX_META_SETTLED: usize = 7_540;
