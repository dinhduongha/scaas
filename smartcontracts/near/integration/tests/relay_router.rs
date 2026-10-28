//! Task 10 (spec §3.8 "Escrow router", §2 rows 8–14; CTR-MTX-16, CTR-MTX-27; rulings R2, R10, T10 pre-flight a–g): the
//! NEAR escrow relay-fee router. One `relay(target, method, args, target_gas, target_deposit, token, op, auth)`
//! transaction: the router records `pending[ref]`, the token holds the payer's router-bound payment
//! (`relay_hold`), the executor calls the target (the target sees the executor), and `on_call` releases on the target's
//! own success or refunds otherwise; `on_settle` deletes the entry and returns its deposit to the relayer. `relay_timeout`
//! (anyone, after the deadline) refunds; a late callback pays nothing. One sandbox per test; the test-only target fixture
//! (`integration/target-fixture`) succeeds, panics, spawns or returns a failing child, or waits (yield). A call cannot
//! stay in flight with the real executor (it returns the target's own receipt), so the timeout tests run a second router
//! whose executor is the fixture, whose `exec` waits until `resume` (a slow or lost call, staged).
mod common;
use common::*;
use near_sdk::json_types::U128;
use near_workspaces::types::Gas;
use scaas_near_common::hash::{hex, pay_lane};
use scaas_near_relayfee::{
    call_gas, call_ref, hold_gas, relay_gas, Check as RCheck, Pending, Stage, GAS_EXEC, GAS_HOLD, GAS_ON_CALL, GAS_ON_HOLD,
    GAS_ON_SETTLE, GAS_RELAY, GAS_RELEASE, PAYEE_REGISTRATION_BYTES, RELAY_TIMEOUT_S,
};
use scaas_near_token::{held_bytes, Held};

const ROUTER_WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_relayfee/scaas_near_relayfee.wasm");
const EXEC_WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_relayexec/scaas_near_relayexec.wasm");
const FX_WASM: &str =
    concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_target_fixture/scaas_near_target_fixture.wasm");
const FEE: u128 = 10;
const SALT: [u8; 32] = [0x5a; 32];
const TARGET_TGAS: u64 = 20;
/// A target deposit the tests can tell apart from gas rewards (0.01 NEAR).
const TD: u128 = 10_000_000_000_000_000_000_000;
const SHAPE: &str = "relay pay shape (op 0, pay_ref = ref, lane = payLane(ref), nonce 0, relayer = the router)";
const ROUTER_OR_EXEC: &str = "target or token is the router or its executor";
const PAY_EXEC: &str = "the executor is never paid";
const SHORT_GAS: &str = "prepaid gas below the relay minimum (hold, call, callbacks)";
const SHORT_DEPOSIT: &str = "attached deposit below the escrow entry, a payee registration, 2 yoctoNEAR and target_deposit";
const BEFORE_DEADLINE: &str = "relay_timeout before the deadline";
const NO_PENDING: &str = "no such pending ref";
const ARGS_CAP: &str = "args over 16,384 bytes";
const PASSKEY_CAP: &str = "passkey clientDataJSON / authenticatorData over 1024 bytes";
const IN_FLIGHT: &str = "this ref is already in flight";
const METHOD_LEN: &str = "method name: 1 to 255 bytes";
const OTHER_TOKEN: &str = "the payment op is not for this token";

fn acc(a: &AccountId) -> near_sdk::AccountId {
    a.as_str().parse().unwrap()
}

fn has(out: &ExecutionFinalResult, s: &str) -> bool {
    out.logs().iter().any(|l| l.contains(s))
}

fn failed_with(out: &ExecutionFinalResult, err: &str) -> bool {
    format!("{:?}", out.failures()).contains(err)
}

fn tg(g: u64) -> f64 {
    g as f64 / 1e12
}

/// One relay job: the call and the payer's router-bound payment.
#[derive(Clone)]
struct Job {
    target: near_sdk::AccountId,
    method: String,
    args: Vec<u8>,
    target_gas: Gas,
    target_deposit: u128,
    op: MetaOp,
    auth: Auth,
}

struct R {
    t: T,
    router: Contract,
    exec: Contract,
    fx: Contract,
}

/// The NEAR balance and storage of the router and the executor.
#[derive(Debug, Clone, Copy)]
struct Snap {
    router: (u128, u64),
    exec: (u128, u64),
}

fn read(p: &str) -> Vec<u8> {
    std::fs::read(p).expect("run build.sh near first")
}

async fn deploy_router(w: &Worker<Sandbox>, executor: &AccountId) -> Contract {
    let router = w.dev_deploy(&read(ROUTER_WASM)).await.unwrap();
    router.call("new").args(b(&acc(executor))).transact().await.unwrap().into_result().unwrap();
    router
}

async fn setup_router() -> R {
    let t = setup().await;
    let exec = t.w.dev_deploy(&read(EXEC_WASM)).await.unwrap();
    let fx = t.w.dev_deploy(&read(FX_WASM)).await.unwrap();
    let router = deploy_router(&t.w, exec.id()).await;
    exec.call("new").args(b(&acc(router.id()))).transact().await.unwrap().into_result().unwrap();
    R { t, router, exec, fx }
}

/// A router whose executor is the fixture (its `exec` waits until `resume`): the call stays in flight.
async fn setup_slow() -> R {
    let r = setup_router().await;
    r.slow().await
}

impl R {
    /// Another router on the same token, its executor the fixture (calls stay in flight until `resume`).
    async fn slow(&self) -> R {
        let t = &self.t;
        let t = T { w: t.w.clone(), token: t.token.clone(), relayer: t.relayer.clone(), alice: t.alice.clone(), bob: t.bob.clone() };
        R { router: deploy_router(&t.w, self.fx.id()).await, t, exec: self.exec.clone(), fx: self.fx.clone() }
    }

    /// A slow router's job: any target (the fixture-executor never calls it), paid by `s` in open mode.
    fn slow_job(&self, s: &Signer, td: u128) -> Job {
        self.job(s, &self.open(), acc(self.t.alice.id()), "anything", vec![], td)
    }

    fn rid(&self) -> near_sdk::AccountId {
        acc(self.router.id())
    }

    fn eid(&self) -> near_sdk::AccountId {
        acc(self.exec.id())
    }

    fn fid(&self) -> near_sdk::AccountId {
        acc(self.fx.id())
    }

    /// Open mode: `to` = the router (the submitting relayer is paid).
    fn open(&self) -> Holder {
        Holder::Near(self.rid())
    }

    /// The payment of `FEE` from `s`'s UA to `to` for the call `target.method(args)`, salt `SALT`.
    fn job(&self, s: &Signer, to: &Holder, target: near_sdk::AccountId, method: &str, args: Vec<u8>, td: u128) -> Job {
        let r = call_ref(&NETWORK, &target, method, &args, &SALT);
        let op = MetaOp { amount: FEE, pay_ref: r, lane: pay_lane(&r), relayer: Some(self.rid()), extra: SALT, ..self.t.op(OP_PAY, &s.ua(), to, 0, &[]) };
        Job { target, method: method.into(), args, target_gas: Gas::from_tgas(TARGET_TGAS), target_deposit: td, auth: s.sign(&op, ORIGIN), op }
    }

    /// A fixture call `method` paid by `s` (open mode).
    fn fx_job(&self, s: &Signer, method: &str, td: u128) -> Job {
        self.job(s, &self.open(), self.fid(), method, vec![], td)
    }

    fn resign(&self, s: &Signer, mut j: Job, f: impl FnOnce(&mut MetaOp)) -> Job {
        f(&mut j.op);
        j.auth = s.sign(&j.op, ORIGIN);
        j
    }

    /// `j` with the payment's salt (`extra`) `salt` and the ref / lane that go with it.
    fn salted(&self, s: &Signer, j: Job, salt: [u8; 32]) -> Job {
        let r = call_ref(&NETWORK, &j.target, &j.method, &j.args, &salt);
        self.resign(s, j, |o| {
            o.extra = salt;
            o.pay_ref = r;
            o.lane = pay_lane(&r);
        })
    }

    fn args(&self, j: &Job) -> Vec<u8> {
        b(&(&j.target, &j.method, &j.args, j.target_gas, U128(j.target_deposit), acc(self.t.token.id()), &j.op, &j.auth))
    }

    async fn check(&self, j: &Job) -> RCheck {
        self.router.view("relay_check").args(self.args(j)).await.unwrap().borsh().unwrap()
    }

    async fn hold_check(&self, who: &Account, j: &Job) -> Check {
        let args = b(&(self.rid(), acc(who.id()), &j.op, &j.auth));
        self.t.token.view("relay_hold_check").args(args).await.unwrap().borsh().unwrap()
    }

    /// The relayer's quote: the router's `deposit_needed` plus the token's hold storage.
    async fn deposit(&self, who: &Account, j: &Job) -> u128 {
        let (rc, hc) = (self.check(j).await, self.hold_check(who, j).await);
        assert_eq!((rc.error.clone(), hc.error.clone()), (None, None), "quote");
        rc.deposit_needed.0 + hc.storage_needed.0
    }

    async fn relay_with(&self, who: &Account, j: &Job, deposit: u128, gas: Gas) -> ExecutionFinalResult {
        let out = who.call(self.router.id(), "relay").args(self.args(j)).deposit(NearToken::from_yoctonear(deposit)).gas(gas)
            .transact().await.unwrap();
        println!("relay {} by {}: {:.3} Tgas, ok {}", j.method, who.id(), tgas(&out), out.is_success());
        out
    }

    /// `relay` with the quoted deposit at exactly `relay_gas` prepaid.
    async fn relay(&self, who: &Account, j: &Job) -> ExecutionFinalResult {
        let d = self.deposit(who, j).await;
        self.relay_with(who, j, d, relay_gas(&j.auth, j.target_gas)).await
    }

    /// `relay` refused at the router with `err` (the check reports it too): nothing held, the payer's lane unused.
    async fn refused(&self, who: &Account, j: &Job, err: &str) {
        let c = self.check(j).await;
        assert!(c.error.as_deref().is_some_and(|e| e.contains(err)), "check {:?}, want {err}", c.error);
        let out = self.relay_with(who, j, NearToken::from_near(1).as_yoctonear(), Gas::from_tgas(300)).await;
        assert!(out.is_failure() && failed_with(&out, err), "{:?}", out.failures());
        self.nothing_held(j).await;
    }

    async fn nothing_held(&self, j: &Job) {
        assert_eq!(self.pending(j.op.pay_ref).await, None, "no pending entry");
        assert_eq!(self.held(j.op.pay_ref).await, None, "nothing held");
        assert_eq!(self.t.lane_nonce(&j.op.from, j.op.lane).await, 0, "the payment's lane unused");
    }

    async fn pending(&self, r: [u8; 32]) -> Option<Pending> {
        self.router.view("pending").args(b(&r)).await.unwrap().borsh().unwrap()
    }

    async fn held(&self, r: [u8; 32]) -> Option<Held> {
        self.t.token.view("relay_held").args(b(&(self.rid(), r))).await.unwrap().borsh().unwrap()
    }

    async fn timeout(&self, who: &Account, r: [u8; 32]) -> ExecutionFinalResult {
        let out = who.call(self.router.id(), "relay_timeout").args(b(&r)).max_gas().transact().await.unwrap();
        println!("relay_timeout by {}: {:.3} Tgas, ok {}", who.id(), tgas(&out), out.is_success());
        out
    }

    /// The pending entry under key `p` ‖ ref (the sandbox clock cannot jump to a deadline).
    async fn patch(&self, r: [u8; 32], f: impl FnOnce(&mut Pending)) {
        let mut p = self.pending(r).await.unwrap();
        f(&mut p);
        self.t.w.patch_state(self.router.id(), &[b"p".as_slice(), &r].concat(), &b(&p)).await.unwrap();
    }

    async fn near(&self, a: &AccountId) -> u128 {
        self.t.w.view_account(a).await.unwrap().balance.as_yoctonear()
    }

    async fn usage_of(&self, c: &Contract) -> u64 {
        c.view_account().await.unwrap().storage_usage
    }

    async fn snap(&self) -> Snap {
        Snap {
            router: (self.near(self.router.id()).await, self.usage_of(&self.router).await),
            exec: (self.near(self.exec.id()).await, self.usage_of(&self.exec).await),
        }
    }

    /// After every receipt of `outs`: the router keeps no entry, its storage is back and its balance grew by its gas reward
    /// only (≤ 30 % of what its receipts burnt); the executor likewise holds nothing above its stake.
    async fn settled(&self, s0: Snap, outs: &[&ExecutionFinalResult], r: [u8; 32]) {
        let reward = |id: &AccountId| -> u128 {
            outs.iter().flat_map(|o| o.receipt_outcomes()).filter(|o| o.executor_id == *id).map(|o| o.tokens_burnt.as_yoctonear()).sum::<u128>()
                * 3 / 10
        };
        let s1 = self.snap().await;
        assert_eq!(self.pending(r).await, None, "the escrow holds nothing once settled");
        assert_eq!(self.held(r).await, None, "the token holds nothing for the router");
        assert_eq!(s1.router.1, s0.router.1, "router storage back");
        let (dr, rr) = (s1.router.0 as i128 - s0.router.0 as i128, reward(self.router.id()));
        assert!(dr >= 0 && dr as u128 <= rr, "router balance moved {dr} yocto (gas reward ≤ {rr})");
        assert_eq!(s1.exec.1, s0.exec.1, "executor storage unchanged");
        let (de, re) = (s1.exec.0 as i128 - s0.exec.0 as i128, reward(self.exec.id()));
        assert!(de >= 0 && de as u128 <= re, "executor balance moved {de} yocto (gas reward ≤ {re})");
    }

    /// A refused hold sent its whole deposit back to the relayer: the token's NEAR moved by its gas reward only (≤ 30 %
    /// of what its receipts burnt) and its storage is unchanged (review m2).
    async fn token_kept_nothing(&self, t0: (u128, u64), out: &ExecutionFinalResult) {
        let reward = out.receipt_outcomes().iter().filter(|o| o.executor_id == *self.t.token.id()).map(|o| o.tokens_burnt.as_yoctonear()).sum::<u128>() * 3 / 10;
        let t1 = (self.near(self.t.token.id()).await, self.t.usage().await);
        let d = t1.0 as i128 - t0.0 as i128;
        assert!(d >= 0 && d as u128 <= reward, "token kept {d} yocto of the refused hold's deposit (gas reward ≤ {reward})");
        assert_eq!(t1.1, t0.1, "token storage unchanged");
    }

    async fn token_near(&self) -> (u128, u64) {
        (self.near(self.t.token.id()).await, self.t.usage().await)
    }

    /// A funded UA payer (ed25519 key `seed`), `FEE * 10` tokens.
    async fn payer(&self, seed: &str) -> Signer {
        let s = Signer::ed(seed);
        self.t.fund(&s.ua(), FEE * 10).await;
        s
    }

    /// Starts `j` (on a slow router) without waiting for its outcome; returns once the call is in flight (stage `Call`).
    async fn in_flight(&self, who: &Account, j: &Job) -> near_workspaces::operations::TransactionStatus {
        let d = self.deposit(who, j).await;
        let st = who.call(self.router.id(), "relay").args(self.args(j)).deposit(NearToken::from_yoctonear(d))
            .gas(relay_gas(&j.auth, j.target_gas)).transact_async().await.unwrap();
        for _ in 0..120 {
            if self.pending(j.op.pay_ref).await.is_some_and(|p| p.stage == Stage::Call) {
                return st;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        panic!("the call never got in flight");
    }

    /// The fixture-executor's `return_deposit` count once it reaches `want` (or after ~5 s): a late callback's detached
    /// receipts may run after the relay transaction's outcome is final.
    async fn returns(&self, want: u32) -> u32 {
        let mut n = 0;
        for _ in 0..20 {
            n = self.fx.view("returns").await.unwrap().json().unwrap();
            if n == want && want > 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(250)).await;
        }
        n
    }

    async fn resume(&self, ok: bool) {
        let out = self.t.alice.call(self.fx.id(), "resume").args_json(json!({ "ok": ok })).max_gas().transact().await.unwrap();
        assert!(out.is_success(), "{:?}", out.failures());
    }

    /// The token's `bob`-style native holder of an account.
    fn h(&self, a: &Account) -> Holder {
        self.t.near(a)
    }
}

fn final_bool(out: &ExecutionFinalResult) -> bool {
    out.clone().borsh::<bool>().unwrap()
}

/// The target succeeded: the payment is released to the payee (open mode: the relayer), `payment_settled` and
/// `relay_fee_paid` carry `ref`, the transaction's value is `true`; the target saw the executor and got
/// `target_deposit`. `relay_check` quotes the entry's real deposit and the gas `relay` requires.
#[tokio::test]
async fn release_on_success() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.fx_job(&p, "ok", TD);
    let rc = r.check(&j).await;
    assert_eq!(rc.gas_needed, relay_gas(&j.auth, j.target_gas));
    let (s0, relayer) = (r.snap().await, r.h(&r.t.relayer));
    let (u0, fx0) = (r.t.usage().await, r.near(r.fx.id()).await);
    let out = r.relay(&r.t.relayer, &j).await;
    assert!(out.is_success() && final_bool(&out), "{:?}", out.failures());
    assert!(out.receipt_outcomes().iter().all(|o| o.is_success()), "{:?}", out.failures());
    for o in out.receipt_outcomes() {
        println!("  receipt {} {:.3} Tgas {:?}", o.executor_id, tg(o.gas_burnt.as_gas()), o.logs.first());
    }
    assert_eq!((r.t.balance(&j.op.from).await, r.t.balance(&relayer).await), (FEE * 9, FEE), "released to the relayer");
    let x = hex(&j.op.pay_ref);
    assert!(has(&out, &format!(r#""event":"payment_settled","data":{{"from":"{}","to":"{}","amount":"{FEE}","pay_ref":"0x{x}"}}"#, j.op.from, relayer)), "{:?}", out.logs());
    let paid = format!(
        r#""event":"relay_fee_paid","data":{{"ref":"0x{x}","target":"{}","token":"{}","payer":"{}","payee":"{}","amount":"{FEE}"}}"#,
        r.fx.id(), r.t.token.id(), j.op.from, relayer
    );
    assert!(has(&out, &paid), "{:?}", out.logs());
    assert!(has(&out, &format!("fixture ok: predecessor {} deposit {TD}", r.exec.id())), "the target sees the executor");
    assert!(r.near(r.fx.id()).await >= fx0 + TD, "target_deposit forwarded");
    r.settled(s0, &[&out], j.op.pay_ref).await;
    // the relayer pays storage: the payer's subject, lane and the relayer's registration stay; the held record is gone
    let s = Subject { keys: vec![p.key()], ..Default::default() };
    let short = 64 - r.t.relayer.id().as_str().len() as u64;
    let perm = record_bytes(&j.op.from, &s) + scaas_near_token::lane_bytes(&j.op.from) + scaas_near_token::ACCOUNT_STORAGE_BYTES;
    assert_eq!(r.t.usage().await - u0, perm - short, "permanent records only");
    // once settled the payment cannot be relayed again (the lane is consumed)
    let out = r.relay_with(&r.t.relayer, &j, NearToken::from_near(1).as_yoctonear(), Gas::from_tgas(300)).await;
    assert!(out.is_success() && !final_bool(&out), "hold refused: wrong lane nonce");
    assert!(has(&out, "relay_hold refused: wrong lane nonce"), "{:?}", out.logs());
    assert_eq!(r.t.balance(&j.op.from).await, FEE * 9);
}

/// The target panics: the payment goes back to the payer (the lane stays consumed), no `payment_settled`, no
/// `relay_fee_paid`; the transaction's value is `false`.
#[tokio::test]
async fn refund_on_target_panic() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.fx_job(&p, "fail", 0);
    let s0 = r.snap().await;
    let out = r.relay(&r.t.relayer, &j).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert!(failed_with(&out, "fixture fail"), "the target failed: {:?}", out.failures());
    assert_eq!((r.t.balance(&j.op.from).await, r.t.balance(&r.h(&r.t.relayer)).await), (FEE * 10, 0), "refunded");
    assert!(!has(&out, "payment_settled") && !has(&out, "relay_fee_paid"), "{:?}", out.logs());
    assert_eq!(r.t.lane_nonce(&j.op.from, j.op.lane).await, 1, "pay-once: the lane stays consumed");
    r.settled(s0, &[&out], j.op.pay_ref).await;
}

/// A target account without code (the call cannot succeed): refunded.
#[tokio::test]
async fn refund_on_missing_code() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.job(&p, &r.open(), acc(r.t.bob.id()), "anything", vec![], 0);
    let s0 = r.snap().await;
    let out = r.relay(&r.t.relayer, &j).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert_eq!(r.t.balance(&j.op.from).await, FEE * 10, "refunded");
    assert!(!has(&out, "relay_fee_paid"));
    r.settled(s0, &[&out], j.op.pay_ref).await;
}

/// Ruling (e): success = the target's own receipt succeeded. A target that succeeds but spawns a failing child promise
/// counts as success: released — whether it detaches the child or returns it (its result is not read).
#[tokio::test]
async fn target_success_with_failing_child_releases() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    for (n, m) in ["spawn_fail", "return_fail"].into_iter().enumerate() {
        let j = r.fx_job(&p, m, 0);
        let out = r.relay(&r.t.relayer, &j).await;
        assert!(out.is_success() && final_bool(&out), "{m}: {:?}", out.failures());
        assert!(failed_with(&out, "fixture fail"), "{m}: the child failed: {:?}", out.failures());
        assert_eq!(r.t.balance(&r.h(&r.t.relayer)).await, FEE * (n as u128 + 1), "{m}: released");
        assert!(has(&out, "relay_fee_paid"), "{m}");
    }
}

/// The hold refused (the payer's balance is short): `on_hold` deletes `pending`, the target is never called, every
/// deposit goes back to the relayer.
#[tokio::test]
async fn hold_failure_clears_pending() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.resign(&p, r.fx_job(&p, "ok", TD), |o| o.amount = FEE * 11);
    let (s0, t0) = (r.snap().await, r.token_near().await);
    let d = r.check(&j).await.deposit_needed.0 + NearToken::from_millinear(10).as_yoctonear();
    let out = r.relay_with(&r.t.relayer, &j, d, relay_gas(&j.auth, j.target_gas)).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert!(has(&out, "relay_hold refused: The UA doesn't have enough balance"), "{:?}", out.logs());
    r.token_kept_nothing(t0, &out).await;
    assert!(!out.receipt_outcomes().iter().any(|o| o.executor_id == *r.fx.id() || o.executor_id == *r.exec.id()), "no call");
    assert_eq!(r.t.balance(&j.op.from).await, FEE * 10);
    r.nothing_held(&j).await;
    r.settled(s0, &[&out], j.op.pay_ref).await;
}

/// Ruling R10 / (b): the router's floor is the escrow entry + a payee registration + 2 yoctoNEAR + `target_deposit`; one
/// yoctoNEAR less is refused at `relay`. At the floor, a hold whose own storage (the payer's first records) needs more is
/// refused by the token: nothing held, the deposit back.
#[tokio::test]
async fn short_deposit_refused() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.fx_job(&p, "ok", TD);
    let rc = r.check(&j).await;
    let floor = rc.storage_needed.0 + PAYEE_REGISTRATION_BYTES as u128 * r.t.byte_cost().await + 2 + TD;
    assert_eq!(rc.deposit_needed.0, floor);
    let gas = relay_gas(&j.auth, j.target_gas);
    // relay_check quotes a 64-char relayer; the real entry is smaller by the id's shortfall
    let short = (64 - r.t.relayer.id().as_str().len()) as u128 * r.t.byte_cost().await;
    let out = r.relay_with(&r.t.relayer, &j, floor - short - 1, gas).await;
    assert!(out.is_failure() && failed_with(&out, SHORT_DEPOSIT), "{:?}", out.failures());
    r.nothing_held(&j).await;
    let (s0, t0) = (r.snap().await, r.token_near().await);
    let out = r.relay_with(&r.t.relayer, &j, floor - short, gas).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert!(has(&out, "relay_hold refused: the attached deposit is short of the hold's storage"), "{:?}", out.logs());
    r.token_kept_nothing(t0, &out).await;
    r.nothing_held(&j).await;
    r.settled(s0, &[&out], j.op.pay_ref).await;
}

/// The call in flight (a waiting target): `relay_timeout` before the deadline is refused; the entry stays; the call then
/// finishes normally.
#[tokio::test]
async fn timeout_refund_refused_before_deadline() {
    let r = setup_slow().await;
    let p = r.payer("p1").await;
    let j = r.slow_job(&p, 0);
    let st = r.in_flight(&r.t.relayer, &j).await;
    let pd = r.pending(j.op.pay_ref).await.unwrap();
    let now = r.t.now_s().await;
    assert!(pd.deadline >= now + RELAY_TIMEOUT_S - 60 && pd.deadline <= now + RELAY_TIMEOUT_S, "deadline = relay time + 3,600 s");
    assert_eq!(r.held(j.op.pay_ref).await.map(|h| h.amount), Some(FEE), "held while the call is in flight");
    let short = (64 - r.t.relayer.id().as_str().len()) as u128 * r.t.byte_cost().await;
    let quote = r.check(&r.salted(&p, r.slow_job(&p, 0), [0x60; 32])).await.storage_needed.0;
    assert_eq!(pd.deposit, quote - short, "relay_check quotes the entry (64-char relayer)");
    let (cost, hd) = (r.t.byte_cost().await, r.held(j.op.pay_ref).await.unwrap());
    assert_eq!(hd.deposit, held_bytes(&r.rid(), &hd) as u128 * cost, "the held record's deposit = its bytes");
    println!(
        "STORAGE router entry {} B (open mode, UA payer, {}-char token / target / relayer ids; relay_check quotes {} B), held record {} B",
        pd.deposit / cost, r.t.token.id().as_str().len(), quote / cost, hd.deposit / cost
    );
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(out.is_failure() && failed_with(&out, BEFORE_DEADLINE), "{:?}", out.failures());
    // the same ref again while in flight: refused, the live entry untouched
    let c = r.check(&j).await;
    assert_eq!(c.error.as_deref(), Some(IN_FLIGHT));
    let out = r.relay_with(&r.t.relayer, &j, NearToken::from_near(1).as_yoctonear(), Gas::from_tgas(300)).await;
    assert!(out.is_failure() && failed_with(&out, IN_FLIGHT), "{:?}", out.failures());
    assert_eq!(r.pending(j.op.pay_ref).await, Some(pd.clone()));
    r.patch(j.op.pay_ref, |p| p.deadline = now + 3_600).await;
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(failed_with(&out, BEFORE_DEADLINE), "{:?}", out.failures());
    r.resume(true).await;
    let out = st.await.unwrap();
    assert!(out.is_success() && final_bool(&out), "{:?}", out.failures());
    assert_eq!(r.t.balance(&r.h(&r.t.relayer)).await, FEE, "released");
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(failed_with(&out, NO_PENDING), "{:?}", out.failures());
}

/// After the deadline anyone refunds an entry whose call is still in flight; the relayer gets the entry and held-record
/// deposits back; the call's late failure asks the executor to return `target_deposit` (and pays nothing).
#[tokio::test]
async fn timeout_refunds_after_deadline() {
    let r = setup_slow().await;
    let p = r.payer("p1").await;
    let j = r.slow_job(&p, TD);
    let s0 = r.snap().await;
    let st = r.in_flight(&r.t.relayer, &j).await;
    let (pd, hd) = (r.pending(j.op.pay_ref).await.unwrap(), r.held(j.op.pay_ref).await.unwrap());
    let now = r.t.now_s().await;
    r.patch(j.op.pay_ref, |p| p.deadline = now - 1).await;
    let r0 = r.near(r.t.relayer.id()).await;
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert!(out.receipt_outcomes().iter().all(|o| o.is_success()), "{:?}", out.failures());
    assert_eq!(r.t.balance(&j.op.from).await, FEE * 10, "refunded");
    assert_eq!((r.pending(j.op.pay_ref).await, r.held(j.op.pay_ref).await), (None, None));
    // the relay transaction's own gas refunds may land meanwhile (its signer is the relayer): at least both deposits
    assert!(r.near(r.t.relayer.id()).await - r0 >= pd.deposit + hd.deposit, "entry and held deposits back to the relayer");
    // the call fails late: on_call asks the executor (here the fixture) to return target_deposit, nothing is paid
    r.resume(false).await;
    let late = st.await.unwrap();
    assert!(!final_bool(&late) && !has(&late, "relay_fee_paid") && !has(&late, "payment_settled"), "{:?}", late.logs());
    assert_eq!(r.returns(1).await, 1, "return_deposit asked once");
    assert_eq!(r.t.balance(&j.op.from).await, FEE * 10);
    r.settled(s0, &[&late, &out], j.op.pay_ref).await;
}

/// Refund wins and is exclusive: after a timeout refund, the target's late success reaches `on_call`, which pays
/// nothing (no release, no event); a second timeout finds no entry.
#[tokio::test]
async fn release_and_refund_exclusive() {
    let r = setup_slow().await;
    let p = r.payer("p1").await;
    let j = r.slow_job(&p, 0);
    let s0 = r.snap().await;
    let st = r.in_flight(&r.t.relayer, &j).await;
    let now = r.t.now_s().await;
    r.patch(j.op.pay_ref, |p| p.deadline = now - 1).await;
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(out.is_success(), "{:?}", out.failures());
    r.resume(true).await;
    let late = st.await.unwrap();
    assert!(has(&late, "fixture resumed ok"), "the call succeeded late: {:?}", late.logs());
    assert_eq!(r.returns(0).await, 0, "no deposit return on a success");
    assert!(late.is_success() && !final_bool(&late), "{:?}", late.failures());
    assert!(!has(&late, "relay_fee_paid") && !has(&late, "payment_settled"), "{:?}", late.logs());
    assert_eq!((r.t.balance(&j.op.from).await, r.t.balance(&r.h(&r.t.relayer)).await), (FEE * 10, 0), "refunded once, never released");
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(failed_with(&out, NO_PENDING), "{:?}", out.failures());
    r.settled(s0, &[&late], j.op.pay_ref).await;
}

/// Each branch (release, target panic, missing code, hold refused, detached / returned failing child) and a timeout
/// with the call in flight and its late failure: the router keeps no entry and no NEAR.
#[tokio::test]
async fn pending_empty_and_router_balance_unchanged_after_each_branch() {
    branches(true).await;
}

/// Each branch through the real executor, every one with a `target_deposit` (forwarded, or refunded to the executor
/// and returned): the executor holds nothing above its storage stake (its balance moves by its gas reward only). The
/// executor side of a timeout is not stageable here — with the real executor a call cannot stay in flight past a
/// deadline — and is covered by the router unit tests (`late_callbacks_pay_nothing`, `stale_callback_leaves_a_newer_entry_alone`).
#[tokio::test]
async fn executor_holds_only_its_stake_after_each_branch() {
    branches(false).await;
}

/// Every branch in one sandbox, `settled` (router and executor) after each; with `timeout`, also a timeout on a slow
/// router (its executor is the fixture, so only the router side is meaningful there).
async fn branches(timeout: bool) {
    let r = setup_router().await;
    let cases: [(&str, &str, u128, bool); 6] = [
        ("ok", "ok", TD, true),
        ("panic", "fail", TD, false),
        ("nocode", "-", TD, false),
        ("hold", "ok", TD, false),
        ("child", "spawn_fail", TD, true),
        ("returned child", "return_fail", TD, true),
    ];
    for (i, (name, method, td, released)) in cases.into_iter().enumerate() {
        let p = r.payer(&format!("b{i}")).await;
        let j = match name {
            "nocode" => r.job(&p, &r.open(), acc(r.t.alice.id()), "anything", vec![], td),
            "hold" => r.resign(&p, r.fx_job(&p, method, td), |o| o.amount = FEE * 11),
            _ => r.fx_job(&p, method, td),
        };
        let s0 = r.snap().await;
        let d = r.check(&j).await.deposit_needed.0 + NearToken::from_millinear(10).as_yoctonear();
        let out = r.relay_with(&r.t.relayer, &j, d, relay_gas(&j.auth, j.target_gas)).await;
        assert!(out.is_success() && final_bool(&out) == released, "{name}: {:?}", out.failures());
        r.settled(s0, &[&out], j.op.pay_ref).await;
        println!("branch {name}: settled");
    }
    if !timeout {
        return;
    }
    // timeout with the call in flight (a slow router), then the late failure
    let r = r.slow().await;
    let p = r.payer("bt").await;
    let j = r.slow_job(&p, TD);
    let s0 = r.snap().await;
    let st = r.in_flight(&r.t.relayer, &j).await;
    let now = r.t.now_s().await;
    r.patch(j.op.pay_ref, |p| p.deadline = now - 1).await;
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(out.is_success(), "{:?}", out.failures());
    r.resume(false).await;
    let late = st.await.unwrap();
    r.settled(s0, &[&late, &out], j.op.pay_ref).await;
    println!("branch timeout: settled");
}

/// `target_deposit` reaches the target on success; on a failed call it comes back to the relayer through the executor
/// (`return_deposit`), the executor and router keeping nothing.
#[tokio::test]
async fn target_deposit_forwarded_and_returned_on_failure() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let fx0 = r.near(r.fx.id()).await;
    let out = r.relay(&r.t.relayer, &r.fx_job(&p, "ok", TD)).await;
    assert!(out.is_success() && final_bool(&out));
    assert!(has(&out, &format!("deposit {TD}")) && r.near(r.fx.id()).await >= fx0 + TD, "forwarded exactly");
    let j = r.fx_job(&p, "fail", TD);
    let s0 = r.snap().await;
    let out = r.relay(&r.t.relayer, &j).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    // the executor's receipts: exec, the failed call's deposit refund (a transfer), return_deposit — all succeed
    let ex: Vec<_> = out.receipt_outcomes().iter().filter(|o| o.executor_id == *r.exec.id()).collect();
    assert_eq!(ex.iter().filter(|o| o.gas_burnt.as_gas() > 500_000_000_000).count(), 2, "exec, then return_deposit");
    assert!(ex.iter().all(|o| o.is_success()), "{:?}", out.failures());
    assert!(r.near(r.fx.id()).await < fx0 + 2 * TD, "the failed call kept nothing");
    r.settled(s0, &[&out], j.op.pay_ref).await;
    // the executor serves only the router
    let out = r.t.relayer.call(r.exec.id(), "return_deposit").args(b(&(acc(r.t.relayer.id()), U128(1)))).max_gas().transact().await.unwrap();
    assert!(failed_with(&out, "only the router calls the executor"), "{:?}", out.failures());
    let out = r.t.relayer.call(r.exec.id(), "exec").args(b(&(r.fid(), "ok".to_string(), Vec::<u8>::new(), Gas::from_tgas(5)))).max_gas()
        .transact().await.unwrap();
    assert!(failed_with(&out, "only the router calls the executor"), "{:?}", out.failures());
}

/// `relay` refuses a prepaid gas below `relay_gas` (the hold with its signature budget, the call's `target_gas` and the
/// callbacks), before any write: nothing held. At exactly `relay_gas` it settles (see also `gas_pins_hold`).
#[tokio::test]
async fn short_prepaid_gas_refused() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.fx_job(&p, "ok", 0);
    let need = relay_gas(&j.auth, j.target_gas);
    assert_eq!(need, Gas::from_gas(GAS_RELAY.as_gas() + hold_gas(&j.auth).as_gas() + GAS_ON_HOLD.as_gas() + GAS_EXEC.as_gas() + j.target_gas.as_gas() + call_gas().as_gas()));
    let d = r.deposit(&r.t.relayer, &j).await;
    let out = r.relay_with(&r.t.relayer, &j, d, Gas::from_gas(need.as_gas() - 1)).await;
    assert!(out.is_failure() && failed_with(&out, SHORT_GAS), "{:?}", out.failures());
    r.nothing_held(&j).await;
    let j = Job { target_gas: Gas::from_tgas(400), ..j };
    let out = r.relay_with(&r.t.relayer, &j, d, Gas::from_tgas(300)).await;
    assert!(failed_with(&out, SHORT_GAS), "a target_gas beyond the transaction: {:?}", out.failures());
}

/// A router-bound payment (`relayer` = the router) cannot be settled outside the router: the plain `mtx_pay` refuses
/// it (rule 7) and a direct `relay_hold` by the relayer holds nothing (the predecessor is not the named router).
#[tokio::test]
async fn near_router_bound_pay_refused_direct() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.job(&p, &r.h(&r.t.bob), r.fid(), "ok", vec![], 0);
    let out = r.t.call(&r.t.relayer, "mtx_pay", [b(&j.op), b(&j.auth)].concat(), NearToken::from_millinear(10).as_yoctonear()).await;
    assert!(failed_with(&out, "relayer is not the predecessor"), "{:?}", out.failures());
    let args = b(&(&j.op, &j.auth, acc(r.t.relayer.id())));
    let out = r.t.call(&r.t.relayer, "relay_hold", args, NearToken::from_millinear(10).as_yoctonear()).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert!(has(&out, "relay_hold refused: routed pay shape"), "{:?}", out.logs());
    r.nothing_held(&j).await;
    assert_eq!(r.t.balance(&j.op.from).await, FEE * 10);
}

/// Spec §2 row 11/12, CTR-MTX-27: the router never calls itself or its executor, and never pays the executor.
#[tokio::test]
async fn target_router_or_executor_refused() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    for t in [r.rid(), r.eid()] {
        r.refused(&r.t.relayer, &r.job(&p, &r.open(), t, "relay_timeout", vec![], 0), ROUTER_OR_EXEC).await;
    }
}

#[tokio::test]
async fn payee_executor_refused() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.job(&p, &Holder::Near(r.eid()), r.fid(), "ok", vec![], 0);
    r.refused(&r.t.relayer, &j, PAY_EXEC).await;
}

/// The shape the router recomputes: `pay_ref == ref(call, salt = op.extra)`, `lane == payLane(ref)`, nonce 0, op 0,
/// `relayer == router`. A payment whose `extra` is not the salt the ref was built with (ruling c), or bound to another
/// call, another lane, nonce or relayer, is refused.
#[tokio::test]
async fn relay_shape_and_salt_refused() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    let j = r.fx_job(&p, "ok", 0);
    let fs: [fn(&mut MetaOp); 5] = [
        |o| o.extra = [0x5b; 32],
        |o| o.lane = [1; 32],
        |o| o.nonce = 1,
        |o| o.op = OP_EXECUTE_TRANSFER,
        |o| o.relayer = None,
    ];
    for f in fs {
        r.refused(&r.t.relayer, &r.resign(&p, j.clone(), f), SHAPE).await;
    }
    r.refused(&r.t.relayer, &Job { method: "fail".into(), ..j.clone() }, SHAPE).await;
    // the payment op names another contract than `token`; an empty or over-long method name (the ref's u8 length)
    r.refused(&r.t.relayer, &r.resign(&p, j.clone(), |o| o.contract = "other.test.near".parse().unwrap()), OTHER_TOKEN).await;
    r.refused(&r.t.relayer, &r.job(&p, &r.open(), r.fid(), "", vec![], 0), METHOD_LEN).await;
    r.refused(&r.t.relayer, &r.job(&p, &r.open(), r.fid(), &"m".repeat(256), vec![], 0), METHOD_LEN).await;
    // a passkey assertion with a 1,025-byte clientDataJSON (its verify gas is budgeted for ≤ 1 KiB fields, review m3)
    let pk = Signer::pk(9, RP);
    let mut big = r.fx_job(&pk, "ok", 0);
    if let Auth::Passkey { client_data_json, .. } = &mut big.auth {
        client_data_json.resize(1_025, b' ');
    }
    r.refused(&r.t.relayer, &big, PASSKEY_CAP).await;
    // the call's arguments are capped (their bytes travel through three receipts with static gas)
    let big = r.job(&p, &r.open(), r.fid(), "ok", vec![7; 16_385], 0);
    r.refused(&r.t.relayer, &big, ARGS_CAP).await;
}

/// A forwarded call runs with the executor as predecessor, which no payer names: a token `relay_hold` or `mtx_pay` of
/// another router-bound payment spends nothing, and a `relay_release` of a payment the router holds finds nothing.
#[tokio::test]
async fn forwarded_call_cannot_spend_router_bound_payment() {
    let r = setup_router().await;
    let (p, q) = (r.payer("p1").await, r.payer("q1").await);
    let tok = acc(r.t.token.id());
    let other = r.fx_job(&q, "ok", 0);
    let hold = r.job(&p, &r.open(), tok.clone(), "relay_hold", b(&(&other.op, &other.auth, acc(r.t.relayer.id()))), 0);
    let out = r.relay(&r.t.relayer, &hold).await;
    assert!(has(&out, "relay_hold refused: routed pay shape"), "{:?}", out.logs());
    let pay = r.job(&p, &r.open(), tok.clone(), "mtx_pay", b(&(&other.op, &other.auth)), 0);
    let out = r.relay(&r.t.relayer, &pay).await;
    assert!(!final_bool(&out) && failed_with(&out, "relayer is not the predecessor"), "{:?}", out.failures());
    assert_eq!((r.t.balance(&q.ua()).await, r.t.lane_nonce(&q.ua(), other.op.lane).await), (FEE * 10, 0), "untouched");
    // a payment a router holds (its call in flight on a slow router) cannot be released by a forwarded relay_release
    let slow = r.slow().await;
    let w = slow.slow_job(&q, 0);
    let st = slow.in_flight(&r.t.relayer, &w).await;
    let rel = r.job(&p, &r.open(), tok, "relay_release", b(&w.op.pay_ref), 0);
    let out = r.relay(&r.t.relayer, &rel).await;
    assert!(!final_bool(&out) && failed_with(&out, "nothing held under this pay_ref for this router"), "{:?}", out.failures());
    assert_eq!(slow.held(w.op.pay_ref).await.map(|h| h.amount), Some(FEE), "still held");
    slow.resume(true).await;
    assert!(final_bool(&st.await.unwrap()));
}

/// Plan risk 4: a bound native payee not registered on the token at `relay` is registered at the hold (from the
/// relayer's deposit) and released; `pending` cleared.
#[tokio::test]
async fn near_router_release_to_unregistered_payee() {
    let r = setup_router().await;
    let p = r.payer("p1").await;
    assert!(!r.t.registered(&r.t.bob).await);
    let j = r.job(&p, &r.h(&r.t.bob), r.fid(), "ok", vec![], 0);
    let hc = r.hold_check(&r.t.relayer, &j).await;
    let held = Held { payer: j.op.from.clone(), payee: r.h(&r.t.bob), amount: FEE, relayer: acc(r.t.relayer.id()), deposit: 0 };
    let s = Subject { keys: vec![p.key()], ..Default::default() };
    let bytes = record_bytes(&j.op.from, &s) + scaas_near_token::lane_bytes(&j.op.from) + scaas_near_token::ACCOUNT_STORAGE_BYTES
        + held_bytes(&r.rid(), &held);
    assert_eq!(hc.storage_needed.0, bytes as u128 * r.t.byte_cost().await, "relay_hold_check = the hold's records");
    let s0 = r.snap().await;
    let out = r.relay(&r.t.relayer, &j).await;
    assert!(out.is_success() && final_bool(&out), "{:?}", out.failures());
    assert!(r.t.registered(&r.t.bob).await);
    assert_eq!((r.t.balance(&r.h(&r.t.bob)).await, r.t.balance(&r.h(&r.t.relayer)).await), (FEE, 0), "the bound payee paid");
    r.settled(s0, &[&out], j.op.pay_ref).await;
}

/// Gas sizing (spec §3.8): each receipt's static gas is the measured maximum of both branches × 1.5; every measured
/// figure ≤ its pin / 1.2. Run at exactly `relay_gas` prepaid with a passkey payer: release (target ok), refund with a
/// deposit return (target panics), the hold refused, and the timeout's settle.
#[tokio::test]
async fn gas_pins_hold() {
    let r = setup_router().await;
    let pk = Signer::pk(7, RP);
    r.t.fund(&pk.ua(), FEE * 10).await;
    let pin = |g: Gas| tg(g.as_gas());
    // (receipt, measured Tgas, pin Tgas)
    let mut rows: Vec<(String, f64, f64)> = vec![];
    let mut measure = |label: &str, out: &ExecutionFinalResult, j: &Job| {
        let of = |id: &AccountId| -> Vec<f64> {
            // function calls only (a transfer or deposit refund receipt burns 0.223 Tgas)
            out.receipt_outcomes().iter().filter(|o| o.executor_id == *id && o.gas_burnt.as_gas() > 500_000_000_000).map(|o| tg(o.gas_burnt.as_gas())).collect()
        };
        let (rt, tk, ex) = (of(r.router.id()), of(r.t.token.id()), of(r.exec.id()));
        println!("{label}: total {:.3} Tgas; router {rt:?}; token {tk:?}; executor {ex:?}", tgas(out));
        let names = ["relay", "on_hold", "on_call", "on_settle"];
        let pins = [pin(GAS_RELAY), pin(GAS_ON_HOLD), pin(GAS_ON_CALL), pin(GAS_ON_SETTLE)];
        for (i, g) in rt.iter().enumerate() {
            rows.push((format!("{label} {}", names[i]), *g, pins[i]));
        }
        rows.push((format!("{label} relay_hold"), tk[0], pin(hold_gas(&j.auth))));
        if let Some(g) = tk.get(1) {
            rows.push((format!("{label} release/refund"), *g, pin(GAS_RELEASE)));
        }
        if let Some(g) = ex.first() {
            rows.push((format!("{label} exec"), *g, pin(GAS_EXEC)));
        }
        if let Some(g) = ex.get(1) {
            rows.push((format!("{label} return_deposit"), *g, pin(GAS_RELEASE)));
        }
    };
    let ed = r.payer("ed").await;
    for (label, s, args) in [("release ed25519", &ed, vec![]), ("release", &pk, vec![]), ("release 16 KiB args", &pk, vec![7; 16_384])] {
        let j = r.job(s, &r.open(), r.fid(), "ok", args, TD);
        let out = r.relay(&r.t.relayer, &j).await;
        assert!(out.is_success() && final_bool(&out), "{:?}", out.failures());
        assert!(out.receipt_outcomes().iter().all(|o| o.is_success()), "every receipt at the minimum: {:?}", out.failures());
        measure(label, &out, &j);
    }
    let j = r.fx_job(&pk, "fail", TD);
    let out = r.relay(&r.t.relayer, &j).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    assert!(out.receipt_outcomes().iter().filter(|o| o.executor_id != *r.fx.id()).all(|o| o.is_success()), "{:?}", out.failures());
    measure("refund", &out, &j);
    let j = r.resign(&pk, r.salted(&pk, r.fx_job(&pk, "ok", TD), [0x5e; 32]), |o| o.amount = FEE * 100);
    let d = r.check(&j).await.deposit_needed.0 + NearToken::from_millinear(10).as_yoctonear();
    let out = r.relay_with(&r.t.relayer, &j, d, relay_gas(&j.auth, j.target_gas)).await;
    assert!(out.is_success() && !final_bool(&out), "{:?}", out.failures());
    measure("hold-refused", &out, &j);
    // the timeout's settle (refund) and its on_settle (a slow router: the call in flight)
    let r = r.slow().await;
    let j = r.slow_job(&pk, TD);
    let st = r.in_flight(&r.t.relayer, &j).await;
    let now = r.t.now_s().await;
    r.patch(j.op.pay_ref, |p| p.deadline = now - 1).await;
    let out = r.timeout(&r.t.bob, j.op.pay_ref).await;
    assert!(out.receipt_outcomes().iter().all(|o| o.is_success()), "{:?}", out.failures());
    let of = |id: &AccountId| -> Vec<f64> {
        out.receipt_outcomes().iter().filter(|o| o.executor_id == *id && o.gas_burnt.as_gas() > 500_000_000_000).map(|o| tg(o.gas_burnt.as_gas())).collect()
    };
    let (rt, tk) = (of(r.router.id()), of(r.t.token.id()));
    println!("timeout: total {:.3} Tgas; router {rt:?}; token {tk:?}", tgas(&out));
    rows.push(("timeout refund".into(), tk[0], pin(GAS_RELEASE)));
    rows.push(("timeout on_settle".into(), rt[1], pin(GAS_ON_SETTLE)));
    r.resume(false).await;
    st.await.unwrap();
    for (name, g, p) in &rows {
        println!("GAS router {name}: {g:.3} Tgas (pin {p:.0}, limit {:.3})", p / 1.2);
    }
    for (name, g, p) in &rows {
        assert!(*g <= p / 1.2, "{name}: {g} Tgas over pin {p} / 1.2");
    }
    println!(
        "GAS router pins: GAS_RELAY {:.0}, GAS_HOLD {:.0} (+ sig_gas: passkey 25, ed25519/secp256k1 1), GAS_ON_HOLD {:.0}, GAS_EXEC {:.0}, GAS_ON_CALL {:.0}, GAS_RELEASE {:.0}, GAS_ON_SETTLE {:.0}; relay_gas(passkey, {TARGET_TGAS} Tgas target) = {} Tgas",
        pin(GAS_RELAY), pin(GAS_HOLD), pin(GAS_ON_HOLD), pin(GAS_EXEC), pin(GAS_ON_CALL), pin(GAS_RELEASE), pin(GAS_ON_SETTLE),
        relay_gas(&j.auth, j.target_gas).as_tgas()
    );
}
