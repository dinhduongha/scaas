//! Task 8 (spec §3.6; CTR-DEX-09 / -10; README §11): the NEAR escrow DEX. The relayer lane calls `dex.settle(order_a,
//! op_a, auth_a, order_b, op_b, auth_b)`; the DEX checks each order's `relayer` (None or the predecessor) and the
//! fill-or-kill pair, then calls `token_a.mtx_trade` and `token_b.mtx_trade` (leg op 1 bound `to = relayer = dex`); each
//! leg moves the whole `sell_amount` into the DEX's NEP-141 balance; the join callback `on_legs` pays both out
//! (`ft_transfer` to a native holder, `transfer_to_ua` to a UA id) or refunds the leg that arrived. `refund_expired`
//! (anyone, after both expiries) covers a lost callback; refund wins. One sandbox per test.
mod common;
use common::*;
use near_workspaces::types::Gas;
use scaas_near_common::hash::hex;
use scaas_near_common::Order;
use scaas_near_dex::{Settle, GAS_LEG_MIN, GAS_ON_LEGS, GAS_ON_REFUND, GAS_PAYOUT, GAS_SETTLE_SELF, GAS_VIEW, SETTLE_MIN_GAS};
use scaas_near_token::{order_bytes, OrderClose, ACCOUNT_STORAGE_BYTES, TRADE_RECORD_OVERHEAD};

const DEX_WASM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../target/near/scaas_near_dex/scaas_near_dex.wasm");
/// What the relayer attaches to `settle`: the escrow entry plus both legs' storage; each token returns its leg's excess
/// to the transaction signer (the relayer).
const DEPOSIT: u128 = 100_000_000_000_000_000_000_000; // 0.1 NEAR
const NOT_DEX: &str = "a leg is pulled only by the order's DEX (to = relayer = predecessor)";
const FOK_AMOUNT: &str = "fill-or-kill: op amount = sell_amount";
const FOK_PRICE: &str = "fill-or-kill: each side's sell_amount covers the other's min_buy";
const ORDER_RELAYER: &str = "order relayer is not the predecessor";
const IN_SETTLE: &str = "a leg is already in a settle";
const FILLED: &str = "order filled";
const CANCEL_FILLED: &str = "order filled: cancel refused";
const CANCELLED: &str = "order cancelled";
const CANCELLED_TWICE: &str = "order already cancelled";
const BELOW_MIN: &str = "order nonce below min_nonce";
const MIN_CAP: &str = "min_nonce must be below 2^63";
const MIN_UP: &str = "min_nonce only increases";
const BEFORE_EXPIRY: &str = "refund before expiry";
const SHORT_GAS: &str = "prepaid gas below the settle minimum (legs + callback)";
/// `settle_gas_pin`: two passkey legs, both paid out, every receipt of the transaction (measured 2026-10-28, see
/// `runs/2026-10-28-near-gas.txt`); the test fails when a measurement exceeds `pin / 1.2`.
const SETTLE_TGAS_PIN: f64 = 90.0;

struct D {
    t: T,
    b: Contract,
    dex: Contract,
}

/// One leg as `settle` takes it.
#[derive(Clone)]
struct L {
    order: Order,
    op: MetaOp,
    auth: Auth,
}

async fn setup_dex() -> D {
    let t = setup().await;
    let b = deploy_token(&t.w).await;
    let dex = t.w.dev_deploy(&std::fs::read(DEX_WASM).expect("run build.sh near first")).await.unwrap();
    dex.call("new").transact().await.unwrap().into_result().unwrap();
    D { t, b, dex }
}

fn acc(a: &AccountId) -> near_sdk::AccountId {
    a.as_str().parse().unwrap()
}

fn settle_id(a: &MetaOp, b: &MetaOp) -> [u8; 32] {
    sha(&[a.digest(), b.digest()].concat())
}

impl D {
    fn tok(&self, sell_a: bool) -> &Contract {
        if sell_a { &self.t.token } else { &self.b }
    }

    fn dex_h(&self) -> Holder {
        Holder::Near(acc(self.dex.id()))
    }

    /// Mint `amount` to `h` on `tok`: a native holder directly, a UA through alice and `transfer_to_ua` (a new record).
    async fn fund(&self, tok: &Contract, h: &Holder, amount: u128) {
        let to = match h {
            Holder::Near(a) => a.to_string(),
            Holder::Ua(_) => self.t.alice.id().to_string(),
        };
        let reg: Value = tok.view("storage_balance_of").args_json(json!({"account_id": to})).await.unwrap().json().unwrap();
        let dep = if reg.is_null() { NearToken::from_millinear(100) } else { NearToken::from_yoctonear(1) };
        let out = tok.call("mint").args_json(json!({"to": to, "amount": amount.to_string()})).deposit(dep).transact().await.unwrap();
        assert!(out.is_success(), "{:?}", out.failures());
        if let Holder::Ua(id) = h {
            let out = self.t.alice.call(tok.id(), "transfer_to_ua")
                .args_json(json!({"id": id.to_vec(), "amount": amount.to_string()}))
                .deposit(NearToken::from_millinear(100)).transact().await.unwrap();
            assert!(out.is_success(), "{:?}", out.failures());
        }
    }

    async fn bal(&self, tok: &Contract, h: &Holder) -> u128 {
        let v: String = match h {
            Holder::Near(a) => tok.view("ft_balance_of").args_json(json!({"account_id": a})).await.unwrap().json().unwrap(),
            Holder::Ua(id) => tok.view("ua_balance_of").args_json(json!({"id": id.to_vec()})).await.unwrap().json().unwrap(),
        };
        v.parse().unwrap()
    }

    /// A native maker's SCaaS key on `tok` (a direct call by the account itself, §3.3).
    async fn native_key(&self, tok: &Contract, who: &Account, s: &Signer) {
        let out = who.call(tok.id(), "add_key_native").args(b(&(s.key(), None::<String>)))
            .deposit(NearToken::from_millinear(100)).transact().await.unwrap();
        assert!(out.is_success(), "{:?}", out.failures());
    }

    /// An order selling `amount` of A (`sell_a`) or B for at least `min_buy` of the other; open relayer, no expiry soon.
    fn order(&self, sell_a: bool, amount: u128, min_buy: u128) -> Order {
        let (s, by) = (self.tok(sell_a), self.tok(!sell_a));
        Order { sell_token: acc(s.id()), buy_token: acc(by.id()), sell_amount: amount, min_buy, relayer: None, expiry: VU }
    }

    /// The leg op of `order` signed by `s` for `maker` on order lane `lane` at `nonce` (op 1, `to = relayer = dex`).
    fn leg(&self, s: &Signer, maker: &Holder, order: Order, lane: [u8; 32], nonce: u64) -> L {
        let op = MetaOp {
            network: NETWORK,
            contract: order.sell_token.clone(),
            op: OP_TRADE,
            from: maker.clone(),
            to: self.dex_h(),
            relayer: Some(acc(self.dex.id())),
            amount: order.sell_amount,
            pay_ref: [0; 32],
            lane,
            nonce,
            valid_until: VU,
            extra: sha(&b(&order)),
        };
        L { auth: s.sign(&op, ORIGIN), order, op }
    }

    fn resign(&self, s: &Signer, mut l: L, f: impl FnOnce(&mut L)) -> L {
        f(&mut l);
        l.auth = s.sign(&l.op, ORIGIN);
        l
    }

    async fn settle_gas(&self, who: &Account, a: &L, bl: &L, gas: Gas) -> ExecutionFinalResult {
        let args = b(&(&a.order, &a.op, &a.auth, &bl.order, &bl.op, &bl.auth));
        let out = who.call(self.dex.id(), "settle").args(args).deposit(NearToken::from_yoctonear(DEPOSIT)).gas(gas)
            .transact().await.unwrap();
        println!("settle by {}: {:.3} Tgas, ok {}", who.id(), tgas(&out), out.is_success());
        out
    }

    async fn settle(&self, who: &Account, a: &L, bl: &L) -> ExecutionFinalResult {
        self.settle_gas(who, a, bl, Gas::from_tgas(300)).await
    }

    async fn pending(&self, id: [u8; 32]) -> Option<Settle> {
        self.dex.view("pending").args(b(&id)).await.unwrap().borsh().unwrap()
    }

    /// The escrow entry under key `s` ‖ id (the sandbox clock cannot jump to an expiry; a lost callback is staged).
    async fn patch(&self, id: [u8; 32], f: impl FnOnce(&mut Settle)) {
        let mut s = self.pending(id).await.unwrap();
        f(&mut s);
        self.t.w.patch_state(self.dex.id(), &[b"s".as_slice(), &id].concat(), &b(&s)).await.unwrap();
    }

    async fn refund(&self, who: &Account, id: [u8; 32]) -> ExecutionFinalResult {
        let out = who.call(self.dex.id(), "refund_expired").args(b(&id)).max_gas().transact().await.unwrap();
        println!("refund_expired by {}: {:.3} Tgas, ok {}", who.id(), tgas(&out), out.is_success());
        out
    }

    async fn trade_check(&self, caller: &AccountId, l: &L, receiver: &Holder) -> Check {
        let tok = if l.op.contract.as_str() == self.t.token.id().as_str() { &self.t.token } else { &self.b };
        let args = b(&(acc(caller), &l.op, &l.auth, &l.order, receiver));
        tok.view("mtx_trade_check").args(args).await.unwrap().borsh().unwrap()
    }

    async fn closed(&self, l: &L) -> Option<OrderClose> {
        let tok = if l.op.contract.as_str() == self.t.token.id().as_str() { &self.t.token } else { &self.b };
        tok.view("order_closed").args(b(&(&l.op.from, l.op.lane, l.op.nonce))).await.unwrap().borsh().unwrap()
    }

    async fn filled(&self, l: &L) -> bool {
        let tok = if l.op.contract.as_str() == self.t.token.id().as_str() { &self.t.token } else { &self.b };
        tok.view("filled").args(b(&(&l.op.from, l.op.lane, l.op.nonce))).await.unwrap().borsh().unwrap()
    }

    async fn usage(&self, c: &Contract) -> u64 {
        c.view_account().await.unwrap().storage_usage
    }

    /// erin (UA, ed25519) sells 100 A for ≥ 50 B; bob (native, SCaaS key on B) sells 60 B for ≥ 100 A; both funded.
    async fn pair(&self, erin: &Signer, bobk: &Signer) -> (L, L) {
        let (e, bob) = (erin.ua(), self.t.near(&self.t.bob));
        self.fund(&self.t.token, &e, 100).await;
        self.fund(&self.b, &bob, 60).await;
        self.native_key(&self.b, &self.t.bob, bobk).await;
        let a = self.leg(erin, &e, self.order(true, 100, 50), [0xa0; 32], 0);
        let bl = self.leg(bobk, &bob, self.order(false, 60, 100), [0xb0; 32], 0);
        (a, bl)
    }
}

fn has(out: &ExecutionFinalResult, s: &str) -> bool {
    out.logs().iter().any(|l| l.contains(s))
}

fn failed_with(out: &ExecutionFinalResult, err: &str) -> bool {
    out.is_failure() && format!("{:?}", out.failures()).contains(err)
}

#[tokio::test]
async fn settle_pays_both_legs() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let (e, bob) = (erin.ua(), d.t.near(&d.t.bob));
    let cost = d.t.byte_cost().await;
    // the relayer's quote: each leg's `mtx_trade_check` with the DEX as caller (the receiver is the other maker)
    let (ca, cb) = (d.trade_check(d.dex.id(), &a, &bob).await, d.trade_check(d.dex.id(), &bl, &e).await);
    assert_eq!((ca.error.clone(), cb.error.clone()), (None, None));
    let opened = record_bytes(&e, &Subject { keys: vec![erin.key()], ..Default::default() });
    let filled = |h: &Holder| order_bytes(h, &OrderClose::Filled([0; 32]));
    // leg A: erin opened lazily, the order record, the DEX and bob registered on A
    assert_eq!(ca.storage_needed.0, (opened + filled(&e) + 2 * ACCOUNT_STORAGE_BYTES) as u128 * cost);
    // leg B: bob's subject exists (add_key_native); the order record, the DEX registered on B, erin's UA record on B
    assert_eq!(cb.storage_needed.0, (filled(&bob) + ACCOUNT_STORAGE_BYTES + scaas_near_token::UA_STORAGE_BYTES) as u128 * cost);
    let (ua, ub, ud) = (d.usage(&d.t.token).await, d.usage(&d.b).await, d.usage(&d.dex).await);
    let n0 = d.dex.view_account().await.unwrap().balance.as_yoctonear();
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success(), "{:?}", out.failures());
    for o in out.receipt_outcomes() {
        println!("  receipt {} {:.3} Tgas {:?}", o.executor_id, o.gas_burnt.as_gas() as f64 / 1e12, o.logs.first());
    }
    assert!(out.receipt_outcomes().iter().all(|o| o.is_success()), "every receipt succeeds: {:?}", out.failures());
    // each leg's excess deposit went to the signer: the DEX kept only its entry deposit (+ gas reward, < 0.001 NEAR)
    let kept = d.dex.view_account().await.unwrap().balance.as_yoctonear() - n0;
    let dep = d.pending(settle_id(&a.op, &bl.op)).await.unwrap().deposit;
    assert!(kept >= dep && kept - dep < NearToken::from_millinear(1).as_yoctonear(), "DEX kept {kept} yocto");
    // each side receives the other's full sell_amount: bob 100 A by ft_transfer, erin 60 B by transfer_to_ua
    assert_eq!((d.bal(&d.t.token, &e).await, d.bal(&d.t.token, &bob).await), (0, 100));
    assert_eq!((d.bal(&d.b, &bob).await, d.bal(&d.b, &e).await), (0, 60));
    assert_eq!((d.bal(&d.t.token, &d.dex_h()).await, d.bal(&d.b, &d.dex_h()).await), (0, 0), "escrow empty");
    let id = settle_id(&a.op, &bl.op);
    assert!(has(&out, r#""event":"matched""#) && has(&out, &hex(&id)), "{:?}", out.logs());
    assert!(has(&out, r#""event":"order_filled""#));
    assert!(has(&out, &format!(r#""old_owner_id":"{}","new_owner_id":"{}","amount":"100""#, d.dex.id(), d.t.bob.id())));
    assert!(has(&out, &format!(r#""from":"{}","to":"{e}","amount":"60""#, d.dex.id())), "ua_transfer to erin");
    assert!(d.filled(&a).await && d.filled(&bl).await);
    assert_eq!(d.closed(&a).await, Some(OrderClose::Filled(a.op.digest())));
    // storage: what each check quoted, less NEP-145's fixed 64-char registration over the real ids
    let short = |x: &AccountId| 64 - x.as_str().len() as u64;
    let grew_a = d.usage(&d.t.token).await - ua;
    assert_eq!(grew_a, opened + filled(&e) + 2 * ACCOUNT_STORAGE_BYTES - short(d.dex.id()) - short(d.t.bob.id()));
    let grew_b = d.usage(&d.b).await - ub;
    assert_eq!(grew_b, filled(&bob) + ACCOUNT_STORAGE_BYTES - short(d.dex.id()) + scaas_near_token::UA_STORAGE_BYTES);
    let s = d.pending(id).await.unwrap();
    let entry = d.usage(&d.dex).await - ud;
    assert!(s.done);
    assert_eq!(s.deposit, entry as u128 * cost, "the entry's deposit = its measured bytes");
    println!("storage: token A +{grew_a} B, token B +{grew_b} B, dex entry +{entry} B (order record {} B UA / {} B native)",
        filled(&e), filled(&bob));
    // the entry (and the leg index) stays until both expiries; then anyone prunes it and the relayer gets its deposit
    let out = d.refund(&d.t.alice, id).await;
    assert!(failed_with(&out, BEFORE_EXPIRY), "{:?}", out.failures());
    let now = d.t.now_s().await;
    d.patch(id, |s| s.expiry = now - 1).await;
    let r0 = d.t.relayer.view_account().await.unwrap().balance.as_yoctonear();
    let out = d.refund(&d.t.alice, id).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert_eq!(d.t.relayer.view_account().await.unwrap().balance.as_yoctonear() - r0, s.deposit, "deposit back");
    assert_eq!((d.pending(id).await, d.usage(&d.dex).await), (None, ud), "pruned");
    // nothing moved on the prune
    assert_eq!((d.bal(&d.t.token, &bob).await, d.bal(&d.b, &e).await), (100, 60));
}

/// One leg refused (it returns `false` and nothing moves on its token), the other refunded by `on_legs`: a UA seller by
/// `transfer_to_ua`, a native seller by `ft_transfer`. The refunded leg's order stays filled (closed).
#[tokio::test]
async fn one_leg_fails_other_refunded() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (e, bob) = (erin.ua(), d.t.near(&d.t.bob));
    d.fund(&d.t.token, &e, 100).await;
    d.fund(&d.b, &bob, 10).await; // bob sells 60 B but holds 10
    d.native_key(&d.b, &d.t.bob, &bobk).await;
    let a = d.leg(&erin, &e, d.order(true, 100, 50), [0xa0; 32], 0);
    let bl = d.leg(&bobk, &bob, d.order(false, 60, 100), [0xb0; 32], 0);
    let ub = d.usage(&d.b).await;
    let n0 = d.dex.view_account().await.unwrap().balance.as_yoctonear();
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success(), "{:?}", out.failures());
    assert!(has(&out, "mtx_trade refused: The account doesn't have enough balance"), "{:?}", out.logs());
    // the refused leg's deposit (~0.046 NEAR) went back to the signer: the DEX kept its entry deposit, 1 yoctoNEAR and
    // its gas reward (30 % of its receipts' gas, < 0.001 NEAR)
    let s = d.pending(settle_id(&a.op, &bl.op)).await.unwrap();
    let kept = d.dex.view_account().await.unwrap().balance.as_yoctonear() - n0 - s.deposit;
    assert!(kept < NearToken::from_millinear(1).as_yoctonear(), "DEX kept {kept} yocto");
    assert!(has(&out, r#""event":"match_failed""#), "{:?}", out.logs());
    assert_eq!((d.bal(&d.t.token, &e).await, d.bal(&d.b, &bob).await), (100, 10), "erin refunded, bob untouched");
    assert_eq!((d.bal(&d.t.token, &d.dex_h()).await, d.bal(&d.t.token, &bob).await), (0, 0));
    assert_eq!(d.usage(&d.b).await, ub, "the refused leg wrote nothing");
    assert!(d.filled(&a).await && !d.filled(&bl).await);
    // the other way round: erin's leg refused (signed by a key that is not hers), bob's 60 B refunded by ft_transfer
    d.fund(&d.b, &bob, 50).await;
    let a2 = d.resign(&bobk, d.leg(&erin, &e, d.order(true, 100, 50), [0xa0; 32], 1), |_| {});
    let b2 = d.leg(&bobk, &bob, d.order(false, 60, 100), [0xb0; 32], 1);
    let out = d.settle(&d.t.relayer, &a2, &b2).await;
    assert!(has(&out, "mtx_trade refused: not a key of the subject"), "{:?}", out.logs());
    assert!(out.is_success() && has(&out, r#""event":"match_failed""#), "{:?}", out.logs());
    assert_eq!((d.bal(&d.b, &bob).await, d.bal(&d.b, &d.dex_h()).await, d.bal(&d.t.token, &e).await), (60, 0, 100));
    assert!(d.filled(&b2).await, "bob's refunded order stays closed");
}

/// CTR-DEX-09: an order bound to a relayer settles only when that relayer submits; `None` = any submitter.
#[tokio::test]
async fn order_relayer_mismatch_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let e = erin.ua();
    let a = d.leg(&erin, &e, Order { relayer: Some(acc(d.t.relayer.id())), ..a.order }, [0xa0; 32], 0);
    let out = d.settle(&d.t.alice, &a, &bl).await;
    assert!(failed_with(&out, ORDER_RELAYER), "{:?}", out.failures());
    let out = d.settle(&d.t.alice, &bl, &a).await;
    assert!(failed_with(&out, ORDER_RELAYER), "either side: {:?}", out.failures());
    assert_eq!((d.bal(&d.t.token, &e).await, d.pending(settle_id(&a.op, &bl.op)).await), (100, None), "nothing moved");
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success() && has(&out, r#""event":"matched""#), "{:?}", out.failures());
}

/// Only the order's DEX (`to = relayer = predecessor`) pulls a leg: a direct call, or another contract, moves nothing.
#[tokio::test]
async fn leg_called_by_non_dex_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, _) = d.pair(&erin, &bobk).await;
    let (e, bob) = (erin.ua(), d.t.near(&d.t.bob));
    let c = d.trade_check(d.t.bob.id(), &a, &bob).await;
    assert_eq!(c.error.as_deref(), Some(NOT_DEX));
    let args = b(&(&a.op, &a.auth, &a.order, &bob));
    let out = d.t.bob.call(d.t.token.id(), "mtx_trade").args(args).deposit(NearToken::from_millinear(10)).max_gas()
        .transact().await.unwrap();
    assert!(out.is_success(), "a refused leg returns false: {:?}", out.failures());
    assert!(has(&out, &format!("mtx_trade refused: {NOT_DEX}")), "{:?}", out.logs());
    assert!(!out.borsh::<bool>().unwrap());
    assert_eq!((d.bal(&d.t.token, &e).await, d.bal(&d.t.token, &bob).await, d.filled(&a).await), (100, 0, false));
    // the leg op must name the DEX as relayer too (`relayer = None` would let any caller pull it)
    let open = d.resign(&erin, a.clone(), |l| l.op.relayer = None);
    assert_eq!(d.trade_check(d.dex.id(), &open, &bob).await.error.as_deref(), Some(NOT_DEX));
    let other = d.resign(&erin, a.clone(), |l| l.op.to = bob.clone());
    assert_eq!(d.trade_check(d.dex.id(), &other, &bob).await.error.as_deref(), Some(NOT_DEX));
    assert_eq!(d.trade_check(d.dex.id(), &a, &bob).await.error, None, "the DEX itself may");
    // the token's own leg checks (the DEX checks the shape too, the token is the authority)
    let now = d.t.now_s().await;
    let cases: [(L, &str); 4] = [
        (d.resign(&erin, a.clone(), |l| l.order.min_buy = 1), "extra is not sha256 of the order"),
        (d.leg(&erin, &e, Order { expiry: now - 1, ..a.order.clone() }, [0xa0; 32], 0), "order expired"),
        (d.resign(&erin, a.clone(), |l| l.order.sell_token = acc(d.b.id())), "order sells another token"),
        (d.resign(&erin, a.clone(), |l| l.op.pay_ref = [1; 32]), "a trade leg carries no pay_ref"),
    ];
    for (l, err) in cases {
        assert_eq!(d.trade_check(d.dex.id(), &l, &bob).await.error.as_deref(), Some(err));
    }
    // ruling R8: a trade leg is a value op, so POLICY_PASSKEY_FOR_VALUE needs a passkey
    let op = d.t.op(OP_SET_GUARDIAN, &e, &e, 0, &[KEYOP_SET_POLICY, POLICY_PASSKEY_FOR_VALUE]);
    d.t.ok(&d.t.relayer, "mtx_set_policy", &op, &erin.sign(&op, ORIGIN), &b(&POLICY_PASSKEY_FOR_VALUE)).await;
    let c = d.trade_check(d.dex.id(), &a, &bob).await;
    assert_eq!(c.error.as_deref(), Some("POLICY_PASSKEY_FOR_VALUE: value ops need a passkey signature"));
}

/// The DEX checks each leg against its order before any call: a mismatch fails `settle` and moves nothing.
#[tokio::test]
async fn settle_leg_shape_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let e = erin.ua();
    let now = d.t.now_s().await;
    let shape = "leg: op 1 for the order's sell token, to = relayer = this DEX";
    let cases: [(L, &str); 5] = [
        (d.resign(&erin, a.clone(), |l| l.op.relayer = None), shape),
        (d.resign(&erin, a.clone(), |l| l.op.op = OP_PAY), shape),
        (d.resign(&erin, a.clone(), |l| l.op.contract = acc(d.b.id())), shape),
        (d.resign(&erin, a.clone(), |l| l.order.min_buy = 1), "extra is not sha256 of the order"),
        (d.leg(&erin, &e, Order { expiry: now - 1, ..a.order.clone() }, [0xa0; 32], 0), "order expired"),
    ];
    for (l, err) in cases {
        let out = d.settle(&d.t.relayer, &l, &bl).await;
        assert!(failed_with(&out, err), "{err}: {:?}", out.failures());
    }
    assert_eq!(d.bal(&d.t.token, &e).await, 100, "nothing moved");
}

/// The relayer pays every record: the escrow entry from `settle`'s deposit (else refused); a leg short of its storage
/// is refused by its token (`false`, nothing written), and its deposit goes to the signer, never stays with the DEX.
#[tokio::test]
async fn settle_deposit_short_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let cost = d.t.byte_cost().await;
    let leg = |l: &L| scaas_near_dex::Leg {
        token: l.order.sell_token.clone(),
        seller: l.op.from.clone(),
        lane: l.op.lane,
        nonce: l.op.nonce,
        digest: l.op.digest(),
        amount: l.op.amount,
    };
    let s = Settle { legs: [leg(&a), leg(&bl)], relayer: acc(d.t.relayer.id()), deposit: 0, expiry: VU, done: false };
    // entry record (key `s` ‖ id) + two index records (key `l` ‖ digest → id), 40 B overhead each
    let entry = (40 + 33 + b(&s).len() as u128) + 2 * (40 + 33 + 32);
    let call = |dep: u128| {
        let args = b(&(&a.order, &a.op, &a.auth, &bl.order, &bl.op, &bl.auth));
        d.t.relayer.call(d.dex.id(), "settle").args(args).deposit(NearToken::from_yoctonear(dep)).max_gas().transact()
    };
    let out = call(entry * cost + 1).await.unwrap();
    assert!(failed_with(&out, "attached deposit below the escrow entry storage"), "{:?}", out.failures());
    let out = call(entry * cost + 2).await.unwrap();
    assert!(out.is_success(), "{:?}", out.failures());
    let short = "mtx_trade refused: the attached deposit is short of the leg's storage";
    assert_eq!(out.logs().iter().filter(|l| l.contains(short)).count(), 2, "{:?}", out.logs());
    assert!(has(&out, r#""event":"match_failed""#));
    assert_eq!((d.bal(&d.t.token, &erin.ua()).await, d.filled(&a).await, d.filled(&bl).await), (100, false, false));
    let id = settle_id(&a.op, &bl.op);
    assert_eq!(d.pending(id).await.unwrap().deposit, entry * cost, "measured = formula ({entry} B)");
}

/// A lost callback (`on_legs` never resolved the entry; staged by putting the escrow back and patching `done`): after
/// both expiries anyone refunds every leg the tokens show filled by this settle's own leg op; refund wins, once.
#[tokio::test]
async fn refund_expired_after_lost_callback() {
    let d = setup_dex().await;
    let (ak, bk) = (Signer::ed("alicek"), Signer::ed("bobk"));
    let (alice, bob) = (d.t.near(&d.t.alice), d.t.near(&d.t.bob));
    d.fund(&d.t.token, &alice, 100).await;
    d.fund(&d.b, &bob, 60).await;
    d.native_key(&d.t.token, &d.t.alice, &ak).await;
    d.native_key(&d.b, &d.t.bob, &bk).await;
    let a = d.leg(&ak, &alice, d.order(true, 100, 50), [0xa0; 32], 0);
    let bl = d.leg(&bk, &bob, d.order(false, 60, 100), [0xb0; 32], 0);
    let ud = d.usage(&d.dex).await;
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let id = settle_id(&a.op, &bl.op);
    // stage the lost callback: the escrow back in the DEX, the entry unresolved
    for (who, tok, amt) in [(&d.t.bob, &d.t.token, 100u128), (&d.t.alice, &d.b, 60)] {
        let out = who.call(tok.id(), "ft_transfer").args_json(json!({"receiver_id": d.dex.id(), "amount": amt.to_string()}))
            .deposit(NearToken::from_yoctonear(1)).transact().await.unwrap();
        assert!(out.is_success(), "{:?}", out.failures());
    }
    d.patch(id, |s| s.done = false).await;
    // a late on_legs from outside is refused (#[private])
    let out = d.t.bob.call(d.dex.id(), "on_legs").args(b(&id)).max_gas().transact().await.unwrap();
    assert!(out.is_failure(), "on_legs is private");
    let now = d.t.now_s().await;
    d.patch(id, |s| s.expiry = now - 1).await;
    let s = d.pending(id).await.unwrap();
    let r0 = d.t.relayer.view_account().await.unwrap().balance.as_yoctonear();
    let out = d.refund(&d.t.bob, id).await;
    assert!(out.is_success(), "{:?}", out.failures());
    for o in out.receipt_outcomes() {
        println!("  receipt {} {:.3} Tgas {:?}", o.executor_id, o.gas_burnt.as_gas() as f64 / 1e12, o.logs.first());
    }
    assert!(has(&out, r#""event":"match_failed""#), "{:?}", out.logs());
    assert_eq!((d.bal(&d.t.token, &alice).await, d.bal(&d.b, &bob).await), (100, 60), "both sellers refunded");
    assert_eq!((d.bal(&d.t.token, &d.dex_h()).await, d.bal(&d.b, &d.dex_h()).await), (0, 0), "escrow empty");
    assert_eq!((d.pending(id).await, d.usage(&d.dex).await), (None, ud), "pruned");
    assert_eq!(d.t.relayer.view_account().await.unwrap().balance.as_yoctonear() - r0, s.deposit, "deposit back");
    // gas pins of the refund path: the reads within GAS_VIEW / 1.2; on_refund prepays its refunds' static gas and their
    // exec fees (each ≤ the refund's burnt gas)
    let tg = |g: u64| g as f64 / 1e12;
    let g = |x: near_sdk::Gas| tg(x.as_gas());
    let (mut on_refund, mut refunds) = (0.0, 0.0);
    for o in out.receipt_outcomes() {
        let (x, log) = (tg(o.gas_burnt.as_gas()), o.logs.join(" "));
        if o.executor_id == *d.dex.id() && log.contains("match_failed") {
            on_refund = x;
        } else if o.executor_id != *d.dex.id() && log.contains("ft_transfer") {
            assert!(x <= g(GAS_PAYOUT) / 1.2, "refund payout {x} Tgas over GAS_PAYOUT / 1.2");
            refunds += x;
        } else if o.executor_id != *d.dex.id() && log.is_empty() && x > 0.5 {
            assert!(x <= g(GAS_VIEW) / 1.2, "order_closed read {x} Tgas over GAS_VIEW / 1.2");
        }
    }
    let used = (on_refund + refunds) * 1.2 + 2.0 * g(GAS_PAYOUT);
    assert!(on_refund > 0.0 && used <= g(GAS_ON_REFUND), "on_refund + refunds: {used} Tgas with margin > GAS_ON_REFUND");
    println!("pins: GAS_VIEW {:.0}, GAS_ON_REFUND {:.0}, GAS_PAYOUT {:.0} Tgas", g(GAS_VIEW), g(GAS_ON_REFUND), g(GAS_PAYOUT));
    // refund once
    let out = d.refund(&d.t.bob, id).await;
    assert!(failed_with(&out, "no such settle"), "{:?}", out.failures());
}

#[tokio::test]
async fn refund_before_expiry_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success(), "{:?}", out.failures());
    let id = settle_id(&a.op, &bl.op);
    d.patch(id, |s| s.done = false).await;
    let out = d.refund(&d.t.relayer, id).await;
    assert!(failed_with(&out, BEFORE_EXPIRY), "{:?}", out.failures());
    let now = d.t.now_s().await;
    d.patch(id, |s| s.expiry = now + 3_600).await;
    let out = d.refund(&d.t.relayer, id).await;
    assert!(failed_with(&out, BEFORE_EXPIRY), "{:?}", out.failures());
    assert!(d.pending(id).await.is_some(), "entry kept");
    let out = d.refund(&d.t.relayer, [9; 32]).await;
    assert!(failed_with(&out, "no such settle"), "{:?}", out.failures());
}

/// `mtx_cancel` (op 14) closes an open order; a filled order cannot be cancelled, a cancelled one not twice, and a
/// cancelled order's leg is refused.
#[tokio::test]
async fn cancel_filled_order_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let (e, bob) = (erin.ua(), d.t.near(&d.t.bob));
    assert!(d.settle(&d.t.relayer, &a, &bl).await.is_success());
    let cancel = |lane: [u8; 32], nonce: u64| {
        let p = b(&(lane, nonce));
        let op = d.t.op(OP_CANCEL, &e, &e, 0, &p);
        (erin.sign(&op, ORIGIN), op, p)
    };
    let (au, op, p) = cancel([0xa0; 32], 0);
    d.t.refused(&d.t.relayer, "mtx_cancel", &op, &au, &p, CANCEL_FILLED).await;
    let (au, op, p) = cancel([0xa0; 32], 5);
    let u0 = d.t.usage().await;
    let c = d.t.ok(&d.t.relayer, "mtx_cancel", &op, &au, &p).await;
    let rec = order_bytes(&e, &OrderClose::Cancelled);
    assert_eq!((c.storage_needed.0, d.t.usage().await - u0), (rec as u128 * d.t.byte_cost().await, rec));
    println!("mtx_cancel: order record {rec} B (UA, cancelled)");
    d.t.refused(&d.t.relayer, "mtx_cancel", &op, &au, &p, CANCELLED_TWICE).await;
    let l = d.leg(&erin, &e, d.order(true, 100, 50), [0xa0; 32], 5);
    assert_eq!(d.trade_check(d.dex.id(), &l, &bob).await.error.as_deref(), Some(CANCELLED));
    assert_eq!(d.closed(&l).await, Some(OrderClose::Cancelled));
    // a filled order's leg again
    assert_eq!(d.trade_check(d.dex.id(), &a, &bob).await.error.as_deref(), Some(FILLED));
    // shape and parameters are signed
    let (au, mut op, p) = cancel([0xa0; 32], 6);
    op.extra = sha(&b(&([0xa0u8; 32], 7u64)));
    d.t.refused(&d.t.relayer, "mtx_cancel", &op, &au, &p, "extra is not sha256 of the parameters").await;
    let (_, mut op, p) = cancel([0xa0; 32], 6);
    op.nonce = 1;
    d.t.refused(&d.t.relayer, "mtx_cancel", &op, &erin.sign(&op, ORIGIN), &p, "cancel shape").await;
}

/// CTR-DEX-10: `min_nonce < 2^63` (NEAR nonces are u64), only increasing; orders below it are refused.
#[tokio::test]
async fn min_nonce_cap_refused() {
    let d = setup_dex().await;
    let erin = Signer::ed("erin");
    let (e, bob) = (erin.ua(), d.t.near(&d.t.bob));
    d.fund(&d.t.token, &e, 100).await;
    let inv = |min: u64| {
        let p = b(&([0xa0u8; 32], min));
        let op = d.t.op(OP_INVALIDATE_NONCES, &e, &e, 0, &p);
        (erin.sign(&op, ORIGIN), op, p)
    };
    let (au, op, p) = inv(1 << 63);
    d.t.refused(&d.t.relayer, "mtx_invalidate_nonces", &op, &au, &p, MIN_CAP).await;
    let (au, op, p) = inv(u64::MAX);
    d.t.refused(&d.t.relayer, "mtx_invalidate_nonces", &op, &au, &p, MIN_CAP).await;
    let (au, op, p) = inv(10);
    let u0 = d.t.usage().await;
    let c = d.t.ok(&d.t.relayer, "mtx_invalidate_nonces", &op, &au, &p).await;
    let opened = record_bytes(&e, &Subject { keys: vec![erin.key()], ..Default::default() });
    let rec = TRADE_RECORD_OVERHEAD + b(&e).len() as u64;
    assert_eq!((c.storage_needed.0, d.t.usage().await - u0), ((opened + rec) as u128 * d.t.byte_cost().await, opened + rec));
    println!("mtx_invalidate_nonces: min_nonce record {rec} B (UA)");
    d.t.refused(&d.t.relayer, "mtx_invalidate_nonces", &op, &au, &p, MIN_UP).await;
    let (au, op, p) = inv(5);
    d.t.refused(&d.t.relayer, "mtx_invalidate_nonces", &op, &au, &p, MIN_UP).await;
    let l = d.leg(&erin, &e, d.order(true, 100, 50), [0xa0; 32], 9);
    assert_eq!(d.trade_check(d.dex.id(), &l, &bob).await.error.as_deref(), Some(BELOW_MIN));
    let l = d.leg(&erin, &e, d.order(true, 100, 50), [0xa0; 32], 10);
    assert_eq!(d.trade_check(d.dex.id(), &l, &bob).await.error, None, "nonce = min_nonce is valid");
    let l = d.leg(&erin, &e, d.order(true, 100, 50), [0xa1; 32], 0);
    assert_eq!(d.trade_check(d.dex.id(), &l, &bob).await.error, None, "per lane");
    let (au, op, p) = inv((1 << 63) - 1);
    d.t.ok(&d.t.relayer, "mtx_invalidate_nonces", &op, &au, &p).await;
    let m: u64 = d.t.token.view("min_nonce").args(b(&(&e, [0xa0u8; 32]))).await.unwrap().borsh().unwrap();
    assert_eq!(m, (1 << 63) - 1);
    let p = b(&([0xa0u8; 32], 9u64));
    let op = d.t.op(OP_CANCEL, &e, &e, 0, &p);
    d.t.refused(&d.t.relayer, "mtx_cancel", &op, &erin.sign(&op, ORIGIN), &p, BELOW_MIN).await;
}

/// Fill-or-kill: a leg moves the whole `sell_amount` or nothing; each side's `sell_amount` covers the other's `min_buy`;
/// a leg already in a settle is refused (no second fill).
#[tokio::test]
async fn no_partial_fill() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let (e, bob) = (erin.ua(), d.t.near(&d.t.bob));
    let part = d.resign(&erin, a.clone(), |l| l.op.amount = 99);
    assert_eq!(d.trade_check(d.dex.id(), &part, &bob).await.error.as_deref(), Some(FOK_AMOUNT));
    let out = d.settle(&d.t.relayer, &part, &bl).await;
    assert!(failed_with(&out, FOK_AMOUNT), "{:?}", out.failures());
    // price: bob wants 101 A, erin sells 100
    let b2 = d.leg(&bobk, &bob, d.order(false, 60, 101), [0xb0; 32], 0);
    let out = d.settle(&d.t.relayer, &a, &b2).await;
    assert!(failed_with(&out, FOK_PRICE), "{:?}", out.failures());
    // erin wants 61 B, bob sells 60
    let a2 = d.leg(&erin, &e, d.order(true, 100, 61), [0xa0; 32], 0);
    let out = d.settle(&d.t.relayer, &a2, &bl).await;
    assert!(failed_with(&out, FOK_PRICE), "{:?}", out.failures());
    // the pair must cross: both selling A
    let a3 = d.leg(&erin, &e, d.order(true, 100, 50), [0xa0; 32], 1);
    let out = d.settle(&d.t.relayer, &a, &a3).await;
    assert!(failed_with(&out, "orders do not pair"), "{:?}", out.failures());
    // orders selling and buying the same token
    let o = Order { buy_token: a.order.sell_token.clone(), min_buy: 0, ..a.order.clone() };
    let (s1, s2) = (d.leg(&erin, &e, o.clone(), [0xa0; 32], 2), d.leg(&erin, &e, o, [0xa0; 32], 3));
    let out = d.settle(&d.t.relayer, &s1, &s2).await;
    assert!(failed_with(&out, "orders do not pair"), "{:?}", out.failures());
    assert_eq!(d.bal(&d.t.token, &e).await, 100, "nothing moved");
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success() && has(&out, r#""event":"matched""#), "{:?}", out.failures());
    // either leg again, with any counter-leg, while the entry holds it
    let b3 = d.leg(&bobk, &bob, d.order(false, 60, 100), [0xb0; 32], 1);
    let out = d.settle(&d.t.relayer, &a, &b3).await;
    assert!(failed_with(&out, IN_SETTLE), "{:?}", out.failures());
    let out = d.settle(&d.t.relayer, &a3, &bl).await;
    assert!(failed_with(&out, IN_SETTLE), "{:?}", out.failures());
}

/// The callback's gas is reserved before any leg runs: `settle` refuses a prepaid gas below the minimum.
#[tokio::test]
async fn settle_short_gas_refused() {
    let d = setup_dex().await;
    let (erin, bobk) = (Signer::ed("erin"), Signer::ed("bobk"));
    let (a, bl) = d.pair(&erin, &bobk).await;
    let out = d.settle_gas(&d.t.relayer, &a, &bl, Gas::from_gas(SETTLE_MIN_GAS.as_gas() - 1)).await;
    assert!(failed_with(&out, SHORT_GAS), "{:?}", out.failures());
    assert_eq!(d.bal(&d.t.token, &erin.ua()).await, 100);
    let out = d.settle_gas(&d.t.relayer, &a, &bl, Gas::from_gas(SETTLE_MIN_GAS.as_gas())).await;
    assert!(out.is_success(), "{:?}", out.failures());
}

/// Ruling (T8 pre-flight): `settle`'s gas pinned — two passkey legs (the costliest single-key kind), both paid out;
/// each receipt within its static gas / 1.2 (legs: `GAS_LEG_MIN`; `on_legs`: `GAS_ON_LEGS` less its two payouts).
#[tokio::test]
async fn settle_gas_pin() {
    let d = setup_dex().await;
    let (pa, pb) = (Signer::pk(7, RP), Signer::pk(8, RP));
    let (ha, hb) = (pa.ua(), pb.ua());
    d.fund(&d.t.token, &ha, 100).await;
    d.fund(&d.b, &hb, 60).await;
    let a = d.leg(&pa, &ha, d.order(true, 100, 50), [0xa0; 32], 0);
    let bl = d.leg(&pb, &hb, d.order(false, 60, 100), [0xb0; 32], 0);
    let out = d.settle(&d.t.relayer, &a, &bl).await;
    assert!(out.is_success() && has(&out, r#""event":"matched""#), "{:?}", out.failures());
    let tg = |g: u64| g as f64 / 1e12;
    let (mut legs, mut payouts, mut on_legs) = (vec![], vec![], 0.0);
    for o in out.receipt_outcomes() {
        let g = tg(o.gas_burnt.as_gas());
        println!("  receipt {} {g:.3} Tgas {:?}", o.executor_id, o.logs.first());
        let log = o.logs.join(" ");
        if o.executor_id == *d.dex.id() && o.logs.is_empty() && g > 1.0 {
            assert!(g <= tg(GAS_SETTLE_SELF.as_gas()) / 1.2, "settle receipt {g} Tgas over GAS_SETTLE_SELF / 1.2");
        } else if log.contains("order_filled") {
            legs.push(g);
        } else if log.contains(r#""event":"matched""#) {
            on_legs = g;
        } else if log.contains("ft_transfer") {
            payouts.push(g);
        }
    }
    let total = tgas(&out);
    println!("settle_gas_pin: total {total:.3} Tgas (pin {SETTLE_TGAS_PIN}); legs {legs:?}; on_legs {on_legs:.3}; payouts {payouts:?}");
    assert_eq!((legs.len(), payouts.len()), (2, 2));
    assert!(total <= SETTLE_TGAS_PIN / 1.2, "settle {total} Tgas > pin {SETTLE_TGAS_PIN} / 1.2");
    let g = |x: near_sdk::Gas| tg(x.as_gas());
    assert!(legs.iter().all(|&l| l <= g(GAS_LEG_MIN) / 1.2), "passkey leg over GAS_LEG_MIN / 1.2");
    assert!(payouts.iter().all(|&p| p <= g(GAS_PAYOUT) / 1.2), "payout over GAS_PAYOUT / 1.2");
    // on_legs prepays its payouts' static gas and their exec fees (each ≤ the payout's burnt gas)
    let used = (on_legs + payouts.iter().sum::<f64>()) * 1.2 + 2.0 * g(GAS_PAYOUT);
    assert!(used <= g(GAS_ON_LEGS), "on_legs + payouts: {used} Tgas with margin > GAS_ON_LEGS");
    let _ = (GAS_VIEW, GAS_ON_REFUND);
}

