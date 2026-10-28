//! SCaaS NEAR escrow DEX (spec §3.6; CTR-DEX-09 / -10; README §11; NET-TON-09 class): two tokens are two contracts, so
//! a settlement cannot move both legs in one receipt; each leg moves into this account's NEP-141 balance at its token,
//! and the join callback pays both out or refunds.
//!
//! - `settle(order_a, op_a, auth_a, order_b, op_b, auth_b)`, payable, any caller: each order's `relayer` is `None` or
//!   the predecessor (CTR-DEX-09); the leg ops are op 1 for the order's sell token with `to = relayer = this DEX`,
//!   `amount = sell_amount`, `extra = sha256(Borsh(order))`; the pair crosses (each buys what the other sells) and is
//!   fill-or-kill (`a.sell_amount ≥ b.min_buy`, `b.sell_amount ≥ a.min_buy`: each side receives the other's whole
//!   `sell_amount`); no leg is in another settle. Stores the escrow entry under `settle_id = sha256(digest(op_a) ‖
//!   digest(op_b))` and an index per leg digest, both paid from the attached deposit (returned to the submitter when
//!   pruned), keeps 2 yoctoNEAR for the payouts, splits the rest between the two `mtx_trade` legs (each token returns
//!   its excess to the transaction signer), and joins them in `on_legs`.
//! - `on_legs(settle_id)` (`#[private]`): both legs `true` → each token's amount to the other leg's seller
//!   (`ft_transfer` to a native holder, `transfer_to_ua` to a UA id; the leg registered it, so 1 yoctoNEAR); otherwise
//!   the leg that arrived back to its seller. Marks the entry done; an entry already resolved (refund won) is left.
//! - `refund_expired(settle_id)`, anyone, after both expiries: a done entry is pruned; an unresolved one (lost
//!   callback) reads each token's `order_closed` and refunds every leg filled by this settle's own leg op (the leg
//!   digest), then prunes. No leg moves after its order's expiry (the token refuses it), so the read is final; the
//!   index keeps a leg digest in at most one settle until then. Refund wins: a late `on_legs` finds no entry.
//!
//! The DEX holds escrow only between a leg and its callback; it has no admin and no upgrade path (§3.9).
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{borsh, env, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise, PromiseError};
use scaas_near_common::metaop::{MetaOp, Order, OP_TRADE};
use scaas_near_common::{Auth, Holder};

/// Static gas per receipt (spec §3.8 sizing: the measured maximum × 1.5, near-sandbox 2026-10-28, `runs/2026-10-28-near-gas.txt`;
/// tests `settle_gas_pin`, `settle_msig_leg_gas_limit` and `refund_expired_after_lost_callback` fail when a measurement
/// exceeds `pin / 1.2`). A leg's static gas is derived from its auth (`leg_gas`, ruling T8-I2): `GAS_LEG_BASE` plus one
/// per-signature cost per signature (an msig: each member signature), and it also gets an equal share of the unused gas.
///
/// A leg without its signature checks: an ed25519 leg opening a UA burns 4.03 Tgas, a passkey leg 23.70 − 20.0 = 3.7.
pub const GAS_LEG_BASE: Gas = Gas::from_tgas(6);
/// One ed25519 (`ed25519_verify`) or secp256k1 (`ecrecover`) signature, incl. its msig member checks (< 0.5 Tgas).
pub const GAS_SIG_KEY: Gas = Gas::from_tgas(1);
/// One P-256 passkey signature: 20.005 Tgas per verify at opt-level 3 (Task 1, `runs/2026-10-28-p256-spike.txt`) × 1.25.
pub const GAS_SIG_PASSKEY: Gas = Gas::from_tgas(25);
/// `ft_transfer` / `transfer_to_ua` to a registered receiver (2.41 Tgas).
pub const GAS_PAYOUT: Gas = Gas::from_tgas(4);
/// `on_legs` (2.31 Tgas) plus what it prepays for its two payouts (their static gas and exec fees; 2 × 2.41 Tgas).
pub const GAS_ON_LEGS: Gas = Gas::from_tgas(10 + 2 * 4);
/// The token's `order_closed` read (1.54 Tgas).
pub const GAS_VIEW: Gas = Gas::from_tgas(3);
/// `on_refund` (2.86 Tgas) plus what it prepays for its two refunds (2 × 2.13 Tgas).
pub const GAS_ON_REFUND: Gas = Gas::from_tgas(10 + 2 * 4);
/// `settle`'s own receipt (3.24 Tgas burnt with two single-key legs) plus the exec fees it prepays for the three receipts
/// it creates, × 1.5 (`settle_gas_pin` runs two passkey legs at exactly `settle_gas`).
pub const GAS_SETTLE_SELF: Gas = Gas::from_tgas(9);
/// Kept per settle for the two payouts / refunds (1 yoctoNEAR each, NEP-141).
const PAYOUT_YOCTO: u128 = 2;

type R<T> = Result<T, &'static str>;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Leg {
    pub token: AccountId,
    pub seller: Holder,
    pub lane: [u8; 32],
    pub nonce: u64,
    pub digest: [u8; 32],
    pub amount: u128,
}

/// An escrow entry: pruned (deposit back to `relayer`) once done or refunded after `expiry` (the later order's).
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settle {
    pub legs: [Leg; 2],
    pub relayer: AccountId,
    pub deposit: u128,
    pub expiry: u64,
    pub done: bool,
}

/// `order_closed`'s answer (the token's `OrderClose`, same Borsh).
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OrderClose {
    Filled([u8; 32]),
    Cancelled,
}

#[near(event_json(standard = "scaas"))]
pub enum Event {
    /// Both legs arrived; each seller is paid the other's amount. `legs` = the two leg op digests (settle-argument order),
    /// the tokens' `order_filled.digest`.
    #[event_version("1.0.0")]
    Matched { settle_id: String, legs: [String; 2] },
    /// Not both legs arrived (or the callback was lost): `refunded` = the digests of the legs paid back to their sellers.
    #[event_version("1.0.0")]
    MatchFailed { settle_id: String, legs: [String; 2], refunded: Vec<String> },
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Dex {
    settles: LookupMap<[u8; 32], Settle>,
    /// Leg digest → its settle, while the entry exists.
    legs: LookupMap<[u8; 32], [u8; 32]>,
}

fn x(b: &[u8]) -> String {
    format!("0x{}", b.iter().map(|v| format!("{v:02x}")).collect::<String>())
}

fn digests(s: &Settle) -> [String; 2] {
    [x(&s.legs[0].digest), x(&s.legs[1].digest)]
}

fn now_s() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

/// One leg's shape against its order (the token checks the same, and the signature).
fn leg(order: &Order, op: &MetaOp, me: &AccountId, caller: &AccountId) -> R<Leg> {
    if order.relayer.as_ref().is_some_and(|r| r != caller) {
        return Err("order relayer is not the predecessor");
    }
    if op.op != OP_TRADE || op.contract != order.sell_token || op.to != Holder::Near(me.clone()) || op.relayer.as_ref() != Some(me) {
        return Err("leg: op 1 for the order's sell token, to = relayer = this DEX");
    }
    if op.amount != order.sell_amount || op.amount == 0 {
        return Err("fill-or-kill: op amount = sell_amount");
    }
    if op.extra != order.hash() {
        return Err("extra is not sha256 of the order");
    }
    if now_s() > order.expiry {
        return Err("order expired");
    }
    Ok(Leg { token: order.sell_token.clone(), seller: op.from.clone(), lane: op.lane, nonce: op.nonce, digest: op.digest(), amount: op.amount })
}

/// A leg's static gas from its auth: `GAS_LEG_BASE` + each signature's cost (an msig: its member signatures; a
/// `near-account` member signs as the predecessor, free).
pub fn leg_gas(auth: &Auth) -> Gas {
    fn sigs(a: &Auth) -> u64 {
        match a {
            Auth::Passkey { .. } => GAS_SIG_PASSKEY.as_gas(),
            Auth::Ed25519 { .. } | Auth::Secp256k1 { .. } => GAS_SIG_KEY.as_gas(),
            Auth::Msig { sigs: s, .. } => s.iter().map(|(_, a)| sigs(a)).fold(0, u64::saturating_add),
        }
    }
    Gas::from_gas(GAS_LEG_BASE.as_gas().saturating_add(sigs(auth)))
}

/// What `settle` needs prepaid: itself, the callback (with its payouts) and both legs' derived gas.
pub fn settle_gas(auth_a: &Auth, auth_b: &Auth) -> Gas {
    Gas::from_gas(
        (GAS_SETTLE_SELF.as_gas() + GAS_ON_LEGS.as_gas()).saturating_add(leg_gas(auth_a).as_gas()).saturating_add(leg_gas(auth_b).as_gas()),
    )
}

/// Largest `client_data_json` / `authenticator_data` of a passkey signature on a trade leg (review T8-M4, controller
/// ruling). `leg_gas` budgets a passkey at a fixed 25 Tgas, but its verify cost grows with these sizes (scan and
/// sha256 of clientDataJSON, sha256 of authenticatorData ‖ hash); real assertions are ≈ 400 B. Without the cap a maker
/// could sign padded assertions that run the leg out of gas (deposit share stranded at the DEX).
pub const PASSKEY_FIELD_MAX: usize = 1024;

/// Every passkey signature of `auth` (directly or as an msig member) within `PASSKEY_FIELD_MAX`.
fn passkey_fields(auth: &Auth) -> R<()> {
    match auth {
        Auth::Passkey { authenticator_data: ad, client_data_json: cd, .. } => {
            if cd.len() > PASSKEY_FIELD_MAX || ad.len() > PASSKEY_FIELD_MAX {
                return Err("passkey clientDataJSON / authenticatorData over 1024 bytes");
            }
            Ok(())
        }
        Auth::Msig { sigs, .. } => sigs.iter().try_for_each(|(_, a)| passkey_fields(a)),
        Auth::Ed25519 { .. } | Auth::Secp256k1 { .. } => Ok(()),
    }
}

/// `sha256(digest(op_a) ‖ digest(op_b))` (ruling, T8 pre-flight).
pub fn settle_id(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    env::sha256_array([&a[..], b].concat())
}

/// The pair crosses and is fill-or-kill.
fn pair(a: &Order, b: &Order) -> R<()> {
    if a.sell_token != b.buy_token || b.sell_token != a.buy_token || a.sell_token == a.buy_token {
        return Err("orders do not pair (each buys what the other sells)");
    }
    if a.sell_amount < b.min_buy || b.sell_amount < a.min_buy {
        return Err("fill-or-kill: each side's sell_amount covers the other's min_buy");
    }
    Ok(())
}

/// A leg arrived at this DEX for this settle: its order was filled by this very leg op (`order_closed` read).
fn arrived(r: &Result<Vec<u8>, PromiseError>, l: &Leg) -> Option<bool> {
    let v: Option<OrderClose> = borsh::from_slice(r.as_ref().ok()?).ok()?;
    Some(v == Some(OrderClose::Filled(l.digest)))
}

/// `true` when leg `i`'s `mtx_trade` returned `true`.
fn leg_ok(i: u64) -> bool {
    env::promise_result_checked(i, 1).is_ok_and(|v| v == [1])
}

/// Pays `amount` of `token` to `to` from this DEX's balance: 1 yoctoNEAR, the receiver's record exists.
fn pay(token: &AccountId, to: &Holder, amount: u128) {
    let (method, args) = match to {
        Holder::Near(a) => ("ft_transfer", near_sdk::serde_json::json!({"receiver_id": a, "amount": U128(amount)})),
        Holder::Ua(id) => ("transfer_to_ua", near_sdk::serde_json::json!({"id": id, "amount": U128(amount)})),
    };
    Promise::new(token.clone())
        .function_call_weight(method, args.to_string().into_bytes(), NearToken::from_yoctonear(1), GAS_PAYOUT, GasWeight(0))
        .detach();
}

#[near]
impl Dex {
    #[init]
    #[private]
    pub fn new() -> Self {
        Self { settles: LookupMap::new(b"s"), legs: LookupMap::new(b"l") }
    }

    #[payable]
    pub fn settle(
        &mut self,
        #[serializer(borsh)] order_a: Order,
        #[serializer(borsh)] op_a: MetaOp,
        #[serializer(borsh)] auth_a: Auth,
        #[serializer(borsh)] order_b: Order,
        #[serializer(borsh)] op_b: MetaOp,
        #[serializer(borsh)] auth_b: Auth,
    ) -> Promise {
        let (me, caller) = (env::current_account_id(), env::predecessor_account_id());
        let legs = leg(&order_a, &op_a, &me, &caller)
            .and_then(|a| Ok([a, leg(&order_b, &op_b, &me, &caller)?]))
            .and_then(|l| pair(&order_a, &order_b).map(|_| l))
            .and_then(|l| passkey_fields(&auth_a).and(passkey_fields(&auth_b)).map(|_| l))
            .unwrap_or_else(|e| env::panic_str(e));
        // Ruling T8-I2: refused before any write or promise (nothing held, no leg can run out of gas).
        require!(env::prepaid_gas() >= settle_gas(&auth_a, &auth_b), "prepaid gas below the settle minimum (legs + callback)");
        let id = settle_id(&legs[0].digest, &legs[1].digest);
        require!(legs.iter().all(|l| !self.legs.contains_key(&l.digest)), "a leg is already in a settle");
        let u0 = env::storage_usage();
        for l in &legs {
            self.legs.insert(l.digest, id);
        }
        let expiry = order_a.expiry.max(order_b.expiry);
        self.settles.insert(id, Settle { legs: legs.clone(), relayer: caller, deposit: u128::MAX, expiry, done: false });
        self.legs.flush();
        self.settles.flush();
        let deposit = env::storage_byte_cost().as_yoctonear() * (env::storage_usage() - u0) as u128;
        self.settles.get_mut(&id).unwrap().deposit = deposit;
        let rest = env::attached_deposit()
            .as_yoctonear()
            .checked_sub(deposit + PAYOUT_YOCTO)
            .unwrap_or_else(|| env::panic_str("attached deposit below the escrow entry storage"));
        let call = |order: Order, op: MetaOp, auth: Auth, receiver: &Holder, d: u128| {
            let gas = leg_gas(&auth);
            let args = borsh::to_vec(&(op, auth, &order, receiver)).unwrap();
            Promise::new(order.sell_token.clone()).function_call_weight("mtx_trade", args, NearToken::from_yoctonear(d), gas, GasWeight(1))
        };
        let (da, db) = (rest / 2, rest - rest / 2);
        let leg_a = call(order_a, op_a, auth_a, &legs[1].seller, da);
        let leg_b = call(order_b, op_b, auth_b, &legs[0].seller, db);
        leg_a.and(leg_b).then(Promise::new(me).function_call_weight(
            "on_legs",
            borsh::to_vec(&id).unwrap(),
            NearToken::from_yoctonear(0),
            GAS_ON_LEGS,
            GasWeight(0),
        ))
    }

    #[private]
    pub fn on_legs(&mut self, #[serializer(borsh)] settle_id: [u8; 32]) {
        let ok = [leg_ok(0), leg_ok(1)];
        let Some(s) = self.settles.get_mut(&settle_id) else { return };
        if s.done {
            return;
        }
        s.done = true;
        let s = s.clone();
        let [a, b] = &s.legs;
        if ok == [true, true] {
            pay(&a.token, &b.seller, a.amount);
            pay(&b.token, &a.seller, b.amount);
            Event::Matched { settle_id: x(&settle_id), legs: digests(&s) }.emit();
            return;
        }
        let mut refunded = vec![];
        for (l, _) in s.legs.iter().zip(ok).filter(|(_, ok)| *ok) {
            pay(&l.token, &l.seller, l.amount);
            refunded.push(x(&l.digest));
        }
        Event::MatchFailed { settle_id: x(&settle_id), legs: digests(&s), refunded }.emit();
    }

    /// Anyone, after both orders' expiries: prunes a done entry; refunds the legs of an unresolved one (lost callback).
    pub fn refund_expired(&mut self, #[serializer(borsh)] settle_id: [u8; 32]) {
        let s = self.settles.get(&settle_id).cloned().unwrap_or_else(|| env::panic_str("no such settle"));
        require!(now_s() > s.expiry, "refund before expiry");
        if s.done {
            return self.prune(settle_id, &s);
        }
        let read = |l: &Leg| {
            Promise::new(l.token.clone()).function_call_weight(
                "order_closed",
                borsh::to_vec(&(&l.seller, l.lane, l.nonce)).unwrap(),
                NearToken::from_yoctonear(0),
                GAS_VIEW,
                GasWeight(0),
            )
        };
        let cb = Promise::new(env::current_account_id()).function_call_weight(
            "on_refund",
            borsh::to_vec(&settle_id).unwrap(),
            NearToken::from_yoctonear(0),
            GAS_ON_REFUND,
            GasWeight(0),
        );
        read(&s.legs[0]).and(read(&s.legs[1])).then(cb).detach();
    }

    /// Refund wins: every leg the tokens show filled by this settle's own leg op goes back to its seller, then the entry
    /// is pruned. A read that failed leaves the entry for another `refund_expired`.
    #[private]
    pub fn on_refund(&mut self, #[serializer(borsh)] settle_id: [u8; 32]) {
        let Some(s) = self.settles.get(&settle_id).cloned() else { return };
        if !s.done {
            let r = [env::promise_result_checked(0, 64), env::promise_result_checked(1, 64)];
            let Some(arr) = s.legs.iter().zip(&r).map(|(l, r)| arrived(r, l)).collect::<Option<Vec<bool>>>() else { return };
            let mut refunded = vec![];
            for (l, _) in s.legs.iter().zip(arr).filter(|(_, a)| *a) {
                pay(&l.token, &l.seller, l.amount);
                refunded.push(x(&l.digest));
            }
            Event::MatchFailed { settle_id: x(&settle_id), legs: digests(&s), refunded }.emit();
        }
        self.prune(settle_id, &s);
    }

    #[result_serializer(borsh)]
    pub fn pending(&self, #[serializer(borsh)] settle_id: [u8; 32]) -> Option<Settle> {
        self.settles.get(&settle_id).cloned()
    }
}

impl Dex {
    /// Deletes the entry and its leg index; the deposit back to the relayer that staked it.
    fn prune(&mut self, id: [u8; 32], s: &Settle) {
        self.settles.remove(&id);
        for l in &s.legs {
            self.legs.remove(&l.digest);
        }
        if s.deposit > 0 {
            Promise::new(s.relayer.clone()).transfer(NearToken::from_yoctonear(s.deposit)).detach();
        }
    }
}

#[cfg(test)]
mod tests {
    //! `settle_id` and the leg shape against `near-vectors.json` (gen_vectors.py `dex_vectors`, ruling R5); the refund's
    //! own-leg guard.
    use super::*;
    use near_sdk::serde_json::{self, Value};
    use near_sdk::test_utils::VMContextBuilder;
    use near_sdk::testing_env;

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");

    fn hx(v: &Value) -> Vec<u8> {
        let s = v.as_str().unwrap().trim_start_matches("0x");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    #[test]
    fn settle_vectors_match() {
        let d: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let rows = d["metaops"]["vectors"].as_array().unwrap();
        let row = |n: &str| rows.iter().find(|r| r["name"] == n).unwrap_or_else(|| panic!("no row {n}"));
        let me: AccountId = d["accounts"]["dex"].as_str().unwrap().parse().unwrap();
        let relayer: AccountId = d["accounts"]["relayer"].as_str().unwrap().parse().unwrap();
        testing_env!(VMContextBuilder::new().current_account_id(me.clone()).predecessor_account_id(relayer.clone()).build());
        let leg_of = |n: &str| {
            let r = row(n);
            let op: MetaOp = borsh::from_slice(&hx(&r["encoding"])[b"scaas.metaop.v1".len()..]).unwrap();
            let order: Order = borsh::from_slice(&hx(&r["order"])).unwrap();
            assert_eq!(op.digest().to_vec(), hx(&r["digest"]));
            (order, op)
        };
        let ((oa, opa), (ob, opb)) = (leg_of("trade_a"), leg_of("trade_b"));
        let (la, lb) = (leg(&oa, &opa, &me, &relayer).unwrap(), leg(&ob, &opb, &me, &relayer).unwrap());
        pair(&oa, &ob).unwrap();
        assert_eq!(settle_id(&la.digest, &lb.digest).to_vec(), hx(&d["dexSettle"]["settleId"]));
        // order A is bound to RELAYER: another submitter is refused (CTR-DEX-09)
        let other: AccountId = "mallory.test.near".parse().unwrap();
        assert_eq!(leg(&oa, &opa, &me, &other).err(), Some("order relayer is not the predecessor"));
        assert!(leg(&ob, &opb, &me, &other).is_ok(), "order B is open");
    }

    /// Refund wins: a late `on_legs` on a resolved (or pruned) entry creates no payout.
    #[test]
    fn late_on_legs_pays_nothing() {
        use near_sdk::test_utils::get_created_receipts;
        use near_sdk::PromiseResult;
        let me: AccountId = "dex.test.near".parse().unwrap();
        let ctx = VMContextBuilder::new().current_account_id(me.clone()).predecessor_account_id(me.clone()).build();
        let ok = vec![PromiseResult::Successful(vec![1]), PromiseResult::Successful(vec![1])];
        testing_env!(ctx.clone(), near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(), ok);
        let mut dex = Dex::new();
        let l = |t: &str| Leg { token: t.parse().unwrap(), seller: Holder::Ua([1; 32]), lane: [0; 32], nonce: 0, digest: [2; 32], amount: 5 };
        let s = Settle { legs: [l("a.near"), l("b.near")], relayer: me.clone(), deposit: 0, expiry: 0, done: true };
        dex.settles.insert([7; 32], s.clone());
        dex.on_legs([7; 32]);
        dex.on_legs([8; 32]);
        assert!(get_created_receipts().is_empty(), "done / missing entry: nothing paid");
        dex.settles.insert([7; 32], Settle { done: false, ..s });
        dex.on_legs([7; 32]);
        assert_eq!(get_created_receipts().len(), 2, "an unresolved entry pays both out");
        assert!(dex.settles.get(&[7; 32]).unwrap().done);
    }

    /// Refund wins only once: an `on_refund` that finds the entry already done (an `on_legs` ran between
    /// `refund_expired` and it) refunds nothing and just prunes (review T8-M1).
    #[test]
    fn on_refund_after_on_legs_pays_nothing() {
        use near_sdk::test_utils::get_created_receipts;
        use near_sdk::PromiseResult;
        let me: AccountId = "dex.test.near".parse().unwrap();
        let ctx = VMContextBuilder::new().current_account_id(me.clone()).predecessor_account_id(me.clone()).build();
        let r = |d: [u8; 32]| PromiseResult::Successful(borsh::to_vec(&Some(OrderClose::Filled(d))).unwrap());
        testing_env!(ctx, near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(), vec![r([2; 32]), r([3; 32])]);
        let mut dex = Dex::new();
        let l = |t: &str, d: u8| Leg { token: t.parse().unwrap(), seller: Holder::Ua([1; 32]), lane: [0; 32], nonce: 0, digest: [d; 32], amount: 5 };
        dex.settles.insert([7; 32], Settle { legs: [l("a.near", 2), l("b.near", 3)], relayer: me, deposit: 0, expiry: 0, done: true });
        dex.on_refund([7; 32]);
        assert!(get_created_receipts().is_empty(), "done entry: on_refund must not refund");
        assert!(dex.settles.get(&[7; 32]).is_none(), "pruned");
    }

    /// M4: a passkey field over 1024 bytes is refused, directly or as an msig member; 1024 is accepted.
    #[test]
    fn passkey_field_cap() {
        let pk = |cd: usize, ad: usize| Auth::Passkey { key: [0; 64], authenticator_data: vec![0; ad], client_data_json: vec![0; cd], sig: [0; 64] };
        let err = Err("passkey clientDataJSON / authenticatorData over 1024 bytes");
        assert_eq!(passkey_fields(&pk(1024, 1024)), Ok(()));
        assert_eq!((passkey_fields(&pk(1025, 37)), passkey_fields(&pk(400, 1025))), (err, err));
        let ed = Auth::Ed25519 { key: [0; 32], sig: [0; 64] };
        let m = |p: Auth| Auth::Msig { key_data: vec![], sigs: vec![(0, ed.clone()), (1, p)] };
        assert_eq!((passkey_fields(&m(pk(400, 37))), passkey_fields(&m(pk(1025, 37)))), (Ok(()), err));
    }

    /// `leg_gas`: base + per signature by kind; an msig counts its member signatures.
    #[test]
    fn leg_gas_by_auth() {
        let ed = Auth::Ed25519 { key: [0; 32], sig: [0; 64] };
        let pk = Auth::Passkey { key: [0; 64], authenticator_data: vec![], client_data_json: vec![], sig: [0; 64] };
        let t = |g: Gas| g.as_tgas();
        assert_eq!((t(leg_gas(&ed)), t(leg_gas(&pk))), (7, 31));
        let m = |n: usize| Auth::Msig { key_data: vec![], sigs: (0..n as u8).map(|i| (i, pk.clone())).chain([(99, ed.clone())]).collect() };
        assert_eq!(t(leg_gas(&m(10))), 6 + 250 + 1);
        assert_eq!(t(settle_gas(&m(10), &ed)), 9 + 18 + 257 + 7);
    }

    /// The refund pays a leg back only when its order was filled by this settle's own leg op.
    #[test]
    fn refund_only_own_leg() {
        let l = Leg { token: "t.near".parse().unwrap(), seller: Holder::Ua([1; 32]), lane: [2; 32], nonce: 3, digest: [4; 32], amount: 5 };
        let r = |c: Option<OrderClose>| Ok(borsh::to_vec(&c).unwrap());
        assert_eq!(arrived(&r(Some(OrderClose::Filled([4; 32]))), &l), Some(true));
        assert_eq!(arrived(&r(Some(OrderClose::Filled([9; 32]))), &l), Some(false), "filled by another leg op");
        assert_eq!(arrived(&r(Some(OrderClose::Cancelled)), &l), Some(false));
        assert_eq!(arrived(&r(None), &l), Some(false));
        assert_eq!(arrived(&Err(PromiseError::Failed), &l), None, "unknown: the entry stays");
    }
}
