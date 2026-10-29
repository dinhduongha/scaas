//! SCaaS NEAR escrow relay-fee router (spec §3.8 "Escrow router", §2 rows 8–14; CTR-MTX-16, CTR-MTX-27; rulings R2,
//! R10, T10 pre-flight a–g). A token fee for a call on another contract: two contracts cannot settle in one receipt, so
//! the payment is held at the token first and settled by a callback; refund wins whenever the call's success is not
//! proven. One `relay` transaction:
//!
//! 1. `relay(target, method, args, target_gas, target_deposit, token, op, auth)` (the relayer): `ref =
//!    keccak256("scaas.relayfee" ‖ op.network ‖ u8 len ‖ target ‖ keccak256(u8 len ‖ target ‖ u8 len ‖ method ‖ args) ‖
//!    op.extra)` (`call_ref`; the salt is the payment's payer-signed `extra`, the network the one the token checks the
//!    op against); shape `op 0`, `pay_ref == ref`, `lane == payLane(ref)`, nonce 0, `relayer == router`, `to ≠ executor`;
//!    `target`, `token ∉ {router, executor}`; prepaid gas ≥ `relay_gas`; attached ≥ the entry's storage + a payee
//!    registration + 2 yoctoNEAR + `target_deposit` (R10). Stores `pending[ref]` (relayer = the predecessor, deadline =
//!    now + `RELAY_TIMEOUT_S`), keeps the entry deposit and `target_deposit`, forwards the rest to `token.relay_hold`.
//! 2. token `relay_hold(op, auth, relayer)`: the shared routed pay checks with this router as the marker, the lane
//!    consumed, `amount` held for (router, ref); a refusal returns `false` and sends its deposit to the relayer.
//! 3. `on_hold`: refused → the entry deleted, its deposit and `target_deposit` back to the relayer; else the executor
//!    calls the target (`exec`, exactly `target_deposit` and `target_gas`; the target sees the executor, never the router).
//! 4. `on_call`: the target's own receipt succeeded (`PromiseResult::Successful` of executor → target; ruling e: the
//!    executor sends the call with a trailing 0-yoctoNEAR transfer action, so the result is the target's own receipt's
//!    even when the target returns a promise; a target that succeeds while a child promise it spawned — detached or
//!    returned — fails still counts as success) → token `relay_release(ref)`; anything else → token `relay_refund(ref)`
//!    and, with a deposit, executor `return_deposit(relayer, target_deposit)` (only a failed receipt refunds its
//!    deposit, and it lands at the executor).
//! 5. `on_settle`: both done → the entry deleted, its deposit back to the relayer that staked it, `relay_fee_paid` on a
//!    release only (NET-NEAR-07); a token settle that failed leaves the entry for the timeout (refund wins); a deposit
//!    return that failed (the refund not landed yet) leaves it as `Owed`, forwarded by `relay_timeout`.
//!
//! `relay_timeout(ref)`, anyone, after the deadline, while no settlement is in flight: refunds (the call's success can no
//! longer be proven), or forwards an owed deposit. Each callback carries its entry's `id` (a per-router counter: after a
//! timeout the same `ref` can open again) and checks the entry's id and stage, so a late `on_hold` refunds what it held,
//! a late `on_call` pays nothing (a failure only returns its own deposit), and neither touches a newer entry of the same
//! `ref` (review m1); the token's held record makes release and refund exclusive anyway.
//! The router never pays itself or the executor (open mode `to == router` pays the relayer, `to == executor` is
//! refused); it has no admin, no upgrade path and no access key (§3.9).
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{
    borsh, env, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise, PromiseError, PromiseOrValue,
};
use scaas_near_common::auth::{passkey_fields, sig_gas};
use scaas_near_common::hash::{hex, pay_lane, relay_ref};
use scaas_near_common::metaop::OP_PAY;
use scaas_near_common::{with_transfer, Auth, Holder, MetaOp};

/// Spec §3.8 timeout (controller call).
pub const RELAY_TIMEOUT_S: u64 = 3_600;
// Static gas per receipt (spec §3.8 sizing): the measured maximum of every branch in near-sandbox × 1.5, rounded up
// (2026-10-28, `runs/2026-10-28-near-gas.txt`, test `gas_pins_hold`: each figure ≤ pin / 1.2 at exactly `relay_gas`
// prepaid). A callback's figure covers its own receipt; what it prepays its children is added in `relay_gas`. T19 ruling A:
// a receipt that sends NEAR to an account the router does not control (the relayer, the target) adds one
// `IMPLICIT_TRANSFER_GAS` (the relayer lanes are implicit accounts: 8.35 Tgas per transfer, common/src/lib.rs).
/// `relay`'s own receipt (entry write, the hold and `on_hold` promises): 2.261 Tgas, 2.927 with 16 KiB `args`.
pub const GAS_RELAY: Gas = Gas::from_tgas(5);
/// `relay_hold` without its signature budget (a lazily opened UA, lane, payee registration, held record); the hold gets
/// `GAS_HOLD + sig_gas(auth)` (`hold_gas`). An ed25519 hold burns 3.981 Tgas (≤ (5 + 1) / 1.5), a passkey hold 23.635;
/// + one transfer: the hold returns its excess deposit (the floor's payee registration and 2 yoctoNEAR) to the relayer.
pub const GAS_HOLD: Gas = with_transfer(5);
/// `on_hold` (the `exec` and `on_call` promises: 2.198 Tgas, 3.181 with 16 KiB `args`; the refused branch's deposit
/// return: 1.660); + one transfer (that deposit return to the relayer).
pub const GAS_ON_HOLD: Gas = with_transfer(5);
/// The executor's `exec` receipt (the target call and its trailing transfer): 1.585 Tgas, 2.539 with 16 KiB `args`;
/// the target itself gets `target_gas`; + one transfer (the trailing 0-yoctoNEAR transfer action to the target, which
/// may be an implicit account).
pub const GAS_EXEC: Gas = with_transfer(4);
/// `on_call` (the release, or the refund and the deposit return, then `on_settle`): 2.175 / 2.586 Tgas.
pub const GAS_ON_CALL: Gas = Gas::from_tgas(4);
/// One settlement call: the token's `relay_release` (2.750 Tgas) or `relay_refund` (2.748), or the executor's
/// `return_deposit` (1.372); + one transfer (the held record's deposit, or `target_deposit`, back to the relayer).
pub const GAS_RELEASE: Gas = with_transfer(5);
/// `on_settle` (entry deleted, deposit back, event): 1.830 Tgas released, 1.639 refunded; + one transfer (that deposit).
pub const GAS_ON_SETTLE: Gas = with_transfer(3);
/// The token's NEP-145 registration of the longest (64-char) account id (`ACCOUNT_STORAGE_BYTES`): the floor's payee
/// registration (R10).
pub const PAYEE_REGISTRATION_BYTES: u64 = 125;
/// Bytes of an entry = this + Borsh(Pending): key prefix `p` (1) + ref (32), NEAR's 40-byte record overhead. `relay`
/// checks every insert against it.
pub const ENTRY_RECORD_OVERHEAD: u64 = 73;
/// Spec §3.8 step 1: the floor's 2 yoctoNEAR. They travel with the hold's deposit (no settlement call carries a
/// yoctoNEAR: the token's escrow calls are authorised by the holding router as predecessor) and come back as its excess.
pub const FLOOR_YOCTO: u128 = 2;
/// Largest `args` (controller call): they travel through three receipts (`relay` → `on_hold` → `exec` → the target)
/// under static gas, measured at this size (`gas_pins_hold`); a two-leg DEX settle with 10-signature passkey msig legs is
/// about 9 KB (estimate: ≈ 400 B per passkey assertion).
pub const MAX_ARGS_BYTES: usize = 16_384;

const SHAPE: &str = "relay pay shape (op 0, pay_ref = ref, lane = payLane(ref), nonce 0, relayer = the router)";

type R<T> = Result<T, &'static str>;

/// Where an entry is: the hold, the call or a settlement in flight, or settled at the token with `target_deposit` still
/// owed to the relayer through the executor.
#[near(serializers = [borsh])]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Hold,
    Call,
    Settle,
    Owed,
}

/// An escrow entry: `id` = the router's counter at `relay` (the callbacks' identity of it); `payee` `None` = open mode
/// (the relayer); `deposit` = this entry's storage, back to `relayer`; `owed`: the call failed and `target_deposit` goes
/// back to the relayer through the executor.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pending {
    pub id: u64,
    pub token: AccountId,
    pub target: AccountId,
    pub payer: Holder,
    pub payee: Option<Holder>,
    pub amount: u128,
    pub relayer: AccountId,
    pub target_deposit: u128,
    pub deposit: u128,
    pub deadline: u64,
    pub stage: Stage,
    pub owed: bool,
}

/// `relay_check`: the router's refusal, or what `relay` needs (Task 16's simulate). `storage_needed` = the entry (quoted
/// for a 64-char relayer id), `deposit_needed` = the router's floor (the relayer adds the token's `relay_hold_check`
/// storage; the excess comes back), `gas_needed` = `relay_gas`.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub error: Option<String>,
    pub storage_needed: U128,
    pub deposit_needed: U128,
    pub gas_needed: Gas,
}

#[near(event_json(standard = "scaas"))]
pub enum Event {
    /// CTR-MTX-27: the payment for the call on `target` was released to `payee` (the relayer in open mode).
    #[event_version("1.0.0")]
    RelayFeePaid { r#ref: String, target: String, token: String, payer: String, payee: String, amount: U128 },
}

/// Spec §2 row 8 / §3.8 step 1: `ref` with target = u8 len ‖ target id, `call = u8 len ‖ target ‖ u8 len ‖ method ‖ args`.
pub fn call_ref(network: &[u8; 32], target: &AccountId, method: &str, args: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    let t = [&[target.as_str().len() as u8][..], target.as_bytes()].concat();
    relay_ref(network, &t, &[&t[..], &[method.len() as u8], method.as_bytes(), args].concat(), salt)
}

/// The hold's static gas: `GAS_HOLD` + the payer's signature budget.
pub fn hold_gas(auth: &Auth) -> Gas {
    Gas::from_gas(GAS_HOLD.as_gas().saturating_add(sig_gas(auth).as_gas()))
}

/// What `on_call` gets: itself, two settlement calls (a refund and a deposit return), `on_settle`.
pub fn call_gas() -> Gas {
    Gas::from_gas(GAS_ON_CALL.as_gas() + 2 * GAS_RELEASE.as_gas() + GAS_ON_SETTLE.as_gas())
}

/// `relay`'s minimum prepaid gas: itself, the hold, `on_hold`, the executor, `target_gas`, `on_call` with its settlement
/// (spec §3.8: the target can never starve the callbacks).
pub fn relay_gas(auth: &Auth, target_gas: Gas) -> Gas {
    let fixed = GAS_RELAY.as_gas() + GAS_ON_HOLD.as_gas() + GAS_EXEC.as_gas() + call_gas().as_gas();
    Gas::from_gas(fixed.saturating_add(hold_gas(auth).as_gas()).saturating_add(target_gas.as_gas()))
}

pub fn entry_bytes(p: &Pending) -> u64 {
    ENTRY_RECORD_OVERHEAD + borsh::to_vec(p).unwrap().len() as u64
}

fn now_s() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

fn yocto(n: u128) -> NearToken {
    NearToken::from_yoctonear(n)
}

/// The promise `i` of this callback failed (a success with any value, even one too long to read, is a success).
fn failed(i: u64) -> bool {
    matches!(env::promise_result_checked(i, 0), Err(PromiseError::Failed))
}

fn call(to: &AccountId, method: &str, args: Vec<u8>, deposit: u128, gas: Gas, weight: u64) -> Promise {
    Promise::new(to.clone()).function_call_weight(method, args, yocto(deposit), gas, GasWeight(weight))
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Router {
    executor: AccountId,
    pending: LookupMap<[u8; 32], Pending>,
    /// The next entry's `id`.
    next_id: u64,
}

impl Router {
    /// No write: every router-side check of `relay`, cheap first; returns `ref`.
    #[allow(clippy::too_many_arguments)]
    fn relay_plan(&self, target: &AccountId, method: &str, args: &[u8], token: &AccountId, op: &MetaOp, auth: &Auth) -> R<[u8; 32]> {
        let me = env::current_account_id();
        if [target, token].iter().any(|a| **a == me || **a == self.executor) {
            return Err("target or token is the router or its executor");
        }
        if method.is_empty() || method.len() > 255 {
            return Err("method name: 1 to 255 bytes");
        }
        if args.len() > MAX_ARGS_BYTES {
            return Err("args over 16,384 bytes");
        }
        if op.contract != *token {
            return Err("the payment op is not for this token");
        }
        let r = call_ref(&op.network, target, method, args, &op.extra);
        if op.op != OP_PAY || op.pay_ref != r || op.lane != pay_lane(&r) || op.nonce != 0 || op.relayer.as_ref() != Some(&me) {
            return Err(SHAPE);
        }
        if op.to == Holder::Near(self.executor.clone()) {
            return Err("the executor is never paid");
        }
        passkey_fields(auth)?;
        if self.pending.contains_key(&r) {
            return Err("this ref is already in flight");
        }
        Ok(r)
    }

    fn token_settle(p: &Pending, method: &str, r: &[u8; 32]) -> Promise {
        call(&p.token, method, borsh::to_vec(r).unwrap(), 0, GAS_RELEASE, 0)
    }

    fn return_deposit(&self, to: &AccountId, amount: u128) -> Promise {
        call(&self.executor, "return_deposit", borsh::to_vec(&(to, U128(amount))).unwrap(), 0, GAS_RELEASE, 0)
    }

    fn on_settle_promise(r: &[u8; 32], id: u64, released: bool) -> Promise {
        call(&env::current_account_id(), "on_settle", borsh::to_vec(&(r, id, released)).unwrap(), 0, GAS_ON_SETTLE, 1)
    }
}

#[near]
impl Router {
    /// Borsh args; only the router account itself (the deploy run, before its keys are deleted).
    #[init]
    #[private]
    pub fn new(#[serializer(borsh)] executor: AccountId) -> Self {
        Self { executor, pending: LookupMap::new(b"p"), next_id: 0 }
    }

    /// The transaction's value is `on_settle`'s: `true` = released (or `false`: refunded / hold refused).
    #[payable]
    #[result_serializer(borsh)]
    #[allow(clippy::too_many_arguments)]
    pub fn relay(
        &mut self,
        #[serializer(borsh)] target: AccountId,
        #[serializer(borsh)] method: String,
        #[serializer(borsh)] args: Vec<u8>,
        #[serializer(borsh)] target_gas: Gas,
        #[serializer(borsh)] target_deposit: U128,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Promise {
        let (me, relayer) = (env::current_account_id(), env::predecessor_account_id());
        let r = self.relay_plan(&target, &method, &args, &token, &op, &auth).unwrap_or_else(|e| env::panic_str(e));
        require!(env::prepaid_gas() >= relay_gas(&auth, target_gas), "prepaid gas below the relay minimum (hold, call, callbacks)");
        let payee = (op.to != Holder::Near(me.clone())).then(|| op.to.clone());
        let mut p = Pending {
            id: self.next_id,
            token: token.clone(),
            target: target.clone(),
            payer: op.from.clone(),
            payee,
            amount: op.amount,
            relayer: relayer.clone(),
            target_deposit: target_deposit.0,
            deposit: 0,
            deadline: now_s() + RELAY_TIMEOUT_S,
            stage: Stage::Hold,
            owed: false,
        };
        let bytes = entry_bytes(&p);
        p.deposit = env::storage_byte_cost().as_yoctonear() * bytes as u128;
        let keep = p.deposit + target_deposit.0;
        let floor = keep + env::storage_byte_cost().as_yoctonear() * PAYEE_REGISTRATION_BYTES as u128 + FLOOR_YOCTO;
        let attached = env::attached_deposit().as_yoctonear();
        require!(attached >= floor, "attached deposit below the escrow entry, a payee registration, 2 yoctoNEAR and target_deposit");
        self.next_id += 1;
        let id = p.id;
        let u0 = env::storage_usage();
        self.pending.insert(r, p);
        self.pending.flush();
        require!(env::storage_usage() - u0 == bytes, "escrow entry size differs from entry_bytes");
        let hold = call(&token, "relay_hold", borsh::to_vec(&(&op, &auth, &relayer)).unwrap(), attached - keep, hold_gas(&auth), 0);
        let next = Gas::from_gas(GAS_ON_HOLD.as_gas() + GAS_EXEC.as_gas() + target_gas.as_gas() + call_gas().as_gas());
        hold.then(call(&me, "on_hold", borsh::to_vec(&(r, id, &token, &target, &method, &args, target_gas)).unwrap(), 0, next, 1))
    }

    /// Step 3. `id`, `token`, `target`, `method`, `args`, `target_gas` come from `relay` (the call is not stored).
    #[private]
    #[result_serializer(borsh)]
    #[allow(clippy::too_many_arguments)]
    pub fn on_hold(
        &mut self,
        #[serializer(borsh)] pay_ref: [u8; 32],
        #[serializer(borsh)] id: u64,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] target: AccountId,
        #[serializer(borsh)] method: String,
        #[serializer(borsh)] args: Vec<u8>,
        #[serializer(borsh)] target_gas: Gas,
    ) -> PromiseOrValue<bool> {
        let held = env::promise_result_checked(0, 1).is_ok_and(|v| v == [1]);
        let Some(p) = self.pending.get_mut(&pay_ref).filter(|p| p.id == id && p.stage == Stage::Hold) else {
            // the timeout ran first (and already returned the deposits): refund wins, the hold goes back. The key (router,
            // ref) holds this relay's payment only: a newer entry's hold is refused while it is held.
            if held {
                call(&token, "relay_refund", borsh::to_vec(&pay_ref).unwrap(), 0, GAS_RELEASE, 0).detach();
            }
            return PromiseOrValue::Value(false);
        };
        if !held {
            let back = p.deposit + p.target_deposit;
            let relayer = p.relayer.clone();
            self.pending.remove(&pay_ref);
            if back > 0 {
                Promise::new(relayer).transfer(yocto(back)).detach();
            }
            return PromiseOrValue::Value(false);
        }
        p.stage = Stage::Call;
        let (relayer, td) = (p.relayer.clone(), p.target_deposit);
        let exec = call(&self.executor, "exec", borsh::to_vec(&(&target, &method, &args, target_gas)).unwrap(), td, Gas::from_gas(GAS_EXEC.as_gas() + target_gas.as_gas()), 0);
        let me = env::current_account_id();
        exec.then(call(&me, "on_call", borsh::to_vec(&(pay_ref, id, &relayer, U128(td))).unwrap(), 0, call_gas(), 1)).into()
    }

    /// Step 4. `id`, `relayer` and `target_deposit` come from `on_hold`, so a late call (after a timeout deleted the
    /// entry, or a newer entry of the same ref opened) still returns its own failed call's deposit; it pays nothing else.
    #[private]
    #[result_serializer(borsh)]
    pub fn on_call(
        &mut self,
        #[serializer(borsh)] pay_ref: [u8; 32],
        #[serializer(borsh)] id: u64,
        #[serializer(borsh)] relayer: AccountId,
        #[serializer(borsh)] target_deposit: U128,
    ) -> PromiseOrValue<bool> {
        let ok = !failed(0);
        let td = target_deposit.0;
        let Some(p) = self.pending.get_mut(&pay_ref).filter(|p| p.id == id && p.stage == Stage::Call) else {
            if !ok && td > 0 {
                self.return_deposit(&relayer, td).detach();
            }
            return PromiseOrValue::Value(false);
        };
        p.stage = Stage::Settle;
        p.owed = !ok && td > 0;
        let p = p.clone();
        let mut settle = Self::token_settle(&p, if ok { "relay_release" } else { "relay_refund" }, &pay_ref);
        if p.owed {
            settle = settle.and(self.return_deposit(&relayer, td));
        }
        settle.then(Self::on_settle_promise(&pay_ref, id, ok)).into()
    }

    /// Step 5 (and the timeout's settlement). Results: the token call, then the deposit return when `owed`; only the
    /// return when the token was settled before (`Owed` retried by the timeout).
    #[private]
    #[result_serializer(borsh)]
    pub fn on_settle(
        &mut self,
        #[serializer(borsh)] pay_ref: [u8; 32],
        #[serializer(borsh)] id: u64,
        #[serializer(borsh)] released: bool,
    ) -> bool {
        let Some(p) = self.pending.get_mut(&pay_ref).filter(|p| p.id == id && p.stage == Stage::Settle) else { return false };
        let (token_ok, ret_ok) = match (env::promise_results_count(), p.owed) {
            (2, _) => (!failed(0), !failed(1)),
            (_, true) => (true, !failed(0)),
            _ => (!failed(0), true),
        };
        if !token_ok {
            // unsettled at the token: the timeout refunds (refund wins)
            p.stage = Stage::Call;
            p.owed &= !ret_ok;
            return false;
        }
        if !ret_ok {
            p.stage = Stage::Owed;
            return false;
        }
        let p = self.pending.remove(&pay_ref).unwrap();
        if p.deposit > 0 {
            Promise::new(p.relayer.clone()).transfer(yocto(p.deposit)).detach();
        }
        if released {
            let payee = p.payee.unwrap_or(Holder::Near(p.relayer));
            Event::RelayFeePaid {
                r#ref: format!("0x{}", hex(&pay_ref)),
                target: p.target.to_string(),
                token: p.token.to_string(),
                payer: p.payer.to_string(),
                payee: payee.to_string(),
                amount: U128(p.amount),
            }
            .emit();
        }
        released
    }

    /// Anyone, after the deadline, while no settlement is in flight: refunds (a hold or a call whose outcome never came
    /// back), or forwards an owed `target_deposit`. The relayer loses its gas, never the payer its fee.
    pub fn relay_timeout(&mut self, #[serializer(borsh)] pay_ref: [u8; 32]) -> Promise {
        let executor = self.executor.clone();
        let p = self.pending.get_mut(&pay_ref).unwrap_or_else(|| env::panic_str("no such pending ref"));
        require!(now_s() > p.deadline, "relay_timeout before the deadline");
        let refund = match p.stage {
            Stage::Settle => env::panic_str("a settlement is in flight"),
            Stage::Hold => {
                // the call never left: target_deposit is still here
                if p.target_deposit > 0 {
                    Promise::new(p.relayer.clone()).transfer(yocto(p.target_deposit)).detach();
                }
                p.target_deposit = 0;
                true
            }
            Stage::Call => true,
            Stage::Owed => false,
        };
        p.stage = Stage::Settle;
        let p = p.clone();
        let ret = || call(&executor, "return_deposit", borsh::to_vec(&(&p.relayer, U128(p.target_deposit))).unwrap(), 0, GAS_RELEASE, 0);
        let settle = match (refund, p.owed) {
            (true, false) => Self::token_settle(&p, "relay_refund", &pay_ref),
            (true, true) => Self::token_settle(&p, "relay_refund", &pay_ref).and(ret()),
            (false, _) => ret(),
        };
        settle.then(Self::on_settle_promise(&pay_ref, p.id, false))
    }

    #[result_serializer(borsh)]
    pub fn pending(&self, #[serializer(borsh)] pay_ref: [u8; 32]) -> Option<Pending> {
        self.pending.get(&pay_ref).cloned()
    }

    #[result_serializer(borsh)]
    pub fn executor(&self) -> AccountId {
        self.executor.clone()
    }

    /// The gas this router budgets per NEAR transfer to an account it does not control (common
    /// `IMPLICIT_TRANSFER_GAS`), checked by the relayer against the chain's fees at start (T19 review I2).
    pub fn implicit_transfer_gas(&self) -> u64 {
        scaas_near_common::IMPLICIT_TRANSFER_GAS.as_gas()
    }

    #[result_serializer(borsh)]
    #[allow(clippy::too_many_arguments)]
    pub fn relay_check(
        &self,
        #[serializer(borsh)] target: AccountId,
        #[serializer(borsh)] method: String,
        #[serializer(borsh)] args: Vec<u8>,
        #[serializer(borsh)] target_gas: Gas,
        #[serializer(borsh)] target_deposit: U128,
        #[serializer(borsh)] token: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        let gas_needed = relay_gas(&auth, target_gas);
        match self.relay_plan(&target, &method, &args, &token, &op, &auth) {
            Err(e) => Check { error: Some(e.into()), storage_needed: U128(0), deposit_needed: U128(0), gas_needed },
            Ok(_) => {
                let cost = env::storage_byte_cost().as_yoctonear();
                let p = Pending {
                    id: 0,
                    token,
                    target,
                    payer: op.from.clone(),
                    payee: (op.to != Holder::Near(env::current_account_id())).then(|| op.to.clone()),
                    amount: op.amount,
                    relayer: "a".repeat(64).parse().unwrap(),
                    target_deposit: target_deposit.0,
                    deposit: 0,
                    deadline: 0,
                    stage: Stage::Hold,
                    owed: false,
                };
                let storage = cost * entry_bytes(&p) as u128;
                let deposit = storage + cost * PAYEE_REGISTRATION_BYTES as u128 + FLOOR_YOCTO + target_deposit.0;
                Check { error: None, storage_needed: U128(storage), deposit_needed: U128(deposit), gas_needed }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    //! `call_ref` against `near-vectors.json` (`relayRefs` router rows, gen_vectors.py; ruling R5, T10 pre-flight c), and
    //! the entry's stages under mocked promise results: refund wins, a late callback pays nothing, an owed deposit goes
    //! back through the timeout.
    use super::*;
    use near_sdk::serde_json::{self, Value};
    use near_sdk::test_utils::{get_created_receipts, VMContextBuilder};
    use near_sdk::{testing_env, PromiseResult};

    const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../vectors/near-vectors.json");

    fn hx(v: &Value) -> Vec<u8> {
        let s = v.as_str().unwrap().trim_start_matches("0x");
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    }

    fn b32(v: &Value) -> [u8; 32] {
        hx(v).try_into().unwrap()
    }

    #[test]
    fn relay_ref_vectors() {
        let d: Value = serde_json::from_str(&std::fs::read_to_string(VECTORS).unwrap()).unwrap();
        let ops = d["metaops"]["vectors"].as_array().unwrap();
        let router = d["accounts"]["router"].as_str().unwrap();
        let net = b32(&d["network"]);
        let rows: Vec<&Value> = d["relayRefs"].as_array().unwrap().iter().filter(|r| r["kind"] == "router").collect();
        assert!(rows.len() >= 3, "router rows");
        for r in rows {
            let target: AccountId = r["target"].as_str().unwrap().parse().unwrap();
            let (method, args) = (r["method"].as_str().unwrap(), hx(&r["args"]));
            let pay = &ops.iter().find(|m| m["name"] == r["payment"]).unwrap()["fields"];
            // salt = the payment op's payer-signed extra, always (spec §2 row 8)
            let salt = b32(&pay["extra"]);
            assert_eq!(call_ref(&net, &target, method, &args, &salt), b32(&r["ref"]), "{}", r["name"]);
            assert_ne!(call_ref(&net, &target, method, &args, &[0; 32]), b32(&r["ref"]));
            assert_eq!((b32(&pay["pay_ref"]), b32(&pay["lane"])), (b32(&r["ref"]), pay_lane(&b32(&r["ref"]))));
            assert_eq!(pay["relayer"].as_str(), Some(router), "{}: bound to the router", r["name"]);
            let call = [&[target.as_str().len() as u8][..], target.as_bytes(), &[method.len() as u8], method.as_bytes(), &args].concat();
            assert_eq!(call, hx(&r["call"]), "call = u8 len ‖ target ‖ u8 len ‖ method ‖ args");
        }
    }

    const REF: [u8; 32] = [7; 32];
    /// The live entry's id in these tests.
    const ID: u64 = 2;

    fn ctx(results: Vec<PromiseResult>, now_s: u64) {
        let me: AccountId = "router.near".parse().unwrap();
        let c = VMContextBuilder::new()
            .current_account_id(me.clone())
            .predecessor_account_id(me)
            .block_timestamp(now_s * 1_000_000_000)
            .build();
        testing_env!(c, near_sdk::test_vm_config(), near_sdk::RuntimeFeesConfig::test(), Default::default(), results);
    }

    fn router(stage: Stage, owed: bool) -> Router {
        let mut r = Router { executor: "exec.near".parse().unwrap(), pending: LookupMap::new(b"p"), next_id: 3 };
        let p = Pending {
            id: ID,
            token: "token.near".parse().unwrap(),
            target: "target.near".parse().unwrap(),
            payer: Holder::Ua([1; 32]),
            payee: None,
            amount: 10,
            relayer: "relayer.near".parse().unwrap(),
            target_deposit: 5,
            deposit: 100,
            deadline: 50,
            stage,
            owed,
        };
        r.pending.insert(REF, p);
        r
    }

    /// (receiver, method or "transfer", yoctoNEAR) of every receipt this call created.
    fn receipts() -> Vec<(String, String, u128)> {
        use near_sdk::mock::MockAction;
        get_created_receipts()
            .into_iter()
            .flat_map(|r| {
                let to = r.receiver_id.to_string();
                r.actions.into_iter().filter_map(move |a| match a {
                    MockAction::FunctionCallWeight { method_name, attached_deposit, .. } => {
                        Some((to.clone(), String::from_utf8(method_name).unwrap(), attached_deposit.as_yoctonear()))
                    }
                    MockAction::Transfer { deposit, .. } => Some((to.clone(), "transfer".into(), deposit.as_yoctonear())),
                    _ => None,
                })
            })
            .collect()
    }

    fn rc(to: &str, m: &str, d: u128) -> (String, String, u128) {
        (to.into(), m.into(), d)
    }

    fn ok() -> PromiseResult {
        PromiseResult::Successful(vec![])
    }

    /// A late `on_call` (the entry gone, or no longer waiting for the call) settles nothing: a success pays nothing, a
    /// failure only returns its deposit through the executor. A late `on_hold` that held refunds it.
    #[test]
    fn late_callbacks_pay_nothing() {
        let relayer: AccountId = "relayer.near".parse().unwrap();
        for stage in [Stage::Hold, Stage::Settle, Stage::Owed] {
            ctx(vec![ok()], 0);
            let mut r = router(stage, false);
            assert!(matches!(r.on_call(REF, ID, relayer.clone(), U128(5)), PromiseOrValue::Value(false)));
            assert!(receipts().is_empty(), "{stage:?}: a late success pays nothing");
            ctx(vec![PromiseResult::Failed], 0);
            assert!(matches!(r.on_call([9; 32], ID, relayer.clone(), U128(5)), PromiseOrValue::Value(false)));
            assert_eq!(receipts(), vec![rc("exec.near", "return_deposit", 0)], "a late failure returns the deposit only");
        }
        ctx(vec![PromiseResult::Successful(vec![1])], 0);
        let mut r = router(Stage::Call, false);
        let t: AccountId = "token.near".parse().unwrap();
        assert!(matches!(r.on_hold(REF, ID, t.clone(), t.clone(), "m".into(), vec![], Gas::from_tgas(1)), PromiseOrValue::Value(false)));
        assert_eq!(receipts(), vec![rc("token.near", "relay_refund", 0)], "a late hold is refunded");
        assert_eq!(r.pending.get(&REF).unwrap().stage, Stage::Call, "the live entry untouched");
    }

    /// Review m1: relay 1 (its call in flight) times out and its entry is deleted; relay 2 opens the same ref on another
    /// token and is waiting for its own call. Relay 1's late `on_call` — a success or a failure — must not settle relay
    /// 2: no token call, relay 2's entry untouched; a late failure only returns relay 1's own deposit.
    #[test]
    fn stale_callback_leaves_a_newer_entry_alone() {
        let r1: AccountId = "relayer1.near".parse().unwrap();
        for (res, want) in [(ok(), vec![]), (PromiseResult::Failed, vec![rc("exec.near", "return_deposit", 0)])] {
            ctx(vec![res], 0);
            let mut r = router(Stage::Call, false); // relay 2's entry under the same ref
            r.pending.get_mut(&REF).unwrap().token = "token2.near".parse().unwrap();
            let before = r.pending.get(&REF).cloned();
            let _ = r.on_call(REF, 1, r1.clone(), U128(7));
            assert_eq!(receipts(), want, "relay 1's late callback acts on relay 1 only");
            assert_eq!(r.pending.get(&REF).cloned(), before, "relay 2's entry untouched");
        }
        // relay 1's late on_hold (its hold succeeded, so relay 2's hold is refused): refunds relay 1, relay 2 untouched
        ctx(vec![PromiseResult::Successful(vec![1])], 0);
        let mut r = router(Stage::Hold, false);
        let before = r.pending.get(&REF).cloned();
        let t: AccountId = "token1.near".parse().unwrap();
        assert!(matches!(r.on_hold(REF, 1, t.clone(), t, "m".into(), vec![], Gas::from_tgas(1)), PromiseOrValue::Value(false)));
        assert_eq!(receipts(), vec![rc("token1.near", "relay_refund", 0)]);
        assert_eq!(r.pending.get(&REF).cloned(), before);
        // a settle result carrying another entry's id is ignored
        ctx(vec![ok()], 0);
        let mut r = router(Stage::Settle, false);
        let before = r.pending.get(&REF).cloned();
        assert!(!r.on_settle(REF, 1, true));
        assert_eq!((receipts(), r.pending.get(&REF).cloned()), (vec![], before));
    }

    /// `on_hold` refused: the entry deleted, its deposit and `target_deposit` back to the relayer, no call.
    #[test]
    fn hold_refused_returns_deposits() {
        ctx(vec![PromiseResult::Successful(vec![0])], 0);
        let mut r = router(Stage::Hold, false);
        let t: AccountId = "token.near".parse().unwrap();
        assert!(matches!(r.on_hold(REF, ID, t.clone(), t, "m".into(), vec![], Gas::from_tgas(1)), PromiseOrValue::Value(false)));
        assert_eq!(receipts(), vec![rc("relayer.near", "transfer", 105)]);
        assert!(r.pending.get(&REF).is_none());
    }

    /// A token settle that failed leaves the entry for the timeout (stage `Call`), which refunds; a deposit return that
    /// failed leaves it `Owed`, and the timeout forwards the deposit only, then deletes the entry.
    #[test]
    fn failed_settle_kept_for_the_timeout() {
        ctx(vec![PromiseResult::Failed], 0);
        let mut r = router(Stage::Settle, false);
        assert!(!r.on_settle(REF, ID, true));
        assert_eq!((r.pending.get(&REF).unwrap().stage, receipts()), (Stage::Call, vec![]), "release failed: refund wins later");
        ctx(vec![], 51);
        let _ = r.relay_timeout(REF);
        assert_eq!(receipts().iter().map(|x| x.1.as_str()).collect::<Vec<_>>(), ["relay_refund", "on_settle"]);
        // refund ok, deposit return failed: owed
        ctx(vec![ok(), PromiseResult::Failed], 0);
        let mut r = router(Stage::Settle, true);
        assert!(!r.on_settle(REF, ID, false));
        assert_eq!(r.pending.get(&REF).unwrap().stage, Stage::Owed);
        ctx(vec![], 50);
        let e = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.relay_timeout(REF)));
        assert!(e.is_err(), "before the deadline");
        ctx(vec![], 51);
        let _ = r.relay_timeout(REF);
        assert_eq!(receipts().iter().map(|x| (x.0.as_str(), x.1.as_str())).collect::<Vec<_>>(), [("exec.near", "return_deposit"), ("router.near", "on_settle")]);
        ctx(vec![ok()], 51);
        assert!(!r.on_settle(REF, ID, false));
        assert!(r.pending.get(&REF).is_none(), "settled");
        assert_eq!(receipts(), vec![rc("relayer.near", "transfer", 100)], "the entry deposit back");
        // a timeout while a settlement is in flight is refused
        ctx(vec![], 51);
        let mut r = router(Stage::Settle, false);
        let e = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.relay_timeout(REF)));
        assert!(e.is_err(), "settlement in flight");
    }

    /// A timeout while the hold is in flight returns `target_deposit` at once (the call never left) and refunds.
    #[test]
    fn timeout_during_hold_returns_target_deposit() {
        ctx(vec![], 51);
        let mut r = router(Stage::Hold, false);
        let _ = r.relay_timeout(REF);
        assert_eq!(receipts(), vec![rc("relayer.near", "transfer", 5), rc("token.near", "relay_refund", 0), rc("router.near", "on_settle", 0)]);
        let p = r.pending.get(&REF).unwrap();
        assert_eq!((p.stage, p.target_deposit), (Stage::Settle, 0));
        ctx(vec![PromiseResult::Successful(vec![0])], 51);
        assert!(!r.on_settle(REF, ID, false));
        assert_eq!(receipts(), vec![rc("relayer.near", "transfer", 100)]);
    }
}
