//! Relay escrow for the cross-contract router (spec §3.8 "Escrow router" steps 2 and 6; rulings R2, R10, T10 pre-flight
//! a, b, f). Only the router the payer named (`op.relayer == Some(router)`, the predecessor) holds, and only it releases
//! or refunds what it holds:
//!
//! - `relay_hold(op, auth, relayer) -> bool`: the shared routed pay checks (`routed_plan` with the router as the marker:
//!   op 0, `lane = payLane(pay_ref)`, nonce 0, `relayer == Some(router)`, payee = `relayer` in open mode (`to` = the
//!   router) else `to`, the value policy, the balance) — the router has already bound `pay_ref` to the call (`ref`).
//!   Consumes the lane (pay-once, `consume_pay`: the pay body's first half), registers the payee, moves `amount` from the
//!   payer into `held[(router, pay_ref)]` (the token's own NEP-141 account, beside the UA pool), charges every new record
//!   from the attached deposit and returns the excess to `relayer`. A refusal returns `false`, writes nothing and sends
//!   the whole deposit back to `relayer` (never to the keyless router: NEP-616 `refund_to` is not assumed).
//! - `relay_release(pay_ref)`: `held` → the payee, `payment_settled` (`pay_ref = ref`); panics when nothing is held.
//! - `relay_refund(pay_ref) -> bool`: `held` → the payer; `false` when nothing is held (the router's timeout may refund a
//!   hold that never happened, or one already settled).
//!
//! Each removes the held record, so release and refund are exclusive, and returns its storage deposit to the relayer
//! that staked it. A forwarded call (the router's executor as predecessor) holds nothing: no payer names the executor.
use crate::account::check_of;
use crate::metatx::{x, Routed};
use crate::storage::charge;
use crate::{transfer_events, Check, Event, Holder, Token, TokenExt};
use near_sdk::json_types::U128;
use near_sdk::{borsh, env, near, AccountId, NearToken, Promise};
use scaas_near_common::auth::Auth;
use scaas_near_common::metaop::MetaOp;

/// Bytes of a held record = this + Borsh(router) + Borsh(Held): key prefix `h` (1) + `pay_ref` (32), NEAR's 40-byte
/// record overhead. `new` measures one.
pub const HELD_RECORD_OVERHEAD: u64 = 73;

type R<T> = Result<T, &'static str>;

/// A payment held for a router: `deposit` = this record's storage, back to `relayer` when it is removed.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub payer: Holder,
    pub payee: Holder,
    pub amount: u128,
    pub relayer: AccountId,
    pub deposit: u128,
}

pub fn held_bytes(router: &AccountId, h: &Held) -> u64 {
    HELD_RECORD_OVERHEAD + (borsh::to_vec(router).unwrap().len() + borsh::to_vec(h).unwrap().len()) as u64
}

impl Token {
    /// No write: the routed pay checks for `router` (the marker) with `relayer` as the open-mode payee, nothing of this
    /// router already held under `pay_ref`; returns the plan, the record to hold and every new byte (lazy open, lane,
    /// payee registration, the held record).
    fn hold_plan(&self, router: &AccountId, relayer: &AccountId, op: &MetaOp, auth: &Auth) -> R<(Routed, Held, u64)> {
        let rt = self.routed_plan(router, router, &Holder::Near(relayer.clone()), op, auth, &op.pay_ref)?;
        if self.held.contains_key(&(router.clone(), op.pay_ref)) {
            return Err("a payment is already held under this pay_ref");
        }
        let h = Held { payer: op.from.clone(), payee: rt.payee.clone(), amount: op.amount, relayer: relayer.clone(), deposit: 0 };
        let bytes = rt.bytes + held_bytes(router, &h);
        Ok((rt, h, bytes))
    }

    /// Moves a held payment out of the escrow to `to`, the record's storage deposit back to its relayer.
    fn unhold(&mut self, h: &Held, to: &Holder) {
        let me = env::current_account_id();
        self.ft.internal_withdraw(&me, h.amount);
        self.credit(to, h.amount);
        transfer_events(&Holder::Near(me), to, h.amount, None);
        if h.deposit > 0 {
            Promise::new(h.relayer.clone()).transfer(NearToken::from_yoctonear(h.deposit)).detach();
        }
    }
}

#[near]
impl Token {
    #[payable]
    #[result_serializer(borsh)]
    pub fn relay_hold(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] relayer: AccountId,
    ) -> bool {
        let router = env::predecessor_account_id();
        let attached = env::attached_deposit();
        let plan = self.hold_plan(&router, &relayer, &op, &auth).and_then(|p| {
            match attached >= env::storage_byte_cost().saturating_mul(p.2.into()) {
                true => Ok(p),
                false => Err("the attached deposit is short of the hold's storage"),
            }
        });
        let (rt, mut h, _) = match plan {
            Ok(p) => p,
            Err(e) => {
                env::log_str(&format!("relay_hold refused: {e}"));
                if attached > NearToken::from_yoctonear(0) {
                    Promise::new(relayer).transfer(attached).detach();
                }
                return false;
            }
        };
        let me = env::current_account_id();
        self.open_lazily(&op.from, rt.subject, rt.old);
        self.consume_pay(&op, &op.from, &rt.payee);
        self.debit(&op.from, op.amount);
        self.ft.internal_deposit(&me, op.amount);
        transfer_events(&op.from, &Holder::Near(me), op.amount, None);
        let bytes = held_bytes(&router, &h);
        h.deposit = env::storage_byte_cost().as_yoctonear() * bytes as u128;
        self.held.insert((router, op.pay_ref), h);
        self.storage_due += bytes;
        charge(std::mem::take(&mut self.storage_due), relayer);
        true
    }

    pub fn relay_release(&mut self, #[serializer(borsh)] pay_ref: [u8; 32]) {
        let h = self
            .held
            .remove(&(env::predecessor_account_id(), pay_ref))
            .unwrap_or_else(|| env::panic_str("nothing held under this pay_ref for this router"));
        self.unhold(&h, &h.payee);
        Event::PaymentSettled { from: h.payer.to_string(), to: h.payee.to_string(), amount: U128(h.amount), pay_ref: x(&pay_ref) }.emit();
    }

    #[result_serializer(borsh)]
    pub fn relay_refund(&mut self, #[serializer(borsh)] pay_ref: [u8; 32]) -> bool {
        let Some(h) = self.held.remove(&(env::predecessor_account_id(), pay_ref)) else { return false };
        self.unhold(&h, &h.payer);
        true
    }

    /// What `router` holds under `pay_ref`.
    #[result_serializer(borsh)]
    pub fn relay_held(&self, #[serializer(borsh)] router: AccountId, #[serializer(borsh)] pay_ref: [u8; 32]) -> Option<Held> {
        self.held.get(&(router, pay_ref)).cloned()
    }

    /// `relay_hold`'s refusal, or the deposit it charges (Task 16's simulate adds it to the router's `relay_check`).
    #[result_serializer(borsh)]
    pub fn relay_hold_check(
        &self,
        #[serializer(borsh)] router: AccountId,
        #[serializer(borsh)] relayer: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        check_of(self.hold_plan(&router, &relayer, &op, &auth).map(|p| p.2))
    }
}
