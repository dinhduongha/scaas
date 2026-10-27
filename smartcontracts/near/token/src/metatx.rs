//! Value entries (spec §2 rows 4–7, 10, 12, 15; §3.4, §3.7; CTR-MTX-16, CTR-MTX-26; NET-ALL-28): `mtx_pay` (op 0, a
//! `pay_ref`), `mtx_pay_meta` (op 0, `pay_ref = metaPayId(salt, meta)`, `lane = payLane(pay_ref)`, nonce 0),
//! `mtx_transfer` (op 4, no `pay_ref`), `mtx_execute_transfer` (op 5, any `pay_ref`). Each consumes the payer's lane
//! `(from, lane)` at `nonce` (lanes are per payer and never removed, so a `(from, pay_ref)` pays once through pay-meta and
//! another payer's lane never blocks it), pays `to`, and charges every new record (lazy UA open, lane, receiver
//! registration) once from the attached deposit. `extra` is payer-chosen: the relay-fee salt (spec §2 row 8).
use crate::{record_bytes, Check, Event, Holder, Subject, Token, TokenExt, POLICY_PASSKEY_FOR_VALUE};
use near_sdk::json_types::U128;
use near_sdk::{borsh, env, near, require, AccountId};
use scaas_near_common::auth::Auth;
use scaas_near_common::hash::{hex, meta_pay_id, pay_lane};
use scaas_near_common::metaop::*;
use scaas_near_common::ua::{parse_msig, KIND_WEBAUTHN_P256};

/// Bytes of one lane record = this + Borsh(Holder): key prefix `l` (1) + lane (32), value u64 (8), NEAR's per-record
/// overhead (40). `new` measures one record against it.
pub const LANE_RECORD_OVERHEAD: u64 = 81;

pub fn lane_bytes(h: &Holder) -> u64 {
    LANE_RECORD_OVERHEAD + borsh::to_vec(h).unwrap().len() as u64
}

type R<T> = Result<T, &'static str>;

fn x(b: &[u8]) -> String {
    format!("0x{}", hex(b))
}

fn pay_meta_shape(op: &MetaOp, salt: &[u8; 32], meta: &[u8]) -> R<()> {
    if op.pay_ref != meta_pay_id(salt, meta) || op.lane != pay_lane(&op.pay_ref) || op.nonce != 0 {
        return Err("pay-meta shape (pay_ref = metaPayId(salt, meta), lane = payLane(pay_ref), nonce 0)");
    }
    Ok(())
}

/// NET-ALL-23 item 3 (ruling R8): with `POLICY_PASSKEY_FOR_VALUE` a value op is signed by a passkey, or by an msig whose
/// members are all passkeys (no wallet key and no near-account weight can count).
pub(crate) fn value_policy(s: &Subject, auth: &Auth) -> R<()> {
    let passkey = match auth {
        Auth::Passkey { .. } => true,
        Auth::Msig { key_data, .. } => parse_msig(key_data).is_ok_and(|m| m.members.iter().all(|m| m.kind == KIND_WEBAUTHN_P256)),
        _ => false,
    };
    if s.policy & POLICY_PASSKEY_FOR_VALUE != 0 && !passkey {
        return Err("POLICY_PASSKEY_FOR_VALUE: value ops need a passkey signature");
    }
    Ok(())
}

impl Token {
    fn next_nonce(&self, h: &Holder, lane: &[u8; 32]) -> Option<u64> {
        self.lanes.get(&(h.clone(), *lane)).copied()
    }

    fn balance(&self, h: &Holder) -> u128 {
        match h {
            Holder::Near(a) => self.ft.accounts.get(a).unwrap_or(0),
            Holder::Ua(id) => self.ua.get(id).copied().unwrap_or(0),
        }
    }

    /// Every check of a plain value entry, no write, cheap first: op code and shape, `to` never the token (rule 12),
    /// `signed` with `caller` as the relayer (rule 7), the value policy, the lane nonce, the balance. Returns the signer's
    /// record, its old size (0 = opened lazily) and the bytes of the new records the entry creates.
    fn value_plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, code: u8) -> R<(Subject, u64, u64)> {
        if op.op != code {
            return Err("wrong op code");
        }
        if code == OP_PAY && op.pay_ref == [0; 32] {
            return Err("mtx_pay needs a pay_ref");
        }
        if code == OP_TRANSFER && op.pay_ref != [0; 32] {
            return Err("mtx_transfer carries no pay_ref");
        }
        if op.to == Holder::Near(env::current_account_id()) {
            return Err("token refuses a transfer to the token itself");
        }
        if op.amount == 0 {
            return Err("The amount should be a positive number");
        }
        if op.from == op.to {
            return Err("Sender and receiver should be different");
        }
        let (s, old) = self.signed(caller, caller, op, auth)?;
        value_policy(&s, auth)?;
        let next = self.next_nonce(&op.from, &op.lane);
        if next.unwrap_or(0) != op.nonce {
            return Err("wrong lane nonce");
        }
        if self.balance(&op.from) < op.amount {
            return Err(match op.from {
                Holder::Near(_) => "The account doesn't have enough balance",
                Holder::Ua(_) => "The UA doesn't have enough balance",
            });
        }
        let open = if old == 0 { record_bytes(&op.from, &s) } else { 0 };
        let lane = if next.is_none() { lane_bytes(&op.from) } else { 0 };
        Ok((s, old, open + lane + self.receiver_bytes(&op.to)))
    }

    /// A plain value entry: plan (panics with its error), open the signer lazily, `payment_meta` for a pay-meta, the pay
    /// body to `op.to`, the storage charged once.
    fn value_entry(&mut self, op: &MetaOp, auth: &Auth, code: u8, meta: Option<&[u8]>) {
        let p = env::predecessor_account_id();
        let (s, old, _) = self.value_plan(&p, op, auth, code).unwrap_or_else(|e| env::panic_str(e));
        self.open_lazily(&op.from, s, old);
        if let Some(m) = meta {
            Event::PaymentMeta { pay_ref: x(&op.pay_ref), meta: x(m) }.emit();
        }
        self.settle_pay(op, &op.from, &op.to);
        self.charge_storage();
    }

    /// The pay body, shared by every value entry and by Tasks 9–10 (relay-fee wrappers, router release): consumes
    /// `from`'s lane `op.lane` at `op.nonce`, registers `payee` (bytes into `storage_due`), moves `op.amount`, emits
    /// `meta_transaction_executed` and, when `pay_ref ≠ 0`, `payment_settled`. Authorisation is the caller's: plain
    /// entries `value_plan` (`payee = op.to`); routed payments `signed` with the marker as relayer and the open-mode
    /// payee (the submitting relayer) when `op.to` is the marker (ruling R2).
    pub(crate) fn settle_pay(&mut self, op: &MetaOp, from: &Holder, payee: &Holder) {
        let next = self.next_nonce(from, &op.lane);
        require!(next.unwrap_or(0) == op.nonce, "wrong lane nonce");
        if next.is_none() {
            self.storage_due += lane_bytes(from);
        }
        self.lanes.insert((from.clone(), op.lane), op.nonce.checked_add(1).unwrap_or_else(|| env::panic_str("lane full")));
        self.storage_due += self.register(payee);
        Event::MetaTransactionExecuted {
            from: from.to_string(),
            relayer: env::predecessor_account_id().to_string(),
            lane: x(&op.lane),
            nonce: op.nonce,
            digest: x(&op.digest()),
        }
        .emit();
        self.move_balance(from, payee, op.amount, None);
        if op.pay_ref != [0; 32] {
            Event::PaymentSettled { from: from.to_string(), to: payee.to_string(), amount: U128(op.amount), pay_ref: x(&op.pay_ref) }
                .emit();
        }
    }

    fn value_check(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, code: u8) -> Check {
        match self.value_plan(caller, op, auth, code) {
            Ok((_, _, bytes)) => {
                Check { error: None, storage_needed: U128(env::storage_byte_cost().as_yoctonear() * bytes as u128) }
            }
            Err(e) => Check { error: Some(e.into()), storage_needed: U128(0) },
        }
    }
}

#[near]
impl Token {
    #[payable]
    pub fn mtx_pay(&mut self, #[serializer(borsh)] op: MetaOp, #[serializer(borsh)] auth: Auth) {
        self.value_entry(&op, &auth, OP_PAY, None);
    }

    /// CTR-MTX-26: the plain pay of `pay_ref = metaPayId(salt, meta)` on `payLane(pay_ref)` at nonce 0 (the same signed
    /// op), `payment_meta` before `payment_settled`. No contract cap on `meta` (bounded by NEAR's log limit).
    #[payable]
    pub fn mtx_pay_meta(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] salt: [u8; 32],
        #[serializer(borsh)] meta: Vec<u8>,
    ) {
        pay_meta_shape(&op, &salt, &meta).unwrap_or_else(|e| env::panic_str(e));
        self.value_entry(&op, &auth, OP_PAY, Some(&meta));
    }

    #[payable]
    pub fn mtx_transfer(&mut self, #[serializer(borsh)] op: MetaOp, #[serializer(borsh)] auth: Auth) {
        self.value_entry(&op, &auth, OP_TRANSFER, None);
    }

    #[payable]
    pub fn mtx_execute_transfer(&mut self, #[serializer(borsh)] op: MetaOp, #[serializer(borsh)] auth: Auth) {
        self.value_entry(&op, &auth, OP_EXECUTE_TRANSFER, None);
    }

    /// The nonce `holder`'s lane `lane` expects next (0 for an unused lane).
    #[result_serializer(borsh)]
    pub fn lane_nonce(&self, #[serializer(borsh)] holder: Holder, #[serializer(borsh)] lane: [u8; 32]) -> u64 {
        self.next_nonce(&holder, &lane).unwrap_or(0)
    }

    #[result_serializer(borsh)]
    pub fn mtx_pay_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        self.value_check(&caller, &op, &auth, OP_PAY)
    }

    #[result_serializer(borsh)]
    pub fn mtx_pay_meta_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] salt: [u8; 32],
        #[serializer(borsh)] meta: Vec<u8>,
    ) -> Check {
        match pay_meta_shape(&op, &salt, &meta) {
            Ok(()) => self.value_check(&caller, &op, &auth, OP_PAY),
            Err(e) => Check { error: Some(e.into()), storage_needed: U128(0) },
        }
    }

    #[result_serializer(borsh)]
    pub fn mtx_transfer_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        self.value_check(&caller, &op, &auth, OP_TRANSFER)
    }

    #[result_serializer(borsh)]
    pub fn mtx_execute_transfer_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        self.value_check(&caller, &op, &auth, OP_EXECUTE_TRANSFER)
    }
}
