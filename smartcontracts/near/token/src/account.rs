//! Subject accounts (spec §3.3, §3.5; R7): one record per `Holder` with its SCaaS keys (≤ 8 `KeyRecord`s), passkey
//! origins, guardian, pending recovery and key nonce. A `Ua` subject opens lazily on its first signed op (the key must
//! derive the id, kinds.json); a `Near` subject adds keys by a direct call (`add_key_native`) or a signed op of a
//! current key. Signatures are checked against these records only, never against a NEAR access key.
//!
//! Key ops (codes 6–12): `amount` 0, `pay_ref` / `lane` zero, `nonce` = the signer's key nonce (consumed),
//! `to` = `from` (start_recovery: the subject recovered), `extra = sha256(Borsh(entry parameters))`. Storage: every
//! byte a record grows by is paid from the attached deposit, the excess refunded (§2 row 15); a record never shrinks
//! its payer's deposit back (records are permanent).
use crate::{Holder, Token, TokenExt};
use near_sdk::json_types::U128;
use near_sdk::{borsh, env, near, AccountId};
use scaas_near_common::auth::{self, Auth};
use scaas_near_common::metaop::*;
use scaas_near_common::ua::KeyRecord;

pub const MAX_KEYS: usize = 8;
pub const MAX_ORIGINS: usize = 8;
pub const MAX_ORIGIN_LEN: usize = 128;
pub const RECOVERY_DELAY_S: u64 = 172_800;
/// Bytes of one subject record = this + Borsh(Holder) + Borsh(Subject): key prefix `a` (1) + NEAR's per-record
/// overhead (40). `new` measures one record against it.
pub const SUBJECT_RECORD_OVERHEAD: u64 = 41;

type R<T> = Result<T, &'static str>;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub key: KeyRecord,
    pub origin: Option<String>,
    pub ready_at: u64,
}

#[near(serializers = [borsh])]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Subject {
    pub keys: Vec<KeyRecord>,
    pub origins: Vec<String>,
    pub guardian: Option<Holder>,
    pub recovery: Option<Recovery>,
    pub key_nonce: u64,
}

/// `*_check` result (NEAR has no write simulation): the entry's error, or the deposit it needs (yoctoNEAR).
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Check {
    pub error: Option<String>,
    pub storage_needed: U128,
}

pub fn record_bytes(h: &Holder, s: &Subject) -> u64 {
    let len = |b: Vec<u8>| b.len() as u64;
    SUBJECT_RECORD_OVERHEAD + len(borsh::to_vec(h).unwrap()) + len(borsh::to_vec(s).unwrap())
}

pub(crate) fn now_s() -> u64 {
    env::block_timestamp() / 1_000_000_000
}

impl Subject {
    fn add_origin(&mut self, o: &str) -> R<()> {
        if o.is_empty() || o.len() > MAX_ORIGIN_LEN {
            return Err("origin length");
        }
        if !self.origins.iter().any(|x| x == o) {
            self.origins.push(o.to_string());
        }
        Ok(())
    }

    fn add_key(&mut self, k: &KeyRecord, origin: &Option<String>) -> R<()> {
        k.validate()?;
        if self.keys.contains(k) {
            return Err("key already present");
        }
        if self.keys.len() >= MAX_KEYS {
            return Err("MAX_KEYS (8) reached");
        }
        self.keys.push(k.clone());
        origin.as_deref().map_or(Ok(()), |o| self.add_origin(o))
    }

    /// Never left without a key, over the caps, or with a passkey and no origin to sign from.
    fn check_usable(&self) -> R<()> {
        if self.keys.is_empty() {
            return Err("the last key cannot be removed");
        }
        if self.origins.len() > MAX_ORIGINS {
            return Err("MAX_ORIGINS (8) reached");
        }
        if self.origins.is_empty() && self.keys.iter().any(KeyRecord::needs_origin) {
            return Err("a passkey needs an origin");
        }
        Ok(())
    }
}

/// One key op's parameters (the entry arguments after `op, auth`).
pub(crate) enum Action {
    AddKey(KeyRecord, Option<String>),
    RemoveKey(KeyRecord),
    AddOrigin(String),
    RemoveOrigin(String),
    SetGuardian(Option<Holder>),
    StartRecovery(KeyRecord, Option<String>),
    CancelRecovery,
}

impl Action {
    fn code_and_params(&self) -> (u8, Vec<u8>) {
        let (code, params) = match self {
            Action::AddKey(k, o) => (OP_ADD_KEY, borsh::to_vec(&(k, o))),
            Action::RemoveKey(k) => (OP_REMOVE_KEY, borsh::to_vec(k)),
            Action::AddOrigin(o) => (OP_ADD_ORIGIN, borsh::to_vec(o)),
            Action::RemoveOrigin(o) => (OP_REMOVE_ORIGIN, borsh::to_vec(o)),
            Action::SetGuardian(g) => (OP_SET_GUARDIAN, borsh::to_vec(g)),
            Action::StartRecovery(k, o) => (OP_START_RECOVERY, borsh::to_vec(&(k, o))),
            Action::CancelRecovery => (OP_CANCEL_RECOVERY, Ok(vec![])),
        };
        (code, params.expect("borsh"))
    }

    fn name(&self) -> &'static str {
        match self {
            Action::AddKey(..) => "add_key",
            Action::RemoveKey(..) => "remove_key",
            Action::AddOrigin(..) => "add_origin",
            Action::RemoveOrigin(..) => "remove_origin",
            Action::SetGuardian(..) => "set_guardian",
            Action::StartRecovery(..) => "start_recovery",
            Action::CancelRecovery => "cancel_recovery",
        }
    }
}

/// A record to write: its new state and its size before the call (0 = new).
pub(crate) struct Write {
    holder: Holder,
    subject: Subject,
    old: u64,
}

impl Write {
    fn growth(&self) -> u64 {
        record_bytes(&self.holder, &self.subject).saturating_sub(self.old)
    }
}

impl Token {
    fn load(&self, h: &Holder) -> Option<(Subject, u64)> {
        self.subjects.get(h).map(|s| (s.clone(), record_bytes(h, s)))
    }

    /// `authorize`'s checks, no write: network, contract, expiry, relayer (rule 7: `None` or `relayer`), then `auth`
    /// against `op.from`'s key records; an unknown `Ua` id opens with the signing key when that key derives the id
    /// (old size 0). `caller` is the predecessor (a `near-account` msig member counts only as it).
    pub(crate) fn signed(&self, caller: &AccountId, relayer: &AccountId, op: &MetaOp, auth: &Auth) -> R<(Subject, u64)> {
        let me = env::current_account_id();
        if op.network != self.network {
            return Err("wrong network");
        }
        if op.contract != me {
            return Err("wrong contract");
        }
        if now_s() > op.valid_until {
            return Err("expired");
        }
        if op.relayer.as_ref().is_some_and(|r| r != relayer) {
            return Err("relayer is not the predecessor");
        }
        let digest = op.digest();
        let key = auth.key()?;
        if let Some((s, old)) = self.load(&op.from) {
            if !s.keys.contains(&key) {
                return Err("not a key of the subject");
            }
            auth::verify(auth, &digest, &me, caller, Some(&s.origins))?;
            return Ok((s, old));
        }
        let Holder::Ua(id) = &op.from else {
            return Err("no SCaaS key: a NEAR account signs only with keys it registered");
        };
        key.validate()?;
        if key.id() != *id {
            return Err("the key does not derive the UA id");
        }
        let mut s = Subject { keys: vec![key], ..Default::default() };
        for o in auth::verify(auth, &digest, &me, caller, None)? {
            s.add_origin(&o)?;
        }
        s.check_usable()?;
        Ok((s, 0))
    }

    /// Spec §3.3 / §3.5 for every signed entry: the checks of `signed` with the predecessor as relayer; a lazily
    /// opened UA record is written and its storage added to the call's deposit (`charge_storage`). Returns the signer.
    pub fn authorize(&mut self, op: &MetaOp, auth: &Auth) -> Holder {
        let p = env::predecessor_account_id();
        let (s, old) = self.signed(&p, &p, op, auth).unwrap_or_else(|e| env::panic_str(e));
        if old == 0 {
            self.save(Write { holder: op.from.clone(), subject: s, old });
        }
        op.from.clone()
    }

    pub(crate) fn plan(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, act: &Action) -> R<Vec<Write>> {
        let (code, params) = act.code_and_params();
        if op.op != code || op.amount != 0 || op.pay_ref != [0; 32] || op.lane != [0; 32] {
            return Err("key op shape (op code, amount 0, pay_ref and lane zero)");
        }
        if op.extra != env::sha256_array(&params) {
            return Err("extra is not sha256 of the parameters");
        }
        let (mut s, old) = self.signed(caller, caller, op, auth)?;
        if op.nonce != s.key_nonce {
            return Err("wrong key nonce");
        }
        s.key_nonce += 1;
        let signer = |s| Write { holder: op.from.clone(), subject: s, old };
        if let Action::StartRecovery(k, origin) = act {
            if op.to == op.from {
                return Err("a subject is not its own guardian");
            }
            let (mut t, told) = self.load(&op.to).ok_or("no such subject")?;
            if t.guardian.as_ref() != Some(&op.from) {
                return Err("not the subject's guardian");
            }
            let mut after = Subject { keys: vec![], ..t.clone() };
            after.add_key(k, origin)?;
            after.check_usable()?;
            t.recovery = Some(Recovery { key: k.clone(), origin: origin.clone(), ready_at: now_s() + RECOVERY_DELAY_S });
            return Ok(vec![signer(s), Write { holder: op.to.clone(), subject: t, old: told }]);
        }
        if op.to != op.from {
            return Err("to must be the subject");
        }
        match act {
            Action::AddKey(k, origin) => s.add_key(k, origin)?,
            Action::RemoveKey(k) => {
                let i = s.keys.iter().position(|x| x == k).ok_or("unknown key")?;
                s.keys.remove(i);
            }
            Action::AddOrigin(o) => s.add_origin(o)?,
            Action::RemoveOrigin(o) => {
                let i = s.origins.iter().position(|x| x == o).ok_or("unknown origin")?;
                s.origins.remove(i);
            }
            Action::SetGuardian(g) => {
                if g.as_ref() == Some(&op.from) {
                    return Err("a subject is not its own guardian");
                }
                s.guardian = g.clone();
                s.recovery = None;
            }
            Action::CancelRecovery => {
                s.recovery.take().ok_or("no recovery pending")?;
            }
            Action::StartRecovery(..) => unreachable!(),
        }
        s.check_usable()?;
        Ok(vec![signer(s)])
    }

    fn save(&mut self, w: Write) {
        self.storage_due += w.growth();
        self.subjects.insert(w.holder, w.subject);
    }

    /// A key-op entry: plan, write, charge the growth once, event.
    pub(crate) fn key_op(&mut self, op: &MetaOp, auth: &Auth, act: Action) {
        let p = env::predecessor_account_id();
        let ws = self.plan(&p, op, auth, &act).unwrap_or_else(|e| env::panic_str(e));
        let subject = ws.last().map(|w| w.holder.to_string()).unwrap_or_default();
        ws.into_iter().for_each(|w| self.save(w));
        crate::Event::KeyOp { subject, action: act.name().into() }.emit();
    }

    fn check(&self, caller: &AccountId, op: &MetaOp, auth: &Auth, act: Action) -> Check {
        match self.plan(caller, op, auth, &act) {
            Ok(ws) => {
                let bytes: u64 = ws.iter().map(Write::growth).sum();
                Check { error: None, storage_needed: U128(env::storage_byte_cost().as_yoctonear() * bytes as u128) }
            }
            Err(e) => Check { error: Some(e.into()), storage_needed: U128(0) },
        }
    }
}

#[near]
impl Token {
    #[payable]
    pub fn mtx_add_key(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
    ) {
        self.key_op(&op, &auth, Action::AddKey(key, origin));
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_remove_key(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
    ) {
        self.key_op(&op, &auth, Action::RemoveKey(key));
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_add_origin(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
    ) {
        self.key_op(&op, &auth, Action::AddOrigin(origin));
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_remove_origin(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
    ) {
        self.key_op(&op, &auth, Action::RemoveOrigin(origin));
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_set_guardian(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] guardian: Option<Holder>,
    ) {
        self.key_op(&op, &auth, Action::SetGuardian(guardian));
        self.charge_storage();
    }

    /// Signed by the guardian (`op.from`), `op.to` = the subject; `key` replaces every key at `finish_recovery` after
    /// `RECOVERY_DELAY_S`, unless a current key cancels first.
    #[payable]
    pub fn mtx_start_recovery(
        &mut self,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
    ) {
        self.key_op(&op, &auth, Action::StartRecovery(key, origin));
        self.charge_storage();
    }

    #[payable]
    pub fn mtx_cancel_recovery(&mut self, #[serializer(borsh)] op: MetaOp, #[serializer(borsh)] auth: Auth) {
        self.key_op(&op, &auth, Action::CancelRecovery);
        self.charge_storage();
    }

    /// Anyone, once `ready_at` has passed: the recovery key replaces every key (and its origin is added); the key
    /// nonce moves on, so key ops signed before are void.
    #[payable]
    pub fn finish_recovery(&mut self, #[serializer(borsh)] subject: Holder) {
        let (mut s, old) = self.load(&subject).unwrap_or_else(|| env::panic_str("no such subject"));
        let r = s.recovery.take().unwrap_or_else(|| env::panic_str("no recovery pending"));
        if now_s() < r.ready_at {
            env::panic_str("recovery delay (172,800 s) not over");
        }
        s.keys = vec![r.key];
        let res = r.origin.as_deref().map_or(Ok(()), |o| s.add_origin(o)).and_then(|_| s.check_usable());
        res.unwrap_or_else(|e| env::panic_str(e));
        s.key_nonce += 1;
        crate::Event::KeyOp { subject: subject.to_string(), action: "finish_recovery".into() }.emit();
        self.save(Write { holder: subject, subject: s, old });
        self.charge_storage();
    }

    /// A native NEAR holder (the predecessor) adds a SCaaS key directly; the first one opens its record.
    #[payable]
    pub fn add_key_native(&mut self, #[serializer(borsh)] key: KeyRecord, #[serializer(borsh)] origin: Option<String>) {
        let h = Holder::Near(env::predecessor_account_id());
        let (mut s, old) = self.load(&h).unwrap_or_default();
        s.add_key(&key, &origin).and_then(|_| s.check_usable()).unwrap_or_else(|e| env::panic_str(e));
        crate::Event::KeyOp { subject: h.to_string(), action: "add_key_native".into() }.emit();
        self.save(Write { holder: h, subject: s, old });
        self.charge_storage();
    }

    #[result_serializer(borsh)]
    pub fn subject(&self, #[serializer(borsh)] holder: Holder) -> Option<Subject> {
        self.subjects.get(&holder).cloned()
    }

    #[result_serializer(borsh)]
    pub fn mtx_add_key_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::AddKey(key, origin))
    }

    #[result_serializer(borsh)]
    pub fn mtx_remove_key_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::RemoveKey(key))
    }

    #[result_serializer(borsh)]
    pub fn mtx_add_origin_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::AddOrigin(origin))
    }

    #[result_serializer(borsh)]
    pub fn mtx_remove_origin_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] origin: String,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::RemoveOrigin(origin))
    }

    #[result_serializer(borsh)]
    pub fn mtx_set_guardian_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] guardian: Option<Holder>,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::SetGuardian(guardian))
    }

    #[result_serializer(borsh)]
    pub fn mtx_start_recovery_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
        #[serializer(borsh)] key: KeyRecord,
        #[serializer(borsh)] origin: Option<String>,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::StartRecovery(key, origin))
    }

    #[result_serializer(borsh)]
    pub fn mtx_cancel_recovery_check(
        &self,
        #[serializer(borsh)] caller: AccountId,
        #[serializer(borsh)] op: MetaOp,
        #[serializer(borsh)] auth: Auth,
    ) -> Check {
        self.check(&caller, &op, &auth, Action::CancelRecovery)
    }
}
