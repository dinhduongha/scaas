//! The wallet of ONE payer with a bounded delegation for automatic payments (as EVM `MandateWallet`, R25), with
//! native and UA holders (spec §5.2, SOR-D9).
//!
//! The funds stay in the contract's own native balance; the delegate (the platform's custody key) spends only within
//! the mandate the owner set: a cap per payment and per period, allowed payees, an expiry, each `pay_ref` once. The
//! contract pays by `token.pay(self, …)` (a native payee) or `token.pay_to_ua(self, …)` (a UA payee), so the
//! settlement event carries `pay_ref` and Odoo reconciles it as a manual payment.
//!
//! Owner, delegate and payees are `Holder`s. Every entry is an `mtx_*` write a relayer submits (fee may be 0): a native
//! holder authorises by host auth (`auth` empty, else `BadAuth`; its lane is not consumed), a UA holder signs
//! `op_digest(mandate, "<fn>", args without auth)` under purpose `metatx` through the registry bound at construction;
//! each UA signature runs once, by the mandate's own lane `UaNonce(ua, lane)` (owner entries, `mtx_revoke` by the
//! delegate) or by `pay_ref` (`mtx_mandate_pay`). `valid_until` and a bound `relayer` are checked for both.
#![no_std]
/// The holder type of the mandate's interface (owner, delegate, payee).
pub use scaas_ua_common::Holder;
use scaas_ua_common::{op_digest, UaRegistryClient, PURPOSE_METATX};
use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    Bytes, BytesN, Env, IntoVal, TryFromVal, Val, Vec,
};

const DAY: u32 = 17_280;
const TTL_MIN: u32 = 30 * DAY;
const TTL_BUMP: u32 = 60 * DAY;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NoMandate = 1,
    MandateExpired = 2,
    PayeeNotAllowed = 3,
    OverPaymentCap = 4,
    OverPeriodCap = 5,
    RefAlreadyPaid = 6,
    BadMandate = 7,
    NotAllowed = 8,
    /// A native holder's entry with a non-empty `auth` (SOR-D9).
    BadAuth = 9,
    /// `valid_until` passed.
    Expired = 10,
    /// A UA entry whose `nonce` is not its lane's next one (a replay, or out of order).
    BadNonce = 11,
    /// A UA signer and no registry bound at construction.
    UaLedgerOff = 12,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Mandate {
    pub delegate: Holder,
    pub expiry: u64,
    pub period_seconds: u64,
    pub period_start: u64,
    pub max_per_payment: i128,
    pub max_per_period: i128,
    pub spent_in_period: i128,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    /// Instance: the owner and the registry (`None` = no UA signer).
    Owner,
    Registry,
    /// Persistent, one entry per key.
    Mandate(Address),
    Payee(Address, Holder),
    Ref(BytesN<32>),
    /// A UA's lane nonce, the mandate's own (not the token's).
    UaNonce(BytesN<32>, BytesN<32>),
}

#[contractevent(topics = ["MandateSet"], data_format = "vec")]
pub struct MandateSet {
    #[topic]
    pub token: Address,
    #[topic]
    pub delegate: Holder,
    pub max_per_payment: i128,
    pub max_per_period: i128,
    pub period_seconds: u64,
    pub expiry: u64,
}

#[contractevent(topics = ["MandateRevoked"], data_format = "single-value")]
pub struct MandateRevoked {
    #[topic]
    pub token: Address,
    pub by: Holder,
}

#[contractevent(topics = ["PaidUnderMandate"], data_format = "vec")]
pub struct PaidUnderMandate {
    #[topic]
    pub token: Address,
    #[topic]
    pub payee: Holder,
    pub amount: i128,
    pub pay_ref: BytesN<32>,
}

/// The part of `scaas-token` the mandate calls.
#[contractclient(name = "PayTokenClient")]
pub trait PayToken {
    fn pay(env: Env, from: Address, to: Address, amount: i128, pay_ref: BytesN<32>, valid_until: u64);
    fn pay_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128, pay_ref: BytesN<32>, valid_until: u64);
    fn transfer(env: Env, from: Address, to: Address, amount: i128);
    fn transfer_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128);
}

fn read<V: TryFromVal<Env, Val>>(env: &Env, k: &Key) -> Option<V> {
    let s = env.storage().persistent();
    let v = s.get(k);
    if v.is_some() {
        s.extend_ttl(k, TTL_MIN, TTL_BUMP);
    }
    v
}

fn write<V: IntoVal<Env, Val>>(env: &Env, k: &Key, v: &V) {
    let s = env.storage().persistent();
    s.set(k, v);
    s.extend_ttl(k, TTL_MIN, TTL_BUMP);
    env.storage().instance().extend_ttl(TTL_MIN, TTL_BUMP);
}

fn owner(env: &Env) -> Holder {
    env.storage().instance().get(&Key::Owner).unwrap()
}

fn mandate(env: &Env, token: &Address) -> Option<Mandate> {
    read(env, &Key::Mandate(token.clone()))
}

fn must_mandate(env: &Env, token: &Address) -> Mandate {
    mandate(env, token).unwrap_or_else(|| panic_with_error!(env, Error::NoMandate))
}

/// `signer` authorises this entry (SOR-D9). Both: `valid_until`, then `Some(r)` ⇒ `r.require_auth()` (S8). A native
/// holder: host auth, `auth` empty. A UA: the lane's `nonce` (when the entry has one), then its signature over
/// `op_digest(self, f, args)` under `metatx`.
#[allow(clippy::too_many_arguments)]
fn authorize(
    env: &Env,
    signer: &Holder,
    f: &str,
    args: Vec<Val>,
    lane: Option<(&BytesN<32>, u64)>,
    valid_until: u64,
    relayer: &Option<Address>,
    auth: &Bytes,
) {
    if env.ledger().timestamp() > valid_until {
        panic_with_error!(env, Error::Expired);
    }
    if let Some(r) = relayer {
        r.require_auth();
    }
    match signer {
        Holder::Addr(a) => {
            if !auth.is_empty() {
                panic_with_error!(env, Error::BadAuth);
            }
            a.require_auth();
        }
        Holder::Ua(ua) => {
            let reg = match env.storage().instance().get::<_, Option<Address>>(&Key::Registry).flatten() {
                Some(r) => UaRegistryClient::new(env, &r),
                None => panic_with_error!(env, Error::UaLedgerOff),
            };
            if let Some((lane, nonce)) = lane {
                let k = Key::UaNonce(ua.clone(), lane.clone());
                if read::<u64>(env, &k).unwrap_or(0) != nonce {
                    panic_with_error!(env, Error::BadNonce);
                }
                write(env, &k, &(nonce + 1));
            }
            let digest = op_digest(env, &env.current_contract_address(), f, args);
            reg.require_authorized(ua, &BytesN::from_array(env, &PURPOSE_METATX), &digest, auth);
        }
    }
}

#[contract]
pub struct MandateWallet;

#[contractimpl]
impl MandateWallet {
    pub fn __constructor(env: Env, owner: Holder, registry: Option<Address>) {
        if matches!(owner, Holder::Ua(_)) && registry.is_none() {
            panic_with_error!(&env, Error::UaLedgerOff);
        }
        env.storage().instance().set(&Key::Owner, &owner);
        env.storage().instance().set(&Key::Registry, &registry);
    }

    pub fn owner(env: Env) -> Holder {
        owner(&env)
    }

    pub fn mandate(env: Env, token: Address) -> Option<Mandate> {
        mandate(&env, &token)
    }

    pub fn ua_nonce(env: Env, ua: BytesN<32>, lane: BytesN<32>) -> u64 {
        read(&env, &Key::UaNonce(ua, lane)).unwrap_or(0)
    }

    /// `pay_ref` spent by this mandate (the node's `op_consumed` for `mtx_mandate_pay`).
    pub fn paid(env: Env, pay_ref: BytesN<32>) -> bool {
        read::<bool>(&env, &Key::Ref(pay_ref)).is_some()
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mtx_set_mandate(
        env: Env,
        token: Address,
        delegate: Holder,
        max_per_payment: i128,
        max_per_period: i128,
        period_seconds: u64,
        expiry: u64,
        lane: BytesN<32>,
        nonce: u64,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let args = (
            token.clone(), delegate.clone(), max_per_payment, max_per_period, period_seconds, expiry, lane.clone(), nonce,
            valid_until, relayer.clone(),
        );
        authorize(&env, &owner(&env), "mtx_set_mandate", args.into_val(&env), Some((&lane, nonce)), valid_until, &relayer, &auth);
        // period_seconds == 0 would reset the period cap on EVERY payment (review W5).
        if period_seconds == 0 || max_per_payment <= 0 || max_per_payment > max_per_period {
            panic_with_error!(&env, Error::BadMandate);
        }
        let m = Mandate { delegate: delegate.clone(), expiry, period_seconds, period_start: env.ledger().timestamp(),
                          max_per_payment, max_per_period, spent_in_period: 0 };
        write(&env, &Key::Mandate(token.clone()), &m);
        MandateSet { token, delegate, max_per_payment, max_per_period, period_seconds, expiry }.publish(&env);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn mtx_set_payee(
        env: Env,
        token: Address,
        payee: Holder,
        allowed: bool,
        lane: BytesN<32>,
        nonce: u64,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let args = (token.clone(), payee.clone(), allowed, lane.clone(), nonce, valid_until, relayer.clone());
        authorize(&env, &owner(&env), "mtx_set_payee", args.into_val(&env), Some((&lane, nonce)), valid_until, &relayer, &auth);
        let k = Key::Payee(token, payee);
        if allowed {
            write(&env, &k, &true);
        } else {
            env.storage().persistent().remove(&k);
        }
    }

    /// The owner, or the delegate revoking its own authority (the platform's kill switch).
    #[allow(clippy::too_many_arguments)]
    pub fn mtx_revoke(
        env: Env,
        token: Address,
        by: Holder,
        lane: BytesN<32>,
        nonce: u64,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let m = must_mandate(&env, &token);
        if by != owner(&env) && by != m.delegate {
            panic_with_error!(&env, Error::NotAllowed);
        }
        let args = (token.clone(), by.clone(), lane.clone(), nonce, valid_until, relayer.clone());
        authorize(&env, &by, "mtx_revoke", args.into_val(&env), Some((&lane, nonce)), valid_until, &relayer, &auth);
        env.storage().persistent().remove(&Key::Mandate(token.clone()));
        MandateRevoked { token, by }.publish(&env);
    }

    /// A UA `to` is credited by `transfer_to_ua`, a native one by `transfer`.
    #[allow(clippy::too_many_arguments)]
    pub fn mtx_withdraw(
        env: Env,
        token: Address,
        to: Holder,
        amount: i128,
        lane: BytesN<32>,
        nonce: u64,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let args = (token.clone(), to.clone(), amount, lane.clone(), nonce, valid_until, relayer.clone());
        authorize(&env, &owner(&env), "mtx_withdraw", args.into_val(&env), Some((&lane, nonce)), valid_until, &relayer, &auth);
        let (t, me) = (PayTokenClient::new(&env, &token), env.current_contract_address());
        match &to {
            Holder::Ua(u) => t.transfer_to_ua(&me, u, &amount),
            Holder::Addr(a) => t.transfer(&me, a, &amount),
        }
    }

    /// Anyone submits (a relayer); the authority is the delegate's, the limits are the mandate's. `pay_ref` runs once
    /// per mandate, which also makes a UA delegate's signature one-shot.
    #[allow(clippy::too_many_arguments)]
    pub fn mtx_mandate_pay(
        env: Env,
        token: Address,
        payee: Holder,
        amount: i128,
        pay_ref: BytesN<32>,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let mut m = must_mandate(&env, &token);
        let rk = Key::Ref(pay_ref.clone());
        // Before the signature check: a replay costs no verify.
        if env.storage().persistent().has(&rk) {
            panic_with_error!(&env, Error::RefAlreadyPaid);
        }
        let args = (token.clone(), payee.clone(), amount, pay_ref.clone(), valid_until, relayer.clone());
        authorize(&env, &m.delegate, "mtx_mandate_pay", args.into_val(&env), None, valid_until, &relayer, &auth);
        let now = env.ledger().timestamp();
        if now > m.expiry {
            panic_with_error!(&env, Error::MandateExpired);
        }
        if read::<bool>(&env, &Key::Payee(token.clone(), payee.clone())).is_none() {
            panic_with_error!(&env, Error::PayeeNotAllowed);
        }
        if amount <= 0 || amount > m.max_per_payment {
            panic_with_error!(&env, Error::OverPaymentCap);
        }
        if now >= m.period_start.saturating_add(m.period_seconds) {
            m.period_start = now;
            m.spent_in_period = 0;
        }
        let spent = m.spent_in_period.saturating_add(amount);
        if spent > m.max_per_period {
            panic_with_error!(&env, Error::OverPeriodCap);
        }
        m.spent_in_period = spent;
        write(&env, &Key::Mandate(token.clone()), &m);
        write(&env, &rk, &true);
        // `self` is `from`, so the token's `require_auth` is met by the direct invoker.
        let (t, me) = (PayTokenClient::new(&env, &token), env.current_contract_address());
        match &payee {
            Holder::Ua(u) => t.pay_to_ua(&me, u, &amount, &pay_ref, &valid_until),
            Holder::Addr(a) => t.pay(&me, a, &amount, &pay_ref, &valid_until),
        }
        PaidUnderMandate { token, payee, amount, pay_ref }.publish(&env);
    }
}

#[cfg(test)]
mod test;
