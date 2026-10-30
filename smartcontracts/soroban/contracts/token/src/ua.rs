//! The token's UA ledger (spec §5.1, §5.5; S6–S9, S11, S16): `UaBalance(ua)` beside the native balances, separate
//! `ua_*` entries signed by the UA through the registry bound at construction, lanes `UaNonce(ua, lane)`. The UA pool
//! is the token's own address: every native ↔ UA move goes through `Balance(token)`, so `balance(token) = Σ UaBalance`
//! and the SEP-41 events replay to `balance()`.
use scaas_ua_common::{
    meta_pay_id, op_digest, pay_lane, Holder, Order, UaRegistryClient, PURPOSE_METATX, PURPOSE_METATX_CANCEL,
    PURPOSE_TRADE,
};
use soroban_sdk::{
    contractevent, contractimpl, panic_with_error, Address, Bytes, BytesN, Env, IntoVal, TryFromVal, Val, Vec,
};

use crate::{
    balance_of, check_amount, move_funds, not_pool, set_balance, Burn, Error, Key, MetaTransactionExecuted, Mint,
    PaymentMeta, Token, TokenArgs, TokenClient, Transfer, TTL_BUMP, TTL_MIN,
};

/// Every UA move; `mint_to_ua` comes from `Holder::Addr(token)`, `ua_burn` goes to it.
#[contractevent(topics = ["UaTransfer"], data_format = "single-value")]
pub struct UaTransfer {
    #[topic]
    pub from: Holder,
    #[topic]
    pub to: Holder,
    pub amount: i128,
}

#[contractevent(topics = ["UaPaymentSettled"], data_format = "vec")]
pub struct UaPaymentSettled {
    #[topic]
    pub from: Holder,
    #[topic]
    pub to: Holder,
    pub amount: i128,
    pub pay_ref: BytesN<32>,
}

/// Every UA-signed entry; `digest` is the op digest the UA signed (the job's id).
#[contractevent(topics = ["UaMetaTransactionExecuted"], data_format = "single-value")]
pub struct UaMetaTransactionExecuted {
    #[topic]
    pub from: BytesN<32>,
    pub digest: BytesN<32>,
}

#[contractevent(topics = ["UaNonceCancelled"], data_format = "single-value")]
pub struct UaNonceCancelled {
    #[topic]
    pub ua: BytesN<32>,
    #[topic]
    pub lane: BytesN<32>,
    pub new_nonce: u64,
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
}

fn ua_bal(env: &Env, ua: &BytesN<32>) -> i128 {
    read(env, &Key::UaBalance(ua.clone())).unwrap_or(0)
}

fn add_ua(env: &Env, ua: &BytesN<32>, amount: i128) {
    write(env, &Key::UaBalance(ua.clone()), &(ua_bal(env, ua) + amount));
}

fn debit_ua(env: &Env, ua: &BytesN<32>, amount: i128) {
    check_amount(env, amount);
    let b = ua_bal(env, ua);
    if b < amount {
        panic_with_error!(env, Error::InsufficientBalance);
    }
    write(env, &Key::UaBalance(ua.clone()), &(b - amount));
}

fn pool(env: &Env) -> Address {
    env.current_contract_address()
}

/// The bound registry, else `UaLedgerOff` (S16).
fn registry(env: &Env) -> UaRegistryClient<'static> {
    match env.storage().instance().get::<_, Option<Address>>(&Key::Registry).flatten() {
        Some(r) => {
            env.storage().instance().extend_ttl(TTL_MIN, TTL_BUMP);
            UaRegistryClient::new(env, &r)
        }
        None => panic_with_error!(env, Error::UaLedgerOff),
    }
}

/// S9 / SOR-D15: a UA receiver must be able to spend here; a native receiver is never the pool.
fn check_receiver(env: &Env, reg: &UaRegistryClient, to: &Holder) {
    match to {
        Holder::Ua(u) => {
            if !reg.receivable(u) {
                let e = if reg.record_of(u).is_none() { Error::UaNotRegistered } else { Error::UaNotReceivable };
                panic_with_error!(env, e);
            }
        }
        Holder::Addr(a) => not_pool(env, a),
    }
}

/// Credit `to` from the pool (a UA debit already happened): a UA in the ledger, an address natively out of the pool.
fn credit(env: &Env, to: &Holder, amount: i128) {
    match to {
        Holder::Ua(u) => add_ua(env, u, amount),
        Holder::Addr(a) => {
            move_funds(env, &pool(env), a, amount);
            Transfer { from: pool(env), to: a.clone(), amount }.publish(env);
        }
    }
}

/// `nonce == UaNonce(ua, lane)` else `BadNonce`, then `nonce + 1` (S7).
fn use_nonce(env: &Env, ua: &BytesN<32>, lane: &BytesN<32>, nonce: u64) -> u64 {
    let k = Key::UaNonce(ua.clone(), lane.clone());
    if read::<u64>(env, &k).unwrap_or(0) != nonce {
        panic_with_error!(env, Error::BadNonce);
    }
    write(env, &k, &(nonce + 1));
    nonce + 1
}

/// A UA-signed entry: ledger on, `valid_until`, the lane, `Some(r)` ⇒ `r.require_auth()` (S8), then the UA's
/// signature over `op_digest(token, f, args)` (args without `auth`). Returns the registry and the digest.
#[allow(clippy::too_many_arguments)]
fn authorize(
    env: &Env,
    f: &str,
    args: Vec<Val>,
    purpose: [u8; 32],
    from: &BytesN<32>,
    lane: &BytesN<32>,
    nonce: u64,
    valid_until: u64,
    relayer: &Option<Address>,
    auth: &Bytes,
) -> (UaRegistryClient<'static>, BytesN<32>) {
    let reg = registry(env);
    if env.ledger().timestamp() > valid_until {
        panic_with_error!(env, Error::Expired);
    }
    use_nonce(env, from, lane, nonce);
    if let Some(r) = relayer {
        r.require_auth();
    }
    let digest = op_digest(env, &pool(env), f, args);
    reg.require_authorized(from, &BytesN::from_array(env, &purpose), &digest, auth);
    (reg, digest)
}

#[contractimpl]
impl Token {
    pub fn registry(env: Env) -> Option<Address> {
        env.storage().instance().get::<_, Option<Address>>(&Key::Registry).flatten()
    }

    pub fn ua_balance(env: Env, ua: BytesN<32>) -> i128 {
        ua_bal(&env, &ua)
    }

    pub fn ua_nonce(env: Env, ua: BytesN<32>, lane: BytesN<32>) -> u64 {
        read(&env, &Key::UaNonce(ua, lane)).unwrap_or(0)
    }

    /// SOR-D7: `ua_pay` is nonce 0 of its pay lane, so the ref is used once that lane moved.
    pub fn ua_ref_used(env: Env, ua: BytesN<32>, pay_ref: BytesN<32>) -> bool {
        let lane = pay_lane(&env, &pay_ref);
        Self::ua_nonce(env, ua, lane) > 0
    }

    /// A native holder pays into the UA ledger (CTR-UA-28): native `from` → pool, `UaBalance(to)` up.
    pub fn transfer_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128) {
        not_pool(&env, &from);
        from.require_auth();
        let reg = registry(&env);
        let to = Holder::Ua(to);
        check_receiver(&env, &reg, &to);
        move_funds(&env, &from, &pool(&env), amount);
        Transfer { from: from.clone(), to: pool(&env), amount }.publish(&env);
        credit(&env, &to, amount);
        UaTransfer { from: Holder::Addr(from), to, amount }.publish(&env);
    }

    /// `pay` to a UA receiver: `PayRef(from, pay_ref)` once, as `pay` (the mandate pays a UA payee through it).
    pub fn pay_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128, pay_ref: BytesN<32>, valid_until: u64) {
        from.require_auth();
        let reg = registry(&env);
        let holder = Holder::Ua(to.clone());
        check_receiver(&env, &reg, &holder);
        Self::use_pay_ref(&env, &from, &pay_ref, valid_until);
        move_funds(&env, &from, &pool(&env), amount);
        Transfer { from: from.clone(), to: pool(&env), amount }.publish(&env);
        credit(&env, &holder, amount);
        let src = Holder::Addr(from.clone());
        UaTransfer { from: src.clone(), to: holder.clone(), amount }.publish(&env);
        UaPaymentSettled { from: src, to: holder, amount, pay_ref: pay_ref.clone() }.publish(&env);
        let args = (from.clone(), to, amount, pay_ref, valid_until);
        let digest = op_digest(&env, &pool(&env), "pay_to_ua", args.into_val(&env));
        MetaTransactionExecuted { from, digest }.publish(&env);
    }

    pub fn mint_to_ua(env: Env, to: BytesN<32>, amount: i128) {
        Self::admin(env.clone()).require_auth();
        let reg = registry(&env);
        check_amount(&env, amount);
        let to = Holder::Ua(to);
        check_receiver(&env, &reg, &to);
        set_balance(&env, &pool(&env), balance_of(&env, &pool(&env)) + amount);
        Mint { to: pool(&env), amount }.publish(&env);
        credit(&env, &to, amount);
        UaTransfer { from: Holder::Addr(pool(&env)), to, amount }.publish(&env);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn ua_transfer(
        env: Env,
        from: BytesN<32>,
        to: Holder,
        amount: i128,
        lane: BytesN<32>,
        nonce: u64,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let args = (from.clone(), to.clone(), amount, lane.clone(), nonce, valid_until, relayer.clone());
        let (reg, digest) =
            authorize(&env, "ua_transfer", args.into_val(&env), PURPOSE_METATX, &from, &lane, nonce, valid_until, &relayer, &auth);
        check_receiver(&env, &reg, &to);
        debit_ua(&env, &from, amount);
        credit(&env, &to, amount);
        UaTransfer { from: Holder::Ua(from.clone()), to, amount }.publish(&env);
        UaMetaTransactionExecuted { from, digest }.publish(&env);
    }

    /// One-shot per `(ua, pay_ref)`: nonce 0 of lane `pay_lane(pay_ref)` (S7, CTR-MTX-26).
    #[allow(clippy::too_many_arguments)]
    pub fn ua_pay(
        env: Env,
        from: BytesN<32>,
        to: Holder,
        amount: i128,
        pay_ref: BytesN<32>,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let args = (from.clone(), to.clone(), amount, pay_ref.clone(), valid_until, relayer.clone());
        Self::ua_settle(&env, "ua_pay", args.into_val(&env), from, to, amount, pay_ref, valid_until, relayer, auth);
    }

    /// `ua_pay` with `pay_ref = meta_pay_id(salt, meta)`; `PaymentMeta` before the settlement (CTR-MTX-26).
    #[allow(clippy::too_many_arguments)]
    pub fn ua_pay_meta(
        env: Env,
        from: BytesN<32>,
        to: Holder,
        amount: i128,
        salt: BytesN<32>,
        meta: Bytes,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let pay_ref = meta_pay_id(&env, &salt, &meta);
        PaymentMeta { pay_id: pay_ref.clone(), meta: meta.clone() }.publish(&env);
        let args = (from.clone(), to.clone(), amount, salt, meta, valid_until, relayer.clone());
        Self::ua_settle(&env, "ua_pay_meta", args.into_val(&env), from, to, amount, pay_ref, valid_until, relayer, auth);
    }

    /// The UA's tokens leave the pool: `UaBalance(from)` and `Balance(token)` down by `amount`.
    #[allow(clippy::too_many_arguments)]
    pub fn ua_burn(
        env: Env,
        from: BytesN<32>,
        amount: i128,
        lane: BytesN<32>,
        nonce: u64,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let args = (from.clone(), amount, lane.clone(), nonce, valid_until, relayer.clone());
        let (_, digest) =
            authorize(&env, "ua_burn", args.into_val(&env), PURPOSE_METATX, &from, &lane, nonce, valid_until, &relayer, &auth);
        debit_ua(&env, &from, amount);
        set_balance(&env, &pool(&env), balance_of(&env, &pool(&env)) - amount);
        Burn { from: pool(&env), amount }.publish(&env);
        UaTransfer { from: Holder::Ua(from.clone()), to: Holder::Addr(pool(&env)), amount }.publish(&env);
        UaMetaTransactionExecuted { from, digest }.publish(&env);
    }

    /// Bumps `lane` by one (purpose `metatx-cancel`): a signed entry at the old nonce can no longer run. The signature
    /// names no nonce, so each cancel digest runs once (`UaCancelUsed`, EVM `cancelUsed`; a replay is `BadNonce`).
    pub fn ua_cancel_nonce(env: Env, ua: BytesN<32>, lane: BytesN<32>, valid_until: u64, auth: Bytes) {
        let nonce = Self::ua_nonce(env.clone(), ua.clone(), lane.clone());
        let args = (ua.clone(), lane.clone(), valid_until);
        let (_, digest) =
            authorize(&env, "ua_cancel_nonce", args.into_val(&env), PURPOSE_METATX_CANCEL, &ua, &lane, nonce, valid_until, &None, &auth);
        let used = Key::UaCancelUsed(digest.clone());
        if read::<bool>(&env, &used).is_some() {
            panic_with_error!(&env, Error::BadNonce);
        }
        write(&env, &used, &true);
        UaNonceCancelled { ua: ua.clone(), lane, new_nonce: nonce + 1 }.publish(&env);
        UaMetaTransactionExecuted { from: ua, digest }.publish(&env);
    }

    /// The DEX (the direct invoker) moves `amount` of a UA maker's order from the UA ledger to itself (spec §5.3).
    /// The order signature is over `op_digest(token, "ua_order", (dex, order))`, purpose `trade`; no nonce: the DEX's
    /// `filled` bounds the fills, so one signature fills partially.
    pub fn ua_trade(env: Env, dex: Address, order: Order, auth: Bytes, amount: i128) {
        dex.require_auth();
        let reg = registry(&env);
        let Holder::Ua(ua) = order.maker.clone() else { panic_with_error!(&env, Error::BadOrder) };
        if order.sell_token != pool(&env) {
            panic_with_error!(&env, Error::BadOrder);
        }
        if env.ledger().timestamp() > order.expiry {
            panic_with_error!(&env, Error::Expired);
        }
        let digest = op_digest(&env, &pool(&env), "ua_order", (dex.clone(), order).into_val(&env));
        reg.require_authorized(&ua, &BytesN::from_array(&env, &PURPOSE_TRADE), &digest, &auth);
        debit_ua(&env, &ua, amount);
        let to = Holder::Addr(dex);
        credit(&env, &to, amount);
        UaTransfer { from: Holder::Ua(ua.clone()), to, amount }.publish(&env);
        UaMetaTransactionExecuted { from: ua, digest }.publish(&env);
    }
}

impl Token {
    /// The body of `ua_pay` / `ua_pay_meta`.
    #[allow(clippy::too_many_arguments)]
    fn ua_settle(
        env: &Env,
        f: &str,
        args: Vec<Val>,
        from: BytesN<32>,
        to: Holder,
        amount: i128,
        pay_ref: BytesN<32>,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        let lane = pay_lane(env, &pay_ref);
        let (reg, digest) = authorize(env, f, args, PURPOSE_METATX, &from, &lane, 0, valid_until, &relayer, &auth);
        check_receiver(env, &reg, &to);
        debit_ua(env, &from, amount);
        credit(env, &to, amount);
        let src = Holder::Ua(from.clone());
        UaTransfer { from: src.clone(), to: to.clone(), amount }.publish(env);
        UaPaymentSettled { from: src, to, amount, pay_ref }.publish(env);
        UaMetaTransactionExecuted { from, digest }.publish(env);
    }
}
