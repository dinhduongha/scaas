//! Ví của MỘT người trả, uỷ quyền có giới hạn cho thanh toán tự động (như `MandateWallet` EVM, R25).
//!
//! Tiền nằm trong contract; delegate (khoá custody của platform) chỉ tiêu được trong mandate owner đặt: hạn mức mỗi
//! lần, mỗi kỳ, payee cho phép, hạn dùng, `pay_ref` một lần. Contract trả bằng `token.pay(self, …)` nên
//! `PaymentSettled` vẫn mang `pay_ref` — Odoo đối soát như thanh toán tay. Owner gasless tự nhiên: auth entry của
//! owner đi qua relayer như mọi meta-tx Soroban (không cần `executeAsOwner`).
#![no_std]
use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, panic_with_error, Address,
    BytesN, Env,
};

const DAY: u32 = 17_280;

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
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Mandate {
    pub delegate: Address,
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
    Owner,
    Mandate(Address),
    Payee(Address, Address),
    Ref(BytesN<32>),
}

#[contractevent(topics = ["MandateSet"], data_format = "vec")]
pub struct MandateSet {
    #[topic]
    pub token: Address,
    #[topic]
    pub delegate: Address,
    pub max_per_payment: i128,
    pub max_per_period: i128,
    pub period_seconds: u64,
    pub expiry: u64,
}

#[contractevent(topics = ["MandateRevoked"], data_format = "single-value")]
pub struct MandateRevoked {
    #[topic]
    pub token: Address,
    pub by: Address,
}

#[contractevent(topics = ["PaidUnderMandate"], data_format = "vec")]
pub struct PaidUnderMandate {
    #[topic]
    pub token: Address,
    #[topic]
    pub payee: Address,
    pub amount: i128,
    pub pay_ref: BytesN<32>,
}

/// Phần của `scaas-token` mandate gọi.
#[contractclient(name = "PayTokenClient")]
pub trait PayToken {
    fn pay(env: Env, from: Address, to: Address, amount: i128, pay_ref: BytesN<32>, valid_until: u64);
    fn transfer(env: Env, from: Address, to: Address, amount: i128);
}

fn owner(env: &Env) -> Address {
    env.storage().instance().get(&Key::Owner).unwrap()
}

fn mandate(env: &Env, token: &Address) -> Option<Mandate> {
    env.storage().persistent().get(&Key::Mandate(token.clone()))
}

fn bump(env: &Env) {
    env.storage().instance().extend_ttl(30 * DAY, 60 * DAY);
}

#[contract]
pub struct MandateWallet;

#[contractimpl]
impl MandateWallet {
    pub fn __constructor(env: Env, owner: Address) {
        env.storage().instance().set(&Key::Owner, &owner);
    }

    pub fn owner(env: Env) -> Address {
        owner(&env)
    }

    pub fn mandate(env: Env, token: Address) -> Option<Mandate> {
        mandate(&env, &token)
    }

    pub fn set_mandate(env: Env, token: Address, delegate: Address, max_per_payment: i128, max_per_period: i128,
                       period_seconds: u64, expiry: u64) {
        owner(&env).require_auth();
        // period_seconds == 0 sẽ reset hạn mức kỳ ở MỌI lần trả (review W5).
        if period_seconds == 0 || max_per_payment <= 0 || max_per_payment > max_per_period {
            panic_with_error!(&env, Error::BadMandate);
        }
        let m = Mandate { delegate: delegate.clone(), expiry, period_seconds, period_start: env.ledger().timestamp(),
                          max_per_payment, max_per_period, spent_in_period: 0 };
        let k = Key::Mandate(token.clone());
        env.storage().persistent().set(&k, &m);
        env.storage().persistent().extend_ttl(&k, 30 * DAY, 60 * DAY);
        bump(&env);
        MandateSet { token, delegate, max_per_payment, max_per_period, period_seconds, expiry }.publish(&env);
    }

    pub fn set_payee(env: Env, token: Address, payee: Address, allowed: bool) {
        owner(&env).require_auth();
        let k = Key::Payee(token, payee);
        if allowed {
            env.storage().persistent().set(&k, &true);
            env.storage().persistent().extend_ttl(&k, 30 * DAY, 60 * DAY);
        } else {
            env.storage().persistent().remove(&k);
        }
    }

    /// Owner, hoặc delegate tự thu hồi quyền của chính nó (kill switch của platform).
    pub fn revoke(env: Env, token: Address, by: Address) {
        let m = mandate(&env, &token).unwrap_or_else(|| panic_with_error!(&env, Error::NoMandate));
        if by != owner(&env) && by != m.delegate {
            panic_with_error!(&env, Error::NotAllowed);
        }
        by.require_auth();
        env.storage().persistent().remove(&Key::Mandate(token.clone()));
        MandateRevoked { token, by }.publish(&env);
    }

    pub fn withdraw(env: Env, token: Address, to: Address, amount: i128) {
        owner(&env).require_auth();
        PayTokenClient::new(&env, &token).transfer(&env.current_contract_address(), &to, &amount);
    }

    /// Ai cũng nộp được (relayer); quyền đến từ auth của delegate, giới hạn đến từ mandate.
    pub fn pay_under_mandate(env: Env, token: Address, payee: Address, amount: i128, pay_ref: BytesN<32>,
                             valid_until: u64) {
        let mut m = mandate(&env, &token).unwrap_or_else(|| panic_with_error!(&env, Error::NoMandate));
        m.delegate.require_auth();
        let now = env.ledger().timestamp();
        if now > m.expiry {
            panic_with_error!(&env, Error::MandateExpired);
        }
        if !env.storage().persistent().has(&Key::Payee(token.clone(), payee.clone())) {
            panic_with_error!(&env, Error::PayeeNotAllowed);
        }
        if amount <= 0 || amount > m.max_per_payment {
            panic_with_error!(&env, Error::OverPaymentCap);
        }
        let rk = Key::Ref(pay_ref.clone());
        if env.storage().persistent().has(&rk) {
            panic_with_error!(&env, Error::RefAlreadyPaid);
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
        let k = Key::Mandate(token.clone());
        env.storage().persistent().set(&k, &m);
        env.storage().persistent().extend_ttl(&k, 30 * DAY, 60 * DAY);
        env.storage().persistent().set(&rk, &true);
        env.storage().persistent().extend_ttl(&rk, 30 * DAY, 60 * DAY);
        bump(&env);
        // Hạn chữ ký (`valid_until`) do token kiểm; `self` là `from` nên require_auth của token tự thoả.
        PayTokenClient::new(&env, &token).pay(&env.current_contract_address(), &payee, &amount, &pay_ref, &valid_until);
        PaidUnderMandate { token, payee, amount, pay_ref }.publish(&env);
    }
}

#[cfg(test)]
mod test;
