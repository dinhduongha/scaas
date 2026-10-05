//! Token SEP-41 + `pay` — tương đương META trên Soroban (R65).
//!
//! Meta-tx cấp contract (R30) KHÔNG cần verifier riêng: `from.require_auth()` được host thoả bằng auth entry
//! chủ thể đã ký (`HashIdPreimage::SorobanAuthorization`: network id + contract + hàm + đối số + nonce ngẫu nhiên
//! + hạn ledger). Relayer là source của tx, trả phí bằng sequence của chính lane. Contract tự tính digest thao
//! tác (cùng công thức với Odoo/adapter) và phát trong `MetaTransactionExecuted` để Odoo chốt op.
#![no_std]
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, xdr::ToXdr, Address,
    BytesN, Env, Executable, MuxedAddress, String, Symbol,
};

const DAY: u32 = 17_280;
const TTL_BUMP: u32 = 60 * DAY;
const TTL_MIN: u32 = 30 * DAY;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    NegativeAmount = 1,
    InsufficientBalance = 2,
    InsufficientAllowance = 3,
    SpenderNotContract = 4,
    Expired = 5,
    RefUsed = 6,
    BadExpiration = 7,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Admin,
    Decimals,
    Name,
    Symbol,
    Balance(Address),
    Allowance(Address, Address),
    PayRef(BytesN<32>),
}

#[contracttype]
#[derive(Clone)]
struct Allowance {
    amount: i128,
    expiration_ledger: u32,
}

#[contractevent(topics = ["PaymentSettled"], data_format = "vec")]
pub struct PaymentSettled {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
    pub pay_ref: BytesN<32>,
}

#[contractevent(topics = ["MetaTransactionExecuted"], data_format = "single-value")]
pub struct MetaTransactionExecuted {
    #[topic]
    pub from: Address,
    pub digest: BytesN<32>,
}

#[contractevent(topics = ["transfer"], data_format = "single-value")]
pub struct Transfer {
    #[topic]
    pub from: Address,
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent(topics = ["approve"], data_format = "vec")]
pub struct Approve {
    #[topic]
    pub from: Address,
    #[topic]
    pub spender: Address,
    pub amount: i128,
    pub expiration_ledger: u32,
}

#[contractevent(topics = ["mint"], data_format = "single-value")]
pub struct Mint {
    #[topic]
    pub to: Address,
    pub amount: i128,
}

#[contractevent(topics = ["burn"], data_format = "single-value")]
pub struct Burn {
    #[topic]
    pub from: Address,
    pub amount: i128,
}

/// Digest thao tác (`MetaOp` v1 trên Soroban): sha256(XDR của
/// `Vec[Symbol("bamboo_metaop_v1"), BytesN32(network_id), Address(contract), Symbol(fn), Vec(args)]`).
/// Python (`fam_soroban.op_digest`) và adapter Rust tính cùng giá trị — vector chéo trong test.
pub fn op_digest(env: &Env, function: &str, args: soroban_sdk::Vec<soroban_sdk::Val>) -> BytesN<32> {
    let v = (
        Symbol::new(env, "bamboo_metaop_v1"),
        env.ledger().network_id(),
        env.current_contract_address(),
        Symbol::new(env, function),
        args,
    );
    env.crypto().sha256(&v.to_xdr(env)).into()
}

fn check_amount(env: &Env, amount: i128) {
    if amount < 0 {
        panic_with_error!(env, Error::NegativeAmount);
    }
}

fn balance_of(env: &Env, id: &Address) -> i128 {
    let k = Key::Balance(id.clone());
    let s = env.storage().persistent();
    match s.get::<_, i128>(&k) {
        Some(b) => {
            s.extend_ttl(&k, TTL_MIN, TTL_BUMP);
            b
        }
        None => 0,
    }
}

fn set_balance(env: &Env, id: &Address, v: i128) {
    let k = Key::Balance(id.clone());
    env.storage().persistent().set(&k, &v);
    env.storage().persistent().extend_ttl(&k, TTL_MIN, TTL_BUMP);
}

fn move_funds(env: &Env, from: &Address, to: &Address, amount: i128) {
    check_amount(env, amount);
    let b = balance_of(env, from);
    if b < amount {
        panic_with_error!(env, Error::InsufficientBalance);
    }
    set_balance(env, from, b - amount);
    set_balance(env, to, balance_of(env, to) + amount);
}

fn allowance_of(env: &Env, from: &Address, spender: &Address) -> i128 {
    match env.storage().temporary().get::<_, Allowance>(&Key::Allowance(from.clone(), spender.clone())) {
        Some(a) if a.expiration_ledger >= env.ledger().sequence() => a.amount,
        _ => 0,
    }
}

fn spend_allowance(env: &Env, from: &Address, spender: &Address, amount: i128) {
    let k = Key::Allowance(from.clone(), spender.clone());
    let a: Allowance = env.storage().temporary().get(&k).unwrap_or(Allowance { amount: 0, expiration_ledger: 0 });
    if a.expiration_ledger < env.ledger().sequence() || a.amount < amount {
        panic_with_error!(env, Error::InsufficientAllowance);
    }
    env.storage().temporary().set(&k, &Allowance { amount: a.amount - amount, ..a });
}

/// R26: chỉ contract (Wasm hoặc Stellar Asset) được làm spender — không bao giờ một account thường.
fn require_contract(env: &Env, spender: &Address) {
    match spender.executable() {
        Some(Executable::Wasm(_)) | Some(Executable::StellarAsset) => {}
        _ => panic_with_error!(env, Error::SpenderNotContract),
    }
}

#[contract]
pub struct Token;

#[contractimpl]
impl Token {
    pub fn __constructor(env: Env, admin: Address, decimals: u32, name: String, symbol: String) {
        let s = env.storage().instance();
        s.set(&Key::Admin, &admin);
        s.set(&Key::Decimals, &decimals);
        s.set(&Key::Name, &name);
        s.set(&Key::Symbol, &symbol);
    }

    pub fn admin(env: Env) -> Address {
        env.storage().instance().get(&Key::Admin).unwrap()
    }

    pub fn mint(env: Env, to: Address, amount: i128) {
        Self::admin(env.clone()).require_auth();
        check_amount(&env, amount);
        env.storage().instance().extend_ttl(TTL_MIN, TTL_BUMP);
        set_balance(&env, &to, balance_of(&env, &to) + amount);
        Mint { to, amount }.publish(&env);
    }

    /// Thanh toán có `pay_ref` (entryRef của Odoo): mỗi `pay_ref` một lần, có hạn theo giờ ledger. Gọi qua relayer
    /// với auth entry chủ thể đã ký (R30) hoặc trực tiếp bởi contract (mandate) — `require_auth` như nhau.
    pub fn pay(env: Env, from: Address, to: Address, amount: i128, pay_ref: BytesN<32>, valid_until: u64) {
        from.require_auth();
        if env.ledger().timestamp() > valid_until {
            panic_with_error!(&env, Error::Expired);
        }
        let k = Key::PayRef(pay_ref.clone());
        let s = env.storage().persistent();
        if s.has(&k) {
            panic_with_error!(&env, Error::RefUsed);
        }
        s.set(&k, &true);
        s.extend_ttl(&k, TTL_MIN, TTL_BUMP);
        env.storage().instance().extend_ttl(TTL_MIN, TTL_BUMP);
        move_funds(&env, &from, &to, amount);
        let args = (from.clone(), to.clone(), amount, pay_ref.clone(), valid_until);
        let digest = op_digest(&env, "pay", soroban_sdk::IntoVal::into_val(&args, &env));
        PaymentSettled { from: from.clone(), to, amount, pay_ref }.publish(&env);
        MetaTransactionExecuted { from, digest }.publish(&env);
    }

    /// `pay_ref` đã dùng chưa (Odoo/relayer đọc trước khi phát lại).
    pub fn ref_used(env: Env, pay_ref: BytesN<32>) -> bool {
        env.storage().persistent().has(&Key::PayRef(pay_ref))
    }

    // ------------------------------------------------------------------ SEP-41

    pub fn allowance(env: Env, from: Address, spender: Address) -> i128 {
        allowance_of(&env, &from, &spender)
    }

    pub fn approve(env: Env, from: Address, spender: Address, amount: i128, expiration_ledger: u32) {
        from.require_auth();
        check_amount(&env, amount);
        require_contract(&env, &spender);
        if amount > 0 && expiration_ledger < env.ledger().sequence() {
            panic_with_error!(&env, Error::BadExpiration);
        }
        let k = Key::Allowance(from.clone(), spender.clone());
        env.storage().temporary().set(&k, &Allowance { amount, expiration_ledger });
        if amount > 0 {
            let live = expiration_ledger - env.ledger().sequence();
            env.storage().temporary().extend_ttl(&k, live, live);
        }
        Approve { from, spender, amount, expiration_ledger }.publish(&env);
    }

    pub fn balance(env: Env, id: Address) -> i128 {
        balance_of(&env, &id)
    }

    pub fn transfer(env: Env, from: Address, to: MuxedAddress, amount: i128) {
        from.require_auth();
        let to = to.address();
        move_funds(&env, &from, &to, amount);
        Transfer { from, to, amount }.publish(&env);
    }

    pub fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128) {
        spender.require_auth();
        check_amount(&env, amount);
        spend_allowance(&env, &from, &spender, amount);
        move_funds(&env, &from, &to, amount);
        Transfer { from, to, amount }.publish(&env);
    }

    pub fn burn(env: Env, from: Address, amount: i128) {
        from.require_auth();
        Self::burn_inner(&env, from, amount);
    }

    pub fn burn_from(env: Env, spender: Address, from: Address, amount: i128) {
        spender.require_auth();
        check_amount(&env, amount);
        spend_allowance(&env, &from, &spender, amount);
        Self::burn_inner(&env, from, amount);
    }

    pub fn decimals(env: Env) -> u32 {
        env.storage().instance().get(&Key::Decimals).unwrap()
    }

    pub fn name(env: Env) -> String {
        env.storage().instance().get(&Key::Name).unwrap()
    }

    pub fn symbol(env: Env) -> String {
        env.storage().instance().get(&Key::Symbol).unwrap()
    }
}

impl Token {
    fn burn_inner(env: &Env, from: Address, amount: i128) {
        check_amount(env, amount);
        let b = balance_of(env, &from);
        if b < amount {
            panic_with_error!(env, Error::InsufficientBalance);
        }
        set_balance(env, &from, b - amount);
        Burn { from, amount }.publish(env);
    }
}

#[cfg(test)]
mod test;
