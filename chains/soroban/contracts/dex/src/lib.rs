//! DEX thanh toán hai chân (R35, R65): mỗi lệnh được maker uỷ quyền bằng `require_auth_for_args((order,))` — auth
//! entry gốc của Soroban (nonce ngẫu nhiên, hạn ledger, network id) thay cho chữ ký EIP-712. Token đi bằng
//! `transfer_from` với DEX là spender (allowance chỉ cho contract — R26).
//!
//! Lệch EVM (R8-3): một auth entry = một lần settle (host tiêu nonce); lệnh khớp một phần cần maker ký lại phần
//! còn lại, `filled[order_hash]` (hash không chứa nonce) chặn overfill giữa các bản ký lại. (R8-4) Không gom
//! nhiều cặp một tx: lỗi một cặp hoàn tác cả tx Soroban.
#![no_std]
use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, panic_with_error,
    xdr::ToXdr, Address, BytesN, Env, IntoVal, I256,
};

const DAY: u32 = 17_280;
pub const PPM: i128 = 1_000_000;
/// Trần phí DEX: 1 %.
pub const MAX_FEE_PPM: u32 = 10_000;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    TokenMismatch = 1,
    Expired = 2,
    BadAmount = 3,
    PriceLimit = 4,
    Overfill = 5,
    FeeAboveSigned = 6,
    FeeAboveCap = 7,
    UnknownMarket = 8,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Order {
    pub maker: Address,
    pub sell_token: Address,
    pub sell_amount: i128,
    pub buy_token: Address,
    /// Nhận tối thiểu `buy_amount` cho toàn bộ `sell_amount` (giới hạn giá).
    pub buy_amount: i128,
    /// Phí DEX tối đa người ký chấp nhận (ppm).
    pub max_fee_ppm: u32,
    /// Giây (giờ ledger).
    pub expiry: u64,
    pub salt: u64,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub struct Market {
    pub maker_fee_ppm: u32,
    pub taker_fee_ppm: u32,
    pub fee_on: bool,
}

#[contracttype]
#[derive(Clone)]
enum Key {
    Admin,
    FeeRecipient,
    Market(Address, Address),
    Filled(BytesN<32>),
}

#[contractevent(topics = ["Settled"], data_format = "vec")]
pub struct Settled {
    #[topic]
    pub maker_hash: BytesN<32>,
    #[topic]
    pub taker_hash: BytesN<32>,
    pub maker_sold: i128,
    pub taker_sold: i128,
    pub maker_fee: i128,
    pub taker_fee: i128,
}

#[contractevent(topics = ["Cancelled"], data_format = "single-value")]
pub struct Cancelled {
    #[topic]
    pub maker: Address,
    pub order_hash: BytesN<32>,
}

#[contractclient(name = "SpendClient")]
pub trait Spend {
    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128);
}

pub fn order_hash(env: &Env, o: &Order) -> BytesN<32> {
    env.crypto().sha256(&o.clone().to_xdr(env)).into()
}

fn market_key(a: &Address, b: &Address) -> Key {
    if a < b { Key::Market(a.clone(), b.clone()) } else { Key::Market(b.clone(), a.clone()) }
}

fn filled(env: &Env, h: &BytesN<32>) -> i128 {
    env.storage().persistent().get(&Key::Filled(h.clone())).unwrap_or(0)
}

fn set_filled(env: &Env, h: &BytesN<32>, v: i128) {
    let k = Key::Filled(h.clone());
    env.storage().persistent().set(&k, &v);
    env.storage().persistent().extend_ttl(&k, 30 * DAY, 60 * DAY);
}

fn admin(env: &Env) -> Address {
    env.storage().instance().get(&Key::Admin).unwrap()
}

#[contract]
pub struct Dex;

#[contractimpl]
impl Dex {
    pub fn __constructor(env: Env, admin: Address, fee_recipient: Address) {
        env.storage().instance().set(&Key::Admin, &admin);
        env.storage().instance().set(&Key::FeeRecipient, &fee_recipient);
    }

    pub fn set_market(env: Env, token_a: Address, token_b: Address, market: Market) {
        admin(&env).require_auth();
        if market.maker_fee_ppm > MAX_FEE_PPM || market.taker_fee_ppm > MAX_FEE_PPM {
            panic_with_error!(&env, Error::FeeAboveCap);
        }
        env.storage().instance().set(&market_key(&token_a, &token_b), &market);
        env.storage().instance().extend_ttl(30 * DAY, 60 * DAY);
    }

    pub fn market(env: Env, token_a: Address, token_b: Address) -> Option<Market> {
        env.storage().instance().get(&market_key(&token_a, &token_b))
    }

    pub fn filled(env: Env, order_hash: BytesN<32>) -> i128 {
        filled(&env, &order_hash)
    }

    pub fn order_hash(env: Env, order: Order) -> BytesN<32> {
        order_hash(&env, &order)
    }

    /// Lệnh huỷ không bao giờ settle: đánh dấu đã khớp hết. Maker uỷ quyền (meta-tx qua relayer).
    pub fn cancel(env: Env, order: Order) {
        order.maker.require_auth();
        let h = order_hash(&env, &order);
        set_filled(&env, &h, order.sell_amount);
        Cancelled { maker: order.maker, order_hash: h }.publish(&env);
    }

    /// `maker_fill` = lượng `maker.sell_token` maker bán trong lần khớp này. Taker trả theo giá của maker
    /// (làm tròn lên — maker không bao giờ nhận dưới giới hạn), và phải nhận ít nhất giá của chính taker.
    pub fn settle(env: Env, maker: Order, taker: Order, maker_fill: i128) {
        // Cùng token ⇒ một lệnh có thể khớp chính nó (mh == th) và ghi đè `filled`.
        if maker.sell_token != taker.buy_token || maker.buy_token != taker.sell_token || maker.sell_token == maker.buy_token {
            panic_with_error!(&env, Error::TokenMismatch);
        }
        maker.maker.require_auth_for_args((maker.clone(),).into_val(&env));
        taker.maker.require_auth_for_args((taker.clone(),).into_val(&env));
        let now = env.ledger().timestamp();
        if now > maker.expiry || now > taker.expiry {
            panic_with_error!(&env, Error::Expired);
        }
        if maker_fill <= 0 || maker.sell_amount <= 0 || maker.buy_amount <= 0 || taker.sell_amount <= 0 || taker.buy_amount <= 0 {
            panic_with_error!(&env, Error::BadAmount);
        }
        // Tích hai lượng 18 số lẻ vượt i128 ⇒ nhân trong I256 của host.
        let w = |v: i128| I256::from_i128(&env, v);
        let taker_fill = w(maker_fill).mul(&w(maker.buy_amount)).add(&w(maker.sell_amount - 1)).div(&w(maker.sell_amount))
            .to_i128()
            .unwrap_or_else(|| panic_with_error!(&env, Error::BadAmount));
        if w(maker_fill).mul(&w(taker.sell_amount)) < w(taker_fill).mul(&w(taker.buy_amount)) {
            panic_with_error!(&env, Error::PriceLimit);
        }
        let (mh, th) = (order_hash(&env, &maker), order_hash(&env, &taker));
        let (mf, tf) = (filled(&env, &mh) + maker_fill, filled(&env, &th) + taker_fill);
        if mf > maker.sell_amount || tf > taker.sell_amount {
            panic_with_error!(&env, Error::Overfill);
        }
        set_filled(&env, &mh, mf);
        set_filled(&env, &th, tf);

        let m: Market = env
            .storage()
            .instance()
            .get(&market_key(&maker.sell_token, &maker.buy_token))
            .unwrap_or_else(|| panic_with_error!(&env, Error::UnknownMarket));
        let (mppm, tppm) = if m.fee_on { (m.maker_fee_ppm, m.taker_fee_ppm) } else { (0, 0) };
        if mppm > maker.max_fee_ppm || tppm > taker.max_fee_ppm {
            panic_with_error!(&env, Error::FeeAboveSigned);
        }
        // Phí trừ vào phần mỗi bên NHẬN.
        let maker_fee = taker_fill * mppm as i128 / PPM;
        let taker_fee = maker_fill * tppm as i128 / PPM;
        let me = env.current_contract_address();
        let fee_to: Address = env.storage().instance().get(&Key::FeeRecipient).unwrap();
        let a = SpendClient::new(&env, &maker.sell_token);
        let b = SpendClient::new(&env, &maker.buy_token);
        a.transfer_from(&me, &maker.maker, &taker.maker, &(maker_fill - taker_fee));
        b.transfer_from(&me, &taker.maker, &maker.maker, &(taker_fill - maker_fee));
        if taker_fee > 0 {
            a.transfer_from(&me, &maker.maker, &fee_to, &taker_fee);
        }
        if maker_fee > 0 {
            b.transfer_from(&me, &taker.maker, &fee_to, &maker_fee);
        }
        Settled { maker_hash: mh, taker_hash: th, maker_sold: maker_fill, taker_sold: taker_fill, maker_fee, taker_fee }
            .publish(&env);
    }
}

#[cfg(test)]
mod test;
