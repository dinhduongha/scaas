//! DEX thanh toán hai chân (R35, R65): mỗi lệnh được maker uỷ quyền bằng `require_auth_for_args((order,))` — auth
//! entry gốc của Soroban (nonce ngẫu nhiên, hạn ledger, network id) thay cho chữ ký EIP-712. Token đi bằng
//! `transfer_from` với DEX là spender (allowance chỉ cho contract — R26).
//!
//! Lệch EVM (R8-3): một auth entry = một lần settle (host tiêu nonce); lệnh khớp một phần cần maker ký lại phần
//! còn lại, `filled[order_hash]` (hash không chứa nonce) chặn overfill giữa các bản ký lại. (R8-4) Không gom
//! nhiều cặp một tx: lỗi một cặp hoàn tác cả tx Soroban.
//!
//! UA legs (spec §5.3, SOR-D10): an order's `maker` and `destination` are `Holder`s and it names its `relayer`
//! (NET-SOR-10), whose authority every `settle` needs. A UA maker's leg is pulled by the sell token's `ua_trade` over the
//! UA's signature of the `ua_trade` digest; that signature is not consumed, so it fills partially without re-signing,
//! bounded by `filled[order_hash]` here and by the token's own `UaPulled`. Every leg is pulled into the DEX, then paid
//! to the other order's `destination` (`transfer`, or `transfer_to_ua` for a UA) and the fee recipient.
#![no_std]
/// The order and holder types of the DEX's interface.
pub use scaas_ua_common::{Holder, Order};
use scaas_ua_common::{op_digest, UaRegistryClient, PURPOSE_TRADE};
use soroban_sdk::{
    contract, contractclient, contracterror, contractevent, contractimpl, contracttype, panic_with_error,
    xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, I256,
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
    /// A native leg with a non-empty `auth`, or a cancel entry for the other holder kind (`cancel` of a UA order,
    /// `ua_cancel` of a native one).
    BadAuth = 9,
    /// `ua_cancel` and no registry bound at construction.
    UaLedgerOff = 10,
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
    /// Instance: `Option<Address>`, the registry `ua_cancel` verifies a UA through.
    Registry,
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
    pub maker: Holder,
    pub order_hash: BytesN<32>,
}

/// The part of `scaas-token` the DEX calls.
#[contractclient(name = "DexTokenClient")]
pub trait DexToken {
    fn transfer_from(env: Env, spender: Address, from: Address, to: Address, amount: i128);
    fn transfer(env: Env, from: Address, to: Address, amount: i128);
    fn transfer_to_ua(env: Env, from: Address, to: BytesN<32>, amount: i128);
    fn ua_trade(env: Env, dex: Address, order: Order, auth: Bytes, amount: i128);
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

/// A native maker signs its order by host auth and carries no `auth`; a UA maker's `auth` is checked by the sell token
/// (`ua_trade`) when its leg is pulled.
fn authorize(env: &Env, o: &Order, auth: &Bytes) {
    if let Holder::Addr(a) = &o.maker {
        if !auth.is_empty() {
            panic_with_error!(env, Error::BadAuth);
        }
        a.require_auth_for_args((o.clone(),).into_val(env));
    }
}

/// `amount` of `o.sell_token` from its maker into the DEX.
fn pull(env: &Env, o: &Order, auth: &Bytes, amount: i128) {
    let (t, me) = (DexTokenClient::new(env, &o.sell_token), env.current_contract_address());
    match &o.maker {
        Holder::Addr(a) => t.transfer_from(&me, a, &me, &amount),
        Holder::Ua(_) => t.ua_trade(&me, o, auth, &amount),
    }
}

/// `amount` of `token` from the DEX to `to`.
fn pay(env: &Env, token: &Address, to: &Holder, amount: i128) {
    let (t, me) = (DexTokenClient::new(env, token), env.current_contract_address());
    match to {
        Holder::Addr(a) => t.transfer(&me, a, &amount),
        Holder::Ua(u) => t.transfer_to_ua(&me, u, &amount),
    }
}

fn cancelled(env: &Env, order: Order) {
    let h = order_hash(env, &order);
    set_filled(env, &h, order.sell_amount);
    Cancelled { maker: order.maker, order_hash: h }.publish(env);
}

#[contract]
pub struct Dex;

#[contractimpl]
impl Dex {
    pub fn __constructor(env: Env, admin: Address, fee_recipient: Address, registry: Option<Address>) {
        env.storage().instance().set(&Key::Admin, &admin);
        env.storage().instance().set(&Key::FeeRecipient, &fee_recipient);
        env.storage().instance().set(&Key::Registry, &registry);
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

    /// Lệnh huỷ không bao giờ settle: đánh dấu đã khớp hết. Maker uỷ quyền (meta-tx qua relayer). A native maker only.
    pub fn cancel(env: Env, order: Order) {
        let Holder::Addr(a) = &order.maker else { panic_with_error!(&env, Error::BadAuth) };
        a.require_auth();
        cancelled(&env, order);
    }

    /// `cancel` for a UA maker (SOR-D10): its signature over `op_digest(dex, "ua_cancel", (order,))`, purpose `trade`,
    /// through the registry bound at construction.
    pub fn ua_cancel(env: Env, order: Order, auth: Bytes) {
        let Holder::Ua(ua) = &order.maker else { panic_with_error!(&env, Error::BadAuth) };
        let reg = match env.storage().instance().get::<_, Option<Address>>(&Key::Registry).flatten() {
            Some(r) => UaRegistryClient::new(&env, &r),
            None => panic_with_error!(&env, Error::UaLedgerOff),
        };
        let digest = op_digest(&env, &env.current_contract_address(), "ua_cancel", (order.clone(),).into_val(&env));
        reg.require_authorized(ua, &BytesN::from_array(&env, &PURPOSE_TRADE), &digest, &auth);
        cancelled(&env, order);
    }

    /// `maker_fill` = lượng `maker.sell_token` maker bán trong lần khớp này. Taker trả theo giá của maker
    /// (làm tròn lên — maker không bao giờ nhận dưới giới hạn), và phải nhận ít nhất giá của chính taker.
    /// `maker_auth` / `taker_auth`: a UA maker's order signature, empty for a native maker (`BadAuth`).
    pub fn settle(env: Env, maker: Order, taker: Order, maker_fill: i128, maker_auth: Bytes, taker_auth: Bytes) {
        // Cùng token ⇒ một lệnh có thể khớp chính nó (mh == th) và ghi đè `filled`.
        if maker.sell_token != taker.buy_token || maker.buy_token != taker.sell_token || maker.sell_token == maker.buy_token {
            panic_with_error!(&env, Error::TokenMismatch);
        }
        // NET-SOR-10: each order's relayer submits it (once when both name the same one).
        maker.relayer.require_auth();
        if taker.relayer != maker.relayer {
            taker.relayer.require_auth();
        }
        authorize(&env, &maker, &maker_auth);
        authorize(&env, &taker, &taker_auth);
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
        let fee_to = Holder::Addr(env.storage().instance().get(&Key::FeeRecipient).unwrap());
        pull(&env, &maker, &maker_auth, maker_fill);
        pull(&env, &taker, &taker_auth, taker_fill);
        pay(&env, &maker.sell_token, &taker.destination, maker_fill - taker_fee);
        pay(&env, &maker.buy_token, &maker.destination, taker_fill - maker_fee);
        if taker_fee > 0 {
            pay(&env, &maker.sell_token, &fee_to, taker_fee);
        }
        if maker_fee > 0 {
            pay(&env, &maker.buy_token, &fee_to, maker_fee);
        }
        Settled { maker_hash: mh, taker_hash: th, maker_sold: maker_fill, taker_sold: taker_fill, maker_fee, taker_fee }
            .publish(&env);
    }
}

#[cfg(test)]
mod test;
