/// Thanh toán DEX trên Sui (R35, DEX design §5): hai lệnh ký, giá nhân chéo, `filled[hash]` không
/// overfill, phí DEX ppm theo thị trường (bật/tắt, trần 1 %, ≤ `max_fee_ppm` trong lệnh), huỷ bằng chữ
/// ký. Tiền đi account→account trong cùng tx; DEX không giữ gì. Nonce/`filled` của riêng DEX (R30).
/// Sai khác (RS7-4): lô = nhiều `settle` trong một PTB, nguyên tử cả lô; không phí relayer.
module bamboo::dex;

use bamboo::auth::{Self, Auth};
use bamboo::meta::{Self, Account, AdminCap, Root};
use std::bcs;
use std::type_name;
use sui::clock::Clock;
use sui::coin;
use sui::event;
use sui::table::{Self, Table};

const ORDER_DOMAIN: vector<u8> = b"bamboo.order.v1";
const CANCEL_DOMAIN: vector<u8> = b"bamboo.cancel.v1";
const NONCES_DOMAIN: vector<u8> = b"bamboo.nonces.v1";
const FOK: u8 = 1;
const IOC: u8 = 2;
const MAX_FEE_PPM: u32 = 10_000;
const PPM: u128 = 1_000_000;

#[error]
const ENoNetwork: vector<u8> = b"Root network is not set yet.";
#[error]
const EBadFee: vector<u8> = b"Fee above 1% or fee recipient missing.";
#[error]
const EBadOrder: vector<u8> = b"Order is not for this DEX/network or has bad flags.";
#[error]
const EExpired: vector<u8> = b"Order expired.";
#[error]
const ENonce: vector<u8> = b"Order nonce invalidated.";
#[error]
const ERelayer: vector<u8> = b"Order is bound to another relayer.";
#[error]
const ETaker: vector<u8> = b"Order is reserved for another counterparty.";
#[error]
const EBadSignature: vector<u8> = b"Order signature does not verify.";
#[error]
const EPair: vector<u8> = b"Orders do not form a pair over these coin types.";
#[error]
const EAccounts: vector<u8> = b"Accounts do not belong to the order makers.";
#[error]
const ENotListed: vector<u8> = b"Market not listed.";
#[error]
const EFill: vector<u8> = b"Fill is zero, overfills, or breaks fill-or-kill.";
#[error]
const EPrice: vector<u8> = b"Fill breaks a signed price limit.";
#[error]
const EFeeAboveSigned: vector<u8> = b"Market fee above the order's max_fee_ppm.";
#[error]
const ENonceDown: vector<u8> = b"min_nonce only increases.";

public struct Market has copy, drop, store {
    listed: bool,
    fee_on: bool,
    maker_ppm: u32,
    taker_ppm: u32,
    fee_recipient: address,
}

public struct Dex has key {
    id: UID,
    network: vector<u8>,
    filled: Table<vector<u8>, u64>,
    min_nonce: Table<address, u128>,
    markets: Table<vector<u8>, Market>,
}

/// Lệnh ký (BCS, personal-message). `sell_type`/`buy_type` = ASCII của `type_name::with_defining_ids`.
public struct Order has copy, drop {
    domain: vector<u8>,
    network: vector<u8>,
    dex: address,
    maker: address,
    taker: address,
    sell_type: vector<u8>,
    buy_type: vector<u8>,
    sell_amount: u64,
    buy_amount: u64,
    nonce: u128,
    expiry: u64,
    max_fee_ppm: u32,
    flags: u8,
    relayer: address,
}

public struct Cancel has copy, drop { domain: vector<u8>, network: vector<u8>, dex: address, order_hash: vector<u8> }

public struct InvalidateNonces has copy, drop {
    domain: vector<u8>,
    network: vector<u8>,
    dex: address,
    maker: address,
    min_nonce: u128,
}

public struct OrderFilled has copy, drop {
    ref: vector<u8>,
    order_hash: vector<u8>,
    owner: address,
    sell_type: vector<u8>,
    sold: u64,
    buy_type: vector<u8>,
    received: u64,
    dex_fee: u64,
    dex_fee_recipient: address,
    filled_total: u64,
}

public struct Matched has copy, drop { ref: vector<u8>, maker_hash: vector<u8>, taker_hash: vector<u8> }

public struct OrderCancelled has copy, drop { order_hash: vector<u8>, maker: address }

public struct NoncesInvalidated has copy, drop { maker: address, min_nonce: u128 }

public struct MarketSet has copy, drop { key: vector<u8>, market: Market }

public fun create(_: &AdminCap, root: &Root, ctx: &mut TxContext) {
    let network = meta::root_network(root);
    assert!(!network.is_empty(), ENoNetwork);
    transfer::share_object(Dex {
        id: object::new(ctx),
        network,
        filled: table::new(ctx),
        min_nonce: table::new(ctx),
        markets: table::new(ctx),
    });
}

/// Admin làm đúng một việc: niêm yết/tắt thị trường và đặt phí (DEX design RS5-1).
public fun set_market<A, B>(
    _: &AdminCap,
    dex: &mut Dex,
    listed: bool,
    fee_on: bool,
    maker_ppm: u32,
    taker_ppm: u32,
    fee_recipient: address,
) {
    assert!(maker_ppm <= MAX_FEE_PPM && taker_ppm <= MAX_FEE_PPM, EBadFee);
    if (fee_on && (maker_ppm > 0 || taker_ppm > 0)) {
        assert!(fee_recipient != @0x0 && fee_recipient != object::id_address(dex), EBadFee);
    };
    let key = market_key(type_bytes<A>(), type_bytes<B>());
    let m = Market { listed, fee_on, maker_ppm, taker_ppm, fee_recipient };
    if (dex.markets.contains(key)) *dex.markets.borrow_mut(key) = m else dex.markets.add(key, m);
    event::emit(MarketSet { key, market: m });
}

public fun new_order(
    network: vector<u8>,
    dex: address,
    maker: address,
    taker: address,
    sell_type: vector<u8>,
    buy_type: vector<u8>,
    sell_amount: u64,
    buy_amount: u64,
    nonce: u128,
    expiry: u64,
    max_fee_ppm: u32,
    flags: u8,
    relayer: address,
): Order {
    Order {
        domain: ORDER_DOMAIN, network, dex, maker, taker, sell_type, buy_type, sell_amount, buy_amount,
        nonce, expiry, max_fee_ppm, flags, relayer,
    }
}

public fun order_hash(o: &Order): vector<u8> { auth::personal_digest(bcs::to_bytes(o)) }

/// Một cặp. Maker bán A lấy B; taker bán B lấy A. Bốn account: (maker: A bán, B nhận), (taker: B bán, A nhận).
public fun settle<A, B>(
    dex: &mut Dex,
    maker_sell: &mut Account<A>,
    maker_buy: &mut Account<B>,
    taker_sell: &mut Account<B>,
    taker_buy: &mut Account<A>,
    maker: Order,
    maker_auth: Auth,
    taker: Order,
    taker_auth: Auth,
    maker_fill: u64,
    taker_fill: u64,
    ref: vector<u8>,
    clock: &Clock,
    ctx: &mut TxContext,
) {
    let (ta, tb) = (type_bytes<A>(), type_bytes<B>());
    assert!(ta != tb && maker.sell_type == ta && maker.buy_type == tb && taker.sell_type == tb && taker.buy_type == ta, EPair);
    assert!(
        meta::owner(maker_sell) == maker.maker && meta::owner(maker_buy) == maker.maker
            && meta::owner(taker_sell) == taker.maker && meta::owner(taker_buy) == taker.maker
            && maker.maker != taker.maker,
        EAccounts,
    );
    let mh = check_order(dex, &maker, &maker_auth, maker_sell, taker.maker, clock, ctx);
    let th = check_order(dex, &taker, &taker_auth, taker_sell, maker.maker, clock, ctx);
    let key = market_key(ta, tb);
    assert!(dex.markets.contains(key), ENotListed);
    let mkt = *dex.markets.borrow(key);
    assert!(mkt.listed, ENotListed);

    let m_total = fill(dex, &maker, mh, maker_fill);
    let t_total = fill(dex, &taker, th, taker_fill);
    // Giá giới hạn của CẢ HAI, nhân chéo (u64·u64 vừa u128 — không tràn).
    assert!((taker_fill as u128) * (maker.sell_amount as u128) >= (maker_fill as u128) * (maker.buy_amount as u128), EPrice);
    assert!((maker_fill as u128) * (taker.sell_amount as u128) >= (taker_fill as u128) * (taker.buy_amount as u128), EPrice);

    let (maker_ppm, taker_ppm) = if (mkt.fee_on) (mkt.maker_ppm, mkt.taker_ppm) else (0, 0);
    assert!(maker_ppm <= maker.max_fee_ppm && taker_ppm <= taker.max_fee_ppm, EFeeAboveSigned);
    // Phí tính trên phần NHẬN của bên chịu phí, làm tròn xuống.
    let taker_fee = (((maker_fill as u128) * (taker_ppm as u128)) / PPM) as u64;
    let maker_fee = (((taker_fill as u128) * (maker_ppm as u128)) / PPM) as u64;

    let mut a = meta::take(maker_sell, maker_fill);
    if (taker_fee > 0) transfer::public_transfer(coin::from_balance(a.split(taker_fee), ctx), mkt.fee_recipient);
    meta::put(taker_buy, a);
    let mut b = meta::take(taker_sell, taker_fill);
    if (maker_fee > 0) transfer::public_transfer(coin::from_balance(b.split(maker_fee), ctx), mkt.fee_recipient);
    meta::put(maker_buy, b);

    event::emit(OrderFilled {
        ref, order_hash: mh, owner: maker.maker, sell_type: ta, sold: maker_fill, buy_type: tb,
        received: taker_fill - maker_fee, dex_fee: maker_fee, dex_fee_recipient: mkt.fee_recipient,
        filled_total: m_total,
    });
    event::emit(OrderFilled {
        ref, order_hash: th, owner: taker.maker, sell_type: tb, sold: taker_fill, buy_type: ta,
        received: maker_fill - taker_fee, dex_fee: taker_fee, dex_fee_recipient: mkt.fee_recipient,
        filled_total: t_total,
    });
    event::emit(Matched { ref, maker_hash: mh, taker_hash: th });
}

/// Đóng vĩnh viễn một lệnh (chữ ký `Cancel` của maker). Chữ ký sai / đã đóng ⇒ `false`, không abort,
/// để một PTB huỷ nhiều lệnh không đổ cả lô. Không hạn (RS5-10): huỷ chỉ có lợi cho người ký.
public fun cancel<X>(dex: &mut Dex, account: &Account<X>, order: Order, a: Auth): bool {
    let h = order_hash(&order);
    if (meta::owner(account) != order.maker || order.dex != object::id_address(dex)) return false;
    let msg = Cancel { domain: CANCEL_DOMAIN, network: dex.network, dex: object::id_address(dex), order_hash: h };
    if (!meta::verify_by(account, &auth::personal_digest(bcs::to_bytes(&msg)), &a)) return false;
    let done = if (dex.filled.contains(h)) dex.filled.remove(h) else 0;
    dex.filled.add(h, order.sell_amount);
    if (done >= order.sell_amount) return false;
    event::emit(OrderCancelled { order_hash: h, maker: order.maker });
    true
}

/// Vô hiệu mọi lệnh `nonce < min_nonce` của maker. Tăng nghiêm ngặt ⇒ phát lại vô hại.
public fun invalidate_nonces<X>(dex: &mut Dex, account: &Account<X>, min_nonce: u128, a: Auth) {
    let maker = meta::owner(account);
    let msg = InvalidateNonces {
        domain: NONCES_DOMAIN, network: dex.network, dex: object::id_address(dex), maker, min_nonce,
    };
    assert!(meta::verify_by(account, &auth::personal_digest(bcs::to_bytes(&msg)), &a), EBadSignature);
    let cur = if (dex.min_nonce.contains(maker)) dex.min_nonce.remove(maker) else 0;
    assert!(min_nonce > cur, ENonceDown);
    dex.min_nonce.add(maker, min_nonce);
    event::emit(NoncesInvalidated { maker, min_nonce });
}

public fun filled(dex: &Dex, h: vector<u8>): u64 { if (dex.filled.contains(h)) *dex.filled.borrow(h) else 0 }

public fun type_bytes<T>(): vector<u8> { type_name::with_defining_ids<T>().into_string().into_bytes() }

fun check_order<X>(
    dex: &Dex,
    o: &Order,
    a: &Auth,
    signer_account: &Account<X>,
    counterparty: address,
    clock: &Clock,
    ctx: &TxContext,
): vector<u8> {
    assert!(
        o.domain == ORDER_DOMAIN && o.network == dex.network && o.dex == object::id_address(dex)
            && o.flags & 0xfc == 0 && o.flags != FOK | IOC,
        EBadOrder,
    );
    assert!(clock.timestamp_ms() / 1000 <= o.expiry, EExpired);
    let min = if (dex.min_nonce.contains(o.maker)) *dex.min_nonce.borrow(o.maker) else 0;
    assert!(o.nonce >= min, ENonce);
    assert!(o.relayer == @0x0 || o.relayer == ctx.sender(), ERelayer);
    assert!(o.taker == @0x0 || o.taker == counterparty, ETaker);
    let h = order_hash(o);
    assert!(meta::verify_by(signer_account, &h, a), EBadSignature);
    h
}

/// Ghi `filled` (không bao giờ vượt `sell_amount`); FOK = một lần đủ; IOC đóng phần còn lại.
fun fill(dex: &mut Dex, o: &Order, h: vector<u8>, amount: u64): u64 {
    let before = if (dex.filled.contains(h)) dex.filled.remove(h) else 0;
    assert!(amount > 0 && before + amount <= o.sell_amount, EFill);
    if (o.flags & FOK != 0) assert!(before == 0 && amount == o.sell_amount, EFill);
    let total = before + amount;
    dex.filled.add(h, if (o.flags & IOC != 0) o.sell_amount else total);
    total
}

fun market_key(a: vector<u8>, b: vector<u8>): vector<u8> {
    let (mut lo, hi) = if (less(&a, &b)) (a, b) else (b, a);
    lo.push_back(0);
    lo.append(hi);
    lo
}

fun less(a: &vector<u8>, b: &vector<u8>): bool {
    let (n, m) = (a.length(), b.length());
    let mut i = 0;
    while (i < n && i < m) {
        if (a[i] != b[i]) return a[i] < b[i];
        i = i + 1;
    };
    n < m
}
