/// Thanh toán DEX trên Aptos (R35, DEX design, spec §5.3, RS11-10): hai lệnh ký, giá nhân chéo trên u128,
/// `filled[hash]` không overfill, phí DEX ppm theo market (bật/tắt, trần 1 %, ≤ `max_fee_ppm` trong lệnh), huỷ bằng chữ
/// ký. Tiền đi Account→Account (primary store → primary store) trong cùng tx; DEX không giữ gì giữa các tx.
/// Mỗi cặp là MỘT `Market` (named object derived từ `Dex` theo cặp — L8): settle/huỷ/`min_nonce` của market này không
/// chạm state của market khác. Lệch so với EVM: entry function không nhận struct ⇒ lệnh đi dạng BCS và một cặp mỗi tx
/// (lô = nhiều tx trên nhiều lane, nguyên tử từng cặp); không phí relayer; IOC đóng phần còn lại trong `settle`.
module scaas::dex {
    use std::bcs;
    use std::hash::sha3_256;
    use std::signer;
    use aptos_std::bcs_stream;
    use aptos_std::table::{Self, Table};
    use aptos_framework::chain_id;
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::{Self, ExtendRef};
    use aptos_framework::primary_fungible_store;
    use aptos_framework::timestamp;
    use scaas::meta;

    const ORDER_DOMAIN: vector<u8> = b"scaas.order.v1";
    const CANCEL_DOMAIN: vector<u8> = b"scaas.cancel.v1";
    const NONCES_DOMAIN: vector<u8> = b"scaas.nonces.v1";
    const FOK: u8 = 1;
    const IOC: u8 = 2;
    const MAX_FEE_PPM: u32 = 10_000;
    const PPM: u128 = 1_000_000;

    /// Phí trên 1 % hoặc thiếu người nhận phí.
    const EBAD_FEE: u64 = 1;
    /// Lệnh không thuộc market/mạng này, hoặc cờ sai, hoặc bytes không chuẩn.
    const EBAD_ORDER: u64 = 2;
    /// Lệnh hết hạn.
    const EEXPIRED: u64 = 3;
    /// Nonce lệnh đã bị vô hiệu.
    const ENONCE: u64 = 4;
    /// Lệnh gắn với relayer khác.
    const ERELAYER: u64 = 5;
    /// Lệnh dành cho đối tác khác.
    const ETAKER: u64 = 6;
    /// Chữ ký lệnh không hợp lệ.
    const EBAD_SIGNATURE: u64 = 7;
    /// Hai lệnh không tạo thành cặp của market này.
    const EPAIR: u64 = 8;
    /// Market chưa niêm yết.
    const ENOT_LISTED: u64 = 9;
    /// Lượng khớp bằng 0, vượt lệnh, hoặc phạm fill-or-kill.
    const EFILL: u64 = 10;
    /// Khớp phạm giá giới hạn đã ký.
    const EPRICE: u64 = 11;
    /// Phí market cao hơn `max_fee_ppm` của lệnh.
    const EFEE_ABOVE_SIGNED: u64 = 12;
    /// `min_nonce` chỉ tăng.
    const ENONCE_DOWN: u64 = 13;
    /// Market không có người nhận phí để `sweep` tới.
    const ENO_RECIPIENT: u64 = 14;
    /// `admin_sweep` chỉ gom từ Root, Dex hoặc một Market.
    const ENOT_HOLDER: u64 = 15;

    struct Dex has key {
        extend: ExtendRef,
    }

    struct Fees has copy, drop, store {
        listed: bool,
        fee_on: bool,
        maker_ppm: u32,
        taker_ppm: u32,
        fee_recipient: address,
    }

    /// `a < b` (so byte của địa chỉ metadata).
    struct Market has key {
        a: address,
        b: address,
        fees: Fees,
        filled: Table<vector<u8>, u64>,
        min_nonce: Table<address, u128>,
        extend: ExtendRef,
    }

    /// Lệnh ký (BCS). Hash = `sha3_256(bcs(Order))`, ký qua phong bì với nhãn `scaas.order.v1` (hoặc challenge
    /// passkey = hash).
    struct Order has copy, drop {
        domain: vector<u8>,
        chain_id: u8,
        market: address,
        maker: address,
        taker: address,
        sell: address,
        buy: address,
        sell_amount: u64,
        buy_amount: u64,
        nonce: u128,
        expiry: u64,
        max_fee_ppm: u32,
        flags: u8,
        relayer: address,
    }

    struct Cancel has copy, drop { domain: vector<u8>, chain_id: u8, market: address, order_hash: vector<u8> }

    /// `min_nonce` theo (maker, market).
    struct InvalidateNonces has copy, drop {
        domain: vector<u8>,
        chain_id: u8,
        market: address,
        maker: address,
        min_nonce: u128,
    }

    #[event]
    struct OrderFilled has drop, store {
        market: address,
        ref: vector<u8>,
        order_hash: vector<u8>,
        owner: address,
        sell: address,
        sold: u64,
        buy: address,
        received: u64,
        dex_fee: u64,
        dex_fee_recipient: address,
        filled_total: u64,
    }

    #[event]
    struct Matched has drop, store { market: address, ref: vector<u8>, maker_hash: vector<u8>, taker_hash: vector<u8> }

    #[event]
    struct OrderCancelled has drop, store { market: address, order_hash: vector<u8>, maker: address }

    #[event]
    struct NoncesInvalidated has drop, store { market: address, maker: address, min_nonce: u128 }

    #[event]
    struct MarketSet has drop, store { market: address, a: address, b: address, fees: Fees }

    #[view]
    public fun dex_address(): address { object::create_object_address(&meta::root(), b"dex") }

    #[view]
    public fun market_of(x: address, y: address): address {
        object::create_object_address(&dex_address(), market_seed(x, y))
    }

    fun market_seed(x: address, y: address): vector<u8> {
        let (bx, by) = (bcs::to_bytes(&x), bcs::to_bytes(&y));
        let seed = b"mkt";
        if (less(&bx, &by)) {
            seed.append(bx);
            seed.append(by);
        } else {
            seed.append(by);
            seed.append(bx);
        };
        seed
    }

    public entry fun create_dex(admin: &signer) {
        meta::assert_admin(admin);
        let c = object::create_named_object(&meta::root_signer(), b"dex");
        move_to(&object::generate_signer(&c), Dex { extend: object::generate_extend_ref(&c) });
    }

    /// Mở market cho cặp {x, y} (một lần — lần hai chain từ chối). Admin chỉ niêm yết/tắt và đặt phí.
    public entry fun list_market(
        admin: &signer,
        x: address,
        y: address,
        listed: bool,
        fee_on: bool,
        maker_ppm: u32,
        taker_ppm: u32,
        fee_recipient: address,
    ) {
        meta::assert_admin(admin);
        assert!(x != y, EPAIR);
        let (bx, by) = (bcs::to_bytes(&x), bcs::to_bytes(&y));
        let (a, b) = if (less(&bx, &by)) (x, y) else (y, x);
        let dex_signer = object::generate_signer_for_extending(&Dex[dex_address()].extend);
        let c = object::create_named_object(&dex_signer, market_seed(x, y));
        let s = object::generate_signer(&c);
        let fees = Fees { listed: false, fee_on: false, maker_ppm: 0, taker_ppm: 0, fee_recipient: @0x0 };
        move_to(&s, Market {
            a, b, fees, filled: table::new(), min_nonce: table::new(), extend: object::generate_extend_ref(&c),
        });
        set_market(admin, signer::address_of(&s), listed, fee_on, maker_ppm, taker_ppm, fee_recipient);
    }

    public entry fun set_market(
        admin: &signer,
        market: address,
        listed: bool,
        fee_on: bool,
        maker_ppm: u32,
        taker_ppm: u32,
        fee_recipient: address,
    ) {
        meta::assert_admin(admin);
        assert!(maker_ppm <= MAX_FEE_PPM && taker_ppm <= MAX_FEE_PPM, EBAD_FEE);
        if (fee_on && (maker_ppm > 0 || taker_ppm > 0)) {
            assert!(fee_recipient != @0x0 && fee_recipient != market, EBAD_FEE);
        };
        let m = &mut Market[market];
        m.fees = Fees { listed, fee_on, maker_ppm, taker_ppm, fee_recipient };
        event::emit(MarketSet { market, a: m.a, b: m.b, fees: m.fees });
    }

    /// Một cặp. Maker bán `maker.sell` lấy `maker.buy`; taker ngược lại. Tiền chảy giữa Account của hai bên.
    package entry fun settle(
        lane: &signer,
        market: address,
        maker_order: vector<u8>,
        maker_pk: vector<u8>,
        maker_sig: vector<u8>,
        maker_env: vector<u8>,
        taker_order: vector<u8>,
        taker_pk: vector<u8>,
        taker_sig: vector<u8>,
        taker_env: vector<u8>,
        maker_fill: u64,
        taker_fill: u64,
        ref: vector<u8>,
    ) {
        let maker = parse_order(&maker_order);
        let taker = parse_order(&taker_order);
        let m = &mut Market[market];
        assert!(
            maker.sell != maker.buy && maker.sell == taker.buy && maker.buy == taker.sell
                && ((maker.sell == m.a && maker.buy == m.b) || (maker.sell == m.b && maker.buy == m.a)),
            EPAIR,
        );
        assert!(maker.maker != taker.maker, EPAIR);
        let fees = m.fees;
        assert!(fees.listed, ENOT_LISTED);
        let mh = check_order(m, market, &maker, &maker_order, &maker_pk, &maker_sig, &maker_env, taker.maker, lane);
        let th = check_order(m, market, &taker, &taker_order, &taker_pk, &taker_sig, &taker_env, maker.maker, lane);
        let m_total = fill(m, &maker, mh, maker_fill);
        let t_total = fill(m, &taker, th, taker_fill);
        // Giá giới hạn của CẢ HAI, nhân chéo (u64·u64 vừa u128).
        assert!((taker_fill as u128) * (maker.sell_amount as u128) >= (maker_fill as u128) * (maker.buy_amount as u128), EPRICE);
        assert!((maker_fill as u128) * (taker.sell_amount as u128) >= (taker_fill as u128) * (taker.buy_amount as u128), EPRICE);
        let (maker_ppm, taker_ppm) = if (fees.fee_on) (fees.maker_ppm, fees.taker_ppm) else (0, 0);
        assert!(maker_ppm <= maker.max_fee_ppm && taker_ppm <= taker.max_fee_ppm, EFEE_ABOVE_SIGNED);
        // Phí tính trên phần NHẬN của bên chịu phí, làm tròn xuống.
        let taker_fee = (((maker_fill as u128) * (taker_ppm as u128)) / PPM) as u64;
        let maker_fee = (((taker_fill as u128) * (maker_ppm as u128)) / PPM) as u64;
        let (maker_acct, taker_acct) = (meta::account_of(maker.maker), meta::account_of(taker.maker));
        let (sell_m, sell_t) = (object::address_to_object<Metadata>(maker.sell), object::address_to_object<Metadata>(taker.sell));
        let ms = meta::signer_of(maker_acct);
        primary_fungible_store::transfer(&ms, sell_m, taker_acct, maker_fill - taker_fee);
        if (taker_fee > 0) primary_fungible_store::transfer(&ms, sell_m, fees.fee_recipient, taker_fee);
        let ts = meta::signer_of(taker_acct);
        primary_fungible_store::transfer(&ts, sell_t, maker_acct, taker_fill - maker_fee);
        if (maker_fee > 0) primary_fungible_store::transfer(&ts, sell_t, fees.fee_recipient, maker_fee);
        event::emit(OrderFilled {
            market, ref, order_hash: mh, owner: maker.maker, sell: maker.sell, sold: maker_fill, buy: maker.buy,
            received: taker_fill - maker_fee, dex_fee: maker_fee, dex_fee_recipient: fees.fee_recipient,
            filled_total: m_total,
        });
        event::emit(OrderFilled {
            market, ref, order_hash: th, owner: taker.maker, sell: taker.sell, sold: taker_fill, buy: taker.buy,
            received: maker_fill - taker_fee, dex_fee: taker_fee, dex_fee_recipient: fees.fee_recipient,
            filled_total: t_total,
        });
        event::emit(Matched { market, ref, maker_hash: mh, taker_hash: th });
    }

    /// Đóng vĩnh viễn một lệnh bằng chữ ký `Cancel` của một khoá Account của maker (ai nộp cũng được). Không hạn
    /// (RS5-10): huỷ chỉ có lợi cho người ký. Đã đóng ⇒ không làm gì.
    package entry fun cancel_signed(market: address, order: vector<u8>, pk: vector<u8>, sig: vector<u8>, env: vector<u8>) {
        cancel(market, order, pk, sig, env);
    }

    /// `cancel_signed`'s body: `false` = the order was already closed and nothing changed (`relayfee` pays nothing
    /// for that, CTR-MTX-27).
    package fun cancel(market: address, order: vector<u8>, pk: vector<u8>, sig: vector<u8>, env: vector<u8>): bool {
        let o = parse_order(&order);
        assert!(o.market == market, EBAD_ORDER);
        let h = sha3_256(order);
        let msg = Cancel { domain: CANCEL_DOMAIN, chain_id: chain_id::get(), market, order_hash: h };
        let d = sha3_256(bcs::to_bytes(&msg));
        assert!(meta::verify_signed(meta::account_of(o.maker), &pk, CANCEL_DOMAIN, &d, &sig, &env), EBAD_SIGNATURE);
        let m = &mut Market[market];
        let done = *m.filled.borrow_with_default(h, &0);
        if (done >= o.sell_amount) return false;
        m.filled.upsert(h, o.sell_amount);
        event::emit(OrderCancelled { market, order_hash: h, maker: o.maker });
        true
    }

    /// Vô hiệu mọi lệnh `nonce < min_nonce` của maker trên market NÀY. Tăng nghiêm ngặt ⇒ phát lại vô hại.
    package entry fun invalidate_nonces_signed(
        market: address,
        maker: address,
        min_nonce: u128,
        pk: vector<u8>,
        sig: vector<u8>,
        env: vector<u8>,
    ) {
        let msg = InvalidateNonces { domain: NONCES_DOMAIN, chain_id: chain_id::get(), market, maker, min_nonce };
        let d = sha3_256(bcs::to_bytes(&msg));
        assert!(meta::verify_signed(meta::account_of(maker), &pk, NONCES_DOMAIN, &d, &sig, &env), EBAD_SIGNATURE);
        let m = &mut Market[market];
        assert!(min_nonce > *m.min_nonce.borrow_with_default(maker, &0), ENONCE_DOWN);
        m.min_nonce.upsert(maker, min_nonce);
        event::emit(NoncesInvalidated { market, maker, min_nonce });
    }

    /// Không cần quyền (L7): market không giữ tiền giữa các tx; FA ai gửi nhầm vào market ⇒ người nhận phí.
    public entry fun sweep(market: address, asset: address) {
        let m = &Market[market];
        assert!(m.fees.fee_recipient != @0x0, ENO_RECIPIENT);
        let meta_obj = object::address_to_object<Metadata>(asset);
        let bal = primary_fungible_store::balance(market, meta_obj);
        if (bal > 0) {
            primary_fungible_store::transfer(&object::generate_signer_for_extending(&m.extend), meta_obj,
                m.fees.fee_recipient, bal);
        }
    }

    /// Review L6: FA gửi nhầm tới Root (`meta::root()`), Dex (`dex_address()`) hoặc một Market (kể cả market chưa có
    /// người nhận phí) ⇒ admin gom về `to`. Không bao giờ chạm Account/Mandate (tiền của người dùng).
    public entry fun admin_sweep(admin: &signer, holder: address, asset: address, to: address) {
        meta::assert_admin(admin);
        let s = if (holder == meta::root()) meta::root_signer()
            else if (holder == dex_address()) object::generate_signer_for_extending(&Dex[holder].extend)
            else {
                assert!(exists<Market>(holder), ENOT_HOLDER);
                object::generate_signer_for_extending(&Market[holder].extend)
            };
        let a = object::address_to_object<Metadata>(asset);
        let bal = primary_fungible_store::balance(holder, a);
        if (bal > 0) primary_fungible_store::transfer(&s, a, to, bal);
    }

    #[view]
    public fun filled(market: address, order_hash: vector<u8>): u64 {
        *Market[market].filled.borrow_with_default(order_hash, &0)
    }

    #[view]
    public fun min_nonce(market: address, maker: address): u128 {
        *Market[market].min_nonce.borrow_with_default(maker, &0)
    }

    /// BCS chặt: hết bytes, và mã hoá lại ra đúng bytes (một lệnh, một hash).
    fun parse_order(b: &vector<u8>): Order {
        let s = bcs_stream::new(*b);
        let o = Order {
            domain: bcs_stream::deserialize_vector(&mut s, |x| bcs_stream::deserialize_u8(x)),
            chain_id: bcs_stream::deserialize_u8(&mut s),
            market: bcs_stream::deserialize_address(&mut s),
            maker: bcs_stream::deserialize_address(&mut s),
            taker: bcs_stream::deserialize_address(&mut s),
            sell: bcs_stream::deserialize_address(&mut s),
            buy: bcs_stream::deserialize_address(&mut s),
            sell_amount: bcs_stream::deserialize_u64(&mut s),
            buy_amount: bcs_stream::deserialize_u64(&mut s),
            nonce: bcs_stream::deserialize_u128(&mut s),
            expiry: bcs_stream::deserialize_u64(&mut s),
            max_fee_ppm: bcs_stream::deserialize_u32(&mut s),
            flags: bcs_stream::deserialize_u8(&mut s),
            relayer: bcs_stream::deserialize_address(&mut s),
        };
        assert!(!bcs_stream::has_remaining(&mut s) && bcs::to_bytes(&o) == *b, EBAD_ORDER);
        o
    }

    fun check_order(
        m: &Market,
        market: address,
        o: &Order,
        bytes: &vector<u8>,
        pk: &vector<u8>,
        sig: &vector<u8>,
        env: &vector<u8>,
        counterparty: address,
        lane: &signer,
    ): vector<u8> {
        assert!(
            o.domain == ORDER_DOMAIN && o.chain_id == chain_id::get() && o.market == market && o.flags & 0xfc == 0
                && o.flags != FOK | IOC,
            EBAD_ORDER,
        );
        assert!(timestamp::now_seconds() <= o.expiry, EEXPIRED);
        assert!(o.nonce >= *m.min_nonce.borrow_with_default(o.maker, &0), ENONCE);
        assert!(o.relayer == @0x0 || o.relayer == signer::address_of(lane), ERELAYER);
        assert!(o.taker == @0x0 || o.taker == counterparty, ETAKER);
        let h = sha3_256(*bytes);
        assert!(meta::verify_signed(meta::account_of(o.maker), pk, ORDER_DOMAIN, &h, sig, env), EBAD_SIGNATURE);
        h
    }

    /// Ghi `filled` (không bao giờ vượt `sell_amount`); FOK = một lần đủ; IOC đóng phần còn lại.
    fun fill(m: &mut Market, o: &Order, h: vector<u8>, amount: u64): u64 {
        let before = *m.filled.borrow_with_default(h, &0);
        assert!(amount > 0 && amount <= o.sell_amount - before, EFILL);
        if (o.flags & FOK != 0) assert!(before == 0 && amount == o.sell_amount, EFILL);
        let total = before + amount;
        m.filled.upsert(h, if (o.flags & IOC != 0) o.sell_amount else total);
        total
    }

    fun less(a: &vector<u8>, b: &vector<u8>): bool {
        let (n, i) = (a.length(), 0);
        while (i < n) {
            if (a[i] != b[i]) return a[i] < b[i];
            i += 1;
        };
        false
    }
}
