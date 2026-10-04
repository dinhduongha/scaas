#[test_only]
module bamboo::dex_tests {
    use std::hash::sha3_256;
    use aptos_framework::account;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::Object;
    use bamboo::dex;
    use bamboo::fixtures::{Self as fx, bal};
    use bamboo::meta;
    use bamboo::vectors as v;

    const FEE: address = @0xfee;
    const REF: vector<u8> = b"ref-1";

    // alice: 1000 EUR, carol: 1000 USD, market EUR/USD niêm yết, phí tắt.
    fun ready(f: &signer, b: &signer): (Object<Metadata>, Object<Metadata>) {
        fx::setup(f, b);
        let (e, u) = (fx::asset(b"EUR"), fx::asset(b"USD"));
        meta::open(v::alice(), v::alice_pk());
        meta::open(v::carol(), v::carol_pk());
        fx::mint(e, v::a_account(), 1000);
        fx::mint(u, v::c_account(), 1000);
        dex::create_dex(b);
        dex::list_market(b, v::eur(), v::usd(), true, false, 0, 0, @0x0);
        assert!(dex::market_of(v::usd(), v::eur()) == v::market() && dex::dex_address() == v::dex(), 0);
        (e, u)
    }

    fun go(
        lane: &signer,
        market: address,
        m: vector<vector<u8>>,
        t: vector<vector<u8>>,
        maker_fill: u64,
        taker_fill: u64,
    ) {
        dex::settle(lane, market, m[0], m[1], m[2], m[3], t[0], t[1], t[2], t[3], maker_fill, taker_fill, REF);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun settles_account_to_account(f: signer, b: signer, lane: signer) {
        let (e, u) = ready(&f, &b);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 100, 200);
        assert!(bal(e, v::a_account()) == 900 && bal(u, v::a_account()) == 200, 0);
        assert!(bal(e, v::c_account()) == 100 && bal(u, v::c_account()) == 800, 1);
        assert!(dex::filled(v::market(), v::o_alice_sell_eur_hash()) == 100, 2);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun partial_fills_add_up(f: signer, b: signer, lane: signer) {
        let (e, _) = ready(&f, &b);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 50, 100);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 50, 100);
        assert!(bal(e, v::c_account()) == 100, 0);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 10, location = bamboo::dex)]
    fun no_overfill(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 100, 200);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_big(), 1, 2);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 11, location = bamboo::dex)]
    fun signed_price_limit_holds(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd_cheap(), 100, 100);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 10, location = bamboo::dex)]
    fun fill_or_kill_is_all_or_nothing(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        go(&lane, v::market(), v::o_alice_fok(), v::o_carol_big(), 50, 100);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun immediate_or_cancel_closes_the_rest(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        go(&lane, v::market(), v::o_alice_ioc(), v::o_carol_big(), 50, 100);
        assert!(dex::filled(v::market(), sha3_256(v::o_alice_ioc()[0])) == 100, 0);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun tiny_fees_round_down_to_zero(f: signer, b: signer, lane: signer) {
        let (e, u) = ready(&f, &b);
        dex::set_market(&b, v::market(), true, true, 1000, 2000, FEE);   // maker 0.1 %, taker 0.2 %
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_big(), 100, 200);
        // taker (carol) pays 0.2 % of the 100 EUR she receives; maker (alice) 0.1 % of 200 USD
        assert!(bal(e, v::c_account()) == 100 && bal(e, FEE) == 0, 0);
        assert!(bal(u, v::a_account()) == 200 && bal(u, FEE) == 0, 1);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun fees_go_to_the_recipient(f: signer, b: signer, lane: signer) {
        let (e, u) = ready(&f, &b);
        dex::set_market(&b, v::market(), true, true, 10_000, 10_000, FEE);   // 1 % both
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_big(), 100, 200);
        assert!(bal(e, FEE) == 1 && bal(e, v::c_account()) == 99, 0);
        assert!(bal(u, FEE) == 2 && bal(u, v::a_account()) == 198, 1);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 12, location = bamboo::dex)]
    fun fee_above_the_signed_maximum(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        dex::set_market(&b, v::market(), true, true, 1, 0, FEE);
        go(&lane, v::market(), v::o_alice_nofee(), v::o_carol_sell_usd(), 100, 200);
    }

    #[test(f = @aptos_framework, b = @bamboo)]
    #[expected_failure(abort_code = 1, location = bamboo::dex)]
    fun fee_cap_is_one_percent(f: signer, b: signer) {
        ready(&f, &b);
        dex::set_market(&b, v::market(), true, true, 10_001, 0, FEE);
    }

    #[test(f = @aptos_framework, b = @bamboo)]
    #[expected_failure(abort_code = 15, location = bamboo::meta)]
    fun only_the_admin_sets_markets(f: signer, b: signer) {
        ready(&f, &b);
        dex::set_market(&account::create_signer_for_test(@0x5ee1), v::market(), true, false, 0, 0, @0x0);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 9, location = bamboo::dex)]
    fun unlisted_market(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        dex::set_market(&b, v::market(), false, false, 0, 0, @0x0);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 100, 200);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 7, location = bamboo::dex)]
    fun order_signed_by_a_foreign_key(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        go(&lane, v::market(), v::o_alice_by_mallory(), v::o_carol_sell_usd(), 100, 200);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 10, location = bamboo::dex)]
    fun cancelled_order_never_settles(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        v::cancel_o_alice_sell_eur();
        assert!(dex::filled(v::market(), v::o_alice_sell_eur_hash()) == 100, 0);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 100, 200);
    }

    // min_nonce theo (maker, market): vô hiệu ở EUR/USD không đụng lệnh cùng nonce ở EUR/GBP.
    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun min_nonce_is_per_market(f: signer, b: signer, lane: signer) {
        let (e, _) = ready(&f, &b);
        let g = fx::asset(b"GBP");
        fx::mint(g, v::c_account(), 1000);
        dex::list_market(&b, v::gbp(), v::eur(), true, false, 0, 0, @0x0);
        assert!(dex::market_of(v::eur(), v::gbp()) == v::market2(), 0);
        v::alice_min_nonce_2();
        assert!(dex::min_nonce(v::market(), v::alice()) == 2 && dex::min_nonce(v::market2(), v::alice()) == 0, 1);
        go(&lane, v::market2(), v::o2_alice_sell_eur(), v::o2_carol_sell_gbp(), 100, 200);
        assert!(bal(e, v::c_account()) == 100 && bal(g, v::a_account()) == 200, 2);
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 4, location = bamboo::dex)]
    fun invalidated_nonce_does_not_settle(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        v::alice_min_nonce_2();
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_carol_sell_usd(), 100, 200);
    }

    #[test(f = @aptos_framework, b = @bamboo)]
    #[expected_failure(abort_code = 13, location = bamboo::dex)]
    fun min_nonce_only_increases(f: signer, b: signer) {
        ready(&f, &b);
        v::alice_min_nonce_2();
        v::alice_min_nonce_2();
    }

    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    #[expected_failure(abort_code = 8, location = bamboo::dex)]
    fun orders_of_another_market_do_not_pair(f: signer, b: signer, lane: signer) {
        ready(&f, &b);
        go(&lane, v::market(), v::o2_alice_sell_eur(), v::o_carol_sell_usd(), 100, 200);
    }

    // Passkey (WebAuthn P-256 trong Move) ký lệnh DEX trước — account dave mở lười bằng một pay.
    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun passkey_signed_order_settles(f: signer, b: signer, lane: signer) {
        let (e, u) = ready(&f, &b);
        fx::mint(e, v::d_account(), 100);
        v::d_pay_eur(&lane, e);
        fx::mint(u, v::d_account(), 200);
        go(&lane, v::market(), v::o_alice_sell_eur(), v::o_dave_sell_usd(), 100, 200);
        assert!(bal(e, v::d_account()) == 100 && bal(u, v::a_account()) == 200, 0);
    }

    // L7: FA gửi nhầm vào market ⇒ ai cũng `sweep` được tới người nhận phí.
    #[test(f = @aptos_framework, b = @bamboo)]
    fun stray_funds_sweep_to_the_fee_recipient(f: signer, b: signer) {
        let (e, _) = ready(&f, &b);
        fx::mint(e, v::market(), 9);
        dex::set_market(&b, v::market(), true, false, 0, 0, FEE);
        dex::sweep(v::market(), v::eur());
        assert!(bal(e, FEE) == 9 && bal(e, v::market()) == 0, 0);
    }

    #[test(f = @aptos_framework, b = @bamboo)]
    #[expected_failure(abort_code = 14, location = bamboo::dex)]
    fun sweep_needs_a_recipient(f: signer, b: signer) {
        let (e, _) = ready(&f, &b);
        fx::mint(e, v::market(), 9);
        dex::sweep(v::market(), v::eur());
    }

    // L6: FA gửi nhầm tới Root, Dex, hoặc market chưa có người nhận phí ⇒ admin gom về địa chỉ chỉ định.
    #[test(f = @aptos_framework, b = @bamboo)]
    fun admin_recovers_funds_sent_to_root_dex_and_a_market(f: signer, b: signer) {
        let (e, _) = ready(&f, &b);
        fx::mint(e, meta::root(), 1);
        fx::mint(e, dex::dex_address(), 2);
        fx::mint(e, v::market(), 3);
        dex::admin_sweep(&b, meta::root(), v::eur(), FEE);
        dex::admin_sweep(&b, dex::dex_address(), v::eur(), FEE);
        dex::admin_sweep(&b, v::market(), v::eur(), FEE);
        assert!(bal(e, FEE) == 6 && bal(e, meta::root()) == 0 && bal(e, v::market()) == 0, 0);
    }

    #[test(f = @aptos_framework, b = @bamboo)]
    #[expected_failure(abort_code = 15, location = bamboo::meta)]
    fun only_the_admin_sweeps(f: signer, b: signer) {
        let (e, _) = ready(&f, &b);
        fx::mint(e, meta::root(), 1);
        dex::admin_sweep(&account::create_signer_for_test(@0xbad), meta::root(), v::eur(), FEE);
    }

    // Tiền của người dùng (Account) không bao giờ đi qua đường gom của admin.
    #[test(f = @aptos_framework, b = @bamboo)]
    #[expected_failure(abort_code = 15, location = bamboo::dex)]
    fun admin_cannot_sweep_an_account(f: signer, b: signer) {
        ready(&f, &b);
        dex::admin_sweep(&b, v::a_account(), v::eur(), FEE);
    }

    // ANTI-LOCK: X (pay qua Account) bị giữ; Y (huỷ lệnh DEX) qua; rồi X qua.
    #[test(f = @aptos_framework, b = @bamboo, lane = @0x1a)]
    fun withheld_pay_does_not_block_a_dex_cancel(f: signer, b: signer, lane: signer) {
        let (e, _) = ready(&f, &b);
        v::cancel_o_alice_sell_eur();                 // Y
        v::a_pay_eur_0(&lane, e);                     // X
        assert!(bal(e, @0xbeef) == 100, 0);
    }
}
