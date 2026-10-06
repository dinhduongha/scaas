#[test_only]
module scaas::meta_tests {
    use aptos_framework::account;
    use aptos_framework::aptos_coin::{Self, AptosCoin};
    use aptos_framework::coin;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object;
    use scaas::fixtures::{Self as fx, bal, set_now};
    use scaas::hooked_fa;
    use scaas::meta;
    use scaas::vectors as v;

    const BEEF: address = @0xbeef;

    fun eur(): object::Object<Metadata> { fx::asset(b"EUR") }

    // ------------------------------------------------------------------ địa chỉ: Move = Python

    #[test(f = @aptos_framework, b = @scaas)]
    fun derived_addresses_match_python(f: signer, b: signer) {
        fx::setup(&f, &b);
        assert!(meta::root() == v::root(), 0);
        assert!(meta::account_of(v::alice()) == v::a_account(), 1);
        let e = eur();
        assert!(object::object_address(&e) == v::eur(), 2);
    }

    // ------------------------------------------------------------------ pay

    // L7: FA gửi thẳng tới địa chỉ Account TRƯỚC khi Account tồn tại chi được; lần chi đầu mở Account (lười).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun pay_opens_lazily_and_spends_funds_sent_before(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        assert!(!meta::exists_at(v::alice()), 0);
        v::a_pay_eur_0(&lane, e);
        assert!(meta::exists_at(v::alice()) && bal(e, BEEF) == 100 && bal(e, v::a_account()) == 900, 1);
        assert!(meta::lane_nonce(v::alice(), x"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1") == 1, 2);
        // …và SAU khi tồn tại
        fx::mint(e, v::a_account(), 5);
        v::a_pay_eur_1(&lane, e);
        assert!(bal(e, BEEF) == 150 && bal(e, v::a_account()) == 855, 3);
    }

    // `pay_check` (view, thay mô phỏng khi Account chưa mở): cùng digest, cùng mã abort, không ghi gì.
    #[test(f = @aptos_framework, b = @scaas)]
    fun pay_check_matches_relay_pay_without_writing(f: signer, b: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        assert!(v::a_pay_eur_0_check(@0x1a, e) == v::a_pay_eur_0_digest(), 0);
        assert!(!meta::exists_at(v::alice()) && bal(e, BEEF) == 0, 1);
        fx::mint(e, v::d_account(), 1000);
        assert!(v::d_pay_eur_check(@0x1a, e).length() == 32 && !meta::exists_at(v::dave()), 2);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 8, location = scaas::meta)]
    fun pay_check_refuses_a_foreign_first_key(f: signer, b: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_by_mallory_check(@0x1a, e);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun pay_check_refuses_a_passkey_without_uv(f: signer, b: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::d_account(), 1000);
        v::d_pay_eur_no_uv_check(@0x1a, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 4, location = scaas::meta)]
    fun replay_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_0(&lane, e);
        v::a_pay_eur_0(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 4, location = scaas::meta)]
    fun nonce_must_be_next(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_1(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 2, location = scaas::meta)]
    fun expired_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        set_now(1001);
        v::a_pay_eur_0(&lane, e);
    }

    // Miền: tài sản khác với tài sản đã ký.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun other_asset_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let u = fx::asset(b"USD");
        fx::mint(u, v::a_account(), 1000);
        v::a_pay_eur_0(&lane, u);
    }

    // Miền: chain id đọc on-chain (mainnet 1) ≠ chain đã ký (4).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun other_chain_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup_chain(&f, &b, 1);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_0(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e1)]
    fun bound_relayer_may_submit(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_relayer(&lane, e);
        assert!(bal(e, BEEF) == 10, 0);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 3, location = scaas::meta)]
    fun other_relayer_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_relayer(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 7, location = scaas::meta)]
    fun insufficient_balance(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 99);
        v::a_pay_eur_0(&lane, e);
    }

    // ------------------------------------------------------------------ phong bì signMessage (§4.2)

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun envelope_line_order_does_not_matter(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_reordered(&lane, e);
        assert!(bal(e, BEEF) == 10, 0);
    }

    // Trang lừa xin ký "hello\nmessage: <ours>" ⇒ hai dòng `message` ⇒ từ chối dù chữ ký ed25519 đúng.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun second_message_line_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_phish(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun envelope_chain_id_must_match(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_chain1(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun envelope_unknown_key_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_unknown_key(&lane, e);
    }

    // M1: Account có origin ⇒ phong bì ví ed25519 phải khai `application:` ∈ origins. Trang lừa xin ký rồi tự nộp
    // (không qua Odoo) bị chain từ chối; Account chưa có origin giữ hành vi cũ (đổi origin không gạch Account).
    fun alice_with_origin(f: &signer, b: &signer): object::Object<Metadata> {
        fx::setup(f, b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        meta::open(v::alice(), v::alice_pk());
        meta::manage_native(&account::create_signer_for_test(v::alice()), 2, 0, vector[], vector[], v::origin(), @0x0);
        e
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun wallet_application_in_the_origins_pays(f: signer, b: signer, lane: signer) {
        let e = alice_with_origin(&f, &b);
        v::a_pay_eur_app(&lane, e);
        assert!(bal(e, BEEF) == 10, 0);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun foreign_wallet_application_is_refused(f: signer, b: signer, lane: signer) {
        let e = alice_with_origin(&f, &b);
        v::a_pay_eur_evil_app(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun missing_wallet_application_is_refused_once_origins_exist(f: signer, b: signer, lane: signer) {
        let e = alice_with_origin(&f, &b);
        v::a_pay_eur_0(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun account_without_origins_takes_any_application(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_evil_app(&lane, e);     // lazy open
        v::a_pay_eur_app(&lane, e);          // open
        assert!(bal(e, BEEF) == 20, 0);
    }

    // L1: assertion WebAuthn trong iframe khác origin (`crossOrigin: true`, hoặc có `topOrigin`) bị từ chối.
    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun passkey_cross_origin_is_refused(f: signer, b: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::d_account(), 1000);
        v::d_pay_eur_cross_origin_check(@0x1a, e);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun passkey_top_origin_is_refused(f: signer, b: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::d_account(), 1000);
        v::d_pay_eur_top_origin_check(@0x1a, e);
    }

    // ------------------------------------------------------------------ khoá đầu tiên, lược đồ

    // Mở lười với khoá không dẫn ra auth key của chủ ⇒ từ chối (kẻ gian không chiếm trước Account).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 8, location = scaas::meta)]
    fun lazy_open_with_a_foreign_key_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_by_mallory(&lane, e);
    }

    // Account đã có: khoá không thuộc Account ⇒ từ chối.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun key_outside_the_account_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        meta::open(v::alice(), v::alice_pk());
        v::a_pay_eur_by_mallory(&lane, e);
    }

    // Tài khoản stateless (không resource `0x1::account::Account`, AIP-115) và tài khoản thường đều mở được.
    #[test(f = @aptos_framework, b = @scaas)]
    fun explicit_open_stateless_and_with_resource(f: signer, b: signer) {
        fx::setup(&f, &b);
        // alice never got a 0x1::account::Account resource: stateless (get_authentication_key = bcs(addr))
        meta::open(v::alice(), v::alice_pk());
        assert!(meta::key_count(v::alice()) == 1, 1);
        account::create_account_for_test(v::carol());
        meta::open(v::carol(), v::carol_pk());
        assert!(meta::has_key(v::carol(), v::carol_pk()), 2);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 8, location = scaas::meta)]
    fun explicit_open_with_a_foreign_key_is_refused(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::mallory_pk());
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 16, location = scaas::meta)]
    fun one_account_per_owner(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        meta::open(v::alice(), v::alice_pk());
    }

    // Chủ có địa chỉ SingleKey ed25519 (AIP-55).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun single_key_owner_pays(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::b_account(), 1000);
        v::b_pay_eur(&lane, e);
        assert!(bal(e, BEEF) == 100, 0);
    }

    // ------------------------------------------------------------------ passkey (WebAuthn P-256 trong Move)

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun passkey_owner_pays_and_origin_is_recorded(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::d_account(), 1000);
        v::d_pay_eur(&lane, e);
        assert!(bal(e, BEEF) == 100 && meta::has_origin(v::dave(), v::origin()), 0);
        v::d_pay_eur_1(&lane, e);
        assert!(bal(e, BEEF) == 110, 1);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun passkey_evil_origin_after_open(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::d_account(), 1000);
        v::d_pay_eur(&lane, e);
        v::d_pay_eur_evil_origin(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun passkey_without_user_verification_is_refused(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::d_account(), 1000);
        v::d_pay_eur_no_uv(&lane, e);
    }

    // ------------------------------------------------------------------ tài sản: coin cặp FA, dispatchable

    // L7: coin APT cũ gửi bằng `coin::deposit` tới địa chỉ Account rơi vào FA cặp (0xa) ⇒ chi được.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun paired_coin_sent_to_the_account_is_spendable(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let (burn, mint) = aptos_coin::initialize_for_test(&f);
        coin::deposit(v::a_account(), coin::mint<AptosCoin>(100, &mint));
        let apt = object::address_to_object<Metadata>(@0xa);
        v::a_pay_apt(&lane, apt);
        assert!(bal(apt, BEEF) == 30 && bal(apt, v::a_account()) == 70, 0);
        coin::destroy_burn_cap(burn);
        coin::destroy_mint_cap(mint);
    }

    // `relay_pay` chuyển qua `primary_fungible_store::transfer` ⇒ hook withdraw của FA dispatchable chạy.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun dispatchable_asset_hook_runs(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let hk = hooked_fa::create(&f, &b);
        assert!(object::object_address(&hk) == v::hook(), 0);
        hooked_fa::mint(hk, v::a_account(), 100);
        v::a_pay_hook(&lane, hk);
        assert!(bal(hk, BEEF) == 40 && hooked_fa::withdraws(hk) == 1, 1);
    }

    // ------------------------------------------------------------------ anti-lock

    // Chủ thể ký X (EUR, lane a1) và Y (USD, lane a2) trên CÙNG Account; X bị giữ; Y qua; rồi X qua.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun withheld_op_does_not_block_another_lane_or_asset(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let (e, u) = (eur(), fx::asset(b"USD"));
        fx::mint(e, v::a_account(), 1000);
        fx::mint(u, v::a_account(), 1000);
        v::a_pay_usd_0(&lane, u);
        assert!(bal(u, BEEF) == 70, 0);
        v::a_pay_eur_0(&lane, e);
        assert!(bal(e, BEEF) == 100, 1);
    }

    // ------------------------------------------------------------------ prune (L10)

    /// `meta::PRUNE_DELAY_S` (30 ngày) — Odoo `LANE_HORIZON_S` không lớn hơn.
    const PRUNE_DELAY: u64 = 2_592_000;
    const LANE_A1: vector<u8> = x"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 2, location = scaas::meta)]
    fun pruned_lane_cannot_replay(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_short(&lane, e);   // valid_until 150
        v::a_pay_eur_0(&lane, e);       // valid_until 1000, lane a1
        set_now(150 + PRUNE_DELAY + 1);
        let short = x"a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8a8";
        let live = x"a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
        meta::prune(v::alice(), vector[short, live]);
        assert!(meta::lane_nonce(v::alice(), short) == 0 && meta::lane_nonce(v::alice(), live) == 1, 0);
        v::a_pay_eur_short(&lane, e);   // expired ⇒ 2
    }

    // M2: hai op đã ký cho MỘT request (Odoo phát lại điều khoản: cùng lane, nonce 0, hạn 1000 rồi 1300). Chỉ một
    // chạy được: op kia trượt nonce khi lane còn; `prune` chờ hết hạn + PRUNE_DELAY nên lúc lane mất thì op kia hết hạn.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 4, location = scaas::meta)]
    fun reissued_op_cannot_run_while_the_lane_is_kept(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_0(&lane, e);
        set_now(1001);                  // op đã chạy hết hạn; op phát lại (1300) còn hạn
        meta::prune(v::alice(), vector[LANE_A1]);
        set_now(1200);
        assert!(meta::lane_nonce(v::alice(), LANE_A1) == 1 && bal(e, BEEF) == 100, 0);
        v::a_pay_eur_0_reissued(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 2, location = scaas::meta)]
    fun reissued_op_is_dead_once_the_lane_is_pruned(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        v::a_pay_eur_0(&lane, e);
        set_now(1000 + PRUNE_DELAY);    // ranh giới: chưa xoá
        meta::prune(v::alice(), vector[LANE_A1]);
        assert!(meta::lane_nonce(v::alice(), LANE_A1) == 1, 0);
        set_now(1000 + PRUNE_DELAY + 1);
        meta::prune(v::alice(), vector[LANE_A1]);
        assert!(meta::lane_nonce(v::alice(), LANE_A1) == 0, 1);
        v::a_pay_eur_0_reissued(&lane, e);
    }

    // ------------------------------------------------------------------ vòng đời khoá (RS11-3)

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun added_key_pays_and_rotation_keeps_the_account(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_alice2();
        v::a2_pay_eur(&lane, e);
        v::a2_remove_alice();
        assert!(meta::key_count(v::alice()) == 1 && meta::key_nonce(v::alice()) == 2, 0);
        assert!(bal(e, BEEF) == 20, 1);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 10, location = scaas::meta)]
    fun last_key_stays(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::a_remove_alice_last();
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun keyop_replay_is_refused(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_alice2();
        v::a_add_alice2();
    }

    // Thêm passkey vào Account ed25519 (cùng origin của nó) bằng chữ ký khoá hiện có.
    #[test(f = @aptos_framework, b = @scaas)]
    fun passkey_key_can_be_added(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_dave_key();
        assert!(meta::has_key(v::alice(), v::dave_pk()) && meta::has_origin(v::alice(), v::origin()), 0);
    }

    // L5: `verify_by` lấy entry ĐẦU có cùng public_key ⇒ cùng passkey (x, y) thêm lại với rpIdHash khác sẽ không bao
    // giờ kiểm được: từ chối trùng public_key.
    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 9, location = scaas::meta)]
    fun same_passkey_with_another_rp_id_is_refused(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        let o = account::create_signer_for_test(v::alice());
        meta::manage_native(&o, 0, 2, v::dave_pk(), v::rp_id_hash(), v::origin(), @0x0);
        meta::manage_native(&o, 0, 2, v::dave_pk(), x"0000000000000000000000000000000000000000000000000000000000000001",
            vector[], @0x0);
    }

    // L7: xoay auth key native KHÔNG gỡ khoá đã ở Account (khoá lộ vẫn tiêu được). Một tx native của chủ (ký bằng auth
    // key hiện tại) thay TOÀN BỘ khoá: khoá cũ hết hiệu lực ngay, KeyOp đang chờ của chúng cũng vậy.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun native_reset_drops_every_old_key(f: signer, b: signer, lane: signer) {
        fx::setup(&f, &b);
        let e = eur();
        fx::mint(e, v::a_account(), 1000);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_alice2();
        meta::reset_keys(&account::create_signer_for_test(v::alice()), 0, v::carol_pk(), vector[], vector[]);
        assert!(meta::key_count(v::alice()) == 1 && meta::has_key(v::alice(), v::carol_pk()), 0);
        assert!(!meta::has_key(v::alice(), v::alice_pk()) && meta::key_nonce(v::alice()) == 2, 1);
        v::a_pay_eur_0(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 13, location = scaas::meta)]
    fun reset_needs_an_account(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::reset_keys(&account::create_signer_for_test(v::alice()), 0, v::carol_pk(), vector[], vector[]);
    }

    // Đường 2: chủ gửi tx native (chủ keyless/passkey gắn khoá seed) — mở Account nếu chưa có.
    #[test(f = @aptos_framework, b = @scaas)]
    fun native_owner_attaches_a_key(f: signer, b: signer) {
        fx::setup(&f, &b);
        let mallory_owned = account::create_signer_for_test(@0x5ee1);
        meta::manage_native(&mallory_owned, 0, 0, v::alice2_pk(), vector[], vector[], @0x0);
        assert!(meta::has_key(@0x5ee1, v::alice2_pk()), 0);
        meta::manage_native(&mallory_owned, 4, 0, vector[], vector[], vector[], @0x9a);
        assert!(meta::guardian(@0x5ee1) == @0x9a, 1);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    fun guardian_recovers_after_the_delay(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_alice2();
        v::a_set_guardian();
        let g = account::create_signer_for_test(@0x9a);
        meta::start_recovery(&g, v::alice(), 0, v::mallory_pk(), vector[], vector[]);
        set_now(100 + 172_800);
        meta::finish_recovery(&g, v::alice());
        assert!(meta::has_key(v::alice(), v::mallory_pk()), 0);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 12, location = scaas::meta)]
    fun recovery_waits_for_the_delay(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_alice2();
        v::a_set_guardian();
        let g = account::create_signer_for_test(@0x9a);
        meta::start_recovery(&g, v::alice(), 0, v::mallory_pk(), vector[], vector[]);
        set_now(100 + 172_799);
        meta::finish_recovery(&g, v::alice());
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 12, location = scaas::meta)]
    fun existing_key_cancels_recovery(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::a_add_alice2();
        v::a_set_guardian();
        let g = account::create_signer_for_test(@0x9a);
        meta::start_recovery(&g, v::alice(), 0, v::mallory_pk(), vector[], vector[]);
        v::a_cancel_recovery();
        set_now(100 + 172_800);
        meta::finish_recovery(&g, v::alice());
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 11, location = scaas::meta)]
    fun only_the_guardian_recovers(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        let g = account::create_signer_for_test(@0x9a);
        meta::start_recovery(&g, v::alice(), 0, v::mallory_pk(), vector[], vector[]);
    }
}
