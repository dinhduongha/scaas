#[test_only]
module scaas::mandate_tests {
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::Object;
    use scaas::fixtures::{Self as fx, bal, set_now};
    use scaas::mandate;
    use scaas::meta;
    use scaas::vectors as v;

    const BEEF: address = @0xbeef;
    const R1: vector<u8> = x"6161616161616161616161616161616161616161616161616161616161616161";

    // Account của alice mở; mandate mở bằng chữ ký khoá Account; vốn = một `pay` thường tới địa chỉ Mandate.
    fun ready(f: &signer, b: &signer, lane: &signer): Object<Metadata> {
        fx::setup(f, b);
        let e = fx::asset(b"EUR");
        fx::mint(e, v::a_account(), 1000);
        meta::open(v::alice(), v::alice_pk());
        v::m_open();
        assert!(mandate::mandate_of(v::alice(), b"m1") == v::mandate(), 0);
        v::a_pay_eur_to_mandate(lane, e);
        assert!(bal(e, v::mandate()) == 200, 1);
        e
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun pays_within_caps_and_resets_each_period(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_60_r1(&lane, e);
        v::m_pay_60_r2(&lane, e);
        assert!(bal(e, BEEF) == 120 && mandate::spent_in_period(v::mandate()) == 120, 0);
        set_now(100 + 600);               // kỳ mới (period 600 s)
        v::m_pay_60_r3(&lane, e);
        assert!(bal(e, BEEF) == 180 && mandate::spent_in_period(v::mandate()) == 60, 1);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 6, location = scaas::mandate)]
    fun period_cap_holds(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_60_r1(&lane, e);
        v::m_pay_60_r2(&lane, e);
        v::m_pay_60_r3(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 5, location = scaas::mandate)]
    fun payment_cap_holds(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_101(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 4, location = scaas::mandate)]
    fun payee_must_be_listed(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_to_mallory(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 7, location = scaas::mandate)]
    fun pay_ref_once(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_60_r1(&lane, e);
        v::m_pay_60_r1(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 8, location = scaas::mandate)]
    fun only_the_delegate_signs(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_by_mallory(&lane, e);
    }

    // Miền: chữ ký của một `pay` qua Account (op 0, contract = Account) không qua được mandate (op 2, contract = Mandate).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 8, location = scaas::mandate)]
    fun account_op_signature_is_not_a_mandate_op(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_with_account_op_sig(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    #[expected_failure(abort_code = 8, location = scaas::mandate)]
    fun only_an_account_key_opens(f: signer, b: signer) {
        fx::setup(&f, &b);
        meta::open(v::alice(), v::alice_pk());
        v::m_open_by_mallory();
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 2, location = scaas::mandate)]
    fun delegate_revokes_then_pay_fails(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_revoke_by_delegate(&lane);
        assert!(mandate::is_revoked(v::mandate()), 0);
        v::m_pay_60_r1(&lane, e);
    }

    // Thu hồi bằng khoá Account của chủ, rồi ai cũng hoàn được tiền về Account (tiền không kẹt).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun owner_revokes_and_funds_return_to_the_account(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        fx::mint(e, v::mandate(), 7);   // L7: FA gửi thẳng tới Mandate được tính
        v::m_revoke_by_owner(&lane);
        mandate::refund(v::mandate(), e);
        assert!(bal(e, v::mandate()) == 0 && bal(e, v::a_account()) == 1007, 0);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 11, location = scaas::mandate)]
    fun live_mandate_does_not_refund(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        mandate::refund(v::mandate(), e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun expired_mandate_refunds(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        set_now(5001);
        mandate::refund(v::mandate(), e);
        assert!(bal(e, v::a_account()) == 1000, 0);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 3, location = scaas::mandate)]
    fun expired_mandate_does_not_pay(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        set_now(5001);
        v::m_pay_60_r1(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun spent_refs_are_pruned_after_their_op_expires(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_60_r1(&lane, e);
        mandate::prune(v::mandate(), vector[R1]);
        assert!(mandate::ref_used(v::mandate(), R1), 0);
        set_now(1000 + 2_592_000);      // hết hạn nhưng chưa qua PRUNE_DELAY (M2)
        mandate::prune(v::mandate(), vector[R1]);
        assert!(mandate::ref_used(v::mandate(), R1), 1);
        set_now(1000 + 2_592_000 + 1);
        mandate::prune(v::mandate(), vector[R1]);
        assert!(!mandate::ref_used(v::mandate(), R1), 2);
    }

    // M2: delegate ký hai op cho cùng pay_ref (hạn 1000 rồi 1300): op thứ hai trượt khi ref còn giữ.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    #[expected_failure(abort_code = 7, location = scaas::mandate)]
    fun reissued_mandate_op_cannot_pay_twice(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_60_r1(&lane, e);
        set_now(1001);
        mandate::prune(v::mandate(), vector[R1]);
        set_now(1200);
        v::m_pay_60_r1_reissued(&lane, e);
    }

    // ANTI-LOCK: chủ thể ký X (pay qua Account) và Y (mandate::pay); X bị giữ; Y qua; rồi X qua.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x1a)]
    fun withheld_account_op_does_not_block_the_mandate(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, &lane);
        v::m_pay_60_r1(&lane, e);          // Y
        assert!(bal(e, BEEF) == 60, 0);
        v::a_pay_eur_0(&lane, e);          // X, đã ký trước Y
        assert!(bal(e, BEEF) == 160, 1);
    }
}
