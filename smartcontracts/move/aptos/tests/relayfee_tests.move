#[test_only]
/// CTR-MTX-27 on Aptos (spec §7.2): `scaas::relayfee`'s static wrappers. Vectors from `scripts/gen_vectors.py`:
/// each `rf_<name>` runs one fee-less signed entry, then Alice's payment of 10 EUR (valid until 2000 s; the inner
/// calls until 1000 s) bound to that call: `pay_ref = ref`, `lane = payLane(ref)`, nonce 0, relayer = marker.
module scaas::relayfee_tests {
    use aptos_framework::event;
    use aptos_framework::fungible_asset::Metadata;
    use aptos_framework::object::Object;
    use scaas::dex;
    use scaas::fixtures::{Self as fx, bal, set_now};
    use scaas::mandate;
    use scaas::meta;
    use scaas::relayfee;
    use scaas::vectors as v;

    const BEEF: address = @0xbeef;
    const LANE: address = @0x7e2;

    fun b32(b: u8): vector<u8> {
        let v = vector[];
        for (i in 0..32) v.push_back(b);
        v
    }

    /// Alice's Account open with `fund` EUR; market EUR/USD listed (cancel / invalidate act on it).
    fun ready(f: &signer, b: &signer, fund: u64): Object<Metadata> {
        fx::setup(f, b);
        let e = fx::asset(b"EUR");
        meta::open(v::alice(), v::alice_pk());
        fx::mint(e, v::a_account(), fund);
        dex::create_dex(b);
        dex::list_market(b, v::eur(), v::usd(), true, false, 0, 0, @0x0);
        e
    }

    // ------------------------------------------------------------------ ref, marker (rule 5)

    #[test(f = @aptos_framework, b = @scaas)]
    fun relay_ref_vectors(f: signer, b: signer) {
        fx::setup(&f, &b);
        assert!(relayfee::relay_ref(v::rf_manage_call(), b32(0x51)) == v::rf_manage_ref(), 0);
        assert!(relayfee::relay_ref(v::rf_open_call(), b32(0x52)) == v::rf_open_ref(), 1);
        assert!(relayfee::relay_ref(v::rf_revoke_call(), b32(0x53)) == v::rf_revoke_ref(), 2);
        assert!(relayfee::relay_ref(v::rf_cancel_call(), b32(0x54)) == v::rf_cancel_ref(), 3);
        assert!(relayfee::relay_ref(v::rf_nonces_call(), b32(0x55)) == v::rf_nonces_ref(), 4);
        assert!(relayfee::relay_ref(v::rf_nonces_by_bob_call(), b32(0x56)) == v::rf_nonces_by_bob_ref(), 5);
        // another salt: another ref
        assert!(relayfee::relay_ref(v::rf_manage_call(), b32(0x52)) != v::rf_manage_ref(), 6);
    }

    #[test(f = @aptos_framework, b = @scaas)]
    fun relay_ref_binds_the_chain(f: signer, b: signer) {
        fx::setup_chain(&f, &b, 1);
        assert!(relayfee::relay_ref(v::rf_manage_call(), b32(0x51)) != v::rf_manage_ref(), 0);
    }

    #[test]
    fun marker_is_the_derived_address() {
        assert!(relayfee::marker() == v::relay_fee_marker(), 0);
        assert!(relayfee::marker() == aptos_framework::object::create_object_address(&@scaas, b"scaas.relayfee"), 1);
    }

    // ------------------------------------------------------------------ one success per wrapped entry

    // Open mode (`to == marker`) pays the submitting lane; the marker is never paid (rule 4); `RelayFeePaid` with
    // Aptos addresses (rule 3); any lane may submit (no lane in `ref`).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_open_mode_pays_lane(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::rf_manage(&lane, e);
        assert!(meta::guardian(v::alice()) == @0x9a, 0);
        assert!(bal(e, LANE) == 10 && bal(e, relayfee::marker()) == 0 && bal(e, v::a_account()) == 990, 1);
        let paid = relayfee::relay_fee_paid_for_testing(v::rf_manage_ref(), v::eur(), v::alice(), LANE, 10);
        assert!(event::was_event_emitted(&paid), 2);
        let settled = meta::payment_settled_for_testing(v::eur(), v::alice(), LANE, 10, v::rf_manage_ref());
        assert!(event::was_event_emitted(&settled), 3);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_mandate_open_succeeds(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::rf_open(&lane, e);
        assert!(!mandate::is_revoked(v::mandate()) && bal(e, LANE) == 10, 0);
    }

    // Bound payee: the payment goes straight to `to`; the lane gets nothing.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_revoke_pays_bound_payee(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::m_open();
        v::rf_revoke(&lane, e);
        assert!(mandate::is_revoked(v::mandate()) && bal(e, BEEF) == 10 && bal(e, LANE) == 0, 0);
        let paid = relayfee::relay_fee_paid_for_testing(v::rf_revoke_ref(), v::eur(), v::alice(), BEEF, 10);
        assert!(event::was_event_emitted(&paid), 1);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_cancel_succeeds(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::rf_cancel(&lane, e);
        assert!(dex::filled(v::market(), v::o_alice_sell_eur_hash()) == 100 && bal(e, LANE) == 10, 0);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_invalidate_nonces_succeeds(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::rf_nonces(&lane, e);
        assert!(dex::min_nonce(v::market(), v::alice()) == 2 && bal(e, LANE) == 10, 0);
    }

    // Rule 11: no object ties the payer to the call on Aptos — Bob pays for Alice's call (his Account opens lazily).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_paid_by_another_payer(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        fx::mint(e, v::b_account(), 10);
        v::rf_nonces_by_bob(&lane, e);
        assert!(dex::min_nonce(v::market(), v::alice()) == 2, 0);
        assert!(bal(e, LANE) == 10 && bal(e, v::b_account()) == 0 && bal(e, v::a_account()) == 1000, 1);
    }

    // ------------------------------------------------------------------ call first, then pay; atomic (rule 9)

    // The call aborts: its own code, even though the payment would fail too (fund 5 < fee 10) ⇒ the call runs first.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 2, location = scaas::meta)]
    fun relay_target_abort_aborts_all(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        set_now(1001);
        v::rf_manage(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 10, location = scaas::mandate)]
    fun relay_open_target_abort_aborts_all(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        set_now(1001);
        v::rf_open(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 2, location = scaas::meta)]
    fun relay_revoke_target_abort_aborts_all(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::m_open();
        set_now(1001);
        v::rf_revoke(&lane, e);
    }

    // A cancel of an order already closed changes nothing: the relay refuses it, nothing is paid.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 1, location = scaas::relayfee)]
    fun relay_cancel_target_refused_aborts_all(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::cancel_o_alice_sell_eur();
        v::rf_cancel(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 13, location = scaas::dex)]
    fun relay_nonces_target_abort_aborts_all(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::alice_min_nonce_2();
        v::rf_nonces(&lane, e);
    }

    // The call ran, then the payment aborts (fund 5 < fee 10): the call's effects revert with it.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 7, location = scaas::meta)]
    fun relay_payment_abort_aborts_manage(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::rf_manage(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 7, location = scaas::meta)]
    fun relay_payment_abort_aborts_open(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::rf_open(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 7, location = scaas::meta)]
    fun relay_payment_abort_aborts_revoke(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::m_open();
        v::rf_revoke(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 7, location = scaas::meta)]
    fun relay_payment_abort_aborts_cancel(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::rf_cancel(&lane, e);
    }

    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 7, location = scaas::meta)]
    fun relay_payment_abort_aborts_nonces(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 5);
        v::rf_nonces(&lane, e);
    }

    // ------------------------------------------------------------------ only through the router (rule 7)

    // Review focus 3: the router-bound payment sent to the plain `relay_pay` (relayer = marker ≠ any lane).
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 3, location = scaas::meta)]
    fun aptos_router_bound_pay_refused_direct(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::rf_manage_direct(&lane, e);
    }

    // The revoke's payment through another wrapper: its ref is another call's ⇒ the signature fails.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 1, location = scaas::meta)]
    fun relay_payment_does_not_cross_wrappers(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::m_open();
        v::rf_nonces_with_revoke_pay(&lane, e);
    }

    // The same call relayed twice (revoke is idempotent): the pay lane pays the ref once.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    #[expected_failure(abort_code = 4, location = scaas::meta)]
    fun relay_same_ref_pays_once(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        v::m_open();
        v::rf_revoke(&lane, e);
        v::rf_revoke(&lane, e);
    }

    // Rule 6: Bob's plain pay of 1 with Alice's ref (his own lane table) does not block Alice's relay.
    #[test(f = @aptos_framework, b = @scaas, lane = @0x7e2)]
    fun relay_preburn_by_another_payer_does_not_block(f: signer, b: signer, lane: signer) {
        let e = ready(&f, &b, 1000);
        fx::mint(e, v::b_account(), 1);
        v::rf_manage_preburn_by_bob(&lane, e);
        v::rf_manage(&lane, e);
        assert!(meta::guardian(v::alice()) == @0x9a && bal(e, LANE) == 10, 0);
    }
}
