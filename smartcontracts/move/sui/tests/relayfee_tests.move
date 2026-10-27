/// CTR-MTX-27 on Sui (spec §7.2): the static wrappers of `scaas::relayfee`. Signatures from `gen_vectors.py`
/// (`rf_<entry>_pay`: Alice pays 10 SUI, valid until 2000 s, relayer = the `RelayFee` marker, salt 0x51…0x54).
#[test_only]
module scaas::relayfee_tests;

use scaas::auth::Auth;
use scaas::dex::{Self, Market};
use scaas::fixtures::{Self as fx, EUR};
use scaas::mandate::{Self, Mandate};
use scaas::meta::{Self, Registry};
use scaas::relayfee::{Self, RelayFee};
use scaas::vectors as v;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario::{Self as ts, Scenario};

const LANE: address = @0x7e1;
const BEEF: address = @0xbeef;
const SET_GUARDIAN: u8 = 4;

fun b32(b: u8): vector<u8> { vector::tabulate!(32, |_| b) }

/// tx4 mandate (as `mandate_tests::setup` ⇒ the id `gen_vectors.py` signed for), EUR/SUI market, Alice funded
/// with `fund` SUI. Returns at the start of a tx sent by `LANE`.
fun scenario(fund: u64): Scenario {
    let mut sc = fx::setup_accounts();
    sc.next_tx(v::alice());
    let r = sc.take_shared<Registry<SUI>>();
    let clock = fx::clock_at(&mut sc, 0);
    let c = coin::mint_for_testing<SUI>(500, sc.ctx());
    mandate::create(&r, c, 0, v::delegate_pk(), 50, 80, 100, 1000, vector[BEEF], &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(r);
    fx::list_eur_sui(&mut sc);
    if (fund > 0) fx::fund<SUI>(&mut sc, v::alice(), fund);
    sc.next_tx(LANE);
    sc
}

fun end_tx(sc: &mut Scenario, sender: address) { sc.next_tx(sender); }

fun manage(sc: &mut Scenario, now: u64, amount: u128, pay_auth: Auth) {
    let rf = sc.take_shared<RelayFee>();
    let mut a = fx::acct<SUI>(sc, v::alice());
    let clock = fx::clock_at(sc, now);
    relayfee::relay_manage(
        &rf, &mut a, SET_GUARDIAN, 0, vector[], vector[], vector[], @0x9a, 1000, v::k_a_guardian(),
        v::relay_fee_marker(), amount, 2000, b32(0x51), pay_auth, &clock, sc.ctx(),
    );
    clock.destroy_for_testing();
    ts::return_shared(a);
    ts::return_shared(rf);
    let s = sc.ctx().sender();
    end_tx(sc, s);
}

fun revoke(sc: &mut Scenario, now: u64, amount: u128, pay_auth: Auth) {
    let rf = sc.take_shared<RelayFee>();
    let mut m = sc.take_shared<Mandate<SUI>>();
    let mut a = fx::acct<SUI>(sc, v::alice());
    let clock = fx::clock_at(sc, now);
    relayfee::relay_revoke_with_sig(&rf, &mut m, 1000, v::m_revoke(), &mut a, BEEF, amount, 2000, b32(0x52), pay_auth, &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(a);
    ts::return_shared(m);
    ts::return_shared(rf);
    let s = sc.ctx().sender();
    end_tx(sc, s);
}

fun cancel(sc: &mut Scenario, amount: u128, pay_auth: Auth) {
    let rf = sc.take_shared<RelayFee>();
    let mut mk = sc.take_shared<Market>();
    let mut a = fx::acct<SUI>(sc, v::alice());
    let clock = fx::clock_at(sc, 0);
    relayfee::relay_cancel(&rf, &mut mk, &mut a, o_a(), v::cancel_o_a(), v::relay_fee_marker(), amount, 2000, b32(0x53), pay_auth, &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(a);
    ts::return_shared(mk);
    ts::return_shared(rf);
    let s = sc.ctx().sender();
    end_tx(sc, s);
}

/// `relay_invalidate_nonces` paying `to` with salt `salt` (the vector: marker, 0x54).
fun nonces(sc: &mut Scenario, to: address, amount: u128, salt: u8, pay_auth: Auth) {
    let rf = sc.take_shared<RelayFee>();
    let mut mk = sc.take_shared<Market>();
    let mut a = fx::acct<SUI>(sc, v::alice());
    let clock = fx::clock_at(sc, 0);
    relayfee::relay_invalidate_nonces(&rf, &mut mk, &mut a, 2, v::nonces_a_2(), to, amount, 2000, b32(salt), pay_auth, &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(a);
    ts::return_shared(mk);
    ts::return_shared(rf);
    let s = sc.ctx().sender();
    end_tx(sc, s);
}

/// `o_a` of `gen_vectors.py`: Alice sells 1000 SUI for 2000 EUR on EUR/SUI, nonce 1.
fun o_a(): dex::Order {
    dex::new_order(
        b"localnet", @0x4c5e7c0aa01e77f7c83bc1bd0c19fc6fdfd44f12920176c52c005f5f6b90326b, v::alice(), @0x0,
        dex::type_bytes<SUI>(), dex::type_bytes<EUR>(), 1000, 2000, 1, 1000, 3000, 0, @0x0,
    )
}

fun alice_balance(sc: &mut Scenario): u64 {
    let a = fx::acct<SUI>(sc, v::alice());
    let b = meta::balance(&a);
    ts::return_shared(a);
    b
}

// ------------------------------------------------------------------ vectors

/// `ref` of each wrapper's call (the bytes `gen_vectors.py` built; the wrappers build the same on chain, or the
/// payments below would not verify). `package()` is the original id, 0x0 under `sui move test`.
#[test]
fun relay_ref_vectors() {
    assert!(relayfee::package() == @0x0);
    assert!(relayfee::relay_ref(b"localnet", v::rf_manage_call(), b32(0x51)) == v::rf_manage_ref());
    assert!(relayfee::relay_ref(b"localnet", v::rf_revoke_call(), b32(0x52)) == v::rf_revoke_ref());
    assert!(relayfee::relay_ref(b"localnet", v::rf_cancel_call(), b32(0x53)) == v::rf_cancel_ref());
    assert!(relayfee::relay_ref(b"localnet", v::rf_nonces_call(), b32(0x54)) == v::rf_nonces_ref());
}

#[test]
fun marker_is_the_relay_fee_object() {
    let mut sc = scenario(0);
    let rf = sc.take_shared<RelayFee>();
    assert!(object::id_address(&rf) == v::relay_fee_marker());
    ts::return_shared(rf);
    sc.end();
}

// ------------------------------------------------------------------ one success per wrapped target

/// Open mode (`to == marker`): any lane may submit (`@0x7e2` here) and is paid; the marker is never paid.
#[test]
fun relay_open_mode_pays_sender() {
    let mut sc = scenario(1000);
    sc.next_tx(@0x7e2);
    let rf = sc.take_shared<RelayFee>();
    let mut a = fx::acct<SUI>(&mut sc, v::alice());
    let clock = fx::clock_at(&mut sc, 0);
    relayfee::relay_manage(
        &rf, &mut a, SET_GUARDIAN, 0, vector[], vector[], vector[], @0x9a, 1000, v::k_a_guardian(),
        v::relay_fee_marker(), 10, 2000, b32(0x51), v::rf_manage_pay(), &clock, sc.ctx(),
    );
    let reg = meta::registry_id(&a);
    assert!(sui::event::events_by_type<relayfee::RelayFeePaid>()
        == vector[relayfee::relay_fee_paid_for_testing(v::rf_manage_ref(), reg, v::alice(), @0x7e2, 10)]);
    assert!(sui::event::events_by_type<meta::PaymentSettled>()
        == vector[meta::payment_settled_for_testing(reg, v::alice(), @0x7e2, 10, v::rf_manage_ref())]);
    assert!(meta::key_nonce(&a) == 1 && meta::balance(&a) == 990);
    assert!(meta::lane_nonce(&a, meta::pay_lane(v::rf_manage_ref())) == 1);
    clock.destroy_for_testing();
    ts::return_shared(a);
    ts::return_shared(rf);
    sc.next_tx(LANE);
    assert!(fx::held<SUI>(&mut sc, @0x7e2) == 10 && fx::held<SUI>(&mut sc, v::relay_fee_marker()) == 0);
    sc.end();
}

/// Bound payee: the payment goes straight to `to`.
#[test]
fun relay_revoke_pays_bound_payee() {
    let mut sc = scenario(1000);
    revoke(&mut sc, 0, 10, v::rf_revoke_pay());
    let m = sc.take_shared<Mandate<SUI>>();
    assert!(mandate::is_revoked(&m));
    ts::return_shared(m);
    assert!(fx::held<SUI>(&mut sc, BEEF) == 10 && fx::held<SUI>(&mut sc, LANE) == 0);
    assert!(alice_balance(&mut sc) == 990);
    sc.end();
}

#[test]
fun relay_cancel_succeeds() {
    let mut sc = scenario(1000);
    cancel(&mut sc, 10, v::rf_cancel_pay());
    let mk = sc.take_shared<Market>();
    assert!(dex::filled(&mk, v::o_a_hash()) == 1000);
    ts::return_shared(mk);
    assert!(fx::held<SUI>(&mut sc, LANE) == 10 && alice_balance(&mut sc) == 990);
    sc.end();
}

#[test]
fun relay_invalidate_nonces_succeeds() {
    let mut sc = scenario(1000);
    nonces(&mut sc, v::relay_fee_marker(), 10, 0x54, v::rf_nonces_pay());
    assert!(fx::held<SUI>(&mut sc, LANE) == 10 && alice_balance(&mut sc) == 990);
    sc.end();
}

// ------------------------------------------------------------------ the call aborts ⇒ nothing is paid

/// Rule 9, call side. The inner `KeyOp` expired at 1000 s; the payment (2000 s) is still valid.
#[test, expected_failure(abort_code = meta::EExpired)]
fun relay_target_abort_aborts_all() {
    let mut sc = scenario(1000);
    manage(&mut sc, 1001, 10, v::rf_manage_pay());
    sc.end();
}

#[test, expected_failure(abort_code = meta::EExpired)]
fun relay_revoke_target_abort_aborts_all() {
    let mut sc = scenario(1000);
    revoke(&mut sc, 1001, 10, v::rf_revoke_pay());
    sc.end();
}

/// `dex::cancel` returns `false` for an order already closed: the wrapper aborts instead of paying for nothing.
#[test, expected_failure(abort_code = relayfee::ECallRefused)]
fun relay_cancel_target_refused_aborts_all() {
    let mut sc = scenario(1000);
    let mut mk = sc.take_shared<Market>();
    let a = fx::acct<SUI>(&mut sc, v::alice());
    assert!(dex::cancel(&mut mk, &a, o_a(), v::cancel_o_a()));
    ts::return_shared(a);
    ts::return_shared(mk);
    sc.next_tx(LANE);
    cancel(&mut sc, 10, v::rf_cancel_pay());
    sc.end();
}

#[test, expected_failure(abort_code = dex::ENonceDown)]
fun relay_nonces_target_abort_aborts_all() {
    let mut sc = scenario(1000);
    let mut mk = sc.take_shared<Market>();
    let a = fx::acct<SUI>(&mut sc, v::alice());
    dex::invalidate_nonces(&mut mk, &a, 2, v::nonces_a_2());
    ts::return_shared(a);
    ts::return_shared(mk);
    sc.next_tx(LANE);
    nonces(&mut sc, v::relay_fee_marker(), 10, 0x54, v::rf_nonces_pay());
    sc.end();
}

// ------------------------------------------------------------------ the payment aborts ⇒ the call is undone

/// Rule 9, payment side: the call ran, the payer cannot pay ⇒ the whole transaction aborts.
#[test, expected_failure(abort_code = meta::EInsufficient)]
fun relay_payment_abort_aborts_manage() {
    let mut sc = scenario(5);
    manage(&mut sc, 0, 10, v::rf_manage_pay());
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun relay_payment_abort_aborts_revoke() {
    let mut sc = scenario(1000);
    revoke(&mut sc, 0, 11, v::rf_revoke_pay());
    sc.end();
}

#[test, expected_failure(abort_code = meta::EInsufficient)]
fun relay_payment_abort_aborts_cancel() {
    let mut sc = scenario(0);
    cancel(&mut sc, 10, v::rf_cancel_pay());
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun relay_payment_abort_aborts_nonces() {
    let mut sc = scenario(1000);
    nonces(&mut sc, v::relay_fee_marker(), 11, 0x54, v::rf_nonces_pay());
    sc.end();
}

// ------------------------------------------------------------------ binding (rules 4–7)

/// Review focus 3 / rule 7: a payment signed for the router does not settle through `relay_pay` — no sender is the
/// `RelayFee` object.
#[test, expected_failure(abort_code = meta::EWrongRelayer)]
fun sui_router_bound_pay_refused_direct() {
    let mut sc = scenario(1000);
    let mut a = fx::acct<SUI>(&mut sc, v::alice());
    let clock = fx::clock_at(&mut sc, 0);
    let r = v::rf_manage_ref();
    meta::relay_pay(&mut a, v::relay_fee_marker(), 10, r, meta::pay_lane(r), 0, 2000, v::relay_fee_marker(), b32(0x51),
        v::rf_manage_pay(), &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(a);
    sc.end();
}

/// Rule 7: nor through `relay_pay_meta` (the other plain pay entry).
#[test, expected_failure(abort_code = meta::EWrongRelayer)]
fun sui_router_bound_pay_meta_refused_direct() {
    let mut sc = scenario(1000);
    let mut a = fx::acct<SUI>(&mut sc, v::alice());
    let clock = fx::clock_at(&mut sc, 0);
    meta::relay_pay_meta(&mut a, v::relay_fee_marker(), 10, v::pm_note_salt(), v::pm_note_meta(), 2000,
        v::relay_fee_marker(), b32(0x51), v::rf_manage_pay(), &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(a);
    sc.end();
}

/// Rule 7: the revoke's payment does not settle through another wrapper (its ref differs ⇒ the signature fails).
#[test, expected_failure(abort_code = meta::EBadSignature)]
fun relay_payment_does_not_cross_wrappers() {
    let mut sc = scenario(1000);
    nonces(&mut sc, BEEF, 10, 0x52, v::rf_revoke_pay());
    sc.end();
}

/// Rules 5 / 6: `revoke_with_sig` is idempotent (the same signed call runs twice), but its payment is once per
/// `(payer, ref)`: the second relay aborts on the payer's pay lane.
#[test, expected_failure(abort_code = meta::EBadNonce)]
fun relay_same_ref_pays_once() {
    let mut sc = scenario(1000);
    revoke(&mut sc, 0, 10, v::rf_revoke_pay());
    revoke(&mut sc, 0, 10, v::rf_revoke_pay());
    sc.end();
}
