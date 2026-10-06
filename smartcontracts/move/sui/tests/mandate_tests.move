#[test_only]
module scaas::mandate_tests;

use scaas::fixtures::{Self as fx};
use scaas::mandate::{Self, Mandate};
use scaas::meta::Registry;
use scaas::vectors as v;
use sui::coin;
use sui::sui::SUI;
use sui::test_scenario as ts;

/// tx4 (sender alice): mandate 500 SUI, trần 50/lần, 80/kỳ 100 s, hạn 1000 s, payee 0xbeef.
fun setup(): ts::Scenario {
    let mut sc = fx::setup_accounts();
    sc.next_tx(v::alice());
    let r = sc.take_shared<Registry<SUI>>();
    let clock = fx::clock_at(&mut sc, 0);
    let c = coin::mint_for_testing<SUI>(500, sc.ctx());
    mandate::create(&r, c, 0, v::delegate_pk(), 50, 80, 100, 1000, vector[@0xbeef], &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(r);
    sc.next_tx(@0x7e1);
    sc
}

fun ref(b: u8): vector<u8> { vector::tabulate!(32, |_| b) }

fun pay(sc: &mut ts::Scenario, amount: u128, r: u8, a: scaas::auth::Auth, now: u64) {
    let mut m = sc.take_shared<Mandate<SUI>>();
    let clock = fx::clock_at(sc, now);
    mandate::pay(&mut m, @0xbeef, amount, ref(r), 1000, @0x0, a, &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(m);
    sc.next_tx(@0x7e1);
}

#[test]
fun print_mandate_id() {
    let mut sc = setup();
    let m = sc.take_shared<Mandate<SUI>>();
    std::debug::print(&object::id(&m));
    ts::return_shared(m);
    sc.end();
}

#[test]
fun delegate_pays_within_caps_and_period_resets() {
    let mut sc = setup();
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 0);
    pay(&mut sc, 40, 0x62, v::m_pay_2(), 10);
    pay(&mut sc, 30, 0x63, v::m_pay_3(), 100);   // kỳ mới
    assert!(fx::held<SUI>(&mut sc, @0xbeef) == 110);
    let m = sc.take_shared<Mandate<SUI>>();
    assert!(mandate::balance(&m) == 390 && mandate::spent_in_period(&m) == 30);
    ts::return_shared(m);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::EOverPeriodCap)]
fun period_cap_holds() {
    let mut sc = setup();
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 0);
    pay(&mut sc, 40, 0x62, v::m_pay_2(), 10);
    pay(&mut sc, 30, 0x63, v::m_pay_3(), 99);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::ERefPaid)]
fun pay_ref_is_paid_once() {
    let mut sc = setup();
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 0);
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::EOverPaymentCap)]
fun per_payment_cap_holds() {
    let mut sc = setup();
    pay(&mut sc, 51, 0x61, v::m_pay_1(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::EBadSignature)]
fun delegate_signature_binds_the_amount() {
    let mut sc = setup();
    pay(&mut sc, 41, 0x61, v::m_pay_1(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::EPayee)]
fun removed_payee_cannot_be_paid() {
    let mut sc = setup();
    sc.next_tx(v::alice());
    let mut m = sc.take_shared<Mandate<SUI>>();
    mandate::set_payee(&mut m, @0xbeef, false, sc.ctx());
    ts::return_shared(m);
    sc.next_tx(@0x7e1);
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::EMandateExpired)]
fun expired_mandate_pays_nothing() {
    let mut sc = setup();
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 1001);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::ENotOwner)]
fun only_owner_withdraws() {
    let mut sc = setup();
    let mut m = sc.take_shared<Mandate<SUI>>();
    mandate::withdraw(&mut m, 1, sc.ctx());
    ts::return_shared(m);
    sc.end();
}

#[test, expected_failure(abort_code = mandate::ERevoked)]
fun delegate_kill_switch_stops_payments() {
    let mut sc = setup();
    let mut m = sc.take_shared<Mandate<SUI>>();
    let clock = fx::clock_at(&mut sc, 0);
    mandate::revoke_with_sig(&mut m, 1000, v::m_revoke(), &clock, sc.ctx());
    assert!(mandate::is_revoked(&m));
    clock.destroy_for_testing();
    ts::return_shared(m);
    sc.next_tx(@0x7e1);
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 0);
    sc.end();
}

#[test]
fun owner_withdraws_and_revokes() {
    let mut sc = setup();
    sc.next_tx(v::alice());
    let mut m = sc.take_shared<Mandate<SUI>>();
    mandate::withdraw(&mut m, 100, sc.ctx());
    mandate::revoke(&mut m, sc.ctx());
    assert!(mandate::balance(&m) == 400 && mandate::is_revoked(&m));
    ts::return_shared(m);
    sc.next_tx(v::alice());
    assert!(fx::held<SUI>(&mut sc, v::alice()) == 100);
    sc.end();
}

/// Review L6: trần kỳ/độ dài kỳ gần u64::MAX và mandate tạo lúc clock > 0 — không tràn số.
#[test]
fun extreme_limits_do_not_overflow() {
    let mut sc = fx::setup_accounts();
    sc.next_tx(v::alice());
    let r = sc.take_shared<Registry<SUI>>();
    let clock = fx::clock_at(&mut sc, 5);
    let max = 0xffffffffffffffff;
    let c = coin::mint_for_testing<SUI>(500, sc.ctx());
    mandate::create(&r, c, 0, v::delegate_pk(), max, max, max, 1000, vector[@0xbeef], &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(r);
    sc.next_tx(@0x7e1);
    pay(&mut sc, 40, 0x61, v::m_pay_1(), 5);
    pay(&mut sc, 40, 0x62, v::m_pay_2(), 10);
    assert!(fx::held<SUI>(&mut sc, @0xbeef) == 80);
    sc.end();
}

/// Review M2: coin gửi thẳng tới id mandate ⇒ kéo vào số dư.
#[test]
fun coins_sent_to_the_mandate_id_are_not_stuck() {
    let mut sc = setup();
    let id = ts::most_recent_id_shared<Mandate<SUI>>().destroy_some();
    transfer::public_transfer(coin::mint_for_testing<SUI>(5, sc.ctx()), id.to_address());
    sc.next_tx(@0x7e1);
    let mut m = sc.take_shared<Mandate<SUI>>();
    mandate::receive(&mut m, ts::most_recent_receiving_ticket<coin::Coin<SUI>>(&id));
    assert!(mandate::balance(&m) == 505);
    ts::return_shared(m);
    sc.end();
}
