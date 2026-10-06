#[test_only]
module scaas::dex_tests;

use scaas::auth::Auth;
use scaas::dex::{Self, Market, Order};
use scaas::fixtures::{Self as fx, EUR};
use scaas::meta::{Self, Account, AdminCap};
use scaas::vectors as v;
use sui::sui::SUI;
use sui::test_scenario::{Self as ts, Scenario};

const FEE: address = @0xfee;

fun dex_addr(_: &mut Scenario): address { ts::most_recent_id_shared<Market>().destroy_some().to_address() }

/// Lệnh y như `gen_vectors.py` đã ký (hạn 1000 s, không relayer, taker tự do).
fun o_a(sc: &mut Scenario): Order {
    let d = dex_addr(sc);
    dex::new_order(b"localnet", d, v::alice(), @0x0, dex::type_bytes<SUI>(), dex::type_bytes<EUR>(), 1000, 2000, 1, 1000, 3000, 0, @0x0)
}

fun o_b(sc: &mut Scenario, buy: u64, nonce: u128, flags: u8, max_fee: u32): Order {
    let d = dex_addr(sc);
    dex::new_order(b"localnet", d, v::bob(), @0x0, dex::type_bytes<EUR>(), dex::type_bytes<SUI>(), 1000, buy, nonce, 1000, max_fee, flags, @0x0)
}

fun market(sc: &mut Scenario, listed: bool, fee_on: bool, maker_ppm: u32, taker_ppm: u32) {
    sc.next_tx(fx::admin());
    let mut m = sc.take_shared<Market>();
    let cap = sc.take_from_sender<AdminCap>();
    dex::set_market(&cap, &mut m, listed, fee_on, maker_ppm, taker_ppm, FEE);
    sc.return_to_sender(cap);
    ts::return_shared(m);
    sc.next_tx(@0x7e1);
}

fun setup(): Scenario {
    let mut sc = fx::setup_accounts();
    fx::fund<SUI>(&mut sc, v::alice(), 1000);
    fx::fund<EUR>(&mut sc, v::bob(), 1000);
    fx::list_eur_sui(&mut sc);
    sc
}

fun settle(sc: &mut Scenario, mo: Order, ma: Auth, to: Order, ta: Auth, mf: u64, tf: u64, now: u64) {
    let mut d = sc.take_shared<Market>();
    let mut ms: Account<SUI> = fx::acct(sc, v::alice());
    let mut mb: Account<EUR> = fx::acct(sc, v::alice());
    let mut ts_: Account<EUR> = fx::acct(sc, v::bob());
    let mut tb: Account<SUI> = fx::acct(sc, v::bob());
    let clock = fx::clock_at(sc, now);
    dex::settle(&mut d, &mut ms, &mut mb, &mut ts_, &mut tb, mo, ma, to, ta, mf, tf, b"r1", &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(d);
    ts::return_shared(ms);
    ts::return_shared(mb);
    ts::return_shared(ts_);
    ts::return_shared(tb);
    sc.next_tx(@0x7e1);
}

fun bal<T>(sc: &mut Scenario, who: address): u64 {
    let a: Account<T> = fx::acct(sc, who);
    let b = meta::balance(&a);
    ts::return_shared(a);
    sc.next_tx(@0x7e1);
    b
}

#[test]
fun order_hash_matches_python() {
    let mut sc = setup();
    let a = o_a(&mut sc);
    assert!(dex::order_hash(&a) == v::o_a_hash());
    let b = o_b(&mut sc, 500, 1, 0, 3000);
    assert!(dex::order_hash(&b) == v::o_b_hash());
    sc.end();
}

#[test]
fun partial_fill_at_the_limit_price_moves_both_legs() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    assert!(bal<SUI>(&mut sc, v::alice()) == 500 && bal<EUR>(&mut sc, v::alice()) == 1000);
    assert!(bal<SUI>(&mut sc, v::bob()) == 500 && bal<EUR>(&mut sc, v::bob()) == 0);
    let d = sc.take_shared<Market>();
    assert!(dex::filled(&d, v::o_a_hash()) == 500 && dex::filled(&d, v::o_b_hash()) == 1000);
    ts::return_shared(d);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EFill)]
fun never_overfills() {
    let mut sc = setup();
    fx::fund<EUR>(&mut sc, v::bob(), 1000);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 1, 2, 0);   // o_b đã đầy
    sc.end();
}

#[test, expected_failure(abort_code = dex::EPrice)]
fun price_limit_of_the_taker_holds() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 600, 4, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b_greedy(), 500, 1000, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EPrice)]
fun price_limit_of_the_maker_holds() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 999, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EFill)]
fun fill_or_kill_refuses_partial() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 2, 1, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b_fok(), 250, 500, 0);
    sc.end();
}

#[test]
fun fill_or_kill_fills_whole() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 2, 1, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b_fok(), 500, 1000, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EFill)]
fun ioc_closes_the_rest() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 3, 2, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b_ioc(), 250, 500, 0);
    let d = sc.take_shared<Market>();
    assert!(dex::filled(&d, dex::order_hash(&b)) == 1000);
    ts::return_shared(d);
    sc.next_tx(@0x7e1);
    settle(&mut sc, a, v::o_a(), b, v::o_b_ioc(), 250, 500, 0);
    sc.end();
}

#[test]
fun dex_fee_is_taken_from_what_each_side_receives() {
    let mut sc = setup();
    market(&mut sc, true, true, 2000, 3000);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    // maker nhận 1000 EUR − 0.2 % = 998; taker nhận 500 SUI − 0.3 % = 499 (làm tròn xuống).
    assert!(bal<EUR>(&mut sc, v::alice()) == 998 && bal<SUI>(&mut sc, v::bob()) == 499);
    assert!(fx::held<EUR>(&mut sc, FEE) == 2 && fx::held<SUI>(&mut sc, FEE) == 1);
    sc.end();
}

#[test]
fun fee_off_moves_no_fee() {
    let mut sc = setup();
    market(&mut sc, true, false, 2000, 3000);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 5, 0, 100));
    settle(&mut sc, a, v::o_a(), b, v::o_b_lowfee(), 500, 1000, 0);
    assert!(fx::held<EUR>(&mut sc, FEE) == 0 && bal<EUR>(&mut sc, v::alice()) == 1000);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EFeeAboveSigned)]
fun fee_above_signed_max_is_refused() {
    let mut sc = setup();
    market(&mut sc, true, true, 2000, 3000);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 5, 0, 100));
    settle(&mut sc, a, v::o_a(), b, v::o_b_lowfee(), 500, 1000, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EBadFee)]
fun fee_cap_is_one_percent() {
    let mut sc = setup();
    market(&mut sc, true, true, 10_001, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::ENotListed)]
fun delisted_market_settles_nothing() {
    let mut sc = setup();
    market(&mut sc, false, false, 0, 0);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EExpired)]
fun expired_order_is_refused() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 1001);
    sc.end();
}

#[test, expected_failure(abort_code = dex::EBadSignature)]
fun order_signature_binds_every_field() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b_fok(), 500, 1000, 0);   // chữ ký của lệnh khác
    sc.end();
}

#[test, expected_failure(abort_code = dex::EFill)]
fun cancelled_order_never_settles() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    let mut d = sc.take_shared<Market>();
    let acct: Account<SUI> = fx::acct(&mut sc, v::alice());
    assert!(dex::cancel(&mut d, &acct, a, v::cancel_o_a()));
    assert!(!dex::cancel(&mut d, &acct, a, v::cancel_o_a()));   // phát lại: no-op
    assert!(!dex::cancel(&mut d, &acct, b, v::cancel_o_a()));   // chữ ký sai: bỏ qua, không abort
    ts::return_shared(acct);
    ts::return_shared(d);
    sc.next_tx(@0x7e1);
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::ENonce)]
fun invalidated_nonce_never_settles() {
    let mut sc = setup();
    let mut d = sc.take_shared<Market>();
    let acct: Account<EUR> = fx::acct(&mut sc, v::alice());
    dex::invalidate_nonces(&mut d, &acct, 2, v::nonces_a_2());
    ts::return_shared(acct);
    ts::return_shared(d);
    sc.next_tx(@0x7e1);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    sc.end();
}

#[test, expected_failure(abort_code = dex::ENonceDown)]
fun min_nonce_only_increases() {
    let mut sc = setup();
    let mut d = sc.take_shared<Market>();
    let acct: Account<EUR> = fx::acct(&mut sc, v::alice());
    dex::invalidate_nonces(&mut d, &acct, 2, v::nonces_a_2());
    dex::invalidate_nonces(&mut d, &acct, 2, v::nonces_a_2());
    ts::return_shared(acct);
    ts::return_shared(d);
    sc.end();
}

/// ANTI-LOCK qua hai contract khác loại: payment X của alice (account SUI) bị giữ; lệnh DEX của alice vẫn
/// khớp; sau đó X vẫn chạy (DEX không đụng lane/nonce của account).
#[test]
fun anti_lock_dex_and_payment_are_independent() {
    let mut sc = setup();
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);
    let mut acct: Account<SUI> = fx::acct(&mut sc, v::alice());
    let clock = fx::clock_at(&mut sc, 0);
    let r = vector::tabulate!(32, |_| 1u8);
    let lane = vector::tabulate!(32, |_| 0xa1u8);
    meta::relay_pay(&mut acct, @0xbeef, 100, r, lane, 0, 1000, @0x0, vector::tabulate!(32, |_| 0u8), v::a_pay_sui_0(), &clock, sc.ctx());
    assert!(meta::balance(&acct) == 400);
    clock.destroy_for_testing();
    ts::return_shared(acct);
    sc.end();
}

/// Review M4: mỗi cặp một `Market` riêng — lệnh của cặp này không settle trên market khác, và `min_nonce`
/// đặt ở market khác không chạm market này.
#[test, expected_failure(abort_code = dex::EPair)]
fun orders_settle_only_on_their_own_market() {
    let mut sc = setup();
    fx::list<fx::USD, SUI>(&mut sc);
    let (a, b) = (o_a(&mut sc), o_b(&mut sc, 500, 1, 0, 3000));
    settle(&mut sc, a, v::o_a(), b, v::o_b(), 500, 1000, 0);   // market gần nhất = USD/SUI
    sc.end();
}

#[test]
fun nonce_invalidation_is_scoped_to_its_market() {
    let mut sc = setup();
    let eur = ts::most_recent_id_shared<Market>().destroy_some();
    fx::list<fx::USD, SUI>(&mut sc);
    let mut usd = sc.take_shared<Market>();
    let acct: Account<SUI> = fx::acct(&mut sc, v::alice());
    dex::invalidate_nonces(&mut usd, &acct, 2, v::nonces_a_2_usd());
    ts::return_shared(acct);
    ts::return_shared(usd);
    sc.next_tx(@0x7e1);
    let a = dex::new_order(b"localnet", eur.to_address(), v::alice(), @0x0, dex::type_bytes<SUI>(), dex::type_bytes<EUR>(), 1000, 2000, 1, 1000, 3000, 0, @0x0);
    let b = dex::new_order(b"localnet", eur.to_address(), v::bob(), @0x0, dex::type_bytes<EUR>(), dex::type_bytes<SUI>(), 1000, 500, 1, 1000, 3000, 0, @0x0);
    let mut m = sc.take_shared_by_id<Market>(eur);
    let mut ms: Account<SUI> = fx::acct(&mut sc, v::alice());
    let mut mb: Account<EUR> = fx::acct(&mut sc, v::alice());
    let mut ts_: Account<EUR> = fx::acct(&mut sc, v::bob());
    let mut tb: Account<SUI> = fx::acct(&mut sc, v::bob());
    let clock = fx::clock_at(&mut sc, 0);
    dex::settle(&mut m, &mut ms, &mut mb, &mut ts_, &mut tb, a, v::o_a(), b, v::o_b(), 500, 1000, b"r1", &clock, sc.ctx());
    assert!(dex::filled(&m, v::o_a_hash()) == 500);
    clock.destroy_for_testing();
    ts::return_shared(m);
    ts::return_shared(ms);
    ts::return_shared(mb);
    ts::return_shared(ts_);
    ts::return_shared(tb);
    sc.end();
}

#[test, expected_failure(abort_code = sui::derived_object::EObjectAlreadyExists)]
fun one_market_per_pair() {
    let mut sc = setup();
    fx::list<SUI, EUR>(&mut sc);   // cùng cặp, đảo thứ tự
    sc.end();
}
