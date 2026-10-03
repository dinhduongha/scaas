#[test_only]
module bamboo::meta_tests;

use bamboo::auth::{Self, Auth};
use bamboo::fixtures::{Self as fx, EUR};
use bamboo::meta::{Self, Account, AdminCap, Registry, Root};
use bamboo::vectors as v;
use sui::sui::SUI;
use sui::test_scenario::{Self as ts, Scenario};

const BEEF: address = @0xbeef;

fun ref(b: u8): vector<u8> { vector::tabulate!(32, |_| b) }

/// `relay_pay` với tham số đúng như `gen_vectors.py` đã ký (to 0xbeef, hạn 1000 s).
fun pay<T>(sc: &mut Scenario, owner: address, amount: u128, r: u8, lane: u8, nonce: u64, relayer: address, a: Auth, now: u64) {
    let mut acct = fx::acct<T>(sc, owner);
    let clock = fx::clock_at(sc, now);
    meta::relay_pay(&mut acct, BEEF, amount, ref(r), ref(lane), nonce, 1000, relayer, ref(0), a, &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(acct);
    let s = sc.ctx().sender();
    sc.next_tx(s);
}

fun funded(): Scenario {
    let mut sc = fx::setup_accounts();
    fx::fund<SUI>(&mut sc, v::alice(), 1000);
    fx::fund<EUR>(&mut sc, v::alice(), 1000);
    fx::fund<SUI>(&mut sc, v::bob(), 1000);
    fx::fund<SUI>(&mut sc, v::carol(), 1000);
    fx::fund<SUI>(&mut sc, v::dave(), 1000);
    sc.next_tx(@0x7e1);
    sc
}

#[test]
fun account_id_and_digest_match_python() {
    let mut sc = fx::setup_accounts();
    let r = sc.take_shared<Registry<SUI>>();
    assert!(meta::account_address(&r, v::alice()) == v::a_sui_account());
    ts::return_shared(r);
    sc.next_tx(@0x7e1);
    let a = fx::acct<SUI>(&mut sc, v::alice());
    assert!(object::id_address(&a) == v::a_sui_account());
    assert!(meta::owner(&a) == v::alice() && auth::address_of(0, &v::alice_pk()) == v::alice());
    let op = meta::new_op(b"localnet", v::a_sui_account(), 0, v::alice(), BEEF, 100, ref(1), ref(0xa1), 0, 1000, @0x0, ref(0));
    assert!(meta::op_digest(&op) == v::a_pay_sui_0_digest());
    ts::return_shared(a);
    sc.end();
}

#[test]
fun pay_with_every_scheme() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    pay<SUI>(&mut sc, v::bob(), 100, 5, 0xb1, 0, @0x0, v::b_pay_sui(), 0);
    pay<SUI>(&mut sc, v::carol(), 100, 6, 0xc1, 0, @0x0, v::c_pay_sui(), 0);
    pay<SUI>(&mut sc, v::dave(), 100, 7, 0xd1, 0, @0x0, v::d_pay_sui(), 0);
    sc.next_tx(@0x7e1);
    assert!(fx::held<SUI>(&mut sc, BEEF) == 400);
    let a = fx::acct<SUI>(&mut sc, v::alice());
    assert!(meta::balance(&a) == 900 && meta::lane_nonce(&a, ref(0xa1)) == 1);
    ts::return_shared(a);
    sc.next_tx(@0x7e1);
    // Lane tuần tự: nonce 1 sau nonce 0.
    pay<SUI>(&mut sc, v::alice(), 50, 2, 0xa1, 1, @0x0, v::a_pay_sui_1(), 999);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadNonce)]
fun replay_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadNonce)]
fun nonce_gap_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::alice(), 50, 2, 0xa1, 1, @0x0, v::a_pay_sui_1(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EExpired)]
fun expired_payload_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 1001);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun relayer_cannot_change_the_amount() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::alice(), 101, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun signature_does_not_cross_contracts() {
    // Cùng chủ, cùng trường, account EUR ⇒ `contract` khác trong miền ký.
    let mut sc = funded();
    pay<EUR>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun signature_of_another_subject_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::bob(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EWrongRelayer)]
fun relayer_bound_payload_refuses_other_senders() {
    let mut sc = funded();
    sc.next_tx(@0x7e2);
    pay<SUI>(&mut sc, v::alice(), 10, 4, 0xa3, 0, @0x7e1, v::a_pay_sui_relayer(), 0);
    sc.end();
}

#[test]
fun relayer_bound_payload_runs_from_that_relayer() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::alice(), 10, 4, 0xa3, 0, @0x7e1, v::a_pay_sui_relayer(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun passkey_from_another_origin_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::dave(), 100, 7, 0xd1, 0, @0x0, v::d_pay_sui_evil_origin(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun passkey_without_user_verification_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::dave(), 100, 7, 0xd1, 0, @0x0, v::d_pay_sui_no_uv(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EInsufficient)]
fun cannot_pay_more_than_the_balance() {
    let mut sc = fx::setup_accounts();
    fx::fund<SUI>(&mut sc, v::alice(), 99);
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = sui::derived_object::EObjectAlreadyExists)]
fun second_account_for_the_same_subject_is_refused() {
    let mut sc = fx::setup_accounts();
    let mut r = sc.take_shared<Registry<SUI>>();
    meta::open(&mut r, 0, v::alice_pk(), sc.ctx());
    ts::return_shared(r);
    sc.end();
}

#[test, expected_failure(abort_code = sui::derived_object::EObjectAlreadyExists)]
fun second_registry_for_a_coin_type_is_refused() {
    let mut sc = fx::setup();
    let mut root = sc.take_shared<Root>();
    meta::new_registry<SUI>(&mut root);
    ts::return_shared(root);
    sc.end();
}

#[test, expected_failure(abort_code = meta::ENetwork)]
fun network_is_set_once() {
    let mut sc = fx::setup();
    let mut root = sc.take_shared<Root>();
    let cap = sc.take_from_sender<AdminCap>();
    meta::set_network(&cap, &mut root, b"mainnet");
    sc.return_to_sender(cap);
    ts::return_shared(root);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun passkey_account_cannot_be_opened_without_the_key() {
    // Kẻ gian mở account passkey cho khoá của carol bằng assertion của dave ⇒ từ chối.
    let mut sc = fx::setup();
    let mut r = sc.take_shared<Registry<SUI>>();
    meta::open_passkey(&mut r, v::carol_pk(), v::d_open(), sc.ctx());
    ts::return_shared(r);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EPasskeyNeedsAssertion)]
fun passkey_account_needs_open_passkey() {
    let mut sc = fx::setup();
    let mut r = sc.take_shared<Registry<SUI>>();
    meta::open(&mut r, 6, v::dave_pk(), sc.ctx());
    ts::return_shared(r);
    sc.end();
}

/// ANTI-LOCK (R30/R62): chủ thể ký X trên contract 1 (account SUI) và Y trên contract 2 (account EUR).
/// X bị giữ lại; Y vẫn chạy, một op khác lane trên CÙNG contract 1 cũng chạy; sau đó X chạy.
#[test]
fun anti_lock_withheld_op_blocks_nothing() {
    let mut sc = funded();
    let x = v::a_pay_sui_0();   // giữ lại
    pay<EUR>(&mut sc, v::alice(), 70, 3, 0xa2, 0, @0x0, v::a_pay_eur_0(), 0);
    pay<SUI>(&mut sc, v::alice(), 10, 4, 0xa3, 0, @0x7e1, v::a_pay_sui_relayer(), 0);
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, x, 0);
    pay<SUI>(&mut sc, v::alice(), 50, 2, 0xa1, 1, @0x0, v::a_pay_sui_1(), 0);
    sc.next_tx(@0x7e1);
    assert!(fx::held<SUI>(&mut sc, BEEF) == 160 && fx::held<EUR>(&mut sc, BEEF) == 70);
    let a: Account<SUI> = fx::acct(&mut sc, v::alice());
    assert!(meta::balance(&a) == 840);
    ts::return_shared(a);
    sc.end();
}

#[test]
fun base64url_matches_rfc4648() {
    assert!(auth::base64url(&b"") == b"");
    assert!(auth::base64url(&b"f") == b"Zg");
    assert!(auth::base64url(&b"fooba") == b"Zm9vYmE");
    assert!(auth::base64url(&x"fbff") == b"-_8");
}
