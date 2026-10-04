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

// ------------------------------------------------------------------ vòng đời khoá (review M1), receive (M2)

const GUARDIAN: address = @0x9a;
const ANDROID: vector<u8> = b"android:apk-key-hash:Kq4X0bWx4mSs2N3uTjRL8tqxHH4m-sPGxBtcIu7b3QM";

fun manage(sc: &mut Scenario, owner: address, action: u8, scheme: u8, pk: vector<u8>, origin: vector<u8>, guardian: address, a: Auth) {
    let mut acct = fx::acct<SUI>(sc, owner);
    let clock = fx::clock_at(sc, 0);
    meta::manage(&mut acct, action, scheme, pk, vector[], origin, guardian, 1000, a, &clock);
    clock.destroy_for_testing();
    ts::return_shared(acct);
    let s = sc.ctx().sender();
    sc.next_tx(s);
}

fun as_guardian(sc: &mut Scenario, start: bool, now: u64) {
    sc.next_tx(GUARDIAN);
    let mut acct = fx::acct<SUI>(sc, v::alice());
    let clock = fx::clock_at(sc, now);
    if (start) meta::start_recovery(&mut acct, 1, v::alice3_pk(), vector[], vector[], &clock, sc.ctx())
    else meta::finish_recovery(&mut acct, &clock, sc.ctx());
    clock.destroy_for_testing();
    ts::return_shared(acct);
    sc.next_tx(@0x7e1);
}

/// Xoay khoá: alice thêm alice2, alice2 xoá alice; alice2 ký được, chữ ký của khoá cũ thì không.
#[test]
fun rotate_key_keeps_the_account() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 0, 0, v::alice2_pk(), vector[], @0x0, v::k_a_add_a2());
    manage(&mut sc, v::alice(), 1, 0, v::alice_pk(), vector[], @0x0, v::k_a2_rm_a());
    let a = fx::acct<SUI>(&mut sc, v::alice());
    assert!(meta::key_count(&a) == 1 && meta::key_nonce(&a) == 2);
    ts::return_shared(a);
    sc.next_tx(@0x7e1);
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a2_pay_sui(), 0);
    assert!(fx::held<SUI>(&mut sc, BEEF) == 100);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun removed_key_no_longer_signs() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 0, 0, v::alice2_pk(), vector[], @0x0, v::k_a_add_a2());
    manage(&mut sc, v::alice(), 1, 0, v::alice_pk(), vector[], @0x0, v::k_a2_rm_a());
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a_pay_sui_0(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun key_op_is_not_replayed() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 0, 0, v::alice2_pk(), vector[], @0x0, v::k_a_add_a2());
    manage(&mut sc, v::alice(), 0, 0, v::alice2_pk(), vector[], @0x0, v::k_a_add_a2());
    sc.end();
}

#[test, expected_failure(abort_code = meta::ELastKey)]
fun last_key_cannot_be_removed() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 1, 0, v::alice_pk(), vector[], @0x0, v::k_a_rm_a());
    sc.end();
}

/// Origin mới (app Android) thêm bằng chữ ký passkey từ origin cũ; sau đó assertion từ Android ký được.
#[test]
fun passkey_origin_is_added_by_the_key() {
    let mut sc = funded();
    manage(&mut sc, v::dave(), 2, 0, vector[], ANDROID, @0x0, v::k_d_add_android());
    let a = fx::acct<SUI>(&mut sc, v::dave());
    assert!(meta::has_origin(&a, ANDROID) && meta::has_origin(&a, b"https://pay.bamboo.test"));
    ts::return_shared(a);
    sc.next_tx(@0x7e1);
    pay<SUI>(&mut sc, v::dave(), 100, 7, 0xd1, 0, @0x0, v::d_pay_sui_android(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::EBadSignature)]
fun passkey_from_an_unlisted_origin_is_refused() {
    let mut sc = funded();
    pay<SUI>(&mut sc, v::dave(), 100, 7, 0xd1, 0, @0x0, v::d_pay_sui_android(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::ELastKey)]
fun passkey_account_keeps_one_origin() {
    let mut sc = funded();
    manage(&mut sc, v::dave(), 3, 0, vector[], b"https://pay.bamboo.test", @0x0, v::k_d_rm_origin());
    sc.end();
}

/// Guardian khôi phục sau `RECOVERY_DELAY` (2 ngày, như `SubjectAccount` EVM): khoá mới ký được.
#[test]
fun guardian_recovers_after_the_delay() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 4, 0, vector[], vector[], GUARDIAN, v::k_a_guardian());
    as_guardian(&mut sc, true, 0);
    as_guardian(&mut sc, false, 172_800);
    pay<SUI>(&mut sc, v::alice(), 100, 1, 0xa1, 0, @0x0, v::a3_pay_sui(), 0);
    sc.end();
}

#[test, expected_failure(abort_code = meta::ERecovery)]
fun recovery_waits_for_the_delay() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 4, 0, vector[], vector[], GUARDIAN, v::k_a_guardian());
    as_guardian(&mut sc, true, 0);
    as_guardian(&mut sc, false, 172_799);
    sc.end();
}

#[test, expected_failure(abort_code = meta::ERecovery)]
fun a_key_cancels_the_recovery() {
    let mut sc = funded();
    manage(&mut sc, v::alice(), 4, 0, vector[], vector[], GUARDIAN, v::k_a_guardian());
    as_guardian(&mut sc, true, 0);
    manage(&mut sc, v::alice(), 5, 0, vector[], vector[], @0x0, v::k_a_cancel());
    as_guardian(&mut sc, false, 172_800);
    sc.end();
}

#[test, expected_failure(abort_code = meta::ENotGuardian)]
fun only_the_guardian_recovers() {
    let mut sc = funded();
    as_guardian(&mut sc, true, 0);   // chưa đặt guardian
    sc.end();
}

/// Coin gửi thẳng tới id account (transfer-to-object) ⇒ kéo vào số dư; coin khác loại ⇒ chuyển cho chủ.
#[test]
fun coins_sent_to_the_account_id_are_not_stuck() {
    let mut sc = funded();
    transfer::public_transfer(sui::coin::mint_for_testing<SUI>(5, sc.ctx()), v::a_sui_account());
    transfer::public_transfer(sui::coin::mint_for_testing<EUR>(7, sc.ctx()), v::a_sui_account());
    sc.next_tx(@0x7e1);
    let mut a = fx::acct<SUI>(&mut sc, v::alice());
    let id = object::id(&a);
    meta::receive(&mut a, ts::most_recent_receiving_ticket<sui::coin::Coin<SUI>>(&id));
    meta::forward(&mut a, ts::most_recent_receiving_ticket<sui::coin::Coin<EUR>>(&id));
    assert!(meta::balance(&a) == 1005);
    ts::return_shared(a);
    sc.next_tx(@0x7e1);
    assert!(fx::held<EUR>(&mut sc, v::alice()) == 7);
    sc.end();
}
