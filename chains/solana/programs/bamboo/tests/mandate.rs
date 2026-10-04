//! Mandate (RS12-11): mở bằng chữ ký khoá Account, cấp vốn bằng một `pay` thường, trần lần/kỳ, payee, `pay_ref` một
//! lần, delegate thu hồi, khoá Account đóng và rút về.
mod common;

use bamboo::BambooError as E;
use common::flows::*;
use common::*;
use solana_signer::Signer;

struct M {
    env: Env,
    alice: Ed,
    delegate: Ed,
    usd: anchor_lang::prelude::Pubkey,
    mandate: anchor_lang::prelude::Pubkey,
    shop: Ed,
}

/// Alice mở mandate (payee: shop) và nạp 200 USD vào nó bằng `relay_pay` tới Mandate PDA.
fn setup() -> M {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let (alice, delegate, shop) = (Ed::new("alice"), Ed::new("delegate"), Ed::new("shop"));
    let kp = alice.kp();
    ok(env.send(&[env.open_ix(&alice.pubkey())], &[&kp]));
    env.fund(&alice.account(), &usd, TOKEN, 1_000);
    let init = env.mandate_init(&alice.account(), [0x0d; 32], &delegate, vec![shop.pubkey()]);
    ok(env.mandate_open(&alice, &init));
    let mandate = mandate_addr(&alice.account(), [0x0d; 32]);
    ok(env.pay(&alice, &usd, TOKEN, &env.args(&mandate, 200, 9, 9, 0, 1000)));
    assert_eq!(env.balance(&ata(&mandate, &usd, &TOKEN)), 200);
    M { env, alice, delegate, usd, mandate, shop }
}

#[test]
fn open_is_signed_by_an_account_key_and_validated() {
    let mut m = setup();
    let a = m.alice.account();
    // replayed open: key nonce moved on
    let init = m.env.mandate_init(&a, [0x0e; 32], &m.delegate, vec![]);
    let mut stale = init.clone();
    stale.nonce -= 1;
    expect_err(m.env.mandate_open(&m.alice, &stale), E::BadNonce);
    let mut bad = init.clone();
    bad.max_per_payment = 81;
    expect_err(m.env.mandate_open(&m.alice, &bad), E::BadMandate);
    let mut bad = init.clone();
    bad.delegate = Passkey::new("p").key();
    expect_err(m.env.mandate_open(&m.alice, &bad), E::BadKey);
    expect_err(m.env.mandate_open_as(&m.alice, &Ed::new("mallory"), &init), E::BadSignature);
    ok(m.env.mandate_open(&m.alice, &init));
}

#[test]
fn caps_payee_and_one_time_ref() {
    let mut m = setup();
    let (d, a, mint, md) = (&m.delegate, &m.alice, m.usd, m.mandate);
    let shop = m.shop.pubkey();
    let shop_ata = ata(&shop, &mint, &TOKEN);
    let mut env = m.env;
    expect_err(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 51, 1, 1, 0, 1000)), E::OverCap);
    expect_err(env.mandate_pay(d, a, &md, &mint, &env.args(&Ed::new("x").pubkey(), 5, 1, 1, 0, 1000)), E::PayeeNotAllowed);
    expect_err(env.mandate_pay(&Ed::new("x"), a, &md, &mint, &env.args(&shop, 5, 1, 1, 0, 1000)), E::BadSignature);
    ok(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 50, 1, 1, 0, 1000)));
    assert!(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 1, 1, 1, 0, 1000)).is_err(), "pay_ref used once");
    expect_err(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 31, 2, 1, 0, 1000)), E::OverCap);
    ok(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 30, 2, 1, 0, 1000)));
    assert_eq!(env.balance(&shop_ata), 80);
    // next period
    env.set_time(NOW + 100);
    ok(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 50, 3, 1, 0, 1000)));
    assert_eq!(env.balance(&shop_ata), 130);
    // mandate expiry (900) and signature expiry
    env.set_time(901);
    expect_err(env.mandate_pay(d, a, &md, &mint, &env.args(&shop, 1, 4, 1, 0, 1000)), E::Expired);
}

#[test]
fn delegate_revokes_and_the_account_closes_back() {
    let mut m = setup();
    let (d, a, mint, md) = (&m.delegate, &m.alice, m.usd, m.mandate);
    let shop = m.shop.pubkey();
    expect_err(m.env.mandate_revoke(a, a, &md), E::BadSignature);
    ok(m.env.mandate_revoke(d, a, &md));
    expect_err(m.env.mandate_pay(d, a, &md, &mint, &m.env.args(&shop, 5, 1, 1, 0, 1000)), E::Revoked);
    let src = ata(&md, &mint, &TOKEN);
    let dst = ata(&a.account(), &mint, &TOKEN);
    let before = m.env.balance(&dst);
    // a token account of someone else cannot be slipped in as the source
    let foreign = m.env.fund(&shop, &mint, TOKEN, 5);
    expect_err(m.env.mandate_close(a, &md, &[(foreign, mint, dst, TOKEN)]), E::BadAccounts);
    expect_err(m.env.mandate_close_as(a, &m.delegate, &md, &[(src, mint, dst, TOKEN)]), E::BadSignature);
    let lane = m.env.lane.pubkey();
    let lane_before = m.env.lamports(&lane);
    ok(m.env.mandate_close(a, &md, &[(src, mint, dst, TOKEN)]));
    assert_eq!(m.env.balance(&dst), before + 200);
    assert!(!m.env.exists(&md));
    assert!(m.env.lamports(&lane) > lane_before, "mandate rent back to its rent payer");
}
