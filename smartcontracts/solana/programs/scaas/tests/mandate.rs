//! Mandate (RS12-11): mở bằng chữ ký khoá Account, cấp vốn bằng một `pay` thường, trần lần/kỳ, payee, `pay_ref` một
//! lần, delegate thu hồi, khoá Account đóng và rút về.
mod common;

use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::{InstructionData, ToAccountMetas};
use scaas::ScaasError as E;
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
    let init = env.mandate_init(&alice.account(), [0x0d; 32], &usd, &delegate, vec![shop.pubkey()]);
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
    let init = m.env.mandate_init(&a, [0x0e; 32], &m.usd, &m.delegate, vec![]);
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

/// Review M2: a mandate pays ONE mint, named in the signed `MandateInit`; caps are in that mint's units.
#[test]
fn a_mandate_pays_only_its_own_mint() {
    let mut m = setup();
    let eur = m.env.mint(TOKEN, 0);
    m.env.fund(&m.alice.account(), &eur, TOKEN, 1_000);
    ok(m.env.pay(&m.alice, &eur, TOKEN, &m.env.args(&m.mandate, 500, 8, 9, 1, 1000)));
    let shop = m.shop.pubkey();
    let (d, a, md) = (&m.delegate, &m.alice, m.mandate);
    expect_err(m.env.mandate_pay(d, a, &md, &eur, &m.env.args(&shop, 50, 1, 1, 0, 1000)), E::WrongMint);
    ok(m.env.mandate_pay(d, a, &md, &m.usd, &m.env.args(&shop, 50, 1, 1, 0, 1000)));
    assert_eq!(m.env.account::<scaas::state::Mandate>(&md).unwrap().asset, m.usd);
}

/// Review L4: closing and reopening at the same seed starts a new generation — delegate ops (and a revoke) signed for
/// the old one never run on the new one.
#[test]
fn reopening_a_seed_does_not_revive_old_delegate_ops() {
    let mut m = setup();
    let (a, md, mint) = (m.alice.account(), m.mandate, m.usd);
    let shop = m.shop.pubkey();
    let g1 = m.env.generation(&md);
    let stale = scaas::PayArgs { nonce: g1, ..m.env.args(&shop, 20, 7, 1, 0, 1000) };
    ok(m.env.mandate_revoke(&m.delegate, &m.alice, &md));
    let (src, dst) = (ata(&md, &mint, &TOKEN), ata(&a, &mint, &TOKEN));
    ok(m.env.mandate_close(&m.alice, &md, &[(src, mint, dst, TOKEN)]));
    let init = m.env.mandate_init(&a, [0x0d; 32], &mint, &m.delegate, vec![shop]);
    ok(m.env.mandate_open(&m.alice, &init));
    let g2 = m.env.generation(&md);
    assert!(g2 > g1);
    ok(m.env.pay(&m.alice, &mint, TOKEN, &m.env.args(&md, 100, 10, 9, 1, 1000)));
    expect_err(m.env.mandate_pay_signed(&m.delegate, &m.alice, &md, &mint, &stale), E::BadNonce);
    expect_err(m.env.mandate_revoke_gen(&m.delegate, &m.alice, &md, g1), E::BadSignature);
    ok(m.env.mandate_pay(&m.delegate, &m.alice, &md, &mint, &m.env.args(&shop, 20, 7, 1, 0, 1000)));
    assert_eq!(m.env.balance(&ata(&shop, &mint, &TOKEN)), 20);
}

/// Review C1 (mandate): two delegate ops with the same `pay_ref` pay once — before the `MandateRef` is pruned (it
/// exists) and after (the other op expired, prune waits `valid_until + PRUNE_DELAY_S`).
#[test]
fn two_ops_with_one_pay_ref_pay_once_before_and_after_prune() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let (alice, delegate, shop) = (Ed::new("alice"), Ed::new("delegate"), Ed::new("shop").pubkey());
    let kp = alice.kp();
    ok(env.send(&[env.open_ix(&alice.pubkey())], &[&kp]));
    env.fund(&alice.account(), &usd, TOKEN, 1_000);
    let mut init = env.mandate_init(&alice.account(), [0x0d; 32], &usd, &delegate, vec![]);
    init.expiry = u64::MAX / 2;
    init.period_s = 1;
    ok(env.mandate_open(&alice, &init));
    let md = mandate_addr(&alice.account(), [0x0d; 32]);
    ok(env.pay(&alice, &usd, TOKEN, &env.args(&md, 200, 9, 9, 0, 1000)));
    let op1 = env.args(&shop, 10, 5, 1, 0, 900);
    let op2 = env.args(&shop, 10, 5, 1, 0, 900 + scaas::PRUNE_DELAY_S as u64);
    ok(env.mandate_pay(&delegate, &alice, &md, &usd, &op1));
    assert!(env.mandate_pay(&delegate, &alice, &md, &usd, &op2).is_err(), "MandateRef exists");
    let mref = pda(&[b"mref", md.as_ref(), &[5; 32]]);
    let lane = env.lane.pubkey();
    let prune = Instruction {
        program_id: scaas::ID,
        accounts: scaas::accounts::Prune { target: mref, rent_payer: lane }.to_account_metas(None),
        data: scaas::instruction::Prune {}.data(),
    };
    env.set_time(900 + scaas::PRUNE_DELAY_S);
    expect_err(env.send(&[prune.clone()], &[]), E::TooEarly);
    env.set_time(901 + scaas::PRUNE_DELAY_S);
    ok(env.send(&[prune], &[]));
    expect_err(env.mandate_pay(&delegate, &alice, &md, &usd, &op2), E::Expired);
    assert_eq!(env.balance(&ata(&shop, &usd, &TOKEN)), 10, "paid exactly once");
}

/// Review L5 (mandate): a token account is not a payee wallet.
#[test]
fn a_mandate_does_not_pay_a_token_account() {
    let mut env = Env::new();
    let usd = env.mint(TOKEN, 6);
    let (alice, delegate) = (Ed::new("alice"), Ed::new("delegate"));
    let kp = alice.kp();
    ok(env.send(&[env.open_ix(&alice.pubkey())], &[&kp]));
    env.fund(&alice.account(), &usd, TOKEN, 1_000);
    let init = env.mandate_init(&alice.account(), [0x0d; 32], &usd, &delegate, vec![]);
    ok(env.mandate_open(&alice, &init));
    let md = mandate_addr(&alice.account(), [0x0d; 32]);
    ok(env.pay(&alice, &usd, TOKEN, &env.args(&md, 200, 9, 9, 0, 1000)));
    let shop_ata = env.fund(&Ed::new("shop").pubkey(), &usd, TOKEN, 0);
    expect_err(env.mandate_pay(&delegate, &alice, &md, &usd, &env.args(&shop_ata, 5, 1, 1, 0, 1000)), E::TokenAccountRecipient);
}
