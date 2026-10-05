//! DEX (RS12-12): giá, overfill, FOK/IOC, phí bật/tắt + `max_fee_ppm`, huỷ (kể cả lệnh chưa khớp), MinNonce theo
//! market, hai market độc lập, batch 2 cặp, self-trade, admin, sweep.
mod common;

use anchor_lang::prelude::Pubkey;
use bamboo::auth as A;
use bamboo::dex::{FOK, IOC};
use bamboo::BambooError as E;
use common::flows::*;
use common::*;
use solana_keypair::Keypair;
use solana_signer::Signer;

struct D {
    env: Env,
    alice: Ed,
    bob: Ed,
    usd: Pubkey,
    eur: Pubkey,
    market: Pubkey,
    fees: Pubkey,
}

fn setup(fee_ppm: u32) -> D {
    let mut env = Env::new();
    let (usd, eur) = (env.mint(TOKEN, 6), env.mint(TOKEN, 6));
    let (alice, bob) = (Ed::new("alice"), Ed::new("bob"));
    for k in [&alice, &bob] {
        let kp = k.kp();
        ok(env.send(&[env.open_ix(&k.pubkey())], &[&kp]));
    }
    env.fund(&alice.account(), &usd, TOKEN, 1_000);
    env.fund(&bob.account(), &eur, TOKEN, 1_000);
    let fees = Keypair::new().pubkey();
    ok(env.list_market(&usd, &eur, fee_ppm, &fees));
    D { env, alice, bob, usd, eur, market: market_addr(&usd, &eur), fees }
}

#[test]
fn admin_lists_and_caps_fees() {
    let mut d = setup(0);
    let other = d.env.mint(TOKEN, 6);
    expect_err(d.env.list_market(&other, &other, 0, &d.fees), E::BadMarket);
    let gbp = d.env.mint(TOKEN, 6);
    expect_err(d.env.list_market(&d.usd, &gbp, 10_001, &d.fees), E::FeeTooHigh);
    let lane = d.env.lane.insecure_clone();
    expect_err(d.env.set_market(&lane, &d.market, 0, false, &d.fees), E::NotAdmin);
    let admin = d.env.admin.insecure_clone();
    expect_err(d.env.set_market(&admin, &d.market, 10_001, true, &d.fees), E::FeeTooHigh);
    ok(d.env.set_market(&admin, &d.market, 10_000, false, &d.fees));
    let a = order(&d.alice, &d.usd, &d.eur, 100, 90, 0);
    let b = order(&d.bob, &d.eur, &d.usd, 90, 100, 0);
    expect_err(d.env.settle(&d.market, &a, &d.alice, &b, &d.bob, 100, 90, false), E::MarketDisabled);
}

#[test]
fn settle_moves_both_legs_at_the_signed_prices() {
    let mut d = setup(0);
    let (alice, bob, usd, eur, mk) = (&d.alice, &d.bob, d.usd, d.eur, d.market);
    let a = order(alice, &usd, &eur, 100, 90, 0);
    let b = order(bob, &eur, &usd, 90, 100, 0);
    // A would get less than its limit price
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 100, 89, false), E::PriceLimit);
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 0, 0, false), E::ZeroAmount);
    // a signature by the wrong key / over another order
    expect_err(d.env.settle(&mk, &a, bob, &b, bob, 100, 90, false), E::BadSignature);
    ok(d.env.settle(&mk, &a, alice, &b, bob, 60, 54, false));
    assert_eq!(d.env.balance(&ata(&bob.account(), &usd, &TOKEN)), 60);
    assert_eq!(d.env.balance(&ata(&alice.account(), &eur, &TOKEN)), 54);
    ok(d.env.settle(&mk, &a, alice, &b, bob, 40, 36, false));
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 10, 9, false), E::Overfill);
    assert_eq!(d.env.balance(&ata(&alice.account(), &usd, &TOKEN)), 900);
    // same account on both sides
    let a2 = order(alice, &usd, &eur, 10, 9, 1);
    let mut b2 = order(alice, &eur, &usd, 9, 10, 2);
    b2.maker = alice.pk();
    assert!(d.env.settle(&mk, &a2, alice, &b2, alice, 10, 9, false).is_err(), "self trade");
    // taker-restricted order
    let mut c = order(alice, &usd, &eur, 10, 9, 3);
    c.taker = Ed::new("carol").pk();
    let b3 = order(bob, &eur, &usd, 9, 10, 4);
    expect_err(d.env.settle(&mk, &c, alice, &b3, bob, 10, 9, false), E::WrongTaker);
    // expired
    d.env.set_time(901);
    expect_err(d.env.settle(&mk, &a2, alice, &b3, bob, 10, 9, false), E::Expired);
}

#[test]
fn fok_and_ioc() {
    let mut d = setup(0);
    let (alice, bob, usd, eur, mk) = (&d.alice, &d.bob, d.usd, d.eur, d.market);
    let mut a = order(alice, &usd, &eur, 100, 90, 0);
    a.flags = FOK;
    let b = order(bob, &eur, &usd, 900, 1000, 0);
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 50, 45, false), E::FillOrKill);
    ok(d.env.settle(&mk, &a, alice, &b, bob, 100, 90, false));
    let mut c = order(alice, &usd, &eur, 100, 90, 1);
    c.flags = IOC;
    ok(d.env.settle(&mk, &c, alice, &b, bob, 30, 27, false));
    expect_err(d.env.settle(&mk, &c, alice, &b, bob, 30, 27, false), E::Overfill);
}

#[test]
fn fees_go_to_the_market_vault_within_the_signed_cap() {
    let mut d = setup(1_000);
    let (alice, bob, usd, eur, mk) = (&d.alice, &d.bob, d.usd, d.eur, d.market);
    let mut a = order(alice, &usd, &eur, 1000, 900, 0);
    a.max_fee_ppm = 999;
    let b = order(bob, &eur, &usd, 900, 1000, 0);
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 1000, 900, true), E::FeeTooHigh);
    a.max_fee_ppm = 1_000;
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 1000, 900, false), E::BadAccounts);
    ok(d.env.settle(&mk, &a, alice, &b, bob, 1000, 900, true));
    assert_eq!(d.env.balance(&ata(&bob.account(), &usd, &TOKEN)), 999);
    assert_eq!(d.env.balance(&ata(&mk, &usd, &TOKEN)), 1);
    assert_eq!(d.env.balance(&ata(&alice.account(), &eur, &TOKEN)), 900 - 0);
    assert_eq!(d.env.balance(&ata(&mk, &eur, &TOKEN)), 0, "fee on 900 at 1000 ppm rounds down to 0");
    // sweep: the vault (and anything sent to the market by mistake) goes to the fee recipient
    let fees = d.fees;
    ok(d.env.sweep(&mk, &ata(&mk, &usd, &TOKEN), &usd, &fees));
    assert_eq!(d.env.balance(&ata(&fees, &usd, &TOKEN)), 1);
    let stray = d.env.side_account(&mk, &usd, TOKEN, 7);
    ok(d.env.sweep(&mk, &stray, &usd, &fees));
    assert_eq!(d.env.balance(&ata(&fees, &usd, &TOKEN)), 8);
    expect_err(d.env.sweep(&mk, &stray, &usd, &Keypair::new().pubkey()), E::WrongRecipient);
}

/// Lệnh chưa từng khớp bị huỷ thì không bao giờ settle được; `Fill` giữ hạn của lệnh (không prune sớm).
#[test]
fn cancel_even_before_any_fill() {
    let mut d = setup(0);
    let (alice, bob, usd, eur, mk) = (&d.alice, &d.bob, d.usd, d.eur, d.market);
    let a = order(alice, &usd, &eur, 100, 90, 0);
    let b = order(bob, &eur, &usd, 90, 100, 0);
    expect_err(d.env.cancel(&mk, &a, bob), E::BadSignature);
    ok(d.env.cancel(&mk, &a, alice));
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 100, 90, false), E::Overfill);
    let fill_addr = pda(&[b"fill", mk.as_ref(), &d.env.order_hash(&mk, &a)]);
    let fill: bamboo::state::Fill = d.env.account(&fill_addr).unwrap();
    assert_eq!((fill.filled, fill.valid_until), (100, 900));
    // prunable only once the order itself expired; the order then cannot settle anyway
    let lane = d.env.lane.pubkey();
    let prune = anchor_lang::solana_program::instruction::Instruction {
        program_id: bamboo::ID,
        accounts: anchor_lang::ToAccountMetas::to_account_metas(&bamboo::accounts::Prune { target: fill_addr, rent_payer: lane }, None),
        data: anchor_lang::InstructionData::data(&bamboo::instruction::Prune {}),
    };
    expect_err(d.env.send(&[prune.clone()], &[]), E::TooEarly);
    d.env.set_time(901);
    ok(d.env.send(&[prune], &[]));
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 100, 90, false), E::Expired);
}

/// MinNonce theo (Account, market): huỷ hàng loạt ở market này không đụng market khác.
#[test]
fn min_nonce_is_per_market() {
    let mut d = setup(0);
    let (alice, bob, usd, eur, mk) = (&d.alice, &d.bob, d.usd, d.eur, d.market);
    let gbp = d.env.mint(TOKEN, 6);
    d.env.fund(&bob.account(), &gbp, TOKEN, 1_000);
    let fees = d.fees;
    ok(d.env.list_market(&usd, &gbp, 0, &fees));
    let mk2 = market_addr(&usd, &gbp);
    ok(d.env.invalidate(&mk, alice, 5));
    expect_err(d.env.invalidate(&mk, alice, 5), E::BadNonce);
    let a = order(alice, &usd, &eur, 10, 9, 4);
    let b = order(bob, &eur, &usd, 9, 10, 0);
    expect_err(d.env.settle(&mk, &a, alice, &b, bob, 10, 9, false), E::BadNonce);
    let a5 = order(alice, &usd, &eur, 10, 9, 5);
    ok(d.env.settle(&mk, &a5, alice, &b, bob, 10, 9, false));
    let a2 = order(alice, &usd, &gbp, 10, 9, 4);
    let b2 = order(bob, &gbp, &usd, 9, 10, 0);
    ok(d.env.settle(&mk2, &a2, alice, &b2, bob, 10, 9, false));
    // an order for one market cannot be settled in another
    let a3 = order(alice, &usd, &gbp, 10, 9, 6);
    let b3 = order(bob, &gbp, &usd, 9, 10, 1);
    expect_err(d.env.settle(&mk, &a3, alice, &b3, bob, 10, 9, false), E::BadMarket);
}

/// Hai cặp trong một tx (một precompile 4 chữ ký): nguyên tử theo tx.
#[test]
fn two_pairs_in_one_transaction() {
    let mut d = setup(0);
    let (alice, bob, usd, eur, mk) = (&d.alice, &d.bob, d.usd, d.eur, d.market);
    let (a1, b1) = (order(alice, &usd, &eur, 10, 9, 0), order(bob, &eur, &usd, 9, 10, 0));
    let (a2, b2) = (order(alice, &usd, &eur, 20, 18, 1), order(bob, &eur, &usd, 18, 20, 1));
    let s = |env: &Env, o: &bamboo::Order, k: &Ed| k.sign(A::KIND_RAW, A::ORDER_LABEL, &env.order_hash(&mk, o));
    let sigs = [s(&d.env, &a1, alice), s(&d.env, &b1, bob), s(&d.env, &a2, alice), s(&d.env, &b2, bob)];
    let i1 = d.env.settle_ix(&mk, &a1, &b1, 10, 9, TOKEN, false, 1, 0, 1);
    let i2 = d.env.settle_ix(&mk, &a2, &b2, 20, 18, TOKEN, false, 1, 2, 3);
    let m = ok(d.env.send(&[cu(1_400_000), ed_ix(&sigs), i1.clone(), i2], &[]));
    assert_eq!(d.env.balance(&ata(&bob.account(), &usd, &TOKEN)), 30);
    println!("two-pair settle: {} CU", m.compute_units_consumed);
    // atomic: a failing second pair rolls the first back
    let (a3, b3) = (order(alice, &usd, &eur, 10, 9, 2), order(bob, &eur, &usd, 9, 10, 2));
    let sigs = [s(&d.env, &a3, alice), s(&d.env, &b3, bob), s(&d.env, &a1, alice), s(&d.env, &b1, bob)];
    let i3 = d.env.settle_ix(&mk, &a3, &b3, 10, 9, TOKEN, false, 1, 0, 1);
    let i4 = d.env.settle_ix(&mk, &a1, &b1, 10, 9, TOKEN, false, 1, 2, 3);
    expect_err(d.env.send(&[cu(1_400_000), ed_ix(&sigs), i3, i4], &[]), E::Overfill);
    assert_eq!(d.env.balance(&ata(&bob.account(), &usd, &TOKEN)), 30);
}
