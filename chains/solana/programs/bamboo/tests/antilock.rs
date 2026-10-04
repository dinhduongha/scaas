//! R30 trên Solana (L8, L12): thao tác khác contract của cùng chủ thể không chung khoá — không nonce chung, không
//! account GHI chung (trừ lane relayer); Config/Market/SubjectAccount chỉ đọc trên đường nóng.
mod common;

use std::collections::BTreeSet;

use anchor_lang::prelude::Pubkey;
use anchor_lang::solana_program::instruction::Instruction;
use bamboo::auth as A;
use common::flows::*;
use common::*;
use solana_signer::Signer;

fn writable(ix: &Instruction, lane: &Pubkey) -> BTreeSet<Pubkey> {
    ix.accounts.iter().filter(|m| m.is_writable && m.pubkey != *lane).map(|m| m.pubkey).collect()
}

fn readonly(ix: &Instruction, keys: &[Pubkey]) -> bool {
    keys.iter().all(|k| ix.accounts.iter().filter(|m| m.pubkey == *k).all(|m| !m.is_writable))
}

struct W {
    env: Env,
    alice: Ed,
    delegate: Ed,
    usd: Pubkey,
    eur: Pubkey,
    mandate: Pubkey,
    market: Pubkey,
}

fn setup() -> W {
    let mut env = Env::new();
    let (usd, eur) = (env.mint(TOKEN, 6), env.mint(TOKEN, 6));
    let (alice, delegate) = (Ed::new("alice"), Ed::new("delegate"));
    let kp = alice.kp();
    ok(env.send(&[env.open_ix(&alice.pubkey())], &[&kp]));
    env.fund(&alice.account(), &usd, TOKEN, 1_000);
    env.fund(&alice.account(), &eur, TOKEN, 1_000);
    let init = env.mandate_init(&alice.account(), [0x0d; 32], &delegate, vec![]);
    ok(env.mandate_open(&alice, &init));
    let mandate = mandate_addr(&alice.account(), [0x0d; 32]);
    ok(env.pay(&alice, &usd, TOKEN, &env.args(&mandate, 100, 9, 9, 0, 1000)));
    let fees = Ed::new("fees").pubkey();
    ok(env.list_market(&usd, &eur, 0, &fees));
    W { env, alice, delegate, usd, eur, mandate, market: market_addr(&usd, &eur) }
}

fn signed_pay(env: &Env, who: &Ed, mint: &Pubkey, args: &bamboo::PayArgs) -> Vec<Instruction> {
    let dg = env.metaop_digest(&who.account(), mint, A::OP_PAY, &who.pk(), args);
    let ix = env.pay_ix(&who.pk(), mint, TOKEN, ata(&who.account(), mint, &TOKEN), args, auth(A::KIND_RAW, 0, 0, 0));
    vec![ed_ix(&[who.sign(A::KIND_RAW, A::METAOP_LABEL, &dg)]), ix]
}

/// Bắt buộc (shared contract): X (pay tài sản A) bị giữ; Y (mandate_pay) và Z (cancel lệnh DEX) qua; rồi X qua.
#[test]
fn withheld_payment_blocks_nothing_else_of_the_subject() {
    let mut w = setup();
    let bob = Ed::new("bob").pubkey();
    let x = signed_pay(&w.env, &w.alice, &w.usd, &w.env.args(&bob, 7, 1, 0x11, 0, 1000));
    ok(w.env.mandate_pay(&w.delegate, &w.alice, &w.mandate, &w.usd, &w.env.args(&bob, 5, 2, 0x22, 0, 1000)));
    let o = order(&w.alice, &w.usd, &w.eur, 10, 9, 0);
    ok(w.env.cancel(&w.market, &o, &w.alice));
    ok(w.env.send(&x, &[]));
    assert_eq!(w.env.balance(&ata(&bob, &w.usd, &TOKEN)), 12);
}

/// Cùng Account, hai tài sản, hai lane: thứ tự gửi tuỳ ý.
#[test]
fn two_assets_two_lanes_in_any_order() {
    let mut w = setup();
    let bob = Ed::new("bob").pubkey();
    let x = signed_pay(&w.env, &w.alice, &w.usd, &w.env.args(&bob, 7, 1, 0xa1, 0, 1000));
    let y = signed_pay(&w.env, &w.alice, &w.eur, &w.env.args(&bob, 3, 2, 0xb2, 0, 1000));
    ok(w.env.send(&y, &[]));
    ok(w.env.send(&x, &[]));
    assert_eq!((w.env.balance(&ata(&bob, &w.usd, &TOKEN)), w.env.balance(&ata(&bob, &w.eur, &TOKEN))), (7, 3));
}

/// L12: tập account GHI của hai thao tác khác contract (trừ lane) rời nhau; Config/Market/SubjectAccount readonly.
#[test]
fn hot_path_write_sets_are_disjoint() {
    let w = setup();
    let env = &w.env;
    let lane = env.lane.pubkey();
    let bob = Ed::new("bob");
    let x = signed_pay(env, &w.alice, &w.usd, &env.args(&bob.pubkey(), 7, 1, 0xa1, 0, 1000)).pop().unwrap();
    let x2 = signed_pay(env, &w.alice, &w.eur, &env.args(&bob.pubkey(), 7, 1, 0xb2, 0, 1000)).pop().unwrap();
    // a different payee: the recipient's ATA is the one unavoidable shared write (spec §3.5)
    let carol = Ed::new("carol").pubkey();
    let y = env.mandate_pay_ix(&w.mandate, &w.usd, TOKEN, &env.args(&carol, 5, 2, 0x22, 0, 1000), auth(A::KIND_RAW, 0, 0, 0));
    let o = order(&w.alice, &w.usd, &w.eur, 10, 9, 0);
    let b = order(&bob, &w.eur, &w.usd, 9, 10, 0);
    let z = {
        // `cancel` instruction (accounts only)
        let h = env.order_hash(&w.market, &o);
        Instruction {
            program_id: bamboo::ID,
            accounts: anchor_lang::ToAccountMetas::to_account_metas(
                &bamboo::accounts::CancelSigned {
                    lane,
                    config: env.config(),
                    market: w.market,
                    subject: w.alice.account(),
                    fill: pda(&[b"fill", w.market.as_ref(), &h]),
                    instructions: IXS,
                    system_program: SYSTEM,
                },
                None,
            ),
            data: vec![],
        }
    };
    let s = env.settle_ix(&w.market, &o, &b, 10, 9, TOKEN, false, 0, 0, 1);
    let (wx, wx2, wy, wz) = (writable(&x, &lane), writable(&x2, &lane), writable(&y, &lane), writable(&z, &lane));
    assert!(wx.is_disjoint(&wy), "pay vs mandate_pay: {:?}", wx.intersection(&wy).collect::<Vec<_>>());
    assert!(wx.is_disjoint(&wz) && wy.is_disjoint(&wz), "cancel writes only its Fill");
    assert!(wx.is_disjoint(&wx2), "two assets of one Account");
    let fixed = [env.config(), w.market, w.alice.account(), account_of(&bob.pk())];
    for (name, ix) in [("pay", &x), ("pay2", &x2), ("mandate_pay", &y), ("cancel", &z), ("settle", &s)] {
        assert!(readonly(ix, &fixed), "{name} writes Config/Market/SubjectAccount");
    }
    assert_eq!(wz.len(), 1);
    println!("pay writes {} accounts besides the lane: {:?}", wx.len(), wx);
}

/// L7: SPL gửi tới ATA của Account trước khi nó tồn tại (Python vector test) và SAU khi tồn tại đều chi được.
#[test]
fn deposits_after_the_account_exists_are_spendable() {
    let mut w = setup();
    let bob = Ed::new("bob").pubkey();
    w.env.fund(&w.alice.account(), &w.usd, TOKEN, 50);
    ok(w.env.pay(&w.alice, &w.usd, TOKEN, &w.env.args(&bob, 950, 3, 3, 0, 1000)));
    assert_eq!(w.env.balance(&ata(&w.alice.account(), &w.usd, &TOKEN)), 0);
}
