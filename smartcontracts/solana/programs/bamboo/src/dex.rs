//! DEX (R35, spec §5.3 — RS12-12): sổ lệnh off-chain, thanh toán on-chain kiểm CẢ HAI chữ ký trong tx; `Fill` PDA
//! mỗi lệnh; phí ppm theo market vào vault (ATA của Market); huỷ bằng chữ ký tạo/đóng `Fill`; `MinNonce` theo
//! (Account, market). Một cặp mỗi instruction `settle`; batch = nhiều `settle` trong một tx (nguyên tử theo tx).
use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::account::INSTRUCTIONS_ID;
use crate::auth::{self, Auth, CANCEL_LABEL, MINNONCE_LABEL, ORDER_LABEL};
use crate::state::*;
use crate::util;
use crate::{BambooError, Matched, OrderFilled};

pub const FOK: u8 = 1;
pub const IOC: u8 = 2;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Order {
    pub maker: [u8; 32],
    pub taker: [u8; 32],
    pub sell_mint: Pubkey,
    pub buy_mint: Pubkey,
    pub sell_amount: u64,
    pub buy_amount: u64,
    pub nonce: u64,
    pub expiry: u64,
    pub max_fee_ppm: u32,
    pub flags: u8,
    pub relayer: [u8; 32],
}

impl Order {
    /// `"bamboo.order.v1" ‖ network ‖ market ‖ maker ‖ taker ‖ sell_mint ‖ buy_mint ‖ sell_amount ‖ buy_amount ‖ nonce
    /// ‖ expiry ‖ max_fee_ppm (u32) ‖ flags ‖ relayer` (LE).
    pub fn bytes(&self, network: &[u8; 32], market: &Pubkey) -> Vec<u8> {
        let mut b = Vec::with_capacity(300);
        b.extend_from_slice(ORDER_LABEL.as_bytes());
        b.extend_from_slice(network);
        b.extend_from_slice(market.as_ref());
        b.extend_from_slice(&self.maker);
        b.extend_from_slice(&self.taker);
        b.extend_from_slice(self.sell_mint.as_ref());
        b.extend_from_slice(self.buy_mint.as_ref());
        for v in [self.sell_amount, self.buy_amount, self.nonce, self.expiry] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.extend_from_slice(&self.max_fee_ppm.to_le_bytes());
        b.push(self.flags);
        b.extend_from_slice(&self.relayer);
        b
    }

    pub fn hash(&self, network: &[u8; 32], market: &Pubkey) -> [u8; 32] {
        auth::sha256(&[&self.bytes(network, market)])
    }
}

// ------------------------------------------------------------------ admin

#[derive(Accounts)]
pub struct ListMarket<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin @ BambooError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(init, payer = admin, space = 8 + Market::INIT_SPACE,
              seeds = [b"mkt", base_mint.key().as_ref(), quote_mint.key().as_ref()], bump)]
    pub market: Account<'info, Market>,
    pub base_mint: InterfaceAccount<'info, Mint>,
    pub quote_mint: InterfaceAccount<'info, Mint>,
    pub system_program: Program<'info, System>,
}

pub fn list_market(ctx: Context<ListMarket>, fee_ppm: u32, fee_recipient: Pubkey) -> Result<()> {
    require!(fee_ppm <= MAX_FEE_PPM, BambooError::FeeTooHigh);
    let (base, quote) = (ctx.accounts.base_mint.key(), ctx.accounts.quote_mint.key());
    require_keys_neq!(base, quote, BambooError::BadMarket);
    let m = &mut ctx.accounts.market;
    m.base_mint = base;
    m.quote_mint = quote;
    m.fee_ppm = fee_ppm;
    m.enabled = true;
    m.fee_recipient = fee_recipient;
    m.bump = ctx.bumps.market;
    Ok(())
}

#[derive(Accounts)]
pub struct SetMarket<'info> {
    pub admin: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump, has_one = admin @ BambooError::NotAdmin)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
    pub market: Account<'info, Market>,
}

pub fn set_market(ctx: Context<SetMarket>, fee_ppm: u32, enabled: bool, fee_recipient: Pubkey) -> Result<()> {
    require!(fee_ppm <= MAX_FEE_PPM, BambooError::FeeTooHigh);
    let m = &mut ctx.accounts.market;
    m.fee_ppm = fee_ppm;
    m.enabled = enabled;
    m.fee_recipient = fee_recipient;
    Ok(())
}

// ------------------------------------------------------------------ settle

#[event_cpi]
#[derive(Accounts)]
#[instruction(a: Order, b: Order, hash_a: [u8; 32], hash_b: [u8; 32])]
pub struct Settle<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Box<Account<'info, Config>>,
    #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
    pub market: Box<Account<'info, Market>>,
    #[account(seeds = [b"acct", a.maker.as_ref()], bump = subject_a.bump)]
    pub subject_a: Box<Account<'info, SubjectAccount>>,
    #[account(seeds = [b"acct", b.maker.as_ref()], bump = subject_b.bump)]
    pub subject_b: Box<Account<'info, SubjectAccount>>,
    #[account(init_if_needed, payer = lane, space = 8 + Fill::INIT_SPACE,
              seeds = [b"fill", market.key().as_ref(), hash_a.as_ref()], bump)]
    pub fill_a: Box<Account<'info, Fill>>,
    #[account(init_if_needed, payer = lane, space = 8 + Fill::INIT_SPACE,
              seeds = [b"fill", market.key().as_ref(), hash_b.as_ref()], bump)]
    pub fill_b: Box<Account<'info, Fill>>,
    /// CHECK: MinNonce PDA of (market, subject_a); may not exist (then 0).
    #[account(seeds = [b"minnonce", market.key().as_ref(), subject_a.key().as_ref()], bump)]
    pub min_nonce_a: UncheckedAccount<'info>,
    /// CHECK: MinNonce PDA of (market, subject_b).
    #[account(seeds = [b"minnonce", market.key().as_ref(), subject_b.key().as_ref()], bump)]
    pub min_nonce_b: UncheckedAccount<'info>,
    #[account(mut, token::mint = mint_x, token::authority = subject_a, token::token_program = token_program_x)]
    pub a_src: Box<InterfaceAccount<'info, TokenAccount>>,
    #[account(mut, token::mint = mint_y, token::authority = subject_b, token::token_program = token_program_y)]
    pub b_src: Box<InterfaceAccount<'info, TokenAccount>>,
    /// CHECK: ATA(subject_a, mint_y) — created idempotently, derivation checked by the ATA program.
    #[account(mut)]
    pub a_dst: UncheckedAccount<'info>,
    /// CHECK: ATA(subject_b, mint_x).
    #[account(mut)]
    pub b_dst: UncheckedAccount<'info>,
    /// CHECK: fee vault ATA(market, mint_x); only when the market charges a fee (else not written — L8).
    #[account(mut)]
    pub vault_x: Option<UncheckedAccount<'info>>,
    /// CHECK: fee vault ATA(market, mint_y).
    #[account(mut)]
    pub vault_y: Option<UncheckedAccount<'info>>,
    #[account(address = a.sell_mint @ BambooError::BadMarket)]
    pub mint_x: Box<InterfaceAccount<'info, Mint>>,
    #[account(address = a.buy_mint @ BambooError::BadMarket)]
    pub mint_y: Box<InterfaceAccount<'info, Mint>>,
    pub token_program_x: Interface<'info, TokenInterface>,
    pub token_program_y: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
}

fn min_nonce(info: &AccountInfo) -> Result<u64> {
    if *info.owner != crate::ID || info.data_is_empty() {
        return Ok(0);
    }
    Ok(MinNonce::try_deserialize(&mut &info.try_borrow_data()?[..])?.min_nonce)
}

#[allow(clippy::too_many_arguments)]
fn check_order(
    o: &Order,
    hash: &[u8; 32],
    network: &[u8; 32],
    market: &Market,
    market_key: &Pubkey,
    subject: &SubjectAccount,
    counterparty: &[u8; 32],
    lane: &Pubkey,
    min_nonce: u64,
    auth: &Auth,
    ix_sysvar: &AccountInfo,
) -> Result<()> {
    require!(o.hash(network, market_key) == *hash, BambooError::BadOrder);
    require!(o.maker == subject.owner, BambooError::BadOrder);
    require!(o.taker == [0; 32] || o.taker == *counterparty, BambooError::WrongTaker);
    require!(o.relayer == [0; 32] || o.relayer == lane.to_bytes(), BambooError::WrongRelayer);
    require!(o.flags & !(FOK | IOC) == 0 && o.sell_amount > 0 && o.buy_amount > 0, BambooError::BadOrder);
    util::check_deadline(o.expiry)?;
    require!(o.nonce >= min_nonce, BambooError::BadNonce);
    require!(o.max_fee_ppm >= market.fee_ppm, BambooError::FeeTooHigh);
    subject.check_policy()?;
    auth::verify(ix_sysvar, auth, &subject.keys, &subject.origins, ORDER_LABEL, hash, None)
}

fn apply_fill(f: &mut Fill, o: &Order, fill: u64, lane: Pubkey) -> Result<()> {
    if f.rent_payer == Pubkey::default() {
        f.rent_payer = lane;
        f.valid_until = o.expiry.min(i64::MAX as u64) as i64;
    }
    let after = f.filled.checked_add(fill).ok_or(BambooError::Overflow)?;
    require!(after <= o.sell_amount, BambooError::Overfill);
    require!(o.flags & FOK == 0 || after == o.sell_amount, BambooError::FillOrKill);
    f.filled = if o.flags & IOC != 0 { o.sell_amount } else { after };
    Ok(())
}

fn fee(amount: u64, ppm: u32) -> u64 {
    (amount as u128 * ppm as u128 / 1_000_000) as u64
}

/// A bán `fill_a` mint X lấy `fill_b` mint Y của B. Giá nhân chéo u128 theo lệnh đã ký; `fill_*` do relayer chọn nhưng
/// bị chặn bởi giá và lượng đã ký (L3). Phí lấy trên phần mỗi bên NHẬN, ≤ `max_fee_ppm` mỗi lệnh.
#[allow(clippy::too_many_arguments)]
pub fn settle(
    ctx: Context<Settle>,
    a: Order,
    b: Order,
    hash_a: [u8; 32],
    hash_b: [u8; 32],
    fill_a: u64,
    fill_b: u64,
    auth_a: Auth,
    auth_b: Auth,
) -> Result<()> {
    let x = &ctx.accounts;
    let (m, mk, net, lane) = (&x.market, x.market.key(), x.config.network, x.lane.key());
    require!(m.enabled, BambooError::MarketDisabled);
    require!(b.sell_mint == a.buy_mint && b.buy_mint == a.sell_mint, BambooError::BadMarket);
    let pair = (a.sell_mint, a.buy_mint);
    require!(pair == (m.base_mint, m.quote_mint) || pair == (m.quote_mint, m.base_mint), BambooError::BadMarket);
    require_keys_neq!(x.subject_a.key(), x.subject_b.key(), BambooError::SelfTrade);
    let (sa, sb) = (&x.subject_a, &x.subject_b);
    check_order(&a, &hash_a, &net, m, &mk, sa, &b.maker, &lane, min_nonce(&x.min_nonce_a)?, &auth_a, &x.instructions)?;
    check_order(&b, &hash_b, &net, m, &mk, sb, &a.maker, &lane, min_nonce(&x.min_nonce_b)?, &auth_b, &x.instructions)?;
    require!(fill_a > 0 && fill_b > 0, BambooError::ZeroAmount);
    let (fa, fb) = (fill_a as u128, fill_b as u128);
    require!(fb * a.sell_amount as u128 >= fa * a.buy_amount as u128, BambooError::PriceLimit);
    require!(fa * b.sell_amount as u128 >= fb * b.buy_amount as u128, BambooError::PriceLimit);
    util::check_mint(&x.mint_x.to_account_info(), fill_a)?;
    util::check_mint(&x.mint_y.to_account_info(), fill_b)?;
    let (fee_x, fee_y) = (fee(fill_a, m.fee_ppm), fee(fill_b, m.fee_ppm));
    let (bump_a, bump_b, fee_ppm) = (sa.bump, sb.bump, m.fee_ppm);

    apply_fill(&mut ctx.accounts.fill_a, &a, fill_a, lane)?;
    apply_fill(&mut ctx.accounts.fill_b, &b, fill_b, lane)?;

    let x = &ctx.accounts;
    let (ap, lp, sp) = (x.associated_token_program.to_account_info(), x.lane.to_account_info(), x.system_program.to_account_info());
    let (mx, my) = (x.mint_x.to_account_info(), x.mint_y.to_account_info());
    let (tx_, ty) = (x.token_program_x.to_account_info(), x.token_program_y.to_account_info());
    let (ia, ib) = (x.subject_a.to_account_info(), x.subject_b.to_account_info());
    util::ata_idempotent(&ap, &lp, &x.b_dst, &ib, &mx, &sp, &tx_)?;
    util::ata_idempotent(&ap, &lp, &x.a_dst, &ia, &my, &sp, &ty)?;
    let seeds_a: &[&[u8]] = &[b"acct", &a.maker, &[bump_a]];
    let seeds_b: &[&[u8]] = &[b"acct", &b.maker, &[bump_b]];
    let (src_a, src_b) = (x.a_src.to_account_info(), x.b_src.to_account_info());
    util::transfer(&tx_, &src_a, &mx, &x.b_dst, &ia, seeds_a, fill_a - fee_x, x.mint_x.decimals)?;
    util::transfer(&ty, &src_b, &my, &x.a_dst, &ib, seeds_b, fill_b - fee_y, x.mint_y.decimals)?;
    if fee_ppm > 0 {
        let mi = x.market.to_account_info();
        let vx = x.vault_x.as_ref().ok_or(BambooError::BadAccounts)?;
        let vy = x.vault_y.as_ref().ok_or(BambooError::BadAccounts)?;
        util::ata_idempotent(&ap, &lp, vx, &mi, &mx, &sp, &tx_)?;
        util::ata_idempotent(&ap, &lp, vy, &mi, &my, &sp, &ty)?;
        util::transfer(&tx_, &src_a, &mx, vx, &ia, seeds_a, fee_x, x.mint_x.decimals)?;
        util::transfer(&ty, &src_b, &my, vy, &ib, seeds_b, fee_y, x.mint_y.decimals)?;
    }
    let maker_a = Pubkey::new_from_array(a.maker);
    let maker_b = Pubkey::new_from_array(b.maker);
    emit_cpi!(OrderFilled { market: mk, order_hash: hash_a, maker: maker_a, sold: fill_a, bought: fill_b - fee_y, fee: fee_y });
    emit_cpi!(OrderFilled { market: mk, order_hash: hash_b, maker: maker_b, sold: fill_b, bought: fill_a - fee_x, fee: fee_x });
    emit_cpi!(Matched { market: mk, a: hash_a, b: hash_b });
    Ok(())
}

// ------------------------------------------------------------------ cancel / min nonce / sweep

#[derive(Accounts)]
#[instruction(order: Order, order_hash: [u8; 32])]
pub struct CancelSigned<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
    pub market: Account<'info, Market>,
    #[account(seeds = [b"acct", order.maker.as_ref()], bump = subject.bump)]
    pub subject: Account<'info, SubjectAccount>,
    #[account(init_if_needed, payer = lane, space = 8 + Fill::INIT_SPACE,
              seeds = [b"fill", market.key().as_ref(), order_hash.as_ref()], bump)]
    pub fill: Account<'info, Fill>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// `"bamboo.cancel.v1" ‖ network ‖ market ‖ order_hash`, ký bởi khoá của maker. Lệnh đầy đủ đi kèm để ràng maker và
/// hạn: `Fill` (tạo nếu chưa có) giữ `valid_until` = hạn lệnh ⇒ không prune được trước khi chính lệnh hết hạn.
pub fn cancel_signed(ctx: Context<CancelSigned>, order: Order, order_hash: [u8; 32], auth: Auth) -> Result<()> {
    let a = &ctx.accounts;
    let (net, mk) = (a.config.network, a.market.key());
    require!(order.hash(&net, &mk) == order_hash && order.maker == a.subject.owner, BambooError::BadOrder);
    let digest = auth::sha256(&[CANCEL_LABEL.as_bytes(), &net, mk.as_ref(), &order_hash]);
    auth::verify(&a.instructions, &auth, &a.subject.keys, &a.subject.origins, CANCEL_LABEL, &digest, None)?;
    let lane = a.lane.key();
    let f = &mut ctx.accounts.fill;
    if f.rent_payer == Pubkey::default() {
        f.rent_payer = lane;
    }
    f.valid_until = f.valid_until.max(order.expiry.min(i64::MAX as u64) as i64);
    f.filled = order.sell_amount;
    Ok(())
}

#[derive(Accounts)]
pub struct InvalidateNonces<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
    pub market: Account<'info, Market>,
    #[account(seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
    pub subject: Account<'info, SubjectAccount>,
    #[account(init_if_needed, payer = lane, space = 8 + MinNonce::INIT_SPACE,
              seeds = [b"minnonce", market.key().as_ref(), subject.key().as_ref()], bump)]
    pub min_nonce: Account<'info, MinNonce>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// `"bamboo.minnonce.v1" ‖ network ‖ market ‖ account ‖ min_nonce` — tăng nghiêm ngặt (chữ ký cũ phát lại ⇒ lỗi).
pub fn invalidate_nonces_signed(ctx: Context<InvalidateNonces>, min_nonce: u64, auth: Auth) -> Result<()> {
    let a = &ctx.accounts;
    let (net, mk, sk) = (a.config.network, a.market.key(), a.subject.key());
    require!(min_nonce > a.min_nonce.min_nonce, BambooError::BadNonce);
    let digest = auth::sha256(&[MINNONCE_LABEL.as_bytes(), &net, mk.as_ref(), sk.as_ref(), &min_nonce.to_le_bytes()]);
    auth::verify(&a.instructions, &auth, &a.subject.keys, &a.subject.origins, MINNONCE_LABEL, &digest, None)?;
    ctx.accounts.min_nonce.min_nonce = min_nonce;
    Ok(())
}

#[derive(Accounts)]
pub struct Sweep<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(seeds = [b"mkt", market.base_mint.as_ref(), market.quote_mint.as_ref()], bump = market.bump)]
    pub market: Account<'info, Market>,
    #[account(mut, token::mint = mint, token::authority = market, token::token_program = token_program)]
    pub source: InterfaceAccount<'info, TokenAccount>,
    pub mint: InterfaceAccount<'info, Mint>,
    /// CHECK: the market's fee recipient.
    #[account(address = market.fee_recipient @ BambooError::WrongRecipient)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: ATA(recipient, mint), created idempotently.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

/// Không cần quyền: mọi token account của Market (vault phí, hay tiền gửi nhầm) ⇒ ATA của `fee_recipient` (L7).
pub fn sweep(ctx: Context<Sweep>) -> Result<()> {
    let a = &ctx.accounts;
    util::ata_idempotent(
        &a.associated_token_program,
        &a.payer,
        &a.destination,
        &a.recipient,
        &a.mint.to_account_info(),
        &a.system_program,
        &a.token_program,
    )?;
    let m = &a.market;
    let seeds: &[&[u8]] = &[b"mkt", m.base_mint.as_ref(), m.quote_mint.as_ref(), &[m.bump]];
    util::transfer(
        &a.token_program,
        &a.source.to_account_info(),
        &a.mint.to_account_info(),
        &a.destination,
        &a.market.to_account_info(),
        seeds,
        a.source.amount,
        a.mint.decimals,
    )
}
