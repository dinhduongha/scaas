//! Mandate (R25, spec §5.2 — RS12-11): khoá Account mở bằng chữ ký; delegate trả trong trần lần/kỳ cho payee đã định;
//! `pay_ref` một lần bằng PDA `mref`; delegate thu hồi (kill switch); khoá Account đóng và rút về Account.
use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::account::{PayArgs, INSTRUCTIONS_ID};
use crate::auth::{self, Auth, MetaOp, MANDATE_LABEL, MCLOSE_LABEL, METAOP_LABEL, OP_MANDATE_PAY, OP_REVOKE};
use crate::state::*;
use crate::util;
use crate::{ScaasError, MetaTransactionExecuted, PaidUnderMandate, PaymentSettled};

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct MandateInit {
    pub seed: [u8; 32],
    /// Mint duy nhất mandate trả (review M2).
    pub asset: Pubkey,
    pub delegate: AuthKey,
    pub max_per_payment: u64,
    pub max_per_period: u64,
    pub period_s: u64,
    pub expiry: u64,
    pub payees: Vec<Pubkey>,
    pub nonce: u64,
    pub valid_until: u64,
}

impl MandateInit {
    /// `"scaas.mandate.v1" ‖ network ‖ account ‖ mandate ‖ asset ‖ scheme ‖ pk33 ‖ rpIdHash ‖ max_per_payment ‖
    /// max_per_period ‖ period_s ‖ expiry ‖ u8 n ‖ payees ‖ nonce ‖ valid_until` (LE).
    pub fn bytes(&self, network: &[u8; 32], account: &Pubkey, mandate: &Pubkey) -> Vec<u8> {
        let mut b = Vec::with_capacity(332 + 32 * self.payees.len());
        b.extend_from_slice(MANDATE_LABEL.as_bytes());
        b.extend_from_slice(network);
        b.extend_from_slice(account.as_ref());
        b.extend_from_slice(mandate.as_ref());
        b.extend_from_slice(self.asset.as_ref());
        b.push(self.delegate.scheme);
        b.extend_from_slice(&self.delegate.pubkey);
        b.extend_from_slice(&self.delegate.rp_id_hash);
        for v in [self.max_per_payment, self.max_per_period, self.period_s, self.expiry] {
            b.extend_from_slice(&v.to_le_bytes());
        }
        b.push(self.payees.len() as u8);
        self.payees.iter().for_each(|p| b.extend_from_slice(p.as_ref()));
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.extend_from_slice(&self.valid_until.to_le_bytes());
        b
    }
}

#[derive(Accounts)]
#[instruction(init: MandateInit)]
pub struct MandateOpen<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
    pub subject: Account<'info, SmartKeyAccount>,
    #[account(init, payer = lane, space = 8 + Mandate::INIT_SPACE,
              seeds = [b"mandate", subject.key().as_ref(), init.seed.as_ref()], bump)]
    pub mandate: Account<'info, Mandate>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

pub fn mandate_open(ctx: Context<MandateOpen>, init: MandateInit, auth: Auth) -> Result<()> {
    util::check_deadline(init.valid_until)?;
    let a = &ctx.accounts;
    let s = &a.subject;
    s.check_policy()?;
    require!(init.nonce == s.key_nonce, ScaasError::BadNonce);
    // Delegate là khoá dịch vụ/HSM của nền tảng ⇒ ed25519 (passkey không chạy trên server) — RS12-11a.
    require!(init.delegate.scheme == SCHEME_ED25519 && init.delegate.well_formed(), ScaasError::BadKey);
    require!(init.payees.len() <= MAX_PAYEES, ScaasError::TooMany);
    require!(init.period_s > 0 && init.max_per_payment > 0 && init.max_per_payment <= init.max_per_period, ScaasError::BadMandate);
    require!(init.expiry > util::now()?.max(0) as u64, ScaasError::Expired);
    let digest = auth::sha256(&[&init.bytes(&a.config.network, &s.key(), &a.mandate.key())]);
    auth::verify(&a.instructions, &auth, &s.keys, &s.origins, MANDATE_LABEL, &digest, None)?;

    let (account, owner, rent_payer) = (a.subject.key(), a.subject.owner, a.lane.key());
    ctx.accounts.subject.key_nonce += 1;
    let m = &mut ctx.accounts.mandate;
    m.account = account;
    m.owner = owner;
    m.seed = init.seed;
    m.bump = ctx.bumps.mandate;
    m.delegate = init.delegate;
    m.max_per_payment = init.max_per_payment;
    m.max_per_period = init.max_per_period;
    m.period_s = init.period_s;
    m.expiry = init.expiry.min(i64::MAX as u64) as i64;
    m.payees = init.payees;
    m.period_start = util::now()?;
    m.spent = 0;
    m.revoked = false;
    m.rent_payer = rent_payer;
    m.asset = init.asset;
    m.generation = init.nonce;
    Ok(())
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(args: PayArgs)]
pub struct MandatePay<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"mandate", mandate.account.as_ref(), mandate.seed.as_ref()], bump = mandate.bump)]
    pub mandate: Account<'info, Mandate>,
    #[account(init, payer = lane, space = 8 + MandateRef::INIT_SPACE,
              seeds = [b"mref", mandate.key().as_ref(), args.pay_ref.as_ref()], bump)]
    pub mref: Account<'info, MandateRef>,
    #[account(mut, token::mint = mint, token::authority = mandate, token::token_program = token_program)]
    pub source: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the payee wallet `to`.
    #[account(address = Pubkey::new_from_array(args.to) @ ScaasError::WrongRecipient)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: ATA(recipient, mint, token_program), derivation checked by the ATA program.
    #[account(mut)]
    pub destination: UncheckedAccount<'info>,
    pub mint: InterfaceAccount<'info, Mint>,
    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
}

pub fn mandate_pay(ctx: Context<MandatePay>, args: PayArgs, auth: Auth) -> Result<()> {
    let a = &ctx.accounts;
    args.check_common(&a.lane.key())?;
    util::check_recipient(&a.recipient)?;
    let m = &a.mandate;
    let now = util::now()?;
    require!(!m.revoked, ScaasError::Revoked);
    require_keys_eq!(a.mint.key(), m.asset, ScaasError::WrongMint);
    // L4: op của thế hệ cũ (mandate đã đóng rồi mở lại cùng seed) không chạy.
    require!(args.nonce == m.generation, ScaasError::BadNonce);
    require!(now <= m.expiry, ScaasError::Expired);
    let to = Pubkey::new_from_array(args.to);
    require!(m.payees.is_empty() || m.payees.contains(&to), ScaasError::PayeeNotAllowed);
    require!(args.amount <= m.max_per_payment, ScaasError::OverCap);
    let op = args.metaop(a.config.network, m.key(), a.mint.key(), OP_MANDATE_PAY, m.owner);
    let digest = op.digest();
    require!(auth.key_index == 0, ScaasError::UnknownKey);
    auth::verify(&a.instructions, &auth, std::slice::from_ref(&m.delegate), &[], METAOP_LABEL, &digest, None)?;
    util::check_mint(&a.mint.to_account_info(), args.amount)?;

    let m = &mut ctx.accounts.mandate;
    if now >= m.period_start.saturating_add(m.period_s.min(i64::MAX as u64) as i64) {
        m.period_start = now;
        m.spent = 0;
    }
    // So bằng phép trừ: không tràn ở `spent + amount` (Sui L6).
    require!(args.amount <= m.max_per_period - m.spent, ScaasError::OverCap);
    m.spent += args.amount;
    let (owner, account, seed, bump) = (m.owner, m.account, m.seed, m.bump);
    let r = &mut ctx.accounts.mref;
    r.valid_until = args.valid_until.min(i64::MAX as u64) as i64;
    r.rent_payer = ctx.accounts.lane.key();

    let a = &ctx.accounts;
    util::ata_idempotent(
        &a.associated_token_program,
        &a.lane,
        &a.destination,
        &a.recipient,
        &a.mint.to_account_info(),
        &a.system_program,
        &a.token_program,
    )?;
    util::transfer(
        &a.token_program,
        &a.source.to_account_info(),
        &a.mint.to_account_info(),
        &a.destination,
        &a.mandate.to_account_info(),
        &[b"mandate", account.as_ref(), &seed, &[bump]],
        args.amount,
        a.mint.decimals,
    )?;
    let (mint, mandate, from) = (a.mint.key(), a.mandate.key(), Pubkey::new_from_array(owner));
    emit_cpi!(MetaTransactionExecuted { contract: mint, account: mandate, from, digest, lane: args.lane, nonce: args.nonce });
    emit_cpi!(PaymentSettled { contract: mint, from, to, amount: args.amount, pay_ref: args.pay_ref });
    emit_cpi!(PaidUnderMandate { mandate, contract: mint, to, amount: args.amount, pay_ref: args.pay_ref });
    Ok(())
}

#[derive(Accounts)]
pub struct MandateRevoke<'info> {
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"mandate", mandate.account.as_ref(), mandate.seed.as_ref()], bump = mandate.bump)]
    pub mandate: Account<'info, Mandate>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
}

/// Kill switch của delegate: `MetaOp{op: revoke, contract: mandate, from: owner, nonce: generation}`, mọi trường khác 0
/// trừ `valid_until`.
pub fn mandate_revoke_signed(ctx: Context<MandateRevoke>, valid_until: u64, auth: Auth) -> Result<()> {
    util::check_deadline(valid_until)?;
    let a = &ctx.accounts;
    let m = &a.mandate;
    let op = MetaOp {
        network: a.config.network,
        contract: m.key().to_bytes(),
        asset: [0; 32],
        op: OP_REVOKE,
        from: m.owner,
        to: [0; 32],
        amount: 0,
        pay_ref: [0; 32],
        lane: [0; 32],
        nonce: m.generation,
        valid_until,
        relayer: [0; 32],
        extra: [0; 32],
    };
    require!(auth.key_index == 0, ScaasError::UnknownKey);
    auth::verify(&a.instructions, &auth, std::slice::from_ref(&m.delegate), &[], METAOP_LABEL, &op.digest(), None)?;
    ctx.accounts.mandate.revoked = true;
    Ok(())
}

#[derive(Accounts)]
pub struct MandateClose<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
    pub subject: Account<'info, SmartKeyAccount>,
    #[account(mut, close = rent_payer, seeds = [b"mandate", mandate.account.as_ref(), mandate.seed.as_ref()],
              bump = mandate.bump, has_one = rent_payer, constraint = mandate.account == subject.key() @ ScaasError::BadOwner)]
    pub mandate: Account<'info, Mandate>,
    /// CHECK: receives the mandate's rent (checked by `has_one`).
    #[account(mut)]
    pub rent_payer: UncheckedAccount<'info>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
}

/// Khoá Account đóng Mandate bất cứ lúc nào (như owner EVM): mọi token account của Mandate truyền vào
/// (`remaining_accounts` theo bộ bốn `[nguồn, mint, đích của Account, token program]`) chuyển hết về Account, rồi đóng
/// PDA (rent về `rent_payer`). Chữ ký `"scaas.mclose.v1" ‖ network ‖ account ‖ mandate ‖ nonce ‖ valid_until`.
pub fn mandate_close_signed<'info>(
    ctx: Context<'info, MandateClose<'info>>,
    nonce: u64,
    valid_until: u64,
    auth: Auth,
) -> Result<()> {
    util::check_deadline(valid_until)?;
    let a = &ctx.accounts;
    let s = &a.subject;
    require!(nonce == s.key_nonce, ScaasError::BadNonce);
    let digest = auth::sha256(&[
        MCLOSE_LABEL.as_bytes(),
        &a.config.network,
        s.key().as_ref(),
        a.mandate.key().as_ref(),
        &nonce.to_le_bytes(),
        &valid_until.to_le_bytes(),
    ]);
    auth::verify(&a.instructions, &auth, &s.keys, &s.origins, MCLOSE_LABEL, &digest, None)?;
    let rest = ctx.remaining_accounts;
    require!(rest.len() % 4 == 0, ScaasError::BadAccounts);
    let m = &a.mandate;
    let seeds: &[&[u8]] = &[b"mandate", m.account.as_ref(), &m.seed, &[m.bump]];
    for q in rest.chunks(4) {
        let (src, mint, dst, tp) = (&q[0], &q[1], &q[2], &q[3]);
        require!(tp.key() == anchor_spl::token::ID || tp.key() == anchor_spl::token_2022::ID, ScaasError::BadAccounts);
        require_keys_eq!(*src.owner, tp.key(), ScaasError::BadAccounts);
        require_keys_eq!(*dst.owner, tp.key(), ScaasError::BadAccounts);
        let from = InterfaceAccount::<TokenAccount>::try_from(src)?;
        let to = InterfaceAccount::<TokenAccount>::try_from(dst)?;
        let mt = InterfaceAccount::<Mint>::try_from(mint)?;
        require!(from.owner == m.key() && to.owner == s.key(), ScaasError::BadAccounts);
        require!(from.mint == mint.key() && to.mint == mint.key(), ScaasError::BadAccounts);
        util::transfer(tp, src, mint, dst, &a.mandate.to_account_info(), seeds, from.amount, mt.decimals)?;
    }
    ctx.accounts.subject.key_nonce += 1;
    Ok(())
}
