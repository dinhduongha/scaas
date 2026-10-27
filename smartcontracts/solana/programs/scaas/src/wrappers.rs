//! CTR-MTX-27 static wrappers (owner 2026-10-27, as Sui / Aptos): one `relay_fee_<entry>` per fee-less signed entry of
//! `scaas`. Each runs the entry's own body in-process (no CPI, no self-recursion), then the router's payment
//! (`pay_routed`: `relay_pay`'s body with the marker as relayer). Call first, then pay; any failure reverts both.
//! `ref` (`wrapper_ref`) commits to the entry's call as if sent alone: its declared accounts (`crate::accounts::<Entry>`)
//! and `data = discriminator ‖ Borsh(arguments)`, its `auth` included, plus the payer-signed salt `args.extra`.
//! Instruction data: the entry's arguments first (its accounts struct may read them as a prefix), then `owner`,
//! `args`, `pay_auth`. Accounts: the entry's, then `relay_pay`'s, then the entry's remaining accounts.
use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::AccountMeta;
use anchor_lang::InstructionData;

// Glob imports: a composite `#[derive(Accounts)]` needs each inner struct's generated items (`<Name>Bumps`,
// `__client_accounts_<name>`) in scope.
use crate::account::*;
use crate::auth::Auth;
use crate::dex::*;
use crate::mandate::*;

#[derive(Accounts)]
pub struct RelayFeeManageSigned<'info> {
    pub call: ManageSigned<'info>,
    pub pay: RelayPay<'info>,
}

pub fn relay_fee_manage_signed<'info>(
    ctx: Context<'info, RelayFeeManageSigned<'info>>,
    op: KeyOp,
    auth: Auth,
    owner: [u8; 32],
    args: PayArgs,
    pay_auth: Auth,
) -> Result<()> {
    let c = &ctx.accounts.call;
    let metas = crate::accounts::ManageSigned {
        lane: c.lane.key(),
        config: c.config.key(),
        subject: c.subject.key(),
        to: c.to.as_ref().map(|t| t.key()),
        instructions: c.instructions.key(),
        system_program: c.system_program.key(),
    }
    .to_account_metas(None);
    let data = crate::instruction::ManageSigned { op: op.clone(), auth: auth.clone() }.data();
    let r = wrapper_ref(&ctx.accounts.pay.config.network, &metas, &data, &args)?;
    let a = ctx.accounts;
    manage_signed(Context::new(ctx.program_id, &mut a.call, ctx.remaining_accounts, ctx.bumps.call), op, auth)?;
    pay_routed(Context::new(ctx.program_id, &mut a.pay, ctx.remaining_accounts, ctx.bumps.pay), owner, &args, &pay_auth, r, crate::ID)
}

#[derive(Accounts)]
pub struct RelayFeeMandateOpen<'info> {
    pub call: MandateOpen<'info>,
    pub pay: RelayPay<'info>,
}

pub fn relay_fee_mandate_open<'info>(
    ctx: Context<'info, RelayFeeMandateOpen<'info>>,
    init: MandateInit,
    auth: Auth,
    owner: [u8; 32],
    args: PayArgs,
    pay_auth: Auth,
) -> Result<()> {
    let c = &ctx.accounts.call;
    let metas = crate::accounts::MandateOpen {
        lane: c.lane.key(),
        config: c.config.key(),
        subject: c.subject.key(),
        mandate: c.mandate.key(),
        instructions: c.instructions.key(),
        system_program: c.system_program.key(),
    }
    .to_account_metas(None);
    let data = crate::instruction::MandateOpen { init: init.clone(), auth: auth.clone() }.data();
    let r = wrapper_ref(&ctx.accounts.pay.config.network, &metas, &data, &args)?;
    let a = ctx.accounts;
    mandate_open(Context::new(ctx.program_id, &mut a.call, ctx.remaining_accounts, ctx.bumps.call), init, auth)?;
    pay_routed(Context::new(ctx.program_id, &mut a.pay, ctx.remaining_accounts, ctx.bumps.pay), owner, &args, &pay_auth, r, crate::ID)
}

#[derive(Accounts)]
pub struct RelayFeeMandateRevoke<'info> {
    pub call: MandateRevoke<'info>,
    pub pay: RelayPay<'info>,
}

pub fn relay_fee_mandate_revoke_signed<'info>(
    ctx: Context<'info, RelayFeeMandateRevoke<'info>>,
    valid_until: u64,
    auth: Auth,
    owner: [u8; 32],
    args: PayArgs,
    pay_auth: Auth,
) -> Result<()> {
    let c = &ctx.accounts.call;
    let metas = crate::accounts::MandateRevoke {
        lane: c.lane.key(),
        config: c.config.key(),
        mandate: c.mandate.key(),
        instructions: c.instructions.key(),
    }
    .to_account_metas(None);
    let data = crate::instruction::MandateRevokeSigned { valid_until, auth: auth.clone() }.data();
    let r = wrapper_ref(&ctx.accounts.pay.config.network, &metas, &data, &args)?;
    let a = ctx.accounts;
    mandate_revoke_signed(Context::new(ctx.program_id, &mut a.call, ctx.remaining_accounts, ctx.bumps.call), valid_until, auth)?;
    pay_routed(Context::new(ctx.program_id, &mut a.pay, ctx.remaining_accounts, ctx.bumps.pay), owner, &args, &pay_auth, r, crate::ID)
}

#[derive(Accounts)]
pub struct RelayFeeMandateClose<'info> {
    pub call: MandateClose<'info>,
    pub pay: RelayPay<'info>,
}

/// The entry's remaining accounts (quads `[source, mint, destination, token program]`) are part of the call, with
/// the flags `mandate_close_signed` is sent with (writable, readonly, writable, readonly).
#[allow(clippy::too_many_arguments)]
pub fn relay_fee_mandate_close_signed<'info>(
    ctx: Context<'info, RelayFeeMandateClose<'info>>,
    nonce: u64,
    valid_until: u64,
    auth: Auth,
    owner: [u8; 32],
    args: PayArgs,
    pay_auth: Auth,
) -> Result<()> {
    let c = &ctx.accounts.call;
    let mut metas = crate::accounts::MandateClose {
        lane: c.lane.key(),
        config: c.config.key(),
        subject: c.subject.key(),
        mandate: c.mandate.key(),
        rent_payer: c.rent_payer.key(),
        instructions: c.instructions.key(),
    }
    .to_account_metas(None);
    for (i, q) in ctx.remaining_accounts.iter().enumerate() {
        metas.push(if i % 2 == 0 { AccountMeta::new(q.key(), false) } else { AccountMeta::new_readonly(q.key(), false) });
    }
    let data = crate::instruction::MandateCloseSigned { nonce, valid_until, auth: auth.clone() }.data();
    let r = wrapper_ref(&ctx.accounts.pay.config.network, &metas, &data, &args)?;
    let a = ctx.accounts;
    mandate_close_signed(Context::new(ctx.program_id, &mut a.call, ctx.remaining_accounts, ctx.bumps.call), nonce, valid_until, auth)?;
    pay_routed(Context::new(ctx.program_id, &mut a.pay, ctx.remaining_accounts, ctx.bumps.pay), owner, &args, &pay_auth, r, crate::ID)
}

#[derive(Accounts)]
pub struct RelayFeeCancelSigned<'info> {
    pub call: CancelSigned<'info>,
    pub pay: RelayPay<'info>,
}

#[allow(clippy::too_many_arguments)]
pub fn relay_fee_cancel_signed<'info>(
    ctx: Context<'info, RelayFeeCancelSigned<'info>>,
    order: Order,
    order_hash: [u8; 32],
    auth: Auth,
    owner: [u8; 32],
    args: PayArgs,
    pay_auth: Auth,
) -> Result<()> {
    let c = &ctx.accounts.call;
    let metas = crate::accounts::CancelSigned {
        lane: c.lane.key(),
        config: c.config.key(),
        market: c.market.key(),
        subject: c.subject.key(),
        fill: c.fill.key(),
        instructions: c.instructions.key(),
        system_program: c.system_program.key(),
    }
    .to_account_metas(None);
    let data = crate::instruction::CancelSigned { order: order.clone(), order_hash, auth: auth.clone() }.data();
    let r = wrapper_ref(&ctx.accounts.pay.config.network, &metas, &data, &args)?;
    let a = ctx.accounts;
    cancel_signed(Context::new(ctx.program_id, &mut a.call, ctx.remaining_accounts, ctx.bumps.call), order, order_hash, auth)?;
    pay_routed(Context::new(ctx.program_id, &mut a.pay, ctx.remaining_accounts, ctx.bumps.pay), owner, &args, &pay_auth, r, crate::ID)
}

#[derive(Accounts)]
pub struct RelayFeeInvalidateNonces<'info> {
    pub call: InvalidateNonces<'info>,
    pub pay: RelayPay<'info>,
}

pub fn relay_fee_invalidate_nonces_signed<'info>(
    ctx: Context<'info, RelayFeeInvalidateNonces<'info>>,
    min_nonce: u64,
    auth: Auth,
    owner: [u8; 32],
    args: PayArgs,
    pay_auth: Auth,
) -> Result<()> {
    let c = &ctx.accounts.call;
    let metas = crate::accounts::InvalidateNonces {
        lane: c.lane.key(),
        config: c.config.key(),
        market: c.market.key(),
        subject: c.subject.key(),
        min_nonce: c.min_nonce.key(),
        instructions: c.instructions.key(),
        system_program: c.system_program.key(),
    }
    .to_account_metas(None);
    let data = crate::instruction::InvalidateNoncesSigned { min_nonce, auth: auth.clone() }.data();
    let r = wrapper_ref(&ctx.accounts.pay.config.network, &metas, &data, &args)?;
    let a = ctx.accounts;
    invalidate_nonces_signed(Context::new(ctx.program_id, &mut a.call, ctx.remaining_accounts, ctx.bumps.call), min_nonce, auth)?;
    pay_routed(Context::new(ctx.program_id, &mut a.pay, ctx.remaining_accounts, ctx.bumps.pay), owner, &args, &pay_auth, r, crate::ID)
}
