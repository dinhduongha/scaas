//! Trợ giúp chung: chính sách Token-2022 (RS12-7), chuyển token do PDA ký, ATA idempotent, tạo/nới PDA.
use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_spl::associated_token;
use anchor_spl::token_2022::spl_token_2022::extension::{
    non_transferable::NonTransferable, transfer_fee::TransferFeeConfig, transfer_hook::TransferHook,
    BaseStateWithExtensions, StateWithExtensions,
};
use anchor_spl::token_2022::spl_token_2022::state::Mint as MintState;
use anchor_spl::token_interface::{self, TransferChecked};

use crate::BambooError;

/// Kiểm mỗi lần chuyển (phí đổi được sau 2 epoch nên không kiểm lúc đăng ký): abort nếu NonTransferable, transfer hook
/// có program, hoặc phí chuyển của epoch hiện tại > 0 với `amount` (người nhận nhận ít hơn số đã ký — phá L3).
pub fn check_mint(mint: &AccountInfo, amount: u64) -> Result<()> {
    if *mint.owner != anchor_spl::token_2022::ID {
        return Ok(());
    }
    let data = mint.try_borrow_data()?;
    let m = StateWithExtensions::<MintState>::unpack(&data)?;
    require!(m.get_extension::<NonTransferable>().is_err(), BambooError::MintNotAllowed);
    if let Ok(h) = m.get_extension::<TransferHook>() {
        require!(Option::<Pubkey>::from(h.program_id).is_none(), BambooError::MintNotAllowed);
    }
    if let Ok(f) = m.get_extension::<TransferFeeConfig>() {
        let epoch = Clock::get()?.epoch;
        require!(f.calculate_epoch_fee(epoch, amount) == Some(0), BambooError::MintNotAllowed);
    }
    Ok(())
}

/// `transfer_checked` ký bởi PDA `seeds`.
#[allow(clippy::too_many_arguments)]
pub fn transfer<'info>(
    token_program: &AccountInfo<'info>,
    from: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    to: &AccountInfo<'info>,
    authority: &AccountInfo<'info>,
    seeds: &[&[u8]],
    amount: u64,
    decimals: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    let accounts = TransferChecked { from: from.clone(), mint: mint.clone(), to: to.clone(), authority: authority.clone() };
    let signer: &[&[&[u8]]] = &[seeds];
    token_interface::transfer_checked(CpiContext::new_with_signer(token_program.key(), accounts, signer), amount, decimals)
}

/// ATA(`wallet`, `mint`) theo đúng token program của mint; chương trình ATA tự kiểm dẫn xuất (sai ⇒ lỗi).
#[allow(clippy::too_many_arguments)]
pub fn ata_idempotent<'info>(
    ata_program: &AccountInfo<'info>,
    payer: &AccountInfo<'info>,
    ata: &AccountInfo<'info>,
    wallet: &AccountInfo<'info>,
    mint: &AccountInfo<'info>,
    system_program: &AccountInfo<'info>,
    token_program: &AccountInfo<'info>,
) -> Result<()> {
    let accounts = associated_token::Create {
        payer: payer.clone(),
        associated_token: ata.clone(),
        authority: wallet.clone(),
        mint: mint.clone(),
        system_program: system_program.clone(),
        token_program: token_program.clone(),
    };
    associated_token::create_idempotent(CpiContext::new(ata_program.key(), accounts))
}

/// Tạo PDA do program sở hữu, kể cả khi ai đó đã gửi lamports trước vào địa chỉ đó (không DoS được lần mở).
pub fn create_pda<'info>(
    payer: &AccountInfo<'info>,
    target: &AccountInfo<'info>,
    system: &AccountInfo<'info>,
    seeds: &[&[u8]],
    space: usize,
) -> Result<()> {
    let rent = Rent::get()?.minimum_balance(space);
    let signer: &[&[&[u8]]] = &[seeds];
    let sys = system.key();
    if target.lamports() == 0 {
        let a = system_program::CreateAccount { from: payer.clone(), to: target.clone() };
        return system_program::create_account(CpiContext::new_with_signer(sys, a, signer), rent, space as u64, &crate::ID);
    }
    let top = rent.saturating_sub(target.lamports());
    if top > 0 {
        system_program::transfer(CpiContext::new(sys, system_program::Transfer { from: payer.clone(), to: target.clone() }), top)?;
    }
    system_program::allocate(CpiContext::new_with_signer(sys, system_program::Allocate { account_to_allocate: target.clone() }, signer), space as u64)?;
    system_program::assign(CpiContext::new_with_signer(sys, system_program::Assign { account_to_assign: target.clone() }, signer), &crate::ID)
}

/// Nới account của program tới `len` (chỉ lớn lên), `payer` bù rent.
pub fn grow<'info>(target: &AccountInfo<'info>, payer: &AccountInfo<'info>, system: &AccountInfo<'info>, len: usize) -> Result<()> {
    if len <= target.data_len() {
        return Ok(());
    }
    let need = Rent::get()?.minimum_balance(len).saturating_sub(target.lamports());
    if need > 0 {
        system_program::transfer(CpiContext::new(system.key(), system_program::Transfer { from: payer.clone(), to: target.clone() }), need)?;
    }
    target.resize(len)?;
    Ok(())
}

/// Đóng account của program: mọi lamports về `to`, data xoá, trả về System.
pub fn close(target: &AccountInfo, to: &AccountInfo) -> Result<()> {
    let l = target.lamports();
    **to.try_borrow_mut_lamports()? = to.lamports().checked_add(l).ok_or(BambooError::Overflow)?;
    **target.try_borrow_mut_lamports()? = 0;
    target.assign(&system_program::ID);
    target.resize(0)?;
    Ok(())
}

/// Review L5: `to` là VÍ; token account / mint (của token program) làm `to` ⇒ ATA có owner là token account, không ai
/// ký được ⇒ tiền mất. PDA của program khác (vault multisig…) vẫn được.
pub fn check_recipient(recipient: &AccountInfo) -> Result<()> {
    let o = recipient.owner;
    require!(*o != anchor_spl::token::ID && *o != anchor_spl::token_2022::ID, BambooError::TokenAccountRecipient);
    Ok(())
}

pub fn now() -> Result<i64> {
    Ok(Clock::get()?.unix_timestamp)
}

/// Hạn chữ ký `valid_until` (giây unix) so với Clock.
pub fn check_deadline(valid_until: u64) -> Result<()> {
    let t = now()?;
    require!(t >= 0 && (t as u64) <= valid_until, BambooError::Expired);
    Ok(())
}
