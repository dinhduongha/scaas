//! TEST ONLY (metatx split T11): đích của `scaas::relay_fee` trong test LiteSVM, không deploy. `data[0] == 0xff` ⇒
//! lỗi `Custom(7)`; còn lại ghi `data` vào đầu `accounts[0]` (account của chính program này, writable) — hiệu ứng thấy
//! được để test chứng minh call và payment cùng revert.
use anchor_lang::solana_program::account_info::AccountInfo;
use anchor_lang::solana_program::program_error::ProgramError;
use anchor_lang::solana_program::pubkey::Pubkey;

anchor_lang::solana_program::entrypoint!(process);

fn process(id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> Result<(), ProgramError> {
    if data.first() == Some(&0xff) {
        return Err(ProgramError::Custom(7));
    }
    let rec = accounts.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    if rec.owner != id || !rec.is_writable {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut d = rec.try_borrow_mut_data()?;
    d.get_mut(..data.len()).ok_or(ProgramError::AccountDataTooSmall)?.copy_from_slice(data);
    Ok(())
}
