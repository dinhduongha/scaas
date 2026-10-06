//! TEST ONLY (S12 review I1): một program khác bọc lệnh gọi `scaas` trong CPI — instruction data chuyển nguyên cho
//! `accounts[0]`, kèm `accounts[1..]` giữ nguyên cờ signer/writable. e2e chứng minh indexer vẫn thấy event của
//! `relay_pay` khi nó không phải instruction cấp tx. Chỉ nạp trên validator e2e (`--bpf-program`), không deploy.
use anchor_lang::solana_program::account_info::AccountInfo;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke;
use anchor_lang::solana_program::program_error::ProgramError;
use anchor_lang::solana_program::pubkey::Pubkey;

anchor_lang::solana_program::entrypoint!(process);

fn process(_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> Result<(), ProgramError> {
    let (target, rest) = accounts.split_first().ok_or(ProgramError::NotEnoughAccountKeys)?;
    let metas = rest.iter().map(|a| AccountMeta { pubkey: *a.key, is_signer: a.is_signer, is_writable: a.is_writable }).collect();
    invoke(&Instruction { program_id: *target.key, accounts: metas, data: data.to_vec() }, rest)
}
