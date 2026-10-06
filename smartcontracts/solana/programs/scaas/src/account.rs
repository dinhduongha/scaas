//! Config, SubjectAccount, `relay_pay`, quản trị khoá (KeyOp), khôi phục, `prune` (spec §3, §5.1).
use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

use crate::auth::{self, Auth, MetaOp, KEYOP_LABEL, METAOP_LABEL, OP_PAY};
use crate::state::*;
use crate::util;
use crate::{ScaasError, MetaTransactionExecuted, PaymentSettled};

pub const INSTRUCTIONS_ID: Pubkey = solana_instructions_sysvar::ID;

// ------------------------------------------------------------------ initialize

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
    #[account(init, payer = authority, space = 8 + Config::INIT_SPACE, seeds = [b"config"], bump)]
    pub config: Account<'info, Config>,
    #[account(constraint = program.programdata_address()? == Some(program_data.key()) @ ScaasError::NotUpgradeAuthority)]
    pub program: Program<'info, crate::program::Scaas>,
    #[account(constraint = program_data.upgrade_authority_address == Some(authority.key()) @ ScaasError::NotUpgradeAuthority)]
    pub program_data: Account<'info, ProgramData>,
    pub system_program: Program<'info, System>,
}

pub fn initialize(ctx: Context<Initialize>, network: [u8; 32], admin: Pubkey) -> Result<()> {
    let c = &mut ctx.accounts.config;
    c.admin = admin;
    c.network = network;
    c.bump = ctx.bumps.config;
    Ok(())
}

// ------------------------------------------------------------------ open

fn new_subject(owner: [u8; 32], bump: u8, key: AuthKey, origins: Vec<String>) -> SubjectAccount {
    SubjectAccount { owner, bump, keys: vec![key], origins, guardian: None, recovery: None, key_nonce: 0, policy: 0 }
}

fn write_subject(info: &AccountInfo, s: &SubjectAccount) -> Result<()> {
    let mut data = info.try_borrow_mut_data()?;
    s.try_serialize(&mut &mut data[..])
}

fn create_subject<'info>(payer: &AccountInfo<'info>, info: &AccountInfo<'info>, system: &AccountInfo<'info>, s: &SubjectAccount) -> Result<()> {
    require!(info.data_is_empty(), ScaasError::AlreadyOpen);
    util::create_pda(payer, info, system, &[b"acct", &s.owner, &[s.bump]], s.space())?;
    write_subject(info, s)
}

/// Mở Account ed25519. Chính ví ký (không mở hộ: một id passkey `sha256(...)` mở trước bằng khoá ed25519 sẽ gạch
/// Account passkey đó — review). Mở hộ không cần: `relay_pay` đầu tiên mở lười bằng chữ ký của chủ.
#[derive(Accounts)]
pub struct Open<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    pub owner: Signer<'info>,
    /// CHECK: SubjectAccount PDA, created here.
    #[account(mut, seeds = [b"acct", owner.key().as_ref()], bump)]
    pub subject: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

pub fn open(ctx: Context<Open>) -> Result<()> {
    let a = &ctx.accounts;
    let owner = a.owner.key().to_bytes();
    let s = new_subject(owner, ctx.bumps.subject, AuthKey::ed25519(owner), vec![]);
    create_subject(&a.payer, &a.subject, &a.system_program, &s)
}

pub fn p256_owner(pk33: &[u8; 33]) -> [u8; 32] {
    auth::sha256(&[b"scaas.owner.p256", pk33])
}

#[derive(Accounts)]
#[instruction(owner: [u8; 32])]
pub struct OpenPasskey<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: SubjectAccount PDA of `sha256("scaas.owner.p256" ‖ pk33)`, created here.
    #[account(mut, seeds = [b"acct", owner.as_ref()], bump)]
    pub subject: UncheckedAccount<'info>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

/// Account passkey-first: challenge `sha256("scaas.open.v1" ‖ program_id ‖ pk33)`; rpIdHash và origin lấy từ chính
/// assertion (không ai mở trước được với origin sai — RS7-2).
pub fn open_passkey(ctx: Context<OpenPasskey>, owner: [u8; 32], pk33: [u8; 33], auth: Auth) -> Result<()> {
    require!(owner == p256_owner(&pk33), ScaasError::BadOwner);
    let challenge = auth::sha256(&[b"scaas.open.v1", crate::ID.as_ref(), &pk33]);
    let (rp_id_hash, origin) = auth::passkey(&ctx.accounts.instructions, &auth, &pk33, &challenge)?;
    require!(!origin.is_empty() && origin.len() <= MAX_ORIGIN_LEN, ScaasError::BadWebAuthn);
    let origin = String::from_utf8(origin.to_vec()).map_err(|_| ScaasError::BadWebAuthn)?;
    let key = AuthKey { scheme: SCHEME_P256, pubkey: pk33, rp_id_hash };
    require!(key.well_formed(), ScaasError::BadKey);
    let s = new_subject(owner, ctx.bumps.subject, key, vec![origin]);
    let a = &ctx.accounts;
    create_subject(&a.payer, &a.subject, &a.system_program, &s)
}

// ------------------------------------------------------------------ relay_pay

/// Tham số `MetaOp` đi trong instruction data; `network`, `contract`, `asset`, `from` lấy từ account đã kiểm seeds.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct PayArgs {
    pub to: [u8; 32],
    pub amount: u64,
    pub pay_ref: [u8; 32],
    pub lane: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub relayer: [u8; 32],
    pub extra: [u8; 32],
}

impl PayArgs {
    pub fn check_common(&self, lane: &Pubkey) -> Result<()> {
        util::check_deadline(self.valid_until)?;
        require!(self.amount > 0, ScaasError::ZeroAmount);
        require!(self.relayer == [0; 32] || self.relayer == lane.to_bytes(), ScaasError::WrongRelayer);
        Ok(())
    }

    pub fn metaop(&self, network: [u8; 32], contract: Pubkey, asset: Pubkey, op: u8, from: [u8; 32]) -> MetaOp {
        MetaOp {
            network,
            contract: contract.to_bytes(),
            asset: asset.to_bytes(),
            op,
            from,
            to: self.to,
            amount: self.amount,
            pay_ref: self.pay_ref,
            lane: self.lane,
            nonce: self.nonce,
            valid_until: self.valid_until,
            relayer: self.relayer,
            extra: self.extra,
        }
    }
}

#[event_cpi]
#[derive(Accounts)]
#[instruction(owner: [u8; 32], args: PayArgs)]
pub struct RelayPay<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    /// CHECK: SubjectAccount PDA; opened lazily on the first pay (writable only then), else read in the handler.
    #[account(seeds = [b"acct", owner.as_ref()], bump)]
    pub subject: UncheckedAccount<'info>,
    #[account(init_if_needed, payer = lane, space = 8 + LanePda::INIT_SPACE,
              seeds = [b"lane", subject.key().as_ref(), args.lane.as_ref()], bump)]
    pub lane_pda: Account<'info, LanePda>,
    /// Any token account the Account PDA owns for this mint (ATA or not — L7).
    #[account(mut, token::mint = mint, token::authority = subject, token::token_program = token_program)]
    pub source: InterfaceAccount<'info, TokenAccount>,
    /// CHECK: the receiving wallet `to`; only its ATA is touched.
    #[account(address = Pubkey::new_from_array(args.to) @ ScaasError::WrongRecipient)]
    pub recipient: UncheckedAccount<'info>,
    /// CHECK: ATA(recipient, mint, token_program); the ATA program checks the derivation in `create_idempotent`.
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

pub fn relay_pay(ctx: Context<RelayPay>, owner: [u8; 32], args: PayArgs, auth: Auth) -> Result<()> {
    let a = &ctx.accounts;
    args.check_common(&a.lane.key())?;
    util::check_recipient(&a.recipient)?;
    let info = a.subject.to_account_info();
    let subject = if info.data_is_empty() {
        // Mở lười: khoá duy nhất là chính `owner`, nên chỉ chữ ký của nó (khoá 0) mở được.
        require!(auth.key_index == 0, ScaasError::UnknownKey);
        let s = new_subject(owner, ctx.bumps.subject, AuthKey::ed25519(owner), vec![]);
        create_subject(&a.lane, &info, &a.system_program, &s)?;
        s
    } else {
        require_keys_eq!(*info.owner, crate::ID, ScaasError::BadOwner);
        SubjectAccount::try_deserialize(&mut &info.try_borrow_data()?[..])?
    };
    subject.check_policy()?;
    let op = args.metaop(a.config.network, a.subject.key(), a.mint.key(), OP_PAY, owner);
    let digest = op.digest();
    auth::verify(&a.instructions, &auth, &subject.keys, &subject.origins, METAOP_LABEL, &digest, None)?;
    util::check_mint(&a.mint.to_account_info(), args.amount)?;

    let lp = &mut ctx.accounts.lane_pda;
    require!(lp.next == args.nonce, ScaasError::BadNonce);
    lp.next = lp.next.checked_add(1).ok_or(ScaasError::Overflow)?;
    lp.valid_until = lp.valid_until.max(args.valid_until.min(i64::MAX as u64) as i64);
    if lp.rent_payer == Pubkey::default() {
        lp.rent_payer = ctx.accounts.lane.key();
    }

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
    let bump = [ctx.bumps.subject];
    util::transfer(
        &a.token_program,
        &a.source.to_account_info(),
        &a.mint.to_account_info(),
        &a.destination,
        &a.subject,
        &[b"acct", &owner, &bump],
        args.amount,
        a.mint.decimals,
    )?;
    let (mint, account) = (a.mint.key(), a.subject.key());
    let from = Pubkey::new_from_array(owner);
    emit_cpi!(MetaTransactionExecuted { contract: mint, account, from, digest, lane: args.lane, nonce: args.nonce });
    emit_cpi!(PaymentSettled { contract: mint, from, to: Pubkey::new_from_array(args.to), amount: args.amount, pay_ref: args.pay_ref });
    Ok(())
}

// ------------------------------------------------------------------ KeyOp

pub const ADD_KEY: u8 = 0;
pub const REMOVE_KEY: u8 = 1;
pub const ADD_ORIGIN: u8 = 2;
pub const REMOVE_ORIGIN: u8 = 3;
pub const SET_GUARDIAN: u8 = 4;
pub const CANCEL_RECOVERY: u8 = 5;
pub const SET_POLICY: u8 = 6;
pub const WITHDRAW_LAMPORTS: u8 = 7;

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct KeyOp {
    pub action: u8,
    pub key: AuthKey,
    pub origin: String,
    pub guardian: [u8; 32],
    pub policy: u8,
    pub to: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
}

impl KeyOp {
    /// `"scaas.keyop.v1" ‖ network ‖ account ‖ action ‖ scheme ‖ pk33 ‖ rpIdHash ‖ u8 len ‖ origin ‖ guardian ‖ policy
    /// ‖ to ‖ nonce ‖ valid_until` (LE).
    pub fn bytes(&self, network: &[u8; 32], account: &Pubkey) -> Vec<u8> {
        let mut b = Vec::with_capacity(260 + self.origin.len());
        b.extend_from_slice(KEYOP_LABEL.as_bytes());
        b.extend_from_slice(network);
        b.extend_from_slice(account.as_ref());
        b.push(self.action);
        b.push(self.key.scheme);
        b.extend_from_slice(&self.key.pubkey);
        b.extend_from_slice(&self.key.rp_id_hash);
        b.push(self.origin.len() as u8);
        b.extend_from_slice(self.origin.as_bytes());
        b.extend_from_slice(&self.guardian);
        b.push(self.policy);
        b.extend_from_slice(&self.to);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.extend_from_slice(&self.valid_until.to_le_bytes());
        b
    }
}

#[derive(Accounts)]
pub struct ManageSigned<'info> {
    #[account(mut)]
    pub lane: Signer<'info>,
    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,
    #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
    pub subject: Account<'info, SubjectAccount>,
    /// CHECK: destination of `withdraw_lamports` (must equal the signed `to`).
    #[account(mut)]
    pub to: Option<UncheckedAccount<'info>>,
    /// CHECK: instructions sysvar.
    #[account(address = INSTRUCTIONS_ID)]
    pub instructions: UncheckedAccount<'info>,
    pub system_program: Program<'info, System>,
}

fn add_origin(s: &mut SubjectAccount, origin: &str) -> Result<()> {
    require!(!origin.is_empty() && origin.len() <= MAX_ORIGIN_LEN, ScaasError::BadOrigin);
    if !s.origins.iter().any(|o| o == origin) {
        require!(s.origins.len() < MAX_ORIGINS, ScaasError::TooMany);
        s.origins.push(origin.to_string());
    }
    Ok(())
}

pub fn manage_signed(ctx: Context<ManageSigned>, op: KeyOp, auth: Auth) -> Result<()> {
    util::check_deadline(op.valid_until)?;
    let a = &ctx.accounts;
    let s = &a.subject;
    require!(op.nonce == s.key_nonce, ScaasError::BadNonce);
    require!(op.origin.len() <= MAX_ORIGIN_LEN, ScaasError::BadOrigin);
    let digest = auth::sha256(&[&op.bytes(&a.config.network, &s.key())]);
    let new_origin = (op.action == ADD_ORIGIN).then_some(op.origin.as_bytes());
    auth::verify(&a.instructions, &auth, &s.keys, &s.origins, KEYOP_LABEL, &digest, new_origin)?;

    let backup_on = s.policy & POLICY_BACKUP_REQUIRED != 0;
    let subject_info = ctx.accounts.subject.to_account_info();
    let s = &mut ctx.accounts.subject;
    s.key_nonce += 1;
    match op.action {
        ADD_KEY => {
            require!(op.key.well_formed(), ScaasError::BadKey);
            require!(!s.keys.contains(&op.key), ScaasError::BadKey);
            require!(s.keys.len() < MAX_KEYS, ScaasError::TooMany);
            if op.key.scheme == SCHEME_P256 && !op.origin.is_empty() {
                add_origin(s, &op.origin)?;
            }
            s.keys.push(op.key.clone());
        }
        REMOVE_KEY => {
            let i = s.keys.iter().position(|k| *k == op.key).ok_or(ScaasError::UnknownKey)?;
            s.keys.remove(i);
            require!(!backup_on || s.has_backup(), ScaasError::NoBackup);
        }
        ADD_ORIGIN => add_origin(s, &op.origin)?,
        REMOVE_ORIGIN => {
            let i = s.origins.iter().position(|o| *o == op.origin).ok_or(ScaasError::BadOrigin)?;
            s.origins.remove(i);
        }
        SET_GUARDIAN => {
            s.guardian = (op.guardian != [0; 32]).then(|| Pubkey::new_from_array(op.guardian));
            require!(!backup_on || s.has_backup(), ScaasError::NoBackup);
        }
        CANCEL_RECOVERY => s.recovery = None,
        SET_POLICY => {
            require!(op.policy & !POLICY_BACKUP_REQUIRED == 0, ScaasError::BadPolicy);
            require!(op.policy & POLICY_BACKUP_REQUIRED == 0 || s.has_backup(), ScaasError::NoBackup);
            s.policy = op.policy;
        }
        WITHDRAW_LAMPORTS => {
            let to = ctx.accounts.to.as_ref().ok_or(ScaasError::WrongRecipient)?;
            require!(to.key().to_bytes() == op.to, ScaasError::WrongRecipient);
            let keep = Rent::get()?.minimum_balance(subject_info.data_len());
            let extra = subject_info.lamports().saturating_sub(keep);
            **subject_info.try_borrow_mut_lamports()? -= extra;
            **to.try_borrow_mut_lamports()? += extra;
        }
        _ => return err!(ScaasError::BadAction),
    }
    s.check_usable()?;
    let len = s.space();
    util::grow(&subject_info, &ctx.accounts.lane, &ctx.accounts.system_program, len)
}

// ------------------------------------------------------------------ recovery (guardian, tx native)

#[derive(Accounts)]
pub struct StartRecovery<'info> {
    #[account(mut)]
    pub guardian: Signer<'info>,
    #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump,
              constraint = subject.guardian == Some(guardian.key()) @ ScaasError::NotGuardian)]
    pub subject: Account<'info, SubjectAccount>,
    pub system_program: Program<'info, System>,
}

pub fn start_recovery(ctx: Context<StartRecovery>, key: AuthKey, origin: String) -> Result<()> {
    require!(key.well_formed(), ScaasError::BadKey);
    require!(origin.len() <= MAX_ORIGIN_LEN, ScaasError::BadOrigin);
    let s = &mut ctx.accounts.subject;
    require!(key.scheme != SCHEME_P256 || !origin.is_empty() || !s.origins.is_empty(), ScaasError::WouldBrick);
    s.recovery = Some(Recovery { key, origin, ready_at: util::now()? + RECOVERY_DELAY });
    let len = s.space();
    let info = ctx.accounts.subject.to_account_info();
    util::grow(&info, &ctx.accounts.guardian, &ctx.accounts.system_program, len)
}

#[derive(Accounts)]
pub struct FinishRecovery<'info> {
    #[account(mut, seeds = [b"acct", subject.owner.as_ref()], bump = subject.bump)]
    pub subject: Account<'info, SubjectAccount>,
}

/// Sau trễ: khoá khôi phục thay MỌI khoá cũ (khoá mất/bị lộ). Không cần quyền — đã hẹn trước 2 ngày, khoá hiện có huỷ
/// được bằng KeyOp `cancel_recovery`.
pub fn finish_recovery(ctx: Context<FinishRecovery>) -> Result<()> {
    let s = &mut ctx.accounts.subject;
    let r = s.recovery.take().ok_or(ScaasError::NoRecovery)?;
    require!(util::now()? >= r.ready_at, ScaasError::TooEarly);
    if !r.origin.is_empty() {
        add_origin(s, &r.origin)?;
    }
    s.keys = vec![r.key];
    s.key_nonce += 1;
    s.check_usable()
}

// ------------------------------------------------------------------ prune

#[derive(Accounts)]
pub struct Prune<'info> {
    /// CHECK: a LanePda / MandateRef / Fill of this program (discriminator-checked in the handler).
    #[account(mut, owner = crate::ID)]
    pub target: UncheckedAccount<'info>,
    /// CHECK: must be the `rent_payer` stored in `target`.
    #[account(mut)]
    pub rent_payer: UncheckedAccount<'info>,
}

/// LanePda / MandateRef xoá được chỉ sau `valid_until + PRUNE_DELAY_S` (review C1). `valid_until` chỉ là hạn của op ĐÃ
/// CHẠY; Odoo phát lại điều khoản của một request trên CÙNG lane, nonce 0 (cùng `pay_ref`), mọi hạn trong
/// `LANE_HORIZON_S` (= 30 ngày) kể từ lúc tạo request ⇒ khi PDA bị xoá, mọi op khác đã ký cho request đó đã hết hạn (không
/// trả hai lần). Giảm hằng này phải giảm horizon của Odoo trước. `Fill` không cần: hạn lệnh nằm trong hash.
pub const PRUNE_DELAY_S: i64 = 2_592_000;

/// Không cần quyền: đóng PDA đã quá hạn xoá, rent về đúng `rent_payer` đã lưu (RS12-6).
pub fn prune(ctx: Context<Prune>) -> Result<()> {
    let t = &ctx.accounts.target;
    let (due, payer) = {
        let data = t.try_borrow_data()?;
        let d = data.get(..8).ok_or(ScaasError::NotPrunable)?;
        if d == LanePda::DISCRIMINATOR {
            let x = LanePda::try_deserialize(&mut &data[..])?;
            (x.valid_until.saturating_add(PRUNE_DELAY_S), x.rent_payer)
        } else if d == MandateRef::DISCRIMINATOR {
            let x = MandateRef::try_deserialize(&mut &data[..])?;
            (x.valid_until.saturating_add(PRUNE_DELAY_S), x.rent_payer)
        } else if d == Fill::DISCRIMINATOR {
            let x = Fill::try_deserialize(&mut &data[..])?;
            (x.valid_until, x.rent_payer)
        } else {
            return err!(ScaasError::NotPrunable);
        }
    };
    require_keys_eq!(payer, ctx.accounts.rent_payer.key(), ScaasError::WrongRentPayer);
    require!(util::now()? > due, ScaasError::TooEarly);
    util::close(t, &ctx.accounts.rent_payer)
}
