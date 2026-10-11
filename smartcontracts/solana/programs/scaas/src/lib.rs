//! `scaas` — meta-transaction cấp program trên Solana (S12, `docs/networks/solana.md`;
//! bản đóng băng `docs/history/specs/2026-10-04-net-solana.md`).
//! Chủ thể ký thông điệp tách miền (ed25519 raw/OCMS qua precompile Ed25519, passkey qua precompile Secp256r1); relayer
//! gửi tx từ lane của chính nó. Số dư = token account của SmartKeyAccount PDA. Đường nóng chỉ GHI account riêng của thao
//! tác (RS12-2).
#![allow(unexpected_cfgs, ambiguous_glob_reexports)]
use anchor_lang::prelude::*;

pub mod account;
pub mod auth;
pub mod dex;
pub mod mandate;
pub mod state;
pub mod util;

pub use account::*;
pub use auth::Auth;
pub use dex::*;
pub use mandate::*;
pub use state::AuthKey;

/// Program id của test/localnet (LiteSVM, e2e, vector). KHOÁ CỦA NÓ ĐÃ CÔNG KHAI (từng nằm trong repo — review M3): ai cũng
/// deploy được vào id này trên cluster công khai ⇒ CHỈ dùng cho localnet. Bản deploy thật build với
/// `SCAAS_PROGRAM_ID=<id của keypair riêng>` qua `scripts/deploy.sh`. Program id khác = miền khác (PDA, event authority,
/// `Config` do đúng upgrade authority của bản đó tạo).
pub const TEST_PROGRAM_ID: &str = "BDo6exf1vzqX44BJc1WDf4Pw6sGZcxqmuVmQPfgUgS3d";

declare_id!(anchor_lang::solana_program::pubkey::Pubkey::from_str_const(match option_env!("SCAAS_PROGRAM_ID") {
    Some(id) => id,
    None => TEST_PROGRAM_ID,
}));

#[program]
pub mod scaas {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>, network: [u8; 32], admin: Pubkey) -> Result<()> {
        account::initialize(ctx, network, admin)
    }

    pub fn open(ctx: Context<Open>) -> Result<()> {
        account::open(ctx)
    }

    pub fn open_passkey(ctx: Context<OpenPasskey>, owner: [u8; 32], pk33: [u8; 33], auth: Auth) -> Result<()> {
        account::open_passkey(ctx, owner, pk33, auth)
    }

    pub fn relay_pay(ctx: Context<RelayPay>, owner: [u8; 32], args: PayArgs, auth: Auth) -> Result<()> {
        account::relay_pay(ctx, owner, args, auth)
    }

    pub fn manage_signed(ctx: Context<ManageSigned>, op: KeyOp, auth: Auth) -> Result<()> {
        account::manage_signed(ctx, op, auth)
    }

    pub fn start_recovery(ctx: Context<StartRecovery>, key: AuthKey, origin: String) -> Result<()> {
        account::start_recovery(ctx, key, origin)
    }

    pub fn finish_recovery(ctx: Context<FinishRecovery>) -> Result<()> {
        account::finish_recovery(ctx)
    }

    pub fn prune(ctx: Context<Prune>) -> Result<()> {
        account::prune(ctx)
    }

    pub fn mandate_open(ctx: Context<MandateOpen>, init: MandateInit, auth: Auth) -> Result<()> {
        mandate::mandate_open(ctx, init, auth)
    }

    pub fn mandate_pay(ctx: Context<MandatePay>, args: PayArgs, auth: Auth) -> Result<()> {
        mandate::mandate_pay(ctx, args, auth)
    }

    pub fn mandate_revoke_signed(ctx: Context<MandateRevoke>, valid_until: u64, auth: Auth) -> Result<()> {
        mandate::mandate_revoke_signed(ctx, valid_until, auth)
    }

    pub fn mandate_close_signed<'info>(
        ctx: Context<'info, MandateClose<'info>>,
        nonce: u64,
        valid_until: u64,
        auth: Auth,
    ) -> Result<()> {
        mandate::mandate_close_signed(ctx, nonce, valid_until, auth)
    }

    pub fn list_market(ctx: Context<ListMarket>, fee_ppm: u32, fee_recipient: Pubkey) -> Result<()> {
        dex::list_market(ctx, fee_ppm, fee_recipient)
    }

    pub fn set_market(ctx: Context<SetMarket>, fee_ppm: u32, enabled: bool, fee_recipient: Pubkey) -> Result<()> {
        dex::set_market(ctx, fee_ppm, enabled, fee_recipient)
    }

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
        dex::settle(ctx, a, b, hash_a, hash_b, fill_a, fill_b, auth_a, auth_b)
    }

    pub fn cancel_signed(ctx: Context<CancelSigned>, order: Order, order_hash: [u8; 32], auth: Auth) -> Result<()> {
        dex::cancel_signed(ctx, order, order_hash, auth)
    }

    pub fn invalidate_nonces_signed(ctx: Context<InvalidateNonces>, min_nonce: u64, auth: Auth) -> Result<()> {
        dex::invalidate_nonces_signed(ctx, min_nonce, auth)
    }

    pub fn sweep(ctx: Context<Sweep>) -> Result<()> {
        dex::sweep(ctx)
    }
}

/// `contract` = mint (token Odoo đã đăng ký); `digest` = sha256(MetaOp) mà Odoo chốt `blockchain.signed.op`.
#[event]
pub struct MetaTransactionExecuted {
    pub contract: Pubkey,
    pub account: Pubkey,
    pub from: Pubkey,
    pub digest: [u8; 32],
    pub lane: [u8; 32],
    pub nonce: u64,
}

#[event]
pub struct PaymentSettled {
    pub contract: Pubkey,
    pub from: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
    pub pay_ref: [u8; 32],
}

#[event]
pub struct PaidUnderMandate {
    pub mandate: Pubkey,
    pub contract: Pubkey,
    pub to: Pubkey,
    pub amount: u64,
    pub pay_ref: [u8; 32],
}

#[event]
pub struct OrderFilled {
    pub market: Pubkey,
    pub order_hash: [u8; 32],
    pub maker: Pubkey,
    pub sold: u64,
    pub bought: u64,
    pub fee: u64,
}

#[event]
pub struct Matched {
    pub market: Pubkey,
    pub a: [u8; 32],
    pub b: [u8; 32],
}

#[error_code]
pub enum ScaasError {
    #[msg("signer is not the program upgrade authority")]
    NotUpgradeAuthority,
    #[msg("signer is not the config admin")]
    NotAdmin,
    #[msg("account already open")]
    AlreadyOpen,
    #[msg("owner does not match")]
    BadOwner,
    #[msg("precompile instruction malformed or not the expected program")]
    BadPrecompile,
    #[msg("signature does not cover the expected message/key")]
    BadSignature,
    #[msg("WebAuthn assertion malformed")]
    BadWebAuthn,
    #[msg("origin not allowed for this account")]
    UnknownOrigin,
    #[msg("key not in the account")]
    UnknownKey,
    #[msg("signature expired")]
    Expired,
    #[msg("amount must be positive")]
    ZeroAmount,
    #[msg("op is bound to another relayer")]
    WrongRelayer,
    #[msg("recipient does not match the signed op")]
    WrongRecipient,
    #[msg("lane nonce mismatch")]
    BadNonce,
    #[msg("arithmetic overflow")]
    Overflow,
    #[msg("mint extension not allowed (non-transferable, transfer hook, transfer fee)")]
    MintNotAllowed,
    #[msg("backup key required by the account policy")]
    NoBackup,
    #[msg("change would leave the account unusable")]
    WouldBrick,
    #[msg("too many keys/origins/payees")]
    TooMany,
    #[msg("bad key")]
    BadKey,
    #[msg("bad origin")]
    BadOrigin,
    #[msg("bad policy")]
    BadPolicy,
    #[msg("unknown key operation")]
    BadAction,
    #[msg("signer is not the guardian")]
    NotGuardian,
    #[msg("no recovery pending")]
    NoRecovery,
    #[msg("too early")]
    TooEarly,
    #[msg("account cannot be pruned")]
    NotPrunable,
    #[msg("rent payer does not match")]
    WrongRentPayer,
    #[msg("bad mandate")]
    BadMandate,
    #[msg("mandate revoked")]
    Revoked,
    #[msg("payee not allowed")]
    PayeeNotAllowed,
    #[msg("over the mandate cap")]
    OverCap,
    #[msg("bad accounts")]
    BadAccounts,
    #[msg("fee above the cap")]
    FeeTooHigh,
    #[msg("bad market")]
    BadMarket,
    #[msg("market disabled")]
    MarketDisabled,
    #[msg("order malformed")]
    BadOrder,
    #[msg("order is for another taker")]
    WrongTaker,
    #[msg("same account on both sides")]
    SelfTrade,
    #[msg("price limit")]
    PriceLimit,
    #[msg("overfill")]
    Overfill,
    #[msg("fill-or-kill not filled")]
    FillOrKill,
    #[msg("mandate is for another mint")]
    WrongMint,
    #[msg("recipient is a token account or mint, not a wallet")]
    TokenAccountRecipient,
}
