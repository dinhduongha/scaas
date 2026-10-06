//! Account của program `scaas` (spec §3.1). Mọi địa chỉ là PDA tính được offline (R20).
use anchor_lang::prelude::*;

pub const SCHEME_ED25519: u8 = 0;
pub const SCHEME_P256: u8 = 2;
pub const MAX_KEYS: usize = 8;
pub const MAX_ORIGINS: usize = 8;
pub const MAX_ORIGIN_LEN: usize = 128;
pub const MAX_PAYEES: usize = 8;
pub const POLICY_BACKUP_REQUIRED: u8 = 1;
pub const RECOVERY_DELAY: i64 = 2 * 24 * 3600;
pub const MAX_FEE_PPM: u32 = 10_000;

#[account]
#[derive(InitSpace)]
pub struct Config {
    pub admin: Pubkey,
    /// Genesis hash của cluster — miền của mọi chữ ký (RS12-8).
    pub network: [u8; 32],
    pub bump: u8,
}

/// Khoá: ed25519 (pk 32 B + 1 byte 0, rp_id_hash = 0) hoặc P-256 WebAuthn (pk nén 33 B + rpIdHash).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq, InitSpace)]
pub struct AuthKey {
    pub scheme: u8,
    pub pubkey: [u8; 33],
    pub rp_id_hash: [u8; 32],
}

impl AuthKey {
    pub fn ed25519(pk: [u8; 32]) -> Self {
        let mut pubkey = [0u8; 33];
        pubkey[..32].copy_from_slice(&pk);
        Self { scheme: SCHEME_ED25519, pubkey, rp_id_hash: [0; 32] }
    }

    pub fn well_formed(&self) -> bool {
        match self.scheme {
            SCHEME_ED25519 => self.pubkey[32] == 0 && self.rp_id_hash == [0; 32],
            SCHEME_P256 => matches!(self.pubkey[0], 2 | 3),
            _ => false,
        }
    }
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    pub key: AuthKey,
    pub origin: String,
    pub ready_at: i64,
}

/// Chủ thể (RS12-3/4/5). Số dư = token account có owner = PDA này. Kích thước theo số khoá/origin (lớn dần).
#[account]
pub struct SubjectAccount {
    pub owner: [u8; 32],
    pub bump: u8,
    pub keys: Vec<AuthKey>,
    pub origins: Vec<String>,
    pub guardian: Option<Pubkey>,
    pub recovery: Option<Recovery>,
    pub key_nonce: u64,
    pub policy: u8,
}

impl SubjectAccount {
    pub fn space(&self) -> usize {
        8 + borsh::to_vec(self).map(|v| v.len()).unwrap_or(0)
    }

    /// "Có backup" ⇔ ≥ 2 khoá, hoặc 1 khoá + guardian (owner OQ1).
    pub fn has_backup(&self) -> bool {
        self.keys.len() >= 2 || (self.keys.len() == 1 && self.guardian.is_some())
    }

    /// Thao tác giá trị khi chính sách bật mà không còn backup ⇒ abort.
    pub fn check_policy(&self) -> Result<()> {
        require!(self.policy & POLICY_BACKUP_REQUIRED == 0 || self.has_backup(), crate::ScaasError::NoBackup);
        Ok(())
    }

    /// Không bao giờ "gạch" Account: ≥ 1 khoá; còn khoá P-256 thì còn ≥ 1 origin.
    pub fn check_usable(&self) -> Result<()> {
        require!(!self.keys.is_empty() && self.keys.len() <= MAX_KEYS, crate::ScaasError::WouldBrick);
        let p256 = self.keys.iter().any(|k| k.scheme == SCHEME_P256);
        require!(!p256 || !self.origins.is_empty(), crate::ScaasError::WouldBrick);
        require!(self.origins.len() <= MAX_ORIGINS, crate::ScaasError::TooMany);
        Ok(())
    }
}

/// Một lane của Account (RS12-6): `next` = nonce kế; prunable sau `valid_until`, rent về `rent_payer`.
#[account]
#[derive(InitSpace)]
pub struct LanePda {
    pub next: u64,
    pub valid_until: i64,
    pub rent_payer: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct Mandate {
    pub account: Pubkey,
    pub owner: [u8; 32],
    pub seed: [u8; 32],
    pub bump: u8,
    pub delegate: AuthKey,
    pub max_per_payment: u64,
    pub max_per_period: u64,
    pub period_s: u64,
    pub expiry: i64,
    #[max_len(8)]
    pub payees: Vec<Pubkey>,
    pub period_start: i64,
    pub spent: u64,
    pub revoked: bool,
    pub rent_payer: Pubkey,
    /// Mint duy nhất mandate trả (review M2): trần/`spent` theo đơn vị của mint này.
    pub asset: Pubkey,
    /// `key_nonce` của Account lúc mở (review L4): op của delegate ký `nonce = generation`; mở lại cùng seed ⇒ thế hệ
    /// mới, op/revoke của thế hệ cũ không chạy.
    pub generation: u64,
}

#[account]
#[derive(InitSpace)]
pub struct MandateRef {
    pub valid_until: i64,
    pub rent_payer: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct Market {
    pub base_mint: Pubkey,
    pub quote_mint: Pubkey,
    pub fee_ppm: u32,
    pub enabled: bool,
    pub fee_recipient: Pubkey,
    pub bump: u8,
}

#[account]
#[derive(InitSpace)]
pub struct Fill {
    pub filled: u64,
    pub valid_until: i64,
    pub rent_payer: Pubkey,
}

#[account]
#[derive(InitSpace)]
pub struct MinNonce {
    pub min_nonce: u64,
}
