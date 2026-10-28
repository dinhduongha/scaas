//! `MetaOp` v1 (spec §2 row 1): `encode = "scaas.metaop.v1" ‖ Borsh(MetaOp)`, `digest = sha256(encode)`. Field order and
//! op codes as `scripts/gen_vectors.py` (plan "Shared decisions").
use crate::Holder;
use near_sdk::{borsh, env, near, AccountId};

pub const LABEL: &[u8] = b"scaas.metaop.v1";

pub const OP_PAY: u8 = 0;
pub const OP_TRADE: u8 = 1;
pub const OP_MANDATE_PAY: u8 = 2;
pub const OP_REVOKE: u8 = 3;
pub const OP_TRANSFER: u8 = 4;
pub const OP_EXECUTE_TRANSFER: u8 = 5;
pub const OP_ADD_KEY: u8 = 6;
pub const OP_REMOVE_KEY: u8 = 7;
pub const OP_ADD_ORIGIN: u8 = 8;
pub const OP_REMOVE_ORIGIN: u8 = 9;
pub const OP_SET_GUARDIAN: u8 = 10;
pub const OP_START_RECOVERY: u8 = 11;
pub const OP_CANCEL_RECOVERY: u8 = 12;
pub const OP_MANDATE_OPEN: u8 = 13;
pub const OP_CANCEL: u8 = 14;
pub const OP_INVALIDATE_NONCES: u8 = 15;

#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaOp {
    pub network: [u8; 32],
    pub contract: AccountId,
    pub op: u8,
    pub from: Holder,
    pub to: Holder,
    pub relayer: Option<AccountId>,
    pub amount: u128,
    pub pay_ref: [u8; 32],
    pub lane: [u8; 32],
    pub nonce: u64,
    /// Seconds (`env::block_timestamp() / 10^9`).
    pub valid_until: u64,
    pub extra: [u8; 32],
}

impl MetaOp {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = LABEL.to_vec();
        borsh::to_writer(&mut b, self).expect("borsh");
        b
    }

    pub fn digest(&self) -> [u8; 32] {
        env::sha256_array(self.encode())
    }
}

/// A DEX order (spec §3.6, plan Task 8): signed through its trade leg, op 1 with `to = Near(dex)`, `relayer =
/// Some(dex)`, `amount = sell_amount`, `extra = sha256(Borsh(Order))`; the order travels verbatim. Fill-or-kill: a
/// fill moves the whole `sell_amount` and pays at least `min_buy` of `buy_token`. `relayer`: the settlement submitter
/// (CTR-DEX-09), `None` = any. `expiry` in seconds; no leg moves after it.
#[near(serializers = [borsh])]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Order {
    pub sell_token: AccountId,
    pub buy_token: AccountId,
    pub sell_amount: u128,
    pub min_buy: u128,
    pub relayer: Option<AccountId>,
    pub expiry: u64,
}

impl Order {
    /// The leg op's `extra`.
    pub fn hash(&self) -> [u8; 32] {
        env::sha256_array(borsh::to_vec(self).expect("borsh"))
    }
}
