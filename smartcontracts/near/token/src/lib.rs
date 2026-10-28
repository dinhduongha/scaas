//! SCaaS NEAR token (spec §3.1 row 1, §3.2): the NEP-141 ledger of native holders (near-contract-standards
//! `FungibleToken`), the UA ledger (`Ua` id → balance), storage paid by the caller (the relayer).
//!
//! UA pool: every UA balance is also held, in sum, by the token's own NEP-141 account (as EVM's `UA_POOL`), so
//! `ft_total_supply` = the sum of `ft_balance_of` over native accounts, the pool included, and a move with a UA side
//! emits the NEP-141 `ft_transfer` from / to the token account plus `"scaas"` `ua_transfer`. The relay router's escrow
//! (Task 10, `escrow.rs`) sits in the same account while a relay is in flight: `ft_balance_of(token)` = the UA total +
//! the held total.
use near_contract_standards::fungible_token::events::FtTransfer;
use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, PanicOnDefault};
pub use scaas_near_common::{Auth, Holder, MetaOp, Order};
use scaas_near_common::ua::{KeyRecord, KIND_ED25519};

mod account;
mod escrow;
mod ft;
mod mandate;
mod metatx;
mod relayfee;
mod storage;
mod trade;
pub use escrow::{held_bytes, Held, HELD_RECORD_OVERHEAD};
pub use account::{
    record_bytes, Check, Recovery, Subject, KEYOP_FINISH_RECOVERY, KEYOP_SET_POLICY, MAX_KEYS, MAX_ORIGINS, POLICY_PASSKEY_FOR_VALUE,
    RECOVERY_DELAY_S, SUBJECT_RECORD_OVERHEAD,
};
pub use mandate::{mandate_bytes, Mandate, MandateTerms, MANDATE_RECORD_OVERHEAD};
pub use metatx::{lane_bytes, LANE_RECORD_OVERHEAD};
pub use relayfee::wrapper_ref;
pub use storage::{ACCOUNT_STORAGE_BYTES, UA_STORAGE_BYTES};
pub use trade::{min_nonce_bytes, order_bytes, OrderClose, MIN_NONCE_CAP, TRADE_RECORD_OVERHEAD};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Token {
    network: [u8; 32],
    admin: AccountId,
    metadata: FungibleTokenMetadata,
    ft: FungibleToken,
    ua: LookupMap<[u8; 32], u128>,
    /// Subject accounts (keys, origins, guardian, recovery), spec §3.3.
    subjects: LookupMap<Holder, Subject>,
    /// Lanes per payer, `(from, lane)` → the next nonce (spec §2 row 6, §3.7); never removed.
    lanes: LookupMap<(Holder, [u8; 32]), u64>,
    /// Mandates by id (spec §3.6); never removed. Their funds sit in `ua` under the same id.
    mandates: LookupMap<[u8; 32], Mandate>,
    /// Closed orders `(holder, lane, nonce)` (spec §3.6); never removed.
    orders: LookupMap<(Holder, [u8; 32], u64), OrderClose>,
    /// `min_nonce` per `(holder, order lane)` (CTR-DEX-10); never removed.
    min_nonces: LookupMap<(Holder, [u8; 32]), u64>,
    /// Relay escrow `(router, pay_ref)` → the held payment (spec §3.8 router steps 2, 6); removed at release / refund.
    held: LookupMap<(AccountId, [u8; 32]), Held>,
    /// Bytes of new records this call created, paid once by `charge_storage` (not state).
    #[borsh(skip)]
    storage_due: u64,
}

/// SCaaS events (NEP-297, standard `"scaas"`); holders in `Holder`'s display form.
#[near(event_json(standard = "scaas"))]
pub enum Event {
    #[event_version("1.0.0")]
    UaTransfer { from: String, to: String, amount: U128 },
    /// A subject account's keys changed (`action`: the key op or `add_key_native`).
    #[event_version("1.0.0")]
    KeyOp { subject: String, action: String },
    /// CTR-MTX-26: `mtx_pay_meta`'s `meta` (never parsed), before its `payment_settled`; bytes as `0x` ‖ hex.
    #[event_version("1.0.0")]
    PaymentMeta { pay_ref: String, meta: String },
    /// A value entry with a `pay_ref` (`mtx_pay`, `mtx_pay_meta`, `mtx_execute_transfer` with `pay_ref ≠ 0`).
    #[event_version("1.0.0")]
    PaymentSettled { from: String, to: String, amount: U128, pay_ref: String },
    /// Every value entry: the signer, the submitting account, the lane and nonce consumed, the op digest.
    #[event_version("1.0.0")]
    MetaTransactionExecuted { from: String, relayer: String, lane: String, nonce: u64, digest: String },
    /// A mandate opened (`by` the owner) or revoked (`by` the owner or the delegate); id as `0x` ‖ hex.
    #[event_version("1.0.0")]
    Mandate { mandate: String, action: String, by: String },
    /// A trade leg moved `amount` from `from` into `dex`'s balance (order `(from, lane, nonce)`, leg op `digest`).
    #[event_version("1.0.0")]
    OrderFilled { from: String, dex: String, lane: String, nonce: u64, amount: U128, digest: String },
    #[event_version("1.0.0")]
    OrderCancelled { from: String, lane: String, nonce: u64 },
    #[event_version("1.0.0")]
    NoncesInvalidated { from: String, lane: String, min_nonce: u64 },
    /// CTR-MTX-27: a `relay_fee_<entry>` wrapper's payment settled (`target` = `token` = this token), the call's last log.
    #[event_version("1.0.0")]
    RelayFeePaid { r#ref: String, target: String, token: String, payer: String, payee: String, amount: U128 },
}

#[near]
impl Token {
    /// Borsh args; only the token account itself (the deploy run, before its keys are deleted). Pins every record
    /// size against a measurement and registers the token's own account (the UA pool), paid from its own balance.
    #[init]
    #[private]
    pub fn new(
        #[serializer(borsh)] network: [u8; 32],
        #[serializer(borsh)] admin: AccountId,
        #[serializer(borsh)] metadata: FungibleTokenMetadata,
    ) -> Self {
        metadata.assert_valid();
        let mut ft = FungibleToken::new(b"f");
        require!(ft.account_storage_usage == ACCOUNT_STORAGE_BYTES, "account record size differs from the pin");
        ft.internal_register_account(&env::current_account_id());
        let mut ua = LookupMap::new(b"u");
        let u0 = env::storage_usage();
        ua.insert([0xff; 32], 0);
        ua.flush();
        require!(env::storage_usage() - u0 == UA_STORAGE_BYTES, "UA record size differs from the pin");
        ua.remove(&[0xff; 32]);
        ua.flush();
        let mut subjects = LookupMap::new(b"a");
        let (h, s) = (Holder::Ua([0xff; 32]), Subject {
            keys: vec![KeyRecord { kind: KIND_ED25519, key_data: vec![0; 32] }],
            ..Default::default()
        });
        let u0 = env::storage_usage();
        subjects.insert(h.clone(), s.clone());
        subjects.flush();
        require!(env::storage_usage() - u0 == record_bytes(&h, &s), "subject record size differs from the pin");
        subjects.remove(&h);
        subjects.flush();
        let mut lanes = LookupMap::new(b"l");
        let u0 = env::storage_usage();
        lanes.insert((h.clone(), [0xff; 32]), 1);
        lanes.flush();
        require!(env::storage_usage() - u0 == lane_bytes(&h), "lane record size differs from the pin");
        lanes.remove(&(h.clone(), [0xff; 32]));
        lanes.flush();
        let mut mandates = LookupMap::new(b"m");
        let terms = MandateTerms { delegate: h.clone(), payee: h.clone(), per_payment: 1, per_period: 1, period_s: 1, expiry: 1, funding: 1 };
        let m = Mandate { owner: h, terms, period_start: 0, spent: 0, revoked: false };
        let u0 = env::storage_usage();
        mandates.insert([0xff; 32], m.clone());
        mandates.flush();
        require!(env::storage_usage() - u0 == mandate_bytes(&m), "mandate record size differs from the pin");
        mandates.remove(&[0xff; 32]);
        mandates.flush();
        let (mut orders, mut min_nonces) = (LookupMap::new(b"o"), LookupMap::new(b"n"));
        let (h, f) = (Holder::Ua([0xff; 32]), OrderClose::Filled([0xff; 32]));
        let u0 = env::storage_usage();
        orders.insert((h.clone(), [0xff; 32], 1), f.clone());
        orders.flush();
        require!(env::storage_usage() - u0 == order_bytes(&h, &f), "order record size differs from the pin");
        orders.remove(&(h.clone(), [0xff; 32], 1));
        orders.flush();
        let u0 = env::storage_usage();
        min_nonces.insert((h.clone(), [0xff; 32]), 1);
        min_nonces.flush();
        require!(env::storage_usage() - u0 == min_nonce_bytes(&h), "min_nonce record size differs from the pin");
        min_nonces.remove(&(h.clone(), [0xff; 32]));
        min_nonces.flush();
        let mut held = LookupMap::new(b"h");
        let me = env::current_account_id();
        let x = Held { payer: h.clone(), payee: h, amount: 1, relayer: me.clone(), deposit: 1 };
        let u0 = env::storage_usage();
        held.insert((me.clone(), [0xff; 32]), x.clone());
        held.flush();
        require!(env::storage_usage() - u0 == held_bytes(&me, &x), "held record size differs from the pin");
        held.remove(&(me, [0xff; 32]));
        held.flush();
        Self { network, admin, metadata, ft, ua, subjects, lanes, mandates, orders, min_nonces, held, storage_due: 0 }
    }

    /// Admin only (tier 1). An unregistered receiver is registered from the deposit, as `ft_transfer`.
    #[payable]
    pub fn mint(&mut self, to: AccountId, amount: U128) {
        require!(env::predecessor_account_id() == self.admin, "mint: admin only");
        require!(amount.0 > 0, "The amount should be a positive number");
        let to = Holder::Near(to);
        self.pay_receiver_storage(&to);
        self.credit(&to, amount.0);
        if let Holder::Near(a) = &to {
            near_contract_standards::fungible_token::events::FtMint { owner_id: a, amount, memo: None }.emit();
        }
    }

    pub fn network(&self) -> [u8; 32] {
        self.network
    }

    pub fn ua_balance_of(&self, id: [u8; 32]) -> U128 {
        U128(self.ua.get(&id).copied().unwrap_or(0))
    }
}

impl Token {
    /// Adds to a holder's balance (and the total supply). The receiver's record must exist: a native receiver
    /// registered, a UA record created by `pay_receiver_storage` (which charges its storage) — never an unpaid record.
    /// The token itself never receives (spec §2 row 12).
    pub(crate) fn credit(&mut self, to: &Holder, amount: u128) {
        match to {
            Holder::Near(a) => {
                require!(*a != env::current_account_id(), "token refuses a transfer to the token itself");
                self.ft.internal_deposit(a, amount);
            }
            Holder::Ua(id) => {
                let b = *self.ua.get(id).unwrap_or_else(|| env::panic_str("UA record not paid for"));
                self.ua.insert(*id, b.checked_add(amount).unwrap_or_else(|| env::panic_str("Balance overflow")));
                self.ft.internal_deposit(&env::current_account_id(), amount);
            }
        }
    }

    /// Takes from a holder's balance (and the total supply); panics on a short balance. The token's own account is
    /// the UA pool, moved only through `Ua` holders, never debited as a native holder.
    pub(crate) fn debit(&mut self, from: &Holder, amount: u128) {
        match from {
            Holder::Near(a) => {
                require!(*a != env::current_account_id(), "the UA pool is never debited as a native holder");
                self.ft.internal_withdraw(a, amount)
            }
            Holder::Ua(id) => {
                let b = self.ua.get(id).copied().unwrap_or_else(|| env::panic_str("The UA has no balance"));
                require!(b >= amount, "The UA doesn't have enough balance");
                self.ua.insert(*id, b - amount);
                self.ft.internal_withdraw(&env::current_account_id(), amount);
            }
        }
    }

    /// `debit` + `credit` + `transfer_events`.
    pub(crate) fn move_balance(&mut self, from: &Holder, to: &Holder, amount: u128, memo: Option<&str>) {
        require!(from != to, "Sender and receiver should be different");
        require!(amount > 0, "The amount should be a positive number");
        self.debit(from, amount);
        self.credit(to, amount);
        transfer_events(from, to, amount, memo);
    }
}

/// NEP-141 `ft_transfer` when a native balance changes (a UA side, and the relay escrow `Near(token)`, show as the
/// token account), `"scaas"` `ua_transfer` when a side is a UA.
pub(crate) fn transfer_events(from: &Holder, to: &Holder, amount: u128, memo: Option<&str>) {
    let pool = env::current_account_id();
    let native = |h: &Holder| match h {
        Holder::Near(a) => a.clone(),
        Holder::Ua(_) => pool.clone(),
    };
    let (old, new) = (native(from), native(to));
    if old != new {
        FtTransfer { old_owner_id: &old, new_owner_id: &new, amount: U128(amount), memo }.emit();
    }
    if matches!(from, Holder::Ua(_)) || matches!(to, Holder::Ua(_)) {
        Event::UaTransfer { from: from.to_string(), to: to.to_string(), amount: U128(amount) }.emit();
    }
}
