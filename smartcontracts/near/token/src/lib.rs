//! SCaaS NEAR token (spec §3.1 row 1, §3.2): the NEP-141 ledger of native holders (near-contract-standards
//! `FungibleToken`), the UA ledger (`Ua` id → balance), storage paid by the caller (the relayer).
//!
//! UA pool: every UA balance is also held, in sum, by the token's own NEP-141 account (as EVM's `UA_POOL`), so
//! `ft_total_supply` = the sum of `ft_balance_of` over native accounts, the pool included, and a move with a UA side
//! emits the NEP-141 `ft_transfer` from / to the token account plus `"scaas"` `ua_transfer`.
use near_contract_standards::fungible_token::events::FtTransfer;
use near_contract_standards::fungible_token::metadata::FungibleTokenMetadata;
use near_contract_standards::fungible_token::FungibleToken;
use near_sdk::json_types::U128;
use near_sdk::store::LookupMap;
use near_sdk::{env, near, require, AccountId, PanicOnDefault};
pub use scaas_near_common::Holder;

mod ft;
mod storage;
pub use storage::{ACCOUNT_STORAGE_BYTES, UA_STORAGE_BYTES};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Token {
    network: [u8; 32],
    admin: AccountId,
    metadata: FungibleTokenMetadata,
    ft: FungibleToken,
    ua: LookupMap<[u8; 32], u128>,
}

/// SCaaS events (NEP-297, standard `"scaas"`); holders in `Holder`'s display form.
#[near(event_json(standard = "scaas"))]
pub enum Event {
    #[event_version("1.0.0")]
    UaTransfer { from: String, to: String, amount: U128 },
}

#[near]
impl Token {
    /// Borsh args; only the token account itself (the deploy run, before its keys are deleted). Pins both record
    /// sizes against a measurement and registers the token's own account (the UA pool), paid from its own balance.
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
        Self { network, admin, metadata, ft, ua }
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

    /// `debit` + `credit` + events: NEP-141 `ft_transfer` when a native balance changes (a UA side shows as the
    /// token account, the pool), `"scaas"` `ua_transfer` when a side is a UA.
    pub(crate) fn move_balance(&mut self, from: &Holder, to: &Holder, amount: u128, memo: Option<&str>) {
        require!(from != to, "Sender and receiver should be different");
        require!(amount > 0, "The amount should be a positive number");
        self.debit(from, amount);
        self.credit(to, amount);
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
}
