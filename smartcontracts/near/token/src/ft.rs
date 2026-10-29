//! NEP-141 / NEP-148 (spec §3.2): standard methods; an unregistered receiver is registered from the attached deposit
//! (`Token::pay_receiver_storage`); `transfer_to_ua` moves a native balance into the UA ledger.
use crate::{Holder, Token, TokenExt};
use near_contract_standards::fungible_token::core::FungibleTokenCore;
use near_contract_standards::fungible_token::metadata::{FungibleTokenMetadata, FungibleTokenMetadataProvider};
use near_contract_standards::fungible_token::receiver::ext_ft_receiver;
use near_contract_standards::fungible_token::resolver::{ext_ft_resolver, FungibleTokenResolver};
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, Gas, PromiseOrValue};

/// As near-contract-standards `core_impl` (private there).
const GAS_FOR_RESOLVE_TRANSFER: Gas = Gas::from_tgas(5);

#[near]
impl FungibleTokenCore for Token {
    #[payable]
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>) {
        let to = Holder::Near(receiver_id);
        self.pay_receiver_storage(&to);
        self.move_balance(&Holder::Near(env::predecessor_account_id()), &to, amount.0, memo.as_deref());
    }

    #[payable]
    fn ft_transfer_call(
        &mut self,
        receiver_id: AccountId,
        amount: U128,
        memo: Option<String>,
        msg: String,
    ) -> PromiseOrValue<U128> {
        let sender_id = env::predecessor_account_id();
        let to = Holder::Near(receiver_id.clone());
        self.pay_receiver_storage(&to);
        self.move_balance(&Holder::Near(sender_id.clone()), &to, amount.0, memo.as_deref());
        ext_ft_receiver::ext(receiver_id.clone())
            .with_unused_gas_weight(1)
            .ft_on_transfer(sender_id.clone(), amount, msg)
            .then(
                ext_ft_resolver::ext(env::current_account_id())
                    .with_static_gas(GAS_FOR_RESOLVE_TRANSFER)
                    .with_unused_gas_weight(0)
                    .ft_resolve_transfer(sender_id, receiver_id, amount),
            )
            .into()
    }

    fn ft_total_supply(&self) -> U128 {
        self.ft.ft_total_supply()
    }

    fn ft_balance_of(&self, account_id: AccountId) -> U128 {
        self.ft.ft_balance_of(account_id)
    }
}

#[near]
impl FungibleTokenResolver for Token {
    /// NEP-141: the unused amount back from the receiver (the sender is always registered: balances are permanent).
    #[private]
    fn ft_resolve_transfer(&mut self, sender_id: AccountId, receiver_id: AccountId, amount: U128) -> U128 {
        self.ft.internal_ft_resolve_transfer(&sender_id, receiver_id, amount).0.into()
    }
}

#[near]
impl FungibleTokenMetadataProvider for Token {
    fn ft_metadata(&self) -> FungibleTokenMetadata {
        self.metadata.clone()
    }
}

#[near]
impl Token {
    /// EVM `transferToUA`: the predecessor's native balance into UA `id`. 1 yoctoNEAR when the UA record exists, else
    /// attached ≥ its storage cost, the excess refunded.
    #[payable]
    pub fn transfer_to_ua(&mut self, id: [u8; 32], amount: U128) {
        let to = Holder::Ua(id);
        self.pay_receiver_storage(&to);
        self.move_balance(&Holder::Near(env::predecessor_account_id()), &to, amount.0, None);
    }
}
