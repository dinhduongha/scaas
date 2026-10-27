//! Test-only NEP-141 receiver for `integration/tests/token.rs` (`ft_transfer_call_resolves_as_nep141`).
use near_sdk::json_types::U128;
use near_sdk::{env, near, AccountId, PromiseOrValue};

#[near(contract_state)]
#[derive(Default)]
pub struct Receiver {}

#[near]
impl Receiver {
    /// Returns `msg` (a decimal) as the unused amount; `msg == "panic"` fails the call (the token refunds all).
    pub fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> PromiseOrValue<U128> {
        let _ = (sender_id, amount);
        if msg == "panic" {
            env::panic_str("receiver refuses");
        }
        PromiseOrValue::Value(U128(msg.parse().unwrap()))
    }
}
