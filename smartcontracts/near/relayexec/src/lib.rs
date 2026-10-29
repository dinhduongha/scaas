//! SCaaS NEAR relay executor (spec §3.8 step 4, §2 row 11; CTR-MTX-27 "The executor"): the router never calls a target
//! itself, so a forwarded call can never be a token entry with the router as predecessor (the payer-named relayer of
//! every router-bound payment). Only the router calls it; it has no admin, no keys (§3.9) and holds nothing above its
//! own storage stake:
//! - `exec(target, method, args, target_gas)`: calls `target` with exactly the attached deposit (the relayer-paid
//!   `target_deposit`) and `target_gas`, and returns that call, so the router's callback reads the target's own result
//!   (ruling T10-e). The call goes out as one receipt of two actions, the function call then a 0-yoctoNEAR transfer: a
//!   receipt's result is its last action's, so a promise the target returns does not become the result (it runs on, its
//!   outcome unread). The router therefore sees exactly the target's own receipt: success, or failure — and only a failed
//!   receipt refunds its deposit, here, so `return_deposit` is asked only for a deposit that comes back;
//! - `return_deposit(to, amount)`: after a failed call, sends the deposit NEAR refunded here back to the relayer `to`.
//!   It fails while that refund has not landed (the balance would drop below the storage stake); the router then keeps
//!   its entry and forwards it at `relay_timeout`.
use near_sdk::json_types::U128;
use near_sdk::{env, near, require, AccountId, Gas, GasWeight, NearToken, PanicOnDefault, Promise};

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Executor {
    router: AccountId,
}

#[near]
impl Executor {
    /// Borsh args; only the executor account itself (the deploy run, before its keys are deleted).
    #[init]
    #[private]
    pub fn new(#[serializer(borsh)] router: AccountId) -> Self {
        Self { router }
    }

    #[payable]
    pub fn exec(
        &mut self,
        #[serializer(borsh)] target: AccountId,
        #[serializer(borsh)] method: String,
        #[serializer(borsh)] args: Vec<u8>,
        #[serializer(borsh)] target_gas: Gas,
    ) -> Promise {
        self.router_only();
        Promise::new(target)
            .function_call_weight(method, args, env::attached_deposit(), target_gas, GasWeight(0))
            .transfer(NearToken::from_yoctonear(0))
    }

    pub fn return_deposit(&mut self, #[serializer(borsh)] to: AccountId, #[serializer(borsh)] amount: U128) {
        self.router_only();
        // T19 ruling A: never a zero-amount return (the router asks only for a deposit that came back)
        if amount.0 > 0 {
            Promise::new(to).transfer(NearToken::from_yoctonear(amount.0)).detach();
        }
    }

    #[result_serializer(borsh)]
    pub fn router(&self) -> AccountId {
        self.router.clone()
    }
}

impl Executor {
    fn router_only(&self) {
        require!(env::predecessor_account_id() == self.router, "only the router calls the executor");
    }
}
