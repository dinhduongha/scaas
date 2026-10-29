//! Test-only relay target (Task 10, never deployed): what a router call can meet at the target.
//! - `ok()`: succeeds, keeps any attached deposit, logs the predecessor (the executor) and the deposit.
//! - `fail()`: panics.
//! - `spawn_fail()`: succeeds, but first spawns a detached call to its own `fail` (a failing child promise).
//! - `return_fail()`: succeeds and returns a call to its own `fail` (its result would be a failure).
//! - `wait()`: yields (NEP-519) and returns the yield: its result would be `on_resume`'s, after `resume(ok)`.
//! - `exec(..)` / `return_deposit(..)`: stands in for the router's executor in the timeout tests (a router created with
//!   this fixture as its executor): `exec` waits as `wait`, so the call stays in flight until `resume(ok)`;
//!   `return_deposit` only counts (`returns()`).
use near_sdk::{env, log, near, require, Gas, GasWeight, NearToken, Promise};

#[near(contract_state)]
#[derive(Default)]
pub struct Fixture {
    yield_id: Option<[u8; 32]>,
    returns: u32,
}

#[near]
impl Fixture {
    #[payable]
    pub fn ok(&mut self) {
        log!("fixture ok: predecessor {} deposit {}", env::predecessor_account_id(), env::attached_deposit().as_yoctonear());
    }

    #[payable]
    pub fn fail(&mut self) {
        env::panic_str("fixture fail");
    }

    #[payable]
    pub fn spawn_fail(&mut self) {
        Promise::new(env::current_account_id())
            .function_call_weight("fail", vec![], NearToken::from_yoctonear(0), Gas::from_tgas(3), GasWeight(0))
            .detach();
        log!("fixture spawned a failing child");
    }

    #[payable]
    pub fn return_fail(&mut self) -> Promise {
        log!("fixture returns a failing child");
        Promise::new(env::current_account_id()).function_call_weight("fail", vec![], NearToken::from_yoctonear(0), Gas::from_tgas(3), GasWeight(0))
    }

    #[payable]
    pub fn exec(&mut self) {
        self.wait();
    }

    pub fn return_deposit(&mut self) {
        self.returns += 1;
    }

    /// How many `return_deposit` calls arrived.
    pub fn returns(&self) -> u32 {
        self.returns
    }

    #[payable]
    pub fn wait(&mut self) {
        let idx = env::promise_yield_create("on_resume", [], Gas::from_tgas(5), GasWeight(0), 0);
        self.yield_id = Some(env::read_register(0).unwrap().try_into().unwrap());
        env::promise_return(idx);
    }

    /// Resumes `wait`: `ok` → it succeeds, else it panics.
    pub fn resume(&mut self, ok: bool) {
        let id = self.yield_id.take().unwrap_or_else(|| env::panic_str("nothing waits"));
        require!(env::promise_yield_resume(&id, [ok as u8]), "yield not found");
    }

    #[private]
    pub fn on_resume(&mut self) {
        match env::promise_result_checked(0, 1) {
            Ok(v) if v == [1] => log!("fixture resumed ok"),
            _ => env::panic_str("fixture resumed with failure"),
        }
    }
}
