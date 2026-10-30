//! CTR-MTX-27 executor of the relay-fee router (EVM `MtxRelayFee`'s executor parity; controller ruling 2026-10-31
//! after the T8 review): the router never calls a target as itself. Soroban grants a contract's authority to every
//! contract it calls directly, so a target called by the router would see `router.require_auth()` satisfied (a
//! router-bound `ua_pay` settled without its call, a router balance drained). The router calls `exec`, and the
//! target sees this executor as its invoker. Holds nothing: the router refuses it as a payee.
#![no_std]
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Symbol, Val, Vec};

const DAY: u32 = 17_280;

#[contracttype]
enum Key {
    Router,
}

#[contract]
pub struct RelayExecutor;

#[contractimpl]
impl RelayExecutor {
    /// Bound to one router for life (deploy: the router's id is computed first, see `deploy.sh soroban`).
    pub fn __constructor(env: Env, router: Address) {
        env.storage().instance().set(&Key::Router, &router);
    }

    pub fn router(env: Env) -> Address {
        env.storage().instance().get(&Key::Router).unwrap()
    }

    /// `target.func(args)` as this executor; only the router (its direct invoker) may call it.
    pub fn exec(env: Env, target: Address, func: Symbol, args: Vec<Val>) -> Val {
        Self::router(env.clone()).require_auth();
        env.storage().instance().extend_ttl(30 * DAY, 60 * DAY);
        env.invoke_contract(&target, &func, args)
    }
}
