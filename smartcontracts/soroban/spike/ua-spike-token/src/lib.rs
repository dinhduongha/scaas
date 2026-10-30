//! T0 spike (plan UA-Soroban T0, spec §5.1): the token side of `ua_pay`. The token computes the NET-SOR-16 op digest,
//! calls the registry's `require_authorized` cross-contract (the registry does the record read, the WebAuthn checks
//! and `secp256r1_verify`), checks the receiver is `receivable` (a second registry call, reading `to`'s record), then
//! does the pay-lane write, the two balance writes and the three events. Never deployed outside the spike.
#![no_std]
#![allow(deprecated)] // events().publish

use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, vec, xdr::ToXdr, Address, Bytes, BytesN, Env, IntoVal, Symbol,
    Val, Vec,
};

const DAY: u32 = 17_280;

#[contracttype]
#[derive(Clone)]
pub enum Holder {
    Ua(BytesN<32>),
    Addr(Address),
}

#[contracttype]
pub enum DataKey {
    Registry,
    UaBal(BytesN<32>),
    UaNonce(BytesN<32>, BytesN<32>),
}

#[contractclient(name = "RegistryClient")]
pub trait Registry {
    fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes);
    fn receivable(env: Env, ua: BytesN<32>) -> bool;
}

fn h(env: &Env, b: &Bytes) -> BytesN<32> {
    env.crypto().keccak256(b).into()
}

fn put<V: IntoVal<Env, Val>>(env: &Env, k: &DataKey, v: &V) {
    env.storage().persistent().set(k, v);
    env.storage().persistent().extend_ttl(k, 30 * DAY, 60 * DAY);
}

/// NET-SOR-16 op digest: sha256(xdr(Vec[Symbol("scaas_metaop_v1"), network_id, contract, Symbol(fn), Vec(args)])),
/// the entry's arguments without `auth`.
fn op_digest(env: &Env, func: &str, args: Vec<Val>) -> BytesN<32> {
    let v: Vec<Val> = vec![
        env,
        Symbol::new(env, "scaas_metaop_v1").into_val(env),
        env.ledger().network_id().into_val(env),
        env.current_contract_address().into_val(env),
        Symbol::new(env, func).into_val(env),
        args.into_val(env),
    ];
    env.crypto().sha256(&v.to_xdr(env)).to_bytes()
}

fn pay_args(
    env: &Env,
    from: &BytesN<32>,
    to: &Holder,
    amount: i128,
    pay_ref: &BytesN<32>,
    valid_until: u64,
    relayer: &Option<Address>,
) -> Vec<Val> {
    vec![
        env,
        from.into_val(env),
        to.into_val(env),
        amount.into_val(env),
        pay_ref.into_val(env),
        valid_until.into_val(env),
        relayer.into_val(env),
    ]
}

#[contract]
pub struct UaSpikeToken;

#[contractimpl]
impl UaSpikeToken {
    pub fn __constructor(env: Env, registry: Address) {
        env.storage().instance().set(&DataKey::Registry, &registry);
    }

    /// Spike set-up only: a UA balance.
    pub fn mint_ua(env: Env, ua: BytesN<32>, amount: i128) {
        put(&env, &DataKey::UaBal(ua), &amount);
    }

    /// Spike helper: the op digest `ua_pay_model` computes for these arguments (the signer's input).
    pub fn pay_digest(
        env: Env,
        from: BytesN<32>,
        to: Holder,
        amount: i128,
        pay_ref: BytesN<32>,
        valid_until: u64,
        relayer: Option<Address>,
    ) -> BytesN<32> {
        op_digest(&env, "ua_pay", pay_args(&env, &from, &to, amount, &pay_ref, valid_until, &relayer))
    }

    /// `ua_pay(from, to, amount, pay_ref, valid_until, relayer, auth)` of spec §5.1.
    pub fn ua_pay_model(
        env: Env,
        from: BytesN<32>,
        to: Holder,
        amount: i128,
        pay_ref: BytesN<32>,
        valid_until: u64,
        relayer: Option<Address>,
        auth: Bytes,
    ) {
        assert!(env.ledger().timestamp() <= valid_until, "Expired");
        assert!(amount > 0, "Amount");
        if let Some(r) = &relayer {
            r.require_auth();
        }
        let digest = op_digest(&env, "ua_pay", pay_args(&env, &from, &to, amount, &pay_ref, valid_until, &relayer));
        let registry: Address = env.storage().instance().get(&DataKey::Registry).unwrap();
        let reg = RegistryClient::new(&env, &registry);
        let purpose = h(&env, &Bytes::from_slice(&env, b"scaas.ua.purpose.metatx.v1"));
        reg.require_authorized(&from, &purpose, &digest, &auth);
        let to_ua = match &to {
            Holder::Ua(u) => u.clone(),
            Holder::Addr(_) => panic!("spike: Holder::Ua only"),
        };
        assert!(reg.receivable(&to_ua), "UaNotReceivable");
        // lane = payLane(pay_ref) = keccak256("scaas.pay.lane" ‖ pay_ref), nonce 0, one-shot
        let mut l = Bytes::from_slice(&env, b"scaas.pay.lane");
        l.append(&pay_ref.clone().into());
        let nk = DataKey::UaNonce(from.clone(), h(&env, &l));
        if env.storage().persistent().get::<_, u64>(&nk).unwrap_or(0) != 0 {
            panic!("BadNonce");
        }
        put(&env, &nk, &1u64);
        let fk = DataKey::UaBal(from.clone());
        let bal: i128 = env.storage().persistent().get(&fk).unwrap_or(0);
        assert!(bal >= amount, "InsufficientBalance");
        put(&env, &fk, &(bal - amount));
        let tk = DataKey::UaBal(to_ua);
        let tb: i128 = env.storage().persistent().get(&tk).unwrap_or(0);
        put(&env, &tk, &(tb + amount));
        let e = env.events();
        let fh = Holder::Ua(from.clone());
        e.publish((Symbol::new(&env, "UaTransfer"),), (fh.clone(), to.clone(), amount));
        e.publish((Symbol::new(&env, "UaPaymentSettled"),), (fh, to, amount, pay_ref));
        e.publish((Symbol::new(&env, "UaMetaTransactionExecuted"),), (from, digest));
    }

    pub fn ua_balance(env: Env, ua: BytesN<32>) -> i128 {
        env.storage().persistent().get(&DataKey::UaBal(ua)).unwrap_or(0)
    }
}

#[cfg(test)]
mod test;
