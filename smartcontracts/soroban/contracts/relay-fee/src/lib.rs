//! CTR-MTX-27 trên Soroban: trả phí token cho một lời gọi không có phí riêng (không owner; chỉ lưu `executor`).
//!
//! `payer.require_auth_for_args((target, func, args, salt, token, to, amount, valid_until))` — auth entry của payer có
//! gốc là chính lời gọi `relay`, với `token.pay` là sub-invocation duy nhất của khoản trả: chữ ký không cho phép
//! `token.pay` gọi trực tiếp (host chỉ khớp cây gọi). `relayer` là nguồn của giao dịch.
//! `relayer.require_auth()`: tx source KHÔNG tự thoả; node thêm auth entry `SourceAccount` gốc là chính lời gọi `relay`.
//!
//! The target call goes through `executor.exec(target, func, args)` (EVM executor parity; controller ruling 2026-10-31
//! after the UA-Soroban T8 review): Soroban grants the router's authority to every contract the router calls directly,
//! so a target called by the router itself could move a router balance (`token.transfer(router, …)`). The token is
//! called directly only for the fee (`pay`) and the open-mode forward. The executor is bound at construction
//! (`__constructor(executor)`, checked against the executor's own `router()`); the fee never rests on the router or
//! the executor (`BadPayee`).
#![no_std]
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, vec, xdr::ToXdr, Address,
    Bytes, BytesN, Env, Executable, IntoVal, Symbol, Val, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Target không phải contract đã khởi tạo (chưa deploy, account thường): khoản trả sẽ mất mà việc không xảy ra.
    TargetNoCode = 1,
    /// The fee would rest on the router or the executor (`to`, or the relayer in open mode).
    BadPayee = 2,
    /// The constructor's executor is not bound to this router (`executor.router() != self`).
    BadExecutor = 3,
}

const DAY: u32 = 17_280;

#[contracttype]
enum Key {
    Executor,
}

fn executor(env: &Env) -> Address {
    env.storage().instance().extend_ttl(30 * DAY, 60 * DAY);
    env.storage().instance().get(&Key::Executor).unwrap()
}

/// `payer`, `payee`: `Address` như event mang (open mode: người gửi giao dịch, ngược lại `to`).
#[contractevent(topics = ["RelayFeePaid"], data_format = "vec")]
pub struct RelayFeePaid {
    #[topic]
    pub call_ref: BytesN<32>,
    #[topic]
    pub target: Address,
    #[topic]
    pub token: Address,
    pub payer: Address,
    pub payee: Address,
    pub amount: i128,
}

/// `keccak256("scaas.relayfee" ‖ network_id ‖ xdr(target) ‖ keccak256(xdr((func, args))) ‖ salt)`.
/// `salt`: 32 bytes the payer signs (the auth entry carries it), so two identical calls get distinct refs.
fn relay_ref(env: &Env, target: &Address, func: &Symbol, args: &Vec<Val>, salt: &BytesN<32>) -> BytesN<32> {
    let mut b = Bytes::from_slice(env, b"scaas.relayfee");
    b.append(&env.ledger().network_id().into());
    b.append(&target.to_xdr(env));
    b.append(&env.crypto().keccak256(&(func.clone(), args.clone()).to_xdr(env)).to_bytes().into());
    b.append(&salt.clone().into());
    env.crypto().keccak256(&b).into()
}

#[contract]
pub struct RelayFee;

#[contractimpl]
impl RelayFee {
    /// The executor's constructor names this router (deploy: the router id first, see `deploy.sh soroban`), checked
    /// here so a mismatched pair fails at deploy, not at the first relay (`BadExecutor`).
    pub fn __constructor(env: Env, executor: Address) {
        let bound: Address = env.invoke_contract(&executor, &Symbol::new(&env, "router"), vec![&env]);
        if bound != env.current_contract_address() {
            panic_with_error!(&env, Error::BadExecutor);
        }
        env.storage().instance().set(&Key::Executor, &executor);
    }

    pub fn executor(env: Env) -> Address {
        executor(&env)
    }

    /// Chạy `target.func(args)` rồi `token.pay(payer, …, amount, ref, valid_until)`; lỗi nào cũng hoàn tác cả hai.
    /// Open mode (`to == router`): khoản trả về router rồi chuyển cho `relayer` (auth entry của payer phải biết
    /// trước người nhận, mà relayer chưa biết lúc ký). Bound payee: trả thẳng `to`.
    pub fn relay(env: Env, payer: Address, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>, token: Address,
                 to: Address, amount: i128, valid_until: u64, relayer: Address) {
        relayer.require_auth();
        let signed: Vec<Val> = (target.clone(), func.clone(), args.clone(), salt.clone(), token.clone(), to.clone(), amount, valid_until)
            .into_val(&env);
        payer.require_auth_for_args(signed);
        let (me, exec) = (env.current_contract_address(), executor(&env));
        let open = to == me;
        let payee = if open { relayer } else { to.clone() };
        if payee == me || payee == exec {
            panic_with_error!(&env, Error::BadPayee);
        }
        // The target must be an instantiated contract, before any call (a call to nothing would "succeed").
        if !matches!(target.executable(), Some(Executable::Wasm(_)) | Some(Executable::StellarAsset)) {
            panic_with_error!(&env, Error::TargetNoCode);
        }
        let call_ref = relay_ref(&env, &target, &func, &args, &salt);
        // never as the router: the target sees the executor as its invoker
        env.invoke_contract::<Val>(&exec, &Symbol::new(&env, "exec"), vec![&env, target.to_val(), func.to_val(), args.to_val()]);
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "pay"),
            vec![&env, payer.to_val(), to.to_val(), amount.into_val(&env), call_ref.to_val(), valid_until.into_val(&env)],
        );
        if open {
            env.invoke_contract::<()>(
                &token,
                &Symbol::new(&env, "transfer"),
                vec![&env, me.to_val(), payee.to_val(), amount.into_val(&env)],
            );
        }
        RelayFeePaid { call_ref, target, token, payer, payee, amount }.publish(&env);
    }

    pub fn relay_ref(env: Env, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>) -> BytesN<32> {
        relay_ref(&env, &target, &func, &args, &salt)
    }
}

#[cfg(test)]
mod test;
