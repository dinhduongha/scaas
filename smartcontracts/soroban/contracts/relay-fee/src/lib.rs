//! CTR-MTX-27 trên Soroban: trả phí token cho một lời gọi không có phí riêng (không owner; chỉ lưu `executor`).
//!
//! `payer.require_auth_for_args((target, func, args, salt, token, to, amount, valid_until))` — auth entry của payer có
//! gốc là chính lời gọi `relay`, với `token.pay` là sub-invocation duy nhất của khoản trả: chữ ký không cho phép
//! `token.pay` gọi trực tiếp (host chỉ khớp cây gọi). `relayer` là nguồn của giao dịch.
//! `relayer.require_auth()`: tx source KHÔNG tự thoả; node thêm auth entry `SourceAccount` gốc là chính lời gọi `relay`.
//!
//! The target call goes through `executor.exec(target, func, args)` (EVM executor parity; controller ruling 2026-10-31
//! after the T8 review): Soroban grants the router's authority to every contract the router calls directly, so a
//! target called by the router itself could settle a victim's router-bound `ua_pay` or move a router balance. The
//! token is called directly only for the fee (`pay` / `ua_pay`) and the open-mode forward. The executor is bound at
//! construction (`__constructor(executor)`, the executor's own constructor names this router).
//!
//! `ua_relay` (spec §5.4): the payer is a UA; the fee is `token.ua_pay(payer, to, amount, ref, valid_until,
//! Some(router), auth)`, whose UA signature covers `pay_ref = ref` and `relayer = router`; only the router's own
//! fee call satisfies `router.require_auth()`. `RelayFeePaid` names `payer` and `payee` as `Holder` (SOR-D11).
#![no_std]
use scaas_ua_common::Holder;
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

/// `payer`, `payee`: `Holder` (SOR-D11: a UA payer of `ua_relay`, a UA bound payee); open mode: the payee is the
/// submitting relayer, otherwise `to`.
#[contractevent(topics = ["RelayFeePaid"], data_format = "vec")]
pub struct RelayFeePaid {
    #[topic]
    pub call_ref: BytesN<32>,
    #[topic]
    pub target: Address,
    #[topic]
    pub token: Address,
    pub payer: Holder,
    pub payee: Holder,
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

/// `BadPayee`, `TargetNoCode`, then `executor.exec(target, func, args)` (never as the router); returns its `ref`
/// (computed before the call).
fn run(env: &Env, to: &Holder, relayer: &Address, target: &Address, func: &Symbol, args: Vec<Val>, salt: &BytesN<32>) -> BytesN<32> {
    let (me, exec) = (env.current_contract_address(), executor(env));
    let payee = if *to == Holder::Addr(me.clone()) { Holder::Addr(relayer.clone()) } else { to.clone() };
    if payee == Holder::Addr(me) || payee == Holder::Addr(exec.clone()) {
        panic_with_error!(env, Error::BadPayee);
    }
    // The target must be an instantiated contract, before any call (a call to nothing would "succeed").
    if !matches!(target.executable(), Some(Executable::Wasm(_)) | Some(Executable::StellarAsset)) {
        panic_with_error!(env, Error::TargetNoCode);
    }
    let call_ref = relay_ref(env, target, func, &args, salt);
    env.invoke_contract::<Val>(&exec, &Symbol::new(env, "exec"), vec![env, target.to_val(), func.to_val(), args.to_val()]);
    call_ref
}

/// After the fee reached `to`: open mode (`to == router`) forwards it to `relayer`; then `RelayFeePaid`.
#[allow(clippy::too_many_arguments)]
fn settle(env: &Env, call_ref: BytesN<32>, target: Address, token: Address, payer: Holder, to: Holder, amount: i128, relayer: Address) {
    let me = env.current_contract_address();
    let payee = if to == Holder::Addr(me.clone()) {
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(env, "transfer"),
            vec![env, me.to_val(), relayer.to_val(), amount.into_val(env)],
        );
        Holder::Addr(relayer)
    } else {
        to
    };
    RelayFeePaid { call_ref, target, token, payer, payee, amount }.publish(env);
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
        let call_ref = run(&env, &Holder::Addr(to.clone()), &relayer, &target, &func, args, &salt);
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "pay"),
            vec![&env, payer.to_val(), to.to_val(), amount.into_val(&env), call_ref.to_val(), valid_until.into_val(&env)],
        );
        settle(&env, call_ref, target, token, Holder::Addr(payer), Holder::Addr(to), amount, relayer);
    }

    /// `relay` for a UA payer (spec §5.4): runs `target.func(args)`, then `token.ua_pay(payer, to, amount, ref,
    /// valid_until, Some(router), auth)`; the UA signature covers `ref`, `to`, `amount` and `relayer = router`.
    /// Open mode (`to == Holder::Addr(router)`) forwards to `relayer`; any failure reverts both.
    #[allow(clippy::too_many_arguments)]
    pub fn ua_relay(env: Env, payer: BytesN<32>, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>,
                    token: Address, to: Holder, amount: i128, valid_until: u64, relayer: Address, auth: Bytes) {
        relayer.require_auth();
        let call_ref = run(&env, &to, &relayer, &target, &func, args, &salt);
        let me = Some(env.current_contract_address());
        let a = (payer.clone(), to.clone(), amount, call_ref.clone(), valid_until, me, auth);
        env.invoke_contract::<()>(&token, &Symbol::new(&env, "ua_pay"), a.into_val(&env));
        settle(&env, call_ref, target, token, Holder::Ua(payer), to, amount, relayer);
    }

    pub fn relay_ref(env: Env, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>) -> BytesN<32> {
        relay_ref(&env, &target, &func, &args, &salt)
    }
}

#[cfg(test)]
mod test;
