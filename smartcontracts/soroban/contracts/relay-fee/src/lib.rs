//! CTR-MTX-27 trên Soroban: trả phí token cho một lời gọi không có phí riêng (stateless, không owner).
//!
//! `payer.require_auth_for_args((target, func, args, salt, token, to, amount, valid_until))` — auth entry của payer có
//! gốc là chính lời gọi `relay`, với `token.pay` là sub-invocation duy nhất của khoản trả: chữ ký không cho phép
//! `token.pay` gọi trực tiếp (host chỉ khớp cây gọi). `relayer` là nguồn của giao dịch.
//! `relayer.require_auth()`: tx source KHÔNG tự thoả; node thêm auth entry `SourceAccount` gốc là chính lời gọi `relay`.
//! Không cần executor: Soroban cấm contract re-entry, auth entry của khoản trả khác gốc ở lời gọi `relay` của nó.
//!
//! `ua_relay` (spec §5.4): the payer is a UA; the fee is `token.ua_pay(payer, to, amount, ref, valid_until,
//! Some(router), auth)`, whose UA signature covers `pay_ref = ref` and `relayer = router`, so only the router (the
//! direct invoker) settles it. `RelayFeePaid` names `payer` and `payee` as `Holder` for both entries (SOR-D11).
#![no_std]
use scaas_ua_common::Holder;
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, panic_with_error, vec, xdr::ToXdr, Address, Bytes, BytesN,
    Env, Executable, IntoVal, Symbol, Val, Vec,
};

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    /// Target không phải contract đã khởi tạo (chưa deploy, account thường): khoản trả sẽ mất mà việc không xảy ra.
    TargetNoCode = 1,
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

/// Runs `target.func(args)` after `TargetNoCode`; returns its `ref` (computed before the call).
fn run(env: &Env, target: &Address, func: &Symbol, args: Vec<Val>, salt: &BytesN<32>) -> BytesN<32> {
    // The target must be an instantiated contract, before any call (a call to nothing would "succeed").
    if !matches!(target.executable(), Some(Executable::Wasm(_)) | Some(Executable::StellarAsset)) {
        panic_with_error!(env, Error::TargetNoCode);
    }
    let call_ref = relay_ref(env, target, func, &args, salt);
    env.invoke_contract::<Val>(target, func, args);
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
    /// Chạy `target.func(args)` rồi `token.pay(payer, …, amount, ref, valid_until)`; lỗi nào cũng hoàn tác cả hai.
    /// Open mode (`to == router`): khoản trả về router rồi chuyển cho `relayer` (auth entry của payer phải biết
    /// trước người nhận, mà relayer chưa biết lúc ký). Bound payee: trả thẳng `to`.
    pub fn relay(env: Env, payer: Address, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>, token: Address,
                 to: Address, amount: i128, valid_until: u64, relayer: Address) {
        relayer.require_auth();
        let signed: Vec<Val> = (target.clone(), func.clone(), args.clone(), salt.clone(), token.clone(), to.clone(), amount, valid_until)
            .into_val(&env);
        payer.require_auth_for_args(signed);
        let call_ref = run(&env, &target, &func, args, &salt);
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
        let call_ref = run(&env, &target, &func, args, &salt);
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
