//! CTR-MTX-27 trên Soroban: trả phí token cho một lời gọi không có phí riêng (stateless, không owner).
//!
//! `payer.require_auth_for_args((target, func, args, salt, token, to, amount, valid_until))` — auth entry của payer có
//! gốc là chính lời gọi `relay`, với `token.pay` là sub-invocation duy nhất của khoản trả: chữ ký không cho phép
//! `token.pay` gọi trực tiếp (host chỉ khớp cây gọi). `relayer` là nguồn của giao dịch.
//! `relayer.require_auth()`: tx source KHÔNG tự thoả; node thêm auth entry `SourceAccount` gốc là chính lời gọi `relay`.
//! Không cần executor: Soroban cấm contract re-entry, auth entry của khoản trả khác gốc ở lời gọi `relay` của nó.
#![no_std]
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
    /// Chạy `target.func(args)` rồi `token.pay(payer, …, amount, ref, valid_until)`; lỗi nào cũng hoàn tác cả hai.
    /// Open mode (`to == router`): khoản trả về router rồi chuyển cho `relayer` (auth entry của payer phải biết
    /// trước người nhận, mà relayer chưa biết lúc ký). Bound payee: trả thẳng `to`.
    pub fn relay(env: Env, payer: Address, target: Address, func: Symbol, args: Vec<Val>, salt: BytesN<32>, token: Address,
                 to: Address, amount: i128, valid_until: u64, relayer: Address) {
        relayer.require_auth();
        let signed: Vec<Val> = (target.clone(), func.clone(), args.clone(), salt.clone(), token.clone(), to.clone(), amount, valid_until)
            .into_val(&env);
        payer.require_auth_for_args(signed);
        // The target must be an instantiated contract, before any call (a call to nothing would "succeed").
        if !matches!(target.executable(), Some(Executable::Wasm(_)) | Some(Executable::StellarAsset)) {
            panic_with_error!(&env, Error::TargetNoCode);
        }
        let call_ref = relay_ref(&env, &target, &func, &args, &salt);
        env.invoke_contract::<Val>(&target, &func, args);
        let me = env.current_contract_address();
        env.invoke_contract::<()>(
            &token,
            &Symbol::new(&env, "pay"),
            vec![&env, payer.to_val(), to.to_val(), amount.into_val(&env), call_ref.to_val(), valid_until.into_val(&env)],
        );
        let open = to == me;
        let payee = if open { relayer } else { to };
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
