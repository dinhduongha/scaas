//! `bamboo-token` — CW20 tối thiểu + meta-tx cấp contract (R30, R66).
//! Số dư nằm trong contract; chủ thể chỉ KÝ `MetaOp`, relayer gửi tx từ lane của nó. Lane/nonce riêng
//! contract (`NONCES[(from, lane)]`) ⇒ thao tác kẹt ở contract khác không bao giờ chặn contract này.
//! Allowance chỉ cho spender là contract, `TransferFrom` chỉ khi người gọi là contract (R26).
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Addr, Binary, Deps, DepsMut, Env, Event, HexBinary, MessageInfo, Response, StdResult, Storage,
    Uint128, WasmMsg,
};
use cw_storage_plus::{Item, Map};
use serde::{Deserialize, Serialize};

use bamboo_metaop::{err, verify, Auth, Cw20ReceiveMsg, ReceiverExecuteMsg};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Balance {
    pub address: String,
    pub amount: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstantiateMsg {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    #[serde(default)]
    pub initial_balances: Vec<Balance>,
    #[serde(default)]
    pub minter: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
    Transfer { recipient: String, amount: Uint128 },
    Send { contract: String, amount: Uint128, msg: Binary },
    Mint { recipient: String, amount: Uint128 },
    /// `info.sender` trả (ví hợp đồng/mandate), phát `payment_settled` mang `pay_ref`.
    Pay { to: String, amount: Uint128, pay_ref: HexBinary },
    /// Meta-tx: `payload` = bytes `MetaOp` chủ thể đã ký (op `pay` | `trade` | `revoke`).
    Relay { payload: Binary, auth: Auth },
    IncreaseAllowance { spender: String, amount: Uint128 },
    DecreaseAllowance { spender: String, amount: Uint128 },
    TransferFrom { owner: String, recipient: String, amount: Uint128 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
    Balance { address: String },
    TokenInfo {},
    Allowance { owner: String, spender: String },
    Nonce { owner: String, lane: HexBinary },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct TokenInfo {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
    pub minter: Option<Addr>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BalanceResponse {
    pub balance: Uint128,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct AllowanceResponse {
    pub allowance: Uint128,
}

const INFO: Item<TokenInfo> = Item::new("info");
const BALANCES: Map<&Addr, Uint128> = Map::new("bal");
const ALLOWANCES: Map<(&Addr, &Addr), Uint128> = Map::new("allow");
const NONCES: Map<(&Addr, &[u8]), u64> = Map::new("nonce");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    let mut total = Uint128::zero();
    for b in &msg.initial_balances {
        let a = deps.api.addr_validate(&b.address)?;
        BALANCES.update(deps.storage, &a, |v| -> StdResult<_> { Ok(v.unwrap_or_default().checked_add(b.amount)?) })?;
        total = total.checked_add(b.amount)?;
    }
    let minter = msg.minter.map(|m| deps.api.addr_validate(&m)).transpose()?;
    INFO.save(deps.storage, &TokenInfo { name: msg.name, symbol: msg.symbol, decimals: msg.decimals, total_supply: total, minter })?;
    Ok(Response::new())
}

fn move_funds(store: &mut dyn Storage, from: &Addr, to: &Addr, amount: Uint128) -> StdResult<()> {
    let have = BALANCES.may_load(store, from)?.unwrap_or_default();
    let left = have.checked_sub(amount).map_err(|_| err("insufficient balance"))?;
    BALANCES.save(store, from, &left)?;
    BALANCES.update(store, to, |v| -> StdResult<_> { Ok(v.unwrap_or_default().checked_add(amount)?) })?;
    Ok(())
}

/// `pay_ref` KHÔNG bị khoá toàn cục ở token (như `MetaToken` EVM): ai cũng gọi được `Pay` với một `pay_ref` bất
/// kỳ, nên khoá "một lần" ở đây cho phép front-run đốt `pay_ref` của người trả. Chống replay là nonce lane;
/// Odoo cộng các khoản theo `entry_ref` + người nhận (thiếu/thừa ⇒ cần chú ý).
fn settle(store: &mut dyn Storage, from: &Addr, to: &Addr, amount: Uint128, pay_ref: &[u8]) -> StdResult<Event> {
    if pay_ref.len() != 32 {
        return Err(err("pay_ref is 32 bytes"));
    }
    move_funds(store, from, to, amount)?;
    Ok(Event::new("payment_settled")
        .add_attribute("from", from)
        .add_attribute("to", to)
        .add_attribute("amount", amount)
        .add_attribute("pay_ref", format!("0x{}", HexBinary::from(pay_ref).to_hex())))
}

fn is_contract(deps: &Deps, addr: &Addr) -> bool {
    deps.querier.query_wasm_contract_info(addr.as_str()).is_ok()
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Transfer { recipient, amount } => {
            let to = deps.api.addr_validate(&recipient)?;
            move_funds(deps.storage, &info.sender, &to, amount)?;
            Ok(Response::new().add_attribute("action", "transfer"))
        }
        ExecuteMsg::Send { contract, amount, msg } => {
            let to = deps.api.addr_validate(&contract)?;
            move_funds(deps.storage, &info.sender, &to, amount)?;
            let hook = ReceiverExecuteMsg::Receive(Cw20ReceiveMsg { sender: info.sender.to_string(), amount, msg });
            Ok(Response::new()
                .add_attribute("action", "send")
                .add_message(WasmMsg::Execute { contract_addr: contract, msg: to_json_binary(&hook)?, funds: vec![] }))
        }
        ExecuteMsg::Mint { recipient, amount } => {
            let mut ti = INFO.load(deps.storage)?;
            if ti.minter.as_ref() != Some(&info.sender) {
                return Err(err("unauthorized"));
            }
            ti.total_supply = ti.total_supply.checked_add(amount)?;
            INFO.save(deps.storage, &ti)?;
            let to = deps.api.addr_validate(&recipient)?;
            BALANCES.update(deps.storage, &to, |v| -> StdResult<_> { Ok(v.unwrap_or_default().checked_add(amount)?) })?;
            Ok(Response::new().add_attribute("action", "mint"))
        }
        ExecuteMsg::Pay { to, amount, pay_ref } => {
            let to = deps.api.addr_validate(&to)?;
            let ev = settle(deps.storage, &info.sender, &to, amount, &pay_ref)?;
            Ok(Response::new().add_event(ev))
        }
        ExecuteMsg::Relay { payload, auth } => relay(deps, env, info, &payload, &auth),
        ExecuteMsg::IncreaseAllowance { spender, amount } => {
            let sp = deps.api.addr_validate(&spender)?;
            if !is_contract(&deps.as_ref(), &sp) {
                return Err(err("spender must be a contract"));
            }
            ALLOWANCES.update(deps.storage, (&info.sender, &sp), |v| -> StdResult<_> {
                Ok(v.unwrap_or_default().checked_add(amount)?)
            })?;
            Ok(Response::new().add_attribute("action", "increase_allowance"))
        }
        ExecuteMsg::DecreaseAllowance { spender, amount } => {
            let sp = deps.api.addr_validate(&spender)?;
            let key = (&info.sender, &sp);
            let left = ALLOWANCES.may_load(deps.storage, key)?.unwrap_or_default().saturating_sub(amount);
            ALLOWANCES.save(deps.storage, key, &left)?;
            Ok(Response::new().add_attribute("action", "decrease_allowance"))
        }
        ExecuteMsg::TransferFrom { owner, recipient, amount } => {
            if !is_contract(&deps.as_ref(), &info.sender) {
                return Err(err("only a contract may transfer_from"));
            }
            let owner = deps.api.addr_validate(&owner)?;
            let to = deps.api.addr_validate(&recipient)?;
            let key = (&owner, &info.sender);
            let have = ALLOWANCES.may_load(deps.storage, key)?.unwrap_or_default();
            ALLOWANCES.save(deps.storage, key, &have.checked_sub(amount).map_err(|_| err("allowance exceeded"))?)?;
            move_funds(deps.storage, &owner, &to, amount)?;
            Ok(Response::new().add_attribute("action", "transfer_from"))
        }
    }
}

fn relay(deps: DepsMut, env: Env, info: MessageInfo, payload: &[u8], auth: &Auth) -> StdResult<Response> {
    let v = verify(deps.api, &env, payload, auth)?;
    let op = &v.op;
    if !op.relayer.is_empty() && op.relayer != info.sender.as_str() {
        return Err(err("metaop: bound to another relayer"));
    }
    let key = (&v.from, op.lane.as_slice());
    let next = NONCES.may_load(deps.storage, key)?.unwrap_or(0);
    if op.nonce != next {
        return Err(err("metaop: nonce already used or out of order"));
    }
    NONCES.save(deps.storage, key, &(next + 1))?;
    let mut res = Response::new();
    match op.op.as_str() {
        "pay" => {
            let to = deps.api.addr_validate(&op.to)?;
            res = res.add_event(settle(deps.storage, &v.from, &to, op.amount, &op.pay_ref)?);
        }
        // Chân lệnh DEX: chỉ DEX (contract) đã được ký làm relayer VÀ người nhận mới kéo được tiền.
        "trade" => {
            if op.relayer != info.sender.as_str() || op.to != info.sender.as_str() || !is_contract(&deps.as_ref(), &info.sender) {
                return Err(err("trade: relayer and recipient must be the calling contract"));
            }
            move_funds(deps.storage, &v.from, &info.sender, op.amount)?;
        }
        // Chỉ tiêu nonce: lệnh/thao tác đã ký trên lane này không bao giờ thực thi được nữa.
        "revoke" => {}
        _ => return Err(err("metaop: unsupported op")),
    }
    Ok(res.add_event(
        Event::new("meta_tx_executed")
            .add_attribute("from", v.from.as_str())
            .add_attribute("digest", format!("0x{}", HexBinary::from(v.digest).to_hex()))
            .add_attribute("op", op.op.as_str())
            .add_attribute("lane", op.lane.to_hex())
            .add_attribute("nonce", op.nonce.to_string()),
    ))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Balance { address } => {
            let a = deps.api.addr_validate(&address)?;
            to_json_binary(&BalanceResponse { balance: BALANCES.may_load(deps.storage, &a)?.unwrap_or_default() })
        }
        QueryMsg::TokenInfo {} => to_json_binary(&INFO.load(deps.storage)?),
        QueryMsg::Allowance { owner, spender } => {
            let (o, s) = (deps.api.addr_validate(&owner)?, deps.api.addr_validate(&spender)?);
            to_json_binary(&AllowanceResponse { allowance: ALLOWANCES.may_load(deps.storage, (&o, &s))?.unwrap_or_default() })
        }
        QueryMsg::Nonce { owner, lane } => {
            let o = deps.api.addr_validate(&owner)?;
            to_json_binary(&NONCES.may_load(deps.storage, (&o, lane.as_slice()))?.unwrap_or(0))
        }
    }
}
