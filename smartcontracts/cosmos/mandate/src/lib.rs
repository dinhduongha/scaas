//! `scaas-mandate` — ví uỷ thác như `MandateWallet` EVM (R25): tiền nằm trong contract, khoá delegate
//! (secp256k1, custody) ký từng khoản; hạn mức mỗi lần + mỗi kỳ, danh sách payee, hạn, thu hồi, mỗi `pay_ref`
//! một lần. Khoản chi đi qua `token.Pay` ⇒ token phát `payment_settled` mang đúng `pay_ref`.
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, to_json_vec, Addr, Binary, Deps, DepsMut, Env, HexBinary, MessageInfo, Response,
    StdResult, Uint128, WasmMsg,
};
use cw_storage_plus::{Item, Map};
use serde::{Deserialize, Serialize};

use scaas_metaop::{err, sha256};

pub const DOMAIN: &str = "scaas.mandate.v1";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstantiateMsg {
    pub owner: String,
    pub token: String,
    pub delegate_pubkey: Binary,
    pub max_per_payment: Uint128,
    pub max_per_period: Uint128,
    pub period_secs: u64,
    pub payees: Vec<String>,
    pub expires_at: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
    Receive(scaas_metaop::Cw20ReceiveMsg),
    PayUnderMandate { to: String, amount: Uint128, pay_ref: HexBinary, valid_until: u64, signature: Binary },
    Revoke {},
    Withdraw { amount: Uint128 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
    Config {},
    Spent {},
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub owner: Addr,
    pub token: Addr,
    pub delegate_pubkey: Binary,
    pub max_per_payment: Uint128,
    pub max_per_period: Uint128,
    pub period_secs: u64,
    pub payees: Vec<Addr>,
    pub expires_at: u64,
    pub revoked: bool,
}

/// Thông điệp delegate ký: JSON chính tắc (trường theo thứ tự chữ cái), `sha256`, `secp256k1_verify`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct MandatePay {
    pub amount: Uint128,
    pub contract: String,
    pub domain: String,
    pub network: String,
    pub pay_ref: HexBinary,
    pub to: String,
    pub valid_until: u64,
}

/// Hai lời gọi token mà mandate cần (khớp `scaas_token::ExecuteMsg`; không phụ thuộc crate token để
/// không hợp nhất feature `library` khi build wasm).
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenMsg {
    Pay { to: String, amount: Uint128, pay_ref: HexBinary },
    Transfer { recipient: String, amount: Uint128 },
}

const CONFIG: Item<Config> = Item::new("config");
/// (đầu kỳ, đã chi trong kỳ)
const PERIOD: Item<(u64, Uint128)> = Item::new("period");
const USED: Map<&[u8], bool> = Map::new("used");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    if msg.delegate_pubkey.len() != 33 || msg.period_secs == 0 || msg.max_per_payment > msg.max_per_period {
        return Err(err("mandate: bad configuration"));
    }
    let payees = msg.payees.iter().map(|p| deps.api.addr_validate(p)).collect::<StdResult<Vec<_>>>()?;
    CONFIG.save(deps.storage, &Config {
        owner: deps.api.addr_validate(&msg.owner)?,
        token: deps.api.addr_validate(&msg.token)?,
        delegate_pubkey: msg.delegate_pubkey,
        max_per_payment: msg.max_per_payment,
        max_per_period: msg.max_per_period,
        period_secs: msg.period_secs,
        payees,
        expires_at: msg.expires_at,
        revoked: false,
    })?;
    PERIOD.save(deps.storage, &(0, Uint128::zero()))?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let mut cfg = CONFIG.load(deps.storage)?;
    match msg {
        ExecuteMsg::Receive(r) => {
            if info.sender != cfg.token {
                return Err(err("mandate: deposits only in its token"));
            }
            Ok(Response::new().add_attribute("action", "deposit").add_attribute("amount", r.amount))
        }
        ExecuteMsg::PayUnderMandate { to, amount, pay_ref, valid_until, signature } => {
            let now = env.block.time.seconds();
            if cfg.revoked || now > cfg.expires_at {
                return Err(err("mandate: revoked or expired"));
            }
            if now > valid_until {
                return Err(err("mandate: payment instruction expired"));
            }
            let payee = deps.api.addr_validate(&to)?;
            if !cfg.payees.contains(&payee) {
                return Err(err("mandate: payee not allowed"));
            }
            if pay_ref.len() != 32 || USED.has(deps.storage, pay_ref.as_slice()) {
                return Err(err("mandate: pay_ref already used"));
            }
            let m = MandatePay {
                amount,
                contract: env.contract.address.to_string(),
                domain: DOMAIN.into(),
                network: env.block.chain_id.clone(),
                pay_ref: pay_ref.clone(),
                to: payee.to_string(),
                valid_until,
            };
            let hash = sha256(&to_json_vec(&m)?);
            if !deps.api.secp256k1_verify(&hash, &signature, &cfg.delegate_pubkey).map_err(err)? {
                return Err(err("mandate: bad delegate signature"));
            }
            if amount.is_zero() || amount > cfg.max_per_payment {
                return Err(err("mandate: above the per-payment cap"));
            }
            let start = now - now % cfg.period_secs;
            let (s, spent) = PERIOD.load(deps.storage)?;
            let spent = if s == start { spent } else { Uint128::zero() } + amount;
            if spent > cfg.max_per_period {
                return Err(err("mandate: above the per-period cap"));
            }
            PERIOD.save(deps.storage, &(start, spent))?;
            USED.save(deps.storage, pay_ref.as_slice(), &true)?;
            let pay = TokenMsg::Pay { to: payee.to_string(), amount, pay_ref };
            Ok(Response::new()
                .add_attribute("action", "pay_under_mandate")
                .add_message(WasmMsg::Execute { contract_addr: cfg.token.to_string(), msg: to_json_binary(&pay)?, funds: vec![] }))
        }
        ExecuteMsg::Revoke {} => {
            if info.sender != cfg.owner {
                return Err(err("unauthorized"));
            }
            cfg.revoked = true;
            CONFIG.save(deps.storage, &cfg)?;
            Ok(Response::new().add_attribute("action", "revoke"))
        }
        ExecuteMsg::Withdraw { amount } => {
            if info.sender != cfg.owner {
                return Err(err("unauthorized"));
            }
            let t = TokenMsg::Transfer { recipient: cfg.owner.to_string(), amount };
            Ok(Response::new()
                .add_attribute("action", "withdraw")
                .add_message(WasmMsg::Execute { contract_addr: cfg.token.to_string(), msg: to_json_binary(&t)?, funds: vec![] }))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Config {} => to_json_binary(&CONFIG.load(deps.storage)?),
        QueryMsg::Spent {} => to_json_binary(&PERIOD.load(deps.storage)?),
    }
}
