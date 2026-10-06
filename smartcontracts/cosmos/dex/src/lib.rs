//! `scaas-dex` — thanh toán hai chân ký (R35 trên CosmWasm). Mỗi lệnh là một `MetaOp` `op="trade"` trên token
//! bán (`to = relayer = DEX`, `extra = sha256(params)`) + `params` nguyên văn. DEX kiểm giới hạn giá, phí
//! ppm của thị trường (≤ 1 %, ≤ `max_fee_ppm` đã ký), `FILLED[digest]`; token kiểm chữ ký/nonce/hạn khi DEX
//! chuyển tiếp hai chân. Mọi thông điệp trong MỘT tx ⇒ nguyên tử. Fill-or-kill (R9-2).
//! Huỷ: chủ thể ký `revoke` trên lane/nonce của lệnh ở token ⇒ chân không bao giờ thực thi được.
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_json, to_json_binary, Addr, Binary, Deps, DepsMut, Env, Event, HexBinary, MessageInfo, Response,
    StdResult, Uint128, WasmMsg,
};
use cw_storage_plus::{Item, Map};
use serde::{Deserialize, Serialize};

use scaas_metaop::{err, sha256, Auth, MetaOp};

pub const MAX_FEE_PPM: u32 = 10_000;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstantiateMsg {
    pub admin: String,
    pub fee_recipient: String,
}

/// Tham số riêng của lệnh, đi nguyên văn cạnh `MetaOp` (review S28). Thứ tự chữ cái = dạng chính tắc.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OrderParams {
    pub buy_amount_min: Uint128,
    pub buy_token: String,
    pub dex: String,
    pub max_fee_ppm: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Leg {
    pub payload: Binary,
    pub params: Binary,
    pub auth: Auth,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Market {
    pub fee_on: bool,
    pub maker_ppm: u32,
    pub taker_ppm: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
// Deserialized once per execute call; boxing a Leg would only add an allocation.
#[allow(clippy::large_enum_variant)]
pub enum ExecuteMsg {
    SetMarket { token_a: String, token_b: String, market: Market },
    Settle { maker: Leg, taker: Leg },
    /// Anti-lock: DEX không giữ số dư giữa các tx (lệnh mở chỉ là chữ ký), nên mọi số dư là token gửi nhầm.
    Sweep { token: String, recipient: String, amount: Uint128 },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
    Market { token_a: String, token_b: String },
    Filled { digest: HexBinary },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub admin: Addr,
    pub fee_recipient: Addr,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenMsg {
    Relay { payload: Binary, auth: Auth },
    Transfer { recipient: String, amount: Uint128 },
}

const CONFIG: Item<Config> = Item::new("config");
const MARKETS: Map<(&str, &str), Market> = Map::new("market");
const FILLED: Map<&[u8], bool> = Map::new("filled");

fn pair<'a>(a: &'a str, b: &'a str) -> (&'a str, &'a str) {
    if a <= b { (a, b) } else { (b, a) }
}

fn exec(contract: &str, msg: &TokenMsg) -> StdResult<WasmMsg> {
    Ok(WasmMsg::Execute { contract_addr: contract.to_string(), msg: to_json_binary(msg)?, funds: vec![] })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, _env: Env, _info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    CONFIG.save(deps.storage, &Config {
        admin: deps.api.addr_validate(&msg.admin)?,
        fee_recipient: deps.api.addr_validate(&msg.fee_recipient)?,
    })?;
    Ok(Response::new())
}

struct Order {
    op: MetaOp,
    params: OrderParams,
    digest: [u8; 32],
}

fn order(env: &Env, leg: &Leg) -> StdResult<Order> {
    let op: MetaOp = from_json(&leg.payload)?;
    let params: OrderParams = from_json(&leg.params)?;
    let me = env.contract.address.as_str();
    if op.op != "trade" || op.to != me || op.relayer != me || params.dex != me {
        return Err(err("dex: order is not addressed to this DEX"));
    }
    if op.extra != HexBinary::from(sha256(&leg.params)).to_hex() {
        return Err(err("dex: params do not match the signed order"));
    }
    Ok(Order { op, params, digest: sha256(&leg.payload) })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    match msg {
        ExecuteMsg::SetMarket { token_a, token_b, market } => {
            if info.sender != CONFIG.load(deps.storage)?.admin {
                return Err(err("unauthorized"));
            }
            if market.maker_ppm > MAX_FEE_PPM || market.taker_ppm > MAX_FEE_PPM {
                return Err(err("dex: fee above 1%"));
            }
            let (a, b) = (deps.api.addr_validate(&token_a)?, deps.api.addr_validate(&token_b)?);
            MARKETS.save(deps.storage, pair(a.as_str(), b.as_str()), &market)?;
            Ok(Response::new().add_attribute("action", "set_market"))
        }
        ExecuteMsg::Sweep { token, recipient, amount } => {
            if info.sender != CONFIG.load(deps.storage)?.admin {
                return Err(err("unauthorized"));
            }
            let (token, recipient) = (deps.api.addr_validate(&token)?, deps.api.addr_validate(&recipient)?);
            let msg = exec(token.as_str(), &TokenMsg::Transfer { recipient: recipient.to_string(), amount })?;
            Ok(Response::new().add_message(msg).add_attribute("action", "sweep"))
        }
        ExecuteMsg::Settle { maker, taker } => {
            let cfg = CONFIG.load(deps.storage)?;
            let (m, t) = (order(&env, &maker)?, order(&env, &taker)?);
            if m.op.contract == t.op.contract || m.params.buy_token != t.op.contract || t.params.buy_token != m.op.contract {
                return Err(err("dex: orders do not cross"));
            }
            let market = MARKETS
                .may_load(deps.storage, pair(&m.op.contract, &t.op.contract))?
                .ok_or_else(|| err("dex: no such market"))?;
            for o in [&m, &t] {
                if FILLED.has(deps.storage, &o.digest) {
                    return Err(err("dex: order already filled"));
                }
                FILLED.save(deps.storage, &o.digest, &true)?;
            }
            let (maker_ppm, taker_ppm) = if market.fee_on { (market.maker_ppm, market.taker_ppm) } else { (0, 0) };
            if maker_ppm > m.params.max_fee_ppm || taker_ppm > t.params.max_fee_ppm {
                return Err(err("dex: fee above the signed maximum"));
            }
            // Maker nhận số taker bán (token t), taker nhận số maker bán (token m), trừ phí của mỗi bên.
            let fee_m = t.op.amount.multiply_ratio(maker_ppm, 1_000_000u32);
            let fee_t = m.op.amount.multiply_ratio(taker_ppm, 1_000_000u32);
            let to_maker = t.op.amount - fee_m;
            let to_taker = m.op.amount - fee_t;
            if to_maker < m.params.buy_amount_min || to_taker < t.params.buy_amount_min {
                return Err(err("dex: price limit"));
            }
            let mut msgs = vec![
                exec(&m.op.contract, &TokenMsg::Relay { payload: maker.payload, auth: maker.auth })?,
                exec(&t.op.contract, &TokenMsg::Relay { payload: taker.payload, auth: taker.auth })?,
                exec(&t.op.contract, &TokenMsg::Transfer { recipient: m.op.from.clone(), amount: to_maker })?,
                exec(&m.op.contract, &TokenMsg::Transfer { recipient: t.op.from.clone(), amount: to_taker })?,
            ];
            if !fee_m.is_zero() {
                msgs.push(exec(&t.op.contract, &TokenMsg::Transfer { recipient: cfg.fee_recipient.to_string(), amount: fee_m })?);
            }
            if !fee_t.is_zero() {
                msgs.push(exec(&m.op.contract, &TokenMsg::Transfer { recipient: cfg.fee_recipient.to_string(), amount: fee_t })?);
            }
            Ok(Response::new().add_messages(msgs).add_event(
                Event::new("trade_settled")
                    .add_attribute("maker_digest", format!("0x{}", HexBinary::from(m.digest).to_hex()))
                    .add_attribute("taker_digest", format!("0x{}", HexBinary::from(t.digest).to_hex()))
                    .add_attribute("maker_fee", fee_m)
                    .add_attribute("taker_fee", fee_t),
            ))
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Market { token_a, token_b } => to_json_binary(&MARKETS.may_load(deps.storage, pair(&token_a, &token_b))?),
        QueryMsg::Filled { digest } => to_json_binary(&FILLED.has(deps.storage, digest.as_slice())),
    }
}
