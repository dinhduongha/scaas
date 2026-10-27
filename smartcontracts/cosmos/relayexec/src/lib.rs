//! `scaas-relayexec` — the unprivileged executor of `scaas-relayfee` (CTR-MTX-27, spec §7.2). Its router
//! instantiates it and is its only caller; it forwards `msg` to `target` with no funds, so a target sees this
//! contract as `info.sender`, never the router (a token `Relay` checks `relayer == info.sender`). It holds nothing:
//! clients never pay or approve it.
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{to_json_binary, Addr, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, StdResult, WasmMsg};
use cw_storage_plus::Item;
use serde::{Deserialize, Serialize};

use scaas_metaop::err;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
    Exec { target: String, msg: Binary },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
    Router {},
}

const ROUTER: Item<Addr> = Item::new("router");

/// The instantiating contract (the router, by `Instantiate2`) is the router.
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, _env: Env, info: MessageInfo, _msg: Empty) -> StdResult<Response> {
    ROUTER.save(deps.storage, &info.sender)?;
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, _env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let ExecuteMsg::Exec { target, msg } = msg;
    if !info.funds.is_empty() {
        return Err(err("relayexec: funds are not accepted"));
    }
    if info.sender != ROUTER.load(deps.storage)? {
        return Err(err("relayexec: only the router"));
    }
    let target = deps.api.addr_validate(&target)?;
    Ok(Response::new().add_message(WasmMsg::Execute { contract_addr: target.into(), msg, funds: vec![] }))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Router {} => to_json_binary(&ROUTER.load(deps.storage)?),
    }
}
