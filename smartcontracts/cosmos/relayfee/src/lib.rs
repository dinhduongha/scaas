//! `scaas-relayfee` — CTR-MTX-27 on CosmWasm (spec §7.2): a token fee to the relayer for one fee-less call.
//! `Relay { target, msg, token, payload, auth }`: the payer's signed `pay` op (`scaas_metaop`) must commit to the
//! call (`pay_ref == ref`, `lane == payLane(ref)`, `nonce == 0`, `relayer == this router`), then three messages run
//! depth-first, all or nothing: the executor's `Exec { target, msg }`, the token's `Relay { payload, auth }`, and in
//! open mode (`op.to == router`) the token's `Transfer` of the amount to `info.sender`. The target sees the
//! unprivileged executor (`scaas-relayexec`), never the router, so a `msg` that is a token `Relay` of another
//! router-bound payment fails (R18). The router's only stored item is its executor's address (plus the re-entry
//! flag held during a relay). The router and its executor have no admin: `Relay` refuses while the router's own
//! `ContractInfo.admin` is set, and the executor is instantiated with `admin: None`.
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    from_json, instantiate2_address, to_json_binary, Addr, Binary, Deps, DepsMut, Empty, Env, Event, HexBinary,
    MessageInfo, Reply, Response, StdResult, SubMsg, WasmMsg,
};
use cw_storage_plus::Item;
use serde::{Deserialize, Serialize};

use scaas_metaop::{err, pay_lane, relay_ref, Auth, MetaOp};

/// `Instantiate2` salt of the executor (fixed: one executor per router).
pub const EXECUTOR_SALT: &[u8] = b"scaas.relayexec";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InstantiateMsg {
    pub executor_code_id: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecuteMsg {
    Relay { target: String, msg: Binary, token: String, payload: Binary, auth: Auth },
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum QueryMsg {
    Executor {},
    /// `relay_ref(chain id, target, msg)` (hex).
    RelayRef { target: String, msg: Binary },
}

/// Token messages the router sends (the `scaas_token::ExecuteMsg` arms, without depending on the token crate).
#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum TokenMsg<'a> {
    Relay { payload: &'a Binary, auth: &'a Auth },
    Transfer { recipient: &'a str, amount: cosmwasm_std::Uint128 },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ExecMsg<'a> {
    Exec { target: &'a str, msg: &'a Binary },
}

const EXECUTOR: Item<Addr> = Item::new("executor");
const LOCK: Item<bool> = Item::new("lock");

/// Instantiates the executor (`Instantiate2`, fixed salt: its address follows from the router's and the code's
/// checksum; the router is its creator and so its only caller).
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(deps: DepsMut, env: Env, _info: MessageInfo, msg: InstantiateMsg) -> StdResult<Response> {
    let checksum = deps.querier.query_wasm_code_info(msg.executor_code_id)?.checksum;
    let me = deps.api.addr_canonicalize(env.contract.address.as_str())?;
    let exec = instantiate2_address(checksum.as_slice(), &me, EXECUTOR_SALT).map_err(err)?;
    EXECUTOR.save(deps.storage, &deps.api.addr_humanize(&exec)?)?;
    Ok(Response::new().add_message(WasmMsg::Instantiate2 {
        admin: None,
        code_id: msg.executor_code_id,
        label: "scaas-relayexec".into(),
        msg: to_json_binary(&Empty {})?,
        funds: vec![],
        salt: EXECUTOR_SALT.into(),
    }))
}

fn target_ref(deps: Deps, env: &Env, target: &Addr, msg: &[u8]) -> StdResult<[u8; 32]> {
    Ok(relay_ref(&env.block.chain_id, deps.api.addr_canonicalize(target.as_str())?.as_slice(), msg))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> StdResult<Response> {
    let ExecuteMsg::Relay { target, msg, token, payload, auth } = msg;
    if !info.funds.is_empty() {
        return Err(err("relayfee: funds are not accepted"));
    }
    if LOCK.exists(deps.storage) {
        return Err(err("relayfee: re-entry"));
    }
    // CTR-MTX-13: an admin could migrate the router (the bound relayer of every payment signed to it) into code
    // that settles without the call. Deploy with `--no-admin`; a failed query fails closed.
    if deps.querier.query_wasm_contract_info(env.contract.address.as_str())?.admin.is_some() {
        return Err(err("relayfee: the router has an admin"));
    }
    let target = deps.api.addr_validate(&target)?;
    let token = deps.api.addr_validate(&token)?;
    let op: MetaOp = from_json(&payload)?;
    let me = env.contract.address.as_str();
    let exec = EXECUTOR.load(deps.storage)?;
    let r = target_ref(deps.as_ref(), &env, &target, &msg)?;
    if op.op != "pay"
        || op.pay_ref.as_slice() != r
        || op.lane.as_slice() != pay_lane(&r)
        || op.nonce != 0
        || op.relayer != me
        || op.to == exec.as_str()
    {
        return Err(err("relayfee: the payment is not bound to this call"));
    }
    // CTR-MTX-27: a call to an address with no contract would "succeed" and burn the payment.
    if deps.querier.query_wasm_contract_info(target.as_str()).is_err() {
        return Err(err("relayfee: target is not an instantiated contract"));
    }
    let payer = deps.api.addr_validate(&op.from)?;
    let open = op.to == me;
    let payee = if open { info.sender.clone() } else { deps.api.addr_validate(&op.to)? };
    LOCK.save(deps.storage, &true)?;
    let wasm = |contract: &Addr, m: Binary| WasmMsg::Execute { contract_addr: contract.to_string(), msg: m, funds: vec![] };
    let mut msgs = vec![
        SubMsg::new(wasm(&exec, to_json_binary(&ExecMsg::Exec { target: target.as_str(), msg: &msg })?)),
        SubMsg::new(wasm(&token, to_json_binary(&TokenMsg::Relay { payload: &payload, auth: &auth })?)),
    ];
    if open {
        let t = TokenMsg::Transfer { recipient: info.sender.as_str(), amount: op.amount };
        msgs.push(SubMsg::new(wasm(&token, to_json_binary(&t)?)));
    }
    // The last message's reply clears the re-entry flag; any failure reverts it with everything else.
    let last = msgs.pop().expect("two messages at least");
    msgs.push(SubMsg::reply_on_success(last.msg, 0));
    Ok(Response::new().add_submessages(msgs).add_event(
        Event::new("relay_fee_paid")
            .add_attribute("ref", format!("0x{}", HexBinary::from(r).to_hex()))
            .add_attribute("target", target.as_str())
            .add_attribute("token", token.as_str())
            .add_attribute("payer", payer.as_str())
            .add_attribute("payee", payee.as_str())
            .add_attribute("amount", op.amount),
    ))
}

/// The relay's last message succeeded: clear the re-entry flag (a failure reverts it with everything else).
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(deps: DepsMut, _env: Env, _msg: Reply) -> StdResult<Response> {
    LOCK.remove(deps.storage);
    Ok(Response::new())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::Executor {} => to_json_binary(&EXECUTOR.load(deps.storage)?),
        QueryMsg::RelayRef { target, msg } => {
            let target = deps.api.addr_validate(&target)?;
            to_json_binary(&HexBinary::from(target_ref(deps, &env, &target, &msg)?))
        }
    }
}
