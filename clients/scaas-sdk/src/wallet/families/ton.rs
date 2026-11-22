// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! TON's balances (spec §8.7, TON row; docs/networks/ton.md): through the profile's TON Center endpoints (`rpc`). The set's
//! height is the answering endpoint's last masterchain seqno (`masterchainInfo`; a masterchain block is final), and every read
//! is pinned to it (`scaas-rpc` `Ton::account_at` / `Ton::run_get_at`, each answer naming that block: pinned in the request, no
//! retry): the holder's account balance (nanoton); per listed token (a jetton master) the master's `get_wallet_address(owner)`
//! (the view gives the address: no cell hash here, rule 6), that wallet's account state and, when it is active, its
//! `get_wallet_data`, whose balance is read only beside the holder as owner and the token as master. A wallet not initialized
//! at that block holds 0 (the master derives exactly one wallet per owner). Endpoint 0 is this network by the profile constant;
//! its masterchain block, root hash included, is each later endpoint's identity reference (scaas-rpc T24.6, owner 2026-11-18).
//! The holder and the tokens are raw `wc:hex` (workchain 0 or -1); TON has no UA ledger, so a `0x` id is `Argument`.
//! UNAUDITED.
use super::{amount, malformed, read_set};
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, SdkError};
use scaas_rpc::boc;
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::ReadError;
use scaas_rpc::ton::{raw_address, StackArg, StackEntry, Ton};
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::Value;

type Addr = (i8, [u8; 32]);

/// A family error as endpoint `i`'s failure.
fn failed(i: usize, e: FamilyError) -> ReadError {
    match e {
        FamilyError::Failure(f) => ReadError::Failure(f),
        e => ReadError::Failure(EndpointFailure::new(
            i,
            FailureKind::Transport,
            &e.to_string(),
        )),
    }
}

/// TVM's success exit codes.
fn success(code: i64) -> bool {
    code == 0 || code == 1
}

/// The address a stack entry's cell holds, else the endpoint's malformed answer naming `what`.
fn address_of(i: usize, e: Option<&StackEntry>, what: &str) -> Result<Addr, ReadError> {
    match e {
        Some(StackEntry::Cell(b)) => boc::parse(b)
            .ok()
            .and_then(|c| boc::std_address(&c))
            .ok_or_else(|| malformed(i, what)),
        _ => Err(malformed(i, what)),
    }
}

/// One listed token's balance of `who` at seqno `s` on endpoint `i`.
async fn token_at(
    ton: &Ton,
    i: usize,
    s: u64,
    who: Addr,
    master: Addr,
) -> Result<String, ReadError> {
    let m = scaas_rpc::ton::format_raw(master);
    let g = ton
        .run_get_at(
            i,
            &m,
            "get_wallet_address",
            &[StackArg::Slice(boc::address_slice(who.0, &who.1))],
            s,
        )
        .await
        .map_err(|e| failed(i, e))?;
    if !success(g.exit_code) {
        return Err(malformed(
            i,
            "get_wallet_address failed: not a jetton master",
        ));
    }
    let wallet = scaas_rpc::ton::format_raw(address_of(
        i,
        g.stack.first(),
        "a wallet address that is not an addr_std",
    )?);
    match ton
        .account_at(i, &wallet, s)
        .await
        .map_err(|e| failed(i, e))?
        .state
        .as_str()
    {
        "uninitialized" => return Ok("0".into()),
        "active" => {}
        _ => {
            return Err(malformed(
                i,
                "a jetton wallet neither active nor uninitialized",
            ))
        }
    }
    let d = ton
        .run_get_at(i, &wallet, "get_wallet_data", &[], s)
        .await
        .map_err(|e| failed(i, e))?;
    if !success(d.exit_code) {
        return Err(malformed(i, "get_wallet_data failed"));
    }
    if address_of(i, d.stack.get(1), "a wallet owner that is not an addr_std")? != who
        || address_of(i, d.stack.get(2), "a wallet master that is not an addr_std")? != master
    {
        return Err(malformed(i, "a jetton wallet of another owner or master"));
    }
    match d.stack.first().and_then(StackEntry::as_u128) {
        Some(b) => Ok(b.to_string()),
        None => Err(malformed(
            i,
            "a jetton balance that is not a number of at most 128 bits",
        )),
    }
}

/// The set at seqno `s` on endpoint `i`: (native, each token's balance).
async fn set_at(
    ton: &Ton,
    i: usize,
    s: u64,
    who: Addr,
    tokens: &[Addr],
) -> Result<(Option<String>, Vec<String>), ReadError> {
    let native = amount(
        i,
        &ton.account_at(i, &scaas_rpc::ton::format_raw(who), s)
            .await
            .map_err(|e| failed(i, e))?
            .balance,
    )?;
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        out.push(token_at(ton, i, s, who, *t).await?);
    }
    Ok((Some(native), out))
}

/// Endpoint `i`'s last masterchain seqno; endpoint 0's block (seqno, root hash) becomes the later endpoints' identity reference.
async fn head(ton: &Ton, i: usize) -> Result<u64, ReadError> {
    let last = ton.masterchain_last(i).await.map_err(|e| failed(i, e))?;
    let (Some(s), Some(root)) = (
        last.get("seqno").and_then(Value::as_u64),
        last.get("root_hash").and_then(Value::as_str),
    ) else {
        return Err(malformed(
            i,
            "masterchainInfo's last block without seqno or root hash",
        ));
    };
    if i == 0 {
        ton.saw(s, root);
    }
    Ok(s)
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let ton = c.ton.as_ref().ok_or(SdkError::Internal)?.as_ref();
    let who = raw_address(id).ok_or(SdkError::Argument)?;
    let tokens = c
        .profile
        .tokens
        .iter()
        .map(|t| raw_address(&t.address).ok_or(SdkError::Argument))
        .collect::<Result<Vec<Addr>, SdkError>>()?;
    let tokens = &tokens;
    let (block, (native, amounts)) = read_set(
        &ton.client,
        ton,
        |i| async move {
            let s = head(ton, i).await?;
            Ok((s, set_at(ton, i, s, who, tokens).await?))
        },
        |j, s| async move { set_at(ton, j, s, who, tokens).await },
    )
    .await?;
    Ok(Balances {
        block,
        native,
        tokens: c
            .profile
            .tokens
            .iter()
            .zip(amounts)
            .map(|(t, amount)| TokenBalance {
                address: t.address.clone(),
                display: t.symbol.clone(),
                decimals: t.decimals,
                amount,
            })
            .collect(),
    })
}
