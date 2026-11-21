// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Solana's balances (spec §8.7, Solana row; docs/networks/solana.md): through the profile's JSON-RPC endpoints, each named by
//! the cluster's genesis hash (`chain_uid`'s 32 bytes in base58). A read set is one JSON-RPC batch (`scaas-rpc`
//! `Solana::batch`: its calls answered together) at `finalized`: the holder's `getBalance` (lamports, a u64 integer) and, per
//! listed mint, `getTokenAccountsByOwner(pda, {mint}, jsonParsed)` on the owner's SCaaS Account, the `["acct", owner]` program
//! address under the params' program (`ua-rs` derives it: no hash here, rule 6), every account's `tokenAmount.amount` summed
//! (the program spends any token account the PDA owns, solana.md). Each answer names its context slot; a set naming two slots
//! is read again once with `minContextSlot` = the later one, then refused (rule 3). Solana reads no past slot, so under
//! `strict_majority` another endpoint reads the set with `minContextSlot` = the answering endpoint's slot and the sets are
//! compared (decisions CLI-SDK-15's Change of 2026-11-21, T24.solana). Holder and mints are base58 of 32 bytes; Solana has no UA
//! ledger, so a `0x` id is `Argument`.
use super::{amount, malformed, read_set};
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, SdkError};
use alloy::primitives::U256;
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::ReadError;
use scaas_rpc::solana::Solana;
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::{json, Value};

/// SPL Token and Token-2022: the programs a token account of the Account may belong to.
const TOKEN_PROGRAMS: [&str; 2] = [
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",
];

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

/// Base58 of exactly 32 bytes.
fn key(s: &str) -> Option<[u8; 32]> {
    bs58::decode(s).into_vec().ok()?.try_into().ok()
}

/// A set: the native lamports and each mint's sum.
type Set = (Option<String>, Vec<String>);

/// One batch on endpoint `i`: the slots its answers name and the set.
async fn pass(
    sol: &Solana,
    i: usize,
    who: &str,
    pda: &str,
    mints: &[String],
    min: Option<u64>,
) -> Result<(Vec<u64>, Set), ReadError> {
    let cfg = |extra: Value| {
        let mut c = serde_json::Map::new();
        c.insert("commitment".into(), json!("finalized"));
        if let Some(m) = min {
            c.insert("minContextSlot".into(), json!(m));
        }
        if let Value::Object(e) = extra {
            c.extend(e);
        }
        Value::Object(c)
    };
    let mut calls = vec![("getBalance", json!([who, cfg(json!({}))]))];
    for m in mints {
        calls.push((
            "getTokenAccountsByOwner",
            json!([pda, {"mint": m}, cfg(json!({"encoding": "jsonParsed"}))]),
        ));
    }
    let answers = sol.batch(i, &calls).await.map_err(|e| failed(i, e))?;
    let mut slots = Vec::with_capacity(answers.len());
    let mut it = answers.into_iter();
    let mut next = || -> Result<Value, ReadError> {
        let r = it
            .next()
            .ok_or_else(|| malformed(i, "a batch member missing"))?
            .map_err(|e| failed(i, e))?;
        slots.push(
            r.pointer("/context/slot")
                .and_then(Value::as_u64)
                .ok_or_else(|| malformed(i, "an answer without its context slot"))?,
        );
        Ok(r)
    };
    let native = next()?
        .get("value")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(i, "lamports that are not a u64"))?
        .to_string();
    let mut sums = Vec::with_capacity(mints.len());
    for m in mints {
        let r = next()?;
        let accounts = r
            .get("value")
            .and_then(Value::as_array)
            .ok_or_else(|| malformed(i, "token accounts that are not a list"))?;
        let mut sum = U256::ZERO;
        for a in accounts {
            let info = a.pointer("/account/data/parsed/info");
            let field = |k: &str| info.and_then(|v| v.pointer(k)).and_then(Value::as_str);
            let program = a.pointer("/account/owner").and_then(Value::as_str);
            if !program.is_some_and(|p| TOKEN_PROGRAMS.contains(&p))
                || field("/mint") != Some(m.as_str())
                || field("/owner") != Some(pda)
            {
                return Err(malformed(i, "a token account of another mint, owner or program"));
            }
            let s = field("/tokenAmount/amount")
                .ok_or_else(|| malformed(i, "a token amount that is not a string"))?;
            let v = U256::from_str_radix(&amount(i, s)?, 10)
                .map_err(|_| malformed(i, "a token amount above 2^256 - 1"))?;
            sum = sum
                .checked_add(v)
                .ok_or_else(|| malformed(i, "token amounts summing above 2^256 - 1"))?;
        }
        sums.push(sum.to_string());
    }
    Ok((slots, (Some(native), sums)))
}

/// The set on endpoint `i` at one slot, at or after `min`: a batch naming two slots is read again once at the later one.
async fn set_at(
    sol: &Solana,
    i: usize,
    who: &str,
    pda: &str,
    mints: &[String],
    min: Option<u64>,
) -> Result<(u64, Set), ReadError> {
    let (slots, v) = pass(sol, i, who, pda, mints, min).await?;
    let (lo, hi) = (slots.iter().min(), slots.iter().max());
    match (lo, hi) {
        (Some(lo), Some(hi)) if lo == hi => return Ok((*hi, v)),
        (_, Some(hi)) => {
            let hi = *hi;
            let (slots, v) = pass(sol, i, who, pda, mints, Some(hi)).await?;
            if let Some(s) = slots.first().filter(|s| slots.iter().all(|t| t == *s)) {
                return Ok((*s, v));
            }
        }
        _ => {}
    }
    Err(malformed(i, "a set at two slots"))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let Some((sol, program)) = c.solana.as_ref() else {
        return Err(SdkError::Argument);
    };
    let sol = sol.as_ref();
    let mints: Vec<String> = c.profile.tokens.iter().map(|t| t.address.clone()).collect();
    let owner = key(id).ok_or(SdkError::Argument)?;
    if !mints.iter().all(|m| key(m).is_some()) {
        return Err(SdkError::Argument);
    }
    let pda = bs58::encode(
        scaas_ua::families::solana::account_of(program, &owner).ok_or(SdkError::Argument)?,
    )
    .into_string();
    let (pda, mints) = (pda.as_str(), mints.as_slice());
    let (block, (native, amounts)) = read_set(
        &sol.client,
        sol,
        |i| async move { set_at(sol, i, id, pda, mints, None).await },
        |j, slot| async move {
            set_at(sol, j, id, pda, mints, Some(slot))
                .await
                .map(|(_, v)| v)
        },
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
