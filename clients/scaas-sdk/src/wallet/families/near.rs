// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! NEAR's balances (spec §8.7, NEAR row; docs/networks/near.md): the native balance is `query view_account`'s `amount`
//! (yocto); a listed token's is its `call_function` `ft_balance_of({account_id})`, or `ua_balance_of({id: [32 numbers]})` for a
//! `0x` 32-byte UA id (NEAR keeps a UA ledger per token); every query pinned by `block_id` to the final block the endpoint
//! names, and every answer must name that block. A view's result is at most 128 bytes of JSON holding one decimal string. An
//! account NEAR does not know at that block (`UNKNOWN_ACCOUNT`) holds nothing: native "0" (a token's ledger answers "0" for an
//! unknown holder itself). Separate from Algorand (NET-NEAR ≠ NET-ALG).
use super::{amount, malformed, read_set};
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, SdkError};
use base64::Engine;
use scaas_rpc::family::FamilyError;
use scaas_rpc::near::Near;
use scaas_rpc::pool::ReadError;
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::{json, Value};

/// The most bytes of a view's result (a U128 as a JSON string, with room).
const VIEW_MAX: usize = 128;

/// Whom a read is of: a NEAR account, or a UA id (its token ledgers only).
enum Holder {
    Account(String),
    Ua([u8; 32]),
}

/// A NEAR account id (nearcore's rule): 2 to 64 bytes of `a-z`, `0-9` and the separators `-`, `_`, `.`, no separator first,
/// last or beside another.
pub(crate) fn account_id(s: &str) -> bool {
    let sep = |b: &u8| matches!(b, b'-' | b'_' | b'.');
    let b = s.as_bytes();
    (2..=64).contains(&b.len())
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || sep(c))
        && !b.first().is_some_and(sep)
        && !b.last().is_some_and(sep)
        && !b.windows(2).any(|w| w.iter().all(sep))
}

fn holder(id: &str) -> Result<Holder, SdkError> {
    let lower = id.to_ascii_lowercase();
    if lower.starts_with("0x") && lower.len() == 66 {
        let b = crate::op::unhex(&lower)?;
        return b.try_into().map(Holder::Ua).map_err(|_| SdkError::Argument);
    }
    if account_id(id) {
        Ok(Holder::Account(id.into()))
    } else {
        Err(SdkError::Argument)
    }
}

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

/// An answer must name the block the set is read at.
fn at_block(i: usize, v: &Value, h: u64) -> Result<(), ReadError> {
    if v.get("block_height").and_then(Value::as_u64) == Some(h) {
        Ok(())
    } else {
        Err(malformed(i, "an answer at another block"))
    }
}

/// The native balance at `h`; an account unknown at `h` holds 0.
async fn native(near: &Near, i: usize, h: u64, account: &str) -> Result<String, ReadError> {
    let q = json!({"request_type": "view_account", "account_id": account, "block_id": h});
    let v = match near.call(i, "query", q).await {
        Err(FamilyError::Rpc { error, .. })
            if error.pointer("/cause/name").and_then(Value::as_str) == Some("UNKNOWN_ACCOUNT") =>
        {
            return Ok("0".into())
        }
        r => r.map_err(|e| failed(i, e))?,
    };
    at_block(i, &v, h)?;
    amount(
        i,
        v.get("amount").and_then(Value::as_str).unwrap_or_default(),
    )
}

/// A token's balance at `h`: `method(args)` on contract `token`, its result one decimal JSON string of at most 128 bytes.
async fn view(
    near: &Near,
    i: usize,
    h: u64,
    token: &str,
    method: &str,
    args: &Value,
) -> Result<String, ReadError> {
    let q = json!({"request_type": "call_function", "account_id": token, "method_name": method,
        "args_base64": base64::engine::general_purpose::STANDARD.encode(args.to_string()), "block_id": h});
    let v = near.call(i, "query", q).await.map_err(|e| failed(i, e))?;
    at_block(i, &v, h)?;
    let bytes = v
        .get("result")
        .and_then(Value::as_array)
        .filter(|r| r.len() <= VIEW_MAX)
        .ok_or_else(|| malformed(i, "a view result that is not at most 128 bytes"))?
        .iter()
        .map(|x| x.as_u64().and_then(|n| u8::try_from(n).ok()))
        .collect::<Option<Vec<u8>>>()
        .ok_or_else(|| malformed(i, "a view result that is not bytes"))?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::String(s)) => amount(i, &s),
        _ => Err(malformed(i, "a view result that is not one string")),
    }
}

/// The set at block `h` on endpoint `i`: (native, each token's balance).
async fn set_at(
    near: &Near,
    i: usize,
    h: u64,
    who: &Holder,
    tokens: &[String],
) -> Result<(Option<String>, Vec<String>), ReadError> {
    let n = match who {
        Holder::Account(a) => Some(native(near, i, h, a).await?),
        Holder::Ua(_) => None,
    };
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        out.push(match who {
            Holder::Account(a) => {
                view(near, i, h, t, "ft_balance_of", &json!({"account_id": a})).await?
            }
            Holder::Ua(id) => view(near, i, h, t, "ua_balance_of", &json!({"id": id})).await?,
        });
    }
    Ok((n, out))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let near = c.near.as_ref().ok_or(SdkError::Internal)?;
    let who = holder(id)?;
    let tokens: Vec<String> = c.profile.tokens.iter().map(|t| t.address.clone()).collect();
    if !tokens.iter().all(|t| account_id(t)) {
        return Err(SdkError::Argument);
    }
    let (who, tokens) = (&who, &tokens);
    let (block, (native, amounts)) = read_set(
        &near.client,
        near.as_ref(),
        |i| async move {
            let h = near.final_header(i).await.map_err(|e| failed(i, e))?.0;
            Ok((h, set_at(near, i, h, who, tokens).await?))
        },
        |j, h| async move { set_at(near, j, h, who, tokens).await },
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
