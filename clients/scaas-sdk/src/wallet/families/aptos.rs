// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Aptos's balances (spec §8.7, Aptos row; docs/networks/aptos.md NET-APT-05): through the profile's REST endpoints, each
//! named by the params' chain id (ledger info's `chain_id`). The set is pinned at the answering endpoint's `ledger_version`
//! (ledger info; a committed version is final), every view of the set asked `?ledger_version=` that version (pinned in the
//! request, as NEAR's `block_id`: no retry); the failover's floor stays ledger info's `block_height`. The native balance is the
//! holder's `0x1::coin::balance<0x1::aptos_coin::AptosCoin>` (octas; the paired FA counted, AIP-63); a listed token is an FA
//! whose metadata address is the token's `address`, held in the owner's SCaaS Account: the view `meta::account_of(owner)` of
//! the params' package gives that Account (no hash in the SDK, spec §8.7 rule 6), then
//! `0x1::primary_fungible_store::balance<0x1::fungible_asset::Metadata>(account, metadata)`. Each view answers a JSON array of
//! one value; an amount is a decimal string (u64 / u128). Aptos has no UA ledger: every `0x` + 64 hex holder is an address.
use super::{amount, malformed, read_set_pinned};
use crate::config::is_aptos_address;
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, FamilyParams, SdkError};
use scaas_rpc::aptos::Aptos;
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::ReadError;
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::{json, Value};

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

/// The view `function` with `types` and `args` on endpoint `i` at `version`: its one value as a string.
async fn view(
    apt: &Aptos,
    i: usize,
    version: u64,
    function: &str,
    types: &[&str],
    args: &[&str],
) -> Result<String, ReadError> {
    let body = json!({"function": function, "type_arguments": types, "arguments": args});
    let (status, v) = apt
        .post_json(
            i,
            &format!("/view?ledger_version={version}"),
            body.to_string().into_bytes(),
            "application/json",
        )
        .await
        .map_err(|e| failed(i, e))?;
    if status != 200 {
        return Err(ReadError::Failure(EndpointFailure::new(
            i,
            FailureKind::Http,
            &format!("a view: HTTP {status}"),
        )));
    }
    match v.as_array().map(Vec::as_slice) {
        Some([Value::String(s)]) => Ok(s.clone()),
        _ => Err(malformed(i, "a view that is not one string")),
    }
}

/// Ledger info of endpoint `i`: (`block_height`, `ledger_version`), each a decimal string.
async fn ledger(apt: &Aptos, i: usize) -> Result<(u64, u64), ReadError> {
    let v = apt
        .get_at(i, "")
        .await
        .map_err(|e| failed(i, e))?
        .unwrap_or(Value::Null);
    let num = |k: &str| {
        v.get(k)
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<u64>().ok())
    };
    match (num("block_height"), num("ledger_version")) {
        (Some(h), Some(l)) => Ok((h, l)),
        _ => Err(malformed(i, "ledger info without its height and version")),
    }
}

/// The set at `version` on endpoint `i`: (native, each token's balance).
async fn set_at(
    apt: &Aptos,
    i: usize,
    version: u64,
    who: &str,
    package: &str,
    tokens: &[String],
) -> Result<(Option<String>, Vec<String>), ReadError> {
    let native = view(
        apt,
        i,
        version,
        "0x1::coin::balance",
        &["0x1::aptos_coin::AptosCoin"],
        &[who],
    )
    .await?;
    let native = amount(i, &native)?;
    let mut out = Vec::with_capacity(tokens.len());
    if !tokens.is_empty() {
        let acct = view(
            apt,
            i,
            version,
            &format!("{package}::meta::account_of"),
            &[],
            &[who],
        )
        .await?;
        if !acct.starts_with("0x")
            || !(3..=66).contains(&acct.len())
            || !acct.bytes().skip(2).all(|b| b.is_ascii_hexdigit())
        {
            return Err(malformed(i, "an account that is not an address"));
        }
        for t in tokens {
            let b = view(
                apt,
                i,
                version,
                "0x1::primary_fungible_store::balance",
                &["0x1::fungible_asset::Metadata"],
                &[&acct, t],
            )
            .await?;
            out.push(amount(i, &b)?);
        }
    }
    Ok((Some(native), out))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let (Some(apt), Some(FamilyParams::Aptos { package, .. })) =
        (c.aptos.as_deref(), c.profile.family_params.as_ref())
    else {
        return Err(SdkError::Argument);
    };
    let tokens: Vec<String> = c.profile.tokens.iter().map(|t| t.address.clone()).collect();
    if !is_aptos_address(id) || !tokens.iter().all(|t| is_aptos_address(t)) {
        return Err(SdkError::Argument);
    }
    let tokens = &tokens;
    let (block, (native, amounts)) = read_set_pinned(
        &apt.client,
        apt,
        |i| async move {
            let (head, version) = ledger(apt, i).await?;
            Ok((
                head,
                version,
                set_at(apt, i, version, id, package, tokens).await?,
            ))
        },
        |j, v| async move { set_at(apt, j, v, id, package, tokens).await },
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
                unknown: None,
            })
            .collect(),
    })
}
