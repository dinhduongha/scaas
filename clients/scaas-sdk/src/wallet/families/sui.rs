// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Sui's balances (spec §8.7, Sui row; docs/networks/sui.md NET-SUI-03): through the params' GraphQL endpoints
//! (`FamilyParams::Sui`; public fullnodes refuse JSON-RPC), each named by `chain_uid` (the genesis checkpoint's digest) in
//! base58 against `chainIdentifier`. The set's height is the answering endpoint's latest checkpoint (a certified checkpoint is
//! final), and one query reads the whole set at it, every read pinned by `atCheckpoint` (pinned in the request: no retry), the
//! answer's `checkpoint` naming it: the holder's `0x2::sui::SUI` `totalBalance` (MIST), and per listed token (a `Registry<T>`
//! id) the object at the owner's `Account<T>` id, which `ua-rs` derives (`families::sui::account_of`, `derive_address`: no hash
//! here, rule 6), its contents' `balance`. The object must name the token's registry and the holder as `owner`; absent at that
//! checkpoint, the owner has no Account of that token and holds 0 of it (the id is the only one the chain lets exist,
//! NET-SUI-03). Sui has no UA ledger: every `0x` + 64 hex holder is an address (rule 1). UNAUDITED.
use super::{amount, malformed, read_set};
use crate::config::is_aptos_address;
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, SdkError};
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::{Probe, ReadError};
use scaas_rpc::sui::SuiGraphql;
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::{json, Map, Value};

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

/// `0x` + 64 lowercase hex (Sui's long form) as its 32 bytes, else `Argument`.
fn bytes32(s: &str) -> Result<[u8; 32], SdkError> {
    if !is_aptos_address(s) {
        return Err(SdkError::Argument);
    }
    crate::text::unhex(s)?
        .try_into()
        .map_err(|_| SdkError::Argument)
}

/// The set's query for `n` tokens: the checkpoint, the holder's SUI, each token's Account object, all at `$c`.
fn query(n: usize) -> String {
    let vars: String = (0..n).map(|k| format!(", $t{k}: SuiAddress!")).collect();
    let objects: String = (0..n)
        .map(|k| {
            format!(" t{k}: object(address: $t{k}, atCheckpoint: $c) {{ asMoveObject {{ contents {{ json }} }} }}")
        })
        .collect();
    format!(
        "query($c: UInt53!, $a: SuiAddress!{vars}) {{ checkpoint(sequenceNumber: $c) {{ sequenceNumber }} \
         address(address: $a, atCheckpoint: $c) {{ balance(coinType: \"0x2::sui::SUI\") {{ totalBalance }} }}{objects} }}"
    )
}

/// The set at checkpoint `c` on endpoint `i`: (native, each token's balance).
async fn set_at(
    sui: &SuiGraphql,
    i: usize,
    c: u64,
    who: &str,
    tokens: &[(String, String)],
) -> Result<(Option<String>, Vec<String>), ReadError> {
    let mut vars = Map::new();
    vars.insert("c".into(), json!(c));
    vars.insert("a".into(), json!(who));
    for (k, (_, account)) in tokens.iter().enumerate() {
        vars.insert(format!("t{k}"), json!(account));
    }
    let d = sui
        .query(i, &query(tokens.len()), Value::Object(vars))
        .await
        .map_err(|e| failed(i, e))?;
    if d.pointer("/checkpoint/sequenceNumber")
        .and_then(Value::as_u64)
        != Some(c)
    {
        return Err(malformed(i, "a set of another checkpoint"));
    }
    let native = match d
        .pointer("/address/balance/totalBalance")
        .and_then(Value::as_str)
    {
        Some(s) => amount(i, s)?,
        None => return Err(malformed(i, "a SUI balance that is not a decimal string")),
    };
    let mut out = Vec::with_capacity(tokens.len());
    for (k, (registry, _)) in tokens.iter().enumerate() {
        let o = d
            .get(format!("t{k}"))
            .ok_or_else(|| malformed(i, "a token's object missing"))?;
        if o.is_null() {
            out.push("0".into());
            continue;
        }
        let j = o
            .pointer("/asMoveObject/contents/json")
            .ok_or_else(|| malformed(i, "an Account that is not a Move object"))?;
        if j.get("registry").and_then(Value::as_str) != Some(registry.as_str())
            || j.get("owner").and_then(Value::as_str) != Some(who)
        {
            return Err(malformed(i, "an Account of another registry or owner"));
        }
        match j.get("balance").and_then(Value::as_str) {
            Some(s) => out.push(amount(i, s)?),
            None => {
                return Err(malformed(
                    i,
                    "an Account balance that is not a decimal string",
                ))
            }
        }
    }
    Ok((Some(native), out))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let Some(sui) = c.sui.as_ref() else {
        return Err(SdkError::Argument);
    };
    let sui = sui.as_ref();
    let owner = bytes32(id)?;
    let tokens = c
        .profile
        .tokens
        .iter()
        .map(|t| {
            let a = scaas_ua::families::sui::account_of(&bytes32(&t.address)?, &owner);
            Ok((t.address.clone(), crate::text::hex(&a)))
        })
        .collect::<Result<Vec<(String, String)>, SdkError>>()?;
    let tokens = &tokens;
    let (block, (native, amounts)) = read_set(
        &sui.client,
        sui,
        |i| async move {
            let h = sui.head(i, None).await.map_err(ReadError::Failure)?;
            Ok((h, set_at(sui, i, h, id, tokens).await?))
        },
        |j, h| async move { set_at(sui, j, h, id, tokens).await },
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
