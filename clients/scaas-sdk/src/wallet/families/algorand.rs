// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Algorand's balances (spec §8.7, Algorand row; docs/networks/algorand.md): the native balance is
//! `/v2/accounts/{a}?exclude=all`'s `amount` (microalgos, an integer); a listed token is one app (its id in decimal) holding a
//! box per holder, `"b" ‖ pk32` for an address and `"u" ‖ id32` for a `0x` 32-byte UA id, its value 32 bytes big-endian. A box
//! algod does not have (404) is 0 (the app keeps none for a zero balance). algod reads the current round only (one-round
//! finality: it is final), so each answer names its `round` and every answer of a set must name one round: a set whose
//! answers name two is read again once, then refused as the endpoint's `AnswerMalformed`; under `strict_majority` another
//! endpoint's set must name the answering endpoint's round. Kept apart from NEAR (NET-NEAR ≠ NET-ALG): one shared app's boxes
//! here, a ledger per token contract there.
use super::{malformed, read_set};
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, SdkError};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use scaas_rpc::algorand::Algorand;
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::ReadError;
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::Value;

/// Whom a read is of: an address (its key and its printed form), or a UA id (its boxes only).
enum Holder {
    Address(String, [u8; 32]),
    Ua([u8; 32]),
}

fn holder(id: &str) -> Result<Holder, SdkError> {
    let lower = id.to_ascii_lowercase();
    if lower.starts_with("0x") && lower.len() == 66 {
        let b = crate::text::unhex(&lower)?;
        return b.try_into().map(Holder::Ua).map_err(|_| SdkError::Argument);
    }
    scaas_ua::algorand::address_to_key(id)
        .map(|k| Holder::Address(id.into(), k))
        .map_err(|_| SdkError::Argument)
}

/// An app id: decimal, no leading zero, 1 to 2^64 - 1.
fn app_id(s: &str) -> Option<u64> {
    s.parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && n.to_string() == s)
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

/// The round an answer names.
fn round_of(i: usize, v: &Value) -> Result<u64, ReadError> {
    v.get("round")
        .and_then(Value::as_u64)
        .ok_or_else(|| malformed(i, "an answer without its round"))
}

/// One pass over the set on endpoint `i`: (the rounds its answers named, native, each token's balance).
async fn pass(
    alg: &Algorand,
    i: usize,
    who: &Holder,
    apps: &[u64],
) -> Result<(Vec<u64>, (Option<String>, Vec<String>)), ReadError> {
    let mut rounds = vec![];
    let (native, key, tag) = match who {
        Holder::Address(a, k) => {
            let v = alg
                .get_raw(
                    i,
                    &format!("/v2/accounts/{a}"),
                    &[("exclude", "all".into())],
                )
                .await
                .and_then(|b| {
                    scaas_rpc::http::decode(&b, scaas_rpc::family::ANSWER_MAX).map_err(|k| {
                        FamilyError::Failure(EndpointFailure::new(i, k, "the account"))
                    })
                })
                .map_err(|e| failed(i, e))?;
            rounds.push(round_of(i, &v)?);
            let n = v
                .get("amount")
                .and_then(Value::as_u64)
                .ok_or_else(|| malformed(i, "an account amount that is not an integer"))?;
            (Some(n.to_string()), k, b'b')
        }
        Holder::Ua(id) => (None, id, b'u'),
    };
    let mut name = vec![tag];
    name.extend_from_slice(key);
    let q = [("name", format!("b64:{}", B64.encode(&name)))];
    let mut out = Vec::with_capacity(apps.len());
    for app in apps {
        match alg
            .get_raw(i, &format!("/v2/applications/{app}/box"), &q)
            .await
        {
            Err(FamilyError::Status { status: 404, .. }) => out.push("0".into()),
            r => {
                let v = r
                    .and_then(|b| {
                        scaas_rpc::http::decode(&b, scaas_rpc::family::ANSWER_MAX).map_err(|k| {
                            FamilyError::Failure(EndpointFailure::new(i, k, "the box"))
                        })
                    })
                    .map_err(|e| failed(i, e))?;
                rounds.push(round_of(i, &v)?);
                let w = v
                    .get("value")
                    .and_then(Value::as_str)
                    .and_then(|s| B64.decode(s).ok())
                    .filter(|w| w.len() == 32)
                    .ok_or_else(|| malformed(i, "a box value that is not 32 bytes"))?;
                out.push(be_dec(&w));
            }
        }
    }
    Ok((rounds, (native, out)))
}

/// The set on endpoint `i` at one round (`want`, or any when `None`): a pass whose answers name two rounds, or not `want`, is
/// read again once. A set with no answer naming a round (a UA id whose boxes are all absent) stands at the endpoint's
/// `last-round` read after it.
async fn set(
    alg: &Algorand,
    i: usize,
    who: &Holder,
    apps: &[u64],
    want: Option<u64>,
) -> Result<(u64, (Option<String>, Vec<String>)), ReadError> {
    for _ in 0..2 {
        let (rounds, v) = pass(alg, i, who, apps).await?;
        let r = match rounds.first() {
            Some(r) => *r,
            None => {
                let s = alg.get(i, "/v2/status").await.map_err(|e| failed(i, e))?;
                s.get("last-round")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| malformed(i, "a status without last-round"))?
            }
        };
        if rounds.iter().all(|x| *x == r) && want.is_none_or(|w| w == r) {
            return Ok((r, v));
        }
    }
    Err(malformed(i, "answers at another round, twice"))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let alg = c.algorand.as_ref().ok_or(SdkError::Internal)?;
    let who = holder(id)?;
    let apps: Vec<u64> = c
        .profile
        .tokens
        .iter()
        .map(|t| app_id(&t.address).ok_or(SdkError::Argument))
        .collect::<Result<_, _>>()?;
    let (who, apps) = (&who, &apps);
    let (block, (native, amounts)) = read_set(
        &alg.client,
        alg.as_ref(),
        |i| async move { set(alg, i, who, apps, None).await },
        |j, r| async move { Ok(set(alg, j, who, apps, Some(r)).await?.1) },
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

/// Big-endian bytes as a decimal string (a box's 32-byte word).
fn be_dec(b: &[u8]) -> String {
    let mut n = b.to_vec();
    let mut digits = vec![];
    while n.iter().any(|x| *x != 0) {
        let mut rem = 0u32;
        for x in n.iter_mut() {
            let v = (rem << 8) | u32::from(*x);
            *x = (v / 10) as u8;
            rem = v % 10;
        }
        digits.push(b'0' + rem as u8);
    }
    if digits.is_empty() {
        return "0".into();
    }
    digits.reverse();
    String::from_utf8(digits).unwrap_or_default()
}

#[cfg(test)]
mod be_dec_tests {
    #[test]
    fn be_dec_words() {
        assert_eq!(super::be_dec(&[0; 32]), "0");
        let mut w = [0u8; 32];
        w[31] = 1;
        w[30] = 1;
        assert_eq!(super::be_dec(&w), "257");
        assert_eq!(
            super::be_dec(&[0xff; 32]),
            "115792089237316195423570985008687907853269984665640564039457584007913129639935"
        );
    }
}
