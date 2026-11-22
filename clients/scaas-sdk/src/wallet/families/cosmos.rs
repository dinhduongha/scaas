// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Cosmos's balances (spec §8.7, Cosmos row; docs/networks/cosmos.md): through the profile's REST gateways
//! (`FamilyParams::Cosmos`), each named by the params' chain id (`node_info`'s network). The set's height is the answering
//! gateway's latest block (CometBFT: a committed block is final) and every read of the set carries it in
//! `x-cosmos-block-height`, so the gateway answers from that block's state (pinned in the request, as NEAR's `block_id`: no
//! retry). The native balance is `bank/v1beta1/balances/{a}/by_denom`'s `balance.amount`; a listed token is a CW20 contract,
//! its smart query `{"balance":{"address"}}` answering `data.balance`. Both are decimal strings (an account the bank does not
//! know answers "0" itself). Cosmos has no UA ledger: a `0x` UA id is `Argument` (spec §8.7 rule 1).
use super::{amount, malformed, read_set};
use crate::wallet::{Balances, TokenBalance};
use crate::{Chain, FamilyParams, SdkError};
use base64::Engine;
use scaas_rpc::cosmos::Cosmos;
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::{Probe, ReadError};
use scaas_rpc::{EndpointFailure, FailureKind};
use serde_json::{json, Value};

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// A Cosmos address of the chain's `prefix`: lowercase bech32 (BIP-173's checksum, an encoding's, no cryptography) of 20 bytes
/// (an account) or 32 (a contract), its padding bits zero.
pub(crate) fn address(prefix: &str, s: &str) -> bool {
    let Some(data) = s.strip_prefix(prefix).and_then(|r| r.strip_prefix('1')) else {
        return false;
    };
    let Some(v) = data
        .bytes()
        .map(|c| CHARSET.iter().position(|x| *x == c).map(|p| p as u8))
        .collect::<Option<Vec<u8>>>()
    else {
        return false;
    };
    // 20 bytes: 32 groups of 5 bits; 32 bytes: 52 groups, the last 4 bits padding; then 6 of checksum
    let pad_ok = match v.len() {
        38 => true,
        58 => v.get(51).is_some_and(|g| g & 0x0f == 0),
        _ => false,
    };
    let mut chk: u32 = 1;
    let hrp = prefix.bytes();
    let values = hrp
        .clone()
        .map(|c| c >> 5)
        .chain([0])
        .chain(hrp.map(|c| c & 31))
        .chain(v.iter().copied());
    for x in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ u32::from(x);
        for (i, g) in [
            0x3b6a_57b2,
            0x2650_8e6d,
            0x1ea1_19fa,
            0x3d42_33dd,
            0x2a14_62b3,
        ]
        .into_iter()
        .enumerate()
        {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    pad_ok && chk == 1
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

/// GET `path` on gateway `i` at height `h`: a 200's JSON, its string at `pointer` read as an amount.
async fn read(
    cos: &Cosmos,
    i: usize,
    h: u64,
    path: &str,
    pointer: &str,
) -> Result<String, ReadError> {
    let (status, v) = cos
        .rest
        .get_at_height(i, path, h)
        .await
        .map_err(|e| failed(i, e))?;
    if status != 200 {
        return Err(ReadError::Failure(EndpointFailure::new(
            i,
            FailureKind::Http,
            &format!("a balance read: HTTP {status}"),
        )));
    }
    match v.pointer(pointer).and_then(Value::as_str) {
        Some(s) => amount(i, s),
        None => Err(malformed(i, "a balance that is not a decimal string")),
    }
}

/// The set at height `h` on gateway `i`: (native, each token's balance).
async fn set_at(
    cos: &Cosmos,
    i: usize,
    h: u64,
    who: &str,
    denom: &str,
    tokens: &[String],
) -> Result<(Option<String>, Vec<String>), ReadError> {
    let native = read(
        cos,
        i,
        h,
        &format!("/cosmos/bank/v1beta1/balances/{who}/by_denom?denom={denom}"),
        "/balance/amount",
    )
    .await?;
    let q = base64::engine::general_purpose::URL_SAFE
        .encode(json!({"balance": {"address": who}}).to_string());
    let mut out = Vec::with_capacity(tokens.len());
    for t in tokens {
        let path = format!("/cosmwasm/wasm/v1/contract/{t}/smart/{q}");
        out.push(read(cos, i, h, &path, "/data/balance").await?);
    }
    Ok((Some(native), out))
}

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let (Some(cos), Some(FamilyParams::Cosmos { denom, prefix, .. })) =
        (c.cosmos.as_ref(), c.profile.family_params.as_ref())
    else {
        return Err(SdkError::Argument);
    };
    let tokens: Vec<String> = c.profile.tokens.iter().map(|t| t.address.clone()).collect();
    if !address(prefix, id) || !tokens.iter().all(|t| address(prefix, t)) {
        return Err(SdkError::Argument);
    }
    let tokens = &tokens;
    let (block, (native, amounts)) = read_set(
        &cos.rest.client,
        &cos.rest,
        |i| async move {
            let h = cos.rest.head(i, None).await.map_err(ReadError::Failure)?;
            Ok((h, set_at(cos, i, h, id, denom, tokens).await?))
        },
        |j, h| async move { set_at(cos, j, h, id, denom, tokens).await },
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
