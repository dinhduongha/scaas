// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Native DOT on a profile's Substrate side (plan T32's read part; decisions CLI-SDK-32's Change of 2026-11-22): Polkadot Hub's
//! plain sr25519 accounts, the relay chain alike. An SS58 id at the params' prefix (`scaas-ua`'s `ss58_public_key`, else
//! `Argument`), its `System.Account` key (`scaas-ua`'s `system_account_key`), read at the finalized head through `scaas-rpc`'s
//! `substrate` client; the native amount is `AccountInfo.free` in planck, no tokens. ARCH-POS-15 by [`super::read_set`]: under
//! `strict_majority` the other endpoints read the account at their own hash of that height, and a strict majority must agree
//! on the hash and the decoded `AccountInfo` (never the answer's text). UNAUDITED.
use super::{read_set, Balances};
use crate::{Chain, SdkError};
use scaas_rpc::family::FamilyError;
use scaas_rpc::pool::ReadError;
use scaas_rpc::substrate::{AccountInfo, Substrate};
use scaas_rpc::{EndpointFailure, FailureKind};

pub(crate) async fn balances(c: &Chain, id: &str) -> Result<Balances, SdkError> {
    let (sub, prefix) = c.substrate.as_ref().ok_or(SdkError::Internal)?;
    let pk = scaas_ua::wallet::ss58_public_key(id, *prefix).map_err(|_| SdkError::Argument)?;
    let key = scaas_ua::wallet::system_account_key(&pk);
    let (sub, key) = (&**sub, &key[..]);
    let (number, (_, info)) = read_set(
        &sub.client,
        sub,
        |i| async move {
            let (hash, n) = sub.finalized(i).await.map_err(|e| failed(i, e))?;
            let info = sub.account(i, key, &hash).await.map_err(|e| failed(i, e))?;
            Ok((n, (hash, info)))
        },
        |j, n| async move { at(sub, j, n, key).await },
    )
    .await?;
    Ok(Balances {
        block: number,
        native: Some(info.free.to_string()),
        tokens: vec![],
    })
}

/// Endpoint `j`'s hash at height `n` and the account read at it.
async fn at(
    sub: &Substrate,
    j: usize,
    n: u64,
    key: &[u8],
) -> Result<(String, AccountInfo), ReadError> {
    let hash = sub
        .block_hash(j, n)
        .await
        .map_err(|e| failed(j, e))?
        .ok_or_else(|| super::malformed(j, "no block at that height"))?;
    let info = sub.account(j, key, &hash).await.map_err(|e| failed(j, e))?;
    Ok((hash, info))
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
