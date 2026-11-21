// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The non-EVM families' balance reads (spec §8.7; plan T24; decisions CLI-SDK-15's Change of 2026-11-21): one `balances`
//! entry, picked by the profile's `family`. Each family reads the native balance and every listed token's at **one** height it
//! calls final, through its own `scaas-rpc` client (no transport here), bounded: an amount is a decimal string of at most 78
//! digits within a U256, else the endpoint's `AnswerMalformed`. ARCH-POS-15 by [`read_set`]: failover through the family
//! client; under `strict_majority` the other endpoints read the set at the height the answering endpoint read it at, and a
//! strict majority must agree (`EndpointNoMajority`). UNAUDITED.
// a build with no family feature reads EVM only: the shared helpers below stay unused there
#![cfg_attr(
    not(any(
        feature = "near",
        feature = "algorand",
        feature = "cosmos",
        feature = "aptos"
    )),
    allow(dead_code, unused_imports, unused_variables)
)]
#[cfg(feature = "algorand")]
pub(crate) mod algorand;
#[cfg(feature = "aptos")]
pub(crate) mod aptos;
#[cfg(feature = "cosmos")]
pub(crate) mod cosmos;
#[cfg(feature = "near")]
pub(crate) mod near;

use super::Balances;
use crate::{Sdk, SdkError};
use scaas_rpc::family::Client;
use scaas_rpc::pool::{Probe, ReadError};
use scaas_rpc::{EndpointFailure, FailureKind, Policy, RpcError};
use std::future::Future;

/// `balances` on a profile of a family other than EVM; `FeatureMissing` for a family this build does not read.
pub(crate) async fn balances(sdk: &Sdk, chain: &str, id: &str) -> Result<Balances, SdkError> {
    let c = sdk.chain(chain)?;
    match c.profile.family {
        #[cfg(feature = "near")]
        crate::Family::Near => near::balances(c, id).await,
        #[cfg(feature = "algorand")]
        crate::Family::Algorand => algorand::balances(c, id).await,
        #[cfg(feature = "cosmos")]
        crate::Family::Cosmos => cosmos::balances(c, id).await,
        #[cfg(feature = "aptos")]
        crate::Family::Aptos => aptos::balances(c, id).await,
        _ => Err(SdkError::FeatureMissing),
    }
}

/// Endpoint `i`'s answer is malformed (`why` names the field, never the value).
pub(crate) fn malformed(i: usize, why: &str) -> ReadError {
    ReadError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

/// A balance as a family sends it: a decimal string of 1 to 78 digits within a U256, written back without leading zeros.
#[cfg(any(feature = "near", feature = "cosmos", feature = "aptos"))]
pub(crate) fn amount(i: usize, s: &str) -> Result<String, ReadError> {
    if s.is_empty() || s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed(i, "a balance that is not a decimal string"));
    }
    alloy::primitives::U256::from_str_radix(s, 10)
        .map(|v| v.to_string())
        .map_err(|_| malformed(i, "a balance above 2^256 - 1"))
}

/// ARCH-POS-15 for one read set: `first(i)` reads endpoint `i`'s final height and the set at it, through the family client's
/// failover (each endpoint's identity, none behind the head endpoint 0 showed); under `strict_majority` every other endpoint
/// (its identity checked) reads the set at that height with `at(j, height)`, and the answering endpoint with those agreeing
/// must be a strict majority of the list.
#[cfg_attr(
    not(any(feature = "near", feature = "algorand", feature = "cosmos")),
    allow(dead_code)
)]
pub(crate) async fn read_set<V, P, F, Fut, G, Gut>(
    client: &Client,
    probe: &P,
    first: F,
    at: G,
) -> Result<(u64, V), SdkError>
where
    V: PartialEq,
    P: Probe,
    F: Fn(usize) -> Fut,
    Fut: Future<Output = Result<(u64, V), ReadError>>,
    G: Fn(usize, u64) -> Gut,
    Gut: Future<Output = Result<V, ReadError>>,
{
    let first = &first;
    read_set_pinned(
        client,
        probe,
        |i| async move { first(i).await.map(|(h, v)| (h, h, v)) },
        at,
    )
    .await
}

/// [`read_set`] for a family whose pin is not its head (Aptos: the set is pinned at a `ledger_version`, the floor of the
/// failover is the `block_height`): `first(i)` gives `(head, pin, set)`; endpoint 0's head raises the floor, the others read
/// at the pin, and the pin is the set's height.
pub(crate) async fn read_set_pinned<V, P, F, Fut, G, Gut>(
    client: &Client,
    probe: &P,
    first: F,
    at: G,
) -> Result<(u64, V), SdkError>
where
    V: PartialEq,
    P: Probe,
    F: Fn(usize) -> Fut,
    Fut: Future<Output = Result<(u64, u64, V), ReadError>>,
    G: Fn(usize, u64) -> Gut,
    Gut: Future<Output = Result<V, ReadError>>,
{
    let a = client.failover(probe, first).await?;
    let (head, height, value) = a.value;
    if a.endpoint == 0 {
        client.pool().saw_block(head);
    }
    if client.pool().policy() == Policy::StrictMajority {
        let n = client.len();
        let need = n / 2 + 1;
        let (mut agree, mut failures) = (1, vec![]);
        for j in (0..n).filter(|j| *j != a.endpoint) {
            let r = match client.pool().admit(probe, j, None).await {
                Ok(()) => at(j, height).await,
                Err(e) => Err(ReadError::Failure(e)),
            };
            match r {
                Ok(v) if v == value => agree += 1,
                Ok(_) => {}
                Err(ReadError::Failure(e)) => failures.push(e),
                Err(ReadError::Revert { reason, .. }) => failures.push(EndpointFailure::new(
                    j,
                    FailureKind::FailoverRevert,
                    &reason,
                )),
            }
        }
        if agree < need {
            return Err(RpcError::EndpointNoMajority {
                n,
                need,
                largest: agree,
                failures,
            }
            .into());
        }
    }
    Ok((height, value))
}
