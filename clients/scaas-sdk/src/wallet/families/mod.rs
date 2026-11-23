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
        feature = "aptos",
        feature = "solana",
        feature = "soroban",
        feature = "sui",
        feature = "ton",
        feature = "substrate"
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
#[cfg(feature = "solana")]
pub(crate) mod solana;
#[cfg(feature = "soroban")]
pub(crate) mod soroban;
#[cfg(feature = "soroban")]
pub(crate) mod soroban_ops;
#[cfg(all(feature = "wallet", feature = "substrate"))]
pub(crate) mod substrate;
#[cfg(feature = "sui")]
pub(crate) mod sui;
#[cfg(feature = "ton")]
pub(crate) mod ton;

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
        #[cfg(feature = "solana")]
        crate::Family::Solana => solana::balances(c, id).await,
        #[cfg(feature = "soroban")]
        crate::Family::Soroban => soroban::balances(c, id).await,
        #[cfg(feature = "sui")]
        crate::Family::Sui => sui::balances(c, id).await,
        #[cfg(feature = "ton")]
        crate::Family::Ton => ton::balances(c, id).await,
        _ => Err(SdkError::FeatureMissing),
    }
}

/// `balances` of an SS58 id on a profile with a Substrate side (an EVM profile); `FeatureMissing` in a build without
/// `substrate`.
#[cfg(feature = "evm")]
pub(crate) async fn substrate_balances(c: &crate::Chain, id: &str) -> Result<Balances, SdkError> {
    #[cfg(all(feature = "wallet", feature = "substrate"))]
    return substrate::balances(c, id).await;
    #[cfg(not(all(feature = "wallet", feature = "substrate")))]
    {
        let _ = (c, id);
        Err(SdkError::FeatureMissing)
    }
}

/// Endpoint `i`'s answer is malformed (`why` names the field, never the value).
pub(crate) fn malformed(i: usize, why: &str) -> ReadError {
    ReadError::Failure(EndpointFailure::new(i, FailureKind::AnswerMalformed, why))
}

/// A balance as a family sends it: a decimal string of 1 to 78 digits within a U256, written back without leading zeros.
#[cfg(any(
    feature = "near",
    feature = "cosmos",
    feature = "aptos",
    feature = "solana",
    feature = "sui",
    feature = "ton"
))]
pub(crate) fn amount(i: usize, s: &str) -> Result<String, ReadError> {
    if s.is_empty() || s.len() > 78 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed(i, "a balance that is not a decimal string"));
    }
    u256_dec(s).ok_or_else(|| malformed(i, "a balance above 2^256 - 1"))
}

/// 2^256 - 1 in decimal.
#[cfg(any(
    feature = "near",
    feature = "cosmos",
    feature = "aptos",
    feature = "solana",
    feature = "sui",
    feature = "ton"
))]
const U256_MAX: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129639935";

/// A string of decimal digits as its shortest form when it is at most 2^256 - 1, else `None` (no alloy in a build without
/// `evm`).
#[cfg(any(
    feature = "near",
    feature = "cosmos",
    feature = "aptos",
    feature = "solana",
    feature = "sui",
    feature = "ton"
))]
pub(crate) fn u256_dec(s: &str) -> Option<String> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let t = s.trim_start_matches('0');
    let t = if t.is_empty() { "0" } else { t };
    (t.len() < 78 || (t.len() == 78 && t <= U256_MAX)).then(|| t.to_string())
}

/// ARCH-POS-15 for one read set: `first(i)` reads endpoint `i`'s final height and the set at it, through the family client's
/// failover (each endpoint's identity, none behind the head endpoint 0 showed); under `strict_majority` every other endpoint
/// (its identity checked) reads the set at that height with `at(j, height)`, and the answering endpoint with those agreeing
/// must be a strict majority of the list.
#[cfg_attr(
    not(any(
        feature = "near",
        feature = "algorand",
        feature = "cosmos",
        feature = "solana",
        feature = "soroban",
        feature = "sui",
        feature = "ton",
        feature = "substrate"
    )),
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
    read_set_from(client, probe, first, at)
        .await
        .map(|(height, value, _)| (height, value))
}

/// [`read_set_pinned`] with the index of the endpoint whose answer stands (review T26 B-2: a status is decisive under
/// `failover` only when endpoint 0 gave it and is not `discovered`, CLI-RPC-09).
pub(crate) async fn read_set_from<V, P, F, Fut, G, Gut>(
    client: &Client,
    probe: &P,
    first: F,
    at: G,
) -> Result<(u64, V, usize), SdkError>
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
    Ok((height, value, a.endpoint))
}

#[cfg(all(test, feature = "near"))]
mod tests {
    use super::u256_dec;

    #[test]
    fn u256_decimals() {
        assert_eq!(u256_dec("0").as_deref(), Some("0"));
        assert_eq!(u256_dec("000").as_deref(), Some("0"));
        assert_eq!(u256_dec("0012").as_deref(), Some("12"));
        let max = super::U256_MAX;
        assert_eq!(u256_dec(max).as_deref(), Some(max));
        assert_eq!(u256_dec(&format!("0{max}")).as_deref(), Some(max));
        // 2^256 and a 79-digit value are above; a sign, a space or nothing is no decimal
        assert_eq!(
            u256_dec(
                "115792089237316195423570985008687907853269984665640564039457584007913129639936"
            ),
            None
        );
        assert_eq!(u256_dec(&format!("1{max}")), None);
        for bad in ["", "-1", "+1", " 1", "1a"] {
            assert_eq!(u256_dec(bad), None, "{bad:?}");
        }
    }
}
