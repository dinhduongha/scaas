// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The registry line (spec 2026-11-19-registry-verify-only-kinds §11.1, §11.2, §12 CTR-UA-65): where a registration, a key
//! write and a PQZ write go, where a UA's record is read, and the PQZ decoy candidates over the line. The rule for every
//! off-chain reader: resolve `holderOf(ua)` once on the bound registry (the profile's `registry`), read the record at
//! `holder` and the PQZ attachment at `pqzHome`; never assume the bound registry holds the record. Every read goes through
//! the chain's pool (the profile's RPC list under its policy, ARCH-POS-15); only the SDK reads the line (owner C6: no RPC in
//! the `ua-*` libraries). UNAUDITED.
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;

alloy::sol! {
    function holderOf(bytes32 ua) external view returns (address holder, uint16 kind, address pqzHome);
    function kindHome(uint16 kind) external view returns (address);
    function kindEnabled(uint16 kind) external view returns (bool);
    function predecessor() external view returns (address);
    function uaCount(uint16 kind) external view returns (uint256);
    function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[]);
    function pqzKeyOf(bytes32 ua) external view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven);
}

/// The PQZ key kind, whose per-generation list is the decoy set (CTR-UA-29, §11.2).
pub(crate) const PQZ_MLWE: u16 = 0x0142;
/// `MAX_GENERATION` (CTR-UA-70): the longest walk.
const MAX_GENERATION: usize = 16;
/// A `uaPage` read's length.
const PAGE: u64 = 256;
/// The decoy candidates read at most over the whole line.
// ponytail: one key read per candidate (its hash, owner P19); a larger set needs an indexer's hashes, not more reads
pub(crate) const DECOYS_MAX: u64 = 4_096;

/// Where a UA's record and its PQZ attachment live, as the bound registry's one walk answers (`holderOf`, §11.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UaLine {
    /// the generation holding the record (`0x` + 40 hex): the target of a key write, where its record is read
    pub holder: String,
    pub kind: u16,
    /// the record's PQZ home (§11.2): the target of a PQZ write, where its attachment is read; `None`: no home on the walk
    pub pqz_home: Option<String>,
}

impl UaLine {
    /// The target of a key write of the UA: its holder (§12).
    pub fn key_target(&self) -> &str {
        &self.holder
    }

    /// The target of a PQZ write of the UA: its PQZ home (§12); `PqzHomeNone` where the walk has none.
    pub fn pqz_target(&self) -> Result<&str, SdkError> {
        self.pqz_home.as_deref().ok_or(SdkError::PqzHomeNone)
    }
}

/// A read's failure as the SDK names it (the reason never carried: CLI-RPC-11).
fn sim(e: scaas_rpc::evm::SimError) -> SdkError {
    SdkError::Rpc(match e {
        scaas_rpc::evm::SimError::Revert(_) => scaas_rpc::RpcError::Revert {
            endpoint: 0,
            data: vec![],
            reason: String::new(),
        },
        scaas_rpc::evm::SimError::Transport(_) => scaas_rpc::RpcError::EndpointAllFailed {
            last: None,
            failover_revert: None,
        },
    })
}

fn addr(a: Address) -> String {
    format!("{a:#x}")
}

/// The chain's bound registry (the profile's `registry`) and its pool: `Argument` without one.
pub(crate) fn bound(
    sdk: &Sdk,
    chain: &str,
) -> Result<(Address, std::sync::Arc<scaas_rpc::evm::EvmPool>), SdkError> {
    let (profile, _, pool) = sdk.evm(chain)?;
    let r = profile
        .registry
        .as_deref()
        .and_then(|r| r.parse().ok())
        .ok_or(SdkError::Argument)?;
    Ok((r, pool))
}

/// One view call `c` on `to`; an answer that does not decode is `AbiMismatch`.
async fn view<C: SolCall>(
    pool: &scaas_rpc::evm::EvmPool,
    to: Address,
    c: C,
) -> Result<C::Return, SdkError> {
    let tx = TransactionRequest::default()
        .with_to(to)
        .with_input(c.abi_encode());
    let out = pool.call_tx(tx).await.map_err(sim)?;
    C::abi_decode_returns(&out).map_err(|_| SdkError::AbiMismatch)
}

/// The target of a registration of `kind` on the bound `registry` (§12): `kindHome(kind)`. `RegistrationKindDisabled`
/// where no generation of the line registers it; `RegistrationVerifyOnly` where the home is another generation (the bound
/// registry carries the kind verify-only, or not at all): nothing is sent to it.
pub(crate) async fn register_target(
    pool: &scaas_rpc::evm::EvmPool,
    registry: Address,
    kind: u16,
) -> Result<Address, SdkError> {
    let home = view(pool, registry, kindHomeCall { kind }).await?;
    match home {
        h if h == Address::ZERO => Err(SdkError::RegistrationKindDisabled),
        h if h == registry => Ok(h),
        _ => Err(SdkError::RegistrationVerifyOnly),
    }
}

/// The UA's line on the bound `registry`: one `holderOf(ua)` (§11.1); `UaUnregistered` where no generation holds it.
pub(crate) async fn ua_line(
    pool: &scaas_rpc::evm::EvmPool,
    registry: Address,
    ua: [u8; 32],
) -> Result<UaLine, SdkError> {
    let r = view(pool, registry, holderOfCall { ua: ua.into() }).await?;
    if r.holder == Address::ZERO {
        return Err(SdkError::UaUnregistered);
    }
    Ok(UaLine {
        holder: addr(r.holder),
        kind: r.kind,
        pqz_home: (r.pqzHome != Address::ZERO).then(|| addr(r.pqzHome)),
    })
}

/// The decoy candidates (owner P19, §11.2 M5): the lists, oldest generation first, each `(ua, key hash)`, concatenated;
/// a key hash already drawn (one key held by two UAs of the line, the §11.2 residual) and a UA already listed count once.
pub(crate) fn distinct_by_key(lists: &[Vec<([u8; 32], [u8; 32])>]) -> Vec<[u8; 32]> {
    let (mut uas, mut keys) = (
        std::collections::HashSet::new(),
        std::collections::HashSet::new(),
    );
    lists
        .iter()
        .flatten()
        .filter(|(ua, key)| uas.insert(*ua) & keys.insert(*key))
        .map(|(ua, _)| *ua)
        .collect()
}

/// The PQZ decoy candidates of the bound `registry`'s line (owner P19, §11.2, §12): the `0x0142` list of every generation on
/// its walk (`predecessor()`, at most `MAX_GENERATION`) that enables `0x0142`, oldest first, concatenated; each UA's key read
/// through the bound registry (`pqzKeyOf`, which forwards to its home) and hashed (`keyHashOf(0x0142, key)`), so the set is
/// distinct by key hash ([`distinct_by_key`]). `Argument` above [`DECOYS_MAX`] candidates or a walk longer than the line.
pub(crate) async fn decoy_candidates(
    pool: &scaas_rpc::evm::EvmPool,
    registry: Address,
) -> Result<Vec<[u8; 32]>, SdkError> {
    let mut walk = vec![registry];
    loop {
        let last = *walk.last().ok_or(SdkError::Internal)?;
        let p = view(pool, last, predecessorCall {}).await?;
        if p == Address::ZERO {
            break;
        }
        if walk.len() >= MAX_GENERATION || walk.contains(&p) {
            return Err(SdkError::Argument);
        }
        walk.push(p);
    }
    let mut lists = Vec::new();
    let mut total = 0u64;
    for g in walk.into_iter().rev() {
        if !view(pool, g, kindEnabledCall { kind: PQZ_MLWE }).await? {
            continue;
        }
        let n = view(pool, g, uaCountCall { kind: PQZ_MLWE }).await?;
        let n = u64::try_from(n).map_err(|_| SdkError::Argument)?;
        total = total.saturating_add(n);
        if total > DECOYS_MAX {
            return Err(SdkError::Argument);
        }
        let mut list = Vec::new();
        let mut start = 0u64;
        while start < n {
            let page = view(
                pool,
                g,
                uaPageCall {
                    kind: PQZ_MLWE,
                    start: U256::from(start),
                    n: U256::from(PAGE.min(n - start)),
                },
            )
            .await?;
            if page.is_empty() {
                return Err(SdkError::AbiMismatch);
            }
            start += page.len() as u64;
            for ua in page {
                let k = view(pool, registry, pqzKeyOfCall { ua }).await?;
                let code = pool.code(k.ptr).await.map_err(sim)?;
                // SSTORE2: the key is the pointer's code without its leading STOP byte
                let key = code
                    .get(1..)
                    .filter(|k| !k.is_empty())
                    .ok_or(SdkError::AbiMismatch)?;
                let hash = scaas_ua::key_hash_of(PQZ_MLWE, key)
                    .ok()
                    .flatten()
                    .ok_or(SdkError::AbiMismatch)?;
                list.push((ua.0, hash));
            }
        }
        lists.push(list);
    }
    Ok(distinct_by_key(&lists))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    fn w(b: u8) -> [u8; 32] {
        [b; 32]
    }

    #[test]
    fn decoys_concatenated_distinct_hash() {
        // gen 1's list, then gen 3's: one key held by two UAs (the residual) counts once, the oldest first; a UA twice once
        let lists = vec![
            vec![(w(1), w(0xa1)), (w(2), w(0xa2))],
            vec![
                (w(3), w(0xa3)),
                (w(4), w(0xa1)),
                (w(2), w(0xa9)),
                (w(5), w(0xa5)),
            ],
        ];
        assert_eq!(distinct_by_key(&lists), vec![w(1), w(2), w(3), w(5)]);
        // control: every hash and UA distinct, every candidate kept, concatenated in order
        let lists = vec![
            vec![(w(1), w(0xa1))],
            vec![(w(3), w(0xa3)), (w(4), w(0xa4))],
        ];
        assert_eq!(distinct_by_key(&lists), vec![w(1), w(3), w(4)]);
    }
}
