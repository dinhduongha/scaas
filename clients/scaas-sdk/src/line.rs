// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The registry line (spec 2026-11-19-registry-verify-only-kinds §11.1, §11.2, §12 CTR-UA-65): where a registration, a key
//! write and a PQZ write go, where a UA's record is read, and the PQZ decoy candidates over the line. The rule for every
//! off-chain reader: resolve `holderOf(ua)` once on the bound registry (the profile's `registry`), read the record at
//! `holder` and the PQZ attachment at `pqzHome`; never assume the bound registry holds the record. Every read goes through
//! the chain's pool (the profile's RPC list under its policy, ARCH-POS-15); only the SDK reads the line (owner C6: no RPC in
//! the `ua-*` libraries). UNAUDITED.
use crate::op::sim;
use crate::{Sdk, SdkError};
use alloy::network::TransactionBuilder;
use alloy::primitives::{Address, U256};
use alloy::rpc::types::TransactionRequest;
use alloy::sol_types::SolCall;
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{BlockChoice, ReadAt, ReadError};
use scaas_rpc::{EndpointFailure, FailureKind, Purpose};
use std::sync::Arc;

/// The registry views the line reads (a private module: the generated call types stay out of the bindings' surface).
mod abi {
    alloy::sol! {
        function holderOf(bytes32 ua) external view returns (address holder, uint16 kind, address pqzHome);
        function kindHome(uint16 kind) external view returns (address);
        function kindEnabled(uint16 kind) external view returns (bool);
        function predecessor() external view returns (address);
        function generation() external view returns (uint256);
        function uaCount(uint16 kind) external view returns (uint256);
        function uaPage(uint16 kind, uint256 start, uint256 n) external view returns (bytes32[]);
        function pqzKeyOf(bytes32 ua) external view returns (uint64 version, address ptr, bytes32 pqzPopHash, bool proven);
    }
}
use abi::*;

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
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[cfg_attr(feature = "wasm", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "wasm", serde(deny_unknown_fields))]
pub struct UaLine {
    /// the generation holding the record (`0x` + 40 hex): the target of a key write, where its record is read
    pub holder: String,
    pub kind: u16,
    /// the record's PQZ home (§11.2): the target of a PQZ write, where its attachment is read; `None`: no home on the walk
    pub pqz_home: Option<String>,
}

impl UaLine {
    /// The target of a key write of the UA: its holder (§12).
    pub fn key_target(&self) -> String {
        self.holder.clone()
    }

    /// The target of a PQZ write of the UA: its PQZ home (§12); `PqzHomeNone` where the walk has none.
    pub fn pqz_target(&self) -> Result<String, SdkError> {
        self.pqz_home.clone().ok_or(SdkError::PqzHomeNone)
    }
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

/// Where a registry write goes on the bound `registry`'s line (§12, CTR-UA-65; the round's merge review A3): a registration
/// (and a cache part) of a kind to `kindHome(kind)` ([`register_target`]: refused where that is another generation),
/// `registerMsig` to the bound registry (every generation registers an `msig`), a key write (`setKemKey`,
/// `acceptMembership`, `updateMsig`) to the UA's holder, a PQZ write (`storePqzPop`, `setPqzKey`, the scoped ones) to its PQZ
/// home. A UA not registered yet (the second part of a registration, the KEM fill of one) goes to the bound registry. The
/// holder comes from [`Line`] (F2, review A-7): one endpoint at one block; a holder or home off the line and a revert are the
/// error, never a fallback.
pub(crate) async fn write_target(
    pool: &EvmPool,
    registry: Address,
    entry: &str,
    ua: [u8; 32],
    kind: Option<u16>,
) -> Result<Address, SdkError> {
    let line = || async {
        Ok::<_, SdkError>(
            read_one(pool, BlockChoice::Latest, Purpose::Plain, |at| async move {
                Line::read(pool, &at, registry)
                    .await?
                    .holder_of(pool, &at, ua)
                    .await
            })
            .await?,
        )
    };
    match entry {
        "register" | "registerWebAuthn" | "registerMuSig2" | "registerFrost"
        | "registerBlsMulti" | "cacheExpandedKey" => {
            register_target(pool, registry, kind.ok_or(SdkError::Argument)?).await
        }
        "setKemKey" | "acceptMembership" | "updateMsig" => {
            Ok(line().await?.map_or(registry, |(h, _, _)| h))
        }
        "storePqzPop" | "setPqzKey" | "setPqzScopedKey" | "storePqzScopedPop" => {
            Ok(line().await?.map_or(registry, |(h, _, p)| p.unwrap_or(h)))
        }
        _ => Ok(registry),
    }
}

/// The UA's line on the bound `registry`: its holder, kind and PQZ home by [`Line`] (§11.1);
/// `UaUnregistered` where no generation holds it.
pub(crate) async fn ua_line(
    pool: &EvmPool,
    registry: Address,
    ua: [u8; 32],
) -> Result<UaLine, SdkError> {
    let r = read_one(pool, BlockChoice::Latest, Purpose::Plain, |at| async move {
        Line::read(pool, &at, registry)
            .await?
            .holder_of(pool, &at, ua)
            .await
    })
    .await?;
    let (holder, kind, pqz_home) = r.ok_or(SdkError::UaUnregistered)?;
    Ok(UaLine {
        holder: addr(holder),
        kind,
        pqz_home: pqz_home.map(addr),
    })
}

/// A read's block (the pinned read of CLI-RPC-05).
pub(crate) type At = ReadAt<alloy::primitives::B256>;

/// An answer endpoint `at` gave that no honest registry gives: that endpoint's failure (the read fails over, never guesses).
pub(crate) fn malformed(at: &At, why: &str) -> ReadError {
    ReadError::Failure(EndpointFailure::new(
        at.endpoint,
        FailureKind::AnswerMalformed,
        why,
    ))
}

/// `eth_call` of `sig(args…)` on `to` at the read's block.
pub(crate) async fn call_at(
    pool: &EvmPool,
    at: &At,
    to: Address,
    sig: &str,
    args: &[[u8; 32]],
) -> Result<Vec<u8>, ReadError> {
    let sel = scaas_ua::keccak256(sig.as_bytes());
    let d = [sel.get(..4).unwrap_or_default(), &args.concat()].concat();
    pool.call_at(at, to, d.into()).await.map(|b| b.to_vec())
}

/// One view call `c` on `to` at the read's block; an answer that does not decode is the endpoint's failure.
async fn view_at<C: SolCall>(
    pool: &EvmPool,
    at: &At,
    to: Address,
    c: C,
) -> Result<C::Return, ReadError> {
    let out = pool.call_at(at, to, c.abi_encode().into()).await?;
    C::abi_decode_returns(&out).map_err(|_| malformed(at, "a registry view that does not decode"))
}

/// F2 (owner 2026-11-23; CTR-UA-70, CTR-UA-72; folds in review A-7): the bound registry's line as one endpoint answers it at
/// one block, oldest generation first (`gens[g - 1]` is generation `g`, the last the bound registry). Every SDK registry read
/// goes through it ([`read_line`]): a record is read at its holder, a native key signs `UAAuth` in the holder's domain at the
/// holder's generation, a key write goes to the holder; a holder off the line, a line that is not consecutive and a revert are
/// the read's failure, never a fallback to the bound registry. UNAUDITED.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Line {
    gens: Vec<Address>,
}

impl Line {
    /// The walk from `bound` (`predecessor()`, at most [`MAX_GENERATION`]), each `generation()` one below its successor's and
    /// generation 1's predecessor 0: anything else is the endpoint's failure.
    pub(crate) async fn read(pool: &EvmPool, at: &At, bound: Address) -> Result<Line, ReadError> {
        let mut gens = vec![bound];
        let top = view_at(pool, at, bound, generationCall {}).await?;
        let top = usize::try_from(top)
            .ok()
            .filter(|g| (1..=MAX_GENERATION).contains(g))
            .ok_or_else(|| malformed(at, "a generation outside 1..=16"))?;
        loop {
            let last = *gens.last().ok_or(malformed(at, "empty line"))?;
            let p = view_at(pool, at, last, predecessorCall {}).await?;
            if gens.len() == top {
                if p != Address::ZERO {
                    return Err(malformed(at, "generation 1 with a predecessor"));
                }
                break;
            }
            if p == Address::ZERO || gens.contains(&p) {
                return Err(malformed(at, "a line that is not consecutive"));
            }
            let g = view_at(pool, at, p, generationCall {}).await?;
            if g != U256::from(top - gens.len()) {
                return Err(malformed(at, "a line that is not consecutive"));
            }
            gens.push(p);
        }
        gens.reverse();
        Ok(Line { gens })
    }

    /// The bound registry (the profile's).
    pub(crate) fn bound(&self) -> Address {
        self.gens.last().copied().unwrap_or_default()
    }

    /// `a`'s generation, `None` off the line.
    pub(crate) fn generation(&self, a: Address) -> Option<u32> {
        let i = self.gens.iter().position(|g| *g == a)?;
        u32::try_from(i + 1).ok()
    }

    /// The generation holding `ua`'s record, its kind and its PQZ home (`None`: no home on the walk): one `holderOf(ua)` on the bound
    /// registry; `None` where no generation holds it (a native-space id without a call). A holder or home off the line is the
    /// endpoint's failure (A-7).
    pub(crate) async fn holder_of(
        &self,
        pool: &EvmPool,
        at: &At,
        ua: [u8; 32],
    ) -> Result<Option<(Address, u16, Option<Address>)>, ReadError> {
        if scaas_ua::in_native_space(&ua) {
            return Ok(None);
        }
        let r = view_at(pool, at, self.bound(), holderOfCall { ua: ua.into() }).await?;
        if r.holder == Address::ZERO {
            return Ok(None);
        }
        let on = |a: Address| self.generation(a).is_some();
        if !on(r.holder) || (r.pqzHome != Address::ZERO && !on(r.pqzHome)) {
            return Err(malformed(at, "a holder off the line"));
        }
        let home = (r.pqzHome != Address::ZERO).then_some(r.pqzHome);
        Ok(Some((r.holder, r.kind, home)))
    }

    /// [`Line::holder_of`]'s holder.
    pub(crate) async fn holder(
        &self,
        pool: &EvmPool,
        at: &At,
        ua: [u8; 32],
    ) -> Result<Option<Address>, ReadError> {
        Ok(self.holder_of(pool, at, ua).await?.map(|(h, _, _)| h))
    }

    /// The `UAAuth` domain a native key signs in for a record `holder` holds (CTR-UA-60: the bound registry hands the check
    /// to the holder): the holder's own at its generation; `None` (a native signer, a native id, an unregistered one) the
    /// bound registry's.
    pub(crate) fn domain(
        &self,
        holder: Option<Address>,
        chain_id: u64,
        chain_uid: [u8; 32],
    ) -> scaas_ua::Domain {
        let at = holder
            .filter(|h| self.generation(*h).is_some())
            .unwrap_or(self.bound());
        scaas_ua::Domain {
            generation: self.generation(at).unwrap_or(1),
            chain_id,
            registry: at.into_array(),
            chain_uid,
        }
    }
}

/// F2's reader: `f` over chain `chain`'s line (the profile's registry), every call of it by one endpoint at one block
/// (`choice`; ARCH-POS-15: a logical read never mixes nodes or blocks, review A2-2), under `purpose`. `f` gets the pool, the
/// block and the [`Line`] read at it; the answer is `f`'s with that line. `Argument` without a registry. On a chain whose RPC
/// is not trusted on a pinned read (the profile's `pinnedReads` false) a read at the latest block is the sticky read
/// ([`read_one`]); a read feeding a decryption or at another block is `PinnedReadsUntrusted` there.
pub(crate) async fn read_line<T, F, Fut>(
    sdk: &Sdk,
    chain: &str,
    choice: BlockChoice,
    purpose: Purpose,
    f: F,
) -> Result<(T, Line), SdkError>
where
    T: Clone + PartialEq,
    F: Fn(Arc<EvmPool>, At, Line) -> Fut,
    Fut: std::future::Future<Output = Result<T, ReadError>>,
{
    let (bound, pool) = self::bound(sdk, chain)?;
    let (f, p) = (&f, &pool);
    Ok(read_one(&pool, choice, purpose, |at| async move {
        let line = Line::read(p, &at, bound).await?;
        let v = f(p.clone(), at, line.clone()).await?;
        Ok((v, line))
    })
    .await?)
}

/// One logical read on `pool` (ARCH-POS-15; owner 2026-11-23, sticky endpoint): pinned to one block by one endpoint
/// ([`EvmPool::read_at_block`]) where the chain's pinned reads are trusted; else, at the latest block, the sticky read
/// ([`EvmPool::read_sticky`]: one endpoint whose head did not move, a read feeding a decryption refused); another block
/// choice there is `PinnedReadsUntrusted`.
pub(crate) async fn read_one<T, F, Fut>(
    pool: &EvmPool,
    choice: BlockChoice,
    purpose: Purpose,
    f: F,
) -> Result<T, scaas_rpc::RpcError>
where
    T: Clone + PartialEq,
    F: Fn(At) -> Fut,
    Fut: std::future::Future<Output = Result<T, ReadError>>,
{
    Ok(if pool.pinned_reads() || choice != BlockChoice::Latest {
        pool.read_at_block(choice, purpose, f).await?
    } else {
        pool.read_sticky(purpose, f).await?
    }
    .value)
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

/// `ReceiverUnregistered` (spec §7.1, owner 2026-11-19 R3; T26 B2-9): `to` a derived UA (not a native id: its top 12 bytes
/// not all zero) that no generation of the profile's line holds (one `holderOf(to)` on the bound registry by [`read_line`]:
/// one endpoint, one block), or a profile naming no registry (fail closed); a native id passes. Every payment prepare calls
/// it, in every build with `evm`.
pub(crate) async fn receiver_registered(
    sdk: &Sdk,
    chain: &str,
    to: &[u8; 32],
) -> Result<(), SdkError> {
    if to.get(..12).is_some_and(|h| h.iter().all(|b| *b == 0)) {
        return Ok(());
    }
    let (profile, _, _) = crate::op::evm(sdk, chain)?;
    if profile.registry.is_none() {
        return Err(SdkError::ReceiverUnregistered);
    }
    let to = *to;
    let (held, _) = read_line(
        sdk,
        chain,
        BlockChoice::Latest,
        Purpose::Plain,
        |pool, at, line| async move { Ok(line.holder(&pool, &at, to).await?.is_some()) },
    )
    .await?;
    held.then_some(()).ok_or(SdkError::ReceiverUnregistered)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::indexing_slicing)]
    use super::*;

    fn w(b: u8) -> [u8; 32] {
        [b; 32]
    }

    /// Decision (161): a simulation's revert keeps the chain's reason (a refused write named its error nowhere before).
    #[test]
    fn a_simulated_revert_keeps_its_reason() {
        let e = crate::op::sim(scaas_rpc::evm::SimError::Revert("UAPqzHolder(0x01)".into()));
        assert!(format!("{e:?}").contains("UAPqzHolder(0x01)"), "{e:?}");
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
