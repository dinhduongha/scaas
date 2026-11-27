//! Money safety before every simulation and signature (PAY-FIX2, NODE-JOB-01, -19, -20, NODE-GW-07). A lane is
//! `msg.sender` of everything it signs, and it holds fee income in tokens, so:
//!
//! - a job runs only as a named entry: its selector is a row of the entry table (`crate::typed`) on the contract kind it
//!   names, and the target meets that kind's rule — a token entry on a registered token, a wallet's or account's on any
//!   bound contract that is no token or factory, a DEX entry on a listed DEX, a registry or factory entry on the configured
//!   one, a `PqChat` entry on an instance the token factory lists as class 3, its unsigned writes paid or under the lane
//!   policy (a `transfer` of the lane's own balance is no row; there is no hex path);
//! - a meta-transaction runs only on a contract bound to this chain (`chainUid()`, the salt every signature on it
//!   commits to); a `MetaTransfer` only on a registered token (answering `chainUid()` costs nothing to deploy);
//! - a signature that can be checked here is (the typed digest, computed locally): a native signer that recovers to
//!   someone else and has no code is refused before any simulation;
//! - `mtxSettle` gas is sized by a simulation that settles every planned settlement (success is not monotonic in gas,
//!   P2b-2), and a contract signer's meta-tx gets at least the ERC-1271 floor (P1b note c);
//! - gas follows the chain's fork, read from its `latest` header: under Amsterdam (EIP-7928 `blockAccessListHash`
//!   present) the two-dimensional model (EIP-7825 + EIP-8037): regular gas ≤ 2^24 per transaction, enforced by the
//!   chain's own simulation and checked here for the calldata floor, the gas limit (regular + state) bounded by
//!   `max_gas_per_tx`, the chain's current block gas limit (read, never assumed) and 2^32 − 1; before it (Osaka, L2s,
//!   anvil) the whole gas limit ≤ 2^24 as before.
//!
//! Pure rules first (unit- and mutation-tested), then the cached chain reads (`Guard`).
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, RwLock};

use alloy::primitives::{Address, Bytes, B256};
use alloy::sol_types::{SolCall, SolValue};
use tracing::warn;

use crate::abi::{
    IModuleGroup, IMtxIds, IOpenFactory, IPqzToken, IRelayFeeRouter, ISCaaSDex, IToken, IUAKindOf,
    IUALedger, IUARegistry, IERC165,
};
use crate::chain::{BlockGas, Chain, SimError};
use crate::config::ChainCfg;
use crate::metatx::{Mtx, UaMtx};
use crate::submit::Work;
use crate::typed;

pub const SEL_MTX_SETTLE: [u8; 4] = ISCaaSDex::mtxSettleCall::SELECTOR;
/// The DEX's `mtxInvalidateNonces(address,uint256,uint256,bytes)`.
pub const SEL_MTX_INVALIDATE_NONCES: [u8; 4] = [0xdb, 0xac, 0x32, 0xd0];
/// The token's `mtxInvalidateNonces(bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))` (R12, R38).
pub const SEL_TOKEN_INVALIDATE_NONCES: [u8; 4] = IMtxIds::mtxInvalidateNoncesCall::SELECTOR;

/// What a contract kind requires of its target (job-api.md §11).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rule {
    /// A registered token (`token`, `zether`, `pqz`).
    Token,
    /// The chain's `SmartKeyAccountFactory` (`account_factory`).
    AccountFactory,
    /// Self-authenticating (`SmartKeyAccount`, `MandateWallet`): any contract bound to this chain that is not a
    /// registered token or the token factory; the target checks the owner's or delegate's signature.
    SelfAuth,
    /// A DEX on the chain's DEX list (`dex`), bound to this chain.
    Dex,
    /// A generation of the chain's `UARegistry` line (`ua_registries`, CTR-UA-65), bound to this chain: its writes (UA-8, ruling R-node; `registerMsig` since typed-signing R1, `registerWebAuthn` / `registerMuSig2` / `registerFrost` since R1b, `registerBlsMulti` since bls-multi Task 10).
    UaRegistry,
    /// One of the chain's `GovernanceRouter`s (`governance_routers`), bound to this chain (spec 2026-11-02-governance §12.7): its
    /// typed entries only; a router is no target of any other kind's row.
    GovRouter,
    /// An instance of a generic class of the chain's `OpenFactory` (`token_factory`, factory index spec §8.6): `infoOf(target)` lists
    /// this `contractClass` with `version ≠ 0` (`pqchat`: class 3, UA-7 P32, topics spec P45; `pqvault`: class 4, CTR-PQV-13). An
    /// instance answers no `chainUid()`
    /// (its records are portable): the listing binds it, and no other kind's rule takes it.
    FactoryClass(u16),
    /// `PqChatStore` (`pqchatstore`, CTR-CHAT-22): the release data's address ([`PQCHATSTORE_ADDRESS`]) whose runtime code
    /// hash at the lane's final block is the release data's ([`PQCHATSTORE_RUNTIME_HASH`]); it answers no `chainUid()` and is
    /// made by no factory.
    ChatStore,
}

/// `PqChat`'s class on `OpenFactory`'s generic path (D22).
pub const CLASS_PQCHAT: u16 = 3;
/// `PqVault`'s class on `OpenFactory`'s generic path (CTR-PQV-13).
pub const CLASS_PQVAULT: u16 = 4;

/// The factory kinds whose writes run on an instance of their class (`Rule::FactoryClass`), with their contract names.
const FACTORY_KINDS: [(&str, &str); 2] = [("pqchat", "PqChat"), ("pqvault", "PqVault")];

fn chatstore_release(k: &str) -> String {
    let r: serde_json::Value = serde_json::from_str(include_str!(
        "../../smartcontracts/evm/release-data/PqChatStore.json"
    ))
    .expect("release data");
    r[k].as_str().expect("release data field").to_string()
}

/// CTR-CHAT-22: `PqChatStore`'s runtime code hash, `release-data/PqChatStore.json`'s `runtimeCodeHash` (plan T6).
pub static PQCHATSTORE_RUNTIME_HASH: std::sync::LazyLock<B256> = std::sync::LazyLock::new(|| {
    chatstore_release("runtimeCodeHash")
        .parse()
        .expect("release data: runtimeCodeHash")
});

/// CTR-CHAT-22: `PqChatStore`'s one address (the deterministic deployer's CREATE2 of the pinned init code, salt 0), the
/// release data's `address` (review P2-3: the address pinned, so no other contract with that runtime is a target).
pub static PQCHATSTORE_ADDRESS: std::sync::LazyLock<Address> = std::sync::LazyLock::new(|| {
    chatstore_release("address")
        .parse()
        .expect("release data: address")
});

/// How long a `PqChatStore` pass is kept before its code is read again (review P2-3), beside the check that its final block's
/// hash still holds.
pub const CHATSTORE_RECHECK: std::time::Duration = std::time::Duration::from_secs(300);

/// The rule of a contract kind (`typed::Row::contracts`).
pub fn rule_of(contract: &str) -> Option<Rule> {
    Some(match contract {
        "token" | "zether" | "pqz" => Rule::Token,
        "wallet" | "account" => Rule::SelfAuth,
        "dex" => Rule::Dex,
        "registry" => Rule::UaRegistry,
        "factory" => Rule::AccountFactory,
        "gov_router" => Rule::GovRouter,
        "pqchat" => Rule::FactoryClass(CLASS_PQCHAT),
        "pqvault" => Rule::FactoryClass(CLASS_PQVAULT),
        "pqchatstore" => Rule::ChatStore,
        _ => return None,
    })
}

/// The allow-list: every selector the node sends, with its table row. `RelayFeeRouter.relay` comes from the `UARelayFee` row
/// (the token's `mtxRelayFee` only ever runs under the router). Anything else is refused.
pub fn row(sel: [u8; 4], contract: &str) -> Option<&'static typed::Row> {
    typed::rows()
        .iter()
        .find(|r| r.sent == sel && !r.entry.is_empty() && r.contracts.contains(&contract))
}

/// The parties of a PQZ debit (group 3g, KV-7): its receivers and, with auditor copies, the token's `auditorUA()`; `None` for
/// any other job.
async fn pqz_parties(chain: &Chain, w: &Work) -> Result<Option<(Address, Vec<B256>)>, SimError> {
    let Some(t) = w
        .typed
        .as_ref()
        .filter(|t| t.contract == "pqz" && (!t.pqz_parties.is_empty() || t.pqz_auditor))
    else {
        return Ok(None);
    };
    let registry = chain.call_view(w.to, IUALedger::registryCall {}).await?;
    let mut parties = t.pqz_parties.clone();
    if t.pqz_auditor {
        parties.push(chain.call_view(w.to, IPqzToken::auditorUACall {}).await?);
    }
    Ok((registry != Address::ZERO).then_some((registry, parties)))
}

/// Group 3g (KV-7, R3, spec §7.3): at intake, a PQZ debit naming a receiver, a leg or the auditor with a **pending** version is
/// refused by name, `PQZ_KEY_ROTATION_PENDING`, before the sender pays for a transaction that would fail. Pending: the UA's latest
/// stored version is above its current one and has the current key's length (this set's; a version of another set's length never
/// becomes current here). A read the registry refuses leaves the decision to the simulation; a transport error is transient.
async fn no_pending_party(chain: &Chain, w: &Work) -> Result<(), Refusal> {
    let read = |what: &'static str| {
        move |e: SimError| match e {
            SimError::Transport(e) => Some(Refusal::Transport(format!("{what}: {e}"))),
            SimError::Revert(_) => None,
        }
    };
    let (registry, parties) = match pqz_parties(chain, w).await {
        Ok(Some(x)) => x,
        Ok(None) => return Ok(()),
        Err(e) => return read("PQZ parties")(e).map_or(Ok(()), Err),
    };
    // NODE-JOB-28 (CTR-UA-43): the key reads follow the token's scope, as its `_keyOf` / `_keyAtOf`
    let scope = match crate::pqz::key_scope(chain, w.to).await {
        Ok((s, _)) => s,
        Err(e) => return read("pqzVerifyConfig")(e).map_or(Ok(()), Err),
    };
    for ua in parties {
        let cur = match scope {
            None => chain
                .call_view(registry, IUARegistry::pqzKeyOfCall { ua })
                .await
                .map(|c| (c.version, c.ptr)),
            Some(scope) => chain
                .call_view(registry, IUARegistry::pqzScopedKeyOfCall { ua, scope })
                .await
                .map(|c| (c.version, c.ptr)),
        };
        let (cur_version, cur_ptr) = match cur {
            Ok(c) => c,
            Err(e) => match read("pqzKeyOf")(e) {
                Some(r) => return Err(r),
                None => continue,
            },
        };
        let latest = match scope {
            None => {
                chain
                    .call_view(registry, IUARegistry::pqzKeyLatestCall { ua })
                    .await
            }
            Some(scope) => {
                chain
                    .call_view(registry, IUARegistry::pqzScopedKeyLatestCall { ua, scope })
                    .await
            }
        };
        let latest = match latest {
            Ok(l) => l,
            Err(e) => match read("pqzKeyLatest")(e) {
                Some(r) => return Err(r),
                None => continue,
            },
        };
        if latest <= cur_version || cur_ptr == Address::ZERO {
            continue;
        }
        let at = match scope {
            None => chain
                .call_view(
                    registry,
                    IUARegistry::pqzKeyAtCall {
                        ua,
                        version: latest,
                    },
                )
                .await
                .map(|a| a.ptr),
            Some(scope) => chain
                .call_view(
                    registry,
                    IUARegistry::pqzScopedKeyAtCall {
                        ua,
                        scope,
                        version: latest,
                    },
                )
                .await
                .map(|a| a.ptr),
        };
        let at_ptr = match at {
            Ok(a) => a,
            Err(e) => match read("pqzKeyAt")(e) {
                Some(r) => return Err(r),
                None => continue,
            },
        };
        let len = |a| async move { chain.code_len(a).await };
        let (l, c) = match (len(at_ptr).await, len(cur_ptr).await) {
            (Ok(l), Ok(c)) => (l, c),
            (Err(e), _) | (_, Err(e)) => match read("eth_getCode")(e) {
                Some(r) => return Err(r),
                None => continue,
            },
        };
        if l == c {
            return Err(Refusal::Policy(format!("PQZ_KEY_ROTATION_PENDING: {ua:#x} has version {latest} stored and not yet current \
                (current {cur_version}); prove against its current key once version {latest} is current")));
        }
    }
    Ok(())
}

/// NODE-JOB-28 (spec 2026-11-13-pqz-three-keys §3, §7; CTR-PQZ-41): on a token with the opening on, the public rollover
/// (`UAPqzRollOver`, `mtxRollOver`) is refused `ROLLOVER_SIGNED_ONLY`, zero sends (the token reverts `RollOverSignedOnly`; the
/// holder signs `mtxRollOverSigned`, row `PqzRollOver`); on an `OFFCHAIN` token a debit with auditor copies whose auditor has no
/// key of the token's scope is `AUDITOR_KEY_MISSING`, back in the queue (the auditor may register), before anything is sent.
async fn three_keys(chain: &Chain, w: &Work) -> Result<(), Refusal> {
    let Some(t) = w.typed.as_ref().filter(|t| t.contract == "pqz") else {
        return Ok(());
    };
    let rollover = w
        .data
        .get(..4)
        .and_then(|s| row(s.try_into().ok()?, "pqz"))
        .is_some_and(|r| r.name == "UAPqzRollOver");
    if !rollover && !t.pqz_auditor {
        return Ok(());
    }
    let tr = |what: &str, e: SimError| match e {
        SimError::Transport(e) => Refusal::Transport(format!("{what}: {e}")),
        SimError::Revert(e) => Refusal::Policy(format!("{what}: {e}")),
    };
    let (scope, opening) = crate::pqz::key_scope(chain, w.to)
        .await
        .map_err(|e| tr("pqzVerifyConfig()", e))?;
    if rollover && opening {
        return Err(Refusal::Policy(format!(
            "ROLLOVER_SIGNED_ONLY: {:#x} has the opening on: only its holder rolls over, by the \
            signed mtxRollOverSigned (row PqzRollOver); no public rollover there",
            w.to
        )));
    }
    let Some(scope) = scope.filter(|_| t.pqz_auditor) else {
        return Ok(());
    };
    let registry = chain
        .call_view(w.to, IUALedger::registryCall {})
        .await
        .map_err(|e| tr("registry()", e))?;
    let auditor = chain
        .call_view(w.to, IPqzToken::auditorUACall {})
        .await
        .map_err(|e| tr("auditorUA()", e))?;
    let k = chain
        .call_view(
            registry,
            IUARegistry::pqzScopedKeyOfCall { ua: auditor, scope },
        )
        .await
        .map_err(|e| tr("pqzScopedKeyOf", e))?;
    if k.ptr == Address::ZERO {
        return Err(Refusal::Transport(format!("AUDITOR_KEY_MISSING: the auditor {auditor:#x} of {:#x} has no key of scope {scope:#x} \
            (pqzScopedKeyOf): a debit with auditor copies cannot land until it registers one", w.to)));
    }
    Ok(())
}

/// Group 3g (spec §7.3): a PQZ debit's `ProofRejected` is `PQZ_KEY_ROTATED` only after an indexed `UAPqzKeyCurrent` of one of its
/// parties in the last `lookback` blocks (the event is evidence of the cause, not proof); `Ok(false)` for any other job.
pub async fn pqz_rotated(chain: &Chain, w: &Work, lookback: u64) -> anyhow::Result<bool> {
    let Some((registry, parties)) = pqz_parties(chain, w)
        .await
        .map_err(|e| anyhow::anyhow!("{e:?}"))?
    else {
        return Ok(false);
    };
    chain
        .pqz_key_current_since(registry, &parties, lookback)
        .await
}

/// Round 3t (CTR-PQZ-36, spec §10): a PQZ job's token emitted a `VerifierFeeSet` that moved the fee ([`fee_moves`]) in the last
/// `lookback` blocks (the event is
/// evidence of the cause of an `AuthRejected` / `PqzVerdictMismatch(3)`, not proof); `Ok(false)` for any other job.
pub async fn pqz_fee_changed(chain: &Chain, w: &Work, lookback: u64) -> anyhow::Result<bool> {
    if w.typed.as_ref().is_none_or(|t| t.contract != "pqz") {
        return Ok(false);
    }
    let logs = chain
        .logs_since(
            w.to,
            <IPqzToken::VerifierFeeSet as alloy::sol_types::SolEvent>::SIGNATURE_HASH,
            lookback,
        )
        .await?;
    Ok(fee_moves(&logs))
}

/// Fable 3r3s3t P3-4: a `VerifierFeeSet` moved the fee (`previous != next`); a cancel `(cur, cur)` moves nothing.
fn fee_moves(logs: &[alloy::rpc::types::Log]) -> bool {
    logs.iter().any(|l| {
        l.log_decode::<IPqzToken::VerifierFeeSet>()
            .is_ok_and(|e| e.inner.previous != e.inner.next)
    })
}

/// Group 3g: how far back a party's `UAPqzKeyCurrent` (and round 3t a token's `VerifierFeeSet`) counts as "since intake".
// ponytail: a fixed window, not the job's own intake block (the pull path carries none); a job older than this window that
// meets a rotation is reported `dead` with `ProofRejected`; use the job's claim block once the node's own queue carries it
pub const ROTATION_LOOKBACK: u64 = 10_000;

/// What a refused simulation of an EVM job means (NODE-LANE-09; Fable E N-1: one classifier for every runner of the EVM
/// contracts, the pipelined `Submitter` and the generic `lane_runner` (Hedera), so one rule on every chain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Done on chain: `Some(label)` is the job's error (`already_invalidated`, `LIQUIDITY_ORDER_CLOSED: …`); `None`: the subject's
    /// nonce is used, the runner labels by whom.
    Consumed(Option<String>),
    /// A refusal a later block may lift, by name: back in the queue, never `dead` while the op may still land.
    Requeue(String),
    /// Never sendable as named.
    Dead(String),
}

/// R80: `mtxNonce(from, batch) > nonce`: the meta-tx's subject nonce is used (by whom: `classify`). `Ok(false)` for a job without
/// an envelope. An RPC error is `Err`: no conclusion (fail closed).
pub async fn consumed(chain: &Chain, w: &Work) -> anyhow::Result<bool> {
    let Some(m) = &w.meta else { return Ok(false) };
    chain.nonce_spent(m).await
}

/// [`Verdict`] of a simulation (or the guard's build step) that refused `w` with `reason` (a `decode_revert` string or a named
/// refusal): a liquidity order already pulled, an invalidation in force or a used subject nonce are `consumed` (G6, MT-8, R80); a
/// PQZ debit over the lane's cap on a `LOG` token, a starved capability check, a regulated refusal (spec §7), a wrap limit
/// (group 3l), a liftable PQZ verdict refusal (group 3f), a fee word moved (round 3t), a rotated or unknown key version
/// (group 3g) are back in the queue by name; the job's own subject off a list, and anything else, `dead`.
pub async fn revert_verdict(chain: &Chain, w: &Work, reason: String) -> Verdict {
    use crate::abi::PqzRefusal;
    if reason.starts_with(LIQUIDITY_ORDER_CLOSED) {
        return Verdict::Consumed(Some(reason));
    }
    // NODE-JOB-29: an ML-DSA key's cache is incomplete; a part may still land (anyone may send it), so the job waits
    if reason.starts_with("UAKeyNotCached") {
        return Verdict::Requeue(format!("{UA_KEY_NOT_CACHED}: {reason}"));
    }
    // CTR-UA-65: the holding generation refuses the cache (its verifier has a precompile): the key's cache never completes
    if reason.starts_with("UAKeyCache") {
        return Verdict::Dead(format!("{UA_KEY_NOT_CACHEABLE}: {reason}"));
    }
    // Review Focus 5 (spec 2026-11-19-registry-verify-only-kinds §5, N13): a starved registry check is gas, never the job's
    // answer: a resend sized by a fresh simulation (up to `txGasCap`) may land, so the job waits
    if reason.starts_with("UAVerifyGas") {
        return Verdict::Requeue(format!("{UA_VERIFY_GAS}: {reason}"));
    }
    // NODE-JOB-24 (group 3h, pqz-proof-path spec §10): under `LOG` a holder of bit 24 may switch the token to `NONE` and the job
    // may land: `PROOF_STORE_OVER_LANE_CAP`, back in the queue; under `NONE`, or without the view, the plain refusal
    if over_cap(&reason) && crate::pqz::is_debit(w) {
        match chain.call_view(w.to, IPqzToken::proofStoreCall {}).await {
            Ok(m) if m == crate::abi::PROOF_STORE_LOG => {
                return Verdict::Requeue(format!("PROOF_STORE_OVER_LANE_CAP: {reason}"))
            }
            Ok(_) | Err(SimError::Revert(_)) => {}
            Err(SimError::Transport(e)) => {
                return Verdict::Requeue(format!("proofStore(): {e}; {reason}"))
            }
        }
    }
    // re-check P3 (spec §11): a starved T7 on a DEX the guard found marked is gas, not a wrong DEX
    if liquidity_starved(&w.data, &reason) {
        return Verdict::Requeue(format!(
            "simulate: {reason}: the tokens' capability check starved, retry"
        ));
    }
    if already_invalidated(&w.data, &reason) {
        return Verdict::Consumed(Some("already_invalidated".into()));
    }
    match consumed(chain, w).await {
        Ok(true) => return Verdict::Consumed(None),
        Ok(false) => {}
        Err(e) => return Verdict::Requeue(format!("mtxNonce: {e:#}")),
    }
    // round 3s (spec 2026-11-10-token-lists.md §9, Fable P3-8): the job's own subject off the allow list or on the deny list:
    // refused by name, not waiting as a liftable refusal
    if let Some(code) = w
        .meta
        .as_ref()
        .and_then(|m| crate::abi::own_list_refusal(&reason, m.from))
    {
        return Verdict::Dead(format!("{code}: {reason}"));
    }
    // D2-5 (CTR-CHAT-27 C9, CTR-CHAT-10, CTR-PQV-06): an exit applies at the head whenever it lands within `EXIT_LAG_MAX` of the
    // epoch it names, and anyone may land its public calldata; a refusal that a later head clears (the leaves owed, the named
    // epoch still incomplete) keeps the job queued. Past the lag the contract answers `PqChatExitLag` / `PqVaultExitLag`: dead.
    if let Some(r) = exit_wait(&w.data, &reason) {
        return Verdict::Requeue(r);
    }
    // regulated-kinds spec §7: a freeze, a pause, an eligibility or the registry may lift and the payload may still land
    if crate::abi::regulated_refusal(&reason).is_some() {
        return Verdict::Requeue(format!("REGULATED_REFUSED: {reason}"));
    }
    // group 3l (wrap limits spec §9): a window ends, a member is added, a redeemer is granted, a later wrap raises the entitlement
    if crate::abi::wrap_limit_refusal(&reason).is_some() {
        return Verdict::Requeue(format!("WRAP_LIMIT_REFUSED: {reason}"));
    }
    // round 3zc (CTR-GOV-30, spec 2026-11-13-burner-wrap-caps.md §4): a wrap or a mint above a cap (an unwrap or a cap change lifts
    // it), a cap setter before its `eta` (`GrantNotReady(31, …)`, the clock lifts it) or under a floor at its apply (supply or
    // the other setter lifts it); `MaxSupplyInvalid`, `MaxWrapSupplyInvalid` and `FeatureNotSet(31)` stay `dead` by name below
    if crate::abi::supply_cap_refusal(&reason).is_some_and(|(_, liftable)| liftable)
        || crate::abi::gov_word(&reason, "GrantNotReady", "bit") == Some(SUPPLY_CAP_ADJUSTABLE)
    {
        return Verdict::Requeue(format!("SUPPLY_CAP_REFUSED: {reason}"));
    }
    // set-auditor (spec §8, CTR-GOV-31): a bit-32 confirm before its proposal's `eta` lands once the clock reaches it (as a cap
    // setter's `GrantNotReady(31, …)`); every other auditor refusal stays `dead` by name below
    if reason.starts_with("AuditorNotReady") && auditor_op(&w.data) {
        return Verdict::Requeue(format!("AUDITOR_NOT_READY: {reason}"));
    }
    // round 3zb (CTR-GOV-29, spec §4; NODE-LANE-09's class): a burner's or a minter's grant window spent (`GrantExhausted(3)`):
    // the next window lifts it. Every other grant refusal (the job's own subject lacks the power) stays `dead` by name.
    if crate::abi::gov_word(&reason, "GrantExhausted", "field") == Some(GRANT_WINDOW)
        && window_op(&w.data)
    {
        return Verdict::Requeue(format!("GRANT_WINDOW_REFUSED: {reason}"));
    }
    // group 3f (spec §11.1): a PQZ verifier mode refusal by name, never `dead` while the op may land with another verdict; a
    // `PqzVerdictMismatch` after a party's indexed `UAPqzKeyCurrent` is `PQZ_KEY_ROTATED` (T55)
    if let Some((name, liftable)) = crate::abi::pqz_verdict_refusal(&reason) {
        if name == "PqzVerdictMismatch" {
            match pqz_rotated(chain, w, ROTATION_LOOKBACK).await {
                Ok(true) => return Verdict::Requeue(format!("PQZ_KEY_ROTATED: {reason}")),
                Ok(false) => {}
                Err(e) => {
                    return Verdict::Requeue(format!("PQZ_KEY_ROTATED read: {e:#}; {reason}"))
                }
            }
            // round 3t: field 3 (the statement) after an indexed `VerifierFeeSet`: the fee word moved
            if verdict_field(&reason) == Some(3) {
                if let Some(v) = fee_moved(chain, w, &reason).await {
                    return v;
                }
            }
        }
        return if liftable {
            Verdict::Requeue(format!("PQZ_VERDICT_REFUSED: {reason}"))
        } else {
            Verdict::Dead(reason)
        };
    }
    // round 3t (CTR-PQZ-36, spec §10): `AuthRejected` after an indexed `VerifierFeeSet` of its token is `PQZ_FEE_MISMATCH`, back
    // in the queue (a decrease may restore the word), never `dead`; without the event `dead`
    if reason.starts_with("AuthRejected") {
        return fee_moved(chain, w, &reason)
            .await
            .unwrap_or(Verdict::Dead(reason));
    }
    // NODE-JOB-28: the public rollover on an opening token never lands (the lease-time check names it first, `three_keys`)
    if reason.starts_with("RollOverSignedOnly") {
        return Verdict::Dead(format!("ROLLOVER_SIGNED_ONLY: {reason}"));
    }
    // group 3g (spec §7.3): a stale debit or two equal keys never land, a version above current may become current, a proof
    // built before a party's rotation is `PQZ_KEY_ROTATED`
    match crate::abi::pqz_refusal(&reason) {
        Some(PqzRefusal::Stale) => Verdict::Dead(format!("PQZ_KEY_STALE: {reason}")),
        Some(PqzRefusal::Reused) => Verdict::Dead(format!("PQZ_KEY_REUSED: {reason}")),
        Some(PqzRefusal::Unknown) => Verdict::Requeue(format!("PQZ_KEY_VERSION_UNKNOWN: {reason}")),
        Some(PqzRefusal::ProofRejected) => match pqz_rotated(chain, w, ROTATION_LOOKBACK).await {
            Ok(true) => Verdict::Requeue(format!("PQZ_KEY_ROTATED: {reason}")),
            Ok(false) => Verdict::Dead(reason),
            Err(e) => Verdict::Requeue(format!("PQZ_KEY_ROTATED read: {e:#}; {reason}")),
        },
        None => Verdict::Dead(reason),
    }
}

/// Governance bit 31 `SUPPLY_CAP_ADJUSTABLE` (CTR-GOV-30): its setters' pending refusal is `GrantNotReady(31, 0, eta)`.
const SUPPLY_CAP_ADJUSTABLE: u8 = 31;
/// `GrantExhausted`'s field 3: the grant's `perWindow` spent in the current window.
const GRANT_WINDOW: u8 = 3;

/// The router's bit-32 ops (CTR-GOV-31, set-auditor spec §8), by the job's selector: the only ones whose `AuditorNotReady` the
/// clock lifts (closing review C3; any other job carrying that error is `dead` by name).
fn auditor_op(data: &[u8]) -> bool {
    data.get(..4).is_some_and(|s| {
        typed::rows()
            .iter()
            .any(|r| matches!(r.name, "UASetAuditorKey" | "UASetAuditorUA") && r.sent[..] == *s)
    })
}

/// The proposal a bit-32 op names (closing review C2, set-auditor spec §13): its token, `pending` as `auditorState()` reads it
/// (`keccak256(newKey)`, or the new UA) and the proposer (the envelope's `from`); `None` for any other job.
pub fn auditor_proposal(data: &[u8]) -> Option<crate::store::AuditorHold> {
    use crate::abi::IAuditorRouter as R;
    let (token, pending, proposer) = if let Ok(c) = R::mtxSetAuditorKeyCall::abi_decode(data) {
        (c.target, alloy::primitives::keccak256(&c.newKey), c.e.from)
    } else {
        let c = R::mtxSetAuditorUACall::abi_decode(data).ok()?;
        (c.target, c.newAuditor, c.e.from)
    };
    Some(crate::store::AuditorHold {
        token: token.to_vec(),
        pending: pending.to_vec(),
        proposer: proposer.to_vec(),
    })
}

/// Closing review C2 (set-auditor spec §13): a held bit-32 confirm (its hold in the node store, C2b), read on chain before it is
/// sent again: `Some(true)` confirmable (`auditorState()` status 2 with the held `pending` and `proposer`), `Some(false)` still
/// waiting (status 1, the same), `None` gone (none, expired, void, another proposal): sent, the call would propose afresh
/// (§5.1), so the job is never sent.
pub async fn auditor_confirm(
    chain: &Chain,
    held: &crate::store::AuditorHold,
) -> Result<Option<bool>, SimError> {
    let Ok(token) = Address::try_from(&held.token[..]) else {
        return Ok(None);
    };
    let st = chain
        .call_view(token, crate::abi::IAuditorSetter::auditorStateCall {})
        .await?;
    Ok(
        match (
            st.status,
            st.pending[..] == held.pending[..] && st.proposer[..] == held.proposer[..],
        ) {
            (2, true) => Some(true),
            (1, true) => Some(false),
            _ => None,
        },
    )
}

/// The ops whose window refusal the next window lifts (spec 2026-11-13-burner-wrap-caps.md §4): a token's `mtxBurn` (bit 30) and
/// the router's `mtxMint`, `mtxMintToUA` (bit 1), by the job's selector.
fn window_op(data: &[u8]) -> bool {
    data.get(..4).is_some_and(|s| {
        typed::rows()
            .iter()
            .any(|r| matches!(r.name, "UABurn" | "UAMint" | "UAMintToUA") && r.sent[..] == *s)
    })
}

/// The `field` of a `decode_revert` string `PqzVerdictMismatch(PqzVerdictMismatch { field: N })`, parsed whole (Fable E N-11: never
/// a substring, so `field: 30` is not field 3).
fn verdict_field(reason: &str) -> Option<u8> {
    let rest = reason.split_once("field: ")?.1;
    rest[..rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len())]
        .parse()
        .ok()
}

/// Round 3t (CTR-PQZ-36, spec §10, T55's pattern): `PQZ_FEE_MISMATCH` when the job's token emitted a `VerifierFeeSet` that moved
/// the fee since intake (the `ROTATION_LOOKBACK` window; a cancel `(cur, cur)` is no move, Fable 3r3s3t P3-4); an unreadable log
/// is `PQZ_FEE_LOG_UNREAD`, back in the queue, never counted as a move.
async fn fee_moved(chain: &Chain, w: &Work, reason: &str) -> Option<Verdict> {
    match pqz_fee_changed(chain, w, ROTATION_LOOKBACK).await {
        Ok(true) => Some(Verdict::Requeue(format!(
            "PQZ_FEE_MISMATCH: {reason} after VerifierFeeSet"
        ))),
        Ok(false) => None,
        Err(e) => Some(Verdict::Requeue(format!(
            "PQZ_FEE_LOG_UNREAD: {e:#}; {reason}"
        ))),
    }
}

/// NODE-JOB-28 (spec 2026-11-13-pqz-three-keys §12): an op the connected chain cannot include, by its own limits (the block gas
/// limit bounds regular + state under EIP-8037; 2^24 regular gas per transaction, EIP-7825; the calldata floor, EIP-7976), is
/// refused by this name instead of sent. The operator's own `max_gas_per_tx` is not a chain limit and keeps its plain refusal.
pub const TX_EXCEEDS_CHAIN_LIMIT: &str = "TX_EXCEEDS_CHAIN_LIMIT";

/// D2-5: an exit job (a tree session's `treeLeave` / `treeRemove`, mode 0's `leave` / `remove`, PqVault's `leaveVault` /
/// `removeVaultMembers`) refused by a state a later head clears: queued under this name, never `dead` within the lag.
pub const EXIT_WAITING: &str = "EXIT_WAITING";
/// The refusals of an exit that a later head may clear (D2-5): the leaves owed at the head, the named epoch not complete yet.
const EXIT_WAITS: [&str; 3] = ["PqChatTreeBacklog", "PqChatIncomplete", "PqVaultIncomplete"];

/// D2-5: the requeue reason of an exit job refused by a state a later head clears; `None` for any other job or refusal.
pub fn exit_wait(data: &[u8], reason: &str) -> Option<String> {
    (exit_op(data) && EXIT_WAITS.iter().any(|p| reason.starts_with(p)))
        .then(|| format!("{EXIT_WAITING}: {reason}"))
}

/// `data` calls an exit entry of `PqChat` or `PqVault` (D2-5).
fn exit_op(data: &[u8]) -> bool {
    const EXITS: [&str; 6] = [
        "treeLeave",
        "treeRemove",
        "leave",
        "remove",
        "leaveVault",
        "removeVaultMembers",
    ];
    data.get(..4).is_some_and(|sel| {
        crate::typed::rows().iter().any(|r| {
            r.selector[..] == *sel
                && EXITS.contains(&r.entry)
                && r.contracts
                    .iter()
                    .any(|c| *c == "pqchat" || *c == "pqvault")
        })
    })
}

/// The refusal of a relayed PQ registration (`register` with its `R_REG` proof) whose gas estimate is over the
/// per-transaction cap ([`total_cap`]: `max_gas_per_tx`, the block gas limit) or that the chain's estimate refuses for
/// gas: the client splits it into `register` without `pqzPop`, then `storePqzPop` (ruling R-node).
pub const UA_REGISTER_SPLIT: &str = "UA_REGISTER_SPLIT";

/// `register` / `registerMsig` calldata with a non-empty `pqzPop`.
pub fn pq_register(data: &[u8]) -> bool {
    use alloy::sol_types::SolCall;
    crate::abi::IUARegistry::registerCall::abi_decode(data).is_ok_and(|c| !c.pqzPop.is_empty())
        || crate::abi::IUARegistry::registerMsigCall::abi_decode(data)
            .is_ok_and(|c| !c.pqzPop.is_empty())
}

/// NODE-JOB-29 (CTR-UA-23, owner 2026-11-15): a check of an ML-DSA key on a registry whose verifier of the kind has no precompile
/// reverts `UAKeyNotCached(ua)` until every part of the key's expanded-key cache is stored. The job waits under this name, `queued`,
/// never `dead`: anyone may send the parts (`cacheExpandedKey`), and for a `register` the lane sends them itself.
pub const UA_KEY_NOT_CACHED: &str = "UA_KEY_NOT_CACHED";

/// Review Focus 5 (CTR-UA-68, N13): a registry check starved of gas (`UAVerifyGas`): back in the queue, never `dead`, while a
/// resend with a fresh estimate may land.
pub const UA_VERIFY_GAS: &str = "UA_VERIFY_GAS";

/// CTR-UA-65 (F9): a registration (or `cacheExpandedKey`) of a kind sent to a generation where the kind is not registrable
/// (verify-only there, or not carried): refused before sending; the refusal names `kindHome(kind)`.
pub const UA_VERIFY_ONLY: &str = "UA_VERIFY_ONLY";
/// CTR-UA-65 (F9): a key write sent to a generation that does not hold the record, or a PQZ write sent elsewhere than the
/// record's PQZ home: refused before sending; the refusal names `holderOf(ua)` / `pqzHomeOf(ua)`.
pub const UA_WRONG_GENERATION: &str = "UA_WRONG_GENERATION";
/// NODE-JOB-29 (CTR-UA-65): the holding generation refuses the cache (`UAKeyCache`, its verifier has a precompile): a key that
/// waits for its cache never completes, `dead` under this name.
pub const UA_KEY_NOT_CACHEABLE: &str = "UA_KEY_NOT_CACHEABLE";

/// Where a registry write belongs on the line (CTR-UA-65).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineTarget {
    /// A registration or a cache part of `kind`: `kindHome(kind)`.
    Kind(u16),
    /// A key write held in the holding generation (`setKemKey`, `acceptMembership`, `updateMsig`): `holderOf(ua)`.
    Holder(B256),
    /// A write of the PQZ attachment (`setPqzKey`, `setPqzScopedKey`, `storePqzPop`, `storePqzScopedPop`): `pqzHomeOf(ua)`.
    PqzHome(B256),
}

/// The line target of a registry row's calldata; `None` for calldata that is no registry row.
pub fn line_target(data: &[u8]) -> Option<LineTarget> {
    use crate::abi::IUARegistry::*;
    use LineTarget::*;
    let sel: [u8; 4] = data.get(..4)?.try_into().ok()?;
    Some(match sel {
        registerCall::SELECTOR => Kind(registerCall::abi_decode(data).ok()?.kind),
        registerMuSig2Call::SELECTOR => Kind(registerMuSig2Call::abi_decode(data).ok()?.kind),
        registerFrostCall::SELECTOR => Kind(registerFrostCall::abi_decode(data).ok()?.kind),
        cacheExpandedKeyCall::SELECTOR => Kind(cacheExpandedKeyCall::abi_decode(data).ok()?.kind),
        // `msig` is registrable in every generation (re-enabled in full, spec §2): no line target, the contract decides; asking
        // the newest generation's `kindHome(0x0120)` refused every `registerMsig` to an older one (Task 21 review P2-5)
        registerMsigCall::SELECTOR => return None,
        registerWebAuthnCall::SELECTOR => Kind(0x0100),
        registerBlsMultiCall::SELECTOR => Kind(0x0121),
        setKemKeyCall::SELECTOR => Holder(setKemKeyCall::abi_decode(data).ok()?.ua),
        acceptMembershipCall::SELECTOR => Holder(acceptMembershipCall::abi_decode(data).ok()?.ua),
        updateMsigCall::SELECTOR => Holder(updateMsigCall::abi_decode(data).ok()?.ua),
        setPqzKeyCall::SELECTOR => PqzHome(setPqzKeyCall::abi_decode(data).ok()?.ua),
        setPqzScopedKeyCall::SELECTOR => PqzHome(setPqzScopedKeyCall::abi_decode(data).ok()?.ua),
        storePqzPopCall::SELECTOR => PqzHome(storePqzPopCall::abi_decode(data).ok()?.ua),
        storePqzScopedPopCall::SELECTOR => {
            PqzHome(storePqzScopedPopCall::abi_decode(data).ok()?.ua)
        }
        _ => return None,
    })
}

/// An ML-DSA kind's FIPS 204 public key length and its cache part count (`PqUA.mldsaParts`): mldsa44 1,312 B / 1 part, mldsa65
/// 1,952 B / 2, mldsa87 2,592 B / 3; `None` for every other kind (no cache).
pub fn mldsa_cache(kind: u16) -> Option<(usize, u64)> {
    match kind {
        0x0130 => Some((1312, 1)),
        0x0131 => Some((1952, 2)),
        0x0134 => Some((2592, 3)),
        _ => None,
    }
}

/// `(kind, pk)` of a `register` calldata whose key is an ML-DSA public key of its kind's length (NODE-JOB-29); `None` otherwise.
pub fn mldsa_register(data: &[u8]) -> Option<(u16, Bytes)> {
    use alloy::sol_types::SolCall;
    let c = crate::abi::IUARegistry::registerCall::abi_decode(data).ok()?;
    (mldsa_cache(c.kind)?.0 == c.keyData.len()).then_some((c.kind, c.keyData))
}

/// NODE-JOB-29 (owner O7, 2026-11-16): an ML-DSA `register` whose `pop` (or attributes) the off-chain check refuses is `dead` under
/// this name before the lane sends any cache part: the registry runs the same check once the key is cached, so it could never land.
pub const UA_REGISTER_POP_REFUSED: &str = "UA_REGISTER_POP_REFUSED";

/// `ua_portable::check_registration` on a `register` calldata (a single key, no `msig` members): what the registry checks at step 6 once
/// the key's cache is complete. An extra check; the contract stays the guard.
pub fn register_pop(data: &[u8]) -> Result<(), String> {
    use alloy::sol_types::SolCall;
    let c = crate::abi::IUARegistry::registerCall::abi_decode(data)
        .map_err(|e| format!("register calldata: {e}"))?;
    let a = scaas_ua::ua_portable::UAAttrs {
        pqz_key: c.attrs.pqzKey.to_vec(),
        pqz_pop_hash: c.attrs.pqzPopHash.0,
        kem: scaas_ua::ua_portable::KemKey {
            scheme: c.attrs.kem.scheme,
            mlkem_ek: c.attrs.kem.mlkemEk.to_vec(),
            x25519: c.attrs.kem.x25519.0,
        },
        kem_pk_hash: c.attrs.kemPkHash.0,
    };
    scaas_ua::ua_portable::check_registration(c.kind, &c.keyData, &a, &c.pop, &c.pqzPop, &|_| None)
        .map_err(|e| e.code().to_string())
}

/// The node's own cache part job (NODE-JOB-29): the named op `cacheExpandedKey {kind, pk, part}` on `registry`, built by the same
/// parser as every job's (`typed.rs`'s plain row), so the calldata comes from the named fields.
pub fn cache_part_op(
    registry: Address,
    kind: u16,
    pk: &[u8],
    part: u64,
    valid_until: u64,
) -> serde_json::Value {
    serde_json::json!({"entry": "cacheExpandedKey", "contract": "registry", "token": format!("{registry:#x}"),
        "args": {"kind": kind, "pk": format!("0x{}", alloy::hex::encode(pk)), "part": part.to_string()},
        "validUntil": valid_until.to_string()})
}

/// Forge's minimum relayer CALL gas of a `SmartKeyAccount`-signed `mtxExecute` after the split (the ERC-1271 call two
/// frames below the token: token → `MtxPipelineLib` → wallet, ≥ (400,000 · 64/63 + 5,000) · 64/63): 446,912
/// (`test_minGas_smartKeyAccountMtxExecute`; 446,904 at `smartcontracts/evm/runs/2026-10-27-metatx-split-node-floor.txt`,
/// Task 8; 446,912 with the ERC-7739 signature, B P3-2, 2026-11-12).
/// It is execution gas only (`call{gas: g}`): no intrinsic, no calldata.
pub const ERC1271_CALL_GAS: u64 = 446_912;

/// The gas floor of a contract signer's meta-tx whose calldata is `len` bytes (P1b note c; T17 fix 1): 21,000
/// intrinsic (pre-Amsterdam; EIP-2780 lowers it, which only grows the margin) + 64 gas per calldata byte (the EIP-7976
/// floor rate, the dearest calldata price, as `calldata_floor`) + `ERC1271_CALL_GAS` + 10 % of it (a larger proof or
/// key set grows the prefix). Entries get no floor (P5 review m6, closed): a starved `SigCheck` reverts
/// `SigCheckGasStarved`, so their estimate already covers the call.
pub fn erc1271_floor(len: usize) -> u64 {
    21_000 + 64 * len as u64 + ERC1271_CALL_GAS + ERC1271_CALL_GAS / 10
}

/// EIP-7825 under Amsterdam (EIP-8037): the cap on a transaction's REGULAR gas (intrinsic, calldata floor and
/// execution). State gas (new slots 97,920, code 1,530 per byte) comes on top, so the gas LIMIT may exceed it.
pub const MAX_TX_GAS: u64 = 1 << 24;
/// EIP-8037 `TX_MAX_TOTAL_GAS_LIMIT`: the largest gas limit (regular + state) a transaction may carry (Nethermind 2.2.0
/// `Eip8037Constants`, PR #13627).
pub const MAX_TX_TOTAL_GAS: u64 = u32::MAX as u64;

/// The EIP-7976 calldata floor of a call to another account, which counts as regular gas: 12,000 (EIP-2780) + 3,000
/// (cold recipient, EIP-8038) + 64 per calldata byte. Measured on the SCaaS testnet: a 220,415 B transaction paid exactly
/// 14,121,560 = 15,000 + 64 · 220,415, and every input over 261,909 B was refused at any gas limit
/// (`pqz-core/nethermind/runs/2026-10-21-glamsterdam-gas-impact.md`).
pub fn calldata_floor(len: usize) -> u64 {
    15_000 + 64 * len as u64
}

/// The gas limit cap of one transaction: `max_gas_per_tx`, the chain's block gas limit (EIP-8037 reserves `tx.gas` in
/// the block's state dimension: a larger limit is never included) and EIP-8037's 2^32 − 1; before Amsterdam EIP-7825's
/// 2^24 caps the whole limit.
pub fn total_cap(max_gas_per_tx: u64, block: BlockGas) -> u64 {
    let c = max_gas_per_tx.min(block.limit).min(MAX_TX_TOTAL_GAS);
    if block.amsterdam {
        c
    } else {
        c.min(MAX_TX_GAS)
    }
}

/// What the node knows of a `call` target.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Facts {
    pub token: bool,
    pub token_factory: bool,
    pub account_factory: bool,
    pub dex: bool,
    pub ua_registry: bool,
    /// One of `governance_routers`.
    pub gov_router: bool,
    /// `infoOf(target)`'s `(contractClass, version)` on `token_factory`, when made there (read for a factory class's rule only).
    pub listed: Option<(u16, u64)>,
    /// `chainUid()` equals this chain's (NODE-GW-07).
    pub bound: bool,
}

pub fn allowed(rule: Rule, f: &Facts) -> bool {
    if rule == Rule::Token {
        return f.bound && f.token;
    }
    if let Rule::FactoryClass(c) = rule {
        // the factory's record is the binding: an instance answers no `chainUid()`
        return matches!(f.listed, Some((k, v)) if k == c && v != 0)
            && !f.token
            && !f.token_factory
            && !f.gov_router;
    }
    f.bound
        && !f.token
        && !f.token_factory
        // a router takes its own rows and no other kind's: its allow-list is its typed table, both directions
        && (rule == Rule::GovRouter) == f.gov_router
        && match rule {
            Rule::Token => false,
            Rule::AccountFactory => f.account_factory,
            Rule::SelfAuth => true,
            Rule::Dex => f.dex,
            Rule::UaRegistry => f.ua_registry,
            Rule::GovRouter => true,
            Rule::FactoryClass(_) | Rule::ChatStore => false, // their own checks
        }
}

/// The chain's relay-fee router (CTR-MTX-27) and the node's policy for it (`params.relay_fee`, `RelayParams`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayFee {
    pub router: Address,
    /// `RelayFeeExecutor`: the router's first `CREATE` (constructor, nonce 1), so derived, never configured.
    pub executor: Address,
    pub params: crate::config::RelayParams,
    /// `relay_fee.min_wei_value = { "<token>" = wei per base unit }`: the node's floor price of a fee token.
    pub min_wei_value: HashMap<Address, Price>,
}

impl RelayFee {
    /// `None` without `params.relay_fee.router`; a router that is not an address is a startup error.
    pub fn from_cfg(cfg: &ChainCfg) -> anyhow::Result<Option<Self>> {
        let params = cfg.relay_params()?;
        let prices = cfg
            .params
            .get("relay_fee")
            .and_then(|t| t.get("min_wei_value"));
        let Some(r) = params.router.as_deref() else {
            // fix 1 (review minor 2): set but unusable is a startup error
            if prices.is_some() {
                anyhow::bail!(
                    "params.relay_fee.min_wei_value is set without params.relay_fee.router"
                );
            }
            return Ok(None);
        };
        let router = crate::metatx::addr(r)
            .map_err(|e| anyhow::anyhow!("params.relay_fee.router: {e:#}"))?;
        let mut min_wei_value = HashMap::new();
        if let Some(v) = prices {
            let table = v.as_table().ok_or_else(|| {
                anyhow::anyhow!("params.relay_fee.min_wei_value must be a table of token = wei")
            })?;
            for (k, n) in table {
                let token = crate::metatx::addr(k)
                    .map_err(|e| anyhow::anyhow!("params.relay_fee.min_wei_value.{k}: {e:#}"))?;
                let price = parse_price(n).ok_or_else(|| anyhow::anyhow!(
                    "params.relay_fee.min_wei_value.{k} must be a non-negative integer (wei per base unit) or \"<wei>/<10^k>\" \
                     (wei per 10^k base units), not {n}"))?;
                if min_wei_value.insert(token, price).is_some() {
                    anyhow::bail!("params.relay_fee.min_wei_value names token {token:#x} twice");
                }
            }
        }
        Ok(Some(Self {
            router,
            executor: router.create(1),
            params,
            min_wei_value,
        }))
    }
}

/// `min_wei_value`'s value: an integer or decimal string (wei per base unit), or `"<wei>/<per>"` with `per` a power of
/// ten (wei per `per` base units).
fn parse_price(n: &toml::Value) -> Option<Price> {
    let dec = |s: &str| {
        (!s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
            .then(|| s.parse::<u128>().ok())
            .flatten()
    };
    match n {
        toml::Value::Integer(i) => Some(Price {
            wei: u128::try_from(*i).ok()?,
            per: 1,
        }),
        toml::Value::String(s) => match s.split_once('/') {
            None => Some(Price {
                wei: dec(s)?,
                per: 1,
            }),
            Some((w, p)) => {
                let per = dec(p)?;
                let t = per.to_string();
                (t.starts_with('1') && t[1..].bytes().all(|b| b == b'0'))
                    .then_some(Price { wei: dec(w)?, per })
            }
        },
        _ => None,
    }
}

/// A relay-fee call (`relay`, CTR-MTX-27) with its payer and payee as ids.
struct RelayCall {
    target: Address,
    call: Bytes,
    token: Address,
    from: B256,
    payee: B256,
    value: alloy::primitives::U256,
    /// A derived payer (a UA's verify costs what its kind costs); a native id verifies as an EOA or ERC-1271 does.
    derived: bool,
}

fn relay_call(data: &[u8]) -> Option<RelayCall> {
    let c = IRelayFeeRouter::relayCall::abi_decode(data).ok()?;
    let derived = crate::metatx::native(&c.from).is_none();
    Some(RelayCall {
        target: c.target,
        call: c.callData,
        token: c.token,
        from: c.from,
        payee: c.payee,
        value: c.value,
        derived,
    })
}

/// The router rule on a relay fee's inner call (spec 2026-11-02-governance §12.7), both directions: a call on one of
/// `routers` is a `gov_router` row, and an entry only the router has runs only on one of `routers`.
pub fn relay_inner_ok(routers: &[Address], data: &[u8]) -> Result<(), String> {
    let Some(c) = relay_call(data) else {
        return Ok(());
    };
    let sel = c
        .call
        .get(..4)
        .map(|s| <[u8; 4]>::try_from(s).expect("4 bytes"));
    let on = |kind: &str| sel.is_some_and(|s| row(s, kind).is_some());
    let router_row = on("gov_router");
    let elsewhere = typed::rows()
        .iter()
        .flat_map(|r| r.contracts)
        .any(|k| *k != "gov_router" && on(k));
    match (routers.contains(&c.target), router_row) {
        (true, false) => Err(format!("CALL_TARGET_REFUSED: the relayed call on router {:#x} is no named entry of it", c.target)),
        (false, true) if !elsewhere => Err(format!("CALL_TARGET_REFUSED: a GovernanceRouter entry relayed to {:#x}, not one of governance_routers", c.target)),
        _ => Ok(()),
    }
}

/// NODE-LANE (CTR-MTX-27) intake of a `relay` call before any simulation: the target is the router; the fee
/// token is registered; the payee is never the executor (the router's own `_shape`, refused here before gas is spent; the
/// token's `RelayFee` struct binds the rest: from, target, callDataHash, payee, value, validUntil, relayer = the router); the
/// fee reaches this lane (open mode or bound to it) and is at least `min_amount`, else the job is refused unless
/// `relay_bound_payee` (a sponsored job). Returns the inner target, which must be bound to this chain. The gas side
/// is [`relay_fee_covers`], after the simulation.
pub fn relay_call_ok(
    rf: &RelayFee,
    lane: Address,
    to: Address,
    data: &[u8],
    registered: impl Fn(Address) -> bool,
) -> Result<Address, String> {
    if to != rf.router {
        return Err(format!(
            "CALL_TARGET_REFUSED: RelayFeeRouter.relay on {to:#x}, not params.relay_fee.router"
        ));
    }
    let c = relay_call(data).ok_or_else(|| "BAD_PAYLOAD: not a relay call".to_string())?;
    if !registered(c.token) {
        return Err(format!(
            "TOKEN_NOT_SERVED: {:#x} is not a registered token of this chain",
            c.token
        ));
    }
    if c.payee == rf.executor.into_word() {
        return Err("RELAY_FEE_SHAPE: the payee is the router's executor".into());
    }
    let amount = u128::try_from(c.value).unwrap_or(u128::MAX);
    crate::adapter::relay_fee_ours(
        c.payee == rf.router.into_word(),
        c.payee == lane.into_word(),
        amount,
        &rf.params,
    )
    .map_err(|e| format!("RELAY_FEE_REFUSED: {e}"))?;
    Ok(c.target)
}

/// The fee covers the lane's known cost (owner rule: the relayer never loses): a relay fee that reaches this lane must
/// be worth, at the token's `relay_fee.min_wei_value`, at least [`relay_quote`] of the simulated call. A derived payer's
/// verify costs what its kind costs (a P-256 passkey cap 0.4 M gas, a Solidity PQ verify 1.4–6 M), so its relay fee on a
/// token with no price is refused; a native payer (an EOA, padded) keeps T17's `min_amount` rule (owner ruling 2026-10-28,
/// item 7) unless its token has a price. A sponsored fee (bound elsewhere, `relay_bound_payee`) is not priced. Any other
/// call passes.
pub fn relay_fee_covers(
    rf: &RelayFee,
    lane: Address,
    data: &[u8],
    gas: u64,
    ceiling: u128,
    l1_fee: u128,
) -> Result<(), Refusal> {
    let Some((c, price)) = relay_price(rf, lane, data)? else {
        return Ok(());
    };
    let quote = relay_quote(gas, ceiling, l1_fee);
    let amount = u128::try_from(c.value).unwrap_or(u128::MAX);
    if !price_covers(&price, amount, quote) {
        // the quote follows the fees of the moment (review minor 3): a retry, never a kill
        return Err(Refusal::Transport(format!("RELAY_FEE_REFUSED: fee {amount} x min_wei_value {}/{} wei is below the quote \
            {quote} wei (gas limit {gas} x fee ceiling {ceiling} + {FEE_HEADROOM} x L1 fee {l1_fee})", price.wei, price.per)));
    }
    Ok(())
}

/// The relay-fee call and its token's price when the job is priced (the fee reaches this lane); `None` when it is not
/// (not a relay-fee call, a sponsored fee, a native payer on an unpriced token); a derived payer on an unpriced token is
/// refused.
fn relay_price(
    rf: &RelayFee,
    lane: Address,
    data: &[u8],
) -> Result<Option<(RelayCall, Price)>, Refusal> {
    let Some(c) = relay_call(data) else {
        return Ok(None);
    };
    if c.payee != rf.router.into_word() && c.payee != lane.into_word() {
        return Ok(None);
    }
    match rf.min_wei_value.get(&c.token).copied() {
        Some(p) => Ok(Some((c, p))),
        None if c.derived => Err(Refusal::Policy(format!(
            "RELAY_FEE_REFUSED: params.relay_fee.min_wei_value has no price for token \
            {:#x} (a derived payer's verify gas depends on its kind)",
            c.token
        ))),
        None => Ok(None),
    }
}

/// Fix 1 (review I1): a priced relay-fee job's fee ceiling is `FEE_HEADROOM` x the max fee per gas of its first send.
pub const FEE_HEADROOM: u128 = 2;

/// The OP-stack `GasPriceOracle` predeploy.
pub const GAS_PRICE_ORACLE: Address =
    alloy::primitives::address!("420000000000000000000000000000000000000F");

pub fn fee_ceiling(max_fee: u128) -> u128 {
    max_fee.saturating_mul(FEE_HEADROOM)
}

/// The lane's cost of a relay-fee job at most: its gas limit × its fee ceiling, plus `FEE_HEADROOM` × the L1 data fee
/// of an OP-stack chain (0 elsewhere; the L1 base fee moves as the L2 one does).
pub fn relay_quote(gas: u64, ceiling: u128, l1_fee: u128) -> u128 {
    u128::from(gas)
        .saturating_mul(ceiling)
        .saturating_add(l1_fee.saturating_mul(FEE_HEADROOM))
}

/// `relay_fee.min_wei_value`: `wei` per `per` base units (`per` a power of ten).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Price {
    pub wei: u128,
    pub per: u128,
}

/// `floor(amount × wei / per) >= quote`, exact (`amount × wei >= quote × per` in 256 bits).
pub fn price_covers(p: &Price, amount: u128, quote: u128) -> bool {
    use alloy::primitives::U256;
    U256::from(amount) * U256::from(p.wei) >= U256::from(quote) * U256::from(p.per)
}

/// The in-flight hold key of subject `id` on `token` (review I2).
pub fn subject_key(token: Address, id: B256) -> B256 {
    alloy::primitives::keccak256(
        [&b"scaas.node.subject"[..], token.as_slice(), id.as_slice()].concat(),
    )
}

/// The gas limit of a simulated estimate (regular + state): +20 %, at least `floor` (`erc1271_floor` for a contract signer),
/// at most `cap` ([`total_cap`]). Above 2^24 is fine under Amsterdam: the chain gives execution at most 2^24 of it and
/// the rest is the state-gas reservoir (EIP-8037).
pub fn gas_limit(estimate: u64, floor: u64, cap: u64) -> u64 {
    estimate.saturating_add(estimate / 5).max(floor).min(cap)
}

/// `mtxSettle` returned `ok` for every settlement it was given.
pub fn settled_all(ret: &[u8]) -> bool {
    <Vec<bool> as SolValue>::abi_decode(ret).is_ok_and(|v| !v.is_empty() && v.iter().all(|x| *x))
}

/// A failed plan's revert data that means "out of gas": empty, or an `InteractionFailed` whose inner reason is empty
/// (an interaction that ran out of gas inside a later batch plan surfaces wrapped, not as an empty revert).
pub fn reason_is_out_of_gas(data: &[u8]) -> bool {
    use crate::abi::ISCaaSDex::InteractionFailed;
    data.is_empty()
        || <InteractionFailed as alloy::sol_types::SolError>::abi_decode(data)
            .is_ok_and(|e| e.reason.is_empty())
}

/// `ILiquidityPullToken`'s ERC-165 id: the selector of `mtxLiquidityPull` (CTR-DEX-30).
pub const LIQUIDITY_PULL_ID: [u8; 4] = [0x85, 0xfd, 0xfd, 0x38];
/// The liquidity module's group (`SCaaSDexCore.GROUP_LIQUIDITY`).
pub const GROUP_LIQUIDITY: u8 = 11;
/// A liquidity plan's work beside its verifies (spec §13: the plan's base): what the budget check adds to the caps.
pub const LIQUIDITY_BASE_GAS: u64 = 1_000_000;

/// The liquidity mark (spec §11, review P1-2 (b)): a module of group 11 among a DEX's `modules()`.
pub fn liquidity_marked(groups: &[u8]) -> bool {
    groups.contains(&GROUP_LIQUIDITY)
}

/// A kind's verify cap (CTR-DEX-26's table); `None` for a kind the table does not name (the simulation decides).
pub fn verify_cap(kind: u16) -> Option<u64> {
    Some(match kind {
        0x0131 => 5_950_000, // mldsa65 (cached key)
        0x0130 => 4_250_000, // mldsa44 (cached key)
        0x0132 => 2_500_000, // fndsa512
        0x0133 => 1_400_000, // slhdsa128s
        0x0102 => 210_000,   // ed25519
        // p256, webauthn-p256: the registry's cap (DeployBase), CTR-DEX-26's row (owner 2026-11-10; was the classical 50,000)
        0x0101 | 0x0100 => 400_000,
        // the classical row (CTR-DEX-26, <= 50,000): bip340, secp256k1 (L6d; the deploy's cap), a native id
        0x0103 | 0x0108 | 0 => 50_000,
        _ => return None,
    })
}

/// `LIQUIDITY_TOO_LARGE` (spec §11, §13): every SCaaS input verifies the same signature once, so the plan needs the signer's
/// cap times the SCaaS inputs plus its base within `budget` (min of the lane's `max_gas_per_tx` and the chain's block limit).
pub fn liquidity_too_large(scaas_inputs: u64, kind: u16, budget: u64) -> Option<String> {
    let need = verify_cap(kind)?
        .saturating_mul(scaas_inputs)
        .saturating_add(LIQUIDITY_BASE_GAS);
    (need > budget).then(|| format!("LIQUIDITY_TOO_LARGE: {scaas_inputs} SCaaS inputs of kind 0x{kind:04x} need about {need} gas, \
        above {budget}: split the order"))
}

/// A simulation of `mtxLiquidity` that reverts `NotLiquidityDex(dex)` on a DEX the guard found marked is a token's capability
/// check starved of gas (re-check P3), not a wrong DEX: the job is requeued, never dead.
pub fn liquidity_starved(data: &[u8], reason: &str) -> bool {
    data.get(..4) == Some(&ISCaaSDex::mtxLiquidityCall::SELECTOR[..])
        && reason.starts_with("NotLiquidityDex(")
}

/// The refusal of a liquidity order the DEX already pulled (`pulled(h) != 0`): it landed, here or by another relayer, so the
/// submitter reports it `consumed`, never `dead` (G6; spec §11 "completion and state").
pub const LIQUIDITY_ORDER_CLOSED: &str = "LIQUIDITY_ORDER_CLOSED";

/// The pre-checks of a `mtxLiquidity` job before simulation (spec 2026-11-10-dex-liquidity.md §11): the DEX's liquidity mark
/// (`DEX_NOT_LIQUIDITY`); `relayer` 0 or this lane (`LIQUIDITY_WRONG_RELAYER`); the node's `h` equal to the DEX's
/// `liquidityOrderDigest` (`LIQUIDITY_DIGEST_MISMATCH`); a native signer's signature over `h` (`BAD_SIGNATURE`, CTR-UA-24: an
/// account without code signs with its own key, a contract's ERC-1271 is the simulation's, as [`Guard::check_signature`]);
/// `pulled(h) == 0` ([`LIQUIDITY_ORDER_CLOSED`]); each SCaaS input's `ILiquidityPullToken` (`LIQUIDITY_TOKEN_UNSUPPORTED`: a
/// token of an earlier release); the verify budget within min(`max_gas_per_tx`, the block gas limit) (`LIQUIDITY_TOO_LARGE`).
/// The signed `validUntil` narrows the job's deadline (`typed.rs`), which the lane checks before simulation. A transport
/// error is a retry; a token's read that reverts is the answer "no".
// ponytail: reads per job, no cache; cache the mark per DEX if the reads show up in the lane's latency
/// Owner 2026-11-12 (`mtxCreateInstance`): the release `(contractClass, kind, version)` is published on the factory (`target`) and
/// not deprecated, read with `classReleaseOf` before the simulation; refused by name (`dead`), an unread answer back in the queue.
async fn check_release(chain: &Chain, row: &typed::Row, data: &[u8]) -> Result<(), Refusal> {
    let bad = |e: anyhow::Error| Refusal::Policy(format!("{e:#}"));
    let v = typed::call_values(row, data).map_err(bad)?;
    let n = |i: usize| {
        v.get(i)
            .and_then(|x| x.as_uint())
            .map_or(0, |(u, _)| u.to::<u64>())
    };
    let factory = v.get(1).and_then(|x| x.as_address()).unwrap_or_default();
    let (c, k, ver) = (n(2) as u16, n(3) as u16, n(4));
    let id = IOpenFactory::ReleaseId {
        contractClass: c,
        kind: k,
        version: ver,
    };
    let r = chain
        .call_view(factory, IOpenFactory::classReleaseOfCall { id })
        .await
        .map_err(|e| match e {
            SimError::Revert(r) => Refusal::Policy(format!(
                "RELEASE_UNKNOWN: class {c} kind {k} version {ver}: the factory {factory:#x} \
            answers no release ({r})"
            )),
            SimError::Transport(t) => Refusal::Transport(format!(
                "release of class {c} kind {k} version {ver} unread: {t}"
            )),
        })?;
    if r.implementation.is_zero() {
        return Err(Refusal::Policy(format!(
            "RELEASE_UNKNOWN: class {c} kind {k} version {ver} is not published on {factory:#x}"
        )));
    }
    if r.deprecated {
        return Err(Refusal::Policy(format!(
            "RELEASE_DEPRECATED: class {c} kind {k} version {ver} on {factory:#x}"
        )));
    }
    Ok(())
}

async fn check_liquidity(chain: &Chain, w: &Work, max_gas_per_tx: u64) -> Result<(), Refusal> {
    let policy = |m: String| Refusal::Policy(m);
    let call = <ISCaaSDex::mtxLiquidityCall as SolCall>::abi_decode(&w.data)
        .map_err(|e| policy(format!("BAD_PAYLOAD: mtxLiquidity: {e}")))?;
    let read = |e: SimError| match e {
        SimError::Transport(m) => Err(Refusal::Transport(m)),
        SimError::Revert(_) => Ok(()),
    };
    let mut groups = vec![];
    match chain.call_view(w.to, ISCaaSDex::modulesCall {}).await {
        Ok(ms) => {
            for m in ms {
                match chain.call_view(m, IModuleGroup::moduleGroupCall {}).await {
                    Ok(g) => groups.push(g),
                    Err(e) => read(e)?,
                }
            }
        }
        Err(e) => read(e)?,
    }
    if !liquidity_marked(&groups) {
        return Err(policy(format!(
            "DEX_NOT_LIQUIDITY: {:#x} has no liquidity module (group 11 among its modules())",
            w.to
        )));
    }
    let o = &call.p.order;
    if o.relayer != Address::ZERO && o.relayer != chain.address() {
        return Err(policy(format!(
            "LIQUIDITY_WRONG_RELAYER: the order is bound to {:#x}, not this lane {:#x}",
            o.relayer,
            chain.address()
        )));
    }
    let uid = chain
        .uid()
        .await
        .map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
    let h = crate::dex::liquidity_order_hash(
        &crate::dex::domain("SCaaS Dex", chain.number, w.to, uid),
        o,
    );
    match chain.call_view(w.to, ISCaaSDex::liquidityOrderDigestCall { o: o.clone() }).await {
        Ok(d) if d == h => {}
        Ok(d) => return Err(policy(format!("LIQUIDITY_DIGEST_MISMATCH: the DEX's liquidityOrderDigest {d:#x} is not the node's h {h:#x}"))),
        Err(SimError::Revert(m)) => return Err(policy(format!("LIQUIDITY_DIGEST_MISMATCH: liquidityOrderDigest reverts ({m})"))),
        Err(SimError::Transport(m)) => return Err(Refusal::Transport(m)),
    }
    let a = &call.p.auth;
    if let Some(who) = crate::metatx::native(&o.from)
        .filter(|_| a.keyData.is_empty() && a.members.is_empty() && a.signature.len() == 65)
    {
        if !typed::recovers(h, &a.signature, who) {
            match chain.is_contract_at(who).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(policy(format!(
                        "BAD_SIGNATURE: not {who:#x}'s over the liquidity order {h:#x}"
                    )))
                }
                Err(e) => return Err(Refusal::Transport(format!("eth_getCode: {e:#}"))),
            }
        }
    }
    match chain
        .call_view(w.to, ISCaaSDex::pulledCall { orderHash: h })
        .await
    {
        Ok(n) if n.is_zero() => {}
        Ok(_) => {
            return Err(policy(format!(
                "{LIQUIDITY_ORDER_CLOSED}: the DEX pulled the order {h:#x} already (consumed)"
            )))
        }
        Err(SimError::Revert(m)) => return Err(policy(m)),
        Err(SimError::Transport(m)) => return Err(Refusal::Transport(m)),
    }
    // CTR-DEX-32: an input is SCaaS iff the DEX's factory made it (`versionOf`), never the DEX's `tokenKind` (0 for a token of
    // a pair never listed) and never a deprecation
    let sim = |e: SimError| match e {
        SimError::Transport(m) => Refusal::Transport(m),
        SimError::Revert(m) => policy(m),
    };
    let factory = chain
        .call_view(w.to, ISCaaSDex::factoryCall {})
        .await
        .map_err(sim)?;
    let mut scaas = vec![];
    for t in &o.inputs {
        if crate::dex::kind_by_factory(chain, factory, t.token)
            .await
            .map_err(sim)?
            != crate::dex::KIND_SCAAS
        {
            continue;
        }
        let ok = match chain
            .call_view(
                t.token,
                IERC165::supportsInterfaceCall {
                    id: LIQUIDITY_PULL_ID.into(),
                },
            )
            .await
        {
            Ok(b) => b,
            Err(e) => {
                read(e)?;
                false
            }
        };
        if !ok {
            return Err(policy(format!(
                "LIQUIDITY_TOKEN_UNSUPPORTED: {:#x} answers no ILiquidityPullToken (a token of an \
                earlier release cannot be a liquidity input)",
                t.token
            )));
        }
        scaas.push(t.token);
    }
    let Some(first) = scaas.first() else {
        return Ok(());
    };
    let kind = if crate::metatx::native(&o.from).is_some() {
        0
    } else {
        let reg = chain
            .call_view(*first, IUALedger::registryCall {})
            .await
            .map_err(|e| match e {
                SimError::Transport(m) => Refusal::Transport(m),
                SimError::Revert(m) => policy(m),
            })?;
        match chain
            .call_view(reg, IUAKindOf::kindOfCall { ua: o.from })
            .await
        {
            Ok(k) => k,
            Err(e) => {
                read(e)?;
                return Ok(()); // the simulation names it
            }
        }
    };
    let block = chain
        .block_gas()
        .await
        .map_err(|e| Refusal::Transport(format!("block gas limit: {e:#}")))?;
    // the lane's per-transaction cap and the chain's block, never a fixed 2^24 (EIP-7825 is not on every chain); the config
    // always carries `max_gas_per_tx` (its serde default, config.rs), so no block-only fallback is needed
    match liquidity_too_large(scaas.len() as u64, kind, max_gas_per_tx.min(block.limit)) {
        Some(m) => Err(policy(m)),
        None => Ok(()),
    }
}

/// The next gas to try for `mtxSettle`: ×1.5, capped at `max`; `None` once at the cap.
pub fn next_gas(g: u64, max: u64) -> Option<u64> {
    (g < max).then(|| g.saturating_add(g / 2).min(max))
}

/// `mtxInvalidateNonces` (token or DEX) whose simulation says the lane is already at or past the asked minimum
/// (`MinNonceNotIncreasing`): what it was sent for already holds, so the job is done, never dead (MT-8).
pub fn already_invalidated(data: &[u8], reason: &str) -> bool {
    let sel = data.get(..4);
    (sel == Some(&SEL_MTX_INVALIDATE_NONCES[..]) || sel == Some(&SEL_TOKEN_INVALIDATE_NONCES[..]))
        && reason.starts_with("MinNonceNotIncreasing(")
}

/// Why the guard refused: a rule (the job is dead with this reason) or an unreadable chain (try again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    Policy(String),
    Transport(String),
}

impl From<Refusal> for SimError {
    fn from(r: Refusal) -> Self {
        match r {
            Refusal::Policy(s) => SimError::Revert(s),
            Refusal::Transport(s) => SimError::Transport(s),
        }
    }
}

/// The chain reads behind the rules, cached: implementations are immutable, so a contract's `chainUid()` never changes
/// (a contract that is not bound yet is asked again).
pub struct Guard {
    pub tokens: Arc<RwLock<Vec<Address>>>,
    /// The lane's `max_gas_per_tx` (a liquidity plan's verify budget, spec §11).
    max_gas_per_tx: u64,
    relay_fee: Option<RelayFee>,
    max_pay_meta_bytes: usize,
    token_factory: Option<Address>,
    account_factory: Option<Address>,
    /// The registry line in generation order (CTR-UA-65; ordered at start by [`crate::config::read_ua_line`]).
    ua_registries: Vec<Address>,
    dexes: Vec<Address>,
    gov_routers: Vec<Address>,
    bound: Mutex<HashSet<Address>>,
    /// `token_factory`'s records read ([`Guard::listed`]): a record never changes once made.
    listed: Mutex<HashMap<Address, (u16, u64)>>,
    /// `params.relay_unsigned_pqchat` (default false): the lane relays `PqChat`'s unsigned writes at its own gas (UA-7 P17).
    relay_unsigned_pqchat: bool,
    /// `params.relay_unsigned_pqvault` (default false): the lane relays `PqVault`'s unsigned `addVaultWraps` at its own gas
    /// (CTR-PQV-11).
    relay_unsigned_pqvault: bool,
    /// NODE-GW-09: `params.relay_pqchat_topics` (default true on a `private` chain, false on a `public` one, NODE-GW-01 (c)):
    /// door A takes the six `PqChat` topic records, fee 0.
    relay_pqchat_topics: bool,
    /// NODE-GW-09: `params.pqchat_topics_per_hour` (default 60, NODE-GW-01 (d)): the topic records door A takes per signing
    /// key per hour.
    pqchat_topics_per_hour: u32,
    /// The topic records taken this hour: per signing key `(hour, count)`, and each call's hash with its hour (a duplicate is
    /// answered queued, never queued twice). In memory.
    topic_intake: Mutex<TopicIntake>,
    /// The runtime code hash a `pqchatstore` target must have ([`PQCHATSTORE_RUNTIME_HASH`]).
    chatstore_code_hash: B256,
    /// The one `pqchatstore` target ([`PQCHATSTORE_ADDRESS`]).
    chatstore_address: Address,
    /// How long a pass is kept ([`CHATSTORE_RECHECK`]).
    chatstore_recheck: std::time::Duration,
    /// The last pass ([`Guard::require_chatstore`]): when, and the final block (number, hash) its code was read at.
    chatstores: Mutex<HashMap<Address, (std::time::Instant, u64, B256)>>,
    /// Tokens whose UA ledger is on (`registry() ≠ 0`).
    ua_ledger: Mutex<HashSet<Address>>,
    /// A token's `eip712Domain().name` (an immutable of its kind), read once ([`Guard::require_kind`]).
    domain_names: Mutex<HashMap<Address, String>>,
    /// `params.l1_fee = "op-stack"`: relay-fee quotes add `GasPriceOracle.getL1Fee`.
    op_stack: bool,
    /// Group 3f: the PQZ verifier mode's verdict fill and shield switch (`[pqz_verifier]`), one rule on every path.
    pqz: crate::pqz::Verifier,
    /// Proposed NODE-JOB-25: the configured services' entries (`[[chains.services]]`), what a job is built from.
    svc: crate::service::Types,
    /// The same services as read from the chain at startup ([`Guard::load_services`]): entries equal both ways, domain.
    services: RwLock<HashMap<Address, Arc<crate::service::Service>>>,
}

/// NODE-GW-09's intake memory: per signing key `(hour, count)`, per call hash its hour.
type TopicIntake = (HashMap<B256, (u64, u32)>, HashMap<B256, u64>);

impl Guard {
    pub fn new(cfg: &ChainCfg, tokens: Arc<RwLock<Vec<Address>>>) -> anyhow::Result<Self> {
        Ok(Self {
            relay_fee: RelayFee::from_cfg(cfg)?,
            max_gas_per_tx: cfg.max_gas_per_tx,
            max_pay_meta_bytes: cfg.relay_params()?.max_pay_meta_bytes,
            tokens,
            token_factory: cfg.token_factory,
            account_factory: cfg.account_factory,
            ua_registries: cfg.ua_registries.clone(),
            dexes: cfg.dex.into_iter().collect(),
            gov_routers: cfg.governance_routers.clone(),
            bound: Default::default(),
            listed: Default::default(),
            relay_unsigned_pqchat: match cfg.params.get("relay_unsigned_pqchat") {
                None => false,
                Some(toml::Value::Boolean(b)) => *b,
                Some(v) => anyhow::bail!("params.relay_unsigned_pqchat must be a bool (relay PqChat's unsigned storeMessage / addWraps \
                    at the lane's gas), not {v}"),
            },
            relay_unsigned_pqvault: match cfg.params.get("relay_unsigned_pqvault") {
                None => false,
                Some(toml::Value::Boolean(b)) => *b,
                Some(v) => anyhow::bail!("params.relay_unsigned_pqvault must be a bool (relay PqVault's unsigned addVaultWraps \
                    at the lane's gas), not {v}"),
            },
            relay_pqchat_topics: match cfg.params.get("relay_pqchat_topics") {
                None => cfg.profile == "private",
                Some(toml::Value::Boolean(b)) => *b,
                Some(v) => anyhow::bail!("params.relay_pqchat_topics must be a bool (door A takes PqChat's six topic records, \
                    fee 0), not {v}"),
            },
            pqchat_topics_per_hour: match cfg.params.get("pqchat_topics_per_hour") {
                None => 60,
                Some(toml::Value::Integer(n)) if (0..=i64::from(u32::MAX)).contains(n) => *n as u32,
                Some(v) => anyhow::bail!("params.pqchat_topics_per_hour must be a whole number (topic records per signing key \
                    per hour at door A), not {v}"),
            },
            topic_intake: Default::default(),
            chatstore_code_hash: *PQCHATSTORE_RUNTIME_HASH,
            chatstore_address: *PQCHATSTORE_ADDRESS,
            chatstore_recheck: CHATSTORE_RECHECK,
            chatstores: Default::default(),
            ua_ledger: Default::default(),
            domain_names: Default::default(),
            op_stack: match cfg.params.get("l1_fee") {
                None => false,
                Some(v) if v.as_str() == Some("op-stack") => true,
                Some(v) => anyhow::bail!("params.l1_fee must be \"op-stack\" (the chain charges an OP-stack L1 data fee), not {v}"),
            },
            pqz: crate::pqz::Verifier::new(&cfg.pqz_verifier)?,
            svc: crate::service::Types::from_cfg(&cfg.services, cfg.relay_params()?.max_service_op_bytes)?,
            services: Default::default(),
        })
    }

    /// NODE-GW-09's intake of a `PqChat` topic record at door A, before the guard and the simulation (`take`: false) and
    /// once it is queued (`take`: true, which counts it): the operator's switch (`PQCHAT_TOPICS_NOT_RELAYED`), the signing
    /// key's hourly bucket (`PQCHAT_TOPICS_RATE`; the key is `sig.keyData`, a single key's UA being its hash), and the call
    /// already queued this hour (`Ok(false)`: answered queued, not queued again). `now` in seconds.
    pub fn topic_intake(
        &self,
        op: &serde_json::Value,
        data: &[u8],
        now: u64,
        take: bool,
    ) -> Result<bool, String> {
        if !self.relay_pqchat_topics {
            return Err("PQCHAT_TOPICS_NOT_RELAYED: this node does not relay PqChat topic records on this chain \
                (params.relay_pqchat_topics); send it from the payer's own account"
                .into());
        }
        let key = op
            .pointer("/args/sig/keyData")
            .and_then(serde_json::Value::as_str)
            .ok_or("BAD_PAYLOAD: args.sig.keyData")?;
        let (key, call) = (
            alloy::primitives::keccak256(key.to_ascii_lowercase().as_bytes()),
            alloy::primitives::keccak256(data),
        );
        let hour = now / 3600;
        let mut g = self
            .topic_intake
            .lock()
            .map_err(|_| "PQCHAT_TOPICS_RATE: intake unavailable".to_string())?;
        let (keys, calls) = &mut *g;
        keys.retain(|_, (h, _)| *h == hour);
        calls.retain(|_, h| *h == hour);
        if calls.contains_key(&call) {
            return Ok(false);
        }
        let n = keys.entry(key).or_insert((hour, 0));
        if n.1 >= self.pqchat_topics_per_hour {
            return Err(format!(
                "PQCHAT_TOPICS_RATE: {} topic records this hour from this key (params.pqchat_topics_per_hour)",
                n.1
            ));
        }
        if take {
            n.1 += 1;
            calls.insert(call, hour);
        }
        Ok(true)
    }

    /// A job's `Work`, with this chain's services ([`crate::submit::work_from_job_with`]).
    pub fn work(
        &self,
        job: &crate::external_pull::Job,
        fee_recipient: Option<Address>,
    ) -> anyhow::Result<Work> {
        crate::submit::work_from_job_with(job, fee_recipient, &self.svc)
    }

    /// Proposed NODE-JOB-25, at startup: every configured service's `servicePullEntries()` equals its config, both
    /// directions, and its `eip712Domain()` is on this chain; otherwise `SERVICE_ENTRIES_MISMATCH` stops the lane.
    pub async fn load_services(&self, chain: &Chain) -> anyhow::Result<()> {
        for (s, entries) in &self.svc.entries {
            let svc = crate::service::load(chain, *s, entries).await?;
            if let Ok(mut m) = self.services.write() {
                m.insert(*s, Arc::new(svc));
            }
        }
        Ok(())
    }

    /// A configured service: one kind per address, so no other kind's row runs on it.
    fn is_service(&self, a: Address) -> bool {
        self.svc.entries.contains_key(&a)
    }

    /// The service rule (proposed NODE-JOB-25) on a call of `data` to the service `s`, direct or a relay fee's inner call:
    /// a service read at startup, no registered token at its address, one of its entries in canonical encoding, §3.3 steps
    /// 1-4, the pull token the contract's (`SERVICE_TOKEN_MISMATCH` against the job's `pullToken`), registered, bound,
    /// with its UA ledger for a derived payer, and the payer's native signature over the pull in that token's domain.
    async fn check_service(
        &self,
        chain: &Chain,
        s: Address,
        data: &[u8],
        job_token: Option<Address>,
    ) -> Result<(), Refusal> {
        let refused = |why: String| Refusal::Policy(why);
        let Some(svc) = self.services.read().ok().and_then(|m| m.get(&s).cloned()) else {
            return Err(refused(format!(
                "CALL_TARGET_REFUSED: {s:#x} is no service read at startup"
            )));
        };
        if self.registered(s) {
            return Err(refused(format!("CALL_TARGET_REFUSED: service {s:#x} is also a registered token (one kind per address)")));
        }
        let d = crate::service::decode(&svc.entries, data).ok_or_else(|| {
            refused(format!(
                "CALL_TARGET_REFUSED: the call on service {s:#x} is no entry of it"
            ))
        })?;
        let pull = crate::service::shape(&svc, &d).map_err(Refusal::Policy)?;
        if job_token.is_some_and(|j| j != pull) {
            return Err(refused(format!("SERVICE_TOKEN_MISMATCH: the job's pullToken is not {pull:#x}, the token the service pulls")));
        }
        if !self.registered(pull) {
            return Err(Self::not_served(pull));
        }
        self.require_bound(chain, pull).await?;
        if crate::metatx::native(&d.t.from).is_none() {
            self.require_ua_ledger(chain, pull).await?;
        }
        let Some(who) = crate::metatx::native(&d.t.from)
            .filter(|_| d.auth.keyData.is_empty() && d.auth.members.is_empty())
        else {
            return Ok(());
        };
        if d.auth.signature.len() != 65 {
            return Ok(()); // a 64-byte Hedera signature, a contract's: the token's
        }
        let digest = pull_digest(
            chain,
            pull,
            crate::metatx::UaMtx::Transfer(d.t.clone()).struct_hash(),
        )
        .await?;
        if typed::recovers(digest, &d.auth.signature, who) {
            return Ok(());
        }
        match chain.is_contract_at(who).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(refused(format!(
                "BAD_SIGNATURE: not {who:#x}'s over the pull {digest:#x}"
            ))),
            Err(e) => Err(Refusal::Transport(format!("eth_getCode: {e:#}"))),
        }
    }

    /// The chain's `RelayFeeRouter` (`params.relay_fee.router`), if any.
    pub fn router(&self) -> Option<Address> {
        self.relay_fee.as_ref().map(|r| r.router)
    }

    /// A token of the chain's registered list (refreshed from the client, review T4 m1); an unreadable list is none.
    fn registered(&self, a: Address) -> bool {
        self.tokens.read().is_ok_and(|t| t.contains(&a))
    }

    pub async fn check(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        if w.entry {
            self.check_named(chain, w).await?;
        } else if let Some(r) = &w.meta {
            self.check_transfer(chain, w, r.ua).await?;
        } else {
            return Err(Refusal::Policy(
                "CALL_TARGET_REFUSED: not a named entry".into(),
            ));
        }
        self.check_signature(chain, w).await
    }

    fn not_served(to: Address) -> Refusal {
        Refusal::Policy(format!(
            "TOKEN_NOT_SERVED: {to:#x} is not a registered token of this chain"
        ))
    }

    /// CTR-MTX-27: never pay the router or its executor outside a relay (the coins would sit where any relay can move
    /// them, or nowhere).
    fn check_payee(&self, payee: Option<B256>) -> Result<(), Refusal> {
        if let (Some(to), Some(rf)) = (payee, &self.relay_fee) {
            if to == rf.router.into_word() || to == rf.executor.into_word() {
                return Err(Refusal::Policy(format!(
                    "PAYEE_REFUSED: a plain pay to the relay-fee router / executor {to:#x}"
                )));
            }
        }
        Ok(())
    }

    /// A transfer struct (review T4 I1): a registered token; one with a derived `from` or `to` needs the token's UA ledger on
    /// (R44); an all-native one runs at `registry() == 0` (R9, C).
    async fn check_transfer(&self, chain: &Chain, w: &Work, ua: bool) -> Result<(), Refusal> {
        if !self.registered(w.to) {
            return Err(Self::not_served(w.to));
        }
        let payee = if ua {
            match UaMtx::from_calldata(&w.data) {
                Some((UaMtx::Transfer(t), _)) => Some(t.to),
                _ => None,
            }
        } else {
            match Mtx::from_calldata(&w.data) {
                Some((Mtx::Transfer(t), _)) => Some(t.to.into_word()),
                _ => None,
            }
        };
        if payee.is_none() {
            return Err(Refusal::Policy(
                "CALL_TARGET_REFUSED: not a transfer".into(),
            ));
        }
        self.check_payee(payee)?;
        self.require_bound(chain, w.to).await?;
        // Fable recheck 2 P3-1: the struct's `contract` (default `token`) picks its digest domain, as on a named row
        if let Some(t) = &w.typed {
            self.require_kind(chain, w.to, t.contract).await?;
        }
        if ua && w.typed.as_ref().is_some_and(|t| t.derived_side) {
            // no published UA allowlist to read: the UA path's fee class and kind are the simulation's
            return self.require_ua_ledger(chain, w.to).await;
        }
        Ok(())
    }

    /// The allow-list: the selector is a row on the contract kind the op names, the target meets that kind's rule.
    async fn check_named(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        let sel: [u8; 4] = match w.data.get(..4) {
            Some(s) => s.try_into().expect("4 bytes"),
            None => return Err(Refusal::Policy("CALL_TARGET_REFUSED: no selector".into())),
        };
        let contract = w.typed.as_ref().map_or("", |t| t.contract);
        let refused = |what: String| Refusal::Policy(format!("CALL_TARGET_REFUSED: {what}"));
        if contract == "service" {
            return self
                .check_service(chain, w.to, &w.data, w.typed.as_ref().map(|t| t.domain_of))
                .await;
        }
        let Some(row) = row(sel, contract) else {
            return Err(refused(format!(
                "0x{} is no named entry of a {contract:?} contract",
                alloy::hex::encode(sel)
            )));
        };
        // B (ua-mtx-merge): a derived subject reaches `_uaAllowed` only, which every merged entry's operation is on and no
        // address entry's is (it has no `bytes32` subject to carry one): refused here, fail closed, before any read
        if w.typed.as_ref().is_some_and(|t| t.derived_signer) && !row.ua() {
            return Err(refused(format!(
                "{} ({}): a derived subject signs merged entries only (B)",
                row.entry, row.name
            )));
        }
        if sel == IRelayFeeRouter::relayCall::SELECTOR {
            let Some(rf) = &self.relay_fee else {
                return Err(refused("no params.relay_fee.router on this chain".into()));
            };
            let target = relay_call_ok(rf, chain.address(), w.to, &w.data, |a| self.registered(a))
                .map_err(Refusal::Policy)?;
            relay_inner_ok(&self.gov_routers, &w.data).map_err(Refusal::Policy)?;
            // Fable recheck 2 P3-1: the payer signs in the fee token's domain, named by the op's `contract`
            if let Some(t) = &w.typed {
                self.require_kind(chain, t.domain_of, t.contract).await?;
            }
            // proposed NODE-JOB-25 on the inner call: a service runs its entries only, under the service rule
            if self.is_service(target) {
                let c = relay_call(&w.data).ok_or_else(|| refused("not a relay call".into()))?;
                return self.check_service(chain, target, &c.call, None).await;
            }
            // UA-7 P32 / topics P45 on the inner call: a `PqChat` entry runs on an instance `token_factory` lists (no `chainUid()`);
            // paid this way, an unsigned write needs no lane policy (P17); a `PqVault` entry likewise on a class-4 instance
            // (CTR-PQV-11, CTR-PQV-13): the kind is the one whose row the inner selector is (no write selector is shared)
            if let Some((kind, name, r)) = relay_call(&w.data).and_then(|c| {
                let s: [u8; 4] = c.call.get(..4)?.try_into().ok()?;
                FACTORY_KINDS
                    .iter()
                    .find_map(|(k, n)| self::row(s, k).map(|r| (*k, *n, r)))
            }) {
                let rule = rule_of(kind)
                    .ok_or_else(|| refused(format!("unknown contract kind {kind:?}")))?;
                if allowed(rule, &self.facts(chain, target, rule).await?) {
                    return Ok(());
                }
                // review P3-5: a paid `storeMessage` to `PqChatStore` (its release address and code), the store's one write
                let inner = relay_call(&w.data).and_then(|c| c.call.get(..4).map(|s| s.to_vec()));
                if target == self.chatstore_address
                    && inner.is_some_and(|s| {
                        s.try_into()
                            .ok()
                            .and_then(|s| self::row(s, "pqchatstore"))
                            .is_some()
                    })
                {
                    return self.require_chatstore(chain, target).await;
                }
                return Err(refused(format!(
                    "{} relayed to {target:#x}: no {name} instance of token_factory",
                    r.entry
                )));
            }
            return self.require_bound(chain, target).await;
        }
        // one kind per address (proposed NODE-JOB-25): a service is no target of any other kind's row
        if self.is_service(w.to) {
            return Err(refused(format!(
                "{} ({contract}) on {:#x}: a service takes its own entries only",
                row.entry, w.to
            )));
        }
        let Some(rule) = rule_of(contract) else {
            return Err(refused(format!("unknown contract kind {contract:?}")));
        };
        // UA-7 P17 (owner 2026-11-05): a `PqChat` write with no `UASig` (`storeMessage`, `addWraps`) runs paid, as a relay fee's call
        // (the branch above), or under the operator's `params.relay_unsigned_pqchat`: by default the lane pays no gas for it
        // CTR-PQV-11: `PqVault`'s unsigned `addVaultWraps` the same, under `params.relay_unsigned_pqvault`; CTR-CHAT-22:
        // `PqChatStore`'s `storeMessage` under `params.relay_unsigned_pqchat`
        let lane_pays = match contract {
            "pqchat" | "pqchatstore" => Some((self.relay_unsigned_pqchat, "relay_unsigned_pqchat")),
            "pqvault" => Some((self.relay_unsigned_pqvault, "relay_unsigned_pqvault")),
            _ => None,
        };
        if let (Some((false, param)), false) =
            (lane_pays, row.fields.iter().any(|f| f.0 == "UASig"))
        {
            return Err(Refusal::Policy(format!(
                "UNSIGNED_WRITE_NOT_PAID: {} carries no signature: send it as a relay fee's call \
                (RelayFeeRouter.relay), or the operator sets params.{param}",
                row.entry
            )));
        }
        if rule == Rule::ChatStore {
            return self.require_chatstore(chain, w.to).await;
        }
        self.check_payee(w.typed.as_ref().and_then(|t| t.payee))?;
        // pay-meta-tax spec §7.1: the `body` of a pay entry's `PayMeta` (plan T83: `payNo` a fixed word), before any read or
        // simulation
        if let Some(n) = w
            .typed
            .as_ref()
            .map(|t| t.pay_meta_len)
            .filter(|n| *n > self.max_pay_meta_bytes)
        {
            return Err(Refusal::Policy(format!(
                "PAY_META_TOO_LONG: body is {n} B, above max_pay_meta_bytes {}",
                self.max_pay_meta_bytes
            )));
        }
        if rule == Rule::Token {
            if !self.registered(w.to) {
                return Err(Self::not_served(w.to));
            }
            self.require_bound(chain, w.to).await?;
            self.require_kind(chain, w.to, contract).await?;
            // R44 (step 7a): only a derived `from` or `to` needs the UA ledger; an all-native merged entry runs at `registry() == 0`
            if w.typed.as_ref().is_some_and(|t| t.derived_side) {
                self.require_ua_ledger(chain, w.to).await?;
            }
            no_pending_party(chain, w).await?;
            three_keys(chain, w).await?;
            // group 3f (spec §11.1): `refuse_shield_when_unserved`, for every consumer
            return self.pqz.check_shield(chain, w).await;
        }
        if !allowed(rule, &self.facts(chain, w.to, rule).await?) {
            return Err(refused(format!("{} on {:#x}", row.entry, w.to)));
        }
        if rule == Rule::UaRegistry {
            self.check_generation(chain, row, w).await?;
        }
        if sel == ISCaaSDex::mtxLiquidityCall::SELECTOR {
            return check_liquidity(chain, w, self.max_gas_per_tx).await;
        }
        if row.name == "UACreateInstance" {
            return check_release(chain, row, &w.data).await;
        }
        Ok(())
    }

    /// The gateway pre-check, on every path: the local typed digest against a native signature. Recovered to the signer ⇒
    /// good. Recovered to anyone else ⇒ the signer may be a contract (ERC-1271), its simulation answers; an account without
    /// code is `BAD_SIGNATURE`, nothing simulated or sent. A signer the node cannot read (`signer` None) and any signature that
    /// is not 65 bytes are the simulation's.
    async fn check_signature(&self, chain: &Chain, w: &Work) -> Result<(), Refusal> {
        let Some(t) = &w.typed else { return Ok(()) };
        let Some((who, sig)) = &t.signer else {
            return Ok(());
        };
        // 65 bytes only: a 64-byte Hedera account signature (HIP-632, CTR-MTX-25) is no ecrecover input; the contract judges it
        if sig.len() != 65 {
            return Ok(());
        }
        let uid = chain
            .uid()
            .await
            .map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
        let Some(d) = t.digest_on(chain.number, uid) else {
            return Ok(());
        };
        if typed::recovers(d, sig, *who) {
            return Ok(());
        }
        match chain.is_contract_at(*who).await {
            Ok(true) => Ok(()),
            Ok(false) => Err(Refusal::Policy(format!(
                "BAD_SIGNATURE: not {who:#x}'s over the typed digest {d:#x} ({} domain)",
                t.contract
            ))),
            Err(e) => Err(Refusal::Transport(format!("eth_getCode: {e:#}"))),
        }
    }

    /// Group 3f (spec §11.1): a PQZ debit's trailing `PqzSignedVerdict`, rebuilt here after [`Guard::check`] and before any
    /// simulation, on every path (lane, gateway, the generic lane runner): the empty verdict for a `PRECOMPILE` token, else the
    /// `PqzVerdict` the node rebuilds with the job's or a fetched signature ([`crate::pqz::Verifier::fill`]).
    pub async fn pqz_fill(&self, chain: &Chain, w: &mut Work) -> Result<(), Refusal> {
        self.pqz.fill(chain, w).await
    }

    /// The subject a job can lower the balance of, as its hold key, and whether the job is a relay-fee job.
    /// A meta-transaction lowers its signer's balance on its token; a relay-fee job its payer's on the fee token. Other
    /// ways to lower it (DEX legs, `mtxWrap`, a plain ERC-20 transfer, another relayer) are the recorded residual.
    pub fn subject(&self, w: &Work) -> Option<(B256, bool)> {
        if let Some(r) = &w.meta {
            return Some((subject_key(r.token, r.from), false));
        }
        if !self.is_relay(w) {
            return None;
        }
        relay_call(&w.data).map(|c| (subject_key(c.token, c.from), true))
    }

    /// `w` is a call on this chain's relay-fee router: its fee side is [`Guard::relay_covers`].
    pub fn is_relay(&self, w: &Work) -> bool {
        self.relay_fee
            .as_ref()
            .is_some_and(|rf| w.meta.is_none() && w.to == rf.router)
    }

    /// `w` is a priced relay-fee job (its fee must cover the quote); a UA payer without a price is refused.
    pub fn relay_priced(&self, lane: Address, w: &Work) -> Result<bool, Refusal> {
        match &self.relay_fee {
            Some(rf) if self.is_relay(w) => Ok(relay_price(rf, lane, &w.data)?.is_some()),
            _ => Ok(false),
        }
    }

    /// The fee side of a priced relay-fee job ([`relay_fee_covers`]) at its fee ceiling and L1 data fee.
    pub fn relay_covers(
        &self,
        lane: Address,
        w: &Work,
        gas: u64,
        ceiling: u128,
        l1_fee: u128,
    ) -> Result<(), Refusal> {
        match &self.relay_fee {
            Some(rf) if self.is_relay(w) => {
                relay_fee_covers(rf, lane, &w.data, gas, ceiling, l1_fee)
            }
            _ => Ok(()),
        }
    }

    /// This chain charges an OP-stack L1 data fee (`params.l1_fee = "op-stack"`).
    pub fn op_stack(&self) -> bool {
        self.op_stack
    }

    /// The L1 data fee of the signed transaction `raw` (review I3): `GasPriceOracle.getL1Fee` on an OP-stack chain, 0
    /// elsewhere. An oracle that does not answer refuses the job (its cost is unknown).
    pub async fn l1_fee(&self, chain: &Chain, raw: &[u8]) -> Result<u128, Refusal> {
        if !self.op_stack {
            return Ok(0);
        }
        match chain.call_view(GAS_PRICE_ORACLE, crate::abi::IGasPriceOracle::getL1FeeCall { _data: raw.to_vec().into() }).await {
            Ok(f) => Ok(u128::try_from(f).unwrap_or(u128::MAX)),
            Err(SimError::Revert(e)) => Err(Refusal::Policy(format!(
                "RELAY_FEE_REFUSED: an OP-stack chain whose GasPriceOracle.getL1Fee does not answer ({e}): the L1 data fee is unknown"))),
            Err(SimError::Transport(e)) => Err(Refusal::Transport(format!("getL1Fee: {e}"))),
        }
    }

    /// A derived side needs the token's UA ledger on (`registry() ≠ 0`, CTR-UA-18; job-api.md step 7a, `token.features ∋ ua`,
    /// R44); the registry is an immutable of the implementation, so a yes is cached.
    async fn require_ua_ledger(&self, chain: &Chain, to: Address) -> Result<(), Refusal> {
        if self.ua_ledger.lock().is_ok_and(|b| b.contains(&to)) {
            return Ok(());
        }
        let off = |why: String| {
            Refusal::Policy(format!(
                "FEATURE_UNSUPPORTED: {to:#x} has no UA ledger ({why}) for a derived from or to"
            ))
        };
        match chain.call_view(to, IUALedger::registryCall {}).await {
            Ok(r) if r != Address::ZERO => {
                if let Ok(mut b) = self.ua_ledger.lock() {
                    b.insert(to);
                }
                Ok(())
            }
            Ok(_) => Err(off("registry() = 0".into())),
            Err(SimError::Revert(e)) => Err(off(format!("registry(): {e}"))),
            Err(SimError::Transport(e)) => Err(Refusal::Transport(format!("registry(): {e}"))),
        }
    }

    /// What the node knows of `to` for `rule`: the config, the registered list, the factory's record (a factory class's rule only)
    /// and `chainUid()` (every other rule).
    async fn facts(&self, chain: &Chain, to: Address, rule: Rule) -> Result<Facts, Refusal> {
        let class = matches!(rule, Rule::FactoryClass(_));
        Ok(Facts {
            token: self.tokens.read().map(|t| t.contains(&to)).unwrap_or(true),
            token_factory: self.token_factory == Some(to),
            account_factory: self.account_factory == Some(to),
            dex: self.dexes.contains(&to),
            ua_registry: self.ua_registries.contains(&to),
            gov_router: self.gov_routers.contains(&to),
            listed: if class {
                self.listed(chain, to).await?
            } else {
                None
            },
            // an instance answers no `chainUid()`: its rule reads the factory's record instead
            bound: !class && self.bound(chain, to).await?,
        })
    }

    /// CTR-UA-65 (F9): a registry write goes to the generation that takes it, read through the line's newest generation (its
    /// walk answers for every generation): a registration (and `cacheExpandedKey`) to `kindHome(kind)`, else `UA_VERIFY_ONLY`;
    /// a key write held in the holding generation to `holderOf(ua)`, a PQZ write to the record's PQZ home, else
    /// `UA_WRONG_GENERATION`; each names its target. An id no generation holds, a kind no generation registers, a read the
    /// registry refuses: the simulation's (the contract stays the guard). One generation: nothing to choose.
    async fn check_generation(
        &self,
        chain: &Chain,
        row: &typed::Row,
        w: &Work,
    ) -> Result<(), Refusal> {
        use crate::abi::IUARegistry as R;
        let (Some(newest), true) = (
            self.ua_registries.last().copied(),
            self.ua_registries.len() > 1,
        ) else {
            return Ok(());
        };
        let Some(target) = line_target(&w.data) else {
            return Ok(());
        };
        let read = |e: SimError| match e {
            SimError::Transport(e) => Err(Refusal::Transport(format!("registry line: {e}"))),
            SimError::Revert(_) => Ok(()),
        };
        let (to, entry) = (w.to, row.entry);
        let policy = |s: String| Err(Refusal::Policy(s));
        match target {
            LineTarget::Kind(kind) => match chain.call_view(newest, R::kindHomeCall { kind }).await {
                Ok(home) if home != Address::ZERO && home != to => policy(format!(
                    "{UA_VERIFY_ONLY}: {entry} of kind {kind:#06x} on {to:#x}, where it is not registrable; \
                     send it to kindHome(kind) {home:#x}")),
                Ok(_) => Ok(()),
                Err(e) => read(e),
            },
            LineTarget::Holder(ua) | LineTarget::PqzHome(ua) => {
                let h = match chain.call_view(newest, R::holderOfCall { ua }).await {
                    Ok(h) => h,
                    Err(e) => return read(e),
                };
                let (at, what) = match target {
                    LineTarget::Holder(_) => (h.holder, "the generation that holds the record, holderOf(ua)"),
                    _ => (h.pqzHome, "the record's PQZ home, pqzHomeOf(ua)"),
                };
                if at != Address::ZERO && at != to {
                    return policy(format!(
                        "{UA_WRONG_GENERATION}: {entry} of {ua:#x} on {to:#x}; send it to {what} {at:#x}"));
                }
                Ok(())
            }
        }
    }

    /// T9 (CTR-CHAT-22), review P2-3: a `pqchatstore` target is the release data's address (else `CHATSTORE_ADDRESS`), whose
    /// runtime code hash at the lane's final block, read pinned to that block's hash, is the release data's (else
    /// `CHATSTORE_CODE_HASH`); no code there yet is a transport-class "not yet" (`CHATSTORE_NOT_FINAL`, retried, never
    /// kept). A pass is kept while its final block's hash still holds (a reorg reads again) and for `chatstore_recheck`.
    async fn require_chatstore(&self, chain: &Chain, to: Address) -> Result<(), Refusal> {
        if to != self.chatstore_address {
            return Err(Refusal::Policy(format!(
                "CHATSTORE_ADDRESS: {to:#x} is not PqChatStore's release address {:#x}",
                self.chatstore_address
            )));
        }
        let kept = self
            .chatstores
            .lock()
            .ok()
            .and_then(|s| s.get(&to).copied());
        if let Some((at, n, h)) = kept {
            if at.elapsed() < self.chatstore_recheck
                && chain.block_hash_now(n).await.ok().flatten() == Some(h)
            {
                return Ok(());
            }
        }
        if let Ok(mut s) = self.chatstores.lock() {
            s.remove(&to);
        }
        let (code, n, h) = chain
            .code_final(to)
            .await
            .map_err(|e| Refusal::Transport(format!("eth_getCode at the final block: {e}")))?;
        if code.is_empty() {
            return Err(Refusal::Transport(format!(
                "CHATSTORE_NOT_FINAL: no code at {to:#x} at the final block {n} yet"
            )));
        }
        let got = alloy::primitives::keccak256(&code);
        if got != self.chatstore_code_hash {
            return Err(Refusal::Policy(format!(
                "CHATSTORE_CODE_HASH: the runtime code hash at {to:#x} is {got:#x}, not PqChatStore's release {:#x}",
                self.chatstore_code_hash
            )));
        }
        if let Ok(mut s) = self.chatstores.lock() {
            s.insert(to, (std::time::Instant::now(), n, h));
        }
        Ok(())
    }

    /// `infoOf(to)` on `token_factory`: `(contractClass, version)` of a contract it made, cached (a record never changes once
    /// made); `None` with no factory configured, for a contract it did not make (class 0, asked again next time), or a factory
    /// that does not answer.
    async fn listed(&self, chain: &Chain, to: Address) -> Result<Option<(u16, u64)>, Refusal> {
        if let Some(l) = self.listed.lock().ok().and_then(|m| m.get(&to).copied()) {
            return Ok(Some(l));
        }
        let Some(f) = self.token_factory else {
            return Ok(None);
        };
        let c = match chain.call_view(f, IOpenFactory::infoOfCall { c: to }).await {
            Ok(c) => c,
            Err(SimError::Revert(_)) => return Ok(None),
            Err(SimError::Transport(e)) => return Err(Refusal::Transport(format!("infoOf: {e}"))),
        };
        if c.contractClass == 0 {
            return Ok(None);
        }
        if let Ok(mut m) = self.listed.lock() {
            m.insert(to, (c.contractClass, c.version));
        }
        Ok(Some((c.contractClass, c.version)))
    }

    /// Fable E N-6: the op's `contract` (`token`, `zether`, `pqz`) picks the node's digest domain, so it must be the token's own:
    /// `eip712Domain().name` equal to that kind's, else `CONTRACT_KIND_MISMATCH` (`dead`). The name is an immutable of the
    /// implementation: kept once it matched a kind asked for, a mismatching answer is read again next time (Fable recheck 2 P3-2).
    async fn require_kind(
        &self,
        chain: &Chain,
        to: Address,
        contract: &str,
    ) -> Result<(), Refusal> {
        let cached = self
            .domain_names
            .lock()
            .ok()
            .and_then(|m| m.get(&to).cloned());
        let name = match cached {
            Some(n) => n,
            None => {
                let n = match chain.call_view(to, IToken::eip712DomainCall {}).await {
                    Ok(d) => d.name,
                    Err(SimError::Revert(e)) => {
                        return Err(Refusal::Policy(format!(
                            "CONTRACT_KIND_MISMATCH: {to:#x} answers no eip712Domain(): {e}"
                        )))
                    }
                    Err(SimError::Transport(e)) => {
                        return Err(Refusal::Transport(format!("eip712Domain(): {e}")))
                    }
                };
                n
            }
        };
        match typed::domain_name(contract) {
            Some(want) if want == name => {
                if let Ok(mut m) = self.domain_names.lock() {
                    m.insert(to, name);
                }
                Ok(())
            }
            want => Err(Refusal::Policy(format!(
                "CONTRACT_KIND_MISMATCH: contract {contract:?} signs in {want:?}, {to:#x}'s domain is {name:?}"))),
        }
    }

    async fn require_bound(&self, chain: &Chain, to: Address) -> Result<(), Refusal> {
        if self.bound(chain, to).await? {
            Ok(())
        } else {
            Err(Refusal::Policy(format!(
                "CHAIN_UID_MISMATCH: {to:#x} is not bound to this chain (NODE-GW-07)"
            )))
        }
    }

    /// `chainUid()` of `to` equals this chain's; a contract without one is not bound.
    async fn bound(&self, chain: &Chain, to: Address) -> Result<bool, Refusal> {
        if self.bound.lock().is_ok_and(|b| b.contains(&to)) {
            return Ok(true);
        }
        let uid = chain
            .uid()
            .await
            .map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
        let ok = match chain.call_view(to, IToken::chainUidCall {}).await {
            Ok(u) => u == uid,
            Err(SimError::Revert(_)) => false,
            Err(SimError::Transport(e)) => {
                return Err(Refusal::Transport(format!("chainUid(): {e}")))
            }
        };
        if ok {
            if let Ok(mut b) = self.bound.lock() {
                b.insert(to);
            }
        }
        Ok(ok)
    }
}

/// The typed digest of `w`, computed here (no chain view: only the cached `chain_uid`): the dedup key, on `w.typed`. On `w.meta`
/// the digest its `MetaTransactionExecuted` will carry: the same, but for a payee fee, which lands as its payment.
pub async fn fill_digest(chain: &Chain, w: &mut Work) -> Result<(), SimError> {
    let Some(t) = w.typed.as_mut() else {
        return Ok(());
    };
    if t.digest.is_some() || t.struct_hash.is_none() {
        return Ok(());
    }
    if t.contract == "service" {
        let d = pull_digest(chain, t.domain_of, t.struct_hash.expect("checked"))
            .await
            .map_err(|e| match e {
                Refusal::Policy(r) => SimError::Revert(r),
                Refusal::Transport(r) => SimError::Transport(r),
            })?;
        t.digest = Some(d);
        if let Some(m) = &mut w.meta {
            m.digest = Some(d);
        }
        return Ok(());
    }
    let uid = chain
        .uid()
        .await
        .map_err(|e| SimError::Transport(format!("{e:#}")))?;
    t.digest = t.digest_on(chain.number, uid);
    if let Some(m) = &mut w.meta {
        m.digest = t.lane_digest_on(chain.number, uid);
    }
    Ok(())
}

/// A service pull's digest (proposed NODE-JOB-25): the `UAMetaTransfer` struct hash in the pulled token's salted domain, its
/// name read from the token (`eip712Domain()`: a SCaaS token kind's, else `TOKEN_NOT_SERVED`).
// ponytail: one eth_call per job and per check; cache by token if the read shows up in the submit latency
async fn pull_digest(chain: &Chain, token: Address, struct_hash: B256) -> Result<B256, Refusal> {
    let d = match chain.call_view(token, IToken::eip712DomainCall {}).await {
        Ok(d) => d,
        Err(SimError::Revert(e)) => {
            return Err(Refusal::Policy(format!(
                "TOKEN_NOT_SERVED: {token:#x} has no eip712Domain(): {e}"
            )))
        }
        Err(SimError::Transport(e)) => {
            return Err(Refusal::Transport(format!("eip712Domain(): {e}")))
        }
    };
    let name = ["token", "zether", "pqz"]
        .into_iter()
        .filter_map(typed::domain_name)
        .find(|n| *n == d.name)
        .ok_or_else(|| {
            Refusal::Policy(format!(
                "TOKEN_NOT_SERVED: {token:#x} is no SCaaS token kind ({:?})",
                d.name
            ))
        })?;
    let uid = chain
        .uid()
        .await
        .map_err(|e| Refusal::Transport(format!("chain_uid: {e:#}")))?;
    let t = typed::Typed {
        contract: "service",
        domain_of: token,
        struct_hash: Some(struct_hash),
        lane_hash: None,
        signer: None,
        payee: None,
        digest: None,
        derived_signer: false,
        derived_side: false,
        pay_meta_len: 0,
        pqz_parties: vec![],
        pqz_auditor: false,
        pqz_verdict: None,
        pqz_fee: None,
    };
    Ok(t.digest_in(name, chain.number, uid).expect("a struct hash"))
}

/// Simulated gas → the gas limit, for the EVM submitter and the lane runner alike. Regular gas: a calldata floor over
/// 2^24 is refused before any RPC; an execution over 2^24 makes the chain's own simulation fail (`Chain::simulate`
/// reads that as a refusal). The estimate (regular + state, `eth_estimateGas`) must fit `max` (`max_gas_per_tx`) and
/// the chain's block gas limit; `mtxSettle` is sized until every planned settlement settles; a contract signer's
/// meta-tx gets at least the ERC-1271 floor.
/// NODE-JOB-24: a refusal of [`gas`] for the lane's per-transaction cap (`max_gas_per_tx`, the block gas limit, 2^24 before
/// Amsterdam), not for the calldata floor or a revert of the call itself.
/// The router's list edits (spec 2026-11-10-token-lists.md §6.2): `mtxSetAllowed`, `mtxSetDenied`, with the target's chain
/// word (CTR-GOV-28 Change, round 3zb + 3zc; were 0x06b98e72, 0x1d288fdc without it).
const SEL_LIST_EDITS: [[u8; 4]; 2] = [[0x6c, 0x83, 0x2e, 0xcf], [0xf8, 0xd9, 0xf1, 0xf3]];

/// Round 3s (spec §6.1, §14; Fable P3-4): a list edit's estimate above the chain's block gas limit is refused by name, before
/// sending: a smaller batch fits (256 new rows ≈ 31 M with the verification).
fn list_batch_note(data: &[u8]) -> &'static str {
    match data.get(..4) {
        Some(s) if SEL_LIST_EDITS.iter().any(|x| x == s) => {
            " (LIST_BATCH_TOO_LARGE: send fewer accounts per setAllowed / setDenied)"
        }
        _ => "",
    }
}

pub fn over_cap(reason: &str) -> bool {
    let reason = reason
        .strip_prefix(TX_EXCEEDS_CHAIN_LIMIT)
        .and_then(|r| r.strip_prefix(": "))
        .unwrap_or(reason);
    reason.starts_with("gas ")
        && (reason.contains(" above max_gas_per_tx ")
            || reason.contains(" above the chain's block gas limit ")
            || reason.contains(" above the 2^24 gas limit of a transaction"))
}

/// NODE-JOB-29 (owner O8, 2026-11-16): a refusal of [`gas`] by this lane's own cap (`max_gas_per_tx`) or by its RPC's gas cap
/// ([`crate::chain::classify_sim`]'s message, which cannot tell the RPC's cap from the 2^24 regular gas: read as the RPC's, so a part
/// that may still land is never `dead`), not by the chain (`TX_EXCEEDS_CHAIN_LIMIT`) or the call itself: another sender may cure it.
pub fn lane_cap(reason: &str) -> bool {
    !reason.starts_with(TX_EXCEEDS_CHAIN_LIMIT) && (over_cap(reason) || rpc_cap(reason))
}

/// [`crate::chain::classify_sim`]'s gas message: the RPC's gas cap or the chain's 2^24 regular gas, which no answer tells apart
/// (Nethermind's words are the same for both).
pub fn rpc_cap(reason: &str) -> bool {
    reason.contains("or the RPC gas cap: ")
}

pub async fn gas(chain: &Chain, w: &Work, max: u64) -> Result<u64, SimError> {
    gas_capped(chain, w, max, None).await
}

/// [`gas`] with the registry line's `txGasCap()` (`tx_cap`, read at start; Review Focus 5, spec 2026-11-19-registry-verify-only-kinds
/// §5 N13): a registry-checked job (a derived subject, whose check runs in the registry) takes its simulated limit up to the
/// chain registry's `txGasCap()` (never below the estimate itself), never a verify budget: a check that passes only on the
/// fallback path is sent with the gas the simulation found.
pub async fn gas_capped(
    chain: &Chain,
    w: &Work,
    max: u64,
    tx_cap: Option<u64>,
) -> Result<u64, SimError> {
    let block = chain
        .block_gas()
        .await
        .map_err(|e| SimError::Transport(format!("block gas limit: {e:#}")))?;
    let floor = calldata_floor(w.data.len());
    if block.amsterdam && floor > MAX_TX_GAS {
        return Err(SimError::Revert(format!(
            "{TX_EXCEEDS_CHAIN_LIMIT}: calldata floor {floor} above the 2^24 regular gas of a transaction ({} B; EIP-7976, EIP-7825)", w.data.len())));
    }
    // ruling R-node: a relayed PQ registration that does not fit one transaction is refused with its own code
    let split = w.meta.is_none() && pq_register(&w.data);
    let refuse = |why: String| {
        SimError::Revert(format!(
            "{UA_REGISTER_SPLIT}: {why}; send register without pqzPop, then storePqzPop"
        ))
    };
    let est = match chain.simulate(w.to, w.data.clone()).await {
        Err(SimError::Revert(r)) if split && r.contains("exceeds allowance") => {
            return Err(refuse(r))
        }
        r => r?,
    };
    if split && est > total_cap(max, block) {
        return Err(refuse(format!(
            "gas {est} above the transaction cap {} (max_gas_per_tx {max}, block gas limit {})",
            total_cap(max, block),
            block.limit
        )));
    }
    if est > max {
        return Err(SimError::Revert(format!(
            "gas {est} above max_gas_per_tx {max}"
        )));
    }
    if est > block.limit {
        return Err(SimError::Revert(format!(
            "{TX_EXCEEDS_CHAIN_LIMIT}: gas {est} above the chain's block gas limit {}{}",
            block.limit,
            list_batch_note(&w.data)
        )));
    }
    if !block.amsterdam && est > MAX_TX_GAS {
        return Err(SimError::Revert(format!("{TX_EXCEEDS_CHAIN_LIMIT}: gas {est} above the 2^24 gas limit of a transaction (EIP-7825, before Amsterdam)")));
    }
    let max_cfg = max;
    let max = total_cap(max, block);
    let g = if w.meta.is_none() && w.data.get(..4) == Some(&SEL_MTX_SETTLE[..]) {
        settle_gas(chain, w.to, &w.data, est, max).await?
    } else if w.meta.is_none()
        && w.data.get(..4) == Some(&crate::abi::IUARegistry::cacheExpandedKeyCall::SELECTOR[..])
    {
        // NODE-JOB-29, NET-EVM-11: a cache part's explicit limit is its measured (regular + state) × 1.05, within the block
        let g = est.saturating_add(est.div_ceil(20));
        if g > block.limit {
            return Err(SimError::Revert(format!(
                "{TX_EXCEEDS_CHAIN_LIMIT}: cache part gas {g} (estimate {est} x 1.05) above the chain's block gas limit {}", block.limit)));
        }
        if g > max {
            return Err(SimError::Revert(format!(
                "gas {g} above max_gas_per_tx {max_cfg} (a cache part's estimate {est} x 1.05)"
            )));
        }
        g
    } else {
        let contract_signer = match &w.meta {
            // a derived UA has no code: its verify is held by the registry (`UAVerifyGas` when starved), so the
            // estimate already covers it; a native id that is a contract gets the ERC-1271 floor on either path (an
            // EIP-7702 designator is an EOA, own key only: no floor, owner ruling 2026-10-30 D1)
            Some(m) => match crate::metatx::native(&m.from) {
                Some(a) => chain
                    .is_contract_at(a)
                    .await
                    .map_err(|e| SimError::Transport(format!("eth_getCode: {e:#}")))?,
                None => false,
            },
            None => false,
        };
        let registry_checked = w
            .meta
            .as_ref()
            .is_some_and(|m| crate::metatx::native(&m.from).is_none());
        let cap = match tx_cap {
            Some(t) if registry_checked => max.min(t.max(est)),
            _ => max,
        };
        gas_limit(
            est,
            if contract_signer {
                erc1271_floor(w.data.len())
            } else {
                0
            },
            cap,
        )
    };
    if g >= block.limit {
        // review L1 (controller 2026-10-22): accepted, but the transaction fills a whole block's gas reservation
        warn!(to = %w.to, gas = g, estimate = est, block = block.limit, "gas limit equals the chain's block gas limit");
    }
    Ok(g)
}

/// Size `mtxSettle` gas by simulation (P2b-2, NODE-DEX-15): from the estimate +20 %, raise ×1.5 until every planned
/// settlement settles, never past `max`. A whole-call revert is the job's answer as it is (never retried with more gas:
/// `SigCheckGasStarved` is forgeable by a hook-token destination); a transport error is transient, never a size. At the
/// cap the refusal names the settlements still failing (review P5 m4: a state failure looks the same as too little gas).
pub async fn settle_gas(
    chain: &Chain,
    to: Address,
    data: &Bytes,
    estimate: u64,
    max: u64,
) -> Result<u64, SimError> {
    let mut g = gas_limit(estimate, 0, max);
    loop {
        let ret = chain.call_with_gas(to, data.clone(), g).await?;
        if settled_all(&ret) {
            return Ok(g);
        }
        let Some(next) = next_gas(g, max) else {
            let failing: Vec<usize> = <Vec<bool> as SolValue>::abi_decode(&ret)
                .map(|v| {
                    v.iter()
                        .enumerate()
                        .filter(|(_, ok)| !**ok)
                        .map(|(i, _)| i)
                        .collect()
                })
                .unwrap_or_default();
            return Err(SimError::Revert(format!(
                "mtxSettle does not settle every settlement within {max} gas: settlements {failing:?} fail at the cap \
                 (a state failure, or more gas than the cap)")));
        };
        g = next;
    }
}

#[cfg(test)]
pub(crate) mod tests {
    /// D2-5 (plan T4): an exit refused `PqChatTreeBacklog` / `PqChatIncomplete` / `PqVaultIncomplete` waits queued; past the lag
    /// (`PqChatExitLag`) or on another refusal it does not; another entry refused the same way does not wait either. The
    /// reasons are the decoded errors (`abi::decode_revert`).
    #[test]
    fn an_exit_waits_within_the_lag() {
        use crate::abi::IPqChatErrors as E;
        let call = |entry: &str| {
            let r = crate::typed::rows()
                .iter()
                .find(|r| r.entry == entry)
                .unwrap();
            [&r.selector[..], &[0u8; 64][..]].concat()
        };
        let backlog = crate::abi::decode_revert(
            &E::PqChatTreeBacklog {
                owed: alloy::primitives::U256::from(21),
            }
            .abi_encode(),
        );
        let incomplete = crate::abi::decode_revert(
            &E::PqChatIncomplete {
                epochId: B256::ZERO,
            }
            .abi_encode(),
        );
        let vault = crate::abi::decode_revert(
            &E::PqVaultIncomplete {
                epochId: B256::ZERO,
            }
            .abi_encode(),
        );
        let lag = crate::abi::decode_revert(&E::PqChatExitLag { named: 1, head: 18 }.abi_encode());
        let member = crate::abi::decode_revert(&E::PqChatNotMember { ua: B256::ZERO }.abi_encode());
        for e in ["treeLeave", "treeRemove", "leave", "remove"] {
            for r in [&backlog, &incomplete] {
                assert!(
                    exit_wait(&call(e), r).is_some_and(|w| w.starts_with(EXIT_WAITING)),
                    "{e}: {r}"
                );
            }
            assert_eq!(exit_wait(&call(e), &lag), None, "{e}: past the lag is dead");
            assert_eq!(exit_wait(&call(e), &member), None, "{e}");
        }
        for e in ["leaveVault", "removeVaultMembers"] {
            assert!(exit_wait(&call(e), &vault).is_some(), "{e}");
        }
        assert_eq!(
            exit_wait(&call("postMessage"), &backlog),
            None,
            "not an exit"
        );
        assert_eq!(exit_wait(&call("commit"), &incomplete), None, "not an exit");
    }

    use super::*;
    use alloy::sol_types::{SolCall, SolError};

    /// The plain rows' selectors are the `cast sig` of their Solidity signatures and the sol! bindings', and the DEX KAT calldata
    /// (contract-generated) starts with them. Selectors only: same-typed arguments in the wrong order pass here; the names and
    /// order are pinned against forge's ABI by `plain_rows_match_the_forge_abi` (`tests/e2e.rs`). Every typed row is pinned by
    /// `typed_ops_kat_every_entry`.
    #[test]
    fn the_plain_rows_are_pinned() {
        use crate::abi::{IRelayFeeRouter as R, ISCaaSDex as D, IUARegistry as U};
        let kat = |f: &str, k: &str| -> Vec<u8> {
            let p = format!(
                "{}/../smartcontracts/evm/test/vectors/{f}",
                env!("CARGO_MANIFEST_DIR")
            );
            let v: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
            alloy::hex::decode(&v[k].as_str().unwrap()[2..]).unwrap()
        };
        let sel = |entry: &str, contract: &str| {
            typed::rows()
                .iter()
                .find(|r| r.entry == entry && !r.typed && r.contracts.contains(&contract))
                .unwrap_or_else(|| panic!("{entry}"))
                .selector
        };
        for (k, c) in [
            ("settle_calldata", D::mtxSettleCall::SELECTOR),
            ("exchange_calldata", D::mtxExchangeCall::SELECTOR),
            ("exchange_via_calldata", D::mtxExchangeViaCall::SELECTOR),
            ("hybrid_calldata", D::mtxHybridCall::SELECTOR),
            ("hybrid_via_calldata", D::mtxHybridViaCall::SELECTOR),
            ("exchange_batch_calldata", D::mtxExchangeBatchCall::SELECTOR),
        ] {
            assert_eq!(kat("dex_order_kat.json", k)[..4], c, "{k}");
            assert!(row(c, "dex").is_some(), "{k} is allowed");
        }
        assert_eq!(
            kat("dex_order_kat.json", "cancel_orders_calldata")[..4],
            D::mtxCancelOrdersCall::SELECTOR
        );
        assert_eq!(
            kat("dex_order_kat.json", "invalidate_calldata")[..4],
            SEL_MTX_INVALIDATE_NONCES
        );
        assert_eq!(sel("mtxSettle", "dex"), SEL_MTX_SETTLE);
        assert_eq!(
            sel("mtxCancelOrders", "dex"),
            D::mtxCancelOrdersCall::SELECTOR
        );
        assert_eq!(sel("mtxExchange", "dex"), D::mtxExchangeCall::SELECTOR);
        assert_eq!(
            sel("mtxExchangeVia", "dex"),
            D::mtxExchangeViaCall::SELECTOR
        );
        assert_eq!(
            sel("mtxExchangeBatch", "dex"),
            D::mtxExchangeBatchCall::SELECTOR
        );
        assert_eq!(sel("mtxHybrid", "dex"), D::mtxHybridCall::SELECTOR);
        assert_eq!(sel("mtxHybridVia", "dex"), D::mtxHybridViaCall::SELECTOR);
        assert_eq!(sel("register", "registry"), U::registerCall::SELECTOR);
        assert_eq!(
            sel("registerMsig", "registry"),
            U::registerMsigCall::SELECTOR
        );
        assert_eq!(
            sel("registerWebAuthn", "registry"),
            U::registerWebAuthnCall::SELECTOR
        );
        assert_eq!(
            sel("registerMuSig2", "registry"),
            U::registerMuSig2Call::SELECTOR
        );
        assert_eq!(
            sel("registerFrost", "registry"),
            U::registerFrostCall::SELECTOR
        );
        assert_eq!(
            sel("registerBlsMulti", "registry"),
            U::registerBlsMultiCall::SELECTOR
        );
        assert_eq!(sel("setKemKey", "registry"), U::setKemKeyCall::SELECTOR);
        assert_eq!(sel("storePqzPop", "registry"), U::storePqzPopCall::SELECTOR);
        assert_eq!(sel("setPqzKey", "registry"), U::setPqzKeyCall::SELECTOR);
        assert_eq!(
            sel("setPqzScopedKey", "registry"),
            U::setPqzScopedKeyCall::SELECTOR
        );
        assert_eq!(
            sel("storePqzScopedPop", "registry"),
            U::storePqzScopedPopCall::SELECTOR
        );
        assert_eq!(
            sel("acceptMembership", "registry"),
            U::acceptMembershipCall::SELECTOR
        );
        assert_eq!(sel("updateMsig", "registry"), U::updateMsigCall::SELECTOR);
        // NODE-JOB-29: `cast sig "cacheExpandedKey(uint16,bytes,uint256)"`
        assert_eq!(
            sel("cacheExpandedKey", "registry"),
            U::cacheExpandedKeyCall::SELECTOR
        );
        assert_eq!(U::cacheExpandedKeyCall::SELECTOR, [0x8b, 0x73, 0x88, 0x73]);
        let cast =
            |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        assert_eq!(
            sel("deploy", "factory"),
            cast("deploy((uint8,bytes32,bytes32,bytes32,bytes32),address)")
        );
        assert_eq!(
            sel("mtxExecuteAsOwner", "account"),
            cast("mtxExecuteAsOwner(bytes,uint256,uint256,bytes)")
        );
        // ua-mtx-merge (MD-11 (a)): the mandate wallet's flat builders and `mtxExecuteAsOwner(Raw)` are no row (legacy/ua-mtx-merge)
        for gone in [
            "mtxExecuteAsOwnerRaw(bytes,uint256,uint256,bytes)",
            "mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)",
            "mtxRevoke(address,uint64,uint256,bytes)",
            "mtxExecuteAsOwner(bytes,uint256,uint256,bytes)",
        ] {
            assert!(row(cast(gone), "wallet").is_none(), "{gone}");
        }
        let ua_sig = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
        // ua-mtx-merge T2 (R28): one `relay` on ids; pay-meta-tax T38: with the payer's `batch`, `nonce`
        assert_eq!(R::relayCall::SELECTOR, cast(&format!("relay(address,bytes,address,bytes32,bytes32,uint256,uint256,uint256,uint256,{ua_sig})")));
        assert_eq!(
            SEL_TOKEN_INVALIDATE_NONCES,
            cast(&format!(
                "mtxInvalidateNonces(bytes32,uint256,uint256,{ua_sig})"
            ))
        );
        assert_eq!(
            SEL_MTX_INVALIDATE_NONCES,
            cast("mtxInvalidateNonces(address,uint256,uint256,bytes)")
        );
        assert_eq!(rule_of("registry"), Some(Rule::UaRegistry));
        assert_eq!(rule_of("nothing"), None);
    }

    /// `(url, chain config, methods seen)`: an RPC answering every `eth_call` with `chain_uid` (so `chainUid()` binds and
    /// `registry()` is non-zero), every `eth_getCode` empty, no `eth_estimateGas`.
    async fn bound(uid: B256) -> (ChainCfg, Arc<Mutex<Vec<String>>>) {
        let (cfg, seen, _) = bound_release(uid).await;
        (cfg, seen)
    }

    /// [`bound`], and the release `classReleaseOf` answers: `(implementation, deprecated)`, a live one at first; `None`: a revert.
    /// Fable recheck 4 R4-4: only for the vector's `UACreateInstance` release `(contractClass, kind, version)` asked of its
    /// scaas-rpc T13 S16: block 0 with the pinned `uid` as its hash, for `eth_getBlockByNumber("0x0")` (a fixture correction:
    /// a node that serves no block 0 is refused now, never trusted on the pin alone).
    /// scaas-rpc T13 point 6 (fixture correction): and `chain` for `eth_chainId` (endpoint 0 is identity-checked now).
    fn block0_of(r: &serde_json::Value, uid: B256, chain: u64) -> Option<serde_json::Value> {
        if r["method"] == "eth_chainId" {
            return Some(serde_json::json!(format!("{chain:#x}")));
        }
        if r["method"] != "eth_getBlockByNumber" || r["params"][0] != "0x0" {
            return None;
        }
        let mut b = serde_json::from_str::<serde_json::Value>(include_str!(
            "../tests/vectors/hedera_testnet.json"
        ))
        .unwrap()["block"]
            .clone();
        b["hash"] = serde_json::json!(format!("{uid:#x}"));
        Some(b)
    }

    /// `target`; any other id or address answers the zero struct (no release).
    async fn bound_release(
        uid: B256,
    ) -> (
        ChainCfg,
        Arc<Mutex<Vec<String>>>,
        Arc<Mutex<Option<(Address, bool)>>>,
    ) {
        let release: Arc<Mutex<Option<(Address, bool)>>> =
            Arc::new(Mutex::new(Some((Address::repeat_byte(0x1e), false))));
        let m = typed::testkit::vectors()["ops"]["UACreateInstance"]["message"].clone();
        let n = |k: &str| {
            m[k].as_u64()
                .or_else(|| m[k].as_str().and_then(|x| x.parse().ok()))
                .unwrap()
        };
        let want = (
            m["target"].as_str().unwrap().parse::<Address>().unwrap(),
            n("contractClass") as u16,
            n("kind") as u16,
            n("version"),
        );
        let r2 = release.clone();
        let seen: Arc<Mutex<Vec<String>>> = Default::default();
        let s2 = seen.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<serde_json::Value>| {
                let (s2, now) = (s2.clone(), *r2.lock().unwrap());
                async move {
                    if let Some(b) = block0_of(&r, uid, 31337) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": b}),
                        );
                    }
                    let m = r["method"].as_str().unwrap().to_string();
                    s2.lock().unwrap().push(m.clone());
                    let p = &r["params"][0];
                    let (input, to) = (
                        p["input"].as_str().or(p["data"].as_str()).unwrap_or("0x"),
                        p["to"]
                            .as_str()
                            .unwrap_or_default()
                            .parse()
                            .unwrap_or_default(),
                    );
                    let release = format!(
                        "0x{}",
                        alloy::hex::encode(IOpenFactory::classReleaseOfCall::SELECTOR)
                    );
                    let result = match m.as_str() {
                        "eth_call" if typed::testkit::domain_answer(input, to).is_some() => {
                            serde_json::json!(typed::testkit::domain_answer(input, to))
                        }
                        // owner 2026-11-12: the release `mtxCreateInstance` names (`bound_release`)
                        "eth_call" if input.starts_with(&release) => match now
                            .filter(|_| {
                                let id = IOpenFactory::classReleaseOfCall::abi_decode(
                                    &alloy::hex::decode(&input[2..]).unwrap(),
                                )
                                .unwrap()
                                .id;
                                (to, id.contractClass, id.kind, id.version) == want
                            })
                            .or(if now.is_some() {
                                Some((Address::ZERO, false))
                            } else {
                                None
                            }) {
                            Some((implementation, deprecated)) => serde_json::json!(format!(
                                "0x{}",
                                alloy::hex::encode(
                                    IOpenFactory::classReleaseOfCall::abi_encode_returns(
                                        &IOpenFactory::ClassRelease {
                                            implementation,
                                            envVersion: 1,
                                            envHash: B256::ZERO,
                                            usableFrom: 0,
                                            deprecated,
                                            initSelector: Default::default(),
                                            interfaceId: Default::default()
                                        }
                                    )
                                )
                            )),
                            None => {
                                return axum::Json(
                                    serde_json::json!({"jsonrpc": "2.0", "id": r["id"],
                            "error": {"code": 3, "message": "execution reverted", "data": "0x"}}),
                                )
                            }
                        },
                        "eth_call" => serde_json::json!(format!("{uid:#x}")),
                        "eth_getCode" => serde_json::json!("0x"),
                        _ => serde_json::Value::Null,
                    };
                    axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": result}),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (
            ChainCfg {
                evm_chain_number: 31337,
                rpc_urls: vec![url],
                chain_uid: Some(uid),
                ..Default::default()
            },
            seen,
            release,
        )
    }

    /// Owner 2026-11-12: `mtxCreateInstance` names a published, live release of the factory, read before the simulation; an
    /// unpublished one is `RELEASE_UNKNOWN`, a deprecated one `RELEASE_DEPRECATED`, a reverting read `RELEASE_UNKNOWN` (all `dead`).
    /// Control: the live release passes.
    #[tokio::test]
    async fn an_instance_names_a_live_release() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let uid: B256 = v["ops"]["UAUnwrap"]["domains"]["token"]["domain"]["salt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let (cfg, _, release) = bound_release(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (w, _) = crate::submit::work_of_op(
            Some(1),
            &op_of("UACreateInstance", "gov_router", &v).unwrap(),
            None,
        )
        .unwrap();
        let g = Guard::new(
            &ChainCfg {
                governance_routers: vec![w.to],
                ..cfg.clone()
            },
            Default::default(),
        )
        .unwrap();
        g.check(&chain, &w).await.expect("control: a live release");
        for (now, want) in [
            (Some((Address::ZERO, false)), "RELEASE_UNKNOWN"),
            (
                Some((Address::repeat_byte(0x1e), true)),
                "RELEASE_DEPRECATED",
            ),
            (None, "RELEASE_UNKNOWN"),
        ] {
            *release.lock().unwrap() = now;
            assert!(
                matches!(g.check(&chain, &w).await, Err(Refusal::Policy(e)) if e.starts_with(want)),
                "{want}"
            );
        }
    }

    fn signer() -> alloy::signers::local::PrivateKeySigner {
        alloy::signers::local::PrivateKeySigner::random()
    }

    /// Both directions, through the guard: every entry of `typed_ops.json` (read from the file, its selector from the
    /// vector) passes on its kind's target, and is refused on a target its kind's rule excludes (a missing row breaks
    /// relaying silently); every selector outside the table is refused on every kind (an extra row opens a path).
    #[tokio::test]
    async fn guard_allows_every_named_entry_only() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let uid: B256 = v["ops"]["UAUnwrap"]["domains"]["token"]["domain"]["salt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let (cfg, _) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (mut sent, mut relayed, mut refused) = (0, 0, 0);
        for (name, o) in v["ops"].as_object().unwrap() {
            for (kind, d) in o["domains"].as_object().unwrap() {
                let Some(mut op) = op_of(name, kind, &v) else {
                    relayed += usize::from(!d["abi"].is_null());
                    continue;
                };
                if name == "UAPayUnderMandate" || name == "UADelegateRevoke" {
                    op["envelope"]["nonce"] = serde_json::json!("0");
                    op["envelope"]["batch"] = serde_json::json!(match name.as_str() {
                        "UAPayUnderMandate" =>
                            typed::mandate_pay_lane(&typed::testkit::hex(&op["args"]["entryRef"])),
                        _ => typed::mandate_revoke_lane(
                            op["args"]["token"].as_str().unwrap().parse().unwrap(),
                            op["args"]["epoch"].as_str().unwrap().parse().unwrap()
                        ),
                    }
                    .to_string());
                }
                let (mut w, _) = crate::submit::work_of_op(Some(1), &op, None)
                    .unwrap_or_else(|e| panic!("{name}: {e:#}"));
                if matches!(
                    name.as_str(),
                    "UAPayUnderMandate" | "UADelegateRevoke" | "UAPayeeFee"
                ) {
                    w.typed.as_mut().unwrap().signer = None; // the vector's lane 7, its one key for payer and payee
                }
                assert_eq!(
                    format!("0x{}", alloy::hex::encode(&w.data[..4])),
                    d["selector"].as_str().unwrap(),
                    "{name}"
                );
                let listed = ChainCfg {
                    dex: (kind == "dex").then_some(w.to),
                    governance_routers: if kind == "gov_router" {
                        vec![w.to]
                    } else {
                        vec![]
                    },
                    ..cfg.clone()
                };
                let right = Guard::new(
                    &listed,
                    Arc::new(RwLock::new(if rule_of(kind) == Some(Rule::Token) {
                        vec![w.to]
                    } else {
                        vec![]
                    })),
                )
                .unwrap();
                right
                    .check(&chain, &w)
                    .await
                    .unwrap_or_else(|e| panic!("{name} on {kind} is a missing row: {e:?}"));
                sent += 1;
                // the kind's rule excludes the other target: a token entry on an unregistered contract, a wallet's on a
                // registered token, a DEX entry on an unlisted address
                let wrong = Guard::new(
                    &cfg,
                    Arc::new(RwLock::new(if rule_of(kind) == Some(Rule::Token) {
                        vec![]
                    } else {
                        vec![w.to]
                    })),
                )
                .unwrap();
                let e = wrong.check(&chain, &w).await.unwrap_err();
                assert!(
                    matches!(&e, Refusal::Policy(r) if r.starts_with("TOKEN_NOT_SERVED") || r.starts_with("CALL_TARGET_REFUSED")),
                    "{name} on {kind}: {e:?}"
                );
                refused += 1;
            }
        }
        // plan T34: (97, 3, 97) -> (105, 3, 105), the router's eight regulated controls' vector rows walked; pay-meta-tax T42:
        // -> (110, 3, 110), UAPayWithTax's three domains and the router's two tax ops
        // group 3f T46 / T47: -> (113, 3, 113), the router's three verifier ops' vector rows
        // group 3h T61: -> (114, 3, 114), the router's `UASetProofStore`; group 3l: -> (116, 3, 116), the router's two wrap-limit ops
        // round 3r (CTR-GOV-23): -> (127, 3, 127), the router's eleven admin rows; round 3s (CTR-GOV-24): -> (130, 3, 130), the
        // router's `UASetAllowed`, `UASetDenied`, `UAEnableFeature`; round 3t: -> (131, 3, 131), the router's `UASetVerifierFee`
        // owner 2026-11-12: -> (132, 3, 132), the router's `UACreateInstance` (its vector row's `init_call`)
        // the three-key model (CTR-PQZ-41): -> (133, 3, 133), `PqzRollOver` (`mtxRollOverSigned` on the PQZ token)
        // round 3zc (CTR-GOV-30): -> (135, 3, 135), the router's `UASetMaxSupply`, `UASetMaxWrapSupply`
        // set-auditor (CTR-GOV-31): -> (137, 3, 137), the router's `UASetAuditorKey`, `UASetAuditorUA`
        // CTR-GOV-33 Change: -> (138, 3, 138), the router's `UACancelNonceFor`
        assert_eq!(
            (sent, relayed, refused),
            (138, 3, 138),
            "the walk reached every row with an entry; the relay fees: submit.rs"
        );
        // plan T32: 87 -> 95, the router's eight regulated controls; pay-meta-tax T42: -> 99, mtxPay, mtxPayWithTax, the two tax ops
        // group 3g T55: -> 100, the rollover one row per kind (`UARollOver` Zether, `UAPqzRollOver` PQZ with `keyVersion`)
        // group 3f T47: -> 103, the router's three verifier ops; group 3h T61: -> 104, `UASetProofStore`
        // T93: 104 -> 116, `PqChat`'s twelve plain rows; group 3l: -> 118, the router's two wrap-limit ops; UA-7 P48:
        // -> 119, `remove`; ua-mtx-liquidity L6 (79c3501e, moved at L6d): -> 120, `mtxLiquidity`
        // round 3r (CTR-GOV-23): -> 131, the router's eleven admin rows; round 3s (CTR-GOV-24): -> 134, the router's three list /
        // enable rows; round 3t: -> 135, `UASetVerifierFee`; owner 2026-11-12: -> 137, `UACreateToken`, `UACreateDex` (no vector
        // walk: their vector rows carry filler `initArgs`; `typed::tests::creation_rows_encode_the_named_config`); -> 138,
        // `UACreateInstance`; the three-key model: -> 141, `PqzRollOver`, the registry's `setPqzScopedKey`, `storePqzScopedPop`;
        // round 3zc (CTR-GOV-30): -> 143, the router's two cap setters; CTR-UA-44 (TODO 3ze): -> 144, the registry's `updateMsig`
        // NODE-JOB-29 (TODO 3zh MD-14): -> 145, the registry's `cacheExpandedKey`; set-auditor (CTR-GOV-31): -> 147, the router's
        // `mtxSetAuditorKey`, `mtxSetAuditorUA`; bls-multi Task 10: -> 148, the registry's `registerBlsMulti`
        // PqVault plan V8 (CTR-PQV-11): -> 156, `PqVault`'s eight plain rows; chains-arweave T9: -> 157, `PqChatStore`'s
        // `storeMessage` (contract kind `pqchatstore`); PqChat TreeKEM T4 (CTR-CHAT-27): 157 -> 163, `PqChat`'s six tree writes
        // CTR-GOV-33 Change: 163 -> 164, the router's `UACancelNonceFor`
        assert_eq!(
            typed::rows().iter().filter(|r| !r.entry.is_empty()).count(),
            164,
            "table rows: 112 typed with an entry, 52 plain"
        );
        // selectors with no row: refused on every kind, on a target that would otherwise pass
        let target = Address::repeat_byte(0x31);
        let g = Guard::new(
            &ChainCfg {
                dex: Some(target),
                governance_routers: vec![target],
                ..cfg.clone()
            },
            Arc::new(RwLock::new(vec![target])),
        )
        .unwrap();
        let cast = |s: &str| -> Vec<u8> { alloy::primitives::keccak256(s)[..4].to_vec() };
        for s in ["transfer(address,uint256)", "approve(address,uint256)", "transferFrom(address,address,uint256)",
            "mint(address,uint256)", "cancelNonce(uint256)",
            "mtxExecute((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
            "mtxBatch((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address)[],bytes[])",
            "mtxTrade((address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256),bytes,(uint256,uint256,uint256,address))",
            "mtxWrap(address,(address,address,uint256,uint256,uint256,uint256,address,address,address,uint8,uint256,uint256,uint256),bytes)",
            "mtxRelayFee(address,address,bytes32,address,uint256,uint256,bytes)",
            "uaRelayFee(bytes32,address,bytes32,bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            "mtxRelayFee(bytes32,address,bytes32,bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            // pay-meta-tax T37 / T38: the retired pay and relay forms
            "mtxPayMeta(bytes32,bytes32,uint256,bytes32,bytes,uint256,uint32,address,uint256,address,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            "relay(address,bytes,address,bytes32,bytes32,uint256,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            "executeMetaTransaction((address,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
            "uaExecute((bytes32,bytes,uint256,uint256,uint256,uint32,address,uint256,address),bytes)",
            "uaBatch((bytes32,bytes,uint256,uint256,uint256,uint32,address,uint256,address)[],bytes[])",
            "mtxExecute((bytes32,bytes,uint256,uint256,uint256,uint32,address,uint256,address),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            // the retired address forms of merged operations and the old `ua<Op>` names (ua-mtx-merge)
            "mtxBurn((address,uint256,uint256,uint256,uint32,address,uint256,address),uint256,bytes)",
            "uaBurn((bytes32,uint256,uint256,uint256,uint32,address,uint256,address),uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))",
            "mtxCancelNonce((address,uint256,uint256,uint256,uint32,address,uint256,address),uint256,bytes)",
            "mtxPayUnderMandate(address,address,uint256,bytes32,uint64,uint256,bytes)", "mtxRevoke(address,uint64,uint256,bytes)",
            "mtxExecuteAsOwnerRaw(bytes,uint256,uint256,bytes)",
            "grantRole(uint8,bytes32)", "setGrant(uint8,bytes32,(uint128,uint128,uint128,uint128,uint32,uint64,uint32,bool,bytes32))",
            "transferAdmin(bytes32,bytes32)", "setListedOnly(bool)",
            // round 3zb + 3zc: the direct entries with the chain word (governed, relayed through the router only) and the cap setters
            "mint(address,uint256,bytes32)", "setListedOnly(bool,bytes32)", "setMaxSupply(uint256,bytes32)",
            "setMaxWrapSupply(uint256,bytes32)"] {
            for kind in ["token", "zether", "pqz", "wallet", "account", "dex", "registry", "factory", "gov_router", "pqchat", "pqvault", "pqchatstore"] {
                let t = typed::Typed { pay_meta_len: 0, pqz_parties: vec![], pqz_auditor: false, pqz_verdict: None, pqz_fee: None, contract: kind, domain_of: target, struct_hash: None, lane_hash: None, signer: None, payee: None, digest: None,
                    derived_signer: false, derived_side: false };
                let w = Work { job_id: Some(1), to: target, data: cast(s).into(), valid_until: 0, envelope_until: 0, meta: None, entry: true, typed: Some(t) };
                let e = g.check(&chain, &w).await.unwrap_err();
                assert!(matches!(&e, Refusal::Policy(r) if r.starts_with("CALL_TARGET_REFUSED")), "{s} on {kind}: {e:?}");
            }
        }
        // the Change of CTR-GOV-28 in round 3zb + 3zc: the 25 router ops' old shapes (without the chain word, their calldata in
        // vectors/typed/legacy/burner-wrap-caps/) are no row: refused by name on a listed router; a job naming one without
        // `chainUid` is `BAD_PAYLOAD` (`typed::tests::chain_word_rows_refuse_a_missing_word`)
        let old = format!(
            "{}/../smartcontracts/vectors/typed/legacy/burner-wrap-caps/typed_ops.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let old: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(old).unwrap()).unwrap();
        let mut moved = 0;
        for (name, o) in old["ops"].as_object().unwrap() {
            let Some(d) = o["domains"].get("gov_router") else {
                continue;
            };
            // the six rows `typed::testkit::vectors()` leaves out (`NO_NODE_ROW`, unchanged since 3fa153e4), not moved shapes of
            // this round: `UACreateToken` / `UACreateDex` are node rows built from a named config, which the vector's filler
            // `initArgs` is not (pinned by `typed::tests::creation_rows_encode_the_named_config`); the four release approvals
            // are no node job by the owner's ruling (decisions.md CTR-GOV-23 "Release management is not a node job", `NOT_ROWS`; job-api.md, the router row)
            if typed::testkit::NO_NODE_ROW.contains(&name.as_str()) {
                continue;
            }
            if v["ops"][name]["typehash"] == o["typehash"] {
                continue;
            }
            let data = alloy::hex::decode(d["calldata"].as_str().unwrap()).unwrap();
            let t = typed::Typed {
                pay_meta_len: 0,
                pqz_parties: vec![],
                pqz_auditor: false,
                pqz_verdict: None,
                pqz_fee: None,
                contract: "gov_router",
                domain_of: target,
                struct_hash: None,
                lane_hash: None,
                signer: None,
                payee: None,
                digest: None,
                derived_signer: false,
                derived_side: false,
            };
            let w = Work {
                job_id: Some(1),
                to: target,
                data: data.into(),
                valid_until: 0,
                envelope_until: 0,
                meta: None,
                entry: true,
                typed: Some(t),
            };
            let e = g.check(&chain, &w).await.unwrap_err();
            assert!(
                matches!(&e, Refusal::Policy(r) if r.starts_with("CALL_TARGET_REFUSED")),
                "the old {name}: {e:?}"
            );
            moved += 1;
        }
        assert_eq!(moved, 25, "the old shapes walked");
    }

    /// Item of the lane, not of `Typed`: after `fill_digest` a payee fee is keyed by its outer digest and `classify` compares
    /// the payment's, what the chain emits; an ordinary op has one digest for both.
    #[tokio::test]
    async fn fill_digest_keeps_the_key_and_what_the_chain_emits_apart() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let d = &v["ops"]["UAPayeeFee"]["domains"]["token"];
        let uid: B256 = d["domain"]["salt"].as_str().unwrap().parse().unwrap();
        let (cfg, _) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (mut w, _) =
            crate::submit::work_of_op(Some(1), &op_of("UAPayeeFee", "token", &v).unwrap(), None)
                .unwrap();
        fill_digest(&chain, &mut w).await.unwrap();
        let t = w.typed.clone().unwrap();
        assert_eq!(
            format!("{:#x}", w.digest().unwrap()),
            d["digest"].as_str().unwrap(),
            "the in-flight key: the vector's outer digest"
        );
        assert_eq!(
            w.meta.unwrap().digest,
            t.lane_digest_on(31337, uid),
            "the job compares the payment's"
        );
        assert_ne!(w.meta.unwrap().digest, w.digest());
        let (mut w, _) =
            crate::submit::work_of_op(Some(1), &op_of("UAUnwrap", "token", &v).unwrap(), None)
                .unwrap();
        fill_digest(&chain, &mut w).await.unwrap();
        assert_eq!(w.meta.unwrap().digest, w.digest());
    }

    /// A 64-byte Hedera signature (HIP-632, CTR-MTX-25) on a codeless account is the contract's to judge; the same account with a
    /// wrong 65-byte one is `BAD_SIGNATURE` (the control), and no code is read for the 64 bytes.
    #[tokio::test]
    async fn a_signature_that_is_not_65_bytes_is_the_contracts() {
        let uid = B256::repeat_byte(0x24);
        let (cfg, seen) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let token = Address::repeat_byte(0x31);
        let g = Guard::new(&cfg, Arc::new(RwLock::new(vec![token]))).unwrap();
        let from = Address::repeat_byte(1);
        let t = crate::metatx::UAMetaTransfer {
            from: from.into_word(),
            to: Address::repeat_byte(2).into_word(),
            value: alloy::primitives::U256::from(1),
            entryRef: B256::ZERO,
            batch: alloy::primitives::U256::ZERO,
            nonce: alloy::primitives::U256::ZERO,
            validUntil: alloy::primitives::U256::from(4_000_000_000u64),
            mode: 0,
            relayer: Address::ZERO,
            fee: alloy::primitives::U256::ZERO,
            feeRecipient: Address::ZERO,
        };
        let m = UaMtx::Transfer(t);
        let auth = |sig: &[u8]| crate::abi::UASig {
            keyData: Bytes::new(),
            signature: sig.to_vec().into(),
            members: vec![],
        };
        let work = |sig: Vec<u8>| Work {
            job_id: Some(1),
            to: token,
            data: m.calldata(auth(&sig)),
            valid_until: 4_000_000_000,
            envelope_until: 4_000_000_000,
            meta: Some(crate::submit::MetaRef::of_ua(token, &m, None)),
            entry: false,
            typed: Some(
                crate::submit::transfer_typed(
                    None,
                    token,
                    m.struct_hash(),
                    Some((from, sig.into())),
                )
                .unwrap(),
            ),
        };
        g.check(&chain, &work(vec![0xab; 64])).await.unwrap();
        assert!(
            seen.lock().unwrap().iter().all(|c| c != "eth_getCode"),
            "64 bytes: not even a code read"
        );
        let e = g.check(&chain, &work(vec![0xab; 65])).await.unwrap_err();
        assert!(
            matches!(&e, Refusal::Policy(r) if r.starts_with("BAD_SIGNATURE")),
            "{e:?}"
        );
    }

    /// A job that is neither a named entry nor a transfer never runs; a transfer struct's selector is the transfer's.
    #[tokio::test]
    async fn work_without_a_row_is_refused_before_any_chain_read() {
        let cfg = ChainCfg {
            evm_chain_number: 7,
            rpc_urls: vec!["http://127.0.0.1:9".into()],
            ..Default::default()
        };
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let g = Guard::new(&cfg, Default::default()).unwrap();
        let w = |data: Vec<u8>, entry: bool| Work {
            job_id: Some(1),
            to: Address::repeat_byte(1),
            data: data.into(),
            valid_until: 0,
            envelope_until: 0,
            meta: None,
            entry,
            typed: None,
        };
        let transfer = IToken::transferCall {
            to: Address::repeat_byte(2),
            value: alloy::primitives::U256::from(1),
        }
        .abi_encode();
        assert!(
            matches!(g.check(&chain, &w(transfer.clone(), true)).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED"))
        );
        assert!(
            matches!(g.check(&chain, &w(transfer, false)).await, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED"))
        );
        assert!(matches!(
            g.check(&chain, &w(vec![], true)).await,
            Err(Refusal::Policy(_))
        ));
    }

    /// An RPC for the service tests (proposed NODE-JOB-25): `eth_call` answered by selector from a `servicepull.json` row —
    /// `servicePullEntries()` (the row's, or `entries` when set), `eip712Domain()` of the service (the row's) and of the token
    /// (`SCaaS MetaToken` on the row's chain and salt), `chainUid()` the row's salt — and `eth_getCode` empty.
    async fn service_rpc(r: &serde_json::Value, entries: Option<Vec<u8>>) -> ChainCfg {
        let h = |k: &serde_json::Value| alloy::hex::decode(k.as_str().unwrap()).unwrap();
        let (svc, tok): (Address, Address) = (
            r["service"]["address"].as_str().unwrap().parse().unwrap(),
            r["token"]["address"].as_str().unwrap().parse().unwrap(),
        );
        let uid: B256 = r["token"]["salt"].as_str().unwrap().parse().unwrap();
        let entries = entries.unwrap_or_else(|| h(&r["service"]["entriesReturn"]));
        let sdom = h(&r["service"]["domainReturn"]);
        let tdom = IToken::eip712DomainCall::abi_encode_returns(&IToken::eip712DomainReturn {
            fields: alloy::primitives::FixedBytes([0x1f]),
            name: "SCaaS MetaToken".into(),
            version: "1".into(),
            chainId: alloy::primitives::U256::from(22779),
            verifyingContract: tok,
            salt: uid,
            extensions: vec![],
        });
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(q): axum::Json<serde_json::Value>| {
                let (entries, sdom, tdom) = (entries.clone(), sdom.clone(), tdom.clone());
                async move {
                    if let Some(b) = block0_of(&q, uid, 22779) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": q["id"], "result": b}),
                        );
                    }
                    let p = &q["params"][0];
                    let to: Address = p["to"]
                        .as_str()
                        .unwrap_or("0x0000000000000000000000000000000000000000")
                        .parse()
                        .unwrap();
                    let input = alloy::hex::decode(
                        p["input"].as_str().or(p["data"].as_str()).unwrap_or("0x"),
                    )
                    .unwrap_or_default();
                    let sel: [u8; 4] = input
                        .get(..4)
                        .map(|x| x.try_into().unwrap())
                        .unwrap_or_default();
                    let out = match q["method"].as_str().unwrap() {
                        "eth_call"
                            if sel
                                == crate::abi::IServicePull::servicePullEntriesCall::SELECTOR
                                && to == svc =>
                        {
                            Some(entries)
                        }
                        "eth_call" if sel == IToken::eip712DomainCall::SELECTOR && to == svc => {
                            Some(sdom)
                        }
                        "eth_call" if sel == IToken::eip712DomainCall::SELECTOR && to == tok => {
                            Some(tdom)
                        }
                        "eth_call" if sel == IToken::chainUidCall::SELECTOR && to == tok => {
                            Some(uid.to_vec())
                        }
                        "eth_getCode" => Some(vec![]),
                        _ => None,
                    };
                    let result = out.map_or(serde_json::Value::Null, |b| {
                        serde_json::json!(format!("0x{}", alloy::hex::encode(b)))
                    });
                    axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": q["id"], "result": result}),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        let cfg = crate::service::ServiceCfg {
            address: svc,
            entries: vec![
                crate::service::EntryCfg {
                    entry: "deposit".into(),
                    op_type: r["service"]["entries"]["opTypes"][0]
                        .as_str()
                        .unwrap()
                        .into(),
                },
                crate::service::EntryCfg {
                    entry: "note".into(),
                    op_type: r["service"]["entries"]["opTypes"][1]
                        .as_str()
                        .unwrap()
                        .into(),
                },
            ],
        };
        let mut rf = toml::Table::new();
        rf.insert(
            "router".into(),
            toml::Value::String(r["relayFee"]["router"].as_str().unwrap().into()),
        );
        let mut params = toml::Table::new();
        params.insert("relay_fee".into(), toml::Value::Table(rf));
        ChainCfg {
            evm_chain_number: 22779,
            rpc_urls: vec![url],
            chain_uid: Some(uid),
            services: vec![cfg],
            params,
            ..Default::default()
        }
    }

    fn sp_rows() -> Vec<serde_json::Value> {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../smartcontracts/vectors/metatx/servicepull.json"
        ))
        .unwrap();
        v["rows"].as_array().unwrap().clone()
    }

    fn sp_job(op: serde_json::Value) -> crate::external_pull::Job {
        serde_json::from_value(serde_json::json!({"id": 1, "kind": "ua_metatx", "op": op})).unwrap()
    }

    fn policy(e: Result<(), Refusal>) -> String {
        match e {
            Err(Refusal::Policy(r)) => r,
            other => panic!("not a policy refusal: {other:?}"),
        }
    }

    /// Proposed NODE-JOB-25 through the guard, on the vectors' service (the RPC answers as the chain would): the startup read
    /// (entries equal, both directions), the job built from named fields and checked (§3.3 steps 1-4, the pull token the
    /// contract's, registered, bound, the payer's signature over the pull in the token's domain), its in-flight digest and
    /// lane the pull's (the payer held on the pulled token), and every refusal next to its control: the unbound
    /// `feeRecipient`, `SERVICE_TOKEN_MISMATCH`, `TOKEN_NOT_SERVED`, a wrong signature, a service that is also a token, another
    /// kind's row on the service, a contract whose entries differ from the config.
    #[tokio::test]
    async fn service_pull_through_the_guard() {
        let rows = sp_rows();
        let r = &rows[0];
        let tok: Address = r["token"]["address"].as_str().unwrap().parse().unwrap();
        let svc: Address = r["service"]["address"].as_str().unwrap().parse().unwrap();
        let cfg = service_rpc(r, None).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let g = Guard::new(&cfg, Arc::new(RwLock::new(vec![tok]))).unwrap();
        g.load_services(&chain).await.unwrap();
        let mut w = g.work(&sp_job(r["job"].clone()), None).unwrap();
        g.check(&chain, &w).await.unwrap();
        fill_digest(&chain, &mut w).await.unwrap();
        let want: B256 = r["transferDigest"].as_str().unwrap().parse().unwrap();
        assert_eq!(
            w.digest(),
            Some(want),
            "the in-flight key is the pull's digest in the token's domain"
        );
        let m = w.meta.unwrap();
        assert_eq!(
            (m.token, m.digest, m.nonce),
            (tok, Some(want), alloy::primitives::U256::ZERO),
            "the lane and completion are the token's"
        );
        assert_eq!(
            g.subject(&w),
            Some((subject_key(tok, m.from), false)),
            "the payer is held on the pulled token"
        );
        // the relay-fee wrap: the service rule on the inner call; the fee in T holds the same subject
        let f = &r["relayFee"];
        let relay = |call: serde_json::Value| {
            serde_json::json!({"entry": "mtxRelayFee", "contract": "token", "token": f["feeToken"], "call": call,
            "args": {"from": r["t"]["from"], "payee": f["payee"], "value": f["value"], "batch": f["batch"], "nonce": f["nonce"],
                     "validUntil": f["validUntil"], "relayer": f["router"]},
            "auth": {"keyData": "0x", "signature": f["signature"], "members": []}})
        };
        let rw = g.work(&sp_job(relay(r["job"].clone())), None).unwrap();
        g.check(&chain, &rw).await.unwrap();
        assert_eq!(
            g.subject(&rw),
            Some((subject_key(tok, m.from), true)),
            "F = T: one hold for both nonces"
        );
        // refusals, one change from the control each
        let refused = |e: String, code: &str| assert!(e.starts_with(code), "{code}: {e}");
        let unbound = &rows[2];
        refused(
            policy(
                g.check(
                    &chain,
                    &g.work(&sp_job(unbound["job"].clone()), None).unwrap(),
                )
                .await,
            ),
            "SERVICE_PULL_SHAPE: 2",
        );
        let mut j = relay(r["job"].clone());
        j["call"]["args"]["op"]["salt"] = unbound["job"]["args"]["op"]["salt"].clone();
        refused(
            policy(g.check(&chain, &g.work(&sp_job(j), None).unwrap()).await),
            "SERVICE_PULL_SHAPE: 3",
        );
        let mut j = r["job"].clone();
        j["args"]["pullToken"] = serde_json::json!(format!("{:#x}", Address::repeat_byte(0x77)));
        refused(
            policy(g.check(&chain, &g.work(&sp_job(j), None).unwrap()).await),
            "SERVICE_TOKEN_MISMATCH",
        );
        let mut j = r["job"].clone();
        let sig = j["args"]["auth"]["signature"].as_str().unwrap().to_string();
        j["args"]["auth"]["signature"] = serde_json::json!(
            format!(
                "{}{}",
                &sig[..10],
                if &sig[10..12] == "00" { "01" } else { "00" }
            ) + &sig[12..]
        );
        refused(
            policy(g.check(&chain, &g.work(&sp_job(j), None).unwrap()).await),
            "BAD_SIGNATURE",
        );
        let unserved = Guard::new(&cfg, Arc::new(RwLock::new(vec![]))).unwrap();
        unserved.load_services(&chain).await.unwrap();
        refused(
            policy(
                unserved
                    .check(
                        &chain,
                        &unserved.work(&sp_job(r["job"].clone()), None).unwrap(),
                    )
                    .await,
            ),
            "TOKEN_NOT_SERVED",
        );
        let also_token = Guard::new(&cfg, Arc::new(RwLock::new(vec![tok, svc]))).unwrap();
        also_token.load_services(&chain).await.unwrap();
        refused(
            policy(
                also_token
                    .check(
                        &chain,
                        &also_token.work(&sp_job(r["job"].clone()), None).unwrap(),
                    )
                    .await,
            ),
            "CALL_TARGET_REFUSED",
        );
        // one kind per address, the reverse: another kind's row (a token's `mtxCancelNonce`) on the service
        let mut tr = crate::typed::testkit::op_of(
            "UACancelNonce",
            "token",
            &crate::typed::testkit::vectors(),
        )
        .unwrap();
        tr["token"] = serde_json::json!(format!("{svc:#x}"));
        let tw = g.work(&sp_job(tr), None).unwrap();
        refused(policy(g.check(&chain, &tw).await), "CALL_TARGET_REFUSED");
        assert!(policy(g.check(&chain, &tw).await).contains("a service takes its own entries only"));
        // a contract whose entries are not the config's: the startup read stops the lane
        let one = crate::abi::IServicePull::servicePullEntriesCall::abi_encode_returns(
            &crate::abi::IServicePull::servicePullEntriesReturn {
                selectors: vec![alloy::primitives::FixedBytes(
                    alloy::hex::decode(r["selector"].as_str().unwrap())
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )],
                opTypes: vec![r["opType"].as_str().unwrap().into()],
                tokens: vec![tok],
            },
        );
        let cfg1 = service_rpc(r, Some(one)).await;
        let g1 = Guard::new(&cfg1, Arc::new(RwLock::new(vec![tok]))).unwrap();
        let e = g1
            .load_services(&Chain::with_signer(&cfg1, signer()).unwrap())
            .await
            .unwrap_err()
            .to_string();
        assert!(
            e.starts_with("SERVICE_ENTRIES_MISMATCH") && e.contains("is not the contract's"),
            "{e}"
        );
        refused(
            policy(
                g1.check(&chain, &g1.work(&sp_job(r["job"].clone()), None).unwrap())
                    .await,
            ),
            "CALL_TARGET_REFUSED",
        );
    }

    /// Startup bounds (proposed NODE-JOB-25): one kind per address against every configured kind, EVM only; the control.
    #[test]
    fn service_config_one_kind_per_address() {
        let s = Address::repeat_byte(0x5e);
        let svc = crate::service::ServiceCfg {
            address: s,
            entries: vec![crate::service::EntryCfg {
                entry: "deposit".into(),
                op_type: "Deposit(bytes32 payer,uint256 amount,uint64 releaseAfter,bytes32 salt)"
                    .into(),
            }],
        };
        let base = ChainCfg {
            evm_chain_number: 7,
            services: vec![svc.clone()],
            ..Default::default()
        };
        base.check_services().unwrap();
        let router = |a: Address| {
            let mut rf = toml::Table::new();
            rf.insert("router".into(), toml::Value::String(format!("{a:#x}")));
            let mut p = toml::Table::new();
            p.insert("relay_fee".into(), toml::Value::Table(rf));
            p
        };
        for (c, what) in [
            (
                ChainCfg {
                    dex: Some(s),
                    ..base.clone()
                },
                "dex",
            ),
            (
                ChainCfg {
                    governance_routers: vec![s],
                    ..base.clone()
                },
                "governance_routers",
            ),
            (
                ChainCfg {
                    ua_registries: vec![s],
                    ..base.clone()
                },
                "ua_registries",
            ),
            (
                ChainCfg {
                    account_factory: Some(s),
                    ..base.clone()
                },
                "account_factory",
            ),
            (
                ChainCfg {
                    token_factory: Some(s),
                    ..base.clone()
                },
                "token_factory",
            ),
            (
                ChainCfg {
                    params: router(s),
                    ..base.clone()
                },
                "relay_fee.router",
            ),
            (
                ChainCfg {
                    params: router(Address::repeat_byte(1)),
                    services: vec![crate::service::ServiceCfg {
                        address: Address::repeat_byte(1).create(1),
                        ..svc.clone()
                    }],
                    ..base.clone()
                },
                "executor",
            ),
            (
                ChainCfg {
                    services: vec![svc.clone(), svc.clone()],
                    ..base.clone()
                },
                "twice",
            ),
            (
                ChainCfg {
                    family: "soroban".into(),
                    ..base.clone()
                },
                "EVM only",
            ),
        ] {
            let e = c.check_services().unwrap_err().to_string();
            assert!(e.contains(what), "{what}: {e}");
        }
    }

    #[test]
    fn each_rule_needs_its_target() {
        let bound = Facts {
            bound: true,
            ..Default::default()
        };
        assert!(allowed(
            Rule::Token,
            &Facts {
                token: true,
                ..bound
            }
        ));
        assert!(!allowed(Rule::Token, &bound), "only a registered token");
        assert!(
            !allowed(
                Rule::Token,
                &Facts {
                    token: true,
                    bound: false,
                    ..bound
                }
            ),
            "NODE-GW-07"
        );
        assert!(allowed(Rule::SelfAuth, &bound));
        assert!(
            !allowed(
                Rule::SelfAuth,
                &Facts {
                    bound: false,
                    ..bound
                }
            ),
            "NODE-GW-07"
        );
        assert!(
            !allowed(
                Rule::SelfAuth,
                &Facts {
                    token: true,
                    ..bound
                }
            ),
            "never a registered token"
        );
        assert!(
            !allowed(
                Rule::SelfAuth,
                &Facts {
                    token_factory: true,
                    ..bound
                }
            ),
            "never the token factory"
        );
        assert!(!allowed(Rule::Dex, &bound), "only a listed DEX");
        assert!(allowed(Rule::Dex, &Facts { dex: true, ..bound }));
        assert!(!allowed(
            Rule::Dex,
            &Facts {
                dex: true,
                token: true,
                ..bound
            }
        ));
        assert!(!allowed(
            Rule::Dex,
            &Facts {
                dex: true,
                bound: false,
                ..bound
            }
        ));
        assert!(
            !allowed(Rule::AccountFactory, &bound),
            "only the account factory"
        );
        assert!(allowed(
            Rule::AccountFactory,
            &Facts {
                account_factory: true,
                ..bound
            }
        ));
        assert!(!allowed(
            Rule::AccountFactory,
            &Facts {
                account_factory: true,
                bound: false,
                ..bound
            }
        ));
        assert!(
            !allowed(Rule::UaRegistry, &bound),
            "only the configured registry"
        );
        assert!(allowed(
            Rule::UaRegistry,
            &Facts {
                ua_registry: true,
                ..bound
            }
        ));
        assert!(
            !allowed(
                Rule::UaRegistry,
                &Facts {
                    ua_registry: true,
                    bound: false,
                    ..bound
                }
            ),
            "NODE-GW-07"
        );
        assert!(!allowed(
            Rule::UaRegistry,
            &Facts {
                ua_registry: true,
                token: true,
                ..bound
            }
        ));
        assert!(
            !allowed(Rule::GovRouter, &bound),
            "only a configured router"
        );
        assert!(allowed(
            Rule::GovRouter,
            &Facts {
                gov_router: true,
                ..bound
            }
        ));
        assert!(
            !allowed(
                Rule::GovRouter,
                &Facts {
                    gov_router: true,
                    bound: false,
                    ..bound
                }
            ),
            "NODE-GW-07"
        );
        for other in [
            Rule::SelfAuth,
            Rule::Dex,
            Rule::AccountFactory,
            Rule::UaRegistry,
        ] {
            let all = Facts {
                gov_router: true,
                dex: true,
                account_factory: true,
                ua_registry: true,
                ..bound
            };
            assert!(
                !allowed(other, &all),
                "{other:?}: a router is no target of another kind's row"
            );
        }
        // T93 (topics P45): a factory class, bound by the factory's record (an instance answers no `chainUid()`)
        let chat = Rule::FactoryClass(CLASS_PQCHAT);
        let listed = Facts {
            listed: Some((3, 1)),
            ..Default::default()
        };
        assert_eq!(rule_of("pqchat"), Some(chat));
        // PqVault plan V8 (CTR-PQV-13): class 4, its own rule; a class-3 listing is no PqVault and the reverse
        let vault = Rule::FactoryClass(CLASS_PQVAULT);
        assert_eq!(rule_of("pqvault"), Some(vault));
        assert!(allowed(
            vault,
            &Facts {
                listed: Some((4, 1)),
                ..Default::default()
            }
        ));
        assert!(!allowed(vault, &listed), "class 3 is no PqVault");
        assert!(
            !allowed(
                chat,
                &Facts {
                    listed: Some((4, 1)),
                    ..Default::default()
                }
            ),
            "class 4 is no PqChat"
        );
        assert!(allowed(chat, &listed), "listed as class 3 with a release");
        assert!(!allowed(chat, &Facts::default()), "only a listed instance");
        assert!(!allowed(chat, &bound), "bound is not listed");
        assert!(
            !allowed(
                chat,
                &Facts {
                    listed: Some((3, 0)),
                    ..listed
                }
            ),
            "version 0"
        );
        assert!(
            !allowed(
                chat,
                &Facts {
                    listed: Some((4, 1)),
                    ..listed
                }
            ),
            "another class"
        );
        assert!(
            !allowed(
                chat,
                &Facts {
                    token: true,
                    ..listed
                }
            ),
            "never a registered token"
        );
        assert!(
            !allowed(
                chat,
                &Facts {
                    token_factory: true,
                    ..listed
                }
            ),
            "never the token factory"
        );
        assert!(
            !allowed(
                chat,
                &Facts {
                    gov_router: true,
                    ..listed
                }
            ),
            "a router takes its own rows only"
        );
        for other in [
            Rule::SelfAuth,
            Rule::Dex,
            Rule::AccountFactory,
            Rule::UaRegistry,
            Rule::GovRouter,
        ] {
            let all = Facts {
                gov_router: other == Rule::GovRouter,
                dex: true,
                account_factory: true,
                ua_registry: true,
                ..listed
            };
            assert!(
                !allowed(other, &all),
                "{other:?}: an instance is no target of another kind's row"
            );
        }
    }

    /// The kind of each contract of `selector_audit.json` (`DexPuller` is no target of a job: the DEX calls it).
    /// Plan T32: the regulated kinds 8-13 on their base kind's contract kind (regulated-kinds spec §7).
    const AUDIT_KINDS: &[(&str, &str)] = &[
        ("NormalToken", "token"),
        ("WrappedToken", "token"),
        ("NormalZetherToken", "zether"),
        ("WrappedZetherToken", "zether"),
        ("NormalPqzToken", "pqz"),
        ("WrappedPqzToken", "pqz"),
        ("SCaaSDex", "dex"),
        ("GovernanceRouter", "gov_router"),
        ("NormalRegulatedToken", "token"),
        ("WrappedRegulatedToken", "token"),
        ("NormalZetherRegulatedToken", "zether"),
        ("WrappedZetherRegulatedToken", "zether"),
        ("NormalPqzRegulatedToken", "pqz"),
        ("WrappedPqzRegulatedToken", "pqz"),
        ("OpenFactory", "open_factory"),
        ("UARegistry", "registry"),
        ("SmartKeyAccountFactory", "factory"),
        ("SmartKeyAccount", "account"),
    ];
    // round 3r (spec §7): `OpenFactory` under its own label: the node's contract kind `factory` is `SmartKeyAccountFactory`
    // (`deploy`); `OpenFactory` has no node row, its three open deploys `APPROVED(release)` are in `NOT_ROWS`
    /// `SIGNED` entries no job names, each with its reason: `(name, the argument list's start)`.
    const NOT_ROWS: &[(&str, &str, &str)] = &[
        ("executeMetaTransaction", "((address,bytes,", "the EIP-1776 alias (R3): its address MetaTransaction is no job shape"),
        ("mtxExecute", "((bytes32,bytes,", "the generic UAMetaTransaction: a job names its operation (HEX_DATA_REFUSED on struct = call)"),
        ("mtxBatch", "((bytes32,bytes,", "the generic batch: as mtxExecute"),
        // owner 2026-11-12: `SmartKeyAccount`'s generic entries on its address `MetaTransaction`
        ("mtxExecute", "((address,bytes,", "the account's generic MetaTransaction: a job names its operation (mtxExecuteAsOwner, the account's named rows)"),
        ("mtxBatch", "((address,bytes,", "the account's generic batch: as its mtxExecute"),
        ("mtxBatchTransfer", "((bytes32,bytes32,", "a transfer relays as one mtxExecuteTransfer (ua_metatx struct job)"),
        ("mtxTransfer", "(bytes32,bytes32,", "the flat transfer: the same UAMetaTransfer as mtxExecuteTransfer"),
        ("mtxTransferWithFee", "(bytes32,bytes32,", "the flat transfer with a fee: as mtxTransfer"),
        ("mtxTrade", "((bytes32,address,", "the DEX's pull (NotDex for any other caller)"),
        ("restorePulled", "((bytes32,address,", "the DEX's (NotDex)"),
        ("mtxLiquidityPull", "((bytes32,(address,uint256)[],", "the DEX's liquidity pull (NotLiquidityDex, and no valid digest for any other caller): reached only through the relayed mtxLiquidity (spec 2026-11-10-dex-liquidity.md §11)"),
        ("exchangeOne", "((bytes32,", "the DEX's own self-call (NotSelf)"),
        ("settleOne", "((bytes32,", "the DEX's own self-call (NotSelf)"),
        // owner 2026-11-12: `mtxCreateToken`, `mtxCreateDex` and `mtxCreateInstance` are rows (their configs named; the instance's
        // `init_call` or a known class's named config)
        ("mtxApproveTokenRelease", "((bytes32,uint256,", RELEASE_NOT_A_JOB),
        ("mtxApproveDexRelease", "((bytes32,uint256,", RELEASE_NOT_A_JOB),
        ("mtxApproveRelease", "((bytes32,uint256,", RELEASE_NOT_A_JOB),
        ("mtxRevokeApproval", "((bytes32,uint256,", RELEASE_NOT_A_JOB),
        ("deployTokenImplementation", "(uint8,", RELEASE_NOT_A_JOB),
        ("deployDexImplementation", "(uint64,", RELEASE_NOT_A_JOB),
        ("deployImplementation", "((uint16,", RELEASE_NOT_A_JOB),
    ];
    /// `addKey` -> `mtxAddKey`: the envelope entry that self-calls an operation.
    fn mtx_of(name: &str) -> String {
        let mut c = name.chars();
        c.next().map_or(String::new(), |f| {
            format!("mtx{}{}", f.to_ascii_uppercase(), c.as_str())
        })
    }

    /// Round 3r (spec 2026-11-10-admin-not-owner.md §5.6, Q3): the four approval ops and the three open deploys.
    const RELEASE_NOT_A_JOB: &str = "release management is not a node job (owner 2026-11-10)";
    const ENV_UA: &str = "((bytes32,uint256,uint256,uint256,uint32,address,uint256,address)";
    const ENV_ADDR: &str = "((address,uint256,uint256,uint256,uint32,address,uint256,address)";

    /// ua-mtx-merge T14 (review focus 8, AGENTS "Node"), both directions per kind against `selector_audit.json`: every row of a token
    /// kind, the DEX and the router is a `SIGNED` entry of a contract of that kind (`mtxRelayFee` by its own selector: the node sends it
    /// through the router); every `SIGNED` entry of those contracts is a row of the kind, a `ua_metatx` struct job's entry
    /// (`mtxExecuteTransfer`, `mtxPayMeta`, the calldata [`crate::metatx::UaMtx`] builds), the inner operation an envelope row of the
    /// same name self-calls (also the holder's direct call), or named in `NOT_ROWS` with its reason. The router's generic entries
    /// (`PERMISSIONLESS(refuses every call)`) are no row; no `BIT`, `ADMIN` or `HOLDER_OWN` entry of a governed contract is a row of any
    /// kind, so no governance op is relayable on it.
    #[test]
    fn allow_lists_equal_the_selector_audit_both_directions() {
        let p = format!(
            "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let sel = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        let kinds = [
            "token",
            "zether",
            "pqz",
            "wallet",
            "account",
            "dex",
            "registry",
            "factory",
            "gov_router",
        ];
        // the struct jobs' entries, as the node builds them
        let m = crate::metatx::UaMtx::Transfer(crate::metatx::UAMetaTransfer {
            from: B256::repeat_byte(1),
            to: B256::repeat_byte(2),
            value: alloy::primitives::U256::from(1),
            entryRef: B256::ZERO,
            batch: alloy::primitives::U256::ZERO,
            nonce: alloy::primitives::U256::ZERO,
            validUntil: alloy::primitives::U256::from(1),
            mode: 0,
            relayer: Address::ZERO,
            fee: alloy::primitives::U256::ZERO,
            feeRecipient: Address::ZERO,
        });
        let auth = crate::abi::UASig {
            keyData: Bytes::new(),
            signature: Bytes::new(),
            members: vec![],
        };
        let struct_jobs: HashSet<[u8; 4]> = [m.calldata(auth)[..4].try_into().unwrap()]
            .into_iter()
            .collect();
        let (mut rowed, mut exempt, mut governed) = (0, 0, 0);
        // Fable E N-10: + the registry and the account factory, whose writes anyone may relay: a row there is a SIGNED entry or a
        // PERMISSIONLESS one (`storePqzPop`, `deploy`: a proof or the address fixes what they write; `cacheExpandedKey`, NODE-JOB-29:
        // the registry derives what it writes from `pk`)
        // owner 2026-11-12: + the account (`SmartKeyAccount`; its guardian's `initiateRecovery` is class GUARDIAN, no row)
        for kind in [
            "token",
            "zether",
            "pqz",
            "dex",
            "gov_router",
            "open_factory",
            "registry",
            "factory",
            "account",
        ] {
            let entries: Vec<&serde_json::Value> = AUDIT_KINDS
                .iter()
                .filter(|(_, k)| *k == kind)
                .flat_map(|(c, _)| audit[*c].as_array().unwrap_or_else(|| panic!("{c}")))
                .collect();
            let signed: HashSet<[u8; 4]> = entries
                .iter()
                .filter(|r| r["class"] == "SIGNED")
                .map(|r| sel(r["sig"].as_str().unwrap()))
                .collect();
            let open_rows = matches!(kind, "registry" | "factory");
            let open: HashSet<[u8; 4]> = entries
                .iter()
                .filter(|r| {
                    open_rows
                        && r["class"]
                            .as_str()
                            .is_some_and(|c| c.starts_with("PERMISSIONLESS("))
                })
                .map(|r| sel(r["sig"].as_str().unwrap()))
                .collect();
            let ours: Vec<&typed::Row> = typed::rows()
                .iter()
                .filter(|r| !r.entry.is_empty() && r.contracts.contains(&kind))
                .collect();
            for r in &ours {
                assert!(
                    signed.contains(&r.selector) || open.contains(&r.selector),
                    "{} ({}) on {kind} is no SIGNED entry of a {kind} contract",
                    r.name,
                    r.entry
                );
            }
            for e in entries.iter().filter(|r| r["class"] == "SIGNED") {
                let s = e["sig"].as_str().unwrap();
                let (name, args) = s.split_at(s.find('(').unwrap());
                if ours.iter().any(|r| r.selector == sel(s)) {
                    rowed += 1;
                } else if kind != "dex" && kind != "gov_router" && struct_jobs.contains(&sel(s)) {
                    exempt += 1;
                } else if !args.starts_with(ENV_UA)
                    && !args.starts_with(ENV_ADDR)
                    && ours
                        .iter()
                        .any(|r| r.enveloped && (r.entry == name || r.entry == mtx_of(name)))
                {
                    exempt += 1; // the inner operation its envelope row self-calls (the account's `addKey` behind `mtxAddKey`)
                } else {
                    assert!(
                        NOT_ROWS
                            .iter()
                            .any(|(n, a, _)| *n == name && args.starts_with(a)),
                        "{kind}: SIGNED {s} has no row and no reason"
                    );
                    exempt += 1;
                }
            }
            for e in entries.iter().filter(|r| r["class"] != "SIGNED") {
                let s = e["sig"].as_str().unwrap();
                for k in kinds {
                    if k == kind && open.contains(&sel(s)) && row(sel(s), k).is_some() {
                        rowed += 1; // a relayable PERMISSIONLESS write of the registry or the account factory
                        continue;
                    }
                    assert!(
                        row(sel(s), k).is_none(),
                        "{kind}: {s} ({}) is a {k} row",
                        e["class"]
                    );
                }
                let class = e["class"].as_str().unwrap();
                if class.starts_with("APPROVED") {
                    // round 3r: the factory's open deploys (an approved release), each named with its reason
                    let (name, args) = s.split_at(s.find('(').unwrap());
                    assert!(
                        NOT_ROWS
                            .iter()
                            .any(|(n, a, _)| *n == name && args.starts_with(a)),
                        "{kind}: {s} ({class}) not in NOT_ROWS"
                    );
                    exempt += 1;
                }
                governed += usize::from(
                    class.starts_with("BIT")
                        || class == "ADMIN"
                        || class == "HOLDER_OWN"
                        || class == "GUARDIAN",
                );
            }
        }
        let not_row = |s: &str| {
            NOT_ROWS
                .iter()
                .any(|(n, a, _)| s.strip_prefix(n).is_some_and(|x| x.starts_with(a)))
        };
        let router: HashSet<[u8; 4]> = audit["GovernanceRouter"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["class"] == "SIGNED")
            .map(|r| r["sig"].as_str().unwrap())
            .filter(|s| !not_row(s))
            .map(sel)
            .collect();
        // group 3f T45 / T47: 30 -> 33, the three verifier ops; group 3h T61: -> 34, `mtxSetProofStore` (bit 24); group 3l: -> 36,
        // `mtxSetWrapLimits`, `mtxSetWrapMember`
        // round 3r: -> 47, the eleven admin ops of the factory and the compliance registry (the four approvals in NOT_ROWS)
        // round 3s (CTR-GOV-24): -> 50, `mtxSetAllowed`, `mtxSetDenied`, `mtxEnableFeature`; round 3t: -> 51, `mtxSetVerifierFee`
        // owner 2026-11-12: -> 53, `mtxCreateToken`, `mtxCreateDex`; -> 54, `mtxCreateInstance`; round 3zc (CTR-GOV-30): -> 56,
        // `mtxSetMaxSupply`, `mtxSetMaxWrapSupply` (the 25 ops of the Change of CTR-GOV-28 moved selector in place); set-auditor
        // (CTR-GOV-31): -> 58, `mtxSetAuditorKey`, `mtxSetAuditorUA`; CTR-GOV-33 Change: -> 59, `mtxCancelNonceFor`
        assert_eq!(router.len(), 59, "19 ops, the eight regulated controls (plan T32), the ordered cancel and the keyed one, the two tax ops (pay-meta-tax T39), the three verifier ops (3f), bit 24's op (3h), the two wrap-limit ops (3l), the eleven admin ops (3r), the three creations (a token, a DEX, an instance), bit 32's two ops; the four release approvals (3r) in NOT_ROWS");
        let ours: HashSet<[u8; 4]> = typed::rows()
            .iter()
            .filter(|r| !r.entry.is_empty() && r.contracts.contains(&"gov_router"))
            .map(|r| r.sent)
            .collect();
        assert_eq!(ours, router, "the router's allow-list, both directions");
        assert_eq!(
            (rowed, exempt, governed),
            (ROWED, EXEMPT, GOVERNED),
            "every SIGNED entry was walked"
        );
    }
    /// Regulated-kinds spec §7 (plan T35), one kind 8-13 against its base kind, both directions:
    /// - the contract (split tree, T66b): `<Kind>Core is <Base>Core, RegulatedBase`; its `_mtxSelectorsBody`, `_mtxRule` and
    ///   `_uaAllowed` are `return super.<f>(…)` over `<Base>Core`; the module's `mtxSelectors()` returns `_mtxSelectorsBody()`;
    ///   and neither `RegulatedBase`, `RegulatedLib`, the face nor the modules define any of them, so the meta-tx allow-lists
    ///   are the base kind's;
    /// - `selector_audit.json`: its `SIGNED` entries are the base kind's, each way; every other entry it adds is one of the eight
    ///   `BIT` controls (5, 6, 7, 10, 22), none a row of any node kind (relayed through the router only);
    /// - the node: the rows of the base's node kind on its `SIGNED` entries are the same set on the regulated kind, and the guard
    ///   allows each of them on that node kind, whose rule is a registered token.
    fn regulated_kind_rows_equal_contract(kind: &str, base: &str, node_kind: &str, base_dir: &str) {
        let root = format!("{}/../smartcontracts/evm", env!("CARGO_MANIFEST_DIR"));
        let read = |p: &str| {
            std::fs::read_to_string(format!("{root}/{p}")).unwrap_or_else(|e| panic!("{p}: {e}"))
        };
        // ua-mtx-merge T66b: the kind's logic is `<Kind>Core`; the face (`<Kind>.sol`) and `<Kind>Modules.sol` forward to it.
        let src = read(&format!("src/regulated/{kind}Core.sol"));
        assert!(
            src.contains(&format!(
                "abstract contract {kind}Core is {base}Core, RegulatedBase {{"
            )),
            "{kind}Core is {base}Core, RegulatedBase"
        );
        assert!(
            read(&format!("src/{base_dir}/{base}Core.sol"))
                .contains(&format!("abstract contract {base}Core ")),
            "{base}Core in src/{base_dir}"
        );
        let body_of = |src: &str, f: &str| -> String {
            let i = src
                .find(&format!("function {f}("))
                .unwrap_or_else(|| panic!("{kind}: no {f}"));
            src[i..i + src[i..].find("\n    }\n").unwrap()].to_string()
        };
        let stmts = |body: &str| -> Vec<String> {
            body[body.find('{').unwrap() + 1..]
                .split(';')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect()
        };
        for (f, args) in [
            ("_mtxSelectorsBody", "()"),
            ("_mtxRule", "(sel)"),
            ("_uaAllowed", "(sel)"),
        ] {
            let body = body_of(&src, f);
            let o = body
                .find("override(")
                .unwrap_or_else(|| panic!("{kind}Core.{f}: no override"))
                + "override(".len();
            let over: Vec<&str> = body[o..o + body[o..].find(')').unwrap()]
                .split(',')
                .map(str::trim)
                .collect();
            assert!(
                over.contains(&format!("{base}Core").as_str()),
                "{kind}Core.{f} overrides {base}Core's: {over:?}"
            );
            assert_eq!(
                stmts(&body),
                [format!("return super.{f}{args}")],
                "{kind}Core.{f}: the base kind's, unchanged"
            );
        }
        let modules = read(&format!("src/regulated/{kind}Modules.sol"));
        assert_eq!(
            stmts(&body_of(&modules, "mtxSelectors")),
            ["return _mtxSelectorsBody()"],
            "{kind}Modules.mtxSelectors"
        );
        for file in [
            "RegulatedBase".to_string(),
            "RegulatedLib".to_string(),
            kind.to_string(),
            format!("{kind}Modules"),
        ] {
            let s = read(&format!("src/regulated/{file}.sol"));
            for f in [
                "function _mtxSelectorsBody(",
                "function _mtxRule(",
                "function _uaAllowed(",
            ] {
                assert!(
                    !s.contains(f),
                    "{file} defines {f}: {kind}'s allow-list would not be {base}Core's"
                );
            }
        }
        let p = format!("{root}/test/vectors/selector_audit.json");
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let sel = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        let class = |c: &str| -> std::collections::BTreeMap<String, String> {
            audit[c]
                .as_array()
                .unwrap_or_else(|| panic!("{c}"))
                .iter()
                .map(|r| {
                    (
                        r["sig"].as_str().unwrap().to_string(),
                        r["class"].as_str().unwrap().to_string(),
                    )
                })
                .collect()
        };
        let (k, b) = (class(kind), class(base));
        let signed =
            |m: &std::collections::BTreeMap<String, String>| -> std::collections::BTreeSet<String> {
                m.iter()
                    .filter(|(_, c)| *c == "SIGNED")
                    .map(|(s, _)| s.clone())
                    .collect()
            };
        // pay-meta-tax T40: + `mtxPayWithTax`, the regulated kinds' own signed entry (a node row on each kind's class)
        const PAY_WITH_TAX: &str = "mtxPayWithTax((bytes32,bytes32,uint256,bytes32,uint256,uint256,uint256,uint32,address,uint256,\
address),uint8,uint256,(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]),(bytes32,bytes32,bool,uint16,bytes))";
        let mut want = signed(&b);
        want.insert(PAY_WITH_TAX.to_string());
        assert_eq!(
            signed(&k),
            want,
            "{kind}: SIGNED entries are {base}'s and mtxPayWithTax, both directions"
        );
        for (s, c) in &b {
            assert_eq!(k.get(s), Some(c), "{kind}: {s} keeps {base}'s class");
        }
        let added: std::collections::BTreeMap<&String, &String> =
            k.iter().filter(|(s, _)| !b.contains_key(*s)).collect();
        // the Change of CTR-GOV-28 in round 3zb + 3zc (O6): every control takes the token's chain word last
        let controls = [
            "freeze(bytes32,bytes32,bytes32,bytes32)",
            "unfreeze(bytes32,bytes32,bytes32)",
            "forceTransfer(bytes32,uint256,bytes32)",
            "pause(bytes32,uint64,bytes32)",
            "unpause(bytes32,bytes32)",
            "recordOrder(bytes32,bytes32,bytes32,bytes32,uint256,uint64,bytes32)",
            "revokeOrder(bytes32,bytes32,bytes32)",
            "operatorTransfer(bytes32,bytes32,uint256,bytes32,bytes32)",
            // pay-meta-tax T39 / T40: bit 23's two powers, the direct payWithTax (the caller's own balance), mtxPayWithTax
            "setTaxRate(uint32,bytes32)",
            "setTaxRecipient(bytes32,bytes32)",
            "payWithTax(bytes32,uint256,uint8,uint256,bytes32,(bytes32,bytes32,bool,uint16,bytes))",
            PAY_WITH_TAX,
            // round 3s (CTR-GOV-24): the lists (bits 8, 9; on 10-13 setAllowed's row holds, no holder can exist) and the enable
            "setAllowed(bytes32[],bool,bytes32)",
            "setDenied(bytes32[],bool,bytes32)",
            "enableFeature(uint8,bytes32)",
        ];
        assert_eq!(
            added
                .keys()
                .map(|s| s.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            controls.into_iter().collect(),
            "{kind}"
        );
        for (s, c) in added.iter().filter(|(s, _)| s.as_str() != PAY_WITH_TAX) {
            assert!(
                c.starts_with("BIT(")
                    || (c.as_str() == "OWN_BALANCE" && s.starts_with("payWithTax("))
                    || (c.as_str() == "ADMIN" && s.as_str() == "enableFeature(uint8,bytes32)"),
                "{kind}: {s} is {c}"
            );
            for nk in [
                "token",
                "zether",
                "pqz",
                "wallet",
                "account",
                "dex",
                "registry",
                "factory",
                "gov_router",
            ] {
                assert!(
                    row(sel(s), nk).is_none(),
                    "{kind}: the control {s} is a {nk} row"
                );
            }
        }
        assert_eq!(rule_of(node_kind), Some(Rule::Token));
        let rows_on = |m: &std::collections::BTreeMap<String, String>| -> std::collections::BTreeSet<&'static str> {
            let s: HashSet<[u8; 4]> = signed(m).iter().map(|x| sel(x)).collect();
            typed::rows().iter().filter(|r| !r.entry.is_empty() && r.contracts.contains(&node_kind) && s.contains(&r.selector))
                .map(|r| r.name).collect()
        };
        let (rk, mut rb) = (rows_on(&k), rows_on(&b));
        assert!(!rk.is_empty(), "{kind}: no {node_kind} row");
        rb.insert("UAPayWithTax");
        assert_eq!(
            rk, rb,
            "{kind}: the {node_kind} rows are {base}'s and UAPayWithTax, both directions"
        );
        for s in signed(&k) {
            if let Some(r) = typed::rows().iter().find(|r| {
                !r.entry.is_empty() && r.contracts.contains(&node_kind) && r.selector == sel(&s)
            }) {
                assert!(
                    row(r.sent, node_kind).is_some(),
                    "{kind}: the guard refuses {}",
                    r.name
                );
            }
        }
    }

    #[test]
    fn regulated_kinds_rows_equal_contract_8() {
        regulated_kind_rows_equal_contract(
            "NormalRegulatedToken",
            "NormalToken",
            "token",
            "metatx",
        );
    }
    #[test]
    fn regulated_kinds_rows_equal_contract_9() {
        regulated_kind_rows_equal_contract(
            "WrappedRegulatedToken",
            "WrappedToken",
            "token",
            "metatx",
        );
    }
    #[test]
    fn regulated_kinds_rows_equal_contract_10() {
        regulated_kind_rows_equal_contract(
            "NormalZetherRegulatedToken",
            "NormalZetherToken",
            "zether",
            "zether",
        );
    }
    #[test]
    fn regulated_kinds_rows_equal_contract_11() {
        regulated_kind_rows_equal_contract(
            "WrappedZetherRegulatedToken",
            "WrappedZetherToken",
            "zether",
            "zether",
        );
    }
    #[test]
    fn regulated_kinds_rows_equal_contract_12() {
        regulated_kind_rows_equal_contract(
            "NormalPqzRegulatedToken",
            "NormalPqzToken",
            "pqz",
            "pqz",
        );
    }
    #[test]
    fn regulated_kinds_rows_equal_contract_13() {
        regulated_kind_rows_equal_contract(
            "WrappedPqzRegulatedToken",
            "WrappedPqzToken",
            "pqz",
            "pqz",
        );
    }

    /// Group 3f (spec §5.3): the `PqzSignedVerdict` ABI, last on every proof-carrying PQZ entry.
    const VERDICT_ABI: &str = "((address,uint256,bytes32,bytes32,bytes32,uint32,uint64),(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
    const UASIG_ABI: &str = "(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[])";
    const PQZ_PROOF_OPS: [&str; 6] = [
        "mtxConfidentialTransfer",
        "mtxConfidentialTransferCompact",
        "mtxConfidentialTransferSingle",
        "mtxConfidentialTransferSingleCompact",
        "mtxUnshield",
        "mtxUnshieldUnwrap",
    ];

    /// Group 3f (spec §5.3, §11.1, §11.3), one PQZ kind against `selector_audit.json`, both directions: its proof-carrying entries
    /// are the `SIGNED` ones that end with the verdict (`n`: ten on 4 and 12, twelve on 5 and 13), half the signed `UAEnvelope`
    /// forms and half the direct forms they self-call, and no entry of a proof op is left without it (the pre-3f selectors gone);
    /// the node's PQZ rows of those ops are exactly the signed forms (each taking the node-built verdict last, the guard allowing
    /// it on a registered PQZ token), every direct form is the inner op of a row of its name and no row of any kind; the three
    /// owner stubs are in the audit, not `SIGNED`, no row of any kind; the seven-argument `verifyTransferAmount` (a view, the
    /// forge artifact's `0xe9748a12`) is no row of any kind.
    fn pqz_verdict_rows_equal_contract(contract: &str, n: usize) {
        let p = format!(
            "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let sel = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        let entries = audit[contract]
            .as_array()
            .unwrap_or_else(|| panic!("{contract}"));
        let name = |s: &str| s[..s.find('(').unwrap()].to_string();
        let kinds = [
            "token",
            "zether",
            "pqz",
            "wallet",
            "account",
            "dex",
            "registry",
            "factory",
            "gov_router",
        ];
        let mut proof = vec![];
        for e in entries
            .iter()
            .filter(|e| PQZ_PROOF_OPS.contains(&name(e["sig"].as_str().unwrap()).as_str()))
        {
            let s = e["sig"].as_str().unwrap();
            assert_eq!(e["class"], "SIGNED", "{contract}: {s}");
            assert!(
                s.ends_with(&format!(",{VERDICT_ABI})")),
                "{contract}: {s} without the verdict last (a pre-3f selector)"
            );
            proof.push(s);
        }
        assert_eq!(proof.len(), n, "{contract}: the proof-carrying entries");
        let (signed, direct): (Vec<&str>, Vec<&str>) = proof
            .iter()
            .copied()
            .partition(|s| s[s.find('(').unwrap()..].starts_with(ENV_UA));
        assert_eq!((signed.len(), direct.len()), (n / 2, n / 2), "{contract}");
        let names: HashSet<String> = proof.iter().map(|s| name(s)).collect();
        let ours: Vec<&typed::Row> = typed::rows()
            .iter()
            .filter(|r| r.contracts.contains(&"pqz") && names.contains(r.entry))
            .collect();
        assert_eq!(
            ours.iter().map(|r| r.selector).collect::<HashSet<_>>(),
            signed.iter().map(|s| sel(s)).collect::<HashSet<_>>(),
            "{contract}: the node's PQZ debit rows are the signed forms, both directions"
        );
        for r in &ours {
            assert_eq!(
                typed::verdict_slot(r),
                Some(r.plan_len() - 1),
                "{}: the node-built verdict last",
                r.name
            );
            assert_eq!(
                row(r.sent, "pqz").map(|x| x.name),
                Some(r.name),
                "{}: allowed on a PQZ token",
                r.name
            );
        }
        for d in &direct {
            assert!(
                ours.iter().any(|r| r.entry == name(d)),
                "{contract}: {d} is the inner op of no row"
            );
            for k in kinds {
                assert!(
                    row(sel(d), k).is_none(),
                    "{contract}: the direct {d} is a {k} row"
                );
            }
        }
        let class = |s: &str| {
            entries
                .iter()
                .find(|e| e["sig"] == s)
                .map(|e| e["class"].as_str().unwrap().to_string())
        };
        let view = format!(
            "verifyTransferAmount(bytes32,uint256,uint256,uint8,uint64,bytes,{VERDICT_ABI})"
        );
        assert_eq!(
            sel(&view),
            [0xe9, 0x74, 0x8a, 0x12],
            "the forge artifact's selector"
        );
        for s in [
            "pqzSetVerifier(bytes32,bytes32)",
            "pqzCancelVerifier(bytes32)",
            "pqzRevokeVerifier(bytes32)",
            view.as_str(),
        ] {
            if !s.starts_with("verifyTransferAmount") {
                let c = class(s).unwrap_or_else(|| panic!("{contract}: {s} not in the audit"));
                assert_ne!(
                    c, "SIGNED",
                    "{contract}: {s} is the owner's own call, relayed through the router only"
                );
            }
            for k in kinds {
                assert!(row(sel(s), k).is_none(), "{contract}: {s} is a {k} row");
            }
        }
    }

    #[test]
    fn pqz_verdict_rows_equal_contract_4() {
        pqz_verdict_rows_equal_contract("NormalPqzToken", 10);
    }
    #[test]
    fn pqz_verdict_rows_equal_contract_5() {
        pqz_verdict_rows_equal_contract("WrappedPqzToken", 12);
    }
    #[test]
    fn pqz_verdict_rows_equal_contract_12() {
        pqz_verdict_rows_equal_contract("NormalPqzRegulatedToken", 10);
    }
    #[test]
    fn pqz_verdict_rows_equal_contract_13() {
        pqz_verdict_rows_equal_contract("WrappedPqzRegulatedToken", 12);
    }

    /// CTR-GOV-28: the three verifier ops and the fee op sign the token's `chainUid` last (selectors old -> new: 0x065bf7fd ->
    /// 0x690eea59, 0x681afa10 -> 0xd5c14210, 0x42242ae3 -> 0xe816ad71, 0xf0d8cbbf -> 0x280839e6).
    /// Group 3f (spec §4.2): the router's three verifier ops (and 3h T61's `UASetProofStore`) are rows of `gov_router` only, over the `UA*` structs the brief names,
    /// their selectors the forge artifact's and the router's `SIGNED` entries in `selector_audit.json`, their vectors in
    /// `typed_ops.json` (struct hash, digest and calldata pinned by `typed_ops_kat_every_entry`); fee mode `NONE` like every router
    /// op (`mode` an envelope field, nothing else to pay).
    #[test]
    fn router_pqz_verifier_rows() {
        let env = format!("{ENV_UA},");
        let want = [
            ("UAPqzSetVerifier", "mtxPqzSetVerifier", "UAPqzSetVerifier(bytes32 from,address target,bytes32 next,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
                format!("mtxPqzSetVerifier{env}address,bytes32,bytes32,{UASIG_ABI})"), [0x69, 0x0e, 0xea, 0x59]),
            ("UAPqzCancelVerifier", "mtxPqzCancelVerifier", "UAPqzCancelVerifier(bytes32 from,address target,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
                format!("mtxPqzCancelVerifier{env}address,bytes32,{UASIG_ABI})"), [0xd5, 0xc1, 0x42, 0x10]),
            ("UAPqzRevokeVerifier", "mtxPqzRevokeVerifier", "UAPqzRevokeVerifier(bytes32 from,address target,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
                format!("mtxPqzRevokeVerifier{env}address,bytes32,{UASIG_ABI})"), [0xe8, 0x16, 0xad, 0x71]),
            // group 3h T61 (PQZ proof path spec §5): bit 24's op, the same router row shape; the Change of CTR-GOV-28 in round
            // 3zb + 3zc: + the chain word (0xa63e5886 -> 0x3b127180)
            ("UASetProofStore", "mtxSetProofStore", "UASetProofStore(bytes32 from,address target,uint8 next,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
                format!("mtxSetProofStore{env}address,uint8,bytes32,{UASIG_ABI})"), [0x3b, 0x12, 0x71, 0x80]),
            // round 3t (CTR-PQZ-36): the admin's verifier fee, the same router row shape
            ("UASetVerifierFee", "mtxSetVerifierFee", "UASetVerifierFee(bytes32 from,address target,uint64 next,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)",
                format!("mtxSetVerifierFee{env}address,uint64,bytes32,{UASIG_ABI})"), [0x28, 0x08, 0x39, 0xe6]),
        ];
        let p = format!(
            "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let router: HashSet<&str> = audit["GovernanceRouter"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["class"] == "SIGNED")
            .map(|r| r["sig"].as_str().unwrap())
            .collect();
        let v = typed::testkit::vectors();
        for (name, entry, ty, sig, artifact) in &want {
            let r = typed::testkit::row_of(name, "gov_router");
            assert_eq!(
                (r.entry, r.type_string().as_str(), r.contracts),
                (*entry, *ty, &["gov_router"][..]),
                "{name}"
            );
            assert_eq!(r.selector, *artifact, "{name}: the forge artifact's {sig}");
            assert_eq!(
                alloy::primitives::keccak256(sig.as_bytes())[..4],
                r.selector[..],
                "{name}"
            );
            assert_eq!(
                row(r.sent, "gov_router").map(|x| x.name),
                Some(*name),
                "{name}: allowed on a router"
            );
            for k in [
                "token", "zether", "pqz", "wallet", "account", "dex", "registry", "factory",
            ] {
                assert!(row(r.sent, k).is_none(), "{name} is a {k} row");
            }
            assert!(
                router.contains(sig.as_str()),
                "{name}: {sig} is no SIGNED entry of the router in selector_audit.json"
            );
            assert_eq!(
                v["ops"][*name]["typeString"].as_str(),
                Some(*ty),
                "{name}: typed_ops.json's row"
            );
        }
    }

    /// Group 3l (wrap limits spec 2026-11-10 §9): the router's two ops on the hybrids are rows of `gov_router` only, over the
    /// `UA*` structs the spec names (the leg array's referenced types in EIP-712 order), their selectors the forge artifact's and
    /// `SIGNED` entries of the router in `selector_audit.json`, their vectors in `typed_ops.json`; no token row moves (the
    /// tokens' `setWrapLimits` / `setWrapMember` are governed, never on a token's allow-list). The Change of CTR-GOV-28 in round
    /// 3zb + 3zc (O5, O6): both sign the token's chain word last (selectors old -> new: `mtxSetWrapLimits` 0x6178483c ->
    /// 0x6564fc04, `mtxSetWrapMember` 0x3c0ed776 -> 0x438aef3c); round 3zc (CTR-GOV-30): the admin's two cap setters, the same
    /// row shape (`mtxSetMaxSupply` 0xf1d24225, `mtxSetMaxWrapSupply` 0xd60e02f5).
    #[test]
    fn router_wrap_limit_rows() {
        let env = format!("{ENV_UA},");
        let leg = "(address,uint8,uint16,(uint24,uint64,uint32),(uint24,uint64,uint32),(uint24,uint64,uint32),(uint24,uint64,uint32))";
        let refs = "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)WrapLimit(uint24 perUser,uint64 tokenWide,uint32 period)";
        let want = [
            ("UASetWrapLimits", "mtxSetWrapLimits",
                format!("UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient){refs}"),
                format!("mtxSetWrapLimits{env}address,{leg}[],bool,bool,bool,bytes32,{UASIG_ABI})"), [0x65, 0x64, 0xfc, 0x04]),
            ("UASetWrapMember", "mtxSetWrapMember",
                "UASetWrapMember(bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)".to_string(),
                format!("mtxSetWrapMember{env}address,bytes32,bool,bool,bytes32,{UASIG_ABI})"), [0x43, 0x8a, 0xef, 0x3c]),
            ("UASetMaxSupply", "mtxSetMaxSupply",
                "UASetMaxSupply(bytes32 from,address target,uint256 maxSupply,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)".to_string(),
                format!("mtxSetMaxSupply{env}address,uint256,bytes32,{UASIG_ABI})"), [0xf1, 0xd2, 0x42, 0x25]),
            ("UASetMaxWrapSupply", "mtxSetMaxWrapSupply",
                "UASetMaxWrapSupply(bytes32 from,address target,uint256 maxWrapSupply,bytes32 chainUid,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)".to_string(),
                format!("mtxSetMaxWrapSupply{env}address,uint256,bytes32,{UASIG_ABI})"), [0xd6, 0x0e, 0x02, 0xf5]),
        ];
        let p = format!(
            "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let router: HashSet<&str> = audit["GovernanceRouter"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["class"] == "SIGNED")
            .map(|r| r["sig"].as_str().unwrap())
            .collect();
        let v = typed::testkit::vectors();
        for (name, entry, ty, sig, artifact) in &want {
            let r = typed::testkit::row_of(name, "gov_router");
            assert_eq!(
                (r.entry, r.type_string().as_str(), r.contracts),
                (*entry, ty.as_str(), &["gov_router"][..]),
                "{name}"
            );
            assert_eq!(r.selector, *artifact, "{name}: the forge artifact's {sig}");
            assert_eq!(
                alloy::primitives::keccak256(sig.as_bytes())[..4],
                r.selector[..],
                "{name}"
            );
            assert_eq!(
                row(r.sent, "gov_router").map(|x| x.name),
                Some(*name),
                "{name}: allowed on a router"
            );
            for k in [
                "token", "zether", "pqz", "wallet", "account", "dex", "registry", "factory",
            ] {
                assert!(row(r.sent, k).is_none(), "{name} is a {k} row");
            }
            assert!(
                router.contains(sig.as_str()),
                "{name}: {sig} is no SIGNED entry of the router in selector_audit.json"
            );
            assert_eq!(
                v["ops"][*name]["typeString"].as_str(),
                Some(ty.as_str()),
                "{name}: typed_ops.json's row"
            );
        }
    }

    /// The Change of CTR-GOV-28 in round 3zb + 3zc (O3, O5, O6, spec 2026-11-13-burner-wrap-caps.md §3.5, §3.8, §3.9, §4): every
    /// role holder's direct entry and the admin's `setWrapLimits` take the chain word last, keep their class in
    /// `selector_audit.json` (the old forms gone), and are no row of any kind (relayed through the router only); the two new cap
    /// setters are `ADMIN` on the six wrapped kinds, never on a token's allow-list.
    #[test]
    fn chain_word_entries_are_governed_and_no_row() {
        let p = format!(
            "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let class = |c: &str, s: &str| {
            audit[c]
                .as_array()
                .unwrap_or_else(|| panic!("{c}"))
                .iter()
                .find(|e| e["sig"] == s)
                .map(|e| e["class"].as_str().unwrap().to_string())
        };
        let leg = "(address,uint8,uint16,(uint24,uint64,uint32),(uint24,uint64,uint32),(uint24,uint64,uint32),(uint24,uint64,uint32))";
        let limits = format!("setWrapLimits({leg}[],bool,bool,bool,bytes32)");
        let any_token = [
            ("mint(address,uint256,bytes32)", "BIT(1)"),
            ("mintToUA(bytes32,uint256,bytes32)", "BIT(1)"),
        ];
        let wrapped = [
            ("disableWrap(address,bytes32,bytes32)", "BIT(4)"),
            ("proposeRate(address,uint96,uint96,bytes32)", "BIT(3)"),
            ("cancelRate(bytes32)", "BIT(3)"),
            ("executeRate(bytes32)", "BIT(3)"),
            ("setWrapMember(bytes32,bool,bool,bytes32)", "BIT(26)"),
            (limits.as_str(), "ADMIN"),
            ("setMaxSupply(uint256,bytes32)", "ADMIN"),
            ("setMaxWrapSupply(uint256,bytes32)", "ADMIN"),
        ];
        let dex = [
            ("setMarket(address,address,bool,bytes32)", "BIT(11)"),
            ("setExchangeTarget(address,bool,bytes32)", "BIT(11)"),
            ("setListedOnly(bool,bytes32)", "BIT(11)"),
            ("setFeeSplit(uint32,address,bytes32)", "BIT(12)"),
        ];
        let gone = [
            "mint(address,uint256)",
            "mintToUA(bytes32,uint256)",
            "disableWrap(address,bytes32)",
            "cancelRate()",
            "executeRate()",
            "setWrapMember(bytes32,bool,bool)",
            "setProofStore(uint8)",
            "setMarket(address,address,bool)",
            "setFeeSplit(uint32,address)",
        ];
        let mut checked = vec![];
        for (c, _) in AUDIT_KINDS
            .iter()
            .filter(|(c, k)| matches!(*k, "token" | "zether" | "pqz") && c.ends_with("Token"))
        {
            let mut want: Vec<(&str, &str)> = any_token.to_vec();
            if c.starts_with("Wrapped") {
                want.extend(wrapped.iter().copied());
            }
            for (s, cl) in &want {
                assert_eq!(class(c, s).as_deref(), Some(*cl), "{c}: {s}");
            }
            assert_eq!(
                class(c, "setMaxSupply(uint256,bytes32)").is_some(),
                c.starts_with("Wrapped"),
                "{c}: the cap setters on the wrapped kinds only"
            );
            checked.extend(want.iter().map(|(s, _)| s.to_string()));
            for s in gone {
                assert_eq!(class(c, s), None, "{c}: the old {s}");
            }
        }
        assert_eq!(
            AUDIT_KINDS
                .iter()
                .filter(|(c, _)| c.starts_with("Wrapped") && c.ends_with("Token"))
                .count(),
            6
        );
        for (s, cl) in dex {
            assert_eq!(class("SCaaSDex", s).as_deref(), Some(cl), "SCaaSDex: {s}");
            checked.push(s.to_string());
        }
        let sel = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        for s in &checked {
            for k in [
                "token",
                "zether",
                "pqz",
                "wallet",
                "account",
                "dex",
                "registry",
                "factory",
                "gov_router",
            ] {
                assert!(row(sel(s), k).is_none(), "{s} is a {k} row");
            }
        }
    }

    /// Group 3h T61 / T63 (spec §10): bit 24's router op both directions: `UASetProofStore` is a row of `gov_router` only, its
    /// selector the forge artifact's and a `SIGNED` entry of the router in `selector_audit.json`; the token's own
    /// `setProofStore(uint8)` (`BIT(24)` on the four PQZ kinds) is no row on any kind (relayed through the router only).
    #[test]
    fn proof_store_router_row_equal_contract() {
        // the Change of CTR-GOV-28 in round 3zb + 3zc: + the chain word (router 0xa63e5886 -> 0x3b127180; direct
        // `setProofStore(uint8)` -> `setProofStore(uint8,bytes32)`)
        let sig = format!("mtxSetProofStore{ENV_UA},address,uint8,bytes32,{UASIG_ABI})");
        let r = typed::testkit::row_of("UASetProofStore", "gov_router");
        assert_eq!(
            (r.entry, r.contracts),
            ("mtxSetProofStore", &["gov_router"][..])
        );
        assert_eq!(
            r.selector,
            [0x3b, 0x12, 0x71, 0x80],
            "the forge artifact's {sig}"
        );
        assert_eq!(
            alloy::primitives::keccak256(sig.as_bytes())[..4],
            r.selector[..]
        );
        assert_eq!(
            row(r.sent, "gov_router").map(|x| x.name),
            Some("UASetProofStore")
        );
        let p = format!(
            "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let audit: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        let class = |c: &str, s: &str| {
            audit[c]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["sig"] == s)
                .map(|e| e["class"].as_str().unwrap().to_string())
        };
        assert_eq!(class("GovernanceRouter", &sig).as_deref(), Some("SIGNED"));
        let direct = alloy::primitives::keccak256(b"setProofStore(uint8,bytes32)");
        for c in [
            "NormalPqzToken",
            "WrappedPqzToken",
            "NormalPqzRegulatedToken",
            "WrappedPqzRegulatedToken",
        ] {
            assert_eq!(
                class(c, "setProofStore(uint8,bytes32)").as_deref(),
                Some("BIT(24)"),
                "{c}"
            );
        }
        for k in [
            "token",
            "zether",
            "pqz",
            "wallet",
            "account",
            "dex",
            "registry",
            "factory",
            "gov_router",
        ] {
            assert!(
                row(direct[..4].try_into().unwrap(), k).is_none(),
                "setProofStore is a {k} row"
            );
            if k != "gov_router" {
                assert!(row(r.sent, k).is_none(), "UASetProofStore is a {k} row");
            }
        }
    }

    /// Counted from the two files outside this code (python over `selector_audit.json` and `typed_ops.json`): 229 `SIGNED` entries
    /// of the eight contracts, 127 of them rows (120 vector rows, the token's invalidation, the DEX's six plain entries and its
    /// invalidation); 91 governance entries. Plan T32: (127, 102, 91) -> (234, 202, 217): + the router's eight regulated
    /// controls (rowed) and the six regulated kinds 8-13 (their base kind's entries again, and eight `BIT` controls each):
    /// 436 `SIGNED` entries of the fourteen contracts, 217 governance entries (python over `selector_audit.json`).
    // pay-meta-tax T42: (234, 202, 217) -> (254, 178, 229), measured: mtxPay a row (no longer in NOT_ROWS), mtxPayWithTax on the
    // six regulated kinds, the router's two tax ops, the six kinds' two bit-23 powers governed (12)
    // group 3f T45 / T47: (254, 181, 229) -> (257, 181, 241), expected from the contracts: the router's three verifier ops rowed, the
    // three owner stubs (`pqzSetVerifier`, `pqzCancelVerifier`, `pqzRevokeVerifier`) governed on each of the four PQZ kinds; the
    // twelve proof entries of 5 and 13 (ten of 4 and 12) moved selector in place (rowed or exempt as before)
    // group 3h T61: (257, 181, 241) -> (258, 181, 245): the router's `mtxSetProofStore` rowed; `setProofStore` governed (bit 24) on
    // each of the four PQZ kinds
    // group 3l: (258, 181, 245) -> (260, 181, 257): the router's `mtxSetWrapLimits`, `mtxSetWrapMember` rowed; the tokens'
    // `setWrapLimits` (ADMIN) and `setWrapMember` (BIT(26)) governed on each of the six wrapped kinds
    // ua-mtx-liquidity L6: ROWED -> 261 (the DEX's `mtxLiquidity`), EXEMPT 181 -> 193 (`mtxLiquidityPull` on the twelve
    // kinds, NOT_ROWS)
    // round 3r (CTR-GOV-23): (261, 193, 257) -> (272, 200, 274), measured and counted from selector_audit.json: the router's
    // eleven admin ops rowed; its four release approvals and `OpenFactory`'s three open deploys in NOT_ROWS; `OpenFactory`'s
    // 17 `ADMIN` / `HOLDER_OWN` entries governed
    // round 3s (CTR-GOV-24): (272, 200, 274) -> (275, 200, 292), measured and counted from selector_audit.json: the router's three
    // list / enable ops rowed (SIGNED); the six regulated kinds' setAllowed BIT(8), setDenied BIT(9), enableFeature ADMIN governed;
    // round 3t (CTR-PQZ-36): -> (276, 200, 296): the router's `mtxSetVerifierFee` rowed; `setVerifierFee` (ADMIN) governed on each
    // of the four PQZ kinds
    // Fable E N-10: 276 -> 286, the registry's eight SIGNED rows and the two PERMISSIONLESS ones (`storePqzPop`, `deploy`)
    // owner 2026-11-12: -> 288, the router's `mtxCreateToken`, `mtxCreateDex`; EXEMPT 200 -> 198
    // owner 2026-11-12 (GUARDIAN): -> 296, the account's eight rows; EXEMPT -> 207, its six self-called operations and its three
    // generic entries; GOVERNED -> 297, its guardian's `initiateRecovery`
    // owner 2026-11-12 (both the generic row and the per-class ones): -> 297, the router's `mtxCreateInstance`; EXEMPT -> 206
    // the three-key model: -> 303, `mtxRollOverSigned` on the four PQZ kinds (row `PqzRollOver`), the registry's
    // `setPqzScopedKey` (SIGNED) and `storePqzScopedPop` (PERMISSIONLESS)
    // round 3zb + 3zc: -> 305, the router's `mtxSetMaxSupply`, `mtxSetMaxWrapSupply`; GOVERNED 297 -> 309, `setMaxSupply`,
    // `setMaxWrapSupply` (ADMIN) on each of the six wrapped kinds (expected from the contracts; the 25 ops of the Change of
    // CTR-GOV-28 and their direct entries moved selector in place, their classes kept)
    // CTR-UA-44 (TODO 3ze): -> 306, the registry's `updateMsig` (SIGNED)
    // NODE-JOB-29 (TODO 3zh MD-14): -> 307, the registry's `cacheExpandedKey` (PERMISSIONLESS)
    // set-auditor (CTR-GOV-31): -> 309, the router's `mtxSetAuditorKey`, `mtxSetAuditorUA`; GOVERNED 309 -> 317, `setAuditorKey`
    // BIT(32) on the Zether kinds 2, 3, 10, 11 and `setAuditorUA` BIT(32) on the PQZ kinds 4, 5, 12, 13
    // bls-multi Task 10: -> 310, the registry's `registerBlsMulti` (SIGNED); CTR-GOV-33 Change: -> 311, the router's
    // `mtxCancelNonceFor` (SIGNED)
    const ROWED: usize = 311;
    // ua-mtx-merge T76: EXEMPT 178 -> 181, the router's three creations (NOT_ROWS)
    const EXEMPT: usize = 206;
    const GOVERNED: usize = 317;

    /// As [`bound`], `registry()` answering `registry` (`Address::ZERO`: the UA ledger off, R9).
    async fn bound_with_registry(uid: B256, registry: Address) -> ChainCfg {
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(
                move |axum::Json(r): axum::Json<serde_json::Value>| async move {
                    if let Some(b) = block0_of(&r, uid, 31337) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": b}),
                        );
                    }
                    let input = r["params"][0]["input"]
                        .as_str()
                        .or(r["params"][0]["data"].as_str())
                        .unwrap_or("0x")
                        .to_string();
                    let reg = format!(
                        "0x{}",
                        alloy::hex::encode(IUALedger::registryCall::SELECTOR)
                    );
                    let to: Address = r["params"][0]["to"]
                        .as_str()
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or_default();
                    let result = match r["method"].as_str().unwrap() {
                        "eth_call" if input.starts_with(&reg) => {
                            serde_json::json!(format!("{:#x}", registry.into_word()))
                        }
                        "eth_call" if typed::testkit::domain_answer(&input, to).is_some() => {
                            serde_json::json!(typed::testkit::domain_answer(&input, to))
                        }
                        "eth_call" => serde_json::json!(format!("{uid:#x}")),
                        "eth_getCode" => serde_json::json!("0x"),
                        _ => serde_json::Value::Null,
                    };
                    axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": result}),
                    )
                },
            ),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        ChainCfg {
            evm_chain_number: 31337,
            rpc_urls: vec![url],
            chain_uid: Some(uid),
            ..Default::default()
        }
    }

    /// The named rows and a `ua_metatx` transfer struct job, at `registry() == 0` on a registered, bound token.
    async fn at_registry_zero(v: &serde_json::Value) -> (Chain, Guard) {
        let uid: B256 = v["ops"]["UAUnwrap"]["domains"]["token"]["domain"]["salt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let cfg = bound_with_registry(uid, Address::ZERO).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        (
            chain,
            Guard::new(&cfg, Arc::new(RwLock::new(vec![]))).unwrap(),
        )
    }

    fn ua_transfer_job(from: B256, to: B256) -> crate::external_pull::Job {
        let z = format!("{:#x}", Address::ZERO);
        serde_json::from_value(serde_json::json!({"id": 1, "kind": "ua_metatx", "token": format!("{:#x}", Address::repeat_byte(0x70)),
            "struct": "transfer", "m": {"from": format!("{from:#x}"), "to": format!("{to:#x}"), "value": "1", "entryRef": format!("{:#x}", B256::ZERO),
            "batch": "0", "nonce": "0", "validUntil": "4000000000", "mode": 0, "relayer": z, "fee": "0", "feeRecipient": z},
            "auth": {"keyData": "0x", "signature": format!("0x{}", "11".repeat(65)), "members": []}})).unwrap()
    }

    /// R9 / R44 (C): an all-native merged entry (`from`, and `to` where there is one, native ids) runs on a token whose
    /// `registry()` is 0: the guard asks no registry. Named rows from the vectors (their signer recovers), a struct job of two EOAs.
    #[tokio::test]
    async fn an_all_native_ua_metatx_runs_at_registry_zero() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let (chain, _) = at_registry_zero(&v).await;
        for (name, kind) in [
            ("UAUnwrap", "token"),
            ("UABurn", "zether"),
            ("UAShield", "pqz"),
            ("UACancelNonce", "token"),
            ("Wrap", "token"),
        ] {
            let (w, _) =
                crate::submit::work_of_op(Some(1), &op_of(name, kind, &v).unwrap(), None).unwrap();
            let g = Guard::new(
                &ChainCfg {
                    rpc_urls: vec![],
                    ..Default::default()
                },
                Arc::new(RwLock::new(vec![w.to])),
            )
            .unwrap();
            g.check(&chain, &w)
                .await
                .unwrap_or_else(|e| panic!("{name} on {kind}: {e:?}"));
        }
        let (a, b) = (
            Address::repeat_byte(0xa1).into_word(),
            Address::repeat_byte(0xb2).into_word(),
        );
        let mut w = crate::submit::work_from_job(&ua_transfer_job(a, b), None).unwrap();
        w.typed.as_mut().unwrap().signer = None;
        let g = Guard::new(&ChainCfg::default(), Arc::new(RwLock::new(vec![w.to]))).unwrap();
        g.check(&chain, &w)
            .await
            .unwrap_or_else(|e| panic!("an EOA to an EOA: {e:?}"));
    }

    /// Fable E N-6: the op's `contract` picks the digest's domain, so on a token it must be the token's own kind: a `UAUnwrap`
    /// named `pqz` on a `SCaaS MetaToken` is `CONTRACT_KIND_MISMATCH` (`Policy`, `dead`), before any simulation; named `token` it
    /// passes (the control). The name is read once per token; an unreachable RPC is `Transport`, nothing cached.
    #[tokio::test]
    async fn the_op_contract_is_the_token_domain_kind() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let (chain, _) = at_registry_zero(&v).await;
        let (w, _) =
            crate::submit::work_of_op(Some(1), &op_of("UAUnwrap", "token", &v).unwrap(), None)
                .unwrap();
        let g = Guard::new(&ChainCfg::default(), Arc::new(RwLock::new(vec![w.to]))).unwrap();
        g.check(&chain, &w)
            .await
            .unwrap_or_else(|e| panic!("control: {e:?}"));
        assert_eq!(
            g.domain_names
                .lock()
                .unwrap()
                .get(&w.to)
                .map(String::as_str),
            Some("SCaaS MetaToken"),
            "read once, kept"
        );
        for kind in ["pqz", "zether"] {
            let mut x = w.clone();
            x.typed.as_mut().unwrap().contract = kind;
            match g.check(&chain, &x).await {
                Err(Refusal::Policy(e)) => assert!(
                    e.starts_with("CONTRACT_KIND_MISMATCH: contract")
                        && e.contains("SCaaS MetaToken"),
                    "{kind}: {e}"
                ),
                r => panic!("{kind}: {r:?}"),
            }
        }
        let down = Chain::with_signer(
            &ChainCfg {
                evm_chain_number: 31337,
                rpc_urls: vec!["http://127.0.0.1:9".into()],
                chain_uid: chain_uid_of(&v),
                ..Default::default()
            },
            signer(),
        )
        .unwrap();
        let g2 = Guard::new(&ChainCfg::default(), Arc::new(RwLock::new(vec![w.to]))).unwrap();
        g2.bound.lock().unwrap().insert(w.to);
        assert!(matches!(
            g2.require_kind(&down, w.to, "token").await,
            Err(Refusal::Transport(_))
        ));
        assert!(
            g2.domain_names.lock().unwrap().is_empty(),
            "an unread name is not kept"
        );
        // Fable recheck 2 P3-2: a name that matched no kind asked for is not kept (one wrong answer never sticks)
        let g3 = Guard::new(&ChainCfg::default(), Arc::new(RwLock::new(vec![w.to]))).unwrap();
        let mut x = w.clone();
        x.typed.as_mut().unwrap().contract = "pqz";
        assert!(g3.check(&chain, &x).await.is_err());
        assert!(
            g3.domain_names.lock().unwrap().is_empty(),
            "a mismatching answer is read again next time"
        );
        g3.check(&chain, &w).await.unwrap();
        assert!(
            g3.domain_names.lock().unwrap().contains_key(&w.to),
            "control: a match is kept"
        );
    }

    fn chain_uid_of(v: &serde_json::Value) -> Option<B256> {
        v["ops"]["UAUnwrap"]["domains"]["token"]["domain"]["salt"]
            .as_str()
            .unwrap()
            .parse()
            .ok()
    }

    /// R44: a derived `from` or `to` needs the UA ledger: at `registry() == 0` it is refused by name (`FEATURE_UNSUPPORTED`)
    /// before any simulation: the vector's `UAUnwrapToUA` and `WrapToUA` (a native payer, a derived `to`), a derived payer's
    /// `UABurn`, and a struct job to or from a derived UA.
    #[tokio::test]
    async fn a_derived_side_at_registry_zero_is_refused_by_name() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let (chain, _) = at_registry_zero(&v).await;
        let derived = B256::repeat_byte(0xaa);
        let mut burn = op_of("UABurn", "token", &v).unwrap();
        burn["envelope"]["from"] = serde_json::json!(format!("{derived:#x}"));
        let mut works = vec![];
        for op in [
            op_of("UAUnwrapToUA", "token", &v).unwrap(),
            op_of("WrapToUA", "token", &v).unwrap(),
            burn,
        ] {
            works.push(crate::submit::work_of_op(Some(1), &op, None).unwrap().0);
        }
        let native = Address::repeat_byte(0xa1).into_word();
        for (f, t) in [(native, derived), (derived, native)] {
            let mut w = crate::submit::work_from_job(&ua_transfer_job(f, t), None).unwrap();
            w.typed.as_mut().unwrap().signer = None;
            works.push(w);
        }
        for w in works {
            let g = Guard::new(&ChainCfg::default(), Arc::new(RwLock::new(vec![w.to]))).unwrap();
            let e = g.check(&chain, &w).await.unwrap_err();
            assert!(
                matches!(&e, Refusal::Policy(r) if r.starts_with("FEATURE_UNSUPPORTED") && r.contains("registry() = 0")),
                "{e:?}"
            );
        }
    }

    /// B (ua-mtx-merge): a derived subject reaches `_uaAllowed` only, and the merged entries are exactly the rows whose operation is on
    /// it: a derived signer on a merged row passes (the UA ledger on), on an address row (a wrap, `SmartKeyAccount`'s, the DEX's) it is
    /// refused by name before any read. The address rows cannot carry a derived `from` in a parsed op (it is an `address`), so the
    /// rule is fail-closed defence: the `Typed` flag set by hand here is what a future row with a `bytes32` subject would set.
    #[tokio::test]
    async fn a_derived_subject_signs_merged_entries_only() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let uid: B256 = v["ops"]["UAUnwrap"]["domains"]["token"]["domain"]["salt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let (cfg, seen) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        for (name, kind, merged) in [
            ("UAUnwrap", "token", true),
            ("UASetPayee", "wallet", true),
            ("Wrap", "token", false),
            ("AddKey", "account", false),
            ("CancelNonce", "account", false),
        ] {
            let (mut w, _) =
                crate::submit::work_of_op(Some(1), &op_of(name, kind, &v).unwrap(), None).unwrap();
            let t = w.typed.as_mut().unwrap();
            assert!(!t.derived_signer, "{name}: the vector's signer is native");
            (t.derived_signer, t.derived_side, t.signer) = (true, true, None);
            let g = Guard::new(
                &cfg,
                Arc::new(RwLock::new(if kind == "token" {
                    vec![w.to]
                } else {
                    vec![]
                })),
            )
            .unwrap();
            seen.lock().unwrap().clear();
            match (merged, g.check(&chain, &w).await) {
                (true, r) => r.unwrap_or_else(|e| panic!("{name}: {e:?}")),
                (false, Err(Refusal::Policy(r))) => {
                    assert!(
                        r.starts_with("CALL_TARGET_REFUSED") && r.contains("derived subject"),
                        "{name}: {r}"
                    );
                    assert!(
                        seen.lock().unwrap().is_empty(),
                        "{name}: before any chain read"
                    );
                }
                (false, r) => panic!("{name}: {r:?}"),
            }
        }
    }

    /// The router rule on a relay fee's inner call, both directions (spec §12.7): a router op relayed to one of `governance_routers`
    /// passes; the same op relayed to another bound contract, and a non-router call relayed to a router, are refused by name; a cancel
    /// the token has too stays the token's.
    #[test]
    fn a_router_op_relayed_through_the_relay_fee_checks_the_inner_target() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let router = Address::repeat_byte(0x9a);
        let other = Address::repeat_byte(0x9b);
        let inner = |name: &str, kind: &str| {
            crate::typed::Op::parse(&op_of(name, kind, &v).unwrap(), None)
                .unwrap()
                .data
        };
        let relay = |to: Address, call: Bytes| {
            IRelayFeeRouter::relayCall {
                target: to,
                callData: call,
                token: Address::repeat_byte(1),
                from: B256::repeat_byte(2),
                payee: B256::repeat_byte(3),
                value: alloy::primitives::U256::from(1),
                batch: alloy::primitives::U256::from(7),
                nonce: alloy::primitives::U256::ZERO,
                validUntil: alloy::primitives::U256::from(4_000_000_000u64),
                auth: crate::abi::UASig {
                    keyData: Bytes::new(),
                    signature: Bytes::new(),
                    members: vec![],
                },
            }
            .abi_encode()
        };
        let grant = inner("UAGrantRole", "gov_router");
        relay_inner_ok(&[router], &relay(router, grant.clone())).unwrap();
        let e = relay_inner_ok(&[router], &relay(other, grant.clone())).unwrap_err();
        assert!(
            e.starts_with("CALL_TARGET_REFUSED") && e.contains("not one of governance_routers"),
            "{e}"
        );
        assert!(
            relay_inner_ok(&[], &relay(router, grant)).is_err(),
            "no router configured: refused"
        );
        let burn = inner("UABurn", "token");
        let e = relay_inner_ok(&[router], &relay(router, burn.clone())).unwrap_err();
        assert!(e.contains("no named entry of it"), "{e}");
        relay_inner_ok(&[router], &relay(other, burn)).unwrap();
        let cancel = inner("UACancelNonce", "token");
        relay_inner_ok(&[router], &relay(router, cancel.clone())).unwrap();
        relay_inner_ok(&[router], &relay(other, cancel)).unwrap();
    }

    /// The same rule where it runs, the guard's relay branch: a relay fee whose inner call is a router op passes on a configured router
    /// and is refused on any other bound contract; with no `governance_routers` it is refused (spec §12.7: "on the inner target of
    /// `RelayFeeRouter.relayCall`", one form since ua-mtx-merge R28).
    #[tokio::test]
    async fn the_guards_relay_branch_runs_the_router_rule() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let uid = B256::repeat_byte(0x31);
        let (cfg, _) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (rf, token, router) = (
            Address::repeat_byte(0xf4),
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x9a),
        );
        let mut params = toml::Table::new();
        params.insert(
            "relay_fee".into(),
            toml::Value::Table(
                [(
                    "router".to_string(),
                    toml::Value::String(format!("{rf:#x}")),
                )]
                .into_iter()
                .collect(),
            ),
        );
        let grant = crate::typed::Op::parse(&op_of("UAGrantRole", "gov_router", &v).unwrap(), None)
            .unwrap()
            .data;
        let work = |target: Address| {
            let data = IRelayFeeRouter::relayCall {
                target,
                callData: grant.clone(),
                token,
                from: B256::repeat_byte(2),
                payee: rf.into_word(),
                value: alloy::primitives::U256::from(1),
                batch: alloy::primitives::U256::from(7),
                nonce: alloy::primitives::U256::ZERO,
                validUntil: alloy::primitives::U256::from(4_000_000_000u64),
                auth: crate::abi::UASig {
                    keyData: Bytes::new(),
                    signature: Bytes::new(),
                    members: vec![],
                },
            }
            .abi_encode();
            let t = typed::Typed {
                pay_meta_len: 0,
                pqz_parties: vec![],
                pqz_auditor: false,
                pqz_verdict: None,
                pqz_fee: None,
                contract: "token",
                domain_of: token,
                struct_hash: None,
                lane_hash: None,
                signer: None,
                payee: None,
                digest: None,
                derived_signer: false,
                derived_side: false,
            };
            Work {
                job_id: Some(1),
                to: rf,
                data: data.into(),
                valid_until: 0,
                envelope_until: 0,
                meta: None,
                entry: true,
                typed: Some(t),
            }
        };
        let g = |routers: Vec<Address>| {
            Guard::new(
                &ChainCfg {
                    params: params.clone(),
                    governance_routers: routers,
                    ..cfg.clone()
                },
                Arc::new(RwLock::new(vec![token])),
            )
            .unwrap()
        };
        g(vec![router]).check(&chain, &work(router)).await.unwrap();
        for (guard, target, what) in [
            (
                g(vec![router]),
                Address::repeat_byte(0x9b),
                "another contract",
            ),
            (g(vec![]), router, "no router"),
        ] {
            let e = guard.check(&chain, &work(target)).await.unwrap_err();
            assert!(
                matches!(&e, Refusal::Policy(r) if r.contains("not one of governance_routers")),
                "{what}: {e:?}"
            );
        }
    }

    /// A router job on its chain, through the guard (spec §12.7): passes on a configured router, bound; refused with no
    /// `governance_routers`, on another address, on a router not bound to this chain; a cancel claimed as a wallet's on the router
    /// address is refused (a router takes its own rows only); a forged signature on a codeless signer is `BAD_SIGNATURE`.
    #[tokio::test]
    async fn a_router_job_runs_only_on_a_configured_router() {
        use crate::typed::testkit::{op_of, vectors};
        let v = vectors();
        let uid: B256 = v["ops"]["UAGrantRole"]["domains"]["gov_router"]["domain"]["salt"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let (cfg, _) = bound(uid).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let (w, _) = crate::submit::work_of_op(
            Some(1),
            &op_of("UAGrantRole", "gov_router", &v).unwrap(),
            None,
        )
        .unwrap();
        let at = |routers: Vec<Address>| {
            Guard::new(
                &ChainCfg {
                    governance_routers: routers,
                    ..cfg.clone()
                },
                Default::default(),
            )
            .unwrap()
        };
        at(vec![w.to]).check(&chain, &w).await.unwrap();
        at(vec![Address::repeat_byte(0x5c), w.to])
            .check(&chain, &w)
            .await
            .unwrap_or_else(|e| panic!("a second router is a config row: {e:?}"));
        for (g, what) in [
            (at(vec![]), "no governance_routers"),
            (at(vec![Address::repeat_byte(0x5c)]), "another router"),
        ] {
            let e = g.check(&chain, &w).await.unwrap_err();
            assert!(
                matches!(&e, Refusal::Policy(r) if r.starts_with("CALL_TARGET_REFUSED")),
                "{what}: {e:?}"
            );
        }
        let (other_uid, _) = bound(B256::repeat_byte(0x77)).await;
        let unbound = Chain::with_signer(
            &ChainCfg {
                chain_uid: Some(uid),
                ..other_uid
            },
            signer(),
        )
        .unwrap();
        assert!(
            at(vec![w.to]).check(&unbound, &w).await.is_err(),
            "a router whose chainUid() differs"
        );
        let mut cancel = op_of("UACancelNonce", "wallet", &v).unwrap();
        cancel["token"] = serde_json::json!(format!("{:#x}", w.to));
        let (cw, _) = crate::submit::work_of_op(Some(1), &cancel, None).unwrap();
        let e = at(vec![w.to]).check(&chain, &cw).await.unwrap_err();
        assert!(
            matches!(&e, Refusal::Policy(r) if r.starts_with("CALL_TARGET_REFUSED")),
            "{e:?}"
        );
        let mut forged = op_of("UAGrantRole", "gov_router", &v).unwrap();
        forged["auth"]["signature"] =
            v["ops"]["UARevokeRole"]["domains"]["gov_router"]["signature"].clone();
        let (fw, _) = crate::submit::work_of_op(Some(1), &forged, None).unwrap();
        let e = at(vec![fw.to]).check(&chain, &fw).await.unwrap_err();
        assert!(
            matches!(&e, Refusal::Policy(r) if r.starts_with("BAD_SIGNATURE")),
            "{e:?}"
        );
    }

    /// Spec §9 / R8 (T17 fix 1): the floor covers forge's measured minimum relayer call gas of a `SmartKeyAccount`-signed
    /// `mtxExecute` (two frames above the ERC-1271 call), the intrinsic 21,000, the job's calldata at 64 gas a byte and
    /// a 10 % margin.
    #[test]
    fn erc1271_floor_covers_forge_minimum() {
        let log = std::fs::read_to_string(format!(
            "{}/../smartcontracts/evm/runs/2026-11-12-fix2-contracts-node-floor.txt",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let tag = "min gas, SmartKeyAccount-signed mtxExecute (relayer's call gas):";
        let measured: u64 = log
            .lines()
            .find_map(|l| l.trim().strip_prefix(tag))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(
            measured, ERC1271_CALL_GAS,
            "the forge figure (B P3-2: ERC-7739)"
        );
        const {
            assert!(
                ERC1271_CALL_GAS >= (400_000 * 64 / 63 + 5_000) * 64 / 63,
                "two frames above the 400 k cap"
            )
        };
        for len in [0usize, 708, 4_000] {
            let f = erc1271_floor(len);
            assert!(
                f >= 21_000 + 64 * len as u64 + measured + measured / 10,
                "{len}: {f}"
            );
        }
        assert_eq!(erc1271_floor(0), 512_603);
        assert_eq!(erc1271_floor(708), 512_603 + 45_312);
    }

    #[test]
    fn gas_floor_and_settle_sizing() {
        let fl = erc1271_floor(100);
        let ams = |limit| BlockGas {
            limit,
            amsterdam: true,
            base_fee: None,
        };
        let cap = total_cap(u64::MAX, ams(200_000_000));
        assert_eq!(gas_limit(100_000, 0, cap), 120_000);
        assert_eq!(gas_limit(100_000, fl, cap), fl);
        assert_eq!(gas_limit(1_000_000, fl, cap), 1_200_000);
        assert_eq!(
            gas_limit(MAX_TX_GAS, 0, cap),
            MAX_TX_GAS + MAX_TX_GAS / 5,
            "Amsterdam: a limit past 2^24 is kept"
        );
        assert_eq!(
            gas_limit(190_000_000, 0, cap),
            200_000_000,
            "the padded estimate is clamped to the cap"
        );
        assert_eq!(
            gas_limit(u64::MAX, fl, total_cap(u64::MAX, ams(u64::MAX))),
            MAX_TX_TOTAL_GAS,
            "EIP-8037: 2^32 - 1"
        );
        assert_eq!(
            total_cap(50_000_000, ams(30_000_000)),
            30_000_000,
            "the block gas limit binds"
        );
        assert_eq!(
            total_cap(50_000_000, ams(200_000_000)),
            50_000_000,
            "max_gas_per_tx binds"
        );
        let osaka = BlockGas {
            limit: 200_000_000,
            amsterdam: false,
            base_fee: None,
        };
        assert_eq!(
            total_cap(50_000_000, osaka),
            MAX_TX_GAS,
            "before Amsterdam the whole limit stays under 2^24"
        );
        assert_eq!(
            gas_limit(MAX_TX_GAS, 0, total_cap(u64::MAX, osaka)),
            MAX_TX_GAS
        );
        assert_eq!(
            calldata_floor(220_415),
            14_121_560,
            "measured on the SCaaS testnet"
        );
        assert!(
            calldata_floor(261_909) <= MAX_TX_GAS && calldata_floor(261_910) > MAX_TX_GAS,
            "261,909 B per transaction"
        );
        assert_eq!(next_gas(1_000, 3_000), Some(1_500));
        assert_eq!(next_gas(2_500, 3_000), Some(3_000));
        assert_eq!(next_gas(3_000, 3_000), None);
        let ok = |v: Vec<bool>| <Vec<bool> as SolValue>::abi_encode(&v);
        assert!(settled_all(&ok(vec![true, true])));
        assert!(
            !settled_all(&ok(vec![true, false])),
            "an empty MatchFailed is out of gas: more gas, never invalid"
        );
        assert!(!settled_all(&ok(vec![])));
        assert!(!settled_all(&[1, 2, 3]));
    }

    /// Spec 2026-11-10-dex-liquidity.md §11: the liquidity mark, the verify budget (three mldsa65-signed SCaaS inputs do not fit
    /// 2^24, two do; a classical signer's eight do), and a starved capability check read as a retry, never a wrong DEX.
    #[test]
    fn liquidity_pre_checks() {
        assert!(liquidity_marked(&[10, 11]));
        assert!(!liquidity_marked(&[10]));
        assert!(!liquidity_marked(&[]));
        assert!(liquidity_too_large(3, 0x0131, MAX_TX_GAS)
            .is_some_and(|m| m.starts_with("LIQUIDITY_TOO_LARGE")));
        assert!(liquidity_too_large(2, 0x0131, MAX_TX_GAS).is_none());
        assert!(liquidity_too_large(8, 0, MAX_TX_GAS).is_none());
        assert!(
            liquidity_too_large(2, 0x0131, 12_000_000).is_some(),
            "a block below 2 caps and the base"
        );
        assert!(
            liquidity_too_large(9, 0x0999, 1).is_none(),
            "a kind the table does not name: the simulation's"
        );
        // CTR-DEX-26's classical row (<= 50,000) holds secp256k1 too (the deploy's cap, DeployBase.sol)
        assert_eq!(verify_cap(0x0108), Some(50_000), "secp256k1");
        // p256 and webauthn-p256 at the registry's 400,000 (DeployBase.sol, owner 2026-11-10): 40 SCaaS inputs need
        // 17,000,000 gas, above the 2^24 transaction cap; at the old 50,000 they fitted (3,000,000)
        assert_eq!(
            (verify_cap(0x0101), verify_cap(0x0100)),
            (Some(400_000), Some(400_000)),
            "p256, webauthn-p256"
        );
        assert!(liquidity_too_large(40, 0x0101, MAX_TX_GAS)
            .is_some_and(|m| m.contains("need about 17000000 gas")));
        assert!(
            liquidity_too_large(39, 0x0100, MAX_TX_GAS).is_none(),
            "39 x 400,000 + the base = 16,600,000"
        );
        let sel = ISCaaSDex::mtxLiquidityCall::SELECTOR;
        assert!(liquidity_starved(
            &[sel[0], sel[1], sel[2], sel[3], 0],
            "NotLiquidityDex(0x00000000000000000000000000000000000000d1)"
        ));
        assert!(!liquidity_starved(
            &[sel[0], sel[1], sel[2], sel[3]],
            "OrderClosed(0x01)"
        ));
        assert!(
            !liquidity_starved(&[0, 0, 0, 0], "NotLiquidityDex(0x01)"),
            "another entry: not ours"
        );
        // the chain's bytes as the simulation decodes them (L6c: unnamed, they read `revert 0x0e46ff74…` and went dead)
        let t7 = crate::abi::decode_revert(
            &ISCaaSDex::NotLiquidityDex {
                caller: Address::repeat_byte(0xd1),
            }
            .abi_encode(),
        );
        assert!(
            liquidity_starved(&[sel[0], sel[1], sel[2], sel[3], 0], &t7),
            "{t7}"
        );
        assert_eq!(
            LIQUIDITY_PULL_ID,
            <crate::abi::ILiquidityPull::mtxLiquidityPullCall as SolCall>::SELECTOR
        );
    }

    #[test]
    fn a_wrapped_empty_interaction_revert_is_out_of_gas() {
        use crate::abi::ISCaaSDex::InteractionFailed;
        let e = |r: &[u8]| {
            InteractionFailed {
                index: alloy::primitives::U256::from(1),
                target: Address::repeat_byte(7),
                reason: r.to_vec().into(),
            }
            .abi_encode()
        };
        assert!(reason_is_out_of_gas(&[]));
        assert!(reason_is_out_of_gas(&e(&[])));
        assert!(!reason_is_out_of_gas(&e(&[1, 2])));
        assert!(!reason_is_out_of_gas(&[1, 2, 3]));
    }

    /// An RPC answering `answer` to every `eth_call`; `(url, gas of each eth_call)`.
    async fn rpc(answer: serde_json::Value) -> (String, Arc<Mutex<Vec<u64>>>) {
        let gases: Arc<Mutex<Vec<u64>>> = Default::default();
        let g = gases.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<serde_json::Value>| {
                let (answer, g) = (answer.clone(), g.clone());
                async move {
                    // scaas-rpc T13 point 6 (fixture correction): chain 7's identity, not counted
                    if let Some(b) = block0_of(&r, B256::ZERO, 7) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": b}),
                        );
                    }
                    let gas = r["params"][0]["gas"]
                        .as_str()
                        .map_or(0, |x| u64::from_str_radix(&x[2..], 16).unwrap());
                    g.lock().unwrap().push(gas);
                    let mut out = serde_json::json!({"jsonrpc": "2.0", "id": r["id"]});
                    let key = if answer.get("code").is_some() {
                        "error"
                    } else {
                        "result"
                    };
                    out[key] = answer;
                    axum::Json(out)
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (url, gases)
    }

    /// Settle sizing on the chain: a transport error is transient (the job goes back to the queue), never a size; at
    /// the cap the refusal names the settlements still failing (review P5 m4).
    #[tokio::test]
    async fn settle_sizing_tells_transport_from_size_and_names_what_fails() {
        let chain = |url: &str| {
            let cfg = ChainCfg {
                evm_chain_number: 7,
                rpc_urls: vec![url.into()],
                ..Default::default()
            };
            Chain::with_signer(&cfg, alloy::signers::local::PrivateKeySigner::random()).unwrap()
        };
        let (to, data) = (
            Address::repeat_byte(0xd0),
            Bytes::from(SEL_MTX_SETTLE.to_vec()),
        );
        let (url, gases) =
            rpc(serde_json::json!({"code": -32603, "message": "upstream unavailable"})).await;
        assert!(matches!(
            settle_gas(&chain(&url), to, &data, 100_000, 3_000_000).await,
            Err(SimError::Transport(_))
        ));
        assert_eq!(
            gases.lock().unwrap().len(),
            1,
            "no ladder on a transport error"
        );
        let ret = format!(
            "0x{}",
            alloy::hex::encode(<Vec<bool> as SolValue>::abi_encode(&vec![
                true, false, true
            ]))
        );
        let (url, gases) = rpc(serde_json::json!(ret)).await;
        let Err(SimError::Revert(r)) = settle_gas(&chain(&url), to, &data, 100_000, 300_000).await
        else {
            panic!()
        };
        assert!(r.contains("settlements [1] fail at the cap"), "{r}");
        assert_eq!(
            *gases.lock().unwrap(),
            vec![120_000, 180_000, 270_000, 300_000]
        );
    }

    #[test]
    fn an_invalidation_already_done_is_success() {
        let reason = crate::abi::decode_revert(
            &IToken::MinNonceNotIncreasing {
                current: alloy::primitives::U256::from(9),
                requested: alloy::primitives::U256::from(5),
            }
            .abi_encode(),
        );
        let inv = [&SEL_MTX_INVALIDATE_NONCES[..], &[0u8; 128]].concat();
        assert!(already_invalidated(&inv, &reason));
        assert!(already_invalidated(
            &[&SEL_TOKEN_INVALIDATE_NONCES[..], &[0u8; 128]].concat(),
            &reason
        ));
        assert!(!already_invalidated(
            &[&[0x93, 0xcb, 0x3e, 0x81][..], &[0u8; 128]].concat(),
            &reason
        ));
        assert!(!already_invalidated(
            &inv,
            "MinNonceAboveCap(MinNonceAboveCap { requested: 1 })"
        ));
    }

    /// CTR-CHAT-27: `PqChatTree.treeCreate`, the module's creation step that `PqChat.createSession` calls; no row of any kind.
    const TREE_CREATE: &str = "treeCreate((bytes32,uint64,bytes32,address,bytes32[],(bytes32,uint64,bytes32)[],bytes32[],bytes,uint8,uint32,bytes32),\
        (bytes32,uint64,bytes,bytes32,bytes)[],(bytes,bytes,(uint16,(uint16,bytes)[],bytes)[]))";
    /// `PqChat`'s unsigned writes (UA-7 P17; CTR-CHAT-27: the tree commit's three pieces), under `params.relay_unsigned_pqchat`.
    const UNSIGNED_PQCHAT: [&str; 5] = [
        "storeMessage",
        "addWraps",
        "addPathList",
        "addPathKeys",
        "addPath",
    ];

    /// The `PqChat` writes as `IPqChat.sol` declares them ([`iface_writes`]).
    fn pqchat_writes() -> Vec<String> {
        iface_writes("pqchat/IPqChat.sol")
    }

    /// The writes an interface under `smartcontracts/evm/src` declares (`IPqChat.sol`, `IPqVault.sol`, `IPqChatStore.sol`), read
    /// from the source, not copied: every `external` function that is neither `view` nor `pure`, as its canonical signature; its
    /// structs and `IPqChat.`'s / `IUARegistry.`'s (for `UASig`) resolved from their sources, `IPqGroupTree`'s with them.
    fn iface_writes(file: &str) -> Vec<String> {
        let src = |f: &str| {
            std::fs::read_to_string(format!(
                "{}/../smartcontracts/evm/src/{f}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
            .lines()
            .map(|l| l.split("//").next().unwrap_or_default().to_string())
            .collect::<Vec<_>>()
            .join(" ")
        };
        let (chat, pc, reg, tree) = (
            src(file),
            src("pqchat/IPqChat.sol"),
            src("ua/IUARegistry.sol"),
            src("pqgroup/IPqGroupTree.sol"),
        );
        let mut structs: HashMap<String, Vec<String>> = HashMap::new();
        // `IPqChat` inherits `IPqGroupTree`'s `TreeAdd` / `TreeRemove` (A-6): named bare inside it, `IPqChat.` or
        // `IPqGroupTree.` outside
        for (scope, s) in [
            ("", &tree),
            ("IPqChat.", &tree),
            ("IPqGroupTree.", &tree),
            ("", &chat),
            ("IPqChat.", &pc),
            ("IUARegistry.", &reg),
        ] {
            for part in s.split(" struct ").skip(1) {
                let (name, body) = part.split_once('{').unwrap();
                let fields = body
                    .split('}')
                    .next()
                    .unwrap()
                    .split(';')
                    .filter_map(|f| f.split_whitespace().next())
                    .map(String::from);
                structs.insert(format!("{scope}{}", name.trim()), fields.collect());
            }
        }
        fn canon(ty: &str, scope: &str, structs: &HashMap<String, Vec<String>>) -> String {
            let base = ty.trim_end_matches("[]");
            let (scope, key) = match base.split_once('.') {
                Some((s, _)) => (format!("{s}."), base.to_string()),
                None => (scope.to_string(), format!("{scope}{base}")),
            };
            match structs.get(&key) {
                Some(f) => format!(
                    "({}){}",
                    f.iter()
                        .map(|t| canon(t, &scope, structs))
                        .collect::<Vec<_>>()
                        .join(","),
                    &ty[base.len()..]
                ),
                None => ty.to_string(),
            }
        }
        chat.split(" function ")
            .skip(1)
            .filter_map(|f| {
                let (name, rest) = f.split_once('(')?;
                let (args, tail) = rest.split_once(')')?;
                let tail = tail.split(';').next()?;
                let args: Vec<String> = args
                    .split(',')
                    .filter_map(|p| p.split_whitespace().next())
                    .map(|t| canon(t, "", &structs))
                    .collect();
                (tail.contains("external") && !tail.contains(" view") && !tail.contains(" pure"))
                    .then(|| format!("{}({})", name.trim(), args.join(",")))
            })
            .collect()
    }

    /// Fable code review of PqVault F10: `test/vectors/selector_audit.json`'s block of `name` (from the built artifact, every
    /// non-view external): the selectors of its `SIGNED` and `PERMISSIONLESS(unsigned …)` rows (the node's rows) and of the rest
    /// (`FACTORY`, `rescue`: no row).
    fn audited(name: &str) -> (HashSet<[u8; 4]>, HashSet<[u8; 4]>) {
        let v: serde_json::Value = serde_json::from_str(
            &std::fs::read_to_string(format!(
                "{}/../smartcontracts/evm/test/vectors/selector_audit.json",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
        .unwrap();
        let (mut rows, mut none) = (HashSet::new(), HashSet::new());
        for r in v[name].as_array().unwrap() {
            let sig = r["sig"].as_str().unwrap();
            let sel: [u8; 4] = alloy::primitives::keccak256(sig)[..4].try_into().unwrap();
            let class = r["class"].as_str().unwrap();
            if class == "SIGNED"
                || (class.starts_with("PERMISSIONLESS(")
                    && class.contains("unsigned")
                    && !sig.starts_with("rescue("))
            {
                rows.insert(sel);
            } else {
                none.insert(sel);
            }
        }
        (rows, none)
    }

    /// PqVault plan V8 (CTR-PQV-11, CTR-PQV-13; AGENTS "Node"): the `pqvault` allow-list equals the contract's writes both
    /// directions, the contract side derived from `IPqVault.sol` with `IPqChat`'s and `IUARegistry`'s types resolved (`initialize`
    /// is the factory's alone, no row); the selectors are forge's `methodIdentifiers`; each write is a row of `pqvault` and of no
    /// other kind; no write selector is `PqChat`'s; a view (one shares `PqChat`'s `versionAt` selector) and `initialize` are rows of
    /// no kind.
    #[test]
    fn pqvault_rows_equal_the_contract_both_directions() {
        let sel = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        let all = iface_writes("pqvault/IPqVault.sol");
        let writes: Vec<&String> = all
            .iter()
            .filter(|s| !s.starts_with("initialize("))
            .collect();
        assert_eq!((all.len(), writes.len()), (9, 8), "{all:?}");
        let theirs: HashSet<[u8; 4]> = writes.iter().map(|s| sel(s)).collect();
        let ours: HashSet<[u8; 4]> = typed::rows()
            .iter()
            .filter(|r| r.contracts.contains(&"pqvault"))
            .map(|r| r.sent)
            .collect();
        assert_eq!(ours, theirs, "the PqVault allow-list, both directions");
        let forge: HashSet<[u8; 4]> = FORGE_PQVAULT_WRITES
            .iter()
            .map(|h| alloy::hex::decode(h).unwrap().try_into().unwrap())
            .collect();
        assert_eq!(ours, forge, "forge's IPqVault methodIdentifiers");
        let (audit_rows, audit_none) = audited("PqVault");
        assert_eq!(ours, audit_rows, "selector_audit.json's PqVault: its SIGNED and unsigned-write rows are the allow-list (Fable F10)");
        for x in &audit_none {
            assert!(
                !ours.contains(x),
                "PqVault: a FACTORY or rescue entry is no row"
            );
        }
        let chat: HashSet<[u8; 4]> = pqchat_writes().iter().map(|s| sel(s)).collect();
        assert!(
            ours.is_disjoint(&chat),
            "no write selector shared with PqChat"
        );
        let kinds = [
            "token",
            "zether",
            "pqz",
            "wallet",
            "account",
            "dex",
            "registry",
            "factory",
            "gov_router",
            "pqchat",
            "pqvault",
        ];
        for s in &writes {
            for k in kinds {
                assert_eq!(row(sel(s), k).is_some(), k == "pqvault", "{s} on {k}");
            }
        }
        for s in [
            "initialize(bytes32)",
            "owner()",
            "versionAt(bytes32,uint32)",
            "vaultOf(bytes32)",
            "latestRange(bytes32,uint256,uint256)",
        ] {
            for k in kinds {
                assert!(row(sel(s), k).is_none(), "{s} on {k}");
            }
        }
    }

    /// `forge inspect IPqVault methodIdentifiers`, its eight writes.
    const FORGE_PQVAULT_WRITES: [&str; 8] = [
        "8f02bc96", "87e8fed1", "c487e92a", "5270d5c2", "6b7f9e2e", "1b5d7365", "344e5e37",
        "1d4c2131",
    ];

    /// PqVault plan V8 (CTR-PQV-13): a `PqVault` job runs only on an instance `token_factory` lists as class 4 with a release:
    /// `CALL_TARGET_REFUSED` on class 3, version 0, an address the factory did not make; a `PqChat` job on a class-4 instance too.
    /// Its unsigned `addVaultWraps` runs on the direct path only under `params.relay_unsigned_pqvault` (default off:
    /// `UNSIGNED_WRITE_NOT_PAID`, before any read; `relay_unsigned_pqchat` does not open it), and as a relay fee's inner call on a
    /// class-4 instance only. Each refusal beside its control.
    #[tokio::test]
    async fn a_pqvault_job_runs_only_on_a_class_4_instance() {
        let uid = B256::repeat_byte(0x31);
        let (factory, vault, chat, v0, other) = (
            Address::repeat_byte(0xfa),
            Address::repeat_byte(0xc4),
            Address::repeat_byte(0xc3),
            Address::repeat_byte(0xc0),
            Address::repeat_byte(0xb0),
        );
        let (cfg, reads) =
            factory_rpc(uid, factory, vec![(vault, 4, 1), (chat, 3, 1), (v0, 4, 0)]).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let work = |entry: &str, to: Address| {
            crate::submit::work_of_op(Some(1), &typed::testkit::pqvault_op(entry, to), None)
                .unwrap()
                .0
        };
        let unpaid = |e: Result<(), Refusal>, what: &str| {
            assert!(
                matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("UNSIGNED_WRITE_NOT_PAID")),
                "{what}: {e:?}"
            )
        };
        let shut = Guard::new(&cfg, Default::default()).unwrap();
        let chat_open = Guard::new(
            &with_param(&cfg, "relay_unsigned_pqchat", toml::Value::Boolean(true)),
            Default::default(),
        )
        .unwrap();
        unpaid(
            shut.check(&chain, &work("addVaultWraps", vault)).await,
            "default",
        );
        unpaid(
            chat_open.check(&chain, &work("addVaultWraps", vault)).await,
            "PqChat's parameter",
        );
        assert_eq!(*reads.lock().unwrap(), 0, "refused before any read");
        let open = Guard::new(
            &with_param(&cfg, "relay_unsigned_pqvault", toml::Value::Boolean(true)),
            Default::default(),
        )
        .unwrap();
        let entries: Vec<&str> = typed::rows()
            .iter()
            .filter(|r| r.contracts.contains(&"pqvault"))
            .map(|r| r.entry)
            .collect();
        assert_eq!(entries.len(), 8);
        for e in &entries {
            open.check(&chain, &work(e, vault))
                .await
                .unwrap_or_else(|x| panic!("{e}: {x:?}"));
            if *e != "addVaultWraps" {
                shut.check(&chain, &work(e, vault))
                    .await
                    .unwrap_or_else(|x| panic!("{e} signed: {x:?}"));
            }
        }
        for (to, what) in [
            (chat, "class 3"),
            (v0, "version 0"),
            (other, "not made by the factory"),
        ] {
            target_refused(open.check(&chain, &work("createItem", to)).await, what);
        }
        let pc = crate::submit::work_of_op(
            Some(1),
            &typed::testkit::pqchat_op("postMessage", vault),
            None,
        )
        .unwrap()
        .0;
        target_refused(
            open.check(&chain, &pc).await,
            "a PqChat job on a class-4 instance",
        );
        for bad in [toml::Value::String("true".into()), toml::Value::Integer(1)] {
            assert!(Guard::new(
                &with_param(&cfg, "relay_unsigned_pqvault", bad),
                Default::default()
            )
            .is_err());
        }
        // the relay path: paid, on a class-4 instance only, and a PqChat call relayed to it refused
        let (rf, token) = (Address::repeat_byte(0xf4), Address::repeat_byte(0x11));
        let router = [(
            "router".to_string(),
            toml::Value::String(format!("{rf:#x}")),
        )]
        .into_iter()
        .collect();
        let paid = Guard::new(
            &with_param(&cfg, "relay_fee", toml::Value::Table(router)),
            Arc::new(RwLock::new(vec![token])),
        )
        .unwrap();
        let relayed = |target: Address, call: Bytes| {
            let data = IRelayFeeRouter::relayCall {
                target,
                callData: call,
                token,
                from: B256::repeat_byte(2),
                payee: rf.into_word(),
                value: alloy::primitives::U256::from(1),
                batch: alloy::primitives::U256::from(7),
                nonce: alloy::primitives::U256::ZERO,
                validUntil: alloy::primitives::U256::from(4_000_000_000u64),
                auth: crate::abi::UASig {
                    keyData: Bytes::new(),
                    signature: Bytes::new(),
                    members: vec![],
                },
            }
            .abi_encode();
            let t = typed::Typed {
                pay_meta_len: 0,
                pqz_parties: vec![],
                pqz_auditor: false,
                pqz_verdict: None,
                pqz_fee: None,
                contract: "token",
                domain_of: token,
                struct_hash: None,
                lane_hash: None,
                signer: None,
                payee: None,
                digest: None,
                derived_signer: false,
                derived_side: false,
            };
            Work {
                job_id: Some(1),
                to: rf,
                data: data.into(),
                valid_until: 0,
                envelope_until: 0,
                meta: None,
                entry: true,
                typed: Some(t),
            }
        };
        for entry in ["addVaultWraps", "createItem"] {
            paid.check(&chain, &relayed(vault, work(entry, vault).data))
                .await
                .unwrap_or_else(|e| panic!("{entry} as a relay fee's call: {e:?}"));
            target_refused(
                paid.check(&chain, &relayed(chat, work(entry, vault).data))
                    .await,
                &format!("{entry} relayed to a class-3 instance"),
            );
            target_refused(
                paid.check(&chain, &relayed(other, work(entry, vault).data))
                    .await,
                &format!("{entry} relayed to no instance"),
            );
        }
        target_refused(
            paid.check(&chain, &relayed(vault, pc.data.clone())).await,
            "a PqChat call relayed to a class-4 instance",
        );
        paid.check(&chain, &relayed(chat, pc.data))
            .await
            .expect("control: the PqChat call relayed to its class-3 instance");
    }

    /// T93 (UA-7 P17, topics P45; AGENTS "Node"): the `pqchat` allow-list equals the contract's writes both directions, the contract
    /// side derived from `IPqChat.sol` (`initialize` is the factory's alone, no row); the selectors are forge's `methodIdentifiers`;
    /// each write is a row of `pqchat` and of no other kind; a view and `initialize` are rows of no kind.
    #[test]
    fn pqchat_rows_equal_the_contract_both_directions() {
        let sel = |s: &str| -> [u8; 4] { alloy::primitives::keccak256(s)[..4].try_into().unwrap() };
        let all = pqchat_writes();
        let writes: Vec<&String> = all
            .iter()
            .filter(|s| !s.starts_with("initialize("))
            .collect();
        assert_eq!((all.len(), writes.len()), (20, 19), "{all:?}"); // CTR-CHAT-27: + the six tree writes
        let theirs: HashSet<[u8; 4]> = writes.iter().map(|s| sel(s)).collect();
        let ours: HashSet<[u8; 4]> = typed::rows()
            .iter()
            .filter(|r| r.contracts.contains(&"pqchat"))
            .map(|r| r.sent)
            .collect();
        assert_eq!(ours, theirs, "the PqChat allow-list, both directions");
        let forge: HashSet<[u8; 4]> = [
            // the path-less delta (C41-C43): createSession 821d41ae -> f2f10b9f, commit 9575f9cb -> 1af1cd19
            "f2f10b9f", "1222a945", "2b9ab93a", "3c289881", "6035115c", "a52f4d6d", "95660a78",
            "47bee6d5", "c8de3d2d", "04857ea8", "1fd5aeac", "f3ee47ee", "5aee92d5",
            // CTR-CHAT-27: commit, addPathList, addPathKeys, addPath, treeLeave, treeRemove
            "1af1cd19", "0b9b356b", "de142cf8", "44889230", "12a4e9ac", "eb3f5236",
        ]
        .iter()
        .map(|h| alloy::hex::decode(h).unwrap().try_into().unwrap())
        .collect();
        assert_eq!(ours, forge, "forge's IPqChat methodIdentifiers");
        let (audit_rows, audit_none) = audited("PqChat");
        assert_eq!(ours, audit_rows, "selector_audit.json's PqChat: its SIGNED and unsigned-write rows are the allow-list (Fable F10)");
        for x in &audit_none {
            assert!(
                !ours.contains(x),
                "PqChat: a FACTORY or rescue entry is no row"
            );
        }
        let kinds = [
            "token",
            "zether",
            "pqz",
            "wallet",
            "account",
            "dex",
            "registry",
            "factory",
            "gov_router",
            "pqchat",
            "pqchatstore",
        ];
        // review P3-6: each write a row of `pqchat` and of no other kind, but `storeMessage`, also `PqChatStore`'s one write
        for s in &writes {
            for k in kinds {
                let store = k == "pqchatstore" && s.as_str() == "storeMessage(uint8,bytes8,bytes)";
                assert_eq!(
                    row(sel(s), k).is_some(),
                    k == "pqchat" || store,
                    "{s} on {k}"
                );
            }
        }
        // CTR-CHAT-27: `treeCreate` is the module's step under `createSession`, the tree views `PqChatTreeViews`' (read-only)
        // the positive control (the path-less delta §13): the string is `PqChatTree.treeCreate`'s selector, forge's
        // methodIdentifiers of out/PqChatTree.sol (0x86320c45 since the session's two fields), so "no row" checks a live one
        assert_eq!(
            sel(TREE_CREATE),
            [0x86, 0x32, 0x0c, 0x45],
            "PqChatTree.treeCreate"
        );
        for s in [
            "initialize(bytes32,uint8)",
            "owner()",
            "sessionOf(bytes32)",
            "storedRange(bytes8,uint256,uint256)",
            "topicOf(bytes32)",
            TREE_CREATE,
            "treeOf(bytes32)",
            "treeLeaves(bytes32,uint256,uint256)",
            "commitOf(bytes32)",
            "pathListOf(bytes32)",
        ] {
            for k in kinds {
                assert!(row(sel(s), k).is_none(), "{s} on {k}");
            }
        }
    }

    /// T93 (UA-7 P32, topics P45): an RPC whose `factory` lists `instances` as `(address, contractClass, version)` through `infoOf`
    /// (the reads counted), every other address unlisted; a listed address answers no `chainUid()` (a `PqChat` record is portable),
    /// every other `eth_call` `uid`; `eth_getCode` empty.
    pub(crate) async fn factory_rpc(
        uid: B256,
        factory: Address,
        instances: Vec<(Address, u16, u64)>,
    ) -> (ChainCfg, Arc<Mutex<usize>>) {
        use crate::abi::IOpenFactory;
        let reads: Arc<Mutex<usize>> = Default::default();
        let r2 = reads.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(q): axum::Json<serde_json::Value>| {
                let (instances, r2) = (instances.clone(), r2.clone());
                async move {
                    if let Some(b) = block0_of(&q, uid, 31337) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": q["id"], "result": b}),
                        );
                    }
                    let p = &q["params"][0];
                    let to: Address = p["to"]
                        .as_str()
                        .unwrap_or("0x0000000000000000000000000000000000000000")
                        .parse()
                        .unwrap();
                    let input = alloy::hex::decode(
                        p["input"].as_str().or(p["data"].as_str()).unwrap_or("0x"),
                    )
                    .unwrap_or_default();
                    let listed = |a: Address| {
                        instances
                            .iter()
                            .find(|i| i.0 == a)
                            .map_or((0, 0), |i| (i.1, i.2))
                    };
                    let out = match q["method"].as_str().unwrap() {
                        "eth_call"
                            if to == factory
                                && input.get(..4)
                                    == Some(&IOpenFactory::infoOfCall::SELECTOR[..]) =>
                        {
                            *r2.lock().unwrap() += 1;
                            let c = IOpenFactory::infoOfCall::abi_decode(&input).unwrap().c;
                            let (class, version) = listed(c);
                            Some(IOpenFactory::infoOfCall::abi_encode_returns(
                                &IOpenFactory::Created {
                                    addr: if class == 0 { Address::ZERO } else { c },
                                    creatorId: B256::ZERO,
                                    contractClass: class,
                                    kind: 0,
                                    version,
                                    createdBlock: 1,
                                    createdAt: 1,
                                },
                            ))
                        }
                        "eth_call" if listed(to).0 != 0 => Some(vec![]),
                        "eth_call"
                            if typed::testkit::domain_answer(
                                &format!("0x{}", alloy::hex::encode(&input)),
                                to,
                            )
                            .is_some() =>
                        {
                            typed::testkit::domain_answer(
                                &format!("0x{}", alloy::hex::encode(&input)),
                                to,
                            )
                            .map(|h| alloy::hex::decode(&h[2..]).unwrap())
                        }
                        "eth_call" => Some(uid.to_vec()),
                        "eth_getCode" => Some(vec![]),
                        // a gateway's simulation (NODE-GW-09's test): the estimate
                        "eth_estimateGas" => Some(vec![0x52, 0x08]),
                        _ => None,
                    };
                    let result = out.map_or(serde_json::Value::Null, |b| {
                        serde_json::json!(format!("0x{}", alloy::hex::encode(b)))
                    });
                    axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": q["id"], "result": result}),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        (
            ChainCfg {
                evm_chain_number: 31337,
                rpc_urls: vec![url],
                chain_uid: Some(uid),
                token_factory: Some(factory),
                ..Default::default()
            },
            reads,
        )
    }

    fn target_refused(e: Result<(), Refusal>, what: &str) {
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("CALL_TARGET_REFUSED")),
            "{what}: {e:?}"
        );
    }

    fn with_param(cfg: &ChainCfg, k: &str, v: toml::Value) -> ChainCfg {
        ChainCfg {
            params: [(k.to_string(), v)].into_iter().collect(),
            ..cfg.clone()
        }
    }

    /// T93 (UA-7 P32, topics P45, factory index §8.6): a `PqChat` job runs only on an instance `token_factory` lists as class 3 with a
    /// release (`version ≠ 0`), read once and cached; `CALL_TARGET_REFUSED` on version 0, another class, an address the factory did not
    /// make, with another factory or none configured; an unknown selector named `pqchat` too. The reverse: another kind's row on an
    /// instance, even one configured as that kind's target, is refused (an instance answers no `chainUid()`), beside its control.
    #[tokio::test]
    async fn a_pqchat_job_runs_only_on_a_class_3_instance() {
        let uid = B256::repeat_byte(0x31);
        let (factory, chat, v0, c4, other) = (
            Address::repeat_byte(0xfa),
            Address::repeat_byte(0xc3),
            Address::repeat_byte(0xc0),
            Address::repeat_byte(0xc4),
            Address::repeat_byte(0xb0),
        );
        let (cfg, reads) =
            factory_rpc(uid, factory, vec![(chat, 3, 1), (v0, 3, 0), (c4, 4, 1)]).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let open = |c: &ChainCfg| {
            Guard::new(
                &with_param(c, "relay_unsigned_pqchat", toml::Value::Boolean(true)),
                Default::default(),
            )
            .unwrap()
        };
        let work = |entry: &str, to: Address| {
            crate::submit::work_of_op(Some(1), &typed::testkit::pqchat_op(entry, to), None)
                .unwrap()
                .0
        };
        let g = open(&cfg);
        let entries: Vec<&str> = typed::rows()
            .iter()
            .filter(|r| r.contracts.contains(&"pqchat"))
            .map(|r| r.entry)
            .collect();
        for e in &entries {
            g.check(&chain, &work(e, chat))
                .await
                .unwrap_or_else(|x| panic!("{e}: {x:?}"));
        }
        assert_eq!(
            (entries.len(), *reads.lock().unwrap()),
            (19, 1),
            "infoOf read once, then cached"
        ); // P48: + remove; CTR-CHAT-27: + the six tree writes
        for (to, c, what) in [
            (v0, cfg.clone(), "version 0"),
            (c4, cfg.clone(), "class 4"),
            (other, cfg.clone(), "not made by the factory"),
            (
                chat,
                ChainCfg {
                    token_factory: Some(Address::repeat_byte(0xfb)),
                    ..cfg.clone()
                },
                "another factory",
            ),
            (
                chat,
                ChainCfg {
                    token_factory: None,
                    ..cfg.clone()
                },
                "no token_factory",
            ),
        ] {
            target_refused(open(&c).check(&chain, &work("postMessage", to)).await, what);
        }
        let cast = |s: &str| -> Bytes { alloy::primitives::keccak256(s)[..4].to_vec().into() };
        for s in [
            "initialize(bytes32,uint8)",
            "sessionOf(bytes32)",
            "storedRange(bytes8,uint256,uint256)",
            "transfer(address,uint256)",
            TREE_CREATE,
            "treeOf(bytes32)",
            "commitOf(bytes32)",
        ] {
            let mut w = work("postMessage", chat);
            w.data = cast(s);
            target_refused(g.check(&chain, &w).await, s);
        }
        for kind in [
            "wallet",
            "account",
            "dex",
            "registry",
            "factory",
            "gov_router",
        ] {
            let r = typed::rows()
                .iter()
                .find(|r| !r.entry.is_empty() && r.contracts.contains(&kind))
                .unwrap();
            let on = |to: Address| {
                let t = typed::Typed {
                    pay_meta_len: 0,
                    pqz_parties: vec![],
                    pqz_auditor: false,
                    pqz_verdict: None,
                    pqz_fee: None,
                    contract: kind,
                    domain_of: to,
                    struct_hash: None,
                    lane_hash: None,
                    signer: None,
                    payee: None,
                    digest: None,
                    derived_signer: false,
                    derived_side: false,
                };
                let c = match kind {
                    "dex" => ChainCfg {
                        dex: Some(to),
                        ..cfg.clone()
                    },
                    "registry" => ChainCfg {
                        ua_registries: vec![to],
                        ..cfg.clone()
                    },
                    "factory" => ChainCfg {
                        account_factory: Some(to),
                        ..cfg.clone()
                    },
                    "gov_router" => ChainCfg {
                        governance_routers: vec![to],
                        ..cfg.clone()
                    },
                    _ => cfg.clone(),
                };
                (
                    Guard::new(&c, Default::default()).unwrap(),
                    Work {
                        job_id: Some(1),
                        to,
                        data: r.sent.to_vec().into(),
                        valid_until: 0,
                        envelope_until: 0,
                        meta: None,
                        entry: true,
                        typed: Some(t),
                    },
                )
            };
            let (g, w) = on(other);
            g.check(&chain, &w)
                .await
                .unwrap_or_else(|e| panic!("{kind} ({}) on a bound contract: {e:?}", r.entry));
            let (g, w) = on(chat);
            target_refused(
                g.check(&chain, &w).await,
                &format!("{kind} ({}) on the instance", r.entry),
            );
        }
    }

    /// T93 (UA-7 P17, owner 2026-11-05): an unsigned write (`storeMessage`, `addWraps`: no `UASig`) runs on the direct path only under
    /// the operator's `params.relay_unsigned_pqchat` (default off: `UNSIGNED_WRITE_NOT_PAID`, before any read), and always as a relay
    /// fee's inner call (paid through `RelayFeeRouter`); a signed write needs neither. On the relay path the target rule holds both
    /// directions: a `PqChat` call relayed to a contract that is no instance is refused, another kind's call relayed to an instance too.
    #[tokio::test]
    async fn unsigned_pqchat_writes_run_paid_or_under_the_lane_policy() {
        let uid = B256::repeat_byte(0x31);
        let (factory, chat, other) = (
            Address::repeat_byte(0xfa),
            Address::repeat_byte(0xc3),
            Address::repeat_byte(0xb0),
        );
        let (cfg, reads) = factory_rpc(uid, factory, vec![(chat, 3, 1)]).await;
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let work = |entry: &str| {
            crate::submit::work_of_op(Some(1), &typed::testkit::pqchat_op(entry, chat), None)
                .unwrap()
                .0
        };
        let unpaid = |e: Result<(), Refusal>, what: &str| {
            assert!(
                matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("UNSIGNED_WRITE_NOT_PAID")),
                "{what}: {e:?}"
            )
        };
        let shut = Guard::new(&cfg, Default::default()).unwrap();
        let off = Guard::new(
            &with_param(&cfg, "relay_unsigned_pqchat", toml::Value::Boolean(false)),
            Default::default(),
        )
        .unwrap();
        for entry in UNSIGNED_PQCHAT {
            unpaid(shut.check(&chain, &work(entry)).await, entry);
            unpaid(off.check(&chain, &work(entry)).await, entry);
        }
        assert_eq!(*reads.lock().unwrap(), 0, "refused before any read");
        let open = Guard::new(
            &with_param(&cfg, "relay_unsigned_pqchat", toml::Value::Boolean(true)),
            Default::default(),
        )
        .unwrap();
        for entry in UNSIGNED_PQCHAT {
            open.check(&chain, &work(entry))
                .await
                .unwrap_or_else(|e| panic!("{entry} under the lane policy: {e:?}"));
        }
        shut.check(&chain, &work("postMessage"))
            .await
            .unwrap_or_else(|e| panic!("a signed write: {e:?}"));
        for bad in [toml::Value::String("true".into()), toml::Value::Integer(1)] {
            assert!(Guard::new(
                &with_param(&cfg, "relay_unsigned_pqchat", bad),
                Default::default()
            )
            .is_err());
        }
        let (rf, token) = (Address::repeat_byte(0xf4), Address::repeat_byte(0x11));
        let router = [(
            "router".to_string(),
            toml::Value::String(format!("{rf:#x}")),
        )]
        .into_iter()
        .collect();
        let paid = Guard::new(
            &with_param(&cfg, "relay_fee", toml::Value::Table(router)),
            Arc::new(RwLock::new(vec![token])),
        )
        .unwrap();
        let relayed = |target: Address, call: Bytes| {
            let data = IRelayFeeRouter::relayCall {
                target,
                callData: call,
                token,
                from: B256::repeat_byte(2),
                payee: rf.into_word(),
                value: alloy::primitives::U256::from(1),
                batch: alloy::primitives::U256::from(7),
                nonce: alloy::primitives::U256::ZERO,
                validUntil: alloy::primitives::U256::from(4_000_000_000u64),
                auth: crate::abi::UASig {
                    keyData: Bytes::new(),
                    signature: Bytes::new(),
                    members: vec![],
                },
            }
            .abi_encode();
            let t = typed::Typed {
                pay_meta_len: 0,
                pqz_parties: vec![],
                pqz_auditor: false,
                pqz_verdict: None,
                pqz_fee: None,
                contract: "token",
                domain_of: token,
                struct_hash: None,
                lane_hash: None,
                signer: None,
                payee: None,
                digest: None,
                derived_signer: false,
                derived_side: false,
            };
            Work {
                job_id: Some(1),
                to: rf,
                data: data.into(),
                valid_until: 0,
                envelope_until: 0,
                meta: None,
                entry: true,
                typed: Some(t),
            }
        };
        for entry in
            UNSIGNED_PQCHAT
                .iter()
                .chain(&["postMessage", "commit", "treeLeave", "treeRemove"])
        {
            paid.check(&chain, &relayed(chat, work(entry).data))
                .await
                .unwrap_or_else(|e| panic!("{entry} as a relay fee's call: {e:?}"));
            target_refused(
                paid.check(&chain, &relayed(other, work(entry).data)).await,
                &format!("{entry} relayed to no instance"),
            );
        }
        let cancel = typed::Op::parse(
            &typed::testkit::op_of("UACancelNonce", "token", &typed::testkit::vectors()).unwrap(),
            None,
        )
        .unwrap()
        .data;
        paid.check(&chain, &relayed(other, cancel.clone()))
            .await
            .unwrap_or_else(|e| panic!("a token's cancel relayed to a bound contract: {e:?}"));
        let e = paid.check(&chain, &relayed(chat, cancel)).await;
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("CHAIN_UID_MISMATCH")),
            "another kind's call relayed to an instance: {e:?}"
        );
    }

    /// Round 3s (spec 2026-11-10-token-lists.md §9, Fable P3-4): a list edit's estimate above the block limit names its remedy;
    /// any other call does not. The selectors are the router's (spec §7).
    #[test]
    fn list_batch_over_block_limit_named() {
        let mut cd = vec![0x6c, 0x83, 0x2e, 0xcf];
        assert!(list_batch_note(&cd).contains("LIST_BATCH_TOO_LARGE"));
        cd[..4].copy_from_slice(&[0xf8, 0xd9, 0xf1, 0xf3]);
        assert!(list_batch_note(&cd).contains("LIST_BATCH_TOO_LARGE"));
        // the old shapes (without the chain word) are no list edit any more
        assert_eq!(
            list_batch_note(&[0x06, 0xb9, 0x8e, 0x72]),
            "",
            "the old mtxSetAllowed"
        );
        assert_eq!(
            list_batch_note(&[0x2e, 0xb8, 0xc7, 0x08]),
            "",
            "mtxEnableFeature: no batch"
        );
        let rows = typed::testkit::vectors();
        for (op, sel) in [
            ("UASetAllowed", SEL_LIST_EDITS[0]),
            ("UASetDenied", SEL_LIST_EDITS[1]),
        ] {
            let cd = rows["ops"][op]["domains"]["gov_router"]["calldata"]
                .as_str()
                .unwrap();
            assert_eq!(
                &cd[2..10],
                alloy::hex::encode(sel),
                "{op}: the router's selector"
            );
        }
    }

    /// CTR-UA-65: what the fake line answers through its newest generation: `kindHome(kind)`, `holderOf(ua)`'s holder and PQZ home,
    /// and the registries those two views were asked on.
    #[derive(Default)]
    struct LineFake {
        home: Address,
        holder: Address,
        pqz_home: Address,
        asked: Vec<Address>,
    }

    /// An RPC answering `kindHome` and `holderOf` from `f`, every other `eth_call` with `uid` (every target bound), block 0 `uid`.
    async fn line_rpc(uid: B256, f: Arc<Mutex<LineFake>>) -> ChainCfg {
        use crate::abi::IUARegistry as R;
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(r): axum::Json<serde_json::Value>| {
                let f = f.clone();
                async move {
                    if let Some(b) = block0_of(&r, uid, 31337) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": b}),
                        );
                    }
                    let p = &r["params"][0];
                    let input = alloy::hex::decode(
                        p["input"]
                            .as_str()
                            .or(p["data"].as_str())
                            .unwrap_or("0x")
                            .trim_start_matches("0x"),
                    )
                    .unwrap_or_default();
                    let to: Address = p["to"]
                        .as_str()
                        .unwrap_or_default()
                        .parse()
                        .unwrap_or_default();
                    let mut f = f.lock().unwrap();
                    let out: Vec<u8> = match input.get(..4) {
                        Some(s) if s == R::kindHomeCall::SELECTOR => {
                            f.asked.push(to);
                            f.home.abi_encode()
                        }
                        Some(s) if s == R::holderOfCall::SELECTOR => {
                            f.asked.push(to);
                            R::holderOfCall::abi_encode_returns(&R::holderOfReturn {
                                holder: f.holder,
                                kind: 0x0131,
                                pqzHome: f.pqz_home,
                            })
                        }
                        _ => uid.abi_encode(),
                    };
                    let result = match r["method"].as_str() {
                        Some("eth_call") => {
                            serde_json::json!(format!("0x{}", alloy::hex::encode(out)))
                        }
                        Some("eth_getCode") => serde_json::json!("0x"),
                        _ => serde_json::Value::Null,
                    };
                    axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": r["id"], "result": result}),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        ChainCfg {
            evm_chain_number: 31337,
            rpc_urls: vec![url],
            chain_uid: Some(uid),
            ..Default::default()
        }
    }

    const G1: Address = Address::repeat_byte(0x61);
    const G2: Address = Address::repeat_byte(0x62);
    const G3: Address = Address::repeat_byte(0x63);

    /// A registry write of `data` on `to`, as the call table builds it.
    fn reg_work(to: Address, data: Vec<u8>) -> Work {
        Work {
            job_id: Some(1),
            to,
            data: data.into(),
            valid_until: 0,
            envelope_until: 0,
            meta: None,
            entry: true,
            typed: Some(typed::Typed {
                pay_meta_len: 0,
                pqz_parties: vec![],
                pqz_auditor: false,
                pqz_verdict: None,
                pqz_fee: None,
                contract: "registry",
                domain_of: to,
                struct_hash: None,
                lane_hash: None,
                signer: None,
                payee: None,
                digest: None,
                derived_signer: false,
                derived_side: false,
            }),
        }
    }

    /// The line `g1, g2, g3` (already in generation order, as the start check leaves it) over `f`.
    async fn line_guard(f: &Arc<Mutex<LineFake>>, line: Vec<Address>) -> (Guard, Chain) {
        let cfg = ChainCfg {
            ua_registries: line,
            ..line_rpc(B256::repeat_byte(0x24), f.clone()).await
        };
        (
            Guard::new(&cfg, Default::default()).unwrap(),
            Chain::with_signer(&cfg, signer()).unwrap(),
        )
    }

    fn sig() -> crate::abi::UASig {
        crate::abi::UASig {
            keyData: Bytes::new(),
            signature: Bytes::from(vec![7; 65]),
            members: vec![],
        }
    }

    fn kem() -> crate::abi::IUARegistry::KemKey {
        crate::abi::IUARegistry::KemKey {
            scheme: 0,
            mlkemEk: Bytes::new(),
            x25519: B256::ZERO,
        }
    }

    /// CTR-UA-65: a `register` (and `cacheExpandedKey`) of a kind sent to a generation where it is not registrable is refused
    /// before sending, `UA_VERIFY_ONLY`, naming `kindHome(kind)`, read through the newest generation. Positive control: the same
    /// write on the home passes; a kind no generation registers (home 0) and a one-generation line are the simulation's.
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn guard_register_verifyOnly_UA_VERIFY_ONLY() {
        use crate::abi::IUARegistry as R;
        let f = Arc::new(Mutex::new(LineFake {
            home: G1,
            ..Default::default()
        }));
        let (g, chain) = line_guard(&f, vec![G1, G2, G3]).await;
        let attrs = R::UAAttrs {
            pqzKey: Bytes::new(),
            pqzPopHash: B256::ZERO,
            kem: kem(),
            kemPkHash: B256::ZERO,
        };
        let register = R::registerCall {
            kind: 0x0131,
            keyData: Bytes::from(vec![1; 1952]),
            attrs,
            pop: Bytes::new(),
            pqzPop: Bytes::new(),
        }
        .abi_encode();
        let cache = R::cacheExpandedKeyCall {
            kind: 0x0131,
            pk: Bytes::from(vec![1; 1952]),
            part: alloy::primitives::U256::ZERO,
        }
        .abi_encode();
        for data in [register.clone(), cache] {
            assert_eq!(
                g.check(&chain, &reg_work(G1, data.clone())).await,
                Ok(()),
                "control: on kindHome"
            );
            for to in [G2, G3] {
                let e = g.check(&chain, &reg_work(to, data.clone())).await;
                assert!(
                    matches!(&e, Err(Refusal::Policy(r)) if r.starts_with(&format!("{UA_VERIFY_ONLY}: "))
                        && r.contains(&format!("kindHome(kind) {G1:#x}")) && r.contains("0x0131")),
                    "{to:#x}: {e:?}"
                );
            }
        }
        assert!(
            f.lock().unwrap().asked.iter().all(|a| *a == G3),
            "read through the newest generation"
        );
        f.lock().unwrap().home = Address::ZERO;
        assert_eq!(
            g.check(&chain, &reg_work(G2, register.clone())).await,
            Ok(()),
            "no home: the simulation's"
        );
        f.lock().unwrap().home = G1;
        let (one, chain) = line_guard(&f, vec![G2]).await;
        assert_eq!(
            one.check(&chain, &reg_work(G2, register)).await,
            Ok(()),
            "one generation"
        );
    }

    /// Task 21 review P2-5: `msig` is registrable in every generation, so a `registerMsig` to an older generation passes the line
    /// check (the newest generation's `kindHome(0x0120)` is never asked); the `register` of a verify-only kind stays refused.
    #[tokio::test]
    async fn guard_register_msig_older_generation_passes() {
        use crate::abi::IUARegistry as R;
        let f = Arc::new(Mutex::new(LineFake {
            home: G3,
            ..Default::default()
        }));
        let (g, chain) = line_guard(&f, vec![G1, G2, G3]).await;
        let attrs = R::UAAttrs {
            pqzKey: Bytes::new(),
            pqzPopHash: B256::ZERO,
            kem: kem(),
            kemPkHash: B256::ZERO,
        };
        let msig = R::registerMsigCall {
            structure: R::MsigStructure {
                threshold: 1,
                members: vec![],
            },
            attrs: attrs.clone(),
            pop: vec![],
            pqzPop: Bytes::new(),
        }
        .abi_encode();
        assert_eq!(line_target(&msig), None);
        for to in [G1, G2, G3] {
            assert_eq!(
                g.check(&chain, &reg_work(to, msig.clone())).await,
                Ok(()),
                "{to:#x}"
            );
        }
        let register = R::registerCall {
            kind: 0x0131,
            keyData: Bytes::from(vec![1; 1952]),
            attrs,
            pop: Bytes::new(),
            pqzPop: Bytes::new(),
        }
        .abi_encode();
        let e = g.check(&chain, &reg_work(G1, register)).await;
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with(&format!("{UA_VERIFY_ONLY}: "))),
            "control: {e:?}"
        );
    }

    /// CTR-UA-65: a key write held in the holding generation (`setKemKey`, `acceptMembership`, `updateMsig`) sent to a generation
    /// that does not hold the record is refused `UA_WRONG_GENERATION`, naming `holderOf(ua)`. Control: on the holder it passes; an
    /// id no generation holds is the simulation's.
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn guard_keyWrite_wrongGeneration() {
        use crate::abi::IUARegistry as R;
        let f = Arc::new(Mutex::new(LineFake {
            holder: G1,
            pqz_home: G2,
            ..Default::default()
        }));
        let (g, chain) = line_guard(&f, vec![G1, G2, G3]).await;
        let ua = B256::repeat_byte(0x11);
        let writes = [
            R::setKemKeyCall {
                ua,
                version: 1,
                kem: kem(),
                sig: sig(),
            }
            .abi_encode(),
            R::acceptMembershipCall {
                ua,
                memberSig: crate::abi::MemberSig {
                    index: 0,
                    members: vec![],
                    sig: Bytes::new(),
                },
            }
            .abi_encode(),
            R::updateMsigCall {
                ua,
                version: 2,
                structure: R::MsigStructure {
                    threshold: 1,
                    members: vec![],
                },
                enabled: alloy::primitives::U256::from(1),
                validUntilBlock: 9,
                sigs: vec![],
                chainUid_: B256::repeat_byte(0x24),
            }
            .abi_encode(),
        ];
        for data in writes {
            assert_eq!(
                g.check(&chain, &reg_work(G1, data.clone())).await,
                Ok(()),
                "control: on the holder"
            );
            for to in [G2, G3] {
                let e = g.check(&chain, &reg_work(to, data.clone())).await;
                assert!(
                    matches!(&e, Err(Refusal::Policy(r)) if r.starts_with(&format!("{UA_WRONG_GENERATION}: "))
                        && r.contains(&format!("holderOf(ua) {G1:#x}"))),
                    "{to:#x}: {e:?}"
                );
            }
        }
        f.lock().unwrap().holder = Address::ZERO;
        let w = R::setKemKeyCall {
            ua,
            version: 1,
            kem: kem(),
            sig: sig(),
        }
        .abi_encode();
        assert_eq!(
            g.check(&chain, &reg_work(G3, w)).await,
            Ok(()),
            "unregistered: the simulation's"
        );
    }

    /// CTR-UA-65, spec §11.2: a PQZ write (`setPqzKey`, `setPqzScopedKey`, `storePqzPop`, `storePqzScopedPop`) sent elsewhere than
    /// the record's PQZ home, the holder included, is refused `UA_WRONG_GENERATION`, naming `pqzHomeOf(ua)`. Control: on the home.
    #[tokio::test]
    #[allow(non_snake_case)]
    async fn guard_pqzWrite_wrongHome() {
        use crate::abi::IUARegistry as R;
        let f = Arc::new(Mutex::new(LineFake {
            holder: G1,
            pqz_home: G2,
            ..Default::default()
        }));
        let (g, chain) = line_guard(&f, vec![G1, G2, G3]).await;
        let ua = B256::repeat_byte(0x11);
        let scope = Address::repeat_byte(0x5c);
        let writes = [
            R::setPqzKeyCall {
                ua,
                version: 1,
                pqzKey: Bytes::new(),
                pqzPopHash: B256::ZERO,
                sig: sig(),
            }
            .abi_encode(),
            R::storePqzPopCall {
                ua,
                version: 1,
                pqzPop: Bytes::from(vec![3; 64]),
            }
            .abi_encode(),
            R::setPqzScopedKeyCall {
                ua,
                scope,
                version: 1,
                pqzKey: Bytes::new(),
                pqzPopHash: B256::ZERO,
                openKem: kem(),
                validUntilBlock: 9,
                sig: sig(),
            }
            .abi_encode(),
            R::storePqzScopedPopCall {
                ua,
                scope,
                version: 1,
                pqzPop: Bytes::from(vec![3; 64]),
            }
            .abi_encode(),
        ];
        for data in writes {
            assert_eq!(
                g.check(&chain, &reg_work(G2, data.clone())).await,
                Ok(()),
                "control: on the PQZ home"
            );
            for to in [G1, G3] {
                let e = g.check(&chain, &reg_work(to, data.clone())).await;
                assert!(
                    matches!(&e, Err(Refusal::Policy(r)) if r.starts_with(&format!("{UA_WRONG_GENERATION}: "))
                        && r.contains(&format!("pqzHomeOf(ua) {G2:#x}"))),
                    "{to:#x}: {e:?}"
                );
            }
        }
    }

    /// CTR-UA-65 (F9): `Rule::UaRegistry` is the set of the line's addresses: a registry row runs on every generation of the line
    /// and on no other address (a former generation dropped from the config included); every `REG` row of the call table has its
    /// line target but `registerMsig` (every generation registers an `msig`), so the generation rule covers each.
    #[tokio::test]
    async fn guard_allow_lists_per_registry() {
        let f = Arc::new(Mutex::new(LineFake::default()));
        let (g, chain) = line_guard(&f, vec![G1, G2, G3]).await;
        for to in [G1, G2, G3, Address::repeat_byte(0x64)] {
            let facts = g.facts(&chain, to, Rule::UaRegistry).await.unwrap();
            assert_eq!(
                allowed(Rule::UaRegistry, &facts),
                to != Address::repeat_byte(0x64),
                "{to:#x}"
            );
            for other in [Rule::Dex, Rule::AccountFactory, Rule::GovRouter] {
                assert!(
                    !allowed(other, &facts) || to == Address::repeat_byte(0x64),
                    "{other:?} on {to:#x}"
                );
            }
        }
        let reg: Vec<&typed::Row> = typed::rows()
            .iter()
            .filter(|r| !r.entry.is_empty() && r.contracts == ["registry"])
            .collect();
        assert_eq!(reg.len(), 14, "the registry rows");
        for r in reg {
            let data = [&r.sent[..], &[0u8; 4096][..]].concat();
            // `registerMsig` alone has none: `msig` is registrable in every generation (Task 21 review P2-5)
            assert_eq!(
                line_target(&data).is_some(),
                r.entry != "registerMsig",
                "{}: its line target",
                r.entry
            );
        }
    }

    /// A chain for the `pqchatstore` tests: block `n`'s hash `keccak(epoch ‖ n)` (a new epoch is a reorg), the code of each
    /// address from block `from` on, `eth_getCode` answered only pinned to a block hash of this chain (each read's block kept).
    #[derive(Default)]
    struct StoreChain {
        head: u64,
        epoch: u8,
        from: u64,
        codes: HashMap<Address, Vec<u8>>,
        code_reads: Vec<u64>,
    }

    impl StoreChain {
        fn hash(&self, n: u64) -> B256 {
            alloy::primitives::keccak256([&[self.epoch][..], &n.to_be_bytes()].concat())
        }
    }

    async fn store_chain(uid: B256, st: Arc<Mutex<StoreChain>>) -> String {
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(q): axum::Json<serde_json::Value>| {
                let st = st.clone();
                async move {
                    if let Some(b) = block0_of(&q, uid, 31337) {
                        return axum::Json(
                            serde_json::json!({"jsonrpc": "2.0", "id": q["id"], "result": b}),
                        );
                    }
                    let mut c = st.lock().unwrap();
                    let result = match q["method"].as_str().unwrap() {
                        "eth_blockNumber" => serde_json::json!(format!("{:#x}", c.head)),
                        "eth_getBlockByNumber" => {
                            let n = match q["params"][0].as_str().unwrap() {
                                "latest" | "finalized" | "safe" => c.head,
                                x => u64::from_str_radix(x.trim_start_matches("0x"), 16).unwrap(),
                            };
                            let mut b = serde_json::from_str::<serde_json::Value>(include_str!(
                                "../tests/vectors/hedera_testnet.json"
                            ))
                            .unwrap()["block"]
                                .clone();
                            b["number"] = serde_json::json!(format!("{n:#x}"));
                            b["hash"] = serde_json::json!(format!("{:#x}", c.hash(n)));
                            b
                        }
                        "eth_getCode" => {
                            let at: Address = q["params"][0].as_str().unwrap().parse().unwrap();
                            let h: B256 = q["params"][1]["blockHash"]
                                .as_str()
                                .unwrap()
                                .parse()
                                .unwrap();
                            let Some(n) = (0..=c.head).find(|&n| c.hash(n) == h) else {
                                return axum::Json(
                                    serde_json::json!({"jsonrpc": "2.0", "id": q["id"],
                                    "error": {"code": -32000, "message": "header not found"}}),
                                );
                            };
                            c.code_reads.push(n);
                            let code = if n >= c.from {
                                c.codes.get(&at).cloned().unwrap_or_default()
                            } else {
                                vec![]
                            };
                            serde_json::json!(format!("0x{}", alloy::hex::encode(code)))
                        }
                        "eth_call" => {
                            let p = &q["params"][0];
                            let to: Address = p["to"]
                                .as_str()
                                .unwrap_or_default()
                                .parse()
                                .unwrap_or_default();
                            let input = p["input"]
                                .as_str()
                                .or(p["data"].as_str())
                                .unwrap_or("0x")
                                .to_string();
                            match typed::testkit::domain_answer(&input, to) {
                                Some(h) => serde_json::json!(h),
                                None => serde_json::json!(format!("0x{}", alloy::hex::encode(uid))),
                            }
                        }
                        _ => serde_json::Value::Null,
                    };
                    axum::Json(
                        serde_json::json!({"jsonrpc": "2.0", "id": q["id"], "result": result}),
                    )
                }
            }),
        );
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });
        url
    }

    fn store_work(to: Address) -> Work {
        let op = serde_json::json!({"entry": "storeMessage", "contract": "pqchatstore", "token": format!("{to:#x}"),
            "validUntil": "4000000000", "args": {"v": "1", "hint": "0x0102030405060708", "env": "0xabcdef"}});
        crate::submit::work_of_op(Some(1), &op, None).unwrap().0
    }

    /// T9 (CTR-CHAT-22, CTR-CHAT-19): a `storeMessage` job of contract kind `pqchatstore` runs on the release data's address
    /// whose runtime code hash is `PqChatStore`'s release (`release-data/PqChatStore.json`), under the operator's lane policy
    /// `params.relay_unsigned_pqchat`; another address is `CHATSTORE_ADDRESS`, other code `CHATSTORE_CODE_HASH`, no code yet
    /// `CHATSTORE_NOT_FINAL` (a retry), each by name; by default the unsigned write is `UNSIGNED_WRITE_NOT_PAID`, before any
    /// read. The pinned hash and address are the release data's.
    #[tokio::test]
    async fn a_pqchatstore_job_runs_on_the_pinned_code_under_the_lane_policy() {
        assert_eq!(
            format!("{:#x}", *PQCHATSTORE_RUNTIME_HASH),
            "0xb7c149f0bd0016966b2ddb38eac3da410aca45ab4f24bfb966a4747eb2d23a58",
            "the release data's runtime code hash"
        );
        assert_eq!(
            *PQCHATSTORE_ADDRESS,
            "0x99c0548Cb7e59fEbE6Af924B6d5Bfa4AE2BdDe36"
                .parse::<Address>()
                .unwrap(),
            "the release data's address"
        );
        let uid = B256::repeat_byte(0x31);
        let (store, other, empty) = (
            Address::repeat_byte(0x5c),
            Address::repeat_byte(0x5d),
            Address::repeat_byte(0x5e),
        );
        let (code, wrong) = (vec![0x60u8, 0x01, 0x00], vec![0x60u8, 0x02, 0x00]);
        let st = Arc::new(Mutex::new(StoreChain {
            head: 0x10,
            codes: [(store, code.clone()), (other, wrong)].into(),
            ..Default::default()
        }));
        let url = store_chain(uid, st.clone()).await;
        let cfg = ChainCfg {
            evm_chain_number: 31337,
            rpc_urls: vec![url],
            chain_uid: Some(uid),
            ..Default::default()
        };
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let with_code = |c: &ChainCfg, at: Address| {
            let mut g = Guard::new(c, Default::default()).unwrap();
            g.chatstore_code_hash = alloy::primitives::keccak256(&code);
            g.chatstore_address = at;
            g
        };
        // the default policy: an unsigned write, unpaid, is not relayed; nothing read
        for g in [
            with_code(&cfg, store),
            with_code(
                &with_param(&cfg, "relay_unsigned_pqchat", toml::Value::Boolean(false)),
                store,
            ),
        ] {
            let e = g.check(&chain, &store_work(store)).await;
            assert!(
                matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("UNSIGNED_WRITE_NOT_PAID")),
                "{e:?}"
            );
        }
        assert!(
            st.lock().unwrap().code_reads.is_empty(),
            "refused before any read"
        );
        // the operator's lane policy: the pinned code at the pinned address runs, read once and kept; others refused by name
        let open_cfg = with_param(&cfg, "relay_unsigned_pqchat", toml::Value::Boolean(true));
        let open = with_code(&open_cfg, store);
        for _ in 0..2 {
            open.check(&chain, &store_work(store))
                .await
                .unwrap_or_else(|e| panic!("the pinned code: {e:?}"));
        }
        assert_eq!(
            st.lock().unwrap().code_reads.len(),
            1,
            "the code read once, then kept"
        );
        let e = open.check(&chain, &store_work(other)).await;
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("CHATSTORE_ADDRESS")),
            "{e:?}"
        );
        let e = with_code(&open_cfg, other)
            .check(&chain, &store_work(other))
            .await;
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("CHATSTORE_CODE_HASH")),
            "{e:?}"
        );
        let e = with_code(&open_cfg, empty)
            .check(&chain, &store_work(empty))
            .await;
        assert!(
            matches!(&e, Err(Refusal::Transport(r)) if r.starts_with("CHATSTORE_NOT_FINAL")),
            "no code: {e:?}"
        );
        // the release's own hash and address: the stand-in code is not PqChatStore's, nor its address
        let mut real = Guard::new(&open_cfg, Default::default()).unwrap();
        let e = real.check(&chain, &store_work(store)).await;
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("CHATSTORE_ADDRESS")),
            "{e:?}"
        );
        real.chatstore_address = store;
        let e = real.check(&chain, &store_work(store)).await;
        assert!(
            matches!(&e, Err(Refusal::Policy(r)) if r.starts_with("CHATSTORE_CODE_HASH")),
            "{e:?}"
        );
        // `PqChat`'s rows are no `pqchatstore` row, and the reverse: one entry, one kind each
        let sel = store_message_selector();
        assert!(row(sel, "pqchatstore").is_some() && row(sel, "pqchat").is_some());
        // review P3-6: the store's allow-list equals `IPqChatStore.sol`'s writes, both directions, read from the source
        let ours: HashSet<[u8; 4]> = typed::rows()
            .iter()
            .filter(|r| r.contracts.contains(&"pqchatstore"))
            .map(|r| r.sent)
            .collect();
        let theirs: HashSet<[u8; 4]> = iface_writes("pqchat/IPqChatStore.sol")
            .iter()
            .map(|s| alloy::primitives::keccak256(s)[..4].try_into().unwrap())
            .collect();
        assert_eq!(ours, theirs, "the store's allow-list, both directions");
        assert_eq!(
            theirs,
            HashSet::from([sel]),
            "IPqChatStore.sol's one write, storeMessage"
        );
    }

    /// Review P2-3: the store's code is read at the lane's final block (here `depth` 2: the head less two), pinned to that
    /// block's hash, never at `latest`; a pass is kept only while that block's hash holds (a reorg reads again) and for
    /// `chatstore_recheck`; code that is at the head but not yet at the final block is `CHATSTORE_NOT_FINAL`, a transport
    /// "not yet" that is never kept, and passes once final.
    #[tokio::test]
    async fn a_pqchatstore_pass_is_read_at_the_final_block_and_not_kept_for_ever() {
        let uid = B256::repeat_byte(0x32);
        let store = Address::repeat_byte(0x5c);
        let code = vec![0x60u8, 0x01, 0x00];
        let st = Arc::new(Mutex::new(StoreChain {
            head: 0x20,
            from: 0x1f, // at the head and the block before it: not yet at the final block (0x1e)
            codes: [(store, code.clone())].into(),
            ..Default::default()
        }));
        let url = store_chain(uid, st.clone()).await;
        let cfg = with_param(
            &ChainCfg {
                evm_chain_number: 31337,
                rpc_urls: vec![url],
                chain_uid: Some(uid),
                finality: crate::config::FinalityCfg {
                    mode: "depth".into(),
                    depth: 2,
                    quorum: 1,
                },
                ..Default::default()
            },
            "relay_unsigned_pqchat",
            toml::Value::Boolean(true),
        );
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let mut g = Guard::new(&cfg, Default::default()).unwrap();
        g.chatstore_code_hash = alloy::primitives::keccak256(&code);
        g.chatstore_address = store;
        let reads = |st: &Arc<Mutex<StoreChain>>| st.lock().unwrap().code_reads.clone();
        // not final yet: a retry, never kept
        for _ in 0..2 {
            let e = g.check(&chain, &store_work(store)).await;
            assert!(
                matches!(&e, Err(Refusal::Transport(r)) if r.starts_with("CHATSTORE_NOT_FINAL")),
                "{e:?}"
            );
        }
        assert_eq!(
            reads(&st),
            [0x1e, 0x1e],
            "read at the head less the depth, each time"
        );
        // final: a pass, kept while its block's hash holds
        st.lock().unwrap().head = 0x22;
        g.check(&chain, &store_work(store)).await.unwrap();
        g.check(&chain, &store_work(store)).await.unwrap();
        assert_eq!(
            reads(&st),
            [0x1e, 0x1e, 0x20],
            "read once at the final block, then kept"
        );
        // a reorg (every hash moves): read again at the new final block
        st.lock().unwrap().epoch = 1;
        g.check(&chain, &store_work(store)).await.unwrap();
        assert_eq!(reads(&st).len(), 4, "a reorg reads again");
        // past the recheck age: read again
        g.chatstore_recheck = std::time::Duration::ZERO;
        g.check(&chain, &store_work(store)).await.unwrap();
        assert_eq!(reads(&st).len(), 5, "an old pass is read again");
        // the code gone at the final block after a reorg: no pass kept
        g.chatstore_recheck = CHATSTORE_RECHECK;
        {
            let mut c = st.lock().unwrap();
            c.epoch = 2;
            c.from = 0x21;
        }
        let e = g.check(&chain, &store_work(store)).await;
        assert!(
            matches!(&e, Err(Refusal::Transport(r)) if r.starts_with("CHATSTORE_NOT_FINAL")),
            "{e:?}"
        );
    }

    /// Review P3-5: a paid `storeMessage` (a relay fee's inner call) to `PqChatStore` runs: the store's release address and its
    /// code at the final block, the store's one write; the same call to another contract is refused, and `PqChat`'s other
    /// unsigned write (`addWraps`) relayed to the store too.
    #[tokio::test]
    async fn a_paid_store_message_relays_to_the_store() {
        let uid = B256::repeat_byte(0x33);
        let (store, other) = (Address::repeat_byte(0x5c), Address::repeat_byte(0x5d));
        let code = vec![0x60u8, 0x01, 0x00];
        let st = Arc::new(Mutex::new(StoreChain {
            head: 0x10,
            codes: [(store, code.clone()), (other, code.clone())].into(),
            ..Default::default()
        }));
        let url = store_chain(uid, st.clone()).await;
        let (rf, token) = (Address::repeat_byte(0xf4), Address::repeat_byte(0x11));
        let router = [(
            "router".to_string(),
            toml::Value::String(format!("{rf:#x}")),
        )]
        .into_iter()
        .collect();
        let cfg = with_param(
            &ChainCfg {
                evm_chain_number: 31337,
                rpc_urls: vec![url],
                chain_uid: Some(uid),
                ..Default::default()
            },
            "relay_fee",
            toml::Value::Table(router),
        );
        let chain = Chain::with_signer(&cfg, signer()).unwrap();
        let mut g = Guard::new(&cfg, Arc::new(RwLock::new(vec![token]))).unwrap();
        g.chatstore_code_hash = alloy::primitives::keccak256(&code);
        g.chatstore_address = store;
        let relayed = |target: Address, call: Bytes| {
            let data = IRelayFeeRouter::relayCall {
                target,
                callData: call,
                token,
                from: B256::repeat_byte(2),
                payee: rf.into_word(),
                value: alloy::primitives::U256::from(1),
                batch: alloy::primitives::U256::from(7),
                nonce: alloy::primitives::U256::ZERO,
                validUntil: alloy::primitives::U256::from(4_000_000_000u64),
                auth: crate::abi::UASig {
                    keyData: Bytes::new(),
                    signature: Bytes::new(),
                    members: vec![],
                },
            }
            .abi_encode();
            let t = typed::Typed {
                pay_meta_len: 0,
                pqz_parties: vec![],
                pqz_auditor: false,
                pqz_verdict: None,
                pqz_fee: None,
                contract: "token",
                domain_of: token,
                struct_hash: None,
                lane_hash: None,
                signer: None,
                payee: None,
                digest: None,
                derived_signer: false,
                derived_side: false,
            };
            Work {
                job_id: Some(1),
                to: rf,
                data: data.into(),
                valid_until: 0,
                envelope_until: 0,
                meta: None,
                entry: true,
                typed: Some(t),
            }
        };
        g.check(&chain, &relayed(store, store_work(store).data))
            .await
            .unwrap_or_else(|e| panic!("a paid storeMessage to the store: {e:?}"));
        target_refused(
            g.check(&chain, &relayed(other, store_work(other).data))
                .await,
            "to another contract",
        );
        let wraps =
            crate::submit::work_of_op(Some(1), &typed::testkit::pqchat_op("addWraps", store), None)
                .unwrap()
                .0;
        target_refused(
            g.check(&chain, &relayed(store, wraps.data)).await,
            "addWraps to the store",
        );
    }

    fn store_message_selector() -> [u8; 4] {
        alloy::primitives::keccak256("storeMessage(uint8,bytes8,bytes)")[..4]
            .try_into()
            .unwrap()
    }
}
