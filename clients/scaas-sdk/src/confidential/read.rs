// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The SDK's reading layer for Zether (spec §9.4, CLI-SDK-10; plan T15): the words `ua-rs`'s Zether facade decrypts and proves
//! over, read so that requirements 1 to 7 of [CLI-UAL-31] to [CLI-UAL-37] hold. Ported from zether-prover's
//! `zether-read-balance` (the factory record, the clone check, the account words) and its `state::LAYOUT`.
//!
//! - **R1** every request is `Purpose::FeedsDecryption` through the profile's list (`scaas-rpc`: no discovered endpoint alone;
//!   under `strict_majority` a named or default member in the agreeing group).
//! - **R2** the session's pool is pinned to the profile's `(chain_id, chain_uid)`; an endpoint of another pair is dropped; the
//!   token's `ChainEnv.chainUid` must be the profile's too.
//! - **R3** one block, the profile's final block ([`final_block`]: `Finalized` or `Depth(d)`, never the plain reads' `Depth(1)`),
//!   every request by number and hash (EIP-1898, `requireCanonical`).
//! - **R4** storage words (`eth_getStorageAt`) and code (`eth_getCode`) only, never a view: no `eth_call` is reachable from
//!   this file (a test reads it). Each pointer's code is checked by what it must hold: the token's code is exactly a clone of a
//!   chain-neutral release with its `ChainEnv` (`scaas_ua::factory::clone_env`), a key pointer's code is `0x00 ‖ Y` with
//!   `UA(Y)` the UA it is the record of.
//! - **R5** the token is catalogued by the profile's factory: `_rec[token]` (slot 8, word 1) is class TOKEN and a Zether kind.
//! - **R6** the registry the token's `ChainEnv` names holds, for the holder's UA, the record of kind `0x0141` whose `Y` is the
//!   handle's (and for each recipient UA its own `Y`).
//! - **R7** [`zether`] fetches a **fixed set** of words, chosen by the token and the UAs only (every point's four data words
//!   whether the point is empty or not), and returns them; every check and the decryption run after the pool returned, so a
//!   failure never makes the pool ask another endpoint.
//!
//! UNAUDITED.
use super::words::{add, be, class_kind, map_slot, rec_slot, word, CLASS_TOKEN, PURPOSE, W};
use crate::op::{addr20, evm, final_block, hex, unhex};
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, U256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{ReadAt, ReadError};
use serde_json::{json, Value};
use zether_prover::state::{LAYOUT, ROOT};

/// The Zether kinds (`IOpenFactory.TokenKind`: NORMAL_ZETHER, WRAPPED_ZETHER, NORMAL_ZETHER_REGULATED,
/// WRAPPED_ZETHER_REGULATED) of the factory record (R5).
const ZETHER_KINDS: [u16; 4] = [2, 3, 10, 11];
/// `UAStore.Layout.records` (registry slot 0): `kind(16) ‖ registeredAt(40) ‖ keyPtr(160) ‖ index(40)` from the low end.
const REG_RECORDS_SLOT: u64 = 0;
const ZETHER_UA_KIND: u16 = 0x0141;
/// A stored G1 point: 128 bytes, a long-form `bytes` of four data words (length word `2·128 + 1`).
const POINT_WORDS: u64 = 4;
const POINT_LEN_WORD: u64 = 2 * 128 + 1;

/// What one endpoint returned for the fixed set, unchecked (compared whole under `strict_majority`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Raw {
    rec: W,
    code: Vec<u8>,
    psid: W,
    modes: W,
    /// `auditorKey`'s length word, then its four data words
    auditor: Vec<W>,
    /// the six slots of `acct[ua]`
    account: Vec<W>,
    /// the four data words of each of `accC`, `accD`, `pendC`, `pendD`, in that order
    data: Vec<(W, W)>,
    /// each UA's registry record word and the code at its key pointer (the holder's first)
    keys: Vec<(W, Vec<u8>)>,
}

/// A checked read: the facade's words of the holder's account, the token's modes and auditor key, the recipients' keys.
#[derive(Debug, Clone)]
pub(crate) struct Read {
    pub block: u64,
    /// `{family, chainId, chainUid, token, block, psid, ua, account, accountData}` (zether-prover `state`)
    pub words: Value,
    /// `auditorMode(8)` of the modes word
    pub auditor_mode: u8,
    /// `disclosureMode(8)` of the modes word (`ZetherTypes.DisclosureMode`: 0 BUNDLE, 1 COMPACT)
    pub disclosure_mode: u8,
    /// the account's six slots (`acct[ua]`: four length words, the counters word, `modeNonce ‖ mode`)
    pub account: Vec<W>,
    /// the token's current auditor key (128 bytes) when it has one
    pub y_aud: Option<Vec<u8>>,
    /// the registered `Y` of each UA after the holder's, in order
    pub ys: Vec<Vec<u8>>,
}

fn lay(label: &str) -> Result<(u64, u64, usize, usize), SdkError> {
    LAYOUT
        .iter()
        .find(|r| r.0 == label)
        .map(|r| (r.1, r.2, r.3, r.4))
        .ok_or(SdkError::Internal)
}

/// The namespace slot of `label` (`ROOT + slot`).
fn ns(label: &str) -> Result<W, SdkError> {
    Ok(add(&ROOT, lay(label)?.0))
}

/// The byte field `label` of word `w` (its `width` bytes at `byte` from the low end).
fn field(w: &W, label: &str) -> Result<u64, SdkError> {
    let (_, _, byte, width) = lay(label)?;
    let b = w
        .get(32 - byte - width..32 - byte)
        .ok_or(SdkError::Internal)?;
    Ok(b.iter().fold(0u64, |a, x| (a << 8) | u64::from(*x)))
}

/// The words of the fixed set's plan: the slots asked, chosen by the token and the UAs only (R7).
struct Plan {
    factory: Address,
    token: Address,
    rec: W,
    psid: W,
    modes: W,
    auditor: W,
    base: W,
    uas: Vec<W>,
}

/// The fixed set at the read's block, nothing checked; the registry and the key pointers are where the token's code and the
/// records (public values) name them, an unreadable one left empty for the checks to refuse.
async fn fetch(
    pool: &EvmPool,
    at: ReadAt<alloy::primitives::B256>,
    p: &Plan,
) -> Result<Raw, ReadError> {
    let at = &at;
    let w = |who: Address, slot: W| async move { word(pool, at, who, &slot).await };
    let rec = w(p.factory, p.rec).await?;
    let code = pool.code_at(at, p.token).await?.to_vec();
    let psid = w(p.token, p.psid).await?;
    let modes = w(p.token, p.modes).await?;
    let mut auditor = vec![w(p.token, p.auditor).await?];
    let d = scaas_ua::keccak256(&p.auditor);
    for k in 0..POINT_WORDS {
        auditor.push(w(p.token, add(&d, k)).await?);
    }
    let mut account = Vec::with_capacity(6);
    for i in 0..6 {
        account.push(w(p.token, add(&p.base, i)).await?);
    }
    let mut data = Vec::with_capacity(16);
    for i in 0..4 {
        let d = scaas_ua::keccak256(&add(&p.base, i));
        for k in 0..POINT_WORDS {
            let s = add(&d, k);
            data.push((s, w(p.token, s).await?));
        }
    }
    let registry = scaas_ua::factory::clone_env(&code).map(|(_, e)| Address::from(e.registry));
    let mut keys = Vec::with_capacity(p.uas.len());
    for ua in &p.uas {
        let (r, c) = match registry {
            Some(reg) => {
                let r = w(reg, map_slot(ua, &be(REG_RECORDS_SLOT))).await?;
                let ptr = Address::from_slice(&r[5..25]);
                let c = if ptr.is_zero() {
                    vec![]
                } else {
                    pool.code_at(at, ptr).await?.to_vec()
                };
                (r, c)
            }
            None => ([0; 32], vec![]),
        };
        keys.push((r, c));
    }
    Ok(Raw {
        rec,
        code,
        psid,
        modes,
        auditor,
        account,
        data,
        keys,
    })
}

/// R6: `rec` is a record of kind `0x0141` whose key pointer holds `0x00 ‖ Y` with `UA(Y) == ua`; its `Y`.
fn registered(ua: &W, rec: &W, code: &[u8]) -> Result<Vec<u8>, SdkError> {
    let kind = u16::from_be_bytes([rec[30], rec[31]]);
    match code.split_first() {
        Some((0, y))
            if kind == ZETHER_UA_KIND
                && y.len() == 128
                && scaas_ua::derive_ua(ZETHER_UA_KIND, y, false).ok().as_ref() == Some(ua) =>
        {
            Ok(y.to_vec())
        }
        _ => Err(SdkError::LegKeyMismatch),
    }
}

/// The checks of a fetched set (R2, R5, R6) and the facade's words; public data only. `y`: the handle's key (`None`: no
/// handle, the watch loop's read of a keystore row's UA; R6 still binds the record's `Y` to the UA).
fn check(
    r: Raw,
    block: u64,
    chain_id: u64,
    chain_uid: &W,
    token: &[u8; 20],
    y: Option<&[u8]>,
    uas: &[W],
) -> Result<Read, SdkError> {
    // R5: catalogued by the profile's factory, a Zether kind
    let (class, kind) = class_kind(&r.rec);
    if class != CLASS_TOKEN || !ZETHER_KINDS.contains(&kind) {
        return Err(SdkError::TokenUncatalogued);
    }
    // R4, R5: a clone of a chain-neutral release; R2: its chain is the profile's
    let (_, env) = scaas_ua::factory::clone_env(&r.code).ok_or(SdkError::TokenUncatalogued)?;
    if env.chain_uid != *chain_uid {
        return Err(SdkError::ProfileMismatch);
    }
    // R6: the holder's registered Y is the handle's; each recipient's Y is its UA's
    let mut ys = Vec::with_capacity(uas.len());
    for (i, (ua, (rec, code))) in uas.iter().zip(&r.keys).enumerate() {
        // a recipient with no registry record (kind 0) has its own name (owner 2026-11-19, P2); the holder's stays R6's
        if i > 0 && u16::from_be_bytes([rec[30], rec[31]]) == 0 {
            return Err(SdkError::ReceiverUnregistered);
        }
        ys.push(registered(ua, rec, code)?);
    }
    if y.is_some_and(|y| ys.first().map(Vec::as_slice) != Some(y)) {
        return Err(SdkError::LegKeyMismatch);
    }
    ys.remove(0);
    let y_aud = match r.auditor.split_first() {
        Some((len, _)) if *len == [0; 32] => None,
        Some((len, d)) if *len == be(POINT_LEN_WORD) => Some(d.concat()),
        _ => return Err(SdkError::Argument),
    };
    // the account words; a point's data words only when its length word is set (an empty point has none)
    let mut data = Vec::new();
    for (i, lw) in r.account.iter().take(4).enumerate() {
        if *lw != [0; 32] {
            let mine = r.data.get(i * 4..i * 4 + 4).ok_or(SdkError::Internal)?;
            data.extend(
                mine.iter()
                    .map(|(s, w)| json!({"slot": hex(s), "word": hex(w)})),
            );
        }
    }
    let words = json!({"family": "evm", "chainId": chain_id, "chainUid": hex(chain_uid), "token": hex(token),
        "block": block, "psid": hex(&r.psid), "ua": hex(uas.first().ok_or(SdkError::Internal)?),
        "account": r.account.iter().map(|w| hex(w)).collect::<Vec<_>>(), "accountData": data});
    Ok(Read {
        block,
        words,
        auditor_mode: u8::try_from(field(&r.modes, "auditorMode")?)
            .map_err(|_| SdkError::Internal)?,
        disclosure_mode: u8::try_from(field(&r.modes, "disclosureMode")?)
            .map_err(|_| SdkError::Internal)?,
        account: r.account,
        y_aud,
        ys,
    })
}

/// The words of Zether token `token` on `chain` for the handle `(y, ua)` and the recipient UAs `others`, at the profile's final
/// block (R1 to R7). `ChainUnknown`; `Argument`: no factory in the profile; `TokenUncatalogued`: a token not catalogued as Zether
/// or not a clone; `ReceiverUnregistered`: a recipient UA with no registry record (P2); `LegKeyMismatch`: the holder not
/// registered, a UA's record of another kind or key, the holder's `Y` not the handle's; `ProfileMismatch`: the
/// token's `ChainEnv` of another chain; the pool's codes (`NoTrustedEndpoint`, `AgreementNeedsThree`, …).
pub(crate) async fn zether(
    sdk: &Sdk,
    chain: &str,
    token: &str,
    y: Option<&[u8]>,
    ua: W,
    others: &[W],
) -> Result<Read, SdkError> {
    let (profile, chain_id, pool) = evm(sdk, chain)?;
    let factory = addr20(
        &profile
            .factory
            .clone()
            .ok_or(SdkError::Argument)?
            .to_ascii_lowercase(),
    )?;
    let t = addr20(&token.to_ascii_lowercase())?;
    let uid: W = unhex(&profile.chain_uid)?
        .try_into()
        .map_err(|_| SdkError::Argument)?;
    let mut uas = vec![ua];
    uas.extend_from_slice(others);
    let plan = Plan {
        factory: Address::from(factory),
        token: Address::from(t),
        rec: rec_slot(&t),
        psid: ns("psid")?,
        modes: ns("disclosureMode")?,
        auditor: ns("auditorKey")?,
        base: map_slot(&ua, &ns("acct[U].accC")?),
        uas: uas.clone(),
    };
    let (pool, plan) = (&pool, &plan);
    let a = pool
        .read_at_block(final_block(&profile), PURPOSE, |at| fetch(pool, at, plan))
        .await?;
    check(a.value, a.number, chain_id, &uid, &t, y, &uas)
}

/// `UAStore.Layout` slots 4 and 5: `uaCount[kind]`, `uaAt[kind][i]` (CTR-UA-29).
const REG_COUNT_SLOT: u64 = 4;
const REG_AT_SLOT: u64 = 5;
/// The longest `0x0141` list read (zether-prover's `zether-read-balance` reads the same at most).
const MAX_LIST: u64 = 50_000;

/// The decoy candidates of a multi-recipient transfer on `token` (CTR-UA-29, the default: uniform over the whole list): the
/// registry's `0x0141` list as the token's `ChainEnv` names it, at the profile's final block, through the same sources as
/// every read here (R1 to R3). A fixed set too: the list's length, then each of its words, chosen by that public length only,
/// never by a decryption. `TokenUncatalogued`: the token's code is not a clone; `Argument`: a list longer than [`MAX_LIST`].
/// Each picked decoy's record and key are then checked by [`zether`] (R6).
pub(crate) async fn candidates(sdk: &Sdk, chain: &str, token: &str) -> Result<Vec<W>, SdkError> {
    let (profile, _, pool) = evm(sdk, chain)?;
    let t = Address::from(addr20(&token.to_ascii_lowercase())?);
    let kind = be(u64::from(ZETHER_UA_KIND));
    let count = map_slot(&kind, &be(REG_COUNT_SLOT));
    let list = map_slot(&kind, &be(REG_AT_SLOT));
    let pool = &pool;
    let (count, list) = (&count, &list);
    let a = pool
        .read_at_block(final_block(&profile), PURPOSE, |at| async move {
            let code = pool.code_at(&at, t).await?;
            let Some((_, env)) = scaas_ua::factory::clone_env(&code) else {
                return Ok(None);
            };
            let reg = Address::from(env.registry);
            let n = U256::from_be_bytes(word(pool, &at, reg, count).await?);
            let n = u64::try_from(n).unwrap_or(u64::MAX);
            if n > MAX_LIST {
                return Ok(Some(Err(n)));
            }
            let mut out = Vec::new();
            for i in 0..n {
                out.push(word(pool, &at, reg, &map_slot(&be(i), list)).await?);
            }
            Ok(Some(Ok(out)))
        })
        .await?;
    match a.value {
        None => Err(SdkError::TokenUncatalogued),
        Some(Err(_)) => Err(SdkError::Argument),
        Some(Ok(mut l)) => {
            let mut seen = std::collections::HashSet::new();
            l.retain(|u| seen.insert(*u));
            Ok(l)
        }
    }
}
