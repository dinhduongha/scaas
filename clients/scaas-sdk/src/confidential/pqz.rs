// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PQZ (spec §9.2, §9.4; plan T16): the SDK's PQZ reading layer and the balance, ported from `ua-rs`'s reference reader
//! `pqz-read` (the account words of `STATE_LAYOUT`, the window, the blobs). The key stays in `ua-rs`'s PQZ facade
//! (`PqzKey::call`): every decryption runs there, over words this layer read at one final block. Zether is separate
//! ([`super::read`]).
//!
//! - **R1** every request is `Purpose::FeedsDecryption` through the profile's list; **R2** the session's pool is pinned to the
//!   profile's `(chain_id, chain_uid)` and the token's `ChainEnv.chainUid` must be the profile's; **R3** one final block
//!   (`Finalized` or the profile's `Depth(d)`), every request by number and hash.
//! - **R4** storage (`eth_getStorageAt`) and code (`eth_getCode`) only: no `eth_call` is reachable from this file (a test reads
//!   it). `proofStore` is a storage word of slot 0 by `STATE_LAYOUT` (owner 2026-11-19, T16-b): NONE 0 or LOG 1, else the token
//!   is of a release before 3h, refused as R5.
//! - **R5** `_rec[token]` is class TOKEN and a PQZ kind (NORMAL_PQZ, WRAPPED_PQZ, NORMAL_PQZ_REGULATED, WRAPPED_PQZ_REGULATED),
//!   the token's code a clone of a chain-neutral release with its `ChainEnv`.
//! - **The set** (spec §9.2): the token's `psid` is this build's PQZL or PQZH id, else `PqzSetMismatch`, checked before any
//!   account word is parsed; a token of another set has none of them read.
//! - **R6** the registry the token's `ChainEnv` names: `pqzKey[ua][v]` proven, its SSTORE2 code `0x00 ‖ pk` with `pk` the
//!   handle's (`LegKeyMismatch` otherwise).
//! - **R7** the word set is fixed by the token, the UA, the key version and the operation's form (op 7 or not): the account's
//!   four slots, `sendCounter[ua]`, `pqzKey[ua][v]`, `pqzVersions[ua]`, `accWords` when the account is materialised, the
//!   pending window `[rolled, p)` with `p` the facade's (CTR-PQZ-06), and the code of each pointer used (the key, `accBlob`,
//!   each pending credit's blob). The window and the pointers come from public counters and pointers, never from a decryption.
//!   Every check and the decryption run after the pool returned: a failure never makes the pool ask another endpoint, and a
//!   failed decryption goes back to the holder only.
//!
//! UNAUDITED.
use super::words::{add, be, class_kind, map_slot, rec_slot, word, CLASS_TOKEN, PURPOSE, W};
use crate::op::{addr20, evm, final_block, hex, unhex, KeyRef};
use crate::vault::OpenSeed;
use crate::{Sdk, SdkError};
use alloy::primitives::{Address, B256};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{ReadAt, ReadError};
use scaas_ua::facade::pqz::{pqz_set, PqzKey, STATE_LAYOUT};
use scaas_ua::facade::pqz_pack::ACC_WORDS;
use serde_json::{json, Value};
use std::sync::Arc;

/// The PQZ kinds of the factory record (`IOpenFactory.TokenKind`).
const PQZ_KINDS: [u16; 4] = [4, 5, 12, 13];
/// The registry's `pqzKey` (slot 2, keyed `(ua, version)`: `ptr(160) ‖ proven(8) ‖ added(8)`) and `pqzVersions` (slot 17),
/// held to `test/ua/UAStoreLayout.t.sol` by `pqz-read`.
const REG_PQZ_KEY_SLOT: u64 = 2;
const REG_PQZ_VERSIONS_SLOT: u64 = 17;
/// `PqzCore.INLINE_MAX`, `INLINE_MAX_PQZH` (op 7 of a PQZH token): the facade's window (CTR-PQZ-06).
const INLINE_MAX: u64 = 16;
const INLINE_MAX_PQZH: u64 = 10;
/// The account's `flags` bit: `acc` materialised in `accWords`.
const MAT: u64 = 1;

/// This build's `K_MAX`: the `kmax<N>` of its set's name (`n2304-kmax4096`: 4096), the name `pqz-core/params/sets` pins.
/// ponytail: parsed from the name, as `scaas-ua` exports no `K_MAX`; an export there replaces it.
fn k_max() -> u64 {
    pqz_set()
        .name
        .rsplit("kmax")
        .next()
        .and_then(|n| n.parse().ok())
        .unwrap_or(0)
}

/// The ERC-7201 root of `scaas.pqz`: `keccak256(abi.encode(uint256(keccak256(id)) − 1)) & ~0xff`.
pub(crate) fn root() -> W {
    let mut m = scaas_ua::keccak256(b"scaas.pqz");
    for b in m.iter_mut().rev() {
        let borrow = *b == 0;
        *b = b.wrapping_sub(1);
        if !borrow {
            break;
        }
    }
    let mut r = scaas_ua::keccak256(&m);
    r[31] = 0;
    r
}

/// `STATE_LAYOUT`'s `(slot, inner, byte, width)` of `label`.
fn lay(label: &str) -> (u64, u64, usize, usize) {
    STATE_LAYOUT
        .iter()
        .find(|r| r.0 == label)
        .map_or((0, 0, 0, 0), |r| (r.1, r.2, r.3, r.4))
}

/// The namespace slot of `label`.
fn ns(label: &str) -> W {
    add(&root(), lay(label).0)
}

/// The field `label` (width ≤ 8) of word `w`, bytes counted from the low end.
pub(crate) fn field(w: &W, label: &str) -> u64 {
    let (_, _, byte, width) = lay(label);
    w.get(32 - byte - width..32 - byte)
        .unwrap_or_default()
        .iter()
        .fold(0u64, |a, x| (a << 8) | u64::from(*x))
}

/// The address at byte `byte` (from the low end) of `w`.
fn low_addr(w: &W, byte: usize) -> [u8; 20] {
    w.get(12 - byte..32 - byte).and_then(|b| b.try_into().ok()).unwrap_or_default()
}

/// `acct[ua][v]`: `keccak256(v ‖ keccak256(ua ‖ root + 8))`.
fn acct_base(ua: &W, v: u64) -> W {
    map_slot(&be(v), &map_slot(ua, &ns("acct[U][7].pendingCount")))
}

/// The facade's window end `p` (CTR-PQZ-06): `min(pendingCount, rolled + min(inline, K_MAX − 1 − accUnits))` (saturating:
/// the facade refuses an account past `K_MAX` itself).
fn window_end(s0: &W, s1: &W, op7_pqzh: bool) -> (u64, u64) {
    let (count, rolled) = (field(s0, "acct[U][7].pendingCount"), field(s0, "acct[U][7].rolled"));
    let room = k_max().saturating_sub(field(s1, "acct[U][7].accUnits").saturating_add(1));
    let inline = if op7_pqzh { INLINE_MAX_PQZH } else { INLINE_MAX };
    (rolled, count.min(rolled.saturating_add(inline.min(room))))
}

/// The ids of this build's set: PQZL, and PQZH where the set has it.
fn set_ids() -> (W, Option<W>) {
    let s = pqz_set();
    (s.pqzl_id, s.pqzh_id)
}

/// What the read asks: chosen by the token, the UA, the key version and the form only (R7).
struct Plan {
    factory: Address,
    token: Address,
    ua: W,
    version: u64,
    op7: bool,
}

/// The account's part of a read, fetched only for a catalogued clone of this build's set.
#[derive(Debug, Clone, PartialEq)]
struct Rest {
    registry: [u8; 20],
    slot0: W,
    key_record: W,
    key_versions: W,
    account: Vec<W>,
    send_counter: W,
    acc_words: Vec<W>,
    pending: Vec<(u64, W)>,
    blobs: Vec<([u8; 20], Vec<u8>)>,
}

/// What one endpoint returned, unchecked (compared whole under `strict_majority`).
#[derive(Debug, Clone, PartialEq)]
struct Raw {
    rec: W,
    code: Vec<u8>,
    psid: W,
    rest: Option<Rest>,
}

/// A checked read of a PQZ account.
#[allow(dead_code)] // `slot0`, `psid`, `registry`: the operations' (T16's entries and verdicts)
#[derive(Debug, Clone)]
pub(crate) struct PqzRead {
    pub block: u64,
    /// the facade's words command fields: `{chainUid, token, block, psid, keyRecord, ua, account, pending, accWords,
    /// sendCounterWord, keyVersion, keyVersions, forOp7, blobs}`
    pub words: Value,
    /// the token's slot 0 (`disclosureMode`, `auditorMode`, `pqzVerifyMode`, `proofStore`, `auditorEpoch`)
    pub slot0: W,
    pub psid: W,
    /// the registry the token's `ChainEnv` names
    pub registry: [u8; 20],
}

/// The fixed set at the read's block (R7), nothing checked: the factory record, the token's code and `psid`; for a
/// catalogued clone of this build's set, the account's words and the codes of the pointers they use. Public data only.
async fn fetch(pool: &EvmPool, at: ReadAt<B256>, p: &Plan) -> Result<Raw, ReadError> {
    let at = &at;
    let tok = |slot: W| async move { word(pool, at, p.token, &slot).await };
    let rec = word(pool, at, p.factory, &rec_slot(&p.token.into_array())).await?;
    let code = pool.code_at(at, p.token).await?.to_vec();
    let psid = tok(ns("psid")).await?;
    let (pqzl, pqzh) = set_ids();
    let env = scaas_ua::factory::clone_env(&code);
    // the set first: a token of another set (or not a clone) has no account word read
    let (true, Some((_, env))) = (psid == pqzl || Some(psid) == pqzh, env) else {
        return Ok(Raw {
            rec,
            code,
            psid,
            rest: None,
        });
    };
    let reg = Address::from(env.registry);
    let slot0 = tok(ns("disclosureMode")).await?;
    let key_record = word(pool, at, reg, &map_slot(&be(p.version), &map_slot(&p.ua, &be(REG_PQZ_KEY_SLOT)))).await?;
    let key_versions = word(pool, at, reg, &map_slot(&p.ua, &be(REG_PQZ_VERSIONS_SLOT))).await?;
    let base = acct_base(&p.ua, p.version);
    let mut account = Vec::with_capacity(4);
    for i in 0..4 {
        account.push(tok(add(&base, i)).await?);
    }
    let send_counter = tok(map_slot(&p.ua, &ns("sendCounter[U]"))).await?;
    let (s0, s1) = (account.first().copied().unwrap_or_default(), account.get(1).copied().unwrap_or_default());
    let mut acc_words = Vec::new();
    let mut ptrs = vec![low_addr(&key_record, 0)];
    if field(&s1, "acct[U][7].flags") & MAT != 0 {
        let first = add(&base, lay("acct[U][7].accWords[0]").1);
        for i in 0..ACC_WORDS as u64 {
            acc_words.push(tok(add(&first, i)).await?);
        }
    } else {
        ptrs.push(low_addr(&s1, lay("acct[U][7].accBlob").2));
    }
    let (rolled, end) = window_end(&s0, &s1, p.op7 && Some(psid) == pqzh);
    let map = add(&base, lay("acct[U][7].pending[3]").1);
    let mut pending = Vec::new();
    for i in rolled..end {
        let e = tok(map_slot(&be(i), &map)).await?;
        // `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)`: a credit (`vOff ≠ 0`) has a blob, a TRIVIAL entry none
        if e[22..24] != [0, 0] {
            ptrs.push(low_addr(&e, 12));
        }
        pending.push((i, e));
    }
    let mut blobs: Vec<([u8; 20], Vec<u8>)> = Vec::new();
    for a in ptrs {
        if a != [0; 20] && !blobs.iter().any(|b| b.0 == a) {
            blobs.push((a, pool.code_at(at, Address::from(a)).await?.to_vec()));
        }
    }
    Ok(Raw {
        rec,
        code,
        psid,
        rest: Some(Rest {
            registry: env.registry,
            slot0,
            key_record,
            key_versions,
            account,
            send_counter,
            acc_words,
            pending,
            blobs,
        }),
    })
}

/// The checks of a fetched set (R2, R5, the set, R6) and the facade's words. `pk`: the handle's key.
#[allow(clippy::too_many_arguments)]
fn check(
    r: Raw,
    block: u64,
    chain_uid: &W,
    token: &[u8; 20],
    ua: &W,
    version: u64,
    pk: &[u8],
    op7: bool,
) -> Result<PqzRead, SdkError> {
    // R5: catalogued by the profile's factory as a PQZ token, a clone of a chain-neutral release; R2: of the profile's chain
    let (class, kind) = class_kind(&r.rec);
    if class != CLASS_TOKEN || !PQZ_KINDS.contains(&kind) {
        return Err(SdkError::TokenUncatalogued);
    }
    let (_, env) = scaas_ua::factory::clone_env(&r.code).ok_or(SdkError::TokenUncatalogued)?;
    if env.chain_uid != *chain_uid {
        return Err(SdkError::ProfileMismatch);
    }
    // the set (spec §9.2), before any account word is parsed
    let (pqzl, pqzh) = set_ids();
    if r.psid != pqzl && Some(r.psid) != pqzh {
        return Err(scaas_ua::wallet::Error::PqzSetMismatch.into());
    }
    let x = r.rest.ok_or(SdkError::Internal)?;
    // R5 (T16-b): a release of 3h or later stores `proofStore` NONE or LOG
    if field(&x.slot0, "proofStore") > 1 {
        return Err(SdkError::TokenUncatalogued);
    }
    // R6: the registry's key of (ua, v), proven, is the handle's
    let ptr = low_addr(&x.key_record, 0);
    let proven = x.key_record[11] == 1;
    let code = x.blobs.iter().find(|b| b.0 == ptr).map(|b| b.1.as_slice());
    if !proven || ptr == [0; 20] || code.and_then(|c| c.split_first()) != Some((&0, pk)) {
        return Err(SdkError::LegKeyMismatch);
    }
    let words = json!({"chainUid": hex(chain_uid), "token": hex(token), "block": block, "psid": hex(&r.psid),
        "keyRecord": hex(&x.key_record), "ua": hex(ua),
        "account": x.account.iter().map(|w| hex(w)).collect::<Vec<_>>(),
        "pending": x.pending.iter().map(|(i, w)| json!({"index": i, "word": hex(w)})).collect::<Vec<_>>(),
        "accWords": x.acc_words.iter().map(|w| hex(w)).collect::<Vec<_>>(),
        "sendCounterWord": hex(&x.send_counter), "keyVersion": version, "keyVersions": hex(&x.key_versions),
        "forOp7": op7,
        "blobs": x.blobs.iter().map(|(a, c)| json!({"address": hex(a), "code": hex(c)})).collect::<Vec<_>>()});
    Ok(PqzRead {
        block,
        words,
        slot0: x.slot0,
        psid: r.psid,
        registry: x.registry,
    })
}

/// The words of `ua`'s account of key version `version` on PQZ token `token`, at the profile's final block (R1 to R7), the
/// handle's key `pk` checked against the registry's. `ChainUnknown`; `Argument`: no factory in the profile;
/// `TokenUncatalogued`, `ProfileMismatch`, `PqzSetMismatch`, `LegKeyMismatch`; the pool's codes.
pub(crate) async fn read(
    sdk: &Sdk,
    chain: &str,
    token: &str,
    ua: W,
    version: u64,
    pk: &[u8],
    op7: bool,
) -> Result<PqzRead, SdkError> {
    let (profile, _, pool) = evm(sdk, chain)?;
    let factory = addr20(&profile.factory.clone().ok_or(SdkError::Argument)?.to_ascii_lowercase())?;
    let t = addr20(&token.to_ascii_lowercase())?;
    let uid: W = unhex(&profile.chain_uid)?.try_into().map_err(|_| SdkError::Argument)?;
    let plan = Plan {
        factory: Address::from(factory),
        token: Address::from(t),
        ua,
        version,
        op7,
    };
    let (pool, plan) = (&pool, &plan);
    let a = pool
        .read_at_block(final_block(&profile), PURPOSE, |at| fetch(pool, at, plan))
        .await?;
    check(a.value, a.number, &uid, &t, &ua, version, pk, op7)
}

/// A PQZ balance read (spec §9.2, §9.4): the account of the UA key `signer` (a PQZ-capable kind, `KeyRef::Ua`) at key
/// version `key_version`, whose PQZ key is the wallet's `pqz_key_version(account, index, key_version)` of the same account and
/// index (spec §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzBalanceRequest {
    pub signer: KeyRef,
    pub chain: String,
    /// the token, `0x` + 40 hex
    pub token: String,
    pub key_version: u64,
}

/// A decrypted PQZ balance, for the holder only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzBalance {
    /// the smallest unit, decimal: what a debit at this block may spend (the account and the window `[rolled, p)`)
    pub amount: String,
    /// the final block the words were read at
    pub block: u64,
    /// the window's end and the UA's `sendCounter` at that block
    pub p: u64,
    pub send_counter: u64,
}

/// The holder's UA and PQZ key of `signer` at `version` (`Argument`: not a `KeyRef::Ua` of a PQZ-capable kind).
pub(crate) fn holder(sdk: &Sdk, signer: &KeyRef, version: u64) -> Result<(W, (Arc<OpenSeed>, PqzKey)), SdkError> {
    let KeyRef::Ua {
        seed,
        kind,
        account,
        index,
    } = signer
    else {
        return Err(SdkError::Argument);
    };
    if !scaas_ua::is_pqz_holder(*kind) {
        return Err(SdkError::Argument);
    }
    let s = sdk.open_seed(seed)?;
    let ua = s.wallet.ua_key(*kind, *account, *index)?.ua().ok_or(SdkError::Argument)?;
    let k = s.wallet.pqz_key_version(*account, *index, version)?;
    Ok((ua, (s, k)))
}

/// `cmd` of the PQZ facade on `req`, off the async workers under `Limits::max_concurrent_heavy`, the seed kept open meanwhile.
pub(crate) async fn call(sdk: &Sdk, key: (Arc<OpenSeed>, PqzKey), cmd: &'static str, req: &Value) -> Result<Value, SdkError> {
    let body = serde_json::to_vec(req).map_err(|_| SdkError::Internal)?;
    let out = sdk
        .heavy(move || {
            let (_seed, k) = key;
            Ok(k.call(cmd, &body)?)
        })
        .await?;
    serde_json::from_str(&out).map_err(|_| SdkError::Internal)
}

impl super::Confidential {
    /// The holder's PQZ balance on `token` (spec §9.2, §9.4): the words read at the profile's final block under R1 to R7, then
    /// decrypted by the facade; the amount goes to the caller only. A word set the facade refuses is `Argument` and nothing is
    /// read again. `WalletLocked`, `ChainUnknown`, `ProfileMismatch`, `TokenUncatalogued`, `PqzSetMismatch`, `LegKeyMismatch`,
    /// the pool's codes.
    pub async fn pqz_balance(&self, r: PqzBalanceRequest) -> Result<PqzBalance, SdkError> {
        let sdk = self.sdk.clone();
        self.sdk
            .spawn(async move {
                let (ua, key) = holder(&sdk, &r.signer, r.key_version)?;
                let pk = key.1.pk();
                let w = read(&sdk, &r.chain, &r.token, ua, r.key_version, &pk, false).await?;
                let out = call(&sdk, key, "balance", &w.words).await?;
                let n = |k: &str| out.get(k).and_then(Value::as_u64).ok_or(SdkError::Internal);
                Ok(PqzBalance {
                    amount: out.get("value").map(|v| v.to_string().trim_matches('"').to_string()).ok_or(SdkError::Internal)?,
                    block: w.block,
                    p: n("p")?,
                    send_counter: n("sendCounter")?,
                })
            })
            .await
    }
}

// --- the PQZ rows without a proof (spec §9.2, §21): `wallet`'s plain path, the contract's domain must be a PQZ token's ---

/// `pqz_shield` (`UAShield` on a PQZ token): `amount` of the signer's public balance into `to_ua`'s pending window.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzShield {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub to_ua: String,
    pub amount: String,
    pub envelope: crate::wallet::Envelope,
}

/// `pqz_wrap_shield` (`WrapShield` on a PQZ token): wrap `amount_in` of `underlying` and shield it to `to_ua`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzWrapShield {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub underlying: String,
    pub amount_in: String,
    pub to_ua: String,
    pub envelope: crate::wallet::Envelope,
}

/// `UAPrepareAcc` (`half` 0 or 1 of the materialisation) and `UAPqzRollOver` (`n` pending entries) of `ua`'s account at key
/// version `key_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqzAccountOp {
    pub signer: KeyRef,
    pub chain: String,
    pub token: String,
    pub batch: String,
    pub ua: String,
    pub key_version: u64,
    /// `half` for `UAPrepareAcc`, `n` for `UAPqzRollOver`
    pub value: String,
    pub envelope: crate::wallet::Envelope,
}

impl super::Confidential {
    #[allow(clippy::too_many_arguments)]
    async fn pqz_plain(
        &self,
        name: &'static str,
        signer: KeyRef,
        chain: String,
        token: String,
        batch: String,
        fields: serde_json::Map<String, Value>,
        env: crate::wallet::Envelope,
    ) -> Result<Arc<crate::op::Prepared>, SdkError> {
        let p = self.sdk.wallet().plain(name, signer, chain, token, batch, fields, env).await?;
        if p.t.kind != "pqz" {
            return Err(SdkError::Argument);
        }
        Ok(p)
    }

    /// Prepares `pqz_shield` (`UAShield` on a PQZ token; spec §9.2): `ProfileMismatch`, `Argument` (not a PQZ token).
    pub async fn prepare_pqz_shield(&self, r: PqzShield) -> Result<Arc<crate::op::Prepared>, SdkError> {
        let mut f = serde_json::Map::new();
        f.insert("toUA".into(), json!(r.to_ua));
        f.insert("amount".into(), json!(r.amount));
        self.pqz_plain("UAShield", r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }

    /// Prepares `pqz_wrap_shield` (`WrapShield` on a PQZ token).
    pub async fn prepare_pqz_wrap_shield(&self, r: PqzWrapShield) -> Result<Arc<crate::op::Prepared>, SdkError> {
        let mut f = serde_json::Map::new();
        f.insert("underlying".into(), json!(r.underlying));
        f.insert("amountIn".into(), json!(r.amount_in));
        f.insert("toUA".into(), json!(r.to_ua));
        self.pqz_plain("WrapShield", r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }

    /// Prepares `UAPrepareAcc` (`value`: the `half`).
    pub async fn prepare_pqz_prepare_acc(&self, r: PqzAccountOp) -> Result<Arc<crate::op::Prepared>, SdkError> {
        self.account_op("UAPrepareAcc", "half", r).await
    }

    /// Prepares `UAPqzRollOver` (`value`: the `n` entries rolled over).
    pub async fn prepare_pqz_roll_over(&self, r: PqzAccountOp) -> Result<Arc<crate::op::Prepared>, SdkError> {
        self.account_op("UAPqzRollOver", "n", r).await
    }

    async fn account_op(&self, name: &'static str, k: &str, r: PqzAccountOp) -> Result<Arc<crate::op::Prepared>, SdkError> {
        let mut f = serde_json::Map::new();
        f.insert("ua".into(), json!(r.ua));
        f.insert("keyVersion".into(), json!(r.key_version.to_string()));
        f.insert(k.into(), json!(r.value));
        self.pqz_plain(name, r.signer, r.chain, r.token, r.batch, f, r.envelope).await
    }
}
