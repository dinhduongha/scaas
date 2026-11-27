// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's TreeKEM mode at the SDK (spec 2026-11-23-pqchat-treekem §8, §10, §13, §15; CLI-PQC-17; plan T5): thin calls over
//! `scaas-ua`'s tree (`wallet::tree`, PqChat's scope `PQCHAT_TREE`): the creation, a commit prepared, reviewed and signed, the
//! exits, the replay and its resumption, the registry's KEM records with their kept signatures (codex-1), and the plan of a
//! commit's transactions in C37's order and of a creation in one transaction. The home's views come from the caller
//! ([`PqTreeReads`]; `pqchat-core` reads them through its port, CLI-PQC-13): each call is a function of the reads it is given
//! and names the reads it misses ([`PqTreeStep::Need`]). No tree logic of its own, no key byte out of `scaas-ua`, no
//! "rejoin" call. UNAUDITED.
use crate::app_core::{AppCore, AppInnerSig, AppKey, AppMemberSig, AppUaSig};
use crate::error::SdkError;
use crate::op::{hex, KeyRef};
use scaas_ua::ua_portable::{KemKey, UAAttrs, UASig};
use scaas_ua::wallet::tree::{
    self, CommitInput, PathlessInput, PreparedCommit, Replay, TargetKey, TreeDevice, TreePrepared,
    TreeReader, View, PQCHAT_TREE,
};
use scaas_ua::wallet::tree_public::{Add, KemRecord, Remove};
use serde_json::Value;
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

fn h32(s: &str) -> Result<[u8; 32], SdkError> {
    crate::app_core::hex32(&s.to_ascii_lowercase())
}

fn unhex(s: &str) -> Result<Vec<u8>, SdkError> {
    let t = s.strip_prefix("0x").ok_or(SdkError::Argument)?;
    alloy::hex::decode(t).map_err(|_| SdkError::Argument)
}

// ------------------------------------------------------------------ the reads

/// `kemHash` of a KEM key (`keccak256(scheme ‖ ek ‖ x25519)`, the leaf's hash of spec §4), `0x` hex; `None` for a key that is
/// not hex.
pub fn kem_hash(kem_pk: &str) -> Option<String> {
    unhex(kem_pk).ok().map(|k| hex(&scaas_ua::keccak256(&k)))
}

/// A UA's registered key (`registrationOf`'s `kind` and `keyData`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PqUaKey {
    pub kind: u16,
    pub key_data: String,
}

/// A UA's registration attributes and `pop` (`registrationOf`), the record of its version-0 KEM key; `kem_pk` the assembled
/// `scheme ‖ ek ‖ x25519` (empty for none).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PqRegistration {
    pub pqz_key: String,
    pub pqz_pop_hash: String,
    pub kem_pk: String,
    pub kem_pk_hash: String,
    pub pop: String,
}

/// The reads a tree call works on: the home's views by name (`scaas-ua`'s `View`: `sessionOf()`, `commitOf(3)`,
/// `kemKeyAt(0x…,2)`, …) in the views' JSON shape, and the registry's records of the signers and members by UA. An entry read
/// and found empty is present (an empty `msigAt` is `("0x", "0x")`, an unregistered UA no `registration`).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PqTreeReads {
    pub views: BTreeMap<String, Value>,
    /// `registrationOf(ua)`: kind and key data (`None`: read, not registered)
    pub keys: BTreeMap<String, Option<PqUaKey>>,
    /// `msigStateOf(ua).accepted`'s slots
    pub accepted: BTreeMap<String, Vec<u16>>,
    /// `msigAt(ua, version)`: the structure and its `enabled` word, hex
    pub msigs: BTreeMap<String, BTreeMap<u64, (String, String)>>,
    /// `registrationOf(ua)`'s attributes and `pop` (`None`: read, none)
    pub registrations: BTreeMap<String, Option<PqRegistration>>,
}

/// A tree call's answer: done, or the reads it misses (by name; the caller reads them, adds them and calls again).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqTreeStep<T> {
    Done(T),
    Need(Vec<String>),
}

/// [`PqTreeReads`] as `scaas-ua`'s reader; every read it does not hold is named in `missed`.
struct Snap<'a> {
    r: &'a PqTreeReads,
    missed: RefCell<Vec<String>>,
}

impl<'a> Snap<'a> {
    fn new(r: &'a PqTreeReads) -> Self {
        Snap {
            r,
            missed: RefCell::new(Vec::new()),
        }
    }
    fn miss(&self, name: String) {
        let mut m = self.missed.borrow_mut();
        if !m.contains(&name) {
            m.push(name);
        }
    }
    /// `Done(v)` unless a read was missing: then the reads to make (whatever `v` was: a miss may have caused it).
    fn step<T>(&self, v: Result<T, SdkError>) -> Result<PqTreeStep<T>, SdkError> {
        let m = self.missed.borrow();
        if !m.is_empty() {
            return Ok(PqTreeStep::Need(m.clone()));
        }
        v.map(PqTreeStep::Done)
    }
}

impl TreeReader for Snap<'_> {
    fn read(&mut self, v: View) -> scaas_ua::wallet::Result<Value> {
        let k = v.to_string();
        match self.r.views.get(&k) {
            Some(x) => Ok(norm(x)),
            None => {
                self.miss(k);
                Err(scaas_ua::wallet::Error::Argument)
            }
        }
    }
    fn ua_key_of(&self, ua: &[u8; 32]) -> Option<(u16, Vec<u8>)> {
        let k = hex(ua);
        match self.r.keys.get(&k) {
            Some(Some(x)) => Some((x.kind, unhex(&x.key_data).ok()?)),
            Some(None) => None,
            None => {
                self.miss(format!("registrationOf({k})"));
                None
            }
        }
    }
    fn accepted(&self, ua: &[u8; 32], index: u16) -> bool {
        let k = hex(ua);
        match self.r.accepted.get(&k) {
            Some(v) => v.contains(&index),
            None => {
                self.miss(format!("msigStateOf({k})"));
                false
            }
        }
    }
    fn msig_at(&self, ua: &[u8; 32], version: u64) -> Option<(Vec<u8>, [u8; 32])> {
        let k = hex(ua);
        match self.r.msigs.get(&k).and_then(|m| m.get(&version)) {
            Some((s, e)) => {
                let s = unhex(s).ok()?;
                let e = unhex(e).ok()?;
                (!s.is_empty()).then_some(())?;
                Some((s, e.try_into().ok()?))
            }
            None => {
                self.miss(format!("msigAt({k},{version})"));
                None
            }
        }
    }
    fn registration(&self, ua: &[u8; 32]) -> Option<(UAAttrs, Vec<u8>)> {
        let k = hex(ua);
        match self.r.registrations.get(&k) {
            Some(Some(x)) => Some((
                UAAttrs {
                    pqz_key: unhex(&x.pqz_key).ok()?,
                    pqz_pop_hash: h32(&x.pqz_pop_hash).ok()?,
                    kem: match unhex(&x.kem_pk).ok()? {
                        pk if pk.is_empty() => KemKey::default(),
                        pk => KemKey::from_kem_pk(&pk).ok()?,
                    },
                    kem_pk_hash: h32(&x.kem_pk_hash).ok()?,
                },
                unhex(&x.pop).ok()?,
            )),
            Some(None) => None,
            None => {
                self.miss(format!("registrationOf({k})"));
                None
            }
        }
    }
}

/// A served view in `scaas-ua`'s shape: the SDK's named JSON (integers as decimal strings) with numbers as numbers, and a
/// kept `UASig` (`{keyData, signature, members}`) as `scaas-ua` reads it: a single key's `signature` hex, an `msig`'s
/// `{signature, members: abi.encode(MemberSig[])}`.
fn norm(v: &Value) -> Value {
    match v {
        Value::String(t)
            if !t.is_empty() && t.len() <= 20 && t.bytes().all(|b| b.is_ascii_digit()) =>
        {
            t.parse::<u64>().map_or_else(|_| v.clone(), Value::from)
        }
        Value::Array(a) => Value::Array(a.iter().map(norm).collect()),
        Value::Object(o)
            if o.contains_key("keyData")
                && o.contains_key("signature")
                && o.contains_key("members") =>
        {
            let sig = o.get("signature").cloned().unwrap_or(Value::Null);
            match ua_sig_members(o.get("members")) {
                Some(m) if m.is_empty() => sig,
                Some(m) => {
                    serde_json::json!({"signature": sig, "members": hex(&scaas_ua::ua_portable::encode_member_sigs(&m))})
                }
                None => Value::Null,
            }
        }
        Value::Object(o) => Value::Object(o.iter().map(|(k, x)| (k.clone(), norm(x))).collect()),
        x => x.clone(),
    }
}

/// A kept `UASig`'s `members` (named JSON) as `MemberSig`s; `None` when they do not decode.
fn ua_sig_members(v: Option<&Value>) -> Option<Vec<scaas_ua::ua_portable::MemberSig>> {
    use scaas_ua::ua_portable::{InnerSig, MemberSig};
    let idx = |x: &Value| x.get("index")?.as_str()?.parse::<u16>().ok();
    let by = |x: &Value, k: &str| unhex(x.get(k)?.as_str()?).ok();
    v?.as_array()?
        .iter()
        .map(|m| {
            Some(MemberSig {
                index: idx(m)?,
                members: m
                    .get("members")?
                    .as_array()?
                    .iter()
                    .map(|x| {
                        Some(InnerSig {
                            index: idx(x)?,
                            sig: by(x, "sig")?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
                sig: by(m, "sig")?,
            })
        })
        .collect()
}

/// The registry record of `(ua, keyId)`'s KEM key from the reads (`kemKeyAt` with its kept signature, the UA's key, and for
/// version 0 its registration), as `scaas-ua` authenticates it (spec §8 step 5); `None` when a read is missing or empty.
fn kem_record(rd: &mut Snap, ua: &[u8; 32], key_id: u64) -> Option<KemRecord> {
    let v = rd.read(View::KemKeyAt(ua, key_id)).ok()?;
    let kem_pk = unhex(v.get("kemPk")?.as_str()?).ok()?;
    let sig = unhex(v.get("sig")?.as_str()?).ok()?;
    let (kind, key_data) = rd.ua_key_of(ua)?;
    Some(if key_id > 0 {
        KemRecord::Version {
            kind,
            key_data,
            kem_pk,
            sig,
        }
    } else {
        let (attrs, pop) = rd.registration(ua)?;
        KemRecord::Registration {
            kind,
            key_data,
            attrs,
            pop,
            kem_pk,
        }
    })
}

fn sig_of(s: &UASig) -> AppUaSig {
    AppUaSig {
        key_data: s.key_data.clone(),
        signature: s.signature.clone(),
        members: s
            .members
            .iter()
            .map(|m| AppMemberSig {
                index: m.index,
                members: m
                    .members
                    .iter()
                    .map(|x| AppInnerSig {
                        index: x.index,
                        sig: x.sig.clone(),
                    })
                    .collect(),
                sig: m.sig.clone(),
            })
            .collect(),
    }
}

// ------------------------------------------------------------------ the registry's records (codex-1)

alloy::sol! {
    struct TreeKemKey { uint8 scheme; bytes mlkemEk; bytes32 x25519; }
    struct TreeUAAttrs { bytes pqzKey; bytes32 pqzPopHash; TreeKemKey kem; bytes32 kemPkHash; }
    function registrationOf(bytes32 ua) external view returns (uint16 kind, bytes keyData, TreeUAAttrs attrs, bytes pop, bytes pqzPop);
    function kemKeyAt(bytes32 ua, uint64 version) external view returns (TreeKemKey kem, bytes sig);
    function msigStateOf(bytes32 ua) external view returns (uint64 version, uint256 enabled, uint256 accepted);
}

/// `scheme ‖ ek ‖ x25519` of a scheme-1 key with a 1,568-byte `ek`; empty otherwise (no key `scaas-ua` takes).
fn kem_pk(k: &TreeKemKey) -> Vec<u8> {
    if k.scheme != 1 || k.mlkemEk.len() != 1568 {
        return vec![];
    }
    [&[1u8][..], &k.mlkemEk, k.x25519.as_slice()].concat()
}

/// `kemKeyAt(ua, v)`'s answer as the `kemKeyAt` view: the key and **its kept signature** (codex-1; `setKemKey`'s, which the
/// cold tree's walk authenticates the key by).
fn kem_view(out: &[u8]) -> Result<Value, SdkError> {
    use alloy::sol_types::SolCall;
    let r = kemKeyAtCall::abi_decode_returns(out).map_err(|_| SdkError::Argument)?;
    Ok(serde_json::json!({"kemPk": hex(&kem_pk(&r.kem)), "sig": hex(&r.sig)}))
}

/// The slots an `accepted` word sets (bit `i` = slot `i`), as the direct path decodes `msigStateOf`.
fn slots_of(accepted: alloy::primitives::U256) -> Vec<u16> {
    let a = accepted.to_be_bytes::<32>();
    (0..256u16)
        .filter(|i| {
            a.get(31 - usize::from(*i) / 8)
                .is_some_and(|b| b >> (i % 8) & 1 == 1)
        })
        .collect()
}

/// `v[k]`, `Null` when absent.
fn at<'a>(v: &'a Value, k: &str) -> &'a Value {
    v.get(k).unwrap_or(&Value::Null)
}

/// A decimal uint256 string's bits set (little-endian bit `i` = slot `i`), at most 256.
fn bits_of(dec: &str) -> Option<Vec<u16>> {
    let n = alloy::primitives::U256::from_str_radix(dec, 10).ok()?;
    Some((0..256u16).filter(|i| n.bit(usize::from(*i))).collect())
}

impl PqTreeReads {
    /// `IUARegistry.registrationOf(ua)`'s named answer (`{kind, keyData, attrs: {pqzKey, pqzPopHash, kem: {scheme,
    /// mlkemEk, x25519}, kemPkHash}, pop, pqzPop}`, read by the caller's port at the final block, trusted): the UA's key and
    /// its registration; kind 0 is read and not registered.
    pub fn put_registration(&mut self, ua: &str, v: &Value) -> Result<(), SdkError> {
        let k = hex(&h32(ua)?);
        let s = |x: &Value| x.as_str().map(str::to_string).ok_or(SdkError::Argument);
        let kind: u16 = s(at(v, "kind"))?.parse().map_err(|_| SdkError::Argument)?;
        if kind == 0 {
            self.keys.insert(k.clone(), None);
            self.registrations.insert(k, None);
            return Ok(());
        }
        let a = at(v, "attrs");
        let kem = TreeKemKey {
            scheme: s(at(at(a, "kem"), "scheme"))?
                .parse()
                .map_err(|_| SdkError::Argument)?,
            mlkemEk: unhex(&s(at(at(a, "kem"), "mlkemEk"))?)?.into(),
            x25519: h32(&s(at(at(a, "kem"), "x25519"))?)?.into(),
        };
        self.keys.insert(
            k.clone(),
            Some(PqUaKey {
                kind,
                key_data: s(at(v, "keyData"))?,
            }),
        );
        self.registrations.insert(
            k,
            Some(PqRegistration {
                pqz_key: s(at(a, "pqzKey"))?,
                pqz_pop_hash: s(at(a, "pqzPopHash"))?,
                kem_pk: hex(&kem_pk(&kem)),
                kem_pk_hash: s(at(a, "kemPkHash"))?,
                pop: s(at(v, "pop"))?,
            }),
        );
        Ok(())
    }

    /// `IUARegistry.kemKeyAt(ua, version)`'s named answer (`{kem: {scheme, mlkemEk, x25519}, sig}`) as the view `name`: the
    /// key **with its kept signature** (codex-1).
    pub fn put_kem_key_at(&mut self, name: &str, v: &Value) -> Result<(), SdkError> {
        let s = |x: &Value| x.as_str().map(str::to_string).ok_or(SdkError::Argument);
        let kem = TreeKemKey {
            scheme: s(at(at(v, "kem"), "scheme"))?
                .parse()
                .map_err(|_| SdkError::Argument)?,
            mlkemEk: unhex(&s(at(at(v, "kem"), "mlkemEk"))?)?.into(),
            x25519: h32(&s(at(at(v, "kem"), "x25519"))?)?.into(),
        };
        self.views.insert(
            name.to_string(),
            serde_json::json!({"kemPk": hex(&kem_pk(&kem)), "sig": s(at(v, "sig"))?}),
        );
        Ok(())
    }

    /// `IUARegistry.msigStateOf(ua)`'s named answer: its accepted slots.
    pub fn put_msig_state(&mut self, ua: &str, v: &Value) -> Result<(), SdkError> {
        let a = at(v, "accepted")
            .as_str()
            .and_then(bits_of)
            .ok_or(SdkError::Argument)?;
        self.accepted.insert(hex(&h32(ua)?), a);
        Ok(())
    }

    /// `IUARegistry.msigAt(ua, version)`'s named answer (`{s: {threshold, members: [{kind, id, weight}]}, enabled}`): the
    /// structure as its key data and the `enabled` word; an empty answer (threshold 0) read as none.
    pub fn put_msig_at(&mut self, ua: &str, version: u64, v: &Value) -> Result<(), SdkError> {
        use scaas_ua::ua_portable::{MsigMember, MsigStructure};
        let n = |x: &Value| {
            x.as_str()
                .and_then(|t| t.parse::<u16>().ok())
                .ok_or(SdkError::Argument)
        };
        let st = at(v, "s");
        let threshold = n(at(st, "threshold"))?;
        let e = if threshold == 0 {
            ("0x".to_string(), "0x".to_string())
        } else {
            let members = at(st, "members")
                .as_array()
                .ok_or(SdkError::Argument)?
                .iter()
                .map(|m| {
                    Ok(MsigMember {
                        kind: n(at(m, "kind"))?,
                        id: h32(at(m, "id").as_str().ok_or(SdkError::Argument)?)?,
                        weight: n(at(m, "weight"))?,
                    })
                })
                .collect::<Result<Vec<_>, SdkError>>()?;
            let en = alloy::primitives::U256::from_str_radix(
                at(v, "enabled").as_str().ok_or(SdkError::Argument)?,
                10,
            )
            .map_err(|_| SdkError::Argument)?;
            (
                hex(&MsigStructure { threshold, members }.key_data()),
                hex(&en.to_be_bytes::<32>()),
            )
        };
        self.msigs
            .entry(hex(&h32(ua)?))
            .or_default()
            .insert(version, e);
        Ok(())
    }
}

/// A registry name a tree call missed (`registrationOf(<ua>)`, `kemKeyAt(<ua>,<v>)`, `msigStateOf(<ua>)`, `msigAt(<ua>,<v>)`):
/// its UA and number; `None` for a home view (the caller's port reads those).
pub fn registry_name(name: &str) -> Option<(&str, [u8; 32], u64)> {
    let (f, rest) = name.split_once('(')?;
    let args = rest.strip_suffix(')')?;
    let (ua, n) = match args.split_once(',') {
        Some((u, n)) => (u, n.parse().ok()?),
        None => (args, 0),
    };
    matches!(f, "registrationOf" | "kemKeyAt" | "msigStateOf" | "msigAt")
        .then(|| Some((f, h32(ua).ok()?, n)))
        .flatten()
}

impl AppCore {
    /// The registry's records the names (of a [`PqTreeStep::Need`]) ask for, read at the profile's final block on `chain` as
    /// reads that feed a decryption, each at the generation that holds the UA, into `reads`: a KEM key **with its kept
    /// signature** (`kemKeyAt`), a UA's registered key and its registration's attributes and `pop` (`registrationOf`), an
    /// `msig`'s accepted slots (`msigStateOf`) and its structure at a version (`msigAt`). A home view among the names is left
    /// to the caller; the names this call read are returned.
    pub async fn pqchat_tree_registry(
        &self,
        chain: &str,
        names: &[String],
        reads: &mut PqTreeReads,
    ) -> Result<Vec<String>, SdkError> {
        use alloy::sol_types::SolCall;
        let (profile, _, _) = crate::op::evm(&self.sdk, chain)?;
        let mut done = Vec::new();
        for name in names {
            let Some((f, ua, n)) = registry_name(name) else {
                continue;
            };
            let mut w = [0u8; 32];
            w[24..].copy_from_slice(&n.to_be_bytes());
            let sig = match f {
                "registrationOf" => "registrationOf(bytes32)",
                "kemKeyAt" => "kemKeyAt(bytes32,uint64)",
                "msigStateOf" => "msigStateOf(bytes32)",
                _ => "msigAt(bytes32,uint64)",
            };
            let args: Vec<[u8; 32]> = if matches!(f, "kemKeyAt" | "msigAt") {
                vec![ua, w]
            } else {
                vec![ua]
            };
            let (out, _) = crate::line::read_line(
                &self.sdk,
                chain,
                crate::op::final_block(&profile),
                scaas_rpc::Purpose::FeedsDecryption,
                |pool, at, line| {
                    let args = args.clone();
                    async move {
                        let to = line.holder(&pool, &at, ua).await?.unwrap_or(line.bound());
                        crate::line::call_at(&pool, &at, to, sig, &args).await
                    }
                },
            )
            .await?;
            let k = hex(&ua);
            match f {
                "registrationOf" => {
                    let r = registrationOfCall::abi_decode_returns(&out)
                        .map_err(|_| SdkError::Argument)?;
                    if r.kind == 0 {
                        reads.keys.insert(k.clone(), None);
                        reads.registrations.insert(k, None);
                    } else {
                        reads.keys.insert(
                            k.clone(),
                            Some(PqUaKey {
                                kind: r.kind,
                                key_data: hex(&r.keyData),
                            }),
                        );
                        reads.registrations.insert(
                            k,
                            Some(PqRegistration {
                                pqz_key: hex(&r.attrs.pqzKey),
                                pqz_pop_hash: hex(r.attrs.pqzPopHash.as_slice()),
                                kem_pk: hex(&kem_pk(&r.attrs.kem)),
                                kem_pk_hash: hex(r.attrs.kemPkHash.as_slice()),
                                pop: hex(&r.pop),
                            }),
                        );
                    }
                }
                "kemKeyAt" => {
                    reads.views.insert(name.clone(), kem_view(&out)?);
                }
                "msigStateOf" => {
                    let r = msigStateOfCall::abi_decode_returns(&out)
                        .map_err(|_| SdkError::Argument)?;
                    reads.accepted.insert(k, slots_of(r.accepted));
                }
                _ => {
                    let s = crate::account::msig::decode_structure(&out);
                    let en = out.get(32..64).map(<[u8]>::to_vec);
                    let e = match (s, en) {
                        (Some(s), Some(en)) if !s.is_empty() => (hex(&s), hex(&en)),
                        _ => ("0x".into(), "0x".into()),
                    };
                    reads.msigs.entry(k).or_default().insert(n, e);
                }
            }
            done.push(name.clone());
        }
        Ok(done)
    }
}

// ------------------------------------------------------------------ creation

/// A created tree session (C29): the session record to sign (with `wrapHashes` and `sealedInfo`, `groupMode` 1), its ids,
/// the wraps of epoch 0 (one per member key, sent with the record: T5's creation in one transaction) and `K_0`.
pub struct PqTreeGenesis {
    pub record: Value,
    pub session_id: String,
    pub tree_id: String,
    pub genesis_ctx: String,
    pub wraps: Vec<Value>,
    pub k: Arc<AppKey>,
}

/// The client default of `pathRefreshBound` (C46; owner 2026-11-25, the delta's R18 as amended: 20): what a creation names
/// when its caller names none; 0 only when named.
pub const PATH_REFRESH_BOUND_DEFAULT: u64 = 20;

/// The `try`s of a path-less Add's nonce per head (C47), `scaas-ua`'s.
pub use scaas_ua::wallet::tree::ADD_NONCE_TRIES;

/// The creation review's line of a session's bound (the path-less delta §3.1, C46).
pub fn refresh_line(bound: u64) -> String {
    if bound == 0 {
        format!(
            "key refresh never forced; the admins are warned after {} added keys",
            tree::PATHLESS_WARN_LEAVES
        )
    } else {
        format!(
            "key refresh forced after {bound} added keys; the admins are warned from {}",
            tree::warn_at(u32::try_from(bound).unwrap_or(u32::MAX))
        )
    }
}

/// A commit's changes as the caller asks them: the Removes and the Adds (`TreeRemove`, `TreeAdd` JSON; each added key's
/// registry record comes from the reads), the admins after it, and the info to seal (`None`: the marker "unchanged").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PqTreeChanges {
    pub removes: Vec<Value>,
    pub adds: Vec<Value>,
    pub admins: Vec<String>,
    pub info: Option<String>,
}

/// A commit built and prepared for its author's signature: its review and digest; [`Self::sign`] signs exactly it.
pub struct PqTreeCommit {
    pub review: Vec<(String, String)>,
    pub digest: String,
    pub epoch_id: String,
    pub record: Value,
    core: Arc<AppCore>,
    account: KeyRef,
    seed: String,
    p: Mutex<Option<PreparedCommit>>,
}

/// A signed commit: the record, its pieces and `K_e`'s handle (spec §6: `commit(c, ctTargets, ctHashes, nodeKeys, cts, wraps,
/// sig)` and the three piece entries take them by name).
pub struct PqTreeCommitSigned {
    pub record: Value,
    pub epoch_id: String,
    pub ct_targets: Vec<u32>,
    pub ct_hashes: Vec<String>,
    pub node_keys: Vec<Vec<u8>>,
    pub cts: Vec<Value>,
    pub wraps: Vec<Value>,
    pub sig: AppUaSig,
    pub k: Arc<AppKey>,
}

impl PqTreeCommit {
    /// The author's signature over the record built here, once.
    pub fn sign(&self) -> Result<PqTreeCommitSigned, SdkError> {
        // B-15 of the T4-T9 review: the key first, so a locked seed leaves the prepared record for a later try
        let crate::op::Key::Ua(_, key) = crate::op::key(&self.core.sdk, &self.account)? else {
            return Err(SdkError::Argument);
        };
        let p = self
            .p
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(SdkError::Argument)?;
        let (b, sig) = p.sign(&key)?;
        Ok(PqTreeCommitSigned {
            record: b.record,
            epoch_id: hex(&b.epoch_id),
            ct_targets: b.ct_targets,
            ct_hashes: b.ct_hashes.iter().map(|h| hex(h)).collect(),
            node_keys: b.node_keys,
            cts: b.cts.iter().map(tree::PathCt::to_json).collect(),
            wraps: b.wraps,
            sig: sig_of(&sig),
            k: self.core.wrap(&self.seed, b.k),
        })
    }
}

/// A tree exit (`PqChatTreeLeave`, `PqChatTreeRemove`) prepared for its signature: review, digest, the record by name.
pub struct PqTreeExit {
    pub review: Vec<(String, String)>,
    pub digest: String,
    pub record: Value,
    core: Arc<AppCore>,
    account: KeyRef,
    p: Mutex<Option<TreePrepared>>,
}

impl PqTreeExit {
    /// The signature over exactly the prepared record, once.
    pub fn sign(&self) -> Result<AppUaSig, SdkError> {
        let crate::op::Key::Ua(_, key) = crate::op::key(&self.core.sdk, &self.account)? else {
            return Err(SdkError::Argument);
        };
        let p = self
            .p
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(SdkError::Argument)?;
        Ok(sig_of(&p.sign(&key)?))
    }
}

/// `PqChatTreeLeave`'s fields (the member is the signing account's UA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreeLeave {
    pub session_id: String,
    pub tree_id: String,
    pub epoch_id: String,
    pub nonce: u64,
}

/// `PqChatTreeRemove`'s fields (the admin is the signing account's UA).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreeRemove {
    pub session_id: String,
    pub tree_id: String,
    pub epoch_id: String,
    pub next_epoch: u64,
    pub members: Vec<String>,
    pub nonce: u64,
}

// ------------------------------------------------------------------ replay

/// One epoch of a device's replay: its state (`followed`, `not followed: <reason>`, `compromise`), `K` (when followed and
/// asked for), what its `sealedInfo` did and the info in force after it.
pub struct PqTreeEpoch {
    pub epoch: u64,
    pub epoch_id: String,
    /// its record's author (epoch 0: the creator) and the admins after it, lowercase hex
    pub author: String,
    pub admins: Vec<String>,
    pub state: String,
    pub k: Option<Arc<AppKey>>,
    pub info: Option<String>,
    pub in_force: Option<String>,
    pub flagged: bool,
}

/// A compromise warning (R10): what the foreign commit of this device's own key added and removed, whether it changed the
/// admins, and which of its added leaves are still in the tree at the head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreeWarning {
    pub epoch: u64,
    pub adds: Vec<(u32, String, u64)>,
    pub removes: Vec<Value>,
    pub admins_changed: bool,
    pub leaves_left: Vec<u32>,
}

/// A device's replay (spec §10): its leaf, join and end epochs, the epochs of its range, the warnings, the pin (public, for
/// the store) and the node keys it holds (inside `scaas-ua`, for [`AppCore::pqchat_tree_resume`]).
pub struct PqTreeReplay {
    pub leaf: u32,
    pub join_epoch: u64,
    pub end_epoch: Option<u64>,
    pub epochs: Vec<PqTreeEpoch>,
    pub warnings: Vec<PqTreeWarning>,
    pub pin: Value,
    /// the info a commit of this device seals (C33): the full info in force, else `None` (the marker)
    pub info_to_seal: Option<String>,
    /// by epoch of the range, each leaf's `(ua, keyId)` (`None` blank): the roster the forward walk reached (C25)
    pub rosters: BTreeMap<u64, Vec<Option<(String, u64)>>>,
    /// the path-less delta §6.2: the C45 epochs ("the author did not hold the epoch") with their added leaves
    pub suspects: Vec<PqTreeWarning>,
    /// the leaves under review (F-3): every still-live leaf a warning or a C45 epoch names; listed by every path commit's
    /// review, never keyed by a commit this client builds by itself
    pub review: Vec<u32>,
    /// the walk's `sincePath` at the head, the session's bound, and the admins' warning (R18, C46: `sincePath ≥ W(N)` on an
    /// admin's device)
    pub since_path: u32,
    pub path_bound: u32,
    pub path_warning: bool,
    /// whether the device holds the head's epoch (its handle with `next`, inside `scaas-ua`): a path-less Add can be built
    pub holds_head: bool,
    inner: Mutex<Replay>,
}

impl PqTreeReplay {
    /// A resume's replay ([`AppCore::pqchat_tree_resume`]) takes the node keys of `from` it keeps on, once the caller keeps it
    /// (its pin stored: D-5, U-a of the T4-T9 re-check), and `from` is consumed: a resume from it again is refused
    /// (`TreePeriod`, R2-C-2). Nothing for a replay that was not resumed, or for `from` itself.
    pub fn adopt(&self, from: &PqTreeReplay) {
        if std::ptr::eq(self, from) {
            return;
        }
        let mut f = from.inner.lock().unwrap_or_else(PoisonError::into_inner);
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .adopt(&mut f);
    }
}

impl AppCore {
    fn device_kem(
        &self,
        account: &KeyRef,
        key_id: u64,
    ) -> Result<(String, [u8; 32], scaas_ua::wallet::KemKeyPair), SdkError> {
        let KeyRef::Ua {
            seed,
            kind,
            account: a,
            index,
        } = account
        else {
            return Err(SdkError::Argument);
        };
        let k = self.sdk.open_seed(seed)?.wallet.ua_key(*kind, *a, *index)?;
        let ua = k.ua().ok_or(SdkError::Argument)?;
        Ok((seed.clone(), ua, k.kem_key(key_id)?))
    }

    /// Creation in order (C29): `session` (the record without `wrapHashes` and `sealedInfo`, `groupMode` 1, `account`'s UA its
    /// creator), each member key authenticated by its registry record from `reads` and admitted, `info` the session info's
    /// canonical JSON. The record is then signed by [`AppCore::prepare_pqchat_tree_session`].
    pub fn pqchat_tree_genesis(
        &self,
        account: KeyRef,
        session: Value,
        reads: &PqTreeReads,
        info: String,
    ) -> Result<PqTreeStep<PqTreeGenesis>, SdkError> {
        self.label(PQCHAT_TREE.prefix.as_bytes())?;
        let (seed, me, _) = self.device_kem(&account, 0)?;
        // C46: the default bound when the caller names none (0 only when named)
        let mut session = session;
        if let Some(o) = session.as_object_mut() {
            o.entry("pathRefreshBound")
                .or_insert(Value::from(PATH_REFRESH_BOUND_DEFAULT));
        }
        if session.get("groupMode").and_then(Value::as_u64) != Some(1)
            || session
                .get("creator")
                .and_then(Value::as_str)
                .and_then(|c| h32(c).ok())
                != Some(me)
        {
            return Err(SdkError::Argument);
        }
        let mut rd = Snap::new(reads);
        let mut kems = Vec::new();
        for m in session
            .get("members")
            .and_then(Value::as_array)
            .ok_or(SdkError::Argument)?
        {
            let ua = h32(m
                .get("ua")
                .and_then(Value::as_str)
                .ok_or(SdkError::Argument)?)?;
            let key_id = m
                .get("keyId")
                .and_then(Value::as_u64)
                .ok_or(SdkError::Argument)?;
            if let Some(r) = kem_record(&mut rd, &ua, key_id) {
                kems.push(r);
            }
        }
        if !rd.missed.borrow().is_empty() {
            return rd.step(Err(SdkError::Argument));
        }
        let g = self.scope(&seed)?.tree_create_genesis(
            &PQCHAT_TREE,
            &session,
            &kems,
            info.as_bytes(),
        )?;
        Ok(PqTreeStep::Done(PqTreeGenesis {
            record: g.record,
            session_id: hex(&g.session_id),
            tree_id: hex(&g.tree_id),
            genesis_ctx: hex(&g.genesis_ctx),
            wraps: g.wraps,
            k: self.wrap(&seed, g.k),
        }))
    }

    /// A commit by `account`'s leaf `leaf` (its KEM key `key_id`) on the head the forward walk reaches over `reads`, from
    /// `pin` (the store's checkpoint) or from the cold tree (spec §8, §15): built inside `scaas-ua`, reviewed, then signed.
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_tree_prepare_commit(
        self: &Arc<Self>,
        account: KeyRef,
        key_id: u64,
        leaf: u32,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        ch: PqTreeChanges,
    ) -> Result<PqTreeStep<PqTreeCommit>, SdkError> {
        self.label(PQCHAT_TREE.prefix.as_bytes())?;
        let (seed, me, kem) = self.device_kem(&account, key_id)?;
        let pin = pin.map(tree::Pin::from_json).transpose()?;
        let mut rd = Snap::new(reads);
        let prepared = match tree::tree_prepare(&PQCHAT_TREE, &mut rd, pin.as_ref()) {
            Ok(p) => p,
            Err(e) => return rd.step(Err(e.into())),
        };
        let session = rd.read(View::SessionOf).ok();
        let tree_id = rd
            .read(View::TreeOf)
            .ok()
            .and_then(|v| v.get("treeId").and_then(Value::as_str).map(h32));
        let (Some(session), Some(Ok(tree_id))) = (session, tree_id) else {
            return rd.step(Err(SdkError::Argument));
        };
        let creator = session
            .pointer("/record/creator")
            .and_then(Value::as_str)
            .map(h32)
            .transpose()?
            .ok_or(SdkError::Argument)?;
        let nonce = session
            .pointer("/record/nonce")
            .and_then(Value::as_u64)
            .ok_or(SdkError::Argument)?;
        let session_id = PQCHAT_TREE.session_id(&creator, nonce);
        let removes = ch
            .removes
            .iter()
            .map(Remove::from_json)
            .collect::<scaas_ua::wallet::Result<Vec<_>>>()?;
        let mut adds = Vec::new();
        for a in &ch.adds {
            let x = Add::from_json(a)?;
            match kem_record(&mut rd, &x.ua, x.key_id) {
                Some(r) => adds.push((x, r)),
                None => return rd.step(Err(SdkError::Argument)),
            }
        }
        let admins = ch
            .admins
            .iter()
            .map(|a| h32(a))
            .collect::<Result<Vec<_>, _>>()?;
        let cold = prepared.parent_epoch() == 0;
        let tree0 = prepared.tree().clone();
        let mut key_of = |x: u32| -> scaas_ua::wallet::Result<TargetKey> {
            if cold {
                let l = tree0.leaf(x / 2).ok_or(scaas_ua::wallet::Error::Argument)?;
                let (ua, k) = (l.ua, l.key_id);
                return kem_record(&mut rd, &ua, k)
                    .map(|r| TargetKey::Record(Box::new(r)))
                    .ok_or(scaas_ua::wallet::Error::Argument);
            }
            tree::key_of(&mut rd, &tree0, x).map(TargetKey::Key)
        };
        let built = self.scope(&seed)?.tree_prepare_commit(
            &PQCHAT_TREE,
            CommitInput {
                parent: &prepared,
                session_id,
                tree_id,
                author: me,
                leaf,
                key_id,
                kem: &kem,
                removes,
                adds,
                admins,
                info: ch.info.as_deref().map(str::as_bytes),
                key_of: &mut key_of,
            },
        );
        let p = match built {
            Ok(p) => p,
            Err(e) => return rd.step(Err(e.into())),
        };
        let out = PqTreeCommit {
            review: p.review().to_vec(),
            digest: hex(&p.digest()?),
            epoch_id: hex(&p.built().epoch_id),
            record: p.built().record.clone(),
            core: self.clone(),
            account,
            seed,
            p: Mutex::new(Some(p)),
        };
        rd.step(Ok(out))
    }

    /// A path-less Add (the path-less delta §6.5) by `account`'s leaf `leaf` (its KEM key `key_id`) of `adds` on the head the
    /// forward walk reaches over `reads` from `pin`, on the head's handle `from` holds (its own replay of that head: refused
    /// `TreeHandle` for another), its nonce at `try_` (C47): built inside `scaas-ua` with the head's admins, reviewed ("adds
    /// without refreshing the group's keys; n of N since the last refresh"), then signed. `info`: the info to seal. Its Adds
    /// are planned and split as any commit's ([`plan_commit`], [`split_adds`]).
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_tree_prepare_pathless(
        self: &Arc<Self>,
        account: KeyRef,
        key_id: u64,
        leaf: u32,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        from: &PqTreeReplay,
        adds: &[Value],
        info: Option<String>,
        try_: u32,
    ) -> Result<PqTreeStep<PqTreeCommit>, SdkError> {
        self.label(PQCHAT_TREE.prefix.as_bytes())?;
        let (seed, me, kem) = self.device_kem(&account, key_id)?;
        let pin = pin.map(tree::Pin::from_json).transpose()?;
        let mut rd = Snap::new(reads);
        let prepared = match tree::tree_prepare(&PQCHAT_TREE, &mut rd, pin.as_ref()) {
            Ok(p) => p,
            Err(e) => return rd.step(Err(e.into())),
        };
        let (Ok(session), Some(Ok(tree_id))) = (
            rd.read(View::SessionOf),
            rd.read(View::TreeOf)
                .ok()
                .and_then(|v| v.get("treeId").and_then(Value::as_str).map(h32)),
        ) else {
            return rd.step(Err(SdkError::Argument));
        };
        let creator = session
            .pointer("/record/creator")
            .and_then(Value::as_str)
            .map(h32)
            .transpose()?
            .ok_or(SdkError::Argument)?;
        let nonce = session
            .pointer("/record/nonce")
            .and_then(Value::as_u64)
            .ok_or(SdkError::Argument)?;
        let mut with = Vec::new();
        for a in adds {
            let x = Add::from_json(a)?;
            match kem_record(&mut rd, &x.ua, x.key_id) {
                Some(r) => with.push((x, r)),
                None => return rd.step(Err(SdkError::Argument)),
            }
        }
        let g = from.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(head) = g.head.as_ref() else {
            return rd.step(Err(SdkError::from(scaas_ua::wallet::Error::Tree(
                scaas_ua::wallet::tree_public::TreeError::Handle,
            ))));
        };
        let built = self.scope(&seed)?.tree_prepare_pathless(
            &PQCHAT_TREE,
            PathlessInput {
                parent: &prepared,
                session_id: PQCHAT_TREE.session_id(&creator, nonce),
                tree_id,
                author: me,
                leaf,
                key_id,
                kem: &kem,
                adds: with,
                info: info.as_deref().map(str::as_bytes),
            },
            head,
            try_,
        );
        drop(g);
        let p = match built {
            Ok(p) => p,
            Err(e) => return rd.step(Err(e.into())),
        };
        let out = PqTreeCommit {
            review: p.review().to_vec(),
            digest: hex(&p.digest()?),
            epoch_id: hex(&p.built().epoch_id),
            record: p.built().record.clone(),
            core: self.clone(),
            account,
            seed,
            p: Mutex::new(Some(p)),
        };
        rd.step(Ok(out))
    }

    /// `treeLeave`'s record prepared for `account`'s signature (C30; its review says the UA cannot come back, R14).
    pub fn prepare_pqchat_tree_leave(
        self: &Arc<Self>,
        account: KeyRef,
        l: PqTreeLeave,
    ) -> Result<PqTreeExit, SdkError> {
        let member = self.account_ua(&account)?;
        let p = tree::tree_prepare_leave(
            &PQCHAT_TREE,
            &tree::TreeLeave {
                session_id: h32(&l.session_id)?,
                tree_id: h32(&l.tree_id)?,
                epoch_id: h32(&l.epoch_id)?,
                member,
                nonce: l.nonce,
            },
        )?;
        self.exit(account, p)
    }

    /// `treeRemove`'s record prepared for `account`'s (an admin's) signature (C30; the removed UAs cannot come back, R14).
    pub fn prepare_pqchat_tree_remove(
        self: &Arc<Self>,
        account: KeyRef,
        r: PqTreeRemove,
    ) -> Result<PqTreeExit, SdkError> {
        let admin = self.account_ua(&account)?;
        let p = tree::tree_prepare_remove(
            &PQCHAT_TREE,
            &tree::TreeRemove {
                session_id: h32(&r.session_id)?,
                tree_id: h32(&r.tree_id)?,
                epoch_id: h32(&r.epoch_id)?,
                next_epoch: r.next_epoch,
                members: r.members.iter().map(|m| h32(m)).collect::<Result<_, _>>()?,
                admin,
                nonce: r.nonce,
            },
        )?;
        self.exit(account, p)
    }

    fn exit(self: &Arc<Self>, account: KeyRef, p: TreePrepared) -> Result<PqTreeExit, SdkError> {
        Ok(PqTreeExit {
            review: p.review().to_vec(),
            digest: hex(&p.digest()?),
            record: p.record(),
            core: self.clone(),
            account,
            p: Mutex::new(Some(p)),
        })
    }

    /// The replay of `account`'s key `key_id` over `reads` (spec §10): the forward walk from the cold tree, the checkpoint
    /// `pin` compared, every piece of the secret range read before anything opens; `K` handles from epoch `keys_from` on.
    /// `Done(None)`: the key is in no period of this session.
    pub fn pqchat_tree_replay(
        &self,
        account: KeyRef,
        key_id: u64,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        self.replay(account, key_id, reads, pin, None, keys_from)
    }

    /// [`AppCore::pqchat_tree_replay`] resumed from `from` (spec §10 step 3): only the epochs after its pin. `from` is left
    /// whole (a refusal, a missing read, a replay the caller drops); its node keys move into the new replay by
    /// [`PqTreeReplay::adopt`] once the caller keeps it. A consumed `from`: `TreePeriod`; a `from` whose pin is below the
    /// store's checkpoint `pin`: `TreeCheckpoint` (R2-C-2 of the T4-T9 re-check).
    pub fn pqchat_tree_resume(
        &self,
        account: KeyRef,
        key_id: u64,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        from: &PqTreeReplay,
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        self.replay(account, key_id, reads, pin, Some(from), keys_from)
    }

    fn replay(
        &self,
        account: KeyRef,
        key_id: u64,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        from: Option<&PqTreeReplay>,
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        self.label(PQCHAT_TREE.prefix.as_bytes())?;
        let (seed, ua, kem) = self.device_kem(&account, key_id)?;
        self.replay_with(&seed, ua, key_id, &kem, reads, pin, from, keys_from)
    }

    /// Test-only (feature `vectors`, never in a release build): [`AppCore::pqchat_tree_replay`] (resumed from `from` when
    /// given, [`AppCore::pqchat_tree_resume`]) by a vector device's KEM key (`kemSeed`, 96 B, as `tree-secrets.json` lays it
    /// out) instead of a wallet key; `K` handles in `seed`'s arena.
    #[cfg(feature = "vectors")]
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_tree_vectors_replay(
        &self,
        seed: &str,
        kem_seed: &[u8],
        ua: &str,
        key_id: u64,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        from: Option<&PqTreeReplay>,
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        self.label(PQCHAT_TREE.prefix.as_bytes())?;
        let b: &[u8; 96] = kem_seed.try_into().map_err(|_| SdkError::Argument)?;
        let kem = scaas_ua::wallet::KemKeyPair::vectors_ephemeral(b)?;
        self.replay_with(seed, h32(ua)?, key_id, &kem, reads, pin, from, keys_from)
    }

    #[allow(clippy::too_many_arguments)]
    fn replay_with(
        &self,
        seed: &str,
        ua: [u8; 32],
        key_id: u64,
        kem: &scaas_ua::wallet::KemKeyPair,
        reads: &PqTreeReads,
        pin: Option<&Value>,
        from: Option<&PqTreeReplay>,
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        let seed = seed.to_string();
        let dev = TreeDevice { ua, key_id, kem };
        let pin = pin.map(tree::Pin::from_json).transpose()?;
        let mut rd = Snap::new(reads);
        let sc = self.scope(&seed)?;
        let r = match from {
            Some(f) => {
                let g = f.inner.lock().unwrap_or_else(PoisonError::into_inner);
                sc.tree_resume_kept(&PQCHAT_TREE, &mut rd, &dev, &g, pin.as_ref(), keys_from)
            }
            None => sc.tree_replay(&PQCHAT_TREE, &mut rd, &dev, pin.as_ref(), keys_from),
        };
        let r = match r {
            Ok(r) => r,
            Err(e) => return rd.step(Err(e.into())),
        };
        let out = r.map(|mut r| {
            let epochs = r
                .epochs
                .iter_mut()
                .map(|e| PqTreeEpoch {
                    epoch: e.epoch,
                    epoch_id: hex(&e.epoch_id),
                    author: hex(&e.author),
                    admins: e.admins.iter().map(|a| hex(a)).collect(),
                    state: match e.state {
                        tree::State::Followed => "followed".into(),
                        tree::State::NotFollowed(why) => format!("not followed: {why}"),
                        tree::State::Compromise => "compromise".into(),
                        tree::State::AuthorDidNotHold => "author did not hold".into(),
                    },
                    k: e.k.take().map(|h| self.wrap(&seed, h)),
                    info: e.info.map(|i| match i {
                        tree::InfoTook::NotTaken => "not taken".into(),
                        i => format!("{i:?}").to_lowercase(),
                    }),
                    in_force: e.in_force.clone(),
                    flagged: e.flagged,
                })
                .collect();
            let warnings = r
                .warnings
                .iter()
                .map(|w| PqTreeWarning {
                    epoch: w.epoch,
                    adds: w.adds.iter().map(|(l, u, k)| (*l, hex(u), *k)).collect(),
                    removes: w.removes.iter().map(Remove::to_json).collect(),
                    admins_changed: w.admins_changed,
                    leaves_left: w.leaves_left.clone(),
                })
                .collect();
            let suspects = r
                .suspects
                .iter()
                .map(|w| PqTreeWarning {
                    epoch: w.epoch,
                    adds: w.adds.iter().map(|(l, u, k)| (*l, hex(u), *k)).collect(),
                    removes: Vec::new(),
                    admins_changed: false,
                    leaves_left: w.leaves_left.clone(),
                })
                .collect();
            Arc::new(PqTreeReplay {
                suspects,
                review: r.review.clone(),
                since_path: r.since_path,
                path_bound: r.pin.tree.path_bound,
                path_warning: r.path_warning,
                holds_head: r.head.is_some(),
                leaf: r.leaf,
                join_epoch: r.join_epoch,
                end_epoch: r.end_epoch,
                epochs,
                warnings,
                pin: r.pin.to_json(),
                info_to_seal: r.info_to_seal().map(str::to_string),
                rosters: r
                    .rosters
                    .iter()
                    .map(|(n, v)| (*n, v.iter().map(|x| x.map(|(u, k)| (hex(&u), k))).collect()))
                    .collect(),
                inner: Mutex::new(r),
            })
        });
        rd.step(Ok(out))
    }
}

// ------------------------------------------------------------------ the plan (spec §13, C37; codex-r2-9, codex-r3-12)

impl AppCore {
    /// How many of `chain`'s endpoints are named (R13: a changed tree info needs a strict majority of at least 3; CLI-RPC-06).
    pub fn named_endpoints(&self, chain: &str) -> Result<usize, SdkError> {
        let (profile, _, _) = crate::op::evm(&self.sdk, chain)?;
        Ok(profile
            .rpc
            .iter()
            .filter(|e| e.class == scaas_rpc::Class::Named)
            .count())
    }

    /// `chain`'s limits for a tree plan: the latest block's gas limit (read by RPC, failed over) and the profile's regular
    /// gas cap of a transaction (EIP-7825; none assumed when the profile names none, as the SDK's quote).
    pub async fn pqchat_tree_limits(&self, chain: &str) -> Result<PqLimits, SdkError> {
        let (profile, _, pool) = crate::op::evm(&self.sdk, chain)?;
        let block = pool.block_gas().await.map_err(crate::op::sim)?;
        Ok(PqLimits {
            block: block.limit,
            tx_regular: profile.tx_gas_cap,
        })
    }
}

/// One part's gas: regular and state (EIP-8037).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PqGas {
    pub regular: u64,
    pub state: u64,
}

impl PqGas {
    fn add(self, o: PqGas) -> PqGas {
        PqGas {
            regular: self.regular.saturating_add(o.regular),
            state: self.state.saturating_add(o.state),
        }
    }
    fn times(self, n: u64) -> PqGas {
        PqGas {
            regular: self.regular.saturating_mul(n),
            state: self.state.saturating_mul(n),
        }
    }
    /// What a transaction asks: (regular + state) × 1.05.
    pub fn asked(self) -> u64 {
        let t = self.regular.saturating_add(self.state);
        t.saturating_add(t.div_ceil(20))
    }
}

/// A linear row: `base + per × n`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PqRow {
    pub base: PqGas,
    pub per: PqGas,
}

impl PqRow {
    fn at(&self, n: u64) -> PqGas {
        self.base.add(self.per.times(n))
    }
}

/// A signer kind's row: its verify (regular gas) and its signature's bytes (`UASig` key data and signature).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PqKindRow {
    pub verify: u64,
    pub sig_bytes: u64,
}

/// A chain's tree gas rows (release data; `gas/pqchat-tree.json` is the forge reference): never a figure in code (the
/// SDK's gas-table rule). Each transaction's limit is still its estimate at send time; these rows plan and quote. The
/// record and the completion are sized by what they do: a tree term per path target, per Add, per Remove, per admin and per
/// KiB of `sealedInfo` above the reference's one each (B-1, B-2, B-3 of the T4-T9 review).
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PqTreeGas {
    /// by signer kind name (`scaas-ua`'s, [`signer_name`]): the verify and the signature's bytes
    pub kinds: BTreeMap<String, PqKindRow>,
    /// the rows were measured with a signature of this many bytes; each byte more costs `per_sig_byte`
    pub sig_ref: u64,
    pub per_sig_byte: PqGas,
    /// the creation in one transaction (the session record with every wrap) per member key, and per admin above one
    pub creation: PqRow,
    pub creation_per_admin: PqGas,
    /// a Welcome wrap in `addWraps`
    pub wrap: PqGas,
    /// the commit record: base + per path target (the tree check), then per Add, per Remove, per admin above one, per
    /// KiB of `sealedInfo` above one
    pub record: PqRow,
    pub record_per_add: PqGas,
    /// an Add on a large tree costs less (the tree term reads its paths already): `record_per_add` less this per target
    pub record_per_add_drop: PqGas,
    pub record_per_remove: PqGas,
    pub record_per_admin: PqGas,
    pub record_per_kib_info: PqGas,
    /// the list per entry, the node keys per key, the path ciphertexts per ciphertext
    pub list: PqRow,
    pub keys: PqRow,
    pub cts: PqRow,
    /// the completion: base + per path target, then per Add and per Remove
    pub completion: PqRow,
    pub completion_per_add: PqGas,
    pub completion_per_remove: PqGas,
    /// a commit with no piece (the last live leaf's Removes): its one transaction with the completion, base + per Remove
    pub no_piece: PqRow,
}

/// `scaas-ua`'s name of a signer kind (`mldsa65` for 0x0131, `mldsa87` for 0x0134, …), the key of [`PqTreeGas::kinds`].
pub fn signer_name(kind: u16) -> Option<&'static str> {
    scaas_ua::KINDS
        .iter()
        .find(|k| k.kind == kind)
        .map(|k| k.name)
}

/// The chain's limits: the block gas limit (read by RPC) and the profile's regular gas cap of a transaction (EIP-7825;
/// `None` when the profile names none: no cap assumed, as the SDK's quote).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqLimits {
    pub block: u64,
    pub tx_regular: Option<u64>,
}

impl PqLimits {
    /// Whether one transaction of `g` fits: its regular gas at most the cap (the quote's own comparison) and what it asks
    /// within the block (EIP-8037: regular + state).
    pub fn fits(&self, g: PqGas) -> bool {
        self.tx_regular.is_none_or(|c| g.regular <= c) && g.asked() <= self.block
    }
}

/// A commit's shape: what the planner sizes (the record's changes, Adds among them, admins and info; the pieces).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PqCommitShape {
    /// Adds plus Removes
    pub changes: u64,
    pub admins: u64,
    pub info: u64,
    /// the path targets (`ctCount`)
    pub cts: u64,
    pub keys: u64,
    pub adds: u64,
}

impl PqCommitShape {
    fn removes(&self) -> u64 {
        self.changes.saturating_sub(self.adds)
    }
}

/// One planned transaction: the entry, its first index and count (ciphertexts, wraps), and its gas.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreeTx {
    pub entry: &'static str,
    pub first: u64,
    pub count: u64,
    pub gas: PqGas,
}

/// A commit's plan (C37): its transactions in order, the last one the held piece with the completion; the quote names both
/// figures, the completion as planned and the dearest piece if it were last (the order broken).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreePlan {
    pub txs: Vec<PqTreeTx>,
    pub completion: PqGas,
    pub dearest_last: PqGas,
}

/// Whether a home view's read error says the record is not stored: the first endpoint's revert (a view that refuses), or
/// a failover over endpoints that all failed whose kept revert is the contract's `PqChatUnknown()` (R2-C-4 of the T4-T9
/// re-check: a failover endpoint's revert is no verdict alone, CLI-RPC-04, but the record unknown to every endpoint that
/// answered is the contract's answer); never a transport failure.
pub fn record_unknown(e: &SdkError) -> bool {
    match e {
        SdkError::Rpc(scaas_rpc::RpcError::Revert { .. }) => true,
        SdkError::Rpc(scaas_rpc::RpcError::EndpointAllFailed {
            failover_revert: Some(d),
            ..
        }) => d.starts_with(&scaas_ua::keccak256(b"PqChatUnknown()")[..4]),
        _ => false,
    }
}

/// A plan refused by name (only the operation whose required piece does not fit), with its figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreeRefused {
    pub what: &'static str,
    pub asked: u64,
    pub regular: u64,
    pub limits: (u64, Option<u64>),
}

fn refused(what: &'static str, g: PqGas, l: PqLimits) -> PqTreeRefused {
    PqTreeRefused {
        what,
        asked: g.asked(),
        regular: g.regular,
        limits: (l.block, l.tx_regular),
    }
}

/// A refusal by the rows' own gap: `signer` has no row.
pub const NO_KIND_ROW: &str = "no verify row for the signer's kind";

/// The signer's own part of a transaction it signs: its verify and its signature's bytes above the rows' reference.
fn kind_gas(g: &PqTreeGas, signer: &str) -> Result<PqGas, PqTreeRefused> {
    let k = g.kinds.get(signer).ok_or(PqTreeRefused {
        what: NO_KIND_ROW,
        asked: 0,
        regular: 0,
        limits: (0, None),
    })?;
    Ok(PqGas {
        regular: k.verify,
        state: 0,
    }
    .add(g.per_sig_byte.times(k.sig_bytes.saturating_sub(g.sig_ref))))
}

/// The record alone: base + targets, Adds, Removes, admins and info, with the signer's verify and signature.
fn record_gas(g: &PqTreeGas, signer: &str, s: &PqCommitShape) -> Result<PqGas, PqTreeRefused> {
    let drop = g.record_per_add_drop.times(s.cts);
    let per_add = PqGas {
        regular: g.record_per_add.regular.saturating_sub(drop.regular),
        state: g.record_per_add.state.saturating_sub(drop.state),
    };
    Ok(g.record
        .at(s.cts)
        .add(per_add.times(s.adds))
        .add(g.record_per_remove.times(s.removes()))
        .add(g.record_per_admin.times(s.admins.saturating_sub(1)))
        .add(
            g.record_per_kib_info
                .times(s.info.div_ceil(1024).saturating_sub(1)),
        )
        .add(kind_gas(g, signer)?))
}

/// The completion: base + targets, Adds and Removes.
fn completion_gas(g: &PqTreeGas, s: &PqCommitShape) -> PqGas {
    g.completion
        .at(s.cts)
        .add(g.completion_per_add.times(s.adds))
        .add(g.completion_per_remove.times(s.removes()))
}

/// The plan of a commit (spec §13, C37): the whole commit in one transaction when it fits; else the record alone, the list,
/// the node keys, the ciphertexts but one and the wraps (in chunks that fit), and the held ciphertext (else the last wrap)
/// alone with the completion. A commit with no piece is one transaction by its own row. A required piece that does not fit
/// refuses the operation by name with its figures.
pub fn plan_commit(
    g: &PqTreeGas,
    l: PqLimits,
    signer: &str,
    s: &PqCommitShape,
) -> Result<PqTreePlan, PqTreeRefused> {
    let one = |gas: PqGas| PqTreePlan {
        txs: vec![PqTreeTx {
            entry: "commit",
            first: 0,
            count: 0,
            gas,
        }],
        completion: gas,
        dearest_last: gas,
    };
    if s.cts == 0 && s.adds == 0 {
        // B-1: the last live leaf's commit, Removes only, measured as its own row
        let whole = g.no_piece.at(s.removes()).add(kind_gas(g, signer)?);
        if !l.fits(whole) {
            return Err(refused("the commit (no piece: one transaction)", whole, l));
        }
        return Ok(one(whole));
    }
    let record = record_gas(g, signer, s)?;
    let at = |r: &PqRow, n: u64| if n > 0 { r.at(n) } else { PqGas::default() };
    let completion = completion_gas(g, s);
    let whole = record
        .add(at(&g.list, s.cts))
        .add(at(&g.keys, s.keys))
        .add(at(&g.cts, s.cts))
        .add(g.wrap.times(s.adds))
        .add(completion);
    if l.fits(whole) {
        let mut p = one(whole);
        p.completion = completion;
        p.dearest_last = pieces(g, l, s, record).map_or(whole, |x| x.dearest_last);
        return Ok(p);
    }
    pieces(g, l, s, record)
}

/// The safety margin of a batch of Adds split into several commits (owner 2026-11-27, CTR-CHAT-27): each commit is planned
/// within each limit less `limit / SPLIT_MARGIN_DIV` (2.5 %: 419,430 gas at a 2^24 cap), so the documented worst case (a cold
/// tree of 511 targets, 32 admins, 4,124 B of info, ML-DSA-87) takes at most 16 Adds per commit (16,310,179 regular gas by
/// the rows, 17 ask 16,464,358 against 16,357,786).
pub const SPLIT_MARGIN_DIV: u64 = 40;

/// `l` less the split's safety margin on each limit.
pub fn margined(l: PqLimits) -> PqLimits {
    PqLimits {
        block: l.block - l.block / SPLIT_MARGIN_DIV,
        tx_regular: l.tx_regular.map(|c| c - c / SPLIT_MARGIN_DIV),
    }
}

/// The most Adds of `s` one commit takes within the margined limits (`s` with that many Adds, its Removes, admins, info and
/// pieces as they are): what an app suggests ("at most N Adds per transaction"). A shape with no Add: 0. Not even one Add:
/// the refusal by name of the one-Add commit.
pub fn adds_per_commit(
    g: &PqTreeGas,
    l: PqLimits,
    signer: &str,
    s: &PqCommitShape,
) -> Result<u64, PqTreeRefused> {
    let m = margined(l);
    let with = |n: u64| PqCommitShape {
        adds: n,
        changes: s.removes() + n,
        ..*s
    };
    let mut best = 0;
    for n in 1..=s.adds {
        match plan_commit(g, m, signer, &with(n)) {
            Ok(_) => best = n,
            Err(e) if n == 1 => return Err(e),
            Err(_) => break,
        }
    }
    Ok(best)
}

/// A batch of Adds whose commit does not fit split into several ordinary commits (owner 2026-11-27): the Adds in their
/// order, [`adds_per_commit`] in each, the last the rest; one commit when they all fit. Each commit is built on its own head
/// and planned in C37's order; not even one Add fits: refused by name.
pub fn split_adds(
    g: &PqTreeGas,
    l: PqLimits,
    signer: &str,
    s: &PqCommitShape,
) -> Result<Vec<u64>, PqTreeRefused> {
    let per = adds_per_commit(g, l, signer, s)?;
    if per == 0 {
        return Ok(vec![s.adds].into_iter().filter(|n| *n > 0).collect());
    }
    let mut out = vec![per; (s.adds / per) as usize];
    if !s.adds.is_multiple_of(per) {
        out.push(s.adds % per);
    }
    Ok(out)
}

/// The split plan of `s` with the record's gas `record` (C37): the record, the list, the node keys, the ciphertexts but one
/// and the wraps in chunks that fit, the held piece with the completion. Also the fallback of a one-transaction plan whose
/// record another sender stored (fable-r2-9), with `record` zero.
fn pieces(
    g: &PqTreeGas,
    l: PqLimits,
    s: &PqCommitShape,
    record: PqGas,
) -> Result<PqTreePlan, PqTreeRefused> {
    let list = if s.cts > 0 {
        g.list.at(s.cts)
    } else {
        PqGas::default()
    };
    let keys = if s.keys > 0 {
        g.keys.at(s.keys)
    } else {
        PqGas::default()
    };
    let completion = completion_gas(g, s);
    // the dearest piece if it were last: the node keys (or the list) with the completion
    let dearest_last = if keys.asked() >= list.asked() {
        keys
    } else {
        list
    }
    .add(completion);
    if s.cts == 0 && s.adds == 0 {
        return Err(refused("the commit (no piece: one transaction)", record, l));
    }
    let mut txs = Vec::new();
    for (entry, gas, n) in [
        ("commit", record, 1),
        ("addPathList", list, s.cts),
        ("addPathKeys", keys, s.keys),
    ] {
        if n == 0 {
            continue;
        }
        if !l.fits(gas) {
            return Err(refused(entry, gas, l));
        }
        txs.push(PqTreeTx {
            entry,
            first: 0,
            count: 0,
            gas,
        });
    }
    let held_wrap = s.cts == 0;
    chunk(
        &mut txs,
        "addPath",
        s.cts.saturating_sub(1),
        |n| g.cts.at(n),
        l,
    )?;
    let rest_wraps = if held_wrap { s.adds - 1 } else { s.adds };
    chunk(&mut txs, "addWraps", rest_wraps, |n| g.wrap.times(n), l)?;
    let last = if held_wrap {
        ("addWraps", s.adds - 1, g.wrap.add(completion))
    } else {
        ("addPath", s.cts - 1, g.cts.at(1).add(completion))
    };
    if !l.fits(last.2) {
        return Err(refused("the held piece with the completion", last.2, l));
    }
    txs.push(PqTreeTx {
        entry: last.0,
        first: last.1,
        count: 1,
        gas: last.2,
    });
    Ok(PqTreePlan {
        txs,
        completion: last.2,
        dearest_last,
    })
}

/// The deferred cost of a run (the path-less delta §6.4, D-10): the next path commit carries about one ciphertext per leaf
/// owed one (`sincePath` plus the warm nodes the Adds blanked); what those ciphertexts ask, from the chain's rows.
pub fn deferred_cost(g: &PqTreeGas, owed_ciphertexts: u64) -> PqGas {
    g.cts.per.times(owed_ciphertexts)
}

/// The planner's choice for an Adds-only change (the path-less delta §6.5, C46; F-5 by the owner's ruling of 2026-11-27):
/// the path-less form only when the device holds the head's epoch, nothing is owed, no head admin is gone, the admin list and
/// Removes do not change, the bound leaves room, no path commit of the device's own is staged on the head (another author's
/// is not visible: the contract's order decides) and a `try` is left; otherwise a path commit with the Adds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PqPathlessCheck {
    pub holds_head: bool,
    pub owed: u32,
    pub gone_admin: bool,
    pub admins_changed: bool,
    pub removes: bool,
    pub since_path: u32,
    pub bound: u32,
    pub adds: u32,
    pub own_path_commit_staged: bool,
    pub tries_left: bool,
}

impl PqPathlessCheck {
    /// The path-less form is offered (`Ok`); else the reason the path form is built.
    pub fn form(&self) -> Result<(), &'static str> {
        if !self.holds_head {
            return Err("the device does not hold the head's epoch");
        }
        if self.owed > 0 {
            return Err("an exit is owed: the next commit honours it with a path");
        }
        if self.gone_admin {
            return Err("a head admin is gone: dropping it keeps a path");
        }
        if self.admins_changed || self.removes {
            return Err("an admin change or a Remove keeps a path");
        }
        if self.adds == 0 {
            return Err("no Add");
        }
        if self.bound > 0 && self.since_path.saturating_add(self.adds) > self.bound {
            return Err("the bound: the next Add carries a key refresh");
        }
        if self.own_path_commit_staged {
            return Err("a key refresh is in progress");
        }
        if !self.tries_left {
            return Err("no try is left");
        }
        Ok(())
    }
}

/// `n` items in chunks of the most that fit one transaction each (B-9: the largest by a search on the monotone `gas`).
fn chunk(
    txs: &mut Vec<PqTreeTx>,
    entry: &'static str,
    n: u64,
    gas: impl Fn(u64) -> PqGas,
    l: PqLimits,
) -> Result<(), PqTreeRefused> {
    let mut first = 0;
    while first < n {
        let (mut lo, mut hi) = (0, n - first);
        while lo < hi {
            let mid = lo + (hi - lo).div_ceil(2);
            if l.fits(gas(mid)) {
                lo = mid;
            } else {
                hi = mid - 1;
            }
        }
        if lo == 0 {
            return Err(refused(entry, gas(1), l));
        }
        txs.push(PqTreeTx {
            entry,
            first,
            count: lo,
            gas: gas(lo),
        });
        first += lo;
    }
    Ok(())
}

/// What is in state of a staged commit (the piece views at the home: `pathListOf`, `pathKeys`, `pathCtAt`, `wrapAt`) and
/// whether the epoch is complete (`epochComplete`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PqTreeLanded {
    pub record: bool,
    pub list: bool,
    pub keys: bool,
    pub cts: Vec<bool>,
    pub wraps: Vec<bool>,
    pub complete: bool,
}

/// The next send of a commit on the state now (C37, codex-r3-12; the fallback to the piece entries once the record is
/// stored, fable-r2-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqTreeNext {
    /// send this (the planned transaction's entry and range)
    Send(PqTreeTx),
    /// wait: the one before is not final (the list and the node keys go one by one), or the last piece is not final yet
    Wait,
    /// complete at the final block
    Done,
    /// the order was broken (another sender landed the held piece first): the piece left would pay the completion and does
    /// not fit; nothing more is sent, the commit is rebuilt with a new nonce
    Void(PqTreeRefused),
}

/// The next send of `plan` on `landed` (at the latest block) with `fin` (at the final block). Done only when the epoch is
/// complete at the final block (C-1 of the T4-T9 review): a one-transaction plan whose record another sender stored goes on
/// through the piece entries (fable-r2-9). Otherwise the first transaction not landed: the record, the list and the node
/// keys each once the one before is final, the held piece once every other is final. When the held piece was landed by
/// another sender first, the piece left last pays the completion: a chunk sends all but one item first and the last one
/// alone; an indivisible piece (the list, the node keys) or one item that cannot pay it makes the commit void, decided on
/// the final state.
pub fn next_send(
    g: &PqTreeGas,
    l: PqLimits,
    plan: &PqTreePlan,
    s: &PqCommitShape,
    landed: &PqTreeLanded,
    fin: &PqTreeLanded,
) -> PqTreeNext {
    if fin.complete {
        return PqTreeNext::Done;
    }
    if plan.txs.len() == 1 && landed.record {
        if s.cts == 0 && s.adds == 0 {
            // no piece: the record's own transaction completes it
            return PqTreeNext::Wait;
        }
        return match pieces(g, l, s, PqGas::default()) {
            Ok(p) => next_send(g, l, &p, s, landed, fin),
            Err(r) => PqTreeNext::Void(r),
        };
    }
    let at = |v: &[bool], i: u64| v.get(i as usize).copied().unwrap_or(false);
    let is_in = |st: &PqTreeLanded, t: &PqTreeTx| match t.entry {
        "commit" => st.record,
        "addPathList" => st.list,
        "addPathKeys" => st.keys,
        "addPath" => (t.first..t.first + t.count.max(1)).all(|i| at(&st.cts, i)),
        _ => (t.first..t.first + t.count.max(1)).all(|i| at(&st.wraps, i)),
    };
    let left_of = |st: &PqTreeLanded| -> Vec<usize> {
        (0..plan.txs.len())
            .filter(|i| plan.txs.get(*i).is_some_and(|t| !is_in(st, t)))
            .collect()
    };
    let left = left_of(landed);
    let Some(&first) = left.first() else {
        // every piece landed, the completion not final yet
        return PqTreeNext::Wait;
    };
    let held = plan.txs.len() - 1;
    let serial = |t: &PqTreeTx| matches!(t.entry, "commit" | "addPathList" | "addPathKeys");
    let fin_left = left_of(fin);
    let broken = plan.txs.len() > 1 && !fin_left.contains(&held) && !fin_left.is_empty();
    if broken {
        let completion = completion_gas(g, s);
        let last = fin_left.last().and_then(|i| plan.txs.get(*i));
        let one = last.map_or(PqGas::default(), |t| match t.entry {
            _ if serial(t) || t.count <= 1 => t.gas,
            "addPath" => g.cts.at(1),
            _ => g.wrap,
        });
        if !l.fits(one.add(completion)) {
            return PqTreeNext::Void(refused(
                "the piece left with the completion (the order broken)",
                one.add(completion),
                l,
            ));
        }
    }
    let Some(t) = plan.txs.get(first) else {
        return PqTreeNext::Done;
    };
    let all_final = |upto: usize| plan.txs.iter().take(upto).all(|x| is_in(fin, x));
    let last_left = left.len() == 1;
    // the record, the list and the node keys, and the last piece left (the held one), each once every one before is final
    if (serial(t) || last_left) && !all_final(first) {
        return PqTreeNext::Wait;
    }
    if !serial(t) && !last_left && first != held {
        // a ciphertext or wrap chunk goes once the record, the list and the node keys are final
        if !plan.txs.iter().filter(|x| serial(x)).all(|x| is_in(fin, x)) {
            return PqTreeNext::Wait;
        }
    }
    if first == held && left.len() > 1 {
        return PqTreeNext::Wait;
    }
    if serial(t) || t.count <= 1 {
        return PqTreeNext::Send(t.clone());
    }
    // a chunk: the first run of its items not in state (another sender may have landed some; a piece landed twice is
    // refused); B-8: a chunk left last after the held piece landed keeps its last item for the completion
    let have = if t.entry == "addPath" {
        &landed.cts
    } else {
        &landed.wraps
    };
    let missing: Vec<u64> = (t.first..t.first + t.count)
        .filter(|i| !at(have, *i))
        .collect();
    let (Some(&a), Some(&z)) = (missing.first(), missing.last()) else {
        return PqTreeNext::Wait;
    };
    let end = if broken && last_left && a < z {
        z
    } else {
        z + 1
    };
    let run = (a..end).take_while(|i| missing.contains(i)).count() as u64;
    let run = run.max(1);
    PqTreeNext::Send(PqTreeTx {
        first: a,
        count: run,
        gas: match t.entry {
            "addPath" => g.cts.at(run),
            _ => g.wrap.times(run),
        },
        ..t.clone()
    })
}

/// The largest creation that fits one transaction (owner 2026-11-25): the session record of `k` member keys with its `k`
/// wraps and `admins` admins, measured as one transaction (B-13), within the chain's limits; 0 when not even one fits.
pub fn create_cap(g: &PqTreeGas, l: PqLimits, signer: &str, admins: u64) -> u64 {
    let Ok(k) = kind_gas(g, signer) else {
        return 0;
    };
    let mut best = 0;
    for n in 1..=512u64 {
        let gas = g
            .creation
            .at(n)
            .add(g.creation_per_admin.times(admins.saturating_sub(1)))
            .add(k);
        if !l.fits(gas) {
            break;
        }
        best = n;
    }
    best
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    /// The path-less delta §6.5 (C46; F-5 by the owner's ruling of 2026-11-27): the path-less form only when every condition
    /// holds, each condition alone falling back to the path form by its reason; the creation review's line of the bound;
    /// a path-less shape planned and split by the same rule as any commit (no list, no keys, the held piece a wrap).
    #[test]
    fn pathless_form_and_its_plan() {
        let ok = PqPathlessCheck {
            holds_head: true,
            owed: 0,
            gone_admin: false,
            admins_changed: false,
            removes: false,
            since_path: 22,
            bound: 24,
            adds: 2,
            own_path_commit_staged: false,
            tries_left: true,
        };
        assert_eq!(ok.form(), Ok(()));
        let no: [(PqPathlessCheck, &str); 9] = [
            (
                PqPathlessCheck {
                    holds_head: false,
                    ..ok
                },
                "the head's epoch",
            ),
            (PqPathlessCheck { owed: 1, ..ok }, "owed"),
            (
                PqPathlessCheck {
                    gone_admin: true,
                    ..ok
                },
                "gone",
            ),
            (
                PqPathlessCheck {
                    admins_changed: true,
                    ..ok
                },
                "admin change",
            ),
            (
                PqPathlessCheck {
                    removes: true,
                    ..ok
                },
                "Remove",
            ),
            (PqPathlessCheck { adds: 3, ..ok }, "the bound"),
            (PqPathlessCheck { adds: 0, ..ok }, "no Add"),
            (
                PqPathlessCheck {
                    own_path_commit_staged: true,
                    ..ok
                },
                "in progress",
            ),
            (
                PqPathlessCheck {
                    tries_left: false,
                    ..ok
                },
                "try",
            ),
        ];
        for (c, why) in no {
            assert!(c.form().is_err_and(|e| e.contains(why)), "{why}");
        }
        assert_eq!(
            PqPathlessCheck {
                bound: 0,
                adds: 30,
                ..ok
            }
            .form(),
            Ok(()),
            "bound 0 never forces"
        );
        assert_eq!(
            refresh_line(0),
            "key refresh never forced; the admins are warned after 20 added keys"
        );
        assert_eq!(
            refresh_line(24),
            "key refresh forced after 24 added keys; the admins are warned from 18"
        );
        assert_eq!(PATH_REFRESH_BOUND_DEFAULT, 20);
        let g = rows();
        let pathless = PqCommitShape {
            changes: 20,
            adds: 20,
            cts: 0,
            keys: 0,
            ..plain()
        };
        let p = plan_commit(&g, L60, "mldsa65", &pathless).unwrap();
        assert!(
            p.txs.iter().all(|t| !t.entry.starts_with("addPath")),
            "{p:?}"
        );
        assert!(
            split_adds(&g, L60, "mldsa65", &pathless)
                .unwrap()
                .iter()
                .sum::<u64>()
                == 20
        );
        assert_eq!(deferred_cost(&g, 3), g.cts.per.times(3));
    }

    fn rows() -> PqTreeGas {
        serde_json::from_str(include_str!("../gas/pqchat-tree.json")).unwrap()
    }
    const L60: PqLimits = PqLimits {
        block: 60_000_000,
        tx_regular: Some(1 << 24),
    };
    /// A small block: plan T5's 20 M (the record's tree term from the rows, B-2 of the T4-T9 review)
    const L20: PqLimits = PqLimits {
        block: 20_000_000,
        tx_regular: Some(1 << 24),
    };
    fn plain() -> PqCommitShape {
        PqCommitShape {
            changes: 1,
            admins: 1,
            info: 64,
            cts: 3,
            keys: 2,
            adds: 0,
        }
    }
    fn bounds() -> PqCommitShape {
        PqCommitShape {
            changes: 20,
            admins: 32,
            info: 4124,
            cts: 511,
            keys: 9,
            adds: 20,
        }
    }

    /// Owner 2026-11-27 (CTR-CHAT-27): the worst case's 20 Adds split into 16 + 4, each commit planned within the cap less
    /// the margin; 16 Adds one commit; a cap too small for one Add refuses it by name.
    #[test]
    fn a_batch_of_adds_over_the_cap_is_split() {
        let g = rows();
        assert_eq!(adds_per_commit(&g, L60, "mldsa87", &bounds()), Ok(16));
        assert_eq!(split_adds(&g, L60, "mldsa87", &bounds()), Ok(vec![16, 4]));
        let m = margined(L60);
        assert_eq!(m.tx_regular, Some((1 << 24) - 419_430));
        for n in [16, 4] {
            let s = PqCommitShape {
                adds: n,
                changes: n,
                ..bounds()
            };
            let p = plan_commit(&g, m, "mldsa87", &s).unwrap();
            assert!(p.txs.iter().all(|t| m.fits(t.gas)), "{n}: {p:?}");
        }
        assert_eq!(
            record_gas(
                &g,
                "mldsa87",
                &PqCommitShape {
                    adds: 16,
                    changes: 16,
                    ..bounds()
                }
            )
            .unwrap()
            .regular,
            // the path-less delta P4's rows (gas/pqchat-tree.json regenerated: the record's two fields): 16,310,179 ->
            // 16,314,102, under the margined cap 16,357,786
            16_314_102
        );
        let sixteen = PqCommitShape {
            adds: 16,
            changes: 16,
            ..bounds()
        };
        assert_eq!(split_adds(&g, L60, "mldsa87", &sixteen), Ok(vec![16]));
        let small = PqLimits {
            block: 60_000_000,
            tx_regular: Some(10_000_000),
        };
        let e = split_adds(&g, small, "mldsa87", &bounds()).unwrap_err();
        assert_eq!(e.what, "commit", "{e:?}");
    }

    /// Plan T5: a chain with a small block (20 M) takes a plain commit and refuses a record at its bounds by name, with
    /// figures.
    #[test]
    fn a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record() {
        let g = rows();
        let p = plan_commit(&g, L20, "mldsa65", &plain()).unwrap();
        assert!(p.txs.iter().all(|t| L20.fits(t.gas)), "{p:?}");
        // B-2: a plain commit's tree term is its own few targets', far below the cold tree of 512's (4.6 M regular)
        let verify = g.kinds["mldsa65"].verify;
        let r = record_gas(&g, "mldsa65", &plain()).unwrap();
        assert!(r.regular < verify + 1_000_000, "{r:?}");
        let e = plan_commit(&g, L20, "mldsa87", &bounds()).unwrap_err();
        assert_eq!(e.what, "commit", "the record alone, by name: {e:?}");
        assert!(
            e.asked > 20_000_000 && e.limits == (20_000_000, Some(1 << 24)),
            "{e:?}"
        );
        // at 60 M the bound commit plans with ML-DSA-65, in C37's order, the held ciphertext last and alone; with ML-DSA-87 its
        // record alone is over 2^24 by the rows (20 Adds on 511 targets measured at 16.58 M with the verify, 32 admins and
        // 4,124 B of info adding 0.34 M), refused by name
        let e = plan_commit(&g, L60, "mldsa87", &bounds()).unwrap_err();
        assert!(e.what == "commit" && e.regular > 1 << 24, "{e:?}");
        let p = plan_commit(&g, L60, "mldsa65", &bounds()).unwrap();
        let names: Vec<&str> = p.txs.iter().map(|t| t.entry).collect();
        assert_eq!(
            &names[..3],
            &["commit", "addPathList", "addPathKeys"],
            "{names:?}"
        );
        let last = p.txs.last().unwrap();
        assert_eq!((last.entry, last.first, last.count), ("addPath", 510, 1));
        assert!(p.txs.iter().all(|t| L60.fits(t.gas)));
        assert!(
            p.dearest_last.asked() > p.completion.asked(),
            "both figures quoted: {p:?}"
        );
    }

    /// Plan T5 (codex-r3-12): the order broken: another sender lands every ciphertext first (the held one too), so the node
    /// keys are left and would pay the completion: the named result with its figures and nothing more sent (rebuild with a
    /// new nonce). Beside it the record-already-stored fallback (the pieces after the record) and the control in which the
    /// held ciphertext is last and the commit completes.
    #[test]
    fn the_order_broken_and_its_controls() {
        let g = rows();
        let s = bounds();
        let p = plan_commit(&g, L60, "mldsa65", &s).unwrap();
        let mut landed = PqTreeLanded {
            record: true,
            list: true,
            keys: false,
            cts: vec![true; 511],
            wraps: vec![true; 20],
            complete: false,
        };
        let fin = landed.clone();
        match next_send(&g, L60, &p, &s, &landed, &fin) {
            PqTreeNext::Void(r) => assert!(
                r.asked > 60_000_000 && r.what.contains("order broken"),
                "{r:?}"
            ),
            x => panic!("{x:?}"),
        }
        // the record stored by an earlier send: the next is the list, then (once final) the node keys
        landed = PqTreeLanded {
            record: true,
            cts: vec![false; 511],
            wraps: vec![false; 20],
            ..Default::default()
        };
        let mut fin = landed.clone();
        assert!(
            matches!(next_send(&g, L60, &p, &s, &landed, &fin), PqTreeNext::Send(t) if t.entry == "addPathList")
        );
        landed.list = true;
        assert_eq!(
            next_send(&g, L60, &p, &s, &landed, &fin),
            PqTreeNext::Wait,
            "the list not final"
        );
        fin.list = true;
        assert!(
            matches!(next_send(&g, L60, &p, &s, &landed, &fin), PqTreeNext::Send(t) if t.entry == "addPathKeys")
        );
        // the node keys landed, not final: no ciphertext leaves yet
        landed.keys = true;
        assert_eq!(
            next_send(&g, L60, &p, &s, &landed, &fin),
            PqTreeNext::Wait,
            "the node keys not final"
        );
        fin.keys = true;
        assert!(
            matches!(next_send(&g, L60, &p, &s, &landed, &fin), PqTreeNext::Send(t) if t.entry == "addPath")
        );
        // the control: everything but the held ciphertext landed and final, then it goes, then done
        landed = PqTreeLanded {
            record: true,
            list: true,
            keys: true,
            cts: vec![true; 511],
            wraps: vec![true; 20],
            complete: false,
        };
        landed.cts[510] = false;
        let fin = landed.clone();
        match next_send(&g, L60, &p, &s, &landed, &fin) {
            PqTreeNext::Send(t) => assert_eq!((t.entry, t.first, t.count), ("addPath", 510, 1)),
            x => panic!("{x:?}"),
        }
        landed.cts[510] = true;
        assert_eq!(
            next_send(&g, L60, &p, &s, &landed, &landed.clone()),
            PqTreeNext::Wait,
            "every piece landed: done only once the epoch is complete at the final block"
        );
        landed.complete = true;
        assert_eq!(
            next_send(&g, L60, &p, &s, &landed, &landed.clone()),
            PqTreeNext::Done
        );
    }

    /// codex-1: the registry's `kemKeyAt` answer keeps its signature in the view (the walk authenticates the key by it); a
    /// scheme other than 1 is no key.
    #[test]
    fn the_kem_view_keeps_the_signature() {
        use alloy::sol_types::SolCall;
        let enc = |scheme: u8| {
            kemKeyAtCall::abi_encode_returns(&kemKeyAtReturn {
                kem: TreeKemKey {
                    scheme,
                    mlkemEk: vec![7u8; 1568].into(),
                    x25519: alloy::primitives::B256::repeat_byte(9),
                },
                sig: vec![1u8, 2, 3].into(),
            })
        };
        let v = kem_view(&enc(1)).unwrap();
        assert_eq!(v["sig"], "0x010203");
        assert_eq!(v["kemPk"].as_str().unwrap().len(), 2 + 2 * 1601);
        assert_eq!(kem_view(&enc(2)).unwrap()["kemPk"], "0x");
    }

    /// Owner 2026-11-25: the creation in one transaction is capped by the chain's limits from the rows: 11 member keys at a
    /// 60 M block by the creation measured as one transaction (B-13 of the T4-T9 review; 12 ask 63.1 M there; the record
    /// and a wrap's fifteenth gave 12 before), fewer with 32 admins, fewer on a small block, none for a kind without a row,
    /// and no figure in code.
    #[test]
    fn the_creation_cap() {
        let g = rows();
        let typical = create_cap(&g, L60, "mldsa65", 1);
        assert_eq!(typical, 11, "{typical}");
        assert!(create_cap(&g, L60, "mldsa65", 32) < typical);
        assert!(create_cap(&g, L20, "mldsa65", 1) < typical);
        assert_eq!(create_cap(&g, L60, "nokind", 1), 0);
    }

    /// The last live leaf's commit (A-8, spec §13: 20 Removes, the admins 1 -> 32, 4,124 B of info, no piece) measured at
    /// 12.83 M / 15.78 M regular: one transaction, under 2^24 and a 60 M block, with both kinds (B-1 of the T4-T9 review).
    #[test]
    fn the_last_live_leafs_commit_plans_as_measured() {
        let g = rows();
        let s = PqCommitShape {
            changes: 20,
            admins: 32,
            info: 4124,
            cts: 0,
            keys: 0,
            adds: 0,
        };
        for kind in ["mldsa65", "mldsa87"] {
            let p = plan_commit(&g, L60, kind, &s).unwrap_or_else(|e| panic!("{kind}: {e:?}"));
            assert_eq!(p.txs.len(), 1, "{kind}");
            assert!(p.txs[0].gas.regular < 1 << 24, "{kind}: {p:?}");
        }
    }

    /// fable-r2-9 (C-1 = B-4 = D-9 of the review): a one-transaction plan whose record another sender stored alone is not
    /// complete; the next send is the first piece through the piece entries; complete only when the epoch is.
    #[test]
    fn a_record_stored_alone_is_not_complete() {
        let g = rows();
        let s = plain();
        let p = plan_commit(&g, L60, "mldsa65", &s).unwrap();
        assert_eq!(p.txs.len(), 1, "one transaction: {p:?}");
        let landed = PqTreeLanded {
            record: true,
            cts: vec![false; 3],
            ..Default::default()
        };
        match next_send(&g, L60, &p, &s, &landed, &landed) {
            PqTreeNext::Send(t) => assert_eq!(t.entry, "addPathList"),
            x => panic!("{x:?}"),
        }
    }

    /// B-5 = C-7 of the review: every signer kind the contract accepts has a verify row (ARCH-POS-18, never a kind refused
    /// for want of a row); a kind with none is refused by its own name, not as a size.
    /// R2-D-7 of the T4-T9 re-check: the kinds walked are `scaas-ua`'s (`KINDS`, every derived kind), so a kind added there
    /// without a row turns this test red. Named apart: the `msig` structure (an `msig` author is planned, CLI-PQC-02) and
    /// `zether-bls12381` (0x0141, a SIGNING kind with no measured row yet: its commit is held to the quote alone, C-7; its row
    /// is left for the owner, the walk found it).
    #[test]
    fn every_signer_kind_has_a_verify_row() {
        let g = rows();
        for kind in scaas_ua::KINDS
            .iter()
            .filter(|k| !k.native && !["msig", "zether-bls12381"].contains(&k.name))
            .map(|k| k.name)
        {
            assert!(plan_commit(&g, L60, kind, &plain()).is_ok(), "{kind}");
            assert!(create_cap(&g, L60, kind, 1) > 0, "{kind}");
        }
        assert_eq!(
            plan_commit(&g, L60, "nokind", &plain()).unwrap_err().what,
            NO_KIND_ROW
        );
    }

    /// B-9 of the review: each chunk but the last holds the most that fit one transaction.
    #[test]
    fn a_chunk_holds_the_most_that_fit() {
        let g = rows();
        let p = plan_commit(&g, L60, "mldsa65", &bounds()).unwrap();
        let chunks: Vec<&PqTreeTx> = p
            .txs
            .iter()
            .filter(|t| t.entry == "addPath" && t.count > 1)
            .collect();
        assert!(chunks.len() > 1, "{p:?}");
        for t in &chunks[..chunks.len() - 1] {
            assert!(
                !L60.fits(g.cts.at(t.count + 1)),
                "{t:?} could take one more"
            );
        }
    }

    fn a8() -> PqCommitShape {
        PqCommitShape {
            changes: 20,
            admins: 32,
            info: 4124,
            cts: 0,
            keys: 0,
            adds: 0,
        }
    }

    /// B-7 of the review: the regular cap binds by itself (EIP-7825): the last live leaf's ML-DSA-87 commit plans at a cap of
    /// its regular gas, whatever the block, and is refused by name one below it.
    #[test]
    fn the_regular_cap_binds_by_itself() {
        let g = rows();
        let r = plan_commit(&g, L60, "mldsa87", &a8()).unwrap().txs[0]
            .gas
            .regular;
        let cap = |c: u64| PqLimits {
            block: 1 << 40,
            tx_regular: Some(c),
        };
        assert!(plan_commit(&g, cap(r), "mldsa87", &a8()).is_ok());
        let e = plan_commit(&g, cap(r - 1), "mldsa87", &a8()).unwrap_err();
        assert_eq!(
            (e.what, e.regular),
            ("the commit (no piece: one transaction)", r)
        );
    }

    /// B-7: the 5 % margin decides: a block of the raw regular + state refuses, a block of what is asked takes it.
    #[test]
    fn the_margin_decides() {
        let g = rows();
        let w = plan_commit(&g, L60, "mldsa65", &a8()).unwrap().txs[0].gas;
        let block = |b: u64| PqLimits {
            block: b,
            tx_regular: None,
        };
        assert!(plan_commit(&g, block(w.regular + w.state), "mldsa65", &a8()).is_err());
        assert!(plan_commit(&g, block(w.asked()), "mldsa65", &a8()).is_ok());
    }

    /// B-7: the held ciphertext waits until every chunk is final, not only landed; D-14: a piece landed at the latest block
    /// and not final is waited for, never sent again.
    #[test]
    fn the_held_piece_waits_for_every_chunk_to_be_final() {
        let g = rows();
        let s = bounds();
        let p = plan_commit(&g, L60, "mldsa65", &s).unwrap();
        let mut landed = PqTreeLanded {
            record: true,
            list: true,
            keys: true,
            cts: vec![true; 511],
            wraps: vec![true; 20],
            complete: false,
        };
        landed.cts[510] = false;
        let mut fin = landed.clone();
        fin.cts[0] = false;
        assert_eq!(next_send(&g, L60, &p, &s, &landed, &fin), PqTreeNext::Wait);
        fin.cts[0] = true;
        assert!(
            matches!(next_send(&g, L60, &p, &s, &landed, &fin), PqTreeNext::Send(t) if t.first == 510)
        );
        // the record landed at the latest block, not final: nothing sent again
        let landed = PqTreeLanded {
            record: true,
            cts: vec![false; 511],
            wraps: vec![false; 20],
            ..Default::default()
        };
        let fin = PqTreeLanded {
            cts: vec![false; 511],
            wraps: vec![false; 20],
            ..Default::default()
        };
        assert_eq!(next_send(&g, L60, &p, &s, &landed, &fin), PqTreeNext::Wait);
    }

    /// B-8: the held ciphertext landed first by another sender with a chunk left: the chunk goes but its last ciphertext,
    /// which then goes alone with the completion; the list left instead (indivisible, with the completion over the block)
    /// is void.
    #[test]
    fn a_chunk_left_last_goes_but_one() {
        let g = rows();
        let s = bounds();
        let p = plan_commit(&g, L60, "mldsa65", &s).unwrap();
        let c = p
            .txs
            .iter()
            .find(|t| t.entry == "addPath" && t.count > 1)
            .unwrap()
            .clone();
        let mut landed = PqTreeLanded {
            record: true,
            list: true,
            keys: true,
            cts: vec![true; 511],
            wraps: vec![true; 20],
            complete: false,
        };
        for i in c.first..c.first + c.count {
            landed.cts[i as usize] = false;
        }
        match next_send(&g, L60, &p, &s, &landed, &landed.clone()) {
            PqTreeNext::Send(t) => assert_eq!(
                (t.entry, t.first, t.count),
                ("addPath", c.first, c.count - 1)
            ),
            x => panic!("{x:?}"),
        }
        for i in c.first..c.first + c.count - 1 {
            landed.cts[i as usize] = true;
        }
        match next_send(&g, L60, &p, &s, &landed, &landed.clone()) {
            PqTreeNext::Send(t) => assert_eq!((t.first, t.count), (c.first + c.count - 1, 1)),
            x => panic!("{x:?}"),
        }
    }

    /// B-6 of the review: the two decoders of the registry's records give the same reads: the direct path's (ABI bytes,
    /// `pqchat_tree_registry`) and the port's (named JSON, `put_*`), for `kemKeyAt` (the key and its kept signature) and
    /// `msigStateOf` (the accepted slots, low and high bits).
    #[test]
    fn the_two_registry_decoders_agree() {
        use alloy::sol_types::SolCall;
        let kem = TreeKemKey {
            scheme: 1,
            mlkemEk: vec![5u8; 1568].into(),
            x25519: alloy::primitives::B256::repeat_byte(3),
        };
        let out = kemKeyAtCall::abi_encode_returns(&kemKeyAtReturn {
            kem: kem.clone(),
            sig: vec![9u8, 8].into(),
        });
        let mut r = PqTreeReads::default();
        r.put_kem_key_at(
            "kemKeyAt(0x01,2)",
            &serde_json::json!({"kem": {"scheme": "1", "mlkemEk": hex(&kem.mlkemEk), "x25519": hex(kem.x25519.as_slice())},
                "sig": "0x0908"}),
        )
        .unwrap();
        assert_eq!(r.views["kemKeyAt(0x01,2)"], kem_view(&out).unwrap());
        let acc =
            alloy::primitives::U256::from(0b1011u64) | (alloy::primitives::U256::from(1u64) << 200);
        let bytes = msigStateOfCall::abi_encode_returns(&msigStateOfReturn {
            version: 1,
            enabled: acc,
            accepted: acc,
        });
        let direct = slots_of(
            msigStateOfCall::abi_decode_returns(&bytes)
                .unwrap()
                .accepted,
        );
        let ua = format!("0x{}", "11".repeat(32));
        r.put_msig_state(&ua, &serde_json::json!({"accepted": acc.to_string()}))
            .unwrap();
        assert_eq!(r.accepted[&ua], direct);
        assert_eq!(direct, vec![0, 1, 3, 200]);
    }
}
