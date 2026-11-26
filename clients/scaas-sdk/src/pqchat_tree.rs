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
    self, CommitInput, PreparedCommit, Replay, TargetKey, TreeDevice, TreePrepared, TreeReader,
    View, PQCHAT_TREE,
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
                    let a = r.accepted.to_be_bytes::<32>();
                    let slots = (0..256u16)
                        .filter(|i| {
                            a.get(31 - usize::from(*i) / 8)
                                .is_some_and(|b| b >> (i % 8) & 1 == 1)
                        })
                        .collect();
                    reads.accepted.insert(k, slots);
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
        let p = self
            .p
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(SdkError::Argument)?;
        let crate::op::Key::Ua(_, key) = crate::op::key(&self.core.sdk, &self.account)? else {
            return Err(SdkError::Argument);
        };
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
        let p = self
            .p
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or(SdkError::Argument)?;
        let crate::op::Key::Ua(_, key) = crate::op::key(&self.core.sdk, &self.account)? else {
            return Err(SdkError::Argument);
        };
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
    inner: Mutex<Replay>,
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

    /// [`AppCore::pqchat_tree_replay`] resumed from `from` (spec §10 step 3): only the epochs after its pin; on success its node
    /// keys move into the new replay. A refusal or a missing read leaves `from` as it was.
    pub fn pqchat_tree_resume(
        &self,
        account: KeyRef,
        key_id: u64,
        reads: &PqTreeReads,
        from: &PqTreeReplay,
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        self.replay(account, key_id, reads, None, Some(from), keys_from)
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

    /// Test-only (feature `vectors`, never in a release build): [`AppCore::pqchat_tree_replay`] by a vector device's KEM key
    /// (`kemSeed`, 96 B, as `tree-secrets.json` lays it out) instead of a wallet key; `K` handles in `seed`'s arena.
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
        keys_from: u64,
    ) -> Result<PqTreeStep<Option<Arc<PqTreeReplay>>>, SdkError> {
        self.label(PQCHAT_TREE.prefix.as_bytes())?;
        let b: &[u8; 96] = kem_seed.try_into().map_err(|_| SdkError::Argument)?;
        let kem = scaas_ua::wallet::KemKeyPair::vectors_ephemeral(b)?;
        self.replay_with(seed, h32(ua)?, key_id, &kem, reads, pin, None, keys_from)
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
                let mut g = f.inner.lock().unwrap_or_else(PoisonError::into_inner);
                sc.tree_resume(&PQCHAT_TREE, &mut rd, &dev, &mut g, keys_from)
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
                    state: match e.state {
                        tree::State::Followed => "followed".into(),
                        tree::State::NotFollowed(why) => format!("not followed: {why}"),
                        tree::State::Compromise => "compromise".into(),
                    },
                    k: e.k.take().map(|h| self.wrap(&seed, h)),
                    info: e.info.map(|i| format!("{i:?}").to_lowercase()),
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
            Arc::new(PqTreeReplay {
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
    /// gas cap of a transaction (2^24, EIP-7825, when the profile names none).
    pub async fn pqchat_tree_limits(&self, chain: &str) -> Result<PqLimits, SdkError> {
        let (profile, _, pool) = crate::op::evm(&self.sdk, chain)?;
        let block = pool.block_gas().await.map_err(|_| SdkError::Argument)?;
        Ok(PqLimits {
            block: block.limit,
            tx_regular: profile.tx_gas_cap.unwrap_or(1 << 24),
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

/// A chain's tree gas rows (release data; `gas/pqchat-tree.json` is the forge reference): never a figure in code (the
/// SDK's gas-table rule). Each transaction's limit is still its estimate at send time; these rows plan and quote.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PqTreeGas {
    /// the signer's verify, by kind name (`mldsa65`, `mldsa87`, …), regular gas
    pub verify: BTreeMap<String, u64>,
    /// the session record per member key (wrap hashes and members), and per admin
    pub session: PqRow,
    pub session_per_admin: PqGas,
    /// a genesis or Welcome wrap: typical, and the first of a subtree
    pub wrap: PqGas,
    pub wrap_first_of_subtree: PqGas,
    /// the commit record per change (Add or Remove), per admin, per 1,024 B of `sealedInfo`
    pub record: PqRow,
    pub record_per_admin: PqGas,
    pub record_per_kib_info: PqGas,
    /// the list per entry, the node keys per key, the path ciphertexts per ciphertext
    pub list: PqRow,
    pub keys: PqRow,
    pub cts: PqRow,
    /// the completion: per change and per path node
    pub completion: PqRow,
    pub completion_per_node: PqGas,
}

/// The chain's limits: the block gas limit (read by RPC) and the regular gas cap of a transaction (2^24, EIP-7825).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PqLimits {
    pub block: u64,
    pub tx_regular: u64,
}

impl PqLimits {
    fn fits(&self, g: PqGas) -> bool {
        g.regular < self.tx_regular && g.asked() <= self.block
    }
}

/// A commit's shape: what the planner sizes (the record's changes, admins and info; the pieces).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PqCommitShape {
    pub changes: u64,
    pub admins: u64,
    pub info: u64,
    pub cts: u64,
    pub keys: u64,
    pub adds: u64,
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

/// A plan refused by name (only the operation whose required piece does not fit), with its figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqTreeRefused {
    pub what: &'static str,
    pub asked: u64,
    pub regular: u64,
    pub limits: (u64, u64),
}

fn refused(what: &'static str, g: PqGas, l: PqLimits) -> PqTreeRefused {
    PqTreeRefused {
        what,
        asked: g.asked(),
        regular: g.regular,
        limits: (l.block, l.tx_regular),
    }
}

/// The record alone: base + changes, admins and info, with the signer's verify (an ML-DSA-87 record at its bounds is sized
/// by its own row).
fn record_gas(g: &PqTreeGas, signer: &str, s: &PqCommitShape) -> Result<PqGas, PqTreeRefused> {
    let v = *g.verify.get(signer).ok_or(PqTreeRefused {
        what: "no verify row for the signer's kind",
        asked: 0,
        regular: 0,
        limits: (0, 0),
    })?;
    Ok(g.record
        .at(s.changes)
        .add(g.record_per_admin.times(s.admins))
        .add(g.record_per_kib_info.times(s.info.div_ceil(1024)))
        .add(PqGas {
            regular: v,
            state: 0,
        }))
}

/// The plan of a commit (spec §13, C37): the whole commit in one transaction when it fits; else the record alone, the list,
/// the node keys, the ciphertexts but one and the wraps (in chunks that fit), and the held ciphertext (else the last wrap)
/// alone with the completion. A required piece that does not fit refuses the operation by name with its figures.
pub fn plan_commit(
    g: &PqTreeGas,
    l: PqLimits,
    signer: &str,
    s: &PqCommitShape,
) -> Result<PqTreePlan, PqTreeRefused> {
    let record = record_gas(g, signer, s)?;
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
    let completion = g
        .completion
        .at(s.changes)
        .add(g.completion_per_node.times(s.keys));
    let cts = g.cts.at(s.cts);
    let wraps = g.wrap.times(s.adds);
    let whole = record
        .add(list)
        .add(keys)
        .add(cts)
        .add(wraps)
        .add(completion);
    // the dearest piece if it were last: the node keys (or the list) with the completion
    let dearest_last = if keys.asked() >= list.asked() {
        keys
    } else {
        list
    }
    .add(completion);
    if l.fits(whole) {
        return Ok(PqTreePlan {
            txs: vec![PqTreeTx {
                entry: "commit",
                first: 0,
                count: 0,
                gas: whole,
            }],
            completion,
            dearest_last,
        });
    }
    if s.cts == 0 && s.adds == 0 {
        return Err(refused("the commit (no piece: one transaction)", whole, l));
    }
    let mut txs = Vec::new();
    for (entry, gas) in [
        ("commit", record),
        ("addPathList", list),
        ("addPathKeys", keys),
    ] {
        if entry != "commit" && gas == PqGas::default() {
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
    let (rest_cts, held_wrap) = match s.cts {
        0 => (0, true),
        n => (n - 1, false),
    };
    let one_ct = g.cts.at(1);
    chunk(&mut txs, "addPath", rest_cts, |n| g.cts.at(n), l)?;
    let rest_wraps = if held_wrap { s.adds - 1 } else { s.adds };
    chunk(&mut txs, "addWraps", rest_wraps, |n| g.wrap.times(n), l)?;
    let last = if held_wrap {
        ("addWraps", s.adds - 1, g.wrap.add(completion))
    } else {
        ("addPath", s.cts - 1, one_ct.add(completion))
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

/// `n` items in chunks of the most that fit one transaction each.
fn chunk(
    txs: &mut Vec<PqTreeTx>,
    entry: &'static str,
    n: u64,
    gas: impl Fn(u64) -> PqGas,
    l: PqLimits,
) -> Result<(), PqTreeRefused> {
    let mut first = 0;
    while first < n {
        let mut k = n - first;
        while k > 0 && !l.fits(gas(k)) {
            k /= 2;
        }
        if k == 0 {
            return Err(refused(entry, gas(1), l));
        }
        txs.push(PqTreeTx {
            entry,
            first,
            count: k,
            gas: gas(k),
        });
        first += k;
    }
    Ok(())
}

/// What is in state of a staged commit (the piece views at the home: `pathListOf`, `pathKeys`, `pathCtAt`, `wrapAt`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PqTreeLanded {
    pub record: bool,
    pub list: bool,
    pub keys: bool,
    pub cts: Vec<bool>,
    pub wraps: Vec<bool>,
}

/// The next send of a commit on the state now (C37, codex-r3-12; the fallback to the piece entries once the record is
/// stored, fable-r2-9).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PqTreeNext {
    /// send this (the planned transaction's entry and range)
    Send(PqTreeTx),
    /// wait: the one before is not final (the list and the node keys go one by one)
    Wait,
    /// complete
    Done,
    /// the order was broken (another sender landed the held piece first): the piece left would pay the completion and does
    /// not fit; nothing more is sent, the commit is rebuilt with a new nonce
    Void(PqTreeRefused),
}

/// The next send of `plan` on `landed` (at the head) with `fin` (at the final block): the first transaction not landed, the
/// record, the list and the node keys each once the one before is final, the held piece once every other is final. When the
/// held piece was landed by another sender first, the piece left last pays the completion: if it cannot, the commit is void.
pub fn next_send(
    g: &PqTreeGas,
    l: PqLimits,
    plan: &PqTreePlan,
    s: &PqCommitShape,
    landed: &PqTreeLanded,
    fin: &PqTreeLanded,
) -> PqTreeNext {
    let at = |v: &[bool], i: u64| v.get(i as usize).copied().unwrap_or(false);
    let is_in = |st: &PqTreeLanded, t: &PqTreeTx| match t.entry {
        "commit" => st.record,
        "addPathList" => st.list,
        "addPathKeys" => st.keys,
        "addPath" => (t.first..t.first + t.count.max(1)).all(|i| at(&st.cts, i)),
        _ => (t.first..t.first + t.count.max(1)).all(|i| at(&st.wraps, i)),
    };
    let left: Vec<usize> = (0..plan.txs.len())
        .filter(|i| plan.txs.get(*i).is_some_and(|t| !is_in(landed, t)))
        .collect();
    let Some(&first) = left.first() else {
        return PqTreeNext::Done;
    };
    let held = plan.txs.len() - 1;
    if plan.txs.len() > 1 && !left.contains(&held) {
        let completion = g
            .completion
            .at(s.changes)
            .add(g.completion_per_node.times(s.keys));
        let last = plan
            .txs
            .get(*left.last().unwrap_or(&first))
            .map_or(PqGas::default(), |t| t.gas)
            .add(completion);
        if !l.fits(last) {
            return PqTreeNext::Void(refused(
                "the piece left with the completion (the order broken)",
                last,
                l,
            ));
        }
    }
    let Some(t) = plan.txs.get(first) else {
        return PqTreeNext::Done;
    };
    let all_final = |upto: usize| plan.txs.iter().take(upto).all(|x| is_in(fin, x));
    let serial = matches!(t.entry, "commit" | "addPathList" | "addPathKeys");
    let last_left = left.len() == 1;
    if (serial || last_left || first == held) && !all_final(first) {
        return PqTreeNext::Wait;
    }
    if !serial && !last_left && first != held {
        // a ciphertext or wrap chunk goes once the record, the list and the node keys are final
        let serial_done = plan
            .txs
            .iter()
            .filter(|x| matches!(x.entry, "commit" | "addPathList" | "addPathKeys"));
        if !serial_done.clone().all(|x| is_in(fin, x)) {
            return PqTreeNext::Wait;
        }
    }
    if first == held && left.len() > 1 {
        return PqTreeNext::Wait;
    }
    PqTreeNext::Send(t.clone())
}

/// The largest creation that fits one transaction (owner 2026-11-25): the session record of `k` member keys and its `k`
/// wraps (`subtrees` of them the first of a subtree) within the chain's limits; 0 when not even one fits.
pub fn create_cap(g: &PqTreeGas, l: PqLimits, signer: &str, admins: u64, subtrees: u64) -> u64 {
    let Some(v) = g.verify.get(signer) else {
        return 0;
    };
    let mut best = 0;
    for k in 1..=512u64 {
        let first = subtrees.min(k);
        let gas = g
            .session
            .at(k)
            .add(g.session_per_admin.times(admins))
            .add(g.wrap_first_of_subtree.times(first))
            .add(g.wrap.times(k - first))
            .add(PqGas {
                regular: *v,
                state: 0,
            });
        if !l.fits(gas) {
            break;
        }
        best = k;
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

    fn rows() -> PqTreeGas {
        serde_json::from_str(include_str!("../gas/pqchat-tree.json")).unwrap()
    }
    const L60: PqLimits = PqLimits {
        block: 60_000_000,
        tx_regular: 1 << 24,
    };
    /// A small block (plan T5 says 20 M; with the measured rows the dearest plain record, the tree check on a cold tree of
    /// 512 with the verify, asks 20.15 M, so the small chain of the test is 24 M)
    const L20: PqLimits = PqLimits {
        block: 24_000_000,
        tx_regular: 1 << 24,
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

    /// Plan T5: a chain with a small block (24 M) takes a plain commit and refuses a record at its bounds by name, with
    /// figures.
    #[test]
    fn a_20m_block_takes_a_plain_commit_and_refuses_the_bound_record() {
        let g = rows();
        let p = plan_commit(&g, L20, "mldsa65", &plain()).unwrap();
        assert!(p.txs.iter().all(|t| L20.fits(t.gas)), "{p:?}");
        let e = plan_commit(&g, L20, "mldsa87", &bounds()).unwrap_err();
        assert_eq!(e.what, "commit", "the record alone, by name: {e:?}");
        assert!(
            e.asked > 24_000_000 && e.limits == (24_000_000, 1 << 24),
            "{e:?}"
        );
        // at 60 M the bound commit plans, in C37's order, the held ciphertext last and alone
        let p = plan_commit(&g, L60, "mldsa87", &bounds()).unwrap();
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

    /// Owner 2026-11-25: the creation in one transaction is capped by the chain's limits from the rows: 12 member keys at a
    /// 60 M block by the measured rows (the spec's estimate said about 16), fewer where wraps open subtrees, fewer on a
    /// small block, none for a kind without a row, and no figure in code.
    #[test]
    fn the_creation_cap() {
        let g = rows();
        let typical = create_cap(&g, L60, "mldsa65", 1, 0);
        assert_eq!(typical, 12, "{typical}");
        assert!(create_cap(&g, L60, "mldsa65", 1, 8) <= typical);
        assert!(create_cap(&g, L20, "mldsa65", 1, 0) < typical);
        assert_eq!(create_cap(&g, L60, "nokind", 1, 0), 0);
    }
}
