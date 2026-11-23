// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The generic surface for app cores above the SDK (spec §12; CLI-SDK-19, CLI-SDK-20; feature `app-core`, bit 26). An app core
//! gets an [`AppCore`] scope: key handles ([`AppKey`], held by `scaas-ua` in the seed's arena, one usage each, never bytes),
//! labels under the prefixes it declared (two live cores never declare prefixes where one starts the other:
//! `AppLabelRefused`), and app record signing on two paths with the refusals of §12.4 (`scaas-ua`'s lists; here the profile's:
//! the domain's `chainId` the chain's, its `verifyingContract` none of the profile's registry, factory, router, tokens or DEX).
//! Scoping avoids collisions; it does not isolate (§12.3: an app holding the user's unlocked seed acts for that UA in every app
//! namespace). The only bytes that leave are the plaintexts the app core asks to decrypt ([`AppCore::open`], a
//! `SecretBytes`). UNAUDITED.
use crate::error::SdkError;
use crate::op::{addr20, final_block, KeyRef};
use crate::op::{ReviewField, Source};
use crate::vault::OpenSeed;
use crate::Sdk;
use alloy::primitives::{Address, Bytes};
use scaas_rpc::evm::EvmPool;
use scaas_rpc::pool::{ReadAt, ReadError};
use scaas_rpc::Purpose;
use scaas_ua::ua_portable::{InnerSig, MemberSig, UASig};
use scaas_ua::wallet::{
    AppKeys, AppPath as UaPath, AppRecordState, Argon2Params, KemWrap, KeyHandle, KeyUsage, Nonce,
    Signer, TypedData,
};
use std::collections::{BTreeMap, HashMap};

/// The secret buffer an app core hands the SDK (a passphrase) and gets back (a plaintext [`AppCore::open`] gives): `scaas-ua`'s,
/// so an app core above the SDK names it without depending on `scaas-ua` (CLI-PQV-01).
pub use scaas_ua::wallet::SecretBytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, Weak};

/// The prefixes every live app core declared, by core id (one process: §12.3 is about the cores one app links).
static DECLARED: Mutex<Vec<(u64, Vec<String>)>> = Mutex::new(Vec::new());
static CORES: AtomicU64 = AtomicU64::new(1);

fn ua(e: scaas_ua::wallet::Error) -> SdkError {
    SdkError::Ua(e)
}

pub(crate) fn hex32(s: &str) -> Result<[u8; 32], SdkError> {
    let h = s.strip_prefix("0x").ok_or(SdkError::Argument)?;
    let v = (0..h.len())
        .step_by(2)
        .map(|i| h.get(i..i + 2).and_then(|b| u8::from_str_radix(b, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .ok_or(SdkError::Argument)?;
    v.try_into().map_err(|_| SdkError::Argument)
}

/// The `i`-th handle `with` gave (it gives as many as it was asked for).
pub(crate) fn at<'a>(hs: &[&'a KeyHandle], i: usize) -> Result<&'a KeyHandle, SdkError> {
    hs.get(i).copied().ok_or(SdkError::Argument)
}

fn hex(b: &[u8]) -> String {
    format!(
        "0x{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// What an app core declares of itself (all self-declared: §12.3).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppDesc {
    /// `0x` + 64 hex, not zero; `None`: a scope that holds handles and labels and signs nothing under an app purpose
    pub app_id: Option<String>,
    pub name: String,
    /// the factory class of the app's contracts, if it has one (a factory instance of another class is refused as a domain)
    pub class: Option<u16>,
    /// the label prefixes the scope's labels must start with (`scaas/<app>/v1/`)
    pub labels: Vec<String>,
}

/// A handle's usage (spec §12.2): fixed at its making, enforced at every use, never in a byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum AppKeyUsage {
    Derive,
    Data,
    KeyWrap,
    /// a file key (CLI-UAL-65): `open_file` only; `seal_file` draws its own
    File,
}

impl From<AppKeyUsage> for KeyUsage {
    fn from(u: AppKeyUsage) -> KeyUsage {
        match u {
            AppKeyUsage::Derive => KeyUsage::Derive,
            AppKeyUsage::Data => KeyUsage::Data,
            AppKeyUsage::KeyWrap => KeyUsage::KeyWrap,
            AppKeyUsage::File => KeyUsage::File,
        }
    }
}

/// A `seal` / `open` nonce.
pub enum AppNonce {
    /// 12 random bytes prepended to the output
    Random,
    /// the nonce the key's own 44-byte derivation gave
    FromKey,
    /// `HMAC(handle, 0x03)[0:12]` of a `Derive` handle of this scope
    FromHandle(Arc<AppKey>),
}

/// A KEM wrap's named fields.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppWrap {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: Vec<u8>,
    pub sealed_key: Vec<u8>,
}

/// A sealed file (CLI-UAL-65): the file key's handle and the public parts.
pub struct AppSealedFile {
    pub key: Arc<AppKey>,
    /// exactly bucket + 16 B
    pub object: Vec<u8>,
    pub ct_sha256: Vec<u8>,
    pub sha256: Vec<u8>,
    pub size: u64,
}

/// `seal_for_arweave`'s answer (CLI-SDK-21): the `file` content's fields, the file key's handle, the signed item to keep and
/// post; the object is the item's data.
#[cfg(feature = "arweave")]
pub struct AppArweaveFile {
    pub url: String,
    pub ct_sha256: Vec<u8>,
    pub sha256: Vec<u8>,
    pub size: u64,
    pub key: Arc<AppKey>,
    pub item: Vec<u8>,
}

/// A key handle of one scope: no bytes, no `Clone` of its key; released by [`AppCore::destroy`], its drop, or the seed's lock.
pub struct AppKey {
    core: u64,
    seed: String,
    h: Mutex<Option<KeyHandle>>,
}

impl AppKey {
    /// The seed whose arena holds the key.
    pub(crate) fn seed(&self) -> &str {
        &self.seed
    }
}

/// An app record's path (spec §12.2).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum AppPath {
    /// (A) `requirePortableApp`: the scope's `app_id`, its purpose `appPurpose(app_id)`
    Portable,
    /// (B) `requireAuthorized` on `chain`: `purpose` the app's own (`0x` + 64 hex), else `appPurpose(app_id)`
    ChainBound {
        chain: String,
        purpose: Option<String>,
    },
}

/// A signed app record: the `UASig`'s named fields, the typed digest and the review shown before it was signed.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppSigned {
    pub key_data: Vec<u8>,
    pub signature: Vec<u8>,
    /// an `msig` signer's slots (`key_data` and `signature` then empty); empty for a single key
    #[serde(default)]
    pub members: Vec<AppMemberSig>,
    pub digest: String,
    pub review: Vec<ReviewField>,
}

/// The `scaas-ua` signing call of a prepared single-key record.
type SignFn = fn(
    &dyn Signer,
    Option<&scaas_ua::Domain>,
    &UaPath,
    &TypedData,
) -> scaas_ua::wallet::Result<UASig>;

/// How a prepared record is signed.
enum How {
    /// a UA key or a native EVM key (`registry`: the bound registry's domain a native key signs `UAAuth` under)
    Key {
        account: KeyRef,
        registry: Option<scaas_ua::Domain>,
        sign: SignFn,
    },
    /// PqVault's `msig` signer, its records read on `chain`'s registry at the signature
    Msig {
        chain: String,
        ua: [u8; 32],
        slots: Vec<crate::op::MsigSlot>,
    },
}

/// An app record prepared for its signature (T26 A-5, decision (125)): the review to show and the typed digest, built from the
/// parsed typed data after every refusal; [`Self::sign`] signs exactly that typed data, once (it consumes the value).
pub struct AppPrepared {
    /// the review shown before the signature (the path, the primary type, every domain and message field)
    pub review: Vec<ReviewField>,
    /// the typed digest the signature covers
    pub digest: String,
    sdk: Arc<Sdk>,
    ua_path: UaPath,
    typed: TypedData,
    how: How,
}

impl AppPrepared {
    /// Signs the prepared record after its review: the key opened now (`Argument` for a stored key; an `msig` as
    /// [`AppCore::prepare_pqvault_record`] states), the `UASig` over [`Self::digest`]'s typed data.
    pub async fn sign(self) -> Result<AppSigned, SdkError> {
        let sdk = self.sdk.clone();
        sdk.clone()
            .spawn(async move {
                let Self {
                    review,
                    digest,
                    ua_path,
                    typed,
                    how,
                    ..
                } = self;
                match how {
                    How::Key {
                        account,
                        registry,
                        sign,
                    } => {
                        let key = crate::op::key(&sdk, &account)?;
                        let signer: &dyn Signer = match &key {
                            crate::op::Key::Ua(_, k) => k,
                            crate::op::Key::Native(_, k) => k,
                            #[allow(unreachable_patterns)]
                            _ => return Err(SdkError::Argument),
                        };
                        let sig = sign(signer, registry.as_ref(), &ua_path, &typed).map_err(ua)?;
                        Ok(AppSigned {
                            key_data: sig.key_data,
                            signature: sig.signature,
                            members: vec![],
                            digest,
                            review,
                        })
                    }
                    How::Msig {
                        chain,
                        ua: m,
                        slots,
                    } => {
                        let sig = crate::account::msig::app_msig(
                            &sdk,
                            &chain,
                            &m,
                            &slots,
                            |first, current, inner, domain, s| {
                                scaas_ua::wallet::pqvault::sign_msig(
                                    first, current, inner, domain, &ua_path, &typed, s,
                                )
                            },
                        )
                        .await?;
                        Ok(AppSigned {
                            key_data: vec![],
                            signature: vec![],
                            members: sig.members.iter().map(AppMemberSig::from).collect(),
                            digest,
                            review,
                        })
                    }
                }
            })
            .await
    }
}

/// A `UASig` as an app record carries it (TS-D12): a single key `key_data` (empty for a stored kind and on path A) and
/// `signature`; an `msig` `members` only.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppUaSig {
    pub key_data: Vec<u8>,
    pub signature: Vec<u8>,
    pub members: Vec<AppMemberSig>,
}

/// One `msig` slot's signature: a signing member `sig`, an `msig` member its leaves' `members`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppMemberSig {
    pub index: u16,
    pub members: Vec<AppInnerSig>,
    pub sig: Vec<u8>,
}

/// One leaf of an `msig` member's slot.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppInnerSig {
    pub index: u16,
    pub sig: Vec<u8>,
}

impl From<&MemberSig> for AppMemberSig {
    fn from(m: &MemberSig) -> AppMemberSig {
        AppMemberSig {
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
        }
    }
}

impl From<&AppUaSig> for UASig {
    fn from(s: &AppUaSig) -> UASig {
        UASig {
            key_data: s.key_data.clone(),
            signature: s.signature.clone(),
            members: s
                .members
                .iter()
                .map(|m| MemberSig {
                    index: m.index,
                    members: m
                        .members
                        .iter()
                        .map(|x| InnerSig {
                            index: x.index,
                            sig: x.sig.clone(),
                        })
                        .collect(),
                    sig: m.sig.clone(),
                })
                .collect(),
        }
    }
}

/// A call of an app's own contract as the user reviews it ([`AppCore::prepare_app_call`]): the entry, the contract and every
/// named argument, and the payer's transaction (`Wallet::submit_native_send` sends exactly it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppCall {
    pub review: Vec<ReviewField>,
    pub quote: crate::wallet::NativeQuote,
}

/// One registry record as [`AppCore::verify_app_record`] reads it: `(kind, keyData)` of `registrationOf`, an `msig`'s current
/// structure with its `enabled` word (`None`: never updated) and its accepted-and-enabled bits.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Rec {
    kind: u16,
    key_data: Vec<u8>,
    current: Option<(Vec<u8>, [u8; 32])>,
    active: [u8; 32],
}

/// The records [`AppCore::verify_app_record`] reads at most: a UA, its members and their members (two levels).
// ponytail: a fixed cap of records per verification; past it the rest is unread and the verdict false (fail closed)
const RECORDS_MAX: usize = 512;
/// A registered key's data read from `registrationOf`, at most (an `msig` of 256 slots is 9,220 bytes).
const KEY_DATA_MAX: u64 = 1 << 16;
const MSIG: u16 = 0x0120;
const KEM_EK: usize = 1568;

fn word(out: &[u8], at: usize) -> Option<[u8; 32]> {
    out.get(at..at.checked_add(32)?)?.try_into().ok()
}

/// A word that is a number at most `max`.
fn small(out: &[u8], at: usize, max: u64) -> Option<usize> {
    let w = word(out, at)?;
    let (hi, lo) = w.split_at(24);
    let n = u64::from_be_bytes(lo.try_into().ok()?);
    (hi.iter().all(|b| *b == 0) && n <= max)
        .then(|| usize::try_from(n).ok())
        .flatten()
}

/// `bytes` at the head offset `head` of the tuple at `base`, at most `max` bytes.
fn dyn_bytes(out: &[u8], base: usize, head: usize, max: u64) -> Option<Vec<u8>> {
    let o = base.checked_add(small(out, head, 1 << 24)?)?;
    let n = small(out, o, max)?;
    out.get(o + 32..o + 32 + n).map(<[u8]>::to_vec)
}

/// `kemKeyAt(ua, v)`'s `(KemKey(uint8 scheme, bytes mlkemEk, bytes32 x25519) kem, bytes sig)` as the KEM key
/// `scheme ‖ mlkemEk ‖ x25519`: scheme 1 only (`KemCheck` otherwise, none at that version included), an `mlkemEk` of exactly
/// 1,568 bytes (`KemCheck`), a malformed answer `Argument`.
fn kem_pk_of(out: &[u8]) -> Result<Vec<u8>, SdkError> {
    let base = small(out, 0, 1 << 16).ok_or(SdkError::Argument)?;
    let scheme = small(out, base, 255).ok_or(SdkError::Argument)?;
    if scheme != 1 {
        return Err(SdkError::Ua(scaas_ua::wallet::Error::KemCheck));
    }
    let ek = dyn_bytes(out, base, base + 32, 1 << 16).ok_or(SdkError::Argument)?;
    let x = word(out, base + 64).ok_or(SdkError::Argument)?;
    if ek.len() != KEM_EK {
        return Err(SdkError::Ua(scaas_ua::wallet::Error::KemCheck));
    }
    Ok([&[1u8][..], &ek, &x].concat())
}

fn sel(sig: &str) -> Vec<u8> {
    scaas_ua::keccak256(sig.as_bytes())
        .get(..4)
        .unwrap_or_default()
        .to_vec()
}

use crate::line::call_at;

fn bit(w: &[u8; 32], i: u16) -> bool {
    let i = usize::from(i);
    i < 256 && w.get(31 - i / 8).is_some_and(|b| b >> (i % 8) & 1 == 1)
}

/// The records of `ua`, its members and theirs (two levels, at most [`RECORDS_MAX`]) at the read's block, each read at the
/// generation that holds it (F2, [`crate::line::Line`]): an unregistered id has none, a malformed answer is unread (the
/// verdict false, never another endpoint's answer: R7 of spec §9.4).
async fn records(
    pool: &EvmPool,
    at: &ReadAt<alloy::primitives::B256>,
    line: &crate::line::Line,
    ua: [u8; 32],
) -> Result<BTreeMap<[u8; 32], Rec>, ReadError> {
    let mut out = BTreeMap::new();
    let mut todo = vec![(ua, 0u8)];
    while let Some((id, depth)) = todo.pop() {
        if out.len() >= RECORDS_MAX || out.contains_key(&id) || scaas_ua::in_native_space(&id) {
            continue;
        }
        let Some(registry) = line.holder(pool, at, id).await? else {
            continue;
        };
        let r = call_at(pool, at, registry, "registrationOf(bytes32)", &[id]).await?;
        let Some(kind) = small(&r, 0, u64::from(u16::MAX)).and_then(|k| u16::try_from(k).ok())
        else {
            continue;
        };
        let Some(key_data) = dyn_bytes(&r, 0, 32, KEY_DATA_MAX) else {
            continue;
        };
        if kind == 0 {
            continue;
        }
        let mut rec = Rec {
            kind,
            key_data,
            current: None,
            active: [0; 32],
        };
        if kind == MSIG {
            let st = call_at(pool, at, registry, "msigStateOf(bytes32)", &[id]).await?;
            let (Some(version), Some(enabled), Some(accepted)) =
                (small(&st, 0, u64::MAX), word(&st, 32), word(&st, 64))
            else {
                continue;
            };
            let structure = if version != 0 {
                let c = call_at(pool, at, registry, "msigOf(bytes32)", &[id]).await?;
                let Some(c) = crate::account::msig::decode_structure(&c) else {
                    continue;
                };
                rec.current = Some((c.clone(), enabled));
                c
            } else {
                rec.key_data.clone()
            };
            for (i, b) in rec.active.iter_mut().enumerate() {
                *b = enabled.get(i).copied().unwrap_or(0) & accepted.get(i).copied().unwrap_or(0);
            }
            if depth < 2 {
                if let Ok(m) = scaas_ua::ua_portable::MsigStructure::from_key_data(&structure) {
                    todo.extend(m.members.iter().map(|x| (x.id, depth + 1)));
                }
            }
        }
        out.insert(id, rec);
    }
    Ok(out)
}

/// A named argument of an app entry as an ABI value of the parameter `(ty, components)`: a tuple from an object of exactly its
/// component names, an array from an array, every other type from its string form (a number or a bool as JSON gives it).
fn abi_value(
    ty: &str,
    comps: &[alloy::json_abi::Param],
    v: &serde_json::Value,
    depth: u8,
) -> Result<alloy::dyn_abi::DynSolValue, SdkError> {
    use alloy::dyn_abi::{DynSolType, DynSolValue};
    use serde_json::Value;
    if depth > 16 {
        return Err(SdkError::Argument);
    }
    if let Some(inner) = ty.strip_suffix(']') {
        let (elem, n) = inner.rsplit_once('[').ok_or(SdkError::Argument)?;
        let a = v.as_array().ok_or(SdkError::Argument)?;
        if a.len() > 4096 || (!n.is_empty() && n.parse::<usize>().ok() != Some(a.len())) {
            return Err(SdkError::Argument);
        }
        let items = a
            .iter()
            .map(|x| abi_value(elem, comps, x, depth + 1))
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(if n.is_empty() {
            DynSolValue::Array(items)
        } else {
            DynSolValue::FixedArray(items)
        });
    }
    if ty == "tuple" {
        let o = v.as_object().ok_or(SdkError::Argument)?;
        if o.len() != comps.len() {
            return Err(SdkError::Argument);
        }
        let items = comps
            .iter()
            .map(|c| {
                let x = o.get(&c.name).ok_or(SdkError::Argument)?;
                abi_value(&c.ty, &c.components, x, depth + 1)
            })
            .collect::<Result<Vec<_>, _>>()?;
        return Ok(DynSolValue::Tuple(items));
    }
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => return Err(SdkError::Argument),
    };
    DynSolType::parse(ty)
        .and_then(|t| t.coerce_str(&s))
        .map_err(|_| SdkError::Argument)
}

/// An entry call: the function, the arguments' object, the calldata.
type EntryCall = (
    alloy::json_abi::Function,
    serde_json::Map<String, serde_json::Value>,
    Vec<u8>,
);

/// An app entry's JSON ABI item `entry` and its named arguments `args` (bounded: 64 KiB, 128 KiB) as the function, the
/// arguments' object and the calldata; `Argument` for an entry that does not parse or arguments that are not its names and
/// types.
fn entry_call(entry: &str, args: &str) -> Result<EntryCall, SdkError> {
    use alloy::dyn_abi::JsonAbiExt;
    if entry.len() > 64 * 1024 || args.len() > 128 * 1024 {
        return Err(SdkError::Argument);
    }
    let f: alloy::json_abi::Function =
        serde_json::from_str(entry).map_err(|_| SdkError::Argument)?;
    let a: serde_json::Value = serde_json::from_str(args).map_err(|_| SdkError::Argument)?;
    let serde_json::Value::Object(o) = a else {
        return Err(SdkError::Argument);
    };
    if o.len() != f.inputs.len() || f.inputs.iter().any(|p| p.name.is_empty()) {
        return Err(SdkError::Argument);
    }
    let values = f
        .inputs
        .iter()
        .map(|p| {
            let v = o.get(&p.name).ok_or(SdkError::Argument)?;
            abi_value(&p.ty, &p.components, v, 0)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let data = f
        .abi_encode_input(&values)
        .map_err(|_| SdkError::Argument)?;
    Ok((f, o, data))
}

/// The deepest a [`AppCore::read_app`] output type nests (each tuple and each array dimension one level).
const READ_DEPTH: usize = 16;
/// The most bytes a [`AppCore::read_app`] answer holds.
const READ_MAX: usize = 1 << 20;

fn type_depth(ty: &str, comps: &[alloy::json_abi::Param]) -> usize {
    let inner = comps
        .iter()
        .map(|c| type_depth(&c.ty, &c.components))
        .max()
        .map_or(0, |d| d + 1);
    ty.matches('[').count() + inner
}

/// A decoded value as named JSON: a tuple an object of its components' names (an unnamed one its index), an array an array,
/// an integer its decimal string, an address, bytes and fixed bytes `0x` + lower-case hex, a bool and a string as JSON's.
fn named(
    v: &alloy::dyn_abi::DynSolValue,
    comps: &[alloy::json_abi::Param],
) -> Result<serde_json::Value, SdkError> {
    use alloy::dyn_abi::DynSolValue as D;
    use serde_json::Value;
    Ok(match v {
        D::Bool(b) => Value::Bool(*b),
        D::Int(i, _) => Value::String(i.to_string()),
        D::Uint(u, _) => Value::String(u.to_string()),
        D::FixedBytes(w, n) => Value::String(hex(w.get(..*n).ok_or(SdkError::Argument)?)),
        D::Address(a) => Value::String(hex(a.as_slice())),
        D::Function(f) => Value::String(hex(f.as_slice())),
        D::Bytes(b) => Value::String(hex(b)),
        D::String(s) => Value::String(s.clone()),
        D::Array(xs) | D::FixedArray(xs) => Value::Array(
            xs.iter()
                .map(|x| named(x, comps))
                .collect::<Result<_, _>>()?,
        ),
        D::Tuple(xs) => {
            if xs.len() != comps.len() {
                return Err(SdkError::Argument);
            }
            let mut o = serde_json::Map::new();
            for (i, (x, c)) in xs.iter().zip(comps).enumerate() {
                let k = if c.name.is_empty() {
                    i.to_string()
                } else {
                    c.name.clone()
                };
                o.insert(k, named(x, &c.components)?);
            }
            Value::Object(o)
        }
        #[allow(unreachable_patterns)]
        _ => return Err(SdkError::Argument),
    })
}

/// A seed's `scaas-ua` scope and the open session whose arena it was made over.
type Scoped = (Weak<OpenSeed>, Arc<AppKeys>);

/// One app core's scope (spec §12.2).
pub struct AppCore {
    pub(crate) sdk: Arc<Sdk>,
    id: u64,
    app_id: Option<[u8; 32]>,
    class: Option<u16>,
    labels: Vec<String>,
    /// one `scaas-ua` scope per seed the core used, over the arena of the seed's open session it was made in (a lock and
    /// the next unlock open a new arena: the scope is made again there)
    keys: Mutex<HashMap<String, Scoped>>,
}

impl Drop for AppCore {
    fn drop(&mut self) {
        DECLARED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(c, _)| *c != self.id);
    }
}

fn overlaps(a: &str, b: &str) -> bool {
    a.starts_with(b) || b.starts_with(a)
}

impl AppCore {
    /// A new scope: `app_id` 0 or malformed, a name empty, no label prefix or an empty one: `Argument`; a prefix that starts
    /// or is started by another live core's (or another of its own): `AppLabelRefused`.
    pub fn new(sdk: Arc<Sdk>, desc: AppDesc) -> Result<Arc<AppCore>, SdkError> {
        let app_id = desc.app_id.as_deref().map(hex32).transpose()?;
        if app_id == Some([0; 32])
            || desc.name.is_empty()
            || desc.labels.is_empty()
            || desc.labels.iter().any(String::is_empty)
        {
            return Err(SdkError::Argument);
        }
        let mut d = DECLARED.lock().unwrap_or_else(PoisonError::into_inner);
        let own = desc
            .labels
            .iter()
            .enumerate()
            .any(|(i, a)| desc.labels.iter().skip(i + 1).any(|b| overlaps(a, b)));
        let other = d
            .iter()
            .flat_map(|(_, l)| l)
            .any(|b| desc.labels.iter().any(|a| overlaps(a, b)));
        if own || other {
            return Err(SdkError::AppLabelRefused);
        }
        let id = CORES.fetch_add(1, Ordering::Relaxed);
        d.push((id, desc.labels.clone()));
        Ok(Arc::new(AppCore {
            sdk,
            id,
            app_id,
            class: desc.class,
            labels: desc.labels,
            keys: Mutex::new(HashMap::new()),
        }))
    }

    pub(crate) fn scope(&self, seed: &str) -> Result<Arc<AppKeys>, SdkError> {
        let open = self.sdk.open_seed(seed)?;
        let mut m = self.keys.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((o, k)) = m.get(seed) {
            if std::ptr::eq(o.as_ptr(), Arc::as_ptr(&open)) {
                return Ok(k.clone());
            }
        }
        let k = Arc::new(open.wallet.app_keys());
        m.insert(seed.to_string(), (Arc::downgrade(&open), k.clone()));
        Ok(k)
    }

    pub(crate) fn label(&self, label: &[u8]) -> Result<(), SdkError> {
        let ok = self.labels.iter().any(|p| label.starts_with(p.as_bytes()));
        ok.then_some(()).ok_or(SdkError::AppLabelRefused)
    }

    fn mine(&self, k: &AppKey) -> Result<(), SdkError> {
        (k.core == self.id)
            .then_some(())
            .ok_or(SdkError::Ua(scaas_ua::wallet::Error::AppHandleForeign))
    }

    /// `f` over the handles `ks` (each this scope's, of one seed), in `seed`'s `scaas-ua` scope.
    pub(crate) fn with<R>(
        &self,
        ks: &[&AppKey],
        f: impl FnOnce(&AppKeys, &[&KeyHandle]) -> Result<R, SdkError>,
    ) -> Result<R, SdkError> {
        let seed = ks
            .first()
            .map(|k| k.seed.clone())
            .ok_or(SdkError::Argument)?;
        // one handle twice would wait on its own lock (controller call 2026-11-22, CLI-SDK-33): refused before any lock
        if ks
            .iter()
            .enumerate()
            .any(|(i, a)| ks.iter().take(i).any(|b| std::ptr::eq(*a, *b)))
        {
            return Err(SdkError::Argument);
        }
        for k in ks {
            self.mine(k)?;
            if k.seed != seed {
                return Err(SdkError::Ua(scaas_ua::wallet::Error::AppHandleForeign));
            }
        }
        let scope = self.scope(&seed)?;
        let guards: Vec<_> = ks
            .iter()
            .map(|k| k.h.lock().unwrap_or_else(PoisonError::into_inner))
            .collect();
        let hs = guards
            .iter()
            .map(|g| {
                g.as_ref()
                    .ok_or(SdkError::Ua(scaas_ua::wallet::Error::KeyRevoked))
            })
            .collect::<Result<Vec<_>, _>>()?;
        f(&scope, &hs)
    }

    pub(crate) fn wrap(&self, seed: &str, h: KeyHandle) -> Arc<AppKey> {
        Arc::new(AppKey {
            core: self.id,
            seed: seed.to_string(),
            h: Mutex::new(Some(h)),
        })
    }

    /// Non-key randomness of `n` bytes (at most 4,096): a salt, a nonce prefix, passphrase words.
    pub fn random_bytes(&self, seed: &str, n: u32) -> Result<Vec<u8>, SdkError> {
        self.scope(seed)?.random_bytes(n as usize).map_err(ua)
    }

    /// A fresh random key of `usage` in `seed`'s arena.
    pub fn random_key(&self, seed: &str, usage: AppKeyUsage) -> Result<Arc<AppKey>, SdkError> {
        let h = self.scope(seed)?.random_key(usage.into()).map_err(ua)?;
        Ok(self.wrap(seed, h))
    }

    /// A generated passphrase (owner 2026-11-22): 6 BIP-39 English words from `scaas-ua`'s generator, one space apart (about
    /// 66 bits), as a secret buffer: the words are made and kept below the SDK.
    pub fn generate_passphrase(&self, seed: &str) -> Result<Arc<SecretBytes>, SdkError> {
        Ok(Arc::new(
            self.scope(seed)?.generated_passphrase().map_err(ua)?,
        ))
    }

    /// HKDF-SHA-256 over the `Derive` handles `keys`, `info = label ‖ context` exactly, `label` under the scope's prefixes;
    /// with `nonce`, the output's next 12 bytes kept on the handle for [`AppNonce::FromKey`].
    pub fn derive(
        &self,
        keys: Vec<Arc<AppKey>>,
        salt: Vec<u8>,
        label: Vec<u8>,
        context: Vec<u8>,
        usage: AppKeyUsage,
        nonce: bool,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(&label)?;
        let refs: Vec<&AppKey> = keys.iter().map(|k| &**k).collect();
        let seed = refs
            .first()
            .map(|k| k.seed.clone())
            .ok_or(SdkError::Argument)?;
        let info = [label, context].concat();
        let h = self.with(&refs, |s, hs| {
            s.derive(hs, &salt, &info, usage.into(), nonce).map_err(ua)
        })?;
        Ok(self.wrap(&seed, h))
    }

    /// HMAC-SHA-256 of `data` under a `Derive` handle into a key of `usage` (a chain step: no label); `data` starting with a
    /// declared prefix of any live core is refused (`AppLabelRefused`: it would rebuild a labelled key, pqchat-core §5.3 (6)).
    pub fn mac_derive(
        &self,
        key: Arc<AppKey>,
        data: Vec<u8>,
        usage: AppKeyUsage,
    ) -> Result<Arc<AppKey>, SdkError> {
        let declared = DECLARED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if declared
            .iter()
            .flat_map(|(_, l)| l)
            .any(|p| data.starts_with(p.as_bytes()))
        {
            return Err(SdkError::AppLabelRefused);
        }
        let h = self.with(&[&key], |s, hs| {
            s.mac_derive(at(hs, 0)?, &data, usage.into()).map_err(ua)
        })?;
        Ok(self.wrap(&key.seed, h))
    }

    /// One public MAC output of 1 to 8 bytes, `label_and_data` starting with a declared prefix, on a key this scope drew or
    /// unwrapped.
    pub fn mac_public(
        &self,
        key: Arc<AppKey>,
        label_and_data: Vec<u8>,
        len: u32,
    ) -> Result<Vec<u8>, SdkError> {
        self.label(&label_and_data)?;
        self.with(&[&key], |s, hs| {
            s.mac_public(at(hs, 0)?, &label_and_data, len as usize)
                .map_err(ua)
        })
    }

    fn nonce_of<'a>(n: &'a AppNonce, from: Option<&'a KeyHandle>) -> Nonce<'a> {
        match (n, from) {
            (AppNonce::Random, _) => Nonce::Random,
            (AppNonce::FromKey, _) => Nonce::FromKey,
            (AppNonce::FromHandle(_), Some(h)) => Nonce::FromHandle(h),
            (AppNonce::FromHandle(_), None) => Nonce::FromKey,
        }
    }

    /// AES-256-GCM-SIV of `pt` under a `Data` handle (`nonce ‖ ct` for a random nonce, `ct` otherwise).
    pub fn seal(
        &self,
        key: Arc<AppKey>,
        nonce: AppNonce,
        aad: Vec<u8>,
        pt: Vec<u8>,
    ) -> Result<Vec<u8>, SdkError> {
        match &nonce {
            AppNonce::FromHandle(n) => self.with(&[&key, n], |s, hs| {
                s.seal(
                    at(hs, 0)?,
                    Self::nonce_of(&nonce, Some(at(hs, 1)?)),
                    &aad,
                    &pt,
                )
                .map_err(ua)
            }),
            _ => self.with(&[&key], |s, hs| {
                s.seal(at(hs, 0)?, Self::nonce_of(&nonce, None), &aad, &pt)
                    .map_err(ua)
            }),
        }
    }

    /// The plaintext of a [`AppCore::seal`] output, as `Plaintext` (a `SecretBytes`): the only bytes that leave.
    pub fn open(
        &self,
        key: Arc<AppKey>,
        nonce: AppNonce,
        aad: Vec<u8>,
        ct: Vec<u8>,
    ) -> Result<SecretBytes, SdkError> {
        let pt = match &nonce {
            AppNonce::FromHandle(n) => self.with(&[&key, n], |s, hs| {
                s.open(
                    at(hs, 0)?,
                    Self::nonce_of(&nonce, Some(at(hs, 1)?)),
                    &aad,
                    &ct,
                )
                .map_err(ua)
            })?,
            _ => self.with(&[&key], |s, hs| {
                s.open(at(hs, 0)?, Self::nonce_of(&nonce, None), &aad, &ct)
                    .map_err(ua)
            })?,
        };
        SecretBytes::from_zeroizing(pt).map_err(ua)
    }

    /// `key` sealed under a `KeyWrap` handle (60 bytes, the key-wrap AAD with `key`'s usage).
    pub fn seal_key(
        &self,
        under: Arc<AppKey>,
        key: Arc<AppKey>,
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, SdkError> {
        self.with(&[&under, &key], |s, hs| {
            s.seal_key(at(hs, 0)?, at(hs, 1)?, &aad).map_err(ua)
        })
    }

    /// The key a [`AppCore::seal_key`] output holds, as a handle of `usage` (the one it was sealed with).
    pub fn open_key(
        &self,
        under: Arc<AppKey>,
        wire: Vec<u8>,
        usage: AppKeyUsage,
        aad: Vec<u8>,
    ) -> Result<Arc<AppKey>, SdkError> {
        let h = self.with(&[&under], |s, hs| {
            s.open_key(at(hs, 0)?, &wire, usage.into(), &aad)
                .map_err(ua)
        })?;
        Ok(self.wrap(&under.seed, h))
    }

    /// Whether two handles hold the same key.
    pub fn same_key(&self, a: Arc<AppKey>, b: Arc<AppKey>) -> Result<bool, SdkError> {
        self.with(&[&a, &b], |s, hs| {
            s.same_key(at(hs, 0)?, at(hs, 1)?).map_err(ua)
        })
    }

    /// Argon2id of `password` (a `SecretBytes`) into a `Derive` handle of `seed`'s arena, off the async workers.
    pub async fn argon2id(
        self: &Arc<Self>,
        seed: String,
        password: Arc<SecretBytes>,
        salt: Vec<u8>,
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Result<Arc<AppKey>, SdkError> {
        let me = self.clone();
        let sdk = self.sdk.clone();
        sdk.heavy(move || {
            let scope = me.scope(&seed)?;
            let h = password
                .with(|pw| scope.argon2id(pw, &salt, Argon2Params { m_kib, t, p }))
                .map_err(ua)?;
            Ok(me.wrap(&seed, h))
        })
        .await
    }

    /// [`AppCore::argon2id`] of a typed passphrase (UTF-8) after RFC 8265's OpaqueString (every non-ASCII space to U+0020,
    /// then NFC), so a composed and a decomposed form give one key; not UTF-8, empty or a control character: `Argument`.
    pub async fn argon2id_passphrase(
        self: &Arc<Self>,
        seed: String,
        passphrase: Arc<SecretBytes>,
        salt: Vec<u8>,
        m_kib: u32,
        t: u32,
        p: u32,
    ) -> Result<Arc<AppKey>, SdkError> {
        let me = self.clone();
        let sdk = self.sdk.clone();
        sdk.heavy(move || {
            let scope = me.scope(&seed)?;
            let h = passphrase
                .with(|pw| scope.argon2id_passphrase(pw, &salt, Argon2Params { m_kib, t, p }))
                .map_err(ua)?;
            Ok(me.wrap(&seed, h))
        })
        .await
    }

    /// `key` wrapped to the KEM key `kem_pk` (a fresh ephemeral key of a device link, or a UA's at a version the app read
    /// under `Purpose::FeedsDecryption`); `label` under the scope's prefixes.
    pub fn kem_wrap_to_key(
        &self,
        kem_pk: Vec<u8>,
        key: Arc<AppKey>,
        label: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.label(&label)?;
        let w = self.with(&[&key], |s, hs| {
            s.kem_wrap(at(hs, 0)?, &label, &aad, &kem_pk).map_err(ua)
        })?;
        Ok(AppWrap {
            mlkem_ct: w.mlkem_ct,
            x25519_eph: w.x25519_eph.to_vec(),
            sealed_key: w.sealed_key,
        })
    }

    /// The key of `wrap` by the account's KEM key at `key_version` (the wrap's `keyId`), as a handle of `usage`.
    pub fn kem_unwrap(
        &self,
        account: KeyRef,
        key_version: u64,
        wrap: AppWrap,
        label: Vec<u8>,
        aad: Vec<u8>,
        usage: AppKeyUsage,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(&label)?;
        let KeyRef::Ua {
            seed,
            kind,
            account,
            index,
        } = account
        else {
            return Err(SdkError::Argument);
        };
        let open = self.sdk.open_seed(&seed)?;
        let kem = open
            .wallet
            .ua_key(kind, account, index)
            .and_then(|k| k.kem_key(key_version))
            .map_err(ua)?;
        let w = KemWrap {
            mlkem_ct: wrap.mlkem_ct,
            x25519_eph: wrap.x25519_eph.try_into().map_err(|_| SdkError::Argument)?,
            sealed_key: wrap.sealed_key,
        };
        let h = self
            .scope(&seed)?
            .kem_unwrap(&kem, &w, &label, &aad, usage.into())
            .map_err(ua)?;
        Ok(self.wrap(&seed, h))
    }

    /// The scope's per-account storage root of `account` (a UA key): `app_id` required (`Argument` without).
    pub fn app_root_key(&self, account: KeyRef) -> Result<Arc<AppKey>, SdkError> {
        let app_id = self.app_id.ok_or(SdkError::Argument)?;
        let id = self.account_ua(&account)?;
        let KeyRef::Ua { seed, .. } = account else {
            return Err(SdkError::Argument);
        };
        let h = self.scope(&seed)?.app_root_key(&app_id, &id).map_err(ua)?;
        Ok(self.wrap(&seed, h))
    }

    /// The generic file seal (CLI-UAL-65, in every store): `file` framed to its power-of-two bucket and sealed under a fresh
    /// file key (a `File` handle); the object is exactly bucket + 16 B. Above the platform's cap: `FileTooLarge`.
    pub fn seal_file(&self, seed: &str, file: Vec<u8>) -> Result<AppSealedFile, SdkError> {
        let s = self.scope(seed)?.seal_file(&file)?;
        Ok(AppSealedFile {
            ct_sha256: s.ct_sha256.to_vec(),
            sha256: s.sha256.to_vec(),
            size: s.size,
            object: s.object,
            key: self.wrap(seed, s.key),
        })
    }

    /// The file of `object` under the `File` handle `key`, after `scaas-ua`'s checks: before any decryption the length
    /// (`FileLength`) and SHA-256 of the object against `ct_sha256` (`FileHashMismatch`; pqchat-core T10b: on every open path,
    /// whoever fetched the bytes), then the tag, the frame's `len` against `size`, the zero pad, SHA-256 against `sha256`, and
    /// only then, as `Plaintext`. A cache of opened files is keyed by `sha256`.
    pub fn open_file(
        &self,
        key: Arc<AppKey>,
        object: Vec<u8>,
        size: u64,
        sha256: Vec<u8>,
        ct_sha256: Vec<u8>,
    ) -> Result<SecretBytes, SdkError> {
        let sha: [u8; 32] = sha256.try_into().map_err(|_| SdkError::Argument)?;
        let ct: [u8; 32] = ct_sha256.try_into().map_err(|_| SdkError::Argument)?;
        let pt = self.with(&[&key], |s, hs| {
            Ok(s.open_file(at(hs, 0)?, &object, size, &sha, &ct)?)
        })?;
        SecretBytes::from_zeroizing(pt).map_err(ua)
    }

    /// `file` sealed for Arweave in one `scaas-ua` call (CLI-SDK-21): a fresh file key, the object, its `ctSha256`, the upload
    /// key from `account`'s app root key and the file key, the item of `signature_type` (2, 3 or 4) built, signed and verified;
    /// `url` = `ar://<id>` is known before any upload. `max_object`: the bundler profile's largest single request
    /// (`FileTooLarge` above its bucket, or above the platform's cap).
    #[cfg(feature = "arweave")]
    pub fn seal_for_arweave(
        &self,
        account: KeyRef,
        file: Vec<u8>,
        signature_type: u16,
        max_object: u64,
    ) -> Result<AppArweaveFile, SdkError> {
        let t =
            scaas_ua::arweave::SigType::from_u16(signature_type).map_err(|_| SdkError::Argument)?;
        let cap = max_object.saturating_sub(scaas_ua::file::TAG);
        let root = self.app_root_key(account)?;
        let seed = root.seed().to_string();
        let a = self.with(&[&root], |s, hs| {
            Ok(s.seal_for_arweave(at(hs, 0)?, &file, t, cap)?)
        });
        self.destroy(root)?;
        let a = a?;
        Ok(AppArweaveFile {
            url: a.url,
            ct_sha256: a.ct_sha256.to_vec(),
            sha256: a.sha256.to_vec(),
            size: a.size,
            item: a.item.into_bytes(),
            key: self.wrap(&seed, a.key),
        })
    }

    /// Wipes the handle's key now.
    pub fn destroy(&self, key: Arc<AppKey>) -> Result<(), SdkError> {
        self.mine(&key)?;
        drop(key.h.lock().unwrap_or_else(PoisonError::into_inner).take());
        Ok(())
    }

    /// The review of an app record (spec §12.2: the domain's name and `app_id` taken from the typed data, the path, every
    /// domain and message field, source `Signed`).
    fn review(path: &AppPath, typed: &TypedData) -> Vec<ReviewField> {
        let v = typed.to_value();
        let mut out = vec![field(
            "path",
            match path {
                AppPath::Portable => "portable".to_string(),
                AppPath::ChainBound { chain, .. } => format!("chain-bound on {chain}"),
            },
            Source::Derived,
        )];
        out.push(field(
            "primaryType",
            typed.primary_type().to_string(),
            Source::Signed,
        ));
        for part in ["domain", "message"] {
            flatten(
                part,
                v.get(part).unwrap_or(&serde_json::Value::Null),
                &mut out,
            );
        }
        out
    }

    /// Prepares the app record `typed_json` (EIP-712 JSON: types, primary type, domain, message; never a digest) on `path` for
    /// `account` (a UA key or a native EVM key; an `msig` or a stored key: `Argument` here) and returns its review and typed
    /// digest; nothing is signed until [`AppPrepared::sign`] (T26 A-5, decision (125): the review is shown before the
    /// signature, from the parsed typed data, never the caller's text). Refused by name (§12.4): a SCaaS purpose, a SCaaS domain
    /// name, path A's field set or salt (`scaas-ua`); on path B a `chainId` other than the profile's or a `verifyingContract`
    /// that is the profile's registry, factory or router, a listed token or DEX (`AppDomainRefused`). A scope without `app_id`
    /// signs nothing under an app purpose (`Argument`).
    pub async fn prepare_app_record(
        self: &Arc<Self>,
        account: KeyRef,
        path: AppPath,
        typed_json: String,
    ) -> Result<AppPrepared, SdkError> {
        self.prepare_with(
            account,
            path,
            typed_json,
            scaas_ua::wallet::app_record_digest,
            scaas_ua::wallet::sign_app_record,
        )
        .await
    }

    /// Prepares the PqVault record `typed_json` (EIP-712 JSON, never a digest) on `path` for `account`, PqVault's dedicated path
    /// (owner 2026-11-22, CLI-PQV-12; `scaas-ua` `wallet::pqvault`), signed by [`AppPrepared::sign`] after its review (A-5): a
    /// scope of PqVault's `app_id`, a primary type and `encodeType` of PqVault's records (`Argument`), the domain `DS_V` on the
    /// portable path or `DS_B` on the chain-bound one under `P_V` (`purpose` none or `P_V`; `AppDomainRefused`), the profile's
    /// checks of a chain-bound domain as [`Self::prepare_app_record`]'s. The generic call refuses every PqVault record.
    /// `records`: the profile whose registry holds an `msig` signer's records on the portable path (controller call
    /// 2026-11-22, explicit parameters: required there, `Argument` without); on the chain-bound path the path's chain (`records`
    /// none or that chain); for a single key on the portable path none (`Argument` when given: nothing reads it).
    pub async fn prepare_pqvault_record(
        self: &Arc<Self>,
        account: KeyRef,
        path: AppPath,
        records: Option<String>,
        typed_json: String,
    ) -> Result<AppPrepared, SdkError> {
        let chain = match (&path, &account, records) {
            (AppPath::ChainBound { chain, .. }, _, r) if r.as_ref().is_none_or(|r| r == chain) => {
                Some(chain.clone())
            }
            (AppPath::Portable, KeyRef::Msig { .. }, Some(r)) => Some(r),
            (AppPath::Portable, KeyRef::Msig { .. }, None) => return Err(SdkError::Argument),
            (AppPath::Portable, _, None) => None,
            _ => return Err(SdkError::Argument),
        };
        if let (KeyRef::Msig { ua: msig_ua, slots }, Some(chain)) = (&account, chain) {
            // the `msig` `ua`: the chain-bound domain's profile checks here; at the signature its records read as the generic
            // `msig` path reads them (its structures, its `msig` members', their enabled and accepted bits: `MsigSlotInactive`)
            // on `chain`'s registry, the slots' keys opened (local keys only: a slot signed elsewhere or a stored key row
            // `Argument`), the registry generation's domain for a native member, then `scaas-ua`'s `pqvault::sign_msig` (its
            // refusals: the record, the path, a set not minimal, a disabled slot)
            let me = self.clone();
            let (ua_hex, slots) = (msig_ua.clone(), slots.clone());
            return self
                .sdk
                .clone()
                .spawn(async move {
                    let typed = TypedData::from_json(typed_json.as_bytes()).map_err(ua)?;
                    let (ua_path, _) = me.ua_path(&path, &typed, &account).await?;
                    let digest = scaas_ua::wallet::pqvault::digest(&ua_path, &typed).map_err(ua)?;
                    Ok(AppPrepared {
                        review: Self::review(&path, &typed),
                        digest: hex(&digest),
                        sdk: me.sdk.clone(),
                        ua_path,
                        typed,
                        how: How::Msig {
                            chain,
                            ua: hex32(&ua_hex)?,
                            slots,
                        },
                    })
                })
                .await;
        }
        self.prepare_with(
            account,
            path,
            typed_json,
            scaas_ua::wallet::pqvault::digest,
            scaas_ua::wallet::pqvault::sign,
        )
        .await
    }

    /// The entry under both prepare calls: `digest` states the record's typed digest after its refusals, `sign` signs it at
    /// [`AppPrepared::sign`].
    async fn prepare_with(
        self: &Arc<Self>,
        account: KeyRef,
        path: AppPath,
        typed_json: String,
        digest: fn(&UaPath, &TypedData) -> scaas_ua::wallet::Result<[u8; 32]>,
        sign: SignFn,
    ) -> Result<AppPrepared, SdkError> {
        let me = self.clone();
        self.sdk
            .clone()
            .spawn(async move {
                let typed = TypedData::from_json(typed_json.as_bytes()).map_err(ua)?;
                let (ua_path, registry) = me.ua_path(&path, &typed, &account).await?;
                let d = digest(&ua_path, &typed).map_err(ua)?;
                Ok(AppPrepared {
                    review: Self::review(&path, &typed),
                    digest: hex(&d),
                    sdk: me.sdk.clone(),
                    ua_path,
                    typed,
                    how: How::Key {
                        account,
                        registry,
                        sign,
                    },
                })
            })
            .await
    }
    /// The `scaas-ua` path of `path`, after the profile's checks of a chain-bound domain, and the registry's domain a native
    /// key signs `UAAuth` under.
    async fn ua_path(
        &self,
        path: &AppPath,
        typed: &TypedData,
        account: &KeyRef,
    ) -> Result<(UaPath, Option<scaas_ua::Domain>), SdkError> {
        let app_id = self.app_id.ok_or(SdkError::Argument)?;
        let (chain, purpose) = match path {
            AppPath::Portable => return Ok((UaPath::Portable { app_id }, None)),
            AppPath::ChainBound { chain, purpose } => (chain, purpose),
        };
        let purpose = match purpose {
            Some(p) => hex32(p)?,
            None => {
                scaas_ua::ua_portable::app_purpose(&app_id).map_err(|e| SdkError::Ua(e.into()))?
            }
        };
        let (profile, chain_id, pool) = crate::op::evm(&self.sdk, chain)?;
        let v = typed.to_value();
        let d = v
            .get("domain")
            .ok_or(SdkError::Ua(scaas_ua::wallet::Error::AppDomainRefused))?;
        let refused = SdkError::Ua(scaas_ua::wallet::Error::AppDomainRefused);
        let id = d.get("chainId").and_then(|c| {
            c.as_str()
                .map(str::to_string)
                .or_else(|| c.as_u64().map(|n| n.to_string()))
        });
        if id.as_deref() != Some(&chain_id.to_string()) {
            return Err(refused);
        }
        let vc = d
            .get("verifyingContract")
            .and_then(|c| c.as_str())
            .unwrap_or_default();
        self.refuse_contract(&profile, &pool, vc).await?;
        let registry = match account {
            // F2: a native signer's `UAAuth` is the bound registry's own, at its generation on the line
            KeyRef::Native { .. } => {
                let (_, line) = crate::line::read_line(
                    &self.sdk,
                    chain,
                    scaas_rpc::pool::BlockChoice::Latest,
                    Purpose::Plain,
                    |_, _, _| async { Ok(()) },
                )
                .await?;
                Some(line.domain(None, chain_id, hex32(&profile.chain_uid)?))
            }
            _ => None,
        };
        Ok((UaPath::ChainBound { purpose }, registry))
    }

    /// `AppDomainRefused` for a contract an app record or call may not name (spec §12.4): the profile's registry, factory or
    /// router, a listed token or DEX, or a contract the profile's factory made of a class other than `AppDesc.class` (its
    /// `infoOf` record read at the profile's final block; any class when the scope declares none). `Argument` for a malformed
    /// address. Depth only (T26 A-10): the guard is the purpose refusal below the SDK; a contract the factory did not make
    /// (class 0) or a profile without a factory passes this layer.
    async fn refuse_contract(
        &self,
        profile: &crate::ChainProfile,
        pool: &EvmPool,
        contract: &str,
    ) -> Result<(), SdkError> {
        let refused = SdkError::Ua(scaas_ua::wallet::Error::AppDomainRefused);
        let c = addr20(&contract.to_ascii_lowercase())?;
        let listed = [
            profile.registry.clone(),
            profile.factory.clone(),
            profile.router.clone(),
        ]
        .into_iter()
        .flatten()
        .chain(profile.tokens.iter().map(|t| t.address.clone()))
        .chain(profile.dexes.iter().map(|x| x.address.clone()))
        .any(|a| a.eq_ignore_ascii_case(contract));
        if listed {
            return Err(refused);
        }
        let Some(f) = profile.factory.as_deref() else {
            return Ok(());
        };
        let f = Address::from(addr20(&f.to_ascii_lowercase())?);
        let mut arg = [0u8; 32];
        arg[12..].copy_from_slice(&c);
        // T26 A-10: at the profile's final block, as every other read of this layer
        let data = Bytes::from([sel("infoOf(address)"), arg.to_vec()].concat());
        let out = pool
            .read_at_block(final_block(profile), Purpose::Plain, |at| {
                let d = data.clone();
                async move { pool.call_at(&at, f, d).await.map(|b| b.to_vec()) }
            })
            .await?
            .value;
        // `Created(address addr, bytes32 creatorId, uint16 contractClass, …)`: a static tuple, the class in word 2
        let class = small(&out, 64, u64::from(u16::MAX)).ok_or(SdkError::Argument)?;
        if class != 0 && Some(class) != self.class.map(usize::from) {
            return Err(refused);
        }
        Ok(())
    }

    /// `key` wrapped to `recipient`'s KEM key at `kem_version` (spec §12.2, review K5): `kemKeyAt(recipient, kem_version)` read
    /// from the profile's registry at the profile's final block as a read that feeds a decryption (`Purpose::FeedsDecryption`,
    /// ARCH-POS-15: a discovered node only under the majority option with at least three nodes), bounded; scheme 1 only
    /// (`KemCheck`); the KDF info's scheme byte and `keccak256(kemPk)` built below the SDK from that key, never the caller's.
    pub async fn kem_wrap(
        self: &Arc<Self>,
        chain: String,
        recipient: String,
        kem_version: u64,
        key: Arc<AppKey>,
        label: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<AppWrap, SdkError> {
        self.label(&label)?;
        let kem_pk = self
            .kem_pk_at(&chain, hex32(&recipient)?, kem_version)
            .await?;
        self.kem_wrap_to_key(kem_pk, key, label, aad)
    }

    /// `kemKeyAt(ua, version)` of the profile's registry on `chain` as the KEM key `scheme ‖ ek ‖ x25519`, read at the final
    /// block as a read that feeds a decryption, bounded; scheme 1 only (`KemCheck`).
    pub(crate) async fn kem_pk_at(
        &self,
        chain: &str,
        ua: [u8; 32],
        version: u64,
    ) -> Result<Vec<u8>, SdkError> {
        let (profile, _, _) = crate::op::evm(&self.sdk, chain)?;
        let mut v = [0u8; 32];
        v[24..].copy_from_slice(&version.to_be_bytes());
        // F2: read at the generation that holds `ua` (an unregistered one at the bound registry, which answers none)
        let (out, _) = crate::line::read_line(
            &self.sdk,
            chain,
            final_block(&profile),
            Purpose::FeedsDecryption,
            |pool, at, line| async move {
                let to = line.holder(&pool, &at, ua).await?.unwrap_or(line.bound());
                call_at(&pool, &at, to, "kemKeyAt(bytes32,uint64)", &[ua, v]).await
            },
        )
        .await?;
        kem_pk_of(&out)
    }

    /// The UA of `account` (a UA key; any other: `Argument`): the id `scaas-ua` derives, no read.
    pub fn account_ua(&self, account: &KeyRef) -> Result<[u8; 32], SdkError> {
        let KeyRef::Ua {
            seed,
            kind,
            account,
            index,
        } = account
        else {
            return Err(SdkError::Argument);
        };
        let open = self.sdk.open_seed(seed)?;
        open.wallet
            .ua_key(*kind, *account, *index)
            .map_err(ua)?
            .ua()
            .ok_or(SdkError::Argument)
    }

    /// Whether `sig` is `ua`'s signature of the app record `typed_json` on `path`, as the profile's registry on `chain` judges
    /// it (spec §12.2, review r2 R7; `scaas-ua` `verify_app_record`): every kind, an `msig` down to its members (two levels),
    /// each key checked against its id; a native signer's `UAAuth` in the registry generation's domain. The records are read
    /// at the profile's final block as a read that feeds a decryption. A path-B `chain` other than `chain`: `Argument`. Not
    /// checked here (false): a native id with code (ERC-1271), a native kind other than `evm-eoa`, a record held by an
    /// earlier registry generation.
    pub async fn verify_app_record(
        self: &Arc<Self>,
        chain: String,
        ua: String,
        path: AppPath,
        typed_json: String,
        sig: AppUaSig,
    ) -> Result<bool, SdkError> {
        self.verify_with(
            chain,
            ua,
            path,
            typed_json,
            sig,
            scaas_ua::wallet::verify_app_record,
        )
        .await
    }

    /// Whether `sig` is `ua`'s signature of the PqVault record `typed_json` on `path`, PqVault's dedicated path (owner
    /// 2026-11-22; `scaas-ua` `wallet::pqvault::verify`): its refusals as [`Self::sign_pqvault_record`]'s (a refused record:
    /// `false`), then the registry's judgement as [`Self::verify_app_record`]'s.
    pub async fn verify_pqvault_record(
        self: &Arc<Self>,
        chain: String,
        ua: String,
        path: AppPath,
        typed_json: String,
        sig: AppUaSig,
    ) -> Result<bool, SdkError> {
        self.verify_with(
            chain,
            ua,
            path,
            typed_json,
            sig,
            scaas_ua::wallet::pqvault::verify,
        )
        .await
    }

    /// The entry under both verifying calls: `f` judges the record on the registry state read.
    #[allow(clippy::too_many_arguments)]
    async fn verify_with(
        self: &Arc<Self>,
        chain: String,
        ua: String,
        path: AppPath,
        typed_json: String,
        sig: AppUaSig,
        f: fn(&[u8; 32], &UaPath, &TypedData, &UASig, &AppRecordState) -> bool,
    ) -> Result<bool, SdkError> {
        let id = hex32(&ua)?;
        let typed = TypedData::from_json(typed_json.as_bytes()).map_err(SdkError::Ua)?;
        let p = match &path {
            AppPath::Portable => UaPath::Portable {
                app_id: self.app_id.ok_or(SdkError::Argument)?,
            },
            AppPath::ChainBound { chain: c, purpose } => {
                if *c != chain {
                    return Err(SdkError::Argument);
                }
                UaPath::ChainBound {
                    purpose: match purpose {
                        Some(p) => hex32(p)?,
                        None => scaas_ua::ua_portable::app_purpose(
                            &self.app_id.ok_or(SdkError::Argument)?,
                        )
                        .map_err(|e| SdkError::Ua(e.into()))?,
                    },
                }
            }
        };
        let chain_bound = matches!(p, UaPath::ChainBound { .. });
        self.with_records(&chain, id, chain_bound, |state| {
            f(&id, &p, &typed, &UASig::from(&sig), state)
        })
        .await
    }

    /// `f` over the registry state of `id` on `chain` (its records, its members' and theirs, two levels), read at the
    /// profile's final block as a read that feeds a decryption; with `chain_bound`, the registry's domain too when `id` is a
    /// native id or an `msig` (a native member signs `UAAuth` in it).
    pub(crate) async fn with_records<R>(
        &self,
        chain: &str,
        id: [u8; 32],
        chain_bound: bool,
        f: impl FnOnce(&AppRecordState) -> R,
    ) -> Result<R, SdkError> {
        let (profile, chain_id, _) = crate::op::evm(&self.sdk, chain)?;
        // F2: the records and the domain from one line, one endpoint, one block
        let ((recs, holder), line) = crate::line::read_line(
            &self.sdk,
            chain,
            final_block(&profile),
            Purpose::FeedsDecryption,
            |pool, at, line| async move {
                let recs = records(&pool, &at, &line, id).await?;
                Ok((recs, line.holder(&pool, &at, id).await?))
            },
        )
        .await?;
        let needs_domain = chain_bound
            && (scaas_ua::in_native_space(&id) || recs.get(&id).is_some_and(|r| r.kind == MSIG));
        // a native id's key signs in the bound registry's domain, an `msig`'s native members in its holder's
        let domain = needs_domain
            .then(|| -> Result<_, SdkError> {
                Ok(line.domain(holder, chain_id, hex32(&profile.chain_uid)?))
            })
            .transpose()?;
        let members = |x: [u8; 32]| recs.get(&x).map(|r| (r.kind, r.key_data.clone()));
        let current = |x: [u8; 32]| recs.get(&x).and_then(|r| r.current.clone());
        let accepted = |x: [u8; 32], i: u16| recs.get(&x).is_some_and(|r| bit(&r.active, i));
        Ok(f(&AppRecordState {
            members: &members,
            current: &current,
            accepted: &accepted,
            domain: domain.as_ref(),
        }))
    }

    /// A call of the app's own contract `contract` on `chain` (spec §12.2, §13): `entry` the function's JSON ABI item as solc
    /// writes it (its parameters and every tuple component named), `args` a JSON object of exactly those names (a signed record
    /// as its `UASig` fields `keyData`, `signature`, `members`; a tuple as an object of its components' names), paid by `payer` (a native EVM key; fee 0 allowed by the contract: anyone
    /// submits a signed record), quoted and reviewed (the entry, the contract, each argument). `AppDomainRefused` for a
    /// contract an app may not call (`refuse_contract`: a SCaaS contract of the profile, a factory instance of another
    /// class); `Argument` for an entry that does not parse or arguments that are not its names and types.
    pub async fn prepare_app_call(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
        payer: KeyRef,
    ) -> Result<AppCall, SdkError> {
        let (f, o, data) = entry_call(&entry, &args)?;
        let mut review = vec![
            field("contract", contract.to_ascii_lowercase(), Source::Derived),
            field("entry", f.signature(), Source::Derived),
        ];
        for p in &f.inputs {
            let v = o.get(&p.name).ok_or(SdkError::Argument)?;
            flatten(&format!("args.{}", p.name), v, &mut review);
        }
        let (profile, _, pool) = crate::op::evm(&self.sdk, &chain)?;
        self.refuse_contract(&profile, &pool, &contract).await?;
        let quote = self
            .sdk
            .wallet()
            .prepare_native_send(crate::wallet::NativeSend {
                key: payer,
                chain,
                to: contract,
                value: "0".into(),
                data: Some(hex(&data)),
                tx_type: None,
            })
            .await?;
        Ok(AppCall { review, quote })
    }

    /// Whether `ua`'s single key (`kind`, `key_data`, read by the caller from the UA's record) signs `typed_json` on `path`.
    pub fn verify_app_record_key(
        &self,
        kind: u16,
        key_data: Vec<u8>,
        path: AppPath,
        purpose: Option<String>,
        typed_json: String,
        signature: Vec<u8>,
    ) -> Result<bool, SdkError> {
        let typed = TypedData::from_json(typed_json.as_bytes()).map_err(ua)?;
        let p = match path {
            AppPath::Portable => UaPath::Portable {
                app_id: self.app_id.ok_or(SdkError::Argument)?,
            },
            AppPath::ChainBound { .. } => UaPath::ChainBound {
                purpose: match purpose {
                    Some(p) => hex32(&p)?,
                    None => {
                        scaas_ua::ua_portable::app_purpose(&self.app_id.ok_or(SdkError::Argument)?)
                            .map_err(|e| SdkError::Ua(e.into()))?
                    }
                },
            },
        };
        Ok(scaas_ua::wallet::verify_app_record_key(
            kind, &key_data, &p, &typed, &signature,
        ))
    }
}

pub(crate) fn field(name: &str, value: String, source: Source) -> ReviewField {
    ReviewField {
        name: name.to_string(),
        display: value.clone(),
        value,
        source,
    }
}

pub(crate) fn flatten(prefix: &str, v: &serde_json::Value, out: &mut Vec<ReviewField>) {
    flatten_as(prefix, v, Source::Signed, out);
}

/// [`flatten`] with the fields' source.
pub(crate) fn flatten_as(
    prefix: &str,
    v: &serde_json::Value,
    source: Source,
    out: &mut Vec<ReviewField>,
) {
    match v {
        serde_json::Value::Object(o) => {
            for (k, x) in o {
                flatten_as(&format!("{prefix}.{k}"), x, source, out);
            }
        }
        serde_json::Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                flatten_as(&format!("{prefix}[{i}]"), x, source, out);
            }
        }
        serde_json::Value::String(s) => out.push(field(prefix, s.clone(), source)),
        other => out.push(field(prefix, other.to_string(), source)),
    }
}

impl AppCore {
    /// A view of an app's contract (or a SCaaS view an app reads, a registry's `kemKeyOf`, a factory listing): `entry` the
    /// function's JSON ABI item (`view` or `pure`, its parameters named; `Argument` otherwise), `args` a JSON object of exactly
    /// its parameter names (as [`AppCore::prepare_app_call`]), read at the profile's final block. Bounded: the entry 64 KiB,
    /// the arguments 128 KiB, the answer 1 MiB, an output type nesting at most 16 levels (`Argument`). Always a read that
    /// feeds a decryption (`Purpose::FeedsDecryption`, ARCH-POS-15: a discovered node only under the majority option with at
    /// least three nodes; T26 B-17: the fail-closed default, never a caller's flag); [`Self::read_app_plain`] for a read
    /// that never feeds one. The answer: a JSON object of the outputs by name (an unnamed one by its index), tuples by their
    /// components' names, integers as decimal strings, bytes, addresses and fixed bytes as `0x` hex.
    pub async fn read_app(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
    ) -> Result<String, SdkError> {
        self.read_app_as(chain, contract, entry, args, Purpose::FeedsDecryption)
            .await
    }

    /// [`Self::read_app`] as a plain read (`Purpose::Plain`): its answer never feeds a decryption (T26 B-17).
    pub async fn read_app_plain(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
    ) -> Result<String, SdkError> {
        self.read_app_as(chain, contract, entry, args, Purpose::Plain)
            .await
    }

    async fn read_app_as(
        self: &Arc<Self>,
        chain: String,
        contract: String,
        entry: String,
        args: String,
        purpose: Purpose,
    ) -> Result<String, SdkError> {
        use alloy::dyn_abi::FunctionExt;
        use alloy::json_abi::StateMutability;
        let (f, _, data) = entry_call(&entry, &args)?;
        if !matches!(
            f.state_mutability,
            StateMutability::View | StateMutability::Pure
        ) || f
            .outputs
            .iter()
            .any(|p| type_depth(&p.ty, &p.components) > READ_DEPTH)
        {
            return Err(SdkError::Argument);
        }
        let to = Address::from(addr20(&contract.to_ascii_lowercase())?);
        let (profile, _, pool) = crate::op::evm(&self.sdk, &chain)?;

        let (pool, data) = (&pool, Bytes::from(data));
        let out = pool
            .read_at_block(final_block(&profile), purpose, |at| {
                let d = data.clone();
                async move { pool.call_at(&at, to, d).await.map(|b| b.to_vec()) }
            })
            .await?
            .value;
        if out.len() > READ_MAX {
            return Err(SdkError::Argument);
        }
        let values = f.abi_decode_output(&out).map_err(|_| SdkError::Argument)?;
        let mut o = serde_json::Map::new();
        for (i, (v, p)) in values.iter().zip(&f.outputs).enumerate() {
            let k = if p.name.is_empty() {
                i.to_string()
            } else {
                p.name.clone()
            };
            o.insert(k, named(v, &p.components)?);
        }
        Ok(serde_json::Value::Object(o).to_string())
    }
}

/// Test-only entry points (feature `vectors`, never in a release build nor a binding): key bytes in and out and fixed
/// randomness, for the vectors.
#[cfg(feature = "vectors")]
impl AppCore {
    /// A handle of `usage` holding `key` (a vector's input), in `seed`'s arena.
    pub fn vectors_import(
        &self,
        seed: &str,
        key: [u8; 32],
        usage: AppKeyUsage,
    ) -> Result<Arc<AppKey>, SdkError> {
        let h = self
            .scope(seed)?
            .vectors_import(&key, usage.into())
            .map_err(ua)?;
        Ok(self.wrap(seed, h))
    }

    /// The handle's key bytes (a vector's comparison).
    pub fn vectors_reveal(&self, key: Arc<AppKey>) -> Result<Vec<u8>, SdkError> {
        self.with(&[&key], |s, hs| s.vectors_reveal(at(hs, 0)?).map_err(ua))
    }

    /// [`AppCore::kem_wrap_to_key`] with fixed `m` and X25519 ephemeral secret `e`.
    pub fn vectors_kem_wrap(
        &self,
        key: Arc<AppKey>,
        kem_pk: Vec<u8>,
        label: Vec<u8>,
        aad: Vec<u8>,
        m: [u8; 32],
        e: [u8; 32],
    ) -> Result<AppWrap, SdkError> {
        self.label(&label)?;
        let w = self.with(&[&key], |s, hs| {
            s.vectors_kem_wrap(at(hs, 0)?, &label, &aad, &kem_pk, &m, &e)
                .map_err(ua)
        })?;
        Ok(AppWrap {
            mlkem_ct: w.mlkem_ct,
            x25519_eph: w.x25519_eph.to_vec(),
            sealed_key: w.sealed_key,
        })
    }

    /// [`AppCore::kem_unwrap`] by a vector's KEM key (`mlkemSeed ‖ x25519Secret`, 96 bytes) into `seed`'s arena.
    pub fn vectors_kem_unwrap(
        &self,
        seed: &str,
        kem_seed: Vec<u8>,
        wrap: AppWrap,
        label: Vec<u8>,
        aad: Vec<u8>,
        usage: AppKeyUsage,
    ) -> Result<Arc<AppKey>, SdkError> {
        self.label(&label)?;
        let ks: [u8; 96] = kem_seed.try_into().map_err(|_| SdkError::Argument)?;
        let kem = scaas_ua::wallet::KemKeyPair::vectors_ephemeral(&ks).map_err(ua)?;
        let w = KemWrap {
            mlkem_ct: wrap.mlkem_ct,
            x25519_eph: wrap.x25519_eph.try_into().map_err(|_| SdkError::Argument)?,
            sealed_key: wrap.sealed_key,
        };
        let h = self
            .scope(seed)?
            .kem_unwrap(&kem, &w, &label, &aad, usage.into())
            .map_err(ua)?;
        Ok(self.wrap(seed, h))
    }

    /// [`AppCore::seal_key`] with a fixed nonce.
    pub fn vectors_seal_key(
        &self,
        under: Arc<AppKey>,
        key: Arc<AppKey>,
        nonce: [u8; 12],
        aad: Vec<u8>,
    ) -> Result<Vec<u8>, SdkError> {
        self.with(&[&under, &key], |s, hs| {
            s.vectors_seal_key(at(hs, 0)?, at(hs, 1)?, &nonce, &aad)
                .map_err(ua)
        })
    }

    /// [`AppCore::seal`] with a fixed nonce, the nonce not in the output.
    pub fn vectors_seal(
        &self,
        key: Arc<AppKey>,
        nonce: [u8; 12],
        aad: Vec<u8>,
        pt: Vec<u8>,
    ) -> Result<Vec<u8>, SdkError> {
        self.with(&[&key], |s, hs| {
            s.vectors_seal(at(hs, 0)?, &nonce, &aad, &pt).map_err(ua)
        })
    }
}
