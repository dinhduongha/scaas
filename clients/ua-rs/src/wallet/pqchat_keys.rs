// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! PqChat's key entries on app-core handles (pqchat-core spec §5 K2–K6, S1 / S2's sealing, S5, V2; its §13 O3 (b); feature
//! `app-core`): the epoch key `K` and every key derived from it stay behind [`KeyHandle`]s; out come public bytes (wraps, the
//! hint, ciphertexts, envelopes, payloads) and the plaintexts a reader asks to open. Byte formats: UA-7 §4.2, §6.2–§6.5, P15,
//! P25, P29 as clientkeys `src/pqchat.js` writes them, `smartcontracts/vectors/pqchat/`.
//!
//! - **K2** [`AppKeys::pqchat_wrap`] / [`AppKeys::pqchat_unwrap`]: the label `scaas/pqchat/v1/wrap`, `aad = sessionId ‖ epochId ‖
//!   member ‖ be64(keyId)`, the KEK's info `label ‖ aad ‖ 0x01 ‖ keccak256(kemPk)` built below (`appkey`), P14's checks
//!   (`KemCheck`).
//! - **K3** [`AppKeys::pqchat_chain`] gives `ck_0` as a chain position; [`AppKeys::pqchat_advance`] walks `n ≤` [`WALK_MAX`]
//!   steps in one call (`PqChatTooFar` past it, CLI-PQC-14). A position records its chain and counter; only a position of
//!   this scope advances, seals or opens, and the public MAC refuses it (spec §5.3 items 2, 3).
//! - **K4** [`AppKeys::pqchat_open_envelope`] (`k_env`, the GCM-SIV open, the bounded decode: public fields) and
//!   [`AppKeys::pqchat_open_message`] (`mk`, `n`, the GCM-SIV open with the §6.4 AAD, `unpad`, the canonical check by
//!   re-serialising and comparing: `PqChatContent`).
//! - **K5** [`AppKeys::pqchat_open_info`], **S1 / S2's seal** [`AppKeys::pqchat_seal_info`]; **K6** [`AppKeys::pqchat_hint`].
//! - **S5** [`AppKeys::pqchat_seal_message`]: canonicalise and pad the content, encrypt at the position's counter, sign
//!   `PqChatMessage` ([`pqchat::sign`]: a single UA key), build `abi.encode(PqChatMessage, UASig)`, seal the envelope under a
//!   random nonce, the payload `abi.encode(uint8 1, bytes8 hint, bytes env)`. No entry takes a digest or a caller's ciphertext.
//! - **V2** [`decode_inner`], [`decode_payload`]: bounded by length and by the type's fixed depth.
//!
//! No skipped key is kept anywhere: a reader walks from the nearest position it holds. UNAUDITED.
use super::aead::{aead_open, aead_seal, hkdf_sha256, hmac_sha256, Alg};
use super::appkey::{rng, AppKeys, KemWrap, KeyHandle, KeyUsage, Origin};
use super::kem::KemKeyPair;
use super::pqchat;
use super::signer::Signer;
use super::{Error, Result};
use crate::keccak256;
use crate::ua_portable::{InnerSig, MemberSig, UASig};
use serde_json::{json, Value};
use zeroize::Zeroizing;

/// PqChat's label prefix (spec §5.2).
pub const PREFIX: &str = "scaas/pqchat/v1/";
pub const WRAP: &[u8] = b"scaas/pqchat/v1/wrap";
pub const CHAIN: &[u8] = b"scaas/pqchat/v1/chain";
pub const ENV: &[u8] = b"scaas/pqchat/v1/env";
pub const INFO: &[u8] = b"scaas/pqchat/v1/info";
pub const HINT: &[u8] = b"scaas/pqchat/v1/hint";
/// CLI-PQC-14: the most steps one walk takes from a held position.
pub const WALK_MAX: u64 = 1 << 20;
/// The largest padded plaintext opened or sealed here (a Matrix event's 65,536 B bound).
pub const PT_MAX: usize = 65_536;
/// The deepest a content value or `sealedInfo` JSON nests.
pub const JSON_DEPTH: usize = 16;
/// The most parents a message names (UA-7 §6.4: at most 8).
pub const PARENTS_MAX: usize = 8;
/// The most `UASig` members (and inner members) a decoded signature holds.
const MEMBERS_MAX: usize = 16;
const BUCKETS: [usize; 4] = [256, 1024, 4096, 16384];

/// A message's header: the `PqChatMessage` fields but its ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub session_id: [u8; 32],
    pub epoch_id: [u8; 32],
    pub sender: [u8; 32],
    pub device: [u8; 16],
    pub counter: u64,
    pub parents: Vec<[u8; 32]>,
}

/// A message sealed and signed (S5): the record's fields, its signature and id, the envelope's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedMessage {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub sig: UASig,
    /// `typed(PqChatMessage)`
    pub message_id: [u8; 32],
    /// `abi.encode(PqChatMessage, UASig)`: what `postMessage` takes
    pub inner: Vec<u8>,
    pub hint: [u8; 8],
    /// `nonce ‖ AES-256-GCM-SIV(k_env, nonce, inner)`
    pub env: Vec<u8>,
    /// `abi.encode(uint8 1, bytes8 hint, bytes env)`
    pub payload: Vec<u8>,
}

/// An envelope opened (public fields): the record and its signature, not yet checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Inner {
    pub header: Header,
    pub ciphertext: Vec<u8>,
    pub sig: UASig,
}

impl Header {
    /// The record as typed-data JSON (`0x` hex), with `ciphertext`.
    pub fn record(&self, ciphertext: &[u8]) -> Value {
        json!({
            "sessionId": hex(&self.session_id), "epochId": hex(&self.epoch_id), "sender": hex(&self.sender),
            "device": hex(&self.device), "counter": self.counter,
            "parents": self.parents.iter().map(|p| hex(p)).collect::<Vec<_>>(), "ciphertext": hex(ciphertext),
        })
    }

    fn check(&self) -> Result<()> {
        let sorted = self
            .parents
            .iter()
            .zip(self.parents.iter().skip(1))
            .all(|(a, b)| a < b);
        if self.parents.len() > PARENTS_MAX || !sorted {
            return Err(Error::Argument);
        }
        Ok(())
    }
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(2 + 2 * b.len());
    s.push_str("0x");
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn word(v: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&v.to_be_bytes());
    w
}

fn be64(v: u64) -> [u8; 8] {
    v.to_be_bytes()
}

// ------------------------------------------------------------------ canonical JSON and padding (UA-7 §6.5, 3C-D9)

/// Canonical JSON (clientkeys `canonicalJson`): object keys sorted by UTF-16 code units, no whitespace, `JSON.stringify`'s
/// escapes; a number other than an integer within ±(2^53 − 1) is `PqChatContent`.
pub fn canonical_json(v: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(v, &mut out)?;
    Ok(out)
}

fn write_canonical(v: &Value, out: &mut String) -> Result<()> {
    const SAFE: u64 = (1 << 53) - 1;
    match v {
        Value::Null | Value::Bool(_) => out.push_str(&v.to_string()),
        Value::Number(n) => {
            let ok = n.as_u64().is_some_and(|x| x <= SAFE)
                || n.as_i64().is_some_and(|x| x.unsigned_abs() <= SAFE);
            if !ok {
                return Err(Error::PqChatContent);
            }
            out.push_str(&n.to_string());
        }
        Value::String(s) => out.push_str(&Value::String(s.clone()).to_string()),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(x, out)?;
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String((*k).clone()).to_string());
                out.push(':');
                write_canonical(&o[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical JSON of the JSON text `text` (bounded: [`PT_MAX`] bytes, [`JSON_DEPTH`]), in memory wiped on drop (a
/// content may carry a file key); the parsed value wiped too.
fn canonical_of_text(text: &[u8]) -> Result<Zeroizing<String>> {
    let mut v = super::bounded::json(text, PT_MAX, JSON_DEPTH).map_err(|_| Error::PqChatContent)?;
    let c = canonical_zeroizing(&v, text.len());
    super::bounded::wipe(&mut v);
    c
}

/// [`canonical_json`] of `v` into a buffer of `cap` bytes reserved up front (no reallocation leaves a copy behind for a
/// canonical form within it), wiped on drop.
pub(super) fn canonical_zeroizing(v: &Value, cap: usize) -> Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::with_capacity(cap.saturating_add(64)));
    write_canonical(v, &mut out)?;
    Ok(out)
}

/// `u32be(len) ‖ content ‖ zeros` to the smallest of 256, 1,024, 4,096, 16,384 B, then multiples of 16,384 B; above
/// [`PT_MAX`] `Argument`.
pub fn pad(content: &[u8]) -> Result<Vec<u8>> {
    let need = 4 + content.len();
    let size = BUCKETS
        .iter()
        .copied()
        .find(|b| *b >= need)
        .unwrap_or(need.div_ceil(16384) * 16384);
    if size > PT_MAX {
        return Err(Error::Argument);
    }
    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(&(content.len() as u32).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(size, 0);
    Ok(out)
}

/// The content of a padded text: anything [`pad`] would not write is `PqChatContent` (a non-zero fill, a wrong bucket, a
/// length past the end).
pub fn unpad(pt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let n = pt
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_be_bytes)
        .ok_or(Error::PqChatContent)? as usize;
    let c = pt
        .get(4..)
        .and_then(|r| r.get(..n))
        .ok_or(Error::PqChatContent)?;
    let again = Zeroizing::new(pad(c).map_err(|_| Error::PqChatContent)?);
    if *again != pt {
        return Err(Error::PqChatContent);
    }
    Ok(Zeroizing::new(c.to_vec()))
}

// ------------------------------------------------------------------ ABI forms (§6.4, P15, P25, 3C-D3)

/// §6.4: `abi.encode(sessionId, epochId, sender, bytes16 device, uint64 counter, keccak256(abi.encode(bytes32[] parents)))`.
pub fn message_aad(h: &Header) -> Vec<u8> {
    let mut dev = [0u8; 32];
    dev[..16].copy_from_slice(&h.device);
    [
        h.session_id,
        h.epoch_id,
        h.sender,
        dev,
        word(h.counter),
        keccak256(&parents_abi(&h.parents)),
    ]
    .concat()
}

/// `abi.encode(bytes32[] parents)`.
fn parents_abi(p: &[[u8; 32]]) -> Vec<u8> {
    [word(32).to_vec(), list_words(p)].concat()
}

fn list_words(p: &[[u8; 32]]) -> Vec<u8> {
    [word(p.len() as u64).to_vec(), p.concat()].concat()
}

fn abi_bytes(b: &[u8]) -> Vec<u8> {
    let mut o = word(b.len() as u64).to_vec();
    o.extend_from_slice(b);
    o.resize(o.len() + b.len().next_multiple_of(32) - b.len(), 0);
    o
}

/// The tail of a dynamic array of dynamic items: length, offsets, items.
fn abi_list(items: Vec<Vec<u8>>) -> Vec<u8> {
    let mut o = word(items.len() as u64).to_vec();
    let mut off = 32 * items.len();
    for t in &items {
        o.extend(word(off as u64));
        off += t.len();
    }
    o.extend(items.concat());
    o
}

/// The tuple `UASig = (bytes keyData, bytes signature, (uint16, (uint16, bytes)[], bytes)[] members)`, as a tail.
fn uasig_abi(s: &UASig) -> Vec<u8> {
    let inner = |i: &InnerSig| {
        [
            word(i.index as u64).to_vec(),
            word(64).to_vec(),
            abi_bytes(&i.sig),
        ]
        .concat()
    };
    let slot = |m: &MemberSig| {
        let list = abi_list(m.members.iter().map(inner).collect());
        [
            word(m.index as u64).to_vec(),
            word(96).to_vec(),
            word(96 + list.len() as u64).to_vec(),
            list,
            abi_bytes(&m.sig),
        ]
        .concat()
    };
    let (kd, sg) = (abi_bytes(&s.key_data), abi_bytes(&s.signature));
    let ms = abi_list(s.members.iter().map(slot).collect());
    [
        word(96).to_vec(),
        word(96 + kd.len() as u64).to_vec(),
        word((96 + kd.len() + sg.len()) as u64).to_vec(),
        kd,
        sg,
        ms,
    ]
    .concat()
}

/// `sigHash = keccak256(abi.encode(UASig))`.
pub fn sig_hash(s: &UASig) -> [u8; 32] {
    keccak256(&[word(32).to_vec(), uasig_abi(s)].concat())
}

/// `abi.encode(PqChatMessage, UASig)`.
pub fn encode_inner(h: &Header, ciphertext: &[u8], sig: &UASig) -> Vec<u8> {
    let mut dev = [0u8; 32];
    dev[..16].copy_from_slice(&h.device);
    let pl = list_words(&h.parents);
    let ct = abi_bytes(ciphertext);
    let head = 7 * 32;
    let msg = [
        h.session_id.to_vec(),
        h.epoch_id.to_vec(),
        h.sender.to_vec(),
        dev.to_vec(),
        word(h.counter).to_vec(),
        word(head as u64).to_vec(),
        word((head + pl.len()) as u64).to_vec(),
        pl,
        ct,
    ]
    .concat();
    let sig = uasig_abi(sig);
    [
        word(64).to_vec(),
        word(64 + msg.len() as u64).to_vec(),
        msg,
        sig,
    ]
    .concat()
}

/// P25 / P29: `abi.encode(uint8 1, bytes8 hint, bytes env)`.
pub fn encode_payload(hint: &[u8; 8], env: &[u8]) -> Vec<u8> {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(hint);
    [
        word(1).to_vec(),
        h.to_vec(),
        word(96).to_vec(),
        abi_bytes(env),
    ]
    .concat()
}

/// A bounded ABI reader over one buffer: every offset and length checked against the buffer, nothing read past it.
struct Abi<'a> {
    b: &'a [u8],
}

impl<'a> Abi<'a> {
    fn word(&self, at: usize) -> Result<&'a [u8; 32]> {
        self.b
            .get(at..at.checked_add(32).ok_or(Error::Argument)?)
            .and_then(|w| w.try_into().ok())
            .ok_or(Error::Argument)
    }
    /// A word holding a number below `max`.
    fn num(&self, at: usize, max: u64) -> Result<usize> {
        let w = self.word(at)?;
        if w[..24].iter().any(|x| *x != 0) {
            return Err(Error::Argument);
        }
        let v = u64::from_be_bytes(w[24..].try_into().map_err(|_| Error::Argument)?);
        if v > max {
            return Err(Error::Argument);
        }
        usize::try_from(v).map_err(|_| Error::Argument)
    }
    /// The start of a dynamic part at the offset stored at `at`, relative to `base`.
    fn tail(&self, base: usize, at: usize) -> Result<usize> {
        let off = self.num(at, self.b.len() as u64)?;
        base.checked_add(off).ok_or(Error::Argument)
    }
    fn bytes(&self, at: usize, max: usize) -> Result<Vec<u8>> {
        let n = self.num(at, max as u64)?;
        let s = at + 32;
        let padded = n.next_multiple_of(32);
        let all = self
            .b
            .get(s..s.checked_add(padded).ok_or(Error::Argument)?)
            .ok_or(Error::Argument)?;
        let (body, fill) = all.split_at(n);
        if fill.iter().any(|x| *x != 0) {
            return Err(Error::Argument);
        }
        Ok(body.to_vec())
    }
    fn u16w(&self, at: usize) -> Result<u16> {
        u16::try_from(self.num(at, u16::MAX as u64)?).map_err(|_| Error::Argument)
    }
}

/// V2: an envelope's inner bytes `abi.encode(PqChatMessage, UASig)` into named fields; bounded by `b`'s length, at most
/// [`PARENTS_MAX`] parents, [`MEMBERS_MAX`] members per level, two levels (the type's own depth); anything else `Argument`.
pub fn decode_inner(b: &[u8]) -> Result<Inner> {
    if b.len() > PT_MAX {
        return Err(Error::Argument);
    }
    let a = Abi { b };
    let m = a.tail(0, 0)?;
    let s = a.tail(0, 32)?;
    let w32 = |at: usize| -> Result<[u8; 32]> { Ok(*a.word(at)?) };
    let dev = a.word(m + 96)?;
    if dev[16..].iter().any(|x| *x != 0) {
        return Err(Error::Argument);
    }
    let counter = u64::try_from(a.num(m + 128, u64::MAX)?).map_err(|_| Error::Argument)?;
    let p = a.tail(m, m + 160)?;
    let np = a.num(p, PARENTS_MAX as u64)?;
    let parents = (0..np)
        .map(|i| w32(p + 32 + 32 * i))
        .collect::<Result<Vec<_>>>()?;
    let ct = a.bytes(a.tail(m, m + 192)?, PT_MAX)?;
    let header = Header {
        session_id: w32(m)?,
        epoch_id: w32(m + 32)?,
        sender: w32(m + 64)?,
        device: dev[..16].try_into().map_err(|_| Error::Argument)?,
        counter,
        parents,
    };
    let sig = decode_uasig(&a, s)?;
    // the canonical form only: a re-encoding equal to the input (no trailing bytes, no aliasing offsets)
    let out = Inner {
        header,
        ciphertext: ct,
        sig,
    };
    if encode_inner(&out.header, &out.ciphertext, &out.sig) != b {
        return Err(Error::Argument);
    }
    Ok(out)
}

fn decode_uasig(a: &Abi, s: usize) -> Result<UASig> {
    let key_data = a.bytes(a.tail(s, s)?, PT_MAX)?;
    let signature = a.bytes(a.tail(s, s + 32)?, PT_MAX)?;
    let ml = a.tail(s, s + 64)?;
    let n = a.num(ml, MEMBERS_MAX as u64)?;
    let mut members = Vec::with_capacity(n);
    for i in 0..n {
        let t = a.tail(ml + 32, ml + 32 + 32 * i)?;
        let il = a.tail(t, t + 32)?;
        let k = a.num(il, MEMBERS_MAX as u64)?;
        let mut inner = Vec::with_capacity(k);
        for j in 0..k {
            let u = a.tail(il + 32, il + 32 + 32 * j)?;
            inner.push(InnerSig {
                index: a.u16w(u)?,
                sig: a.bytes(a.tail(u, u + 32)?, PT_MAX)?,
            });
        }
        members.push(MemberSig {
            index: a.u16w(t)?,
            members: inner,
            sig: a.bytes(a.tail(t, t + 64)?, PT_MAX)?,
        });
    }
    Ok(UASig {
        key_data,
        signature,
        members,
    })
}

/// V2: a stored payload `abi.encode(uint8 v, bytes8 hint, bytes env)`: `v == 1`, the canonical form only, `env` non-empty,
/// at most [`PT_MAX`] + 12 + 16 bytes; else `Argument`.
pub fn decode_payload(b: &[u8]) -> Result<([u8; 8], Vec<u8>)> {
    let a = Abi { b };
    if a.num(0, 1)? != 1 {
        return Err(Error::Argument);
    }
    let h = a.word(32)?;
    let hint: [u8; 8] = h[..8].try_into().map_err(|_| Error::Argument)?;
    let env = a.bytes(a.tail(0, 64)?, PT_MAX + 28)?;
    if env.is_empty() || encode_payload(&hint, &env) != b {
        return Err(Error::Argument);
    }
    Ok((hint, env))
}

// ------------------------------------------------------------------ the entries on handles

fn chain_ctx(
    h_session: &[u8; 32],
    epoch: &[u8; 32],
    sender: &[u8; 32],
    device: &[u8; 16],
) -> Vec<u8> {
    [&h_session[..], epoch, sender, device].concat()
}

fn wrap_aad(session: &[u8; 32], epoch: &[u8; 32], member: &[u8; 32], key_id: u64) -> Vec<u8> {
    [&session[..], epoch, member, &be64(key_id)].concat()
}

fn key32(s: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    Ok(Zeroizing::new(s.try_into().map_err(|_| Error::Argument)?))
}

impl AppKeys {
    /// An epoch key `K`: a `Derive` handle this scope drew or unwrapped.
    fn epoch_key(&self, k: &KeyHandle) -> Result<Zeroizing<[u8; 32]>> {
        self.check_usage(k, KeyUsage::Derive)?;
        if !matches!(k.origin, Origin::Drawn | Origin::Unwrapped) {
            return Err(Error::AppKeyUsage);
        }
        self.bytes(k)
    }

    /// A chain position of this scope: its key, chain and counter.
    fn position(&self, pos: &KeyHandle) -> Result<(Zeroizing<[u8; 32]>, [u8; 32], u64)> {
        self.check_usage(pos, KeyUsage::Derive)?;
        let (Origin::Chain, Some((chain, counter))) = (pos.origin, pos.chain) else {
            return Err(Error::AppKeyUsage);
        };
        Ok((self.bytes(pos)?, chain, counter))
    }

    fn make_position(&self, ck: &[u8], chain: [u8; 32], counter: u64) -> Result<KeyHandle> {
        let mut h = self.make(ck, KeyUsage::Derive, Origin::Chain, None)?;
        h.chain = Some((chain, counter));
        Ok(h)
    }

    /// K2: `K` wrapped to the member's KEM key `kem_pk` (the version `key_id`, read by the caller as a trusted read).
    pub fn pqchat_wrap(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        member: &[u8; 32],
        key_id: u64,
        kem_pk: &[u8],
    ) -> Result<KemWrap> {
        self.epoch_key(k)?;
        self.kem_wrap(k, WRAP, &wrap_aad(session, epoch, member, key_id), kem_pk)
    }

    /// K2: the epoch key of `wrap` by `kem` (the member's KEM key at `key_id`), as a `Derive` handle: `Aead` when it does not
    /// open.
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_unwrap(
        &self,
        kem: &KemKeyPair,
        wrap: &KemWrap,
        session: &[u8; 32],
        epoch: &[u8; 32],
        member: &[u8; 32],
        key_id: u64,
    ) -> Result<KeyHandle> {
        let aad = wrap_aad(session, epoch, member, key_id);
        self.kem_unwrap(kem, wrap, WRAP, &aad, KeyUsage::Derive)
    }

    /// K3: `ck_0 = HKDF(K, "scaas/pqchat/v1/chain" ‖ sessionId ‖ epochId ‖ sender ‖ device)`, a position at counter 0.
    pub fn pqchat_chain(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        sender: &[u8; 32],
        device: &[u8; 16],
    ) -> Result<KeyHandle> {
        let key = self.epoch_key(k)?;
        let ctx = chain_ctx(session, epoch, sender, device);
        let ck = hkdf_sha256(&key[..], &[], &[CHAIN, &ctx].concat(), 32)?;
        self.make_position(&ck, keccak256(&ctx), 0)
    }

    /// K3: the position `n` steps past `pos` (`ck_{i+1} = HMAC(ck_i, 0x02)`), in one call; `n` above [`WALK_MAX`]
    /// `PqChatTooFar`, before any step.
    pub fn pqchat_advance(&self, pos: &KeyHandle, n: u64) -> Result<KeyHandle> {
        if n > WALK_MAX {
            return Err(Error::PqChatTooFar);
        }
        let (ck, chain, counter) = self.position(pos)?;
        let to = counter.checked_add(n).ok_or(Error::PqChatTooFar)?;
        let mut ck = ck;
        for _ in 0..n {
            ck = key32(&hmac_sha256(&ck[..], &[2]))?;
        }
        self.make_position(&ck[..], chain, to)
    }

    /// K6: `HMAC(K, "scaas/pqchat/v1/hint")[0:8]`, only of an epoch key this scope drew or unwrapped.
    pub fn pqchat_hint(&self, k: &KeyHandle) -> Result<[u8; 8]> {
        let key = self.epoch_key(k)?;
        let m = hmac_sha256(&key[..], HINT);
        m.get(..8)
            .and_then(|h| h.try_into().ok())
            .ok_or(Error::Argument)
    }

    fn sub_key(
        &self,
        k: &KeyHandle,
        label: &[u8],
        session: &[u8; 32],
        epoch: &[u8; 32],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let key = self.epoch_key(k)?;
        key32(&hkdf_sha256(
            &key[..],
            &[],
            &[label, session, epoch].concat(),
            32,
        )?)
    }

    fn seal_info_with(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        info_json: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        let canon = canonical_of_text(info_json)?;
        let pt = Zeroizing::new(pad(canon.as_bytes())?);
        let key = self.sub_key(k, INFO, session, epoch)?;
        let ct = aead_seal(Alg::Aes256GcmSiv, &key, nonce, &[], &pt)?;
        Ok([&nonce[..], &ct].concat())
    }

    /// S1 / S2's seal (§4.2): `nonce ‖ AES-256-GCM-SIV(HKDF(K, "scaas/pqchat/v1/info" ‖ sessionId ‖ epochId), nonce,
    /// pad(canonical JSON of info_json))`, a random nonce.
    pub fn pqchat_seal_info(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        info_json: &[u8],
    ) -> Result<Vec<u8>> {
        let mut n = [0u8; 12];
        rng(&mut n)?;
        self.seal_info_with(k, session, epoch, info_json, &n)
    }

    /// K5: the canonical JSON of a `sealedInfo` (`Aead` when it does not open, `PqChatContent` when its padding or canonical
    /// form is not what a sealer writes).
    pub fn pqchat_open_info(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        sealed: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if sealed.len() > PT_MAX + 28 {
            return Err(Error::Argument);
        }
        let key = self.sub_key(k, INFO, session, epoch)?;
        let nonce: [u8; 12] = sealed
            .get(..12)
            .and_then(|n| n.try_into().ok())
            .ok_or(Error::Aead)?;
        let pt = aead_open(
            Alg::Aes256GcmSiv,
            &key,
            &nonce,
            &[],
            sealed.get(12..).ok_or(Error::Aead)?,
        )?;
        canonical_content(&pt)
    }

    /// `mk`, `n` of the position at the header's counter (`Argument` for a position of another chain or counter).
    fn message_key(&self, pos: &KeyHandle, h: &Header) -> Result<(Zeroizing<[u8; 32]>, [u8; 12])> {
        let (ck, chain, counter) = self.position(pos)?;
        let ctx = chain_ctx(&h.session_id, &h.epoch_id, &h.sender, &h.device);
        if chain != keccak256(&ctx) || counter != h.counter {
            return Err(Error::Argument);
        }
        let mk = key32(&hmac_sha256(&ck[..], &[1]))?;
        let n = hmac_sha256(&ck[..], &[3]);
        Ok((
            mk,
            n.get(..12)
                .and_then(|x| x.try_into().ok())
                .ok_or(Error::Argument)?,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn seal_message_with(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        content_json: &[u8],
        signer: &dyn Signer,
        env_nonce: &[u8; 12],
    ) -> Result<SealedMessage> {
        h.check()?;
        let canon = canonical_of_text(content_json)?;
        self.seal_canonical(k, pos, h, canon.as_bytes(), signer, env_nonce)
    }

    /// S5 from a canonical content (`canon`): padded, encrypted at `pos`, signed, the envelope and the payload.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn seal_canonical(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        canon: &[u8],
        signer: &dyn Signer,
        env_nonce: &[u8; 12],
    ) -> Result<SealedMessage> {
        h.check()?;
        let pt = Zeroizing::new(pad(canon)?);
        let (mk, n) = self.message_key(pos, h)?;
        let ciphertext = aead_seal(Alg::Aes256GcmSiv, &mk, &n, &message_aad(h), &pt)?;
        let td = pqchat::typed("PqChatMessage", h.record(&ciphertext))?;
        let message_id = td.digest()?;
        let sig = pqchat::sign(signer, &td)?;
        let inner = encode_inner(h, &ciphertext, &sig);
        let hint = self.pqchat_hint(k)?;
        let env = self.envelope_with(k, &h.session_id, &h.epoch_id, &inner, env_nonce)?;
        let payload = encode_payload(&hint, &env);
        Ok(SealedMessage {
            header: h.clone(),
            ciphertext,
            sig,
            message_id,
            inner,
            hint,
            env,
            payload,
        })
    }

    fn envelope_with(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        inner: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        let key = self.sub_key(k, ENV, session, epoch)?;
        let ct = aead_seal(Alg::Aes256GcmSiv, &key, nonce, &[], inner)?;
        Ok([&nonce[..], &ct].concat())
    }

    /// S5: the content (a JSON text) canonicalised, padded and encrypted at `pos` (the own chain's position at `h.counter`),
    /// `PqChatMessage` signed by `signer` (a single UA key), the envelope sealed under `K` with a random nonce, the payload.
    pub fn pqchat_seal_message(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        content_json: &[u8],
        signer: &dyn Signer,
    ) -> Result<SealedMessage> {
        let mut n = [0u8; 12];
        rng(&mut n)?;
        self.seal_message_with(k, pos, h, content_json, signer, &n)
    }

    /// K4, first half: the envelope `env` opened under `k_env` and decoded (V2) into the record and its signature, unchecked;
    /// `Aead` when it does not open, `Argument` when it does not decode.
    pub fn pqchat_open_envelope(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        env: &[u8],
    ) -> Result<Inner> {
        if env.len() > PT_MAX + 28 {
            return Err(Error::Argument);
        }
        let key = self.sub_key(k, ENV, session, epoch)?;
        let nonce: [u8; 12] = env
            .get(..12)
            .and_then(|n| n.try_into().ok())
            .ok_or(Error::Aead)?;
        let inner = aead_open(
            Alg::Aes256GcmSiv,
            &key,
            &nonce,
            &[],
            env.get(12..).ok_or(Error::Aead)?,
        )?;
        decode_inner(&inner)
    }

    /// K4, second half (after V1 and the membership check): the content of the record `(h, ciphertext)` at `pos` (the
    /// sender chain's position at `h.counter`): the GCM-SIV open with the §6.4 AAD (`Aead`), `unpad` and the canonical check
    /// (`PqChatContent`); the canonical JSON bytes.
    pub fn pqchat_open_message(
        &self,
        pos: &KeyHandle,
        h: &Header,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        h.check()?;
        if ciphertext.len() > PT_MAX + 16 {
            return Err(Error::Argument);
        }
        let (mk, n) = self.message_key(pos, h)?;
        let pt = aead_open(Alg::Aes256GcmSiv, &mk, &n, &message_aad(h), ciphertext)?;
        canonical_content(&pt)
    }
}

/// `unpad`, then the canonical check: the content re-serialised must equal its bytes.
fn canonical_content(pt: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let c = unpad(pt)?;
    let again = canonical_of_text(&c)?;
    if again.as_bytes() != c.as_slice() {
        return Err(Error::PqChatContent);
    }
    Ok(c)
}

/// Test-only entry points (feature `vectors`, never in a release build): fixed randomness for the vectors.
#[cfg(feature = "vectors")]
impl AppKeys {
    /// [`AppKeys::pqchat_wrap`] with fixed `m` and X25519 ephemeral secret.
    #[allow(clippy::too_many_arguments)]
    pub fn pqchat_vectors_wrap(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        member: &[u8; 32],
        key_id: u64,
        kem_pk: &[u8],
        m: &[u8; 32],
        e: &[u8; 32],
    ) -> Result<KemWrap> {
        self.epoch_key(k)?;
        self.wrap_with(
            k,
            WRAP,
            &wrap_aad(session, epoch, member, key_id),
            kem_pk,
            m,
            e,
        )
    }

    /// [`AppKeys::pqchat_seal_info`] with a fixed nonce.
    pub fn pqchat_vectors_seal_info(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        info_json: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        self.seal_info_with(k, session, epoch, info_json, nonce)
    }

    /// [`AppKeys::pqchat_seal_message`] with a fixed envelope nonce.
    pub fn pqchat_vectors_seal_message(
        &self,
        k: &KeyHandle,
        pos: &KeyHandle,
        h: &Header,
        content_json: &[u8],
        signer: &dyn Signer,
        env_nonce: &[u8; 12],
    ) -> Result<SealedMessage> {
        self.seal_message_with(k, pos, h, content_json, signer, env_nonce)
    }

    /// The envelope of given inner bytes (a vector's `inner`, signed elsewhere), with a fixed nonce.
    pub fn pqchat_vectors_envelope(
        &self,
        k: &KeyHandle,
        session: &[u8; 32],
        epoch: &[u8; 32],
        inner: &[u8],
        nonce: &[u8; 12],
    ) -> Result<Vec<u8>> {
        self.envelope_with(k, session, epoch, inner, nonce)
    }
}
