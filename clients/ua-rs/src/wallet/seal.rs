// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Seal / open to a UA KEM key and the sealed containers of backup and link (spec §6.3, C-03, C-11, MD-10, MD-11; clientkeys
//! `seal.js`; T8):
//!
//! ```text
//! key        = HKDF-SHA256(ss, salt = empty, info = "scaas/seal/v1" ‖ u8 scheme ‖ be16 len(purpose) ‖ purpose ‖ keccak256(kemPk), 32)
//! ciphertext = AES-256-GCM(key, nonce = 0^96, pt, aad)      every key encrypts once: m and e are fresh per seal (OS RNG inside)
//! ```
//!
//! **Seal authenticates no sender:** anyone can seal to any key; a raw [`Sealed`] proves nothing about who made it. **No replay
//! protection:** [`KemKeyPair::open`] and [`KemKeyPair::open_container`] open a valid seal again and again; a valid signature and
//! tag authenticate `created`, they do not make a container fresh (RFC 9180 §9.7.3 likewise). A link session gives its window and
//! one use ([`Wallet::from_link`]); a restore its generation ([`Wallet::restore_backup`]).
//!
//! A container `{v: 1, purpose, recipient, sender: {ua, auth}, created, sealed}` carries the sender's full `UASig` over
//! `uaMessage(kind, seal, keccak256(aad ‖ wire form))` under the off-chain purpose `scaas.ua.purpose.seal.v1` (MD-10): a single
//! key its key data and signature, an `msig` its structure as key data, no signature and the minimal member set at both levels.
//! It opens only against what the opener expects ([`ContainerExpect`]): purpose, recipient, sender (expected UA or approved set),
//! key data that derives the sender's UA (the container names no kind: each derived kind that may sign a container is tried),
//! the signature (an `msig`: its member keys from `members`, never trusted; its signers accepted at both levels, CTR-UA-37), all
//! before decapsulation. A container's recipient is a single-key KEM holder by type ([`Recipient`], MD-11: an `msig` has no KEM
//! key; seal to each of its accepted members). UNAUDITED.
//!
//! There is no container open without a [`ContainerExpect`] (`no_container_open_without_expect`; positive control first):
//! ```no_run
//! use scaas_ua::wallet::{ContainerExpect, KemKeyPair, SealedContainer};
//! fn f(k: &KemKeyPair, c: &SealedContainer, e: &ContainerExpect) {
//!     let none = |_: [u8; 32]| -> Option<(u16, Vec<u8>)> { None };
//!     let _ = k.open_container(c, e, &none, None);
//! }
//! ```
//! ```compile_fail,E0061
//! use scaas_ua::wallet::{KemKeyPair, SealedContainer};
//! fn f(k: &KemKeyPair, c: &SealedContainer) {
//!     let none = |_: [u8; 32]| -> Option<(u16, Vec<u8>)> { None };
//!     let _ = k.open_container(c, &none, None);
//! }
//! ```
//! A link session installs once (`second_link_install_cannot_be_expressed`: the session is moved):
//! ```no_run
//! use scaas_ua::wallet::{ContainerExpect, LinkSession, SealedContainer, Wallet};
//! fn f(s: LinkSession, c: &SealedContainer, e: &ContainerExpect) {
//!     let none = |_: [u8; 32]| -> Option<(u16, Vec<u8>)> { None };
//!     let _ = Wallet::from_link(s, c, e, &none, None, "");
//! }
//! ```
//! ```compile_fail,E0382
//! use scaas_ua::wallet::{ContainerExpect, LinkSession, SealedContainer, Wallet};
//! fn f(s: LinkSession, c: &SealedContainer, e: &ContainerExpect) {
//!     let none = |_: [u8; 32]| -> Option<(u16, Vec<u8>)> { None };
//!     let _ = Wallet::from_link(s, c, e, &none, None, "");
//!     let _ = Wallet::from_link(s, c, e, &none, None, "");
//! }
//! ```
use super::aead::{aead_open, aead_seal, hkdf_sha256, Alg};
use super::kem::{is_kem_holder, kem_encaps, Encapsulated, KemKeyPair};
use super::sign::seal_request;
use super::signer::{KeyRef, Signer};
use super::uasig::{msig_members, Slot};
use super::{bounded, Error, Result, Wallet};
use crate::ua8::{inner_digest, member_keys, msig_sig_minimal, Accepted, Inner, InnerSig, MemberSig, Members, MsigStructure, UASig};
use crate::{derive_ua, keccak256, member_digest, purpose_tag, seal_purpose_tag, ua_message};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{OsRng, RngCore};
use super::eip712::from_hex;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The purpose of a backup container (spec §8.4).
pub const PURPOSE_BACKUP: &str = "scaas/backup/v1";
/// The purpose of a link container (device linking).
pub const PURPOSE_LINK: &str = "scaas/link/v1";
/// The largest plaintext of a seal: 1 MiB.
pub const MAX_PT: usize = 1 << 20;
/// A link container's `created` lies in `[session start, start + LINK_WINDOW]` (seconds; 10 minutes).
pub const LINK_WINDOW: u64 = 600;

const CT: usize = 1568;
const TAG: usize = 16;
const SEAL_INFO: &[u8] = b"scaas/seal/v1";
const MSIG: u16 = 0x0120;
/// The kinds whose key signs a container itself or as an `msig` member: the derived single keys. A native or group key, a
/// Zether key, an `msig` as a leaf: none.
const SENDER_KINDS: [u16; 15] =
    [0x0100, 0x0101, 0x0102, 0x0103, 0x0104, 0x0105, 0x0106, 0x0107, 0x0108, 0x0130, 0x0131, 0x0132, 0x0133, 0x0134, 0x0135];
/// Whether `kind` signs a container (a derived single key).
pub(super) fn is_sender_kind(kind: u16) -> bool {
    SENDER_KINDS.contains(&kind)
}
/// The container JSON: 1 MiB of ciphertext and two levels of 16 member signatures, base64url (spec §9.3: fixed field lengths).
const CONTAINER_JSON: usize = 4 << 20;
/// `{sender: {auth: {members: [{members: [{…}]}]}}}`.
const CONTAINER_DEPTH: usize = 7;
/// An approved sender set holds at most 64 UAs (spec §9.3).
const SET_MAX: usize = 64;
/// An `msig` has at most 16 members (CTR-UA-09): a longer list is malformed.
const LIST_MAX: usize = 16;

/// A seal: the named fields; [`Sealed::to_wire`] is the storage and transport form only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed {
    pub version: u8,
    pub scheme: u8,
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: [u8; 32],
    pub ciphertext: Vec<u8>,
}

impl Sealed {
    /// `version ‖ scheme ‖ mlkemCt ‖ x25519Eph ‖ ciphertext`.
    pub fn to_wire(&self) -> Vec<u8> {
        [&[self.version, self.scheme][..], &self.mlkem_ct, &self.x25519_eph, &self.ciphertext].concat()
    }

    /// The named fields of a wire form: `SealOpen` for one shorter than its fixed fields and a tag, `SealVersion` for a version
    /// or scheme other than 1.
    pub fn from_wire(w: &[u8]) -> Result<Sealed> {
        let short = w.len() < 2 + CT + 32 + TAG;
        let (head, rest) = w.split_at_checked(2).filter(|_| !short).ok_or(Error::SealOpen)?;
        if head != [1, 1] {
            return Err(Error::SealVersion);
        }
        let (ct, rest) = rest.split_at_checked(CT).ok_or(Error::SealOpen)?;
        let (eph, ciphertext) = rest.split_at_checked(32).ok_or(Error::SealOpen)?;
        let x25519_eph = eph.try_into().map_err(|_| Error::SealOpen)?;
        Ok(Sealed { version: 1, scheme: 1, mlkem_ct: ct.to_vec(), x25519_eph, ciphertext: ciphertext.to_vec() })
    }
}

/// `purpose` as bytes: ASCII `[a-z0-9./-]`, 1–64 bytes, else `Argument`.
fn purpose_bytes(p: &str) -> Result<&[u8]> {
    let ok = (1..=64).contains(&p.len()) && p.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'.' | b'/' | b'-'));
    ok.then_some(p.as_bytes()).ok_or(Error::Argument)
}

fn be16(n: usize) -> Result<[u8; 2]> {
    Ok(u16::try_from(n).map_err(|_| Error::Argument)?.to_be_bytes())
}

/// The AEAD key of a seal: binds the version, the scheme, the purpose and the recipient's whole key.
fn seal_key(ss: &[u8; 32], p: &[u8], kem_pk: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let info = [SEAL_INFO, &[1], &be16(p.len())?, p, &keccak256(kem_pk)].concat();
    let okm = hkdf_sha256(ss, &[], &info, 32)?;
    Ok(Zeroizing::new(okm.as_slice().try_into().map_err(|_| Error::Argument)?))
}

fn seal_with(kem_pk: &[u8], purpose: &str, aad: &[u8], pt: &[u8], encaps: impl FnOnce(&[u8]) -> Result<Encapsulated>) -> Result<Sealed> {
    let p = purpose_bytes(purpose)?;
    if pt.len() > MAX_PT {
        return Err(Error::Argument);
    }
    let (mlkem_ct, x25519_eph, ss) = encaps(kem_pk)?;
    let key = seal_key(&ss, p, kem_pk)?;
    let ciphertext = aead_seal(Alg::Aes256Gcm, &key, &[0; 12], aad, pt)?;
    Ok(Sealed { version: 1, scheme: 1, mlkem_ct, x25519_eph, ciphertext })
}

/// [`Sealed`] of `pt` (at most 1 MiB, may be empty) to `kem_pk` under `purpose` (`[a-z0-9./-]{1,64}`) with `aad`; `m` and `e`
/// from the OS RNG inside. `Argument` for the purpose or the length, `KemCheck` for `kem_pk` (spec §6.2). **Authenticates no
/// sender**; no length hiding (padding is the caller's).
pub fn seal(kem_pk: &[u8], purpose: &str, aad: &[u8], pt: &[u8]) -> Result<Sealed> {
    seal_with(kem_pk, purpose, aad, pt, kem_encaps)
}

impl KemKeyPair {
    /// The plaintext of `s` under `purpose` and `aad`: `SealVersion` for a version or scheme other than 1, `Argument` for the
    /// purpose, `SealOpen` for any other failure (decapsulation checks, tag), `KeyRevoked` once the key's store was locked. **No
    /// replay protection**: a valid seal opens again.
    pub fn open(&self, purpose: &str, aad: &[u8], s: &Sealed) -> Result<Zeroizing<Vec<u8>>> {
        if s.version != 1 || s.scheme != 1 {
            return Err(Error::SealVersion);
        }
        let p = purpose_bytes(purpose)?;
        if s.ciphertext.len() > MAX_PT + TAG {
            return Err(Error::SealOpen);
        }
        let ss = self.decaps(&s.mlkem_ct, &s.x25519_eph).map_err(|e| if e == Error::KemCheck { Error::SealOpen } else { e })?;
        let key = seal_key(&ss, p, &self.kem_pk())?;
        aead_open(Alg::Aes256Gcm, &key, &[0; 12], aad, &s.ciphertext).map_err(|_| Error::SealOpen)
    }

    /// The plaintext of a container, accepted only as `expect` says (spec §6.3, C-03), in order, each before decapsulation:
    /// the purpose; the recipient (the container's is `expect.recipient`, and that is this key's own); the sender (the expected
    /// UA or in the approved set, at most 64); `sender.auth.keyData` derives `sender.ua` as an `msig` or as exactly one
    /// single-key kind; then the `UASig` over the rebuilt `aad` and wire form (a single key: its signature, no members, neither
    /// lookup asked; an `msig`: no signature of its own, `accepted` present, the minimal member set at both levels, at each
    /// level the accepted weight of its signing slots reaching the threshold (CTR-UA-37), every member signature over keys from
    /// `members`, each re-derived), then the seal. A mismatch, an `msig` sender without `accepted`, a signer not accepted or an
    /// unknown member: `ContainerSender`; a bad signature, a `UASig` of the wrong form, a non-minimal set or a bad tag:
    /// `SealOpen`. A link container needs its session's short code ([`Wallet::from_link`]): here `Argument`. **No replay
    /// protection.**
    pub fn open_container(
        &self, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>,
    ) -> Result<Zeroizing<Vec<u8>>> {
        open_container_with(self, c, expect, members, accepted, None)
    }
}

/// The id a container names its recipient by.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecipientId {
    /// A UA's KEM key of record version `version`.
    Ua { ua: [u8; 32], version: u64 },
    /// An ephemeral key (a link session's): `keccak256(kemPk)`.
    KemPkHash([u8; 32]),
}

impl RecipientId {
    /// `(recipientId, version)` of the `aad` (version 0 for an ephemeral key).
    fn parts(&self) -> ([u8; 32], u64) {
        match *self {
            RecipientId::Ua { ua, version } => (ua, version),
            RecipientId::KemPkHash(h) => (h, 0),
        }
    }
}

/// The recipient of a container: a single-key KEM holder's key by type (MD-11: an `msig` has no KEM key; seal to each of its
/// accepted members), or an ephemeral key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    id: RecipientId,
    kem_pk: Vec<u8>,
}

impl Recipient {
    /// The KEM key `kem_pk` of record `version` of the UA of `(kind, key_data)` (its record on the chain): `KemHolder` for a kind
    /// that holds none (CTR-UA-32), an `msig` (`0x0120`) included; the key data must derive its UA.
    pub fn ua(kind: u16, key_data: &[u8], version: u64, kem_pk: &[u8]) -> Result<Recipient> {
        if !is_kem_holder(kind) {
            return Err(Error::KemHolder);
        }
        let ua = derive_ua(kind, key_data, false)?;
        Ok(Recipient { id: RecipientId::Ua { ua, version }, kem_pk: kem_pk.to_vec() })
    }

    /// An ephemeral key (a link session's `kem_pk`), named by `keccak256(kem_pk)`.
    pub fn ephemeral(kem_pk: &[u8]) -> Recipient {
        Recipient { id: RecipientId::KemPkHash(keccak256(kem_pk)), kem_pk: kem_pk.to_vec() }
    }

    pub fn id(&self) -> RecipientId {
        self.id
    }

    pub fn kem_pk(&self) -> &[u8] {
        &self.kem_pk
    }
}

/// The sender the opener expects (never the container's own claim).
#[derive(Clone, Copy, Debug)]
pub enum ExpectedSender<'a> {
    Ua([u8; 32]),
    /// An approved set, at most 64 UAs.
    Set(&'a [[u8; 32]]),
}

/// What a container must be to open (spec §6.3): its purpose, its sender, its recipient (the opening key's own).
#[derive(Clone, Copy, Debug)]
pub struct ContainerExpect<'a> {
    pub purpose: &'a str,
    pub sender: ExpectedSender<'a>,
    pub recipient: RecipientId,
}

/// A sealed container (backup, link): named fields; JSON `{v: 1, purpose, recipient, created, sender: {ua, auth}, sealed}`,
/// bytes base64url, through [`SealedContainer::to_json`] / [`SealedContainer::from_json`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedContainer {
    pub purpose: String,
    pub recipient: RecipientId,
    pub created: u64,
    pub sender_ua: [u8; 32],
    /// The sender's `UASig` (`key_data` always the sender's key data or `msig` structure).
    pub auth: UASig,
    pub sealed: Sealed,
}

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

impl SealedContainer {
    /// The container JSON, fields in clientkeys' order.
    pub fn to_json(&self) -> String {
        let recipient = match self.recipient {
            RecipientId::Ua { ua, version } => format!("{{\"ua\":\"{}\",\"version\":{version}}}", b64(&ua)),
            RecipientId::KemPkHash(h) => format!("{{\"kemPkHash\":\"{}\"}}", b64(&h)),
        };
        let inner = |l: &[InnerSig]| l.iter().map(|x| format!("{{\"index\":{},\"sig\":\"{}\"}}", x.index, b64(&x.sig))).collect::<Vec<_>>();
        let members = self
            .auth
            .members
            .iter()
            .map(|m| format!("{{\"index\":{},\"members\":[{}],\"sig\":\"{}\"}}", m.index, inner(&m.members).join(","), b64(&m.sig)))
            .collect::<Vec<_>>();
        let s = &self.sealed;
        format!(
            "{{\"v\":1,\"purpose\":{},\"recipient\":{recipient},\"created\":{},\"sender\":{{\"ua\":\"{}\",\"auth\":{{\"keyData\":\"{}\",\
             \"signature\":\"{}\",\"members\":[{}]}}}},\"sealed\":{{\"mlkemCt\":\"{}\",\"x25519Eph\":\"{}\",\"ciphertext\":\"{}\"}}}}",
            Value::from(self.purpose.as_str()),
            self.created,
            b64(&self.sender_ua),
            b64(&self.auth.key_data),
            b64(&self.auth.signature),
            members.join(","),
            b64(&s.mlkem_ct),
            b64(&s.x25519_eph),
            b64(&s.ciphertext),
        )
    }

    /// The named fields of a container JSON: `Argument` past 4 MiB or depth 7 (spec §9.3), `SealVersion` for `v` ≠ 1, `SealOpen`
    /// for a malformed field (base64url without padding, a 32-byte field of another length, a list longer than 16, a third
    /// level of member signatures).
    pub fn from_json(json: &[u8]) -> Result<SealedContainer> {
        let v = bounded::json(json, CONTAINER_JSON, CONTAINER_DEPTH)?;
        if v.get("v").and_then(Value::as_u64) != Some(1) {
            return Err(Error::SealVersion);
        }
        parse_container(&v).ok_or(Error::SealOpen)
    }
}

fn bytes_of(v: &Value) -> Option<Vec<u8>> {
    Base64UrlUnpadded::decode_vec(v.as_str()?).ok()
}
fn b32_of(v: &Value) -> Option<[u8; 32]> {
    bytes_of(v)?.try_into().ok()
}
fn index_of(v: &Value) -> Option<u16> {
    u16::try_from(v.get("index")?.as_u64()?).ok()
}
/// A member list (absent: empty), at most 16 entries.
fn list_of(v: &Value) -> Option<&[Value]> {
    match v.get("members") {
        None => Some(&[]),
        Some(l) => l.as_array().map(Vec::as_slice).filter(|l| l.len() <= LIST_MAX),
    }
}

fn parse_container(v: &Value) -> Option<SealedContainer> {
    let r = v.get("recipient")?;
    let recipient = match (r.get("kemPkHash"), r.get("ua")) {
        (Some(h), None) => RecipientId::KemPkHash(b32_of(h)?),
        (None, Some(ua)) => RecipientId::Ua { ua: b32_of(ua)?, version: r.get("version")?.as_u64()? },
        _ => return None,
    };
    let sender = v.get("sender")?;
    let auth = sender.get("auth")?;
    let members = list_of(auth)?
        .iter()
        .map(|m| {
            let inner = list_of(m)?
                .iter()
                .map(|x| match list_of(x)? {
                    [] => Some(InnerSig { index: index_of(x)?, sig: bytes_of(x.get("sig")?)? }),
                    _ => None, // a third level (CTR-UA-38)
                })
                .collect::<Option<Vec<_>>>()?;
            Some(MemberSig { index: index_of(m)?, members: inner, sig: bytes_of(m.get("sig")?)? })
        })
        .collect::<Option<Vec<_>>>()?;
    let s = v.get("sealed")?;
    Some(SealedContainer {
        purpose: v.get("purpose")?.as_str()?.to_owned(),
        recipient,
        created: v.get("created")?.as_u64()?,
        sender_ua: b32_of(sender.get("ua")?)?,
        auth: UASig { key_data: bytes_of(auth.get("keyData")?)?, signature: bytes_of(auth.get("signature")?)?, members },
        sealed: Sealed {
            version: 1,
            scheme: 1,
            mlkem_ct: bytes_of(s.get("mlkemCt")?)?,
            x25519_eph: b32_of(s.get("x25519Eph")?)?,
            ciphertext: bytes_of(s.get("ciphertext")?)?,
        },
    })
}

/// The container's AEAD `aad`: `u8 1 ‖ be16 len(purpose) ‖ purpose ‖ recipientId ‖ be64 version ‖ senderUa ‖ be64 created`, for
/// `scaas/link/v1` followed by `sha256(shortCode)` (the code both screens show; `Argument` without one).
fn container_aad(purpose: &str, recipient: &RecipientId, sender_ua: &[u8; 32], created: u64, short_code: Option<&str>) -> Result<Vec<u8>> {
    let p = purpose_bytes(purpose)?;
    let (id, version) = recipient.parts();
    let mut aad = [&[1u8][..], &be16(p.len())?, p, &id, &version.to_be_bytes(), sender_ua, &created.to_be_bytes()].concat();
    if purpose == PURPOSE_LINK {
        let code = short_code.filter(|c| !c.is_empty()).ok_or(Error::Argument)?;
        aad.extend(Sha256::digest(code.as_bytes()));
    }
    Ok(aad)
}

/// What the sender signs: `keccak256(aad ‖ wire form)`.
fn sealed_digest(aad: &[u8], s: &Sealed) -> [u8; 32] {
    keccak256(&[aad, &s.to_wire()].concat())
}

/// The sender of a container: a UA key (a derived single key of a sender kind), or an `msig` by the slots the caller names
/// (`inner` gives an `msig` member's key data); a native or group key does not sign a container.
pub enum ContainerSigner<'a> {
    Key(&'a dyn Signer),
    Msig { key_data: &'a [u8], inner: &'a Inner<'a>, slots: &'a [Slot<'a>] },
}

/// `(sender UA, its key data)`: `Argument` for a key of no sender kind.
fn sender_of(sender: &ContainerSigner) -> Result<([u8; 32], Vec<u8>)> {
    match sender {
        ContainerSigner::Key(k) => match k.key_ref() {
            KeyRef::Ua { kind, key_data } if SENDER_KINDS.contains(&kind) => Ok((derive_ua(kind, &key_data, false)?, key_data)),
            _ => Err(Error::Argument),
        },
        ContainerSigner::Msig { key_data, .. } => Ok((derive_ua(MSIG, key_data, false)?, key_data.to_vec())),
    }
}

/// The sender's `UASig` over `digest` under the seal purpose (MD-10): a single key its key data and signature, no members; an
/// `msig` its structure as key data, no signature, the minimal set at both levels (`UAPoP` otherwise; a native member:
/// `Argument`).
fn container_sig(sender: &ContainerSigner, key_data: Vec<u8>, digest: &[u8; 32]) -> Result<UASig> {
    match sender {
        ContainerSigner::Key(k) => {
            let KeyRef::Ua { kind, .. } = k.key_ref() else { return Err(Error::Argument) };
            let signature = k.sign_request(&seal_request(kind, digest)?)?;
            Ok(UASig { key_data, signature, members: vec![] })
        }
        ContainerSigner::Msig { key_data: d, inner, slots } => {
            let s = msig_members(d, inner, &seal_purpose_tag(), digest, None, None, slots)?;
            Ok(UASig { key_data, signature: vec![], members: s.members })
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn seal_container_with(
    recipient: &Recipient, purpose: &str, sender: &ContainerSigner, created: u64, pt: &[u8], short_code: Option<&str>,
    encaps: impl FnOnce(&[u8]) -> Result<Encapsulated>,
) -> Result<SealedContainer> {
    let (sender_ua, key_data) = sender_of(sender)?;
    let aad = container_aad(purpose, &recipient.id, &sender_ua, created, short_code)?;
    let sealed = seal_with(&recipient.kem_pk, purpose, &aad, pt, encaps)?;
    let auth = container_sig(sender, key_data, &sealed_digest(&aad, &sealed))?;
    Ok(SealedContainer { purpose: purpose.to_owned(), recipient: recipient.id, created, sender_ua, auth, sealed })
}

/// A container of `pt` to `recipient` under `purpose`, signed by `sender` over the `aad` and wire form; `created` the sender's
/// clock (seconds); `short_code` the code the new device shows (`scaas/link/v1` only, required there). `m` and `e` from the OS
/// RNG inside. Errors as [`seal`], and `Argument` for a sender that does not sign containers.
pub fn seal_container(
    recipient: &Recipient, purpose: &str, sender: &ContainerSigner, created: u64, pt: &[u8], short_code: Option<&str>,
) -> Result<SealedContainer> {
    seal_container_with(recipient, purpose, sender, created, pt, short_code, kem_encaps)
}

fn open_container_with(
    kk: &KemKeyPair, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>,
    short_code: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    if c.purpose != expect.purpose || c.recipient != expect.recipient || kk.recipient() != expect.recipient {
        return Err(Error::ContainerSender);
    }
    let allowed = match &expect.sender {
        ExpectedSender::Ua(u) => core::slice::from_ref(u),
        ExpectedSender::Set(s) if s.len() <= SET_MAX => s,
        ExpectedSender::Set(_) => return Err(Error::Argument),
    };
    if !allowed.contains(&c.sender_ua) {
        return Err(Error::ContainerSender);
    }
    let auth = &c.auth;
    let derives = |k: &u16| derive_ua(*k, &auth.key_data, false).ok() == Some(c.sender_ua);
    let kind = *core::iter::once(&MSIG).chain(&SENDER_KINDS).find(|k| derives(k)).ok_or(Error::ContainerSender)?;
    let aad = container_aad(&c.purpose, &c.recipient, &c.sender_ua, c.created, short_code)?;
    let m0 = ua_message(kind, &seal_purpose_tag(), &sealed_digest(&aad, &c.sealed))?;
    let ok = if kind == MSIG {
        let accepted = accepted.ok_or(Error::ContainerSender)?;
        auth.signature.is_empty() && msig_ok(&c.sender_ua, &auth.key_data, &m0, &auth.members, members, accepted)?
    } else {
        auth.members.is_empty() && crate::verify::verify(kind, &auth.key_data, &m0, &auth.signature, false)
    };
    if !ok {
        return Err(Error::SealOpen);
    }
    kk.open(&c.purpose, &aad, &c.sealed)
}

/// At one level of the `msig` `id` (key data `d`): the weight of the signing slots `indexes` whose `accepted(id, index)` is
/// `true` reaches the threshold (CTR-UA-37), else `ContainerSender`. The set is minimal, so this holds only when every signer is
/// accepted.
fn accepted_ok(id: &[u8; 32], d: &[u8], indexes: impl Iterator<Item = u16>, accepted: &Accepted) -> Result<()> {
    let s = MsigStructure::from_key_data(d).map_err(|_| Error::ContainerSender)?;
    let w: u32 = indexes
        .filter(|i| accepted(*id, *i))
        .map(|i| s.members.get(usize::from(i)).map_or(0, |m| u32::from(m.weight)))
        .sum();
    if w < u32::from(s.threshold) {
        return Err(Error::ContainerSender);
    }
    Ok(())
}

/// A leaf member's signature (a sender kind, no list below it) over `uaMessage(kind, member, md)`.
fn leaf_ok(kind: u16, key: &[u8], md: &[u8; 32], sig: &[u8]) -> Result<bool> {
    let msg = ua_message(kind, &purpose_tag("member")?, md)?;
    Ok(SENDER_KINDS.contains(&kind) && crate::verify::verify(kind, key, &msg, sig, false))
}

/// An `msig` sender's member signatures over its `ua_msg` `m0`: member keys from `members` (re-derived; unknown:
/// `ContainerSender`), the minimal set at both levels (else `false`), each level's signers accepted ([`accepted_ok`]), a derived
/// member over `memberDigest(id, m0)`, an `msig` member with no `sig` and its own non-empty list over `innerDigest`.
fn msig_ok(id: &[u8; 32], d: &[u8], m0: &[u8; 32], slots: &[MemberSig], members: &Members, accepted: &Accepted) -> Result<bool> {
    let cs = |_| Error::ContainerSender;
    let keys = member_keys(d, members).map_err(cs)?;
    let inner = |x: [u8; 32]| members(x).map(|(_, k)| k);
    if !msig_sig_minimal(d, slots, &inner).map_err(cs)? {
        return Ok(false);
    }
    let all = MsigStructure::from_key_data(d).map_err(cs)?.members;
    let at = |i: u16| Some((*all.get(usize::from(i))?, keys.get(usize::from(i))?));
    accepted_ok(id, d, slots.iter().map(|s| s.index), accepted)?;
    for s in slots {
        let (m, key) = at(s.index).ok_or(Error::ContainerSender)?;
        if m.kind == MSIG {
            accepted_ok(&m.id, key, s.members.iter().map(|x| x.index), accepted)?;
        }
    }
    let md = member_digest(id, m0);
    for s in slots {
        let (m, key) = at(s.index).ok_or(Error::ContainerSender)?;
        let ok = if m.kind != MSIG {
            s.members.is_empty() && leaf_ok(m.kind, key, &md, &s.sig)?
        } else {
            let leaves = MsigStructure::from_key_data(key).map_err(cs)?.members;
            let inner_keys = member_keys(key, members).map_err(cs)?;
            let imd = inner_digest(&m.id, &md)?;
            let leaf = |x: &InnerSig| -> Result<bool> {
                match (leaves.get(usize::from(x.index)), inner_keys.get(usize::from(x.index))) {
                    (Some(l), Some(k)) => leaf_ok(l.kind, k, &imd, &x.sig),
                    _ => Ok(false),
                }
            };
            s.sig.is_empty() && !s.members.is_empty() && s.members.iter().try_fold(true, |a, x| Ok::<_, Error>(a && leaf(x)?))?
        };
        if !ok {
            return Ok(false);
        }
    }
    Ok(true)
}

/// A link session on the new device (spec §6.3, C-11): an ephemeral KEM key in a store of its own, the short code both screens
/// show (8 decimal digits, OS RNG), its start (seconds); a container opens when `created` lies in `[start, start + 600]`, once:
/// [`Wallet::from_link`] takes the session by value and wipes its key.
pub struct LinkSession {
    key: KemKeyPair,
    short_code: String,
    start: u64,
}

impl LinkSession {
    /// A session from now.
    pub fn new() -> Result<LinkSession> {
        Ok(LinkSession { key: KemKeyPair::generate_ephemeral()?, short_code: short_code()?, start: now()? })
    }
    /// The key the existing device seals to.
    pub fn kem_pk(&self) -> Vec<u8> {
        self.key.kem_pk()
    }
    /// `keccak256(kemPk)`: the recipient the container names and the opener expects.
    pub fn recipient(&self) -> RecipientId {
        self.key.recipient()
    }
    pub fn short_code(&self) -> String {
        self.short_code.clone()
    }
    /// The session's start (seconds since 1970).
    pub fn start(&self) -> u64 {
        self.start
    }
}

/// 8 decimal digits, uniform (a `u32` below `42 × 10^8`, reduced).
fn short_code() -> Result<String> {
    loop {
        let mut b = [0u8; 4];
        OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
        let n = u32::from_be_bytes(b);
        if n < 4_200_000_000 {
            return Ok(format!("{:08}", n % 100_000_000));
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn now() -> Result<u64> {
    let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_err(|_| Error::Argument)?;
    Ok(t.as_secs())
}

// `SystemTime::now` panics on wasm32-unknown-unknown: the JS clock, as the OS RNG takes the JS backend
#[cfg(target_arch = "wasm32")]
pub(crate) fn now() -> Result<u64> {
    let ms = js_sys::Date::now();
    if !(ms.is_finite() && ms >= 0.0) {
        return Err(Error::Argument);
    }
    Ok((ms / 1000.0) as u64)
}

fn link_install(
    s: &LinkSession, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>,
    bip39_passphrase: &str,
) -> Result<Wallet> {
    if expect.purpose != PURPOSE_LINK {
        return Err(Error::Argument);
    }
    if c.created < s.start || c.created > s.start.saturating_add(LINK_WINDOW) {
        return Err(Error::ContainerReplay);
    }
    let pt = open_container_with(&s.key, c, expect, members, accepted, Some(&s.short_code))?;
    super::manifest::install_link(&pt, bip39_passphrase)
}

impl Wallet {
    /// The wallet a link container carries to `session` (spec §6.3, C-11): `expect.purpose` must be `scaas/link/v1`
    /// (`Argument`), `created` in the session's window (`ContainerReplay`), then [`KemKeyPair::open_container`]'s acceptance with
    /// the session's short code in the `aad`; the payload (a `BackupPayload`: `Argument` if malformed) builds the wallet: its
    /// entropy (with `bip39_passphrase`, never carried), imported keys, manifest entries and generation.
    /// The session is consumed and its key wiped whatever the outcome, so a second install cannot be expressed.
    pub fn from_link(
        session: LinkSession, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>,
        bip39_passphrase: &str,
    ) -> Result<Wallet> {
        let r = link_install(&session, c, expect, members, accepted, bip39_passphrase);
        session.key.wipe_own_store();
        r
    }
}

/// The JSON inputs of a container open across the C ABI and the bindings (spec §9.2, §9.3; no callback crosses the ABI): each
/// JSON depth 4 ([`bounded::json`]), ids and bytes `0x` hex, an unknown key `Argument`; `expect_json` and `accepted_json` at most
/// 16 KiB, `members_json` at most 512 KiB and 64 UAs (owner 2026-11-06: 16 KiB held about three ML-DSA-87 member keys).
const LOOKUP_JSON: usize = 16 << 10;
const MEMBERS_JSON: usize = 512 << 10;
const LOOKUP_DEPTH: usize = 4;

/// A 32-byte `0x` hex value.
fn h32(v: &Value) -> Option<[u8; 32]> {
    from_hex(v.as_str()?)?.try_into().ok()
}
/// `v` as an object whose keys are all in `keys`.
fn only<'a>(v: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    let o = v.as_object()?;
    o.keys().all(|k| keys.contains(&k.as_str())).then_some(o)
}

/// A [`ContainerExpect`] read from JSON, owning its data; [`ContainerExpectJson::get`] lends the expectation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerExpectJson {
    purpose: String,
    sender: Vec<[u8; 32]>,
    set: bool,
    recipient: RecipientId,
}

impl ContainerExpectJson {
    /// `{purpose, sender: {ua} | {set: [ua, …]}, recipient: {ua, version} | {kemPkHash}}` (clientkeys `openContainer`'s
    /// `expect`, the vector rows' `expect`): an approved set holds at most 64 UAs; anything else `Argument`.
    pub fn from_json(json: &[u8]) -> Result<ContainerExpectJson> {
        let v = bounded::json(json, LOOKUP_JSON, LOOKUP_DEPTH)?;
        parse_expect(&v).ok_or(Error::Argument)
    }

    pub fn get(&self) -> ContainerExpect<'_> {
        let sender = match (self.set, self.sender.first()) {
            (false, Some(u)) => ExpectedSender::Ua(*u),
            _ => ExpectedSender::Set(&self.sender),
        };
        ContainerExpect { purpose: &self.purpose, sender, recipient: self.recipient }
    }
}

fn parse_expect(v: &Value) -> Option<ContainerExpectJson> {
    let o = only(v, &["purpose", "sender", "recipient"])?;
    let purpose = o.get("purpose")?.as_str()?.to_owned();
    let s = only(o.get("sender")?, &["ua", "set"])?;
    let (sender, set) = match (s.get("ua"), s.get("set")) {
        (Some(u), None) => (vec![h32(u)?], false),
        (None, Some(l)) => {
            let l = l.as_array().filter(|l| l.len() <= SET_MAX)?;
            (l.iter().map(h32).collect::<Option<Vec<_>>>()?, true)
        }
        _ => return None,
    };
    let r = only(o.get("recipient")?, &["ua", "version", "kemPkHash"])?;
    let recipient = match (r.get("ua"), r.get("version"), r.get("kemPkHash")) {
        (Some(ua), Some(version), None) => RecipientId::Ua { ua: h32(ua)?, version: version.as_u64()? },
        (None, None, Some(h)) => RecipientId::KemPkHash(h32(h)?),
        _ => return None,
    };
    Some(ContainerExpectJson { purpose, sender, set, recipient })
}

/// An `msig` sender's member keys by id ([`Members`]) read from JSON: `{"<id>": {kind, keyData}}`. Never trusted: the opener
/// checks that each answer derives its id. [`MembersJson::default`] answers nothing (a single-key sender asks nothing).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MembersJson(Vec<([u8; 32], u16, Vec<u8>)>);

impl MembersJson {
    /// `Argument` past 512 KiB, depth 4 or 64 UAs, for an id that is not 32 bytes, a kind that is not a `u16` or key data that
    /// is not hex.
    pub fn from_json(json: &[u8]) -> Result<MembersJson> {
        let v = bounded::json(json, MEMBERS_JSON, LOOKUP_DEPTH)?;
        let entry = |(id, x): (&String, &Value)| {
            let x = only(x, &["kind", "keyData"])?;
            let kind = u16::try_from(x.get("kind")?.as_u64()?).ok()?;
            Some((h32(&Value::from(id.as_str()))?, kind, from_hex(x.get("keyData")?.as_str()?)?))
        };
        v.as_object()
            .filter(|o| o.len() <= SET_MAX)
            .and_then(|o| o.iter().map(entry).collect::<Option<_>>())
            .map(MembersJson)
            .ok_or(Error::Argument)
    }

    /// The [`Members`] answer for `id`.
    pub fn lookup(&self, id: [u8; 32]) -> Option<(u16, Vec<u8>)> {
        self.0.iter().find(|(x, ..)| *x == id).map(|(_, k, d)| (*k, d.clone()))
    }
}

/// The caller's `memberAccepted` reads ([`Accepted`]) as JSON: `{"<msig id>": [accepted member indices]}`; an index not listed
/// (or an id not named) is not accepted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AcceptedJson(Vec<([u8; 32], Vec<u16>)>);

impl AcceptedJson {
    /// `Argument` past 16 KiB or depth 4, for an id that is not 32 bytes or an index that is not a `u16`.
    pub fn from_json(json: &[u8]) -> Result<AcceptedJson> {
        let v = bounded::json(json, LOOKUP_JSON, LOOKUP_DEPTH)?;
        let index = |i: &Value| u16::try_from(i.as_u64()?).ok();
        let entry = |(id, l): (&String, &Value)| {
            Some((h32(&Value::from(id.as_str()))?, l.as_array()?.iter().map(index).collect::<Option<_>>()?))
        };
        v.as_object().and_then(|o| o.iter().map(entry).collect::<Option<_>>()).map(AcceptedJson).ok_or(Error::Argument)
    }

    /// The [`Accepted`] answer for `(id, index)`.
    pub fn accepted(&self, id: [u8; 32], index: u16) -> bool {
        self.0.iter().any(|(x, l)| *x == id && l.contains(&index))
    }
}

/// Test-only entry points (feature `vectors`, never in a release build).
#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use crate::wallet::kem::vectors_encaps;

    /// [`seal`] with the given `m` and `e`.
    pub fn vectors_seal(kem_pk: &[u8], purpose: &str, aad: &[u8], pt: &[u8], m: &[u8; 32], e: &[u8; 32]) -> Result<Sealed> {
        seal_with(kem_pk, purpose, aad, pt, |k| vectors_encaps(k, m, e))
    }

    /// [`seal_container`] with the given `m` and `e`.
    #[allow(clippy::too_many_arguments)]
    pub fn vectors_seal_container(
        recipient: &Recipient, purpose: &str, sender: &ContainerSigner, created: u64, pt: &[u8], short_code: Option<&str>,
        m: &[u8; 32], e: &[u8; 32],
    ) -> Result<SealedContainer> {
        seal_container_with(recipient, purpose, sender, created, pt, short_code, |k| vectors_encaps(k, m, e))
    }

    impl LinkSession {
        /// A session from 96 given bytes (the ephemeral key), a given short code and start.
        pub fn vectors_new(seed: &[u8; 96], short_code: &str, start: u64) -> Result<LinkSession> {
            Ok(LinkSession { key: KemKeyPair::vectors_ephemeral(seed)?, short_code: short_code.to_owned(), start })
        }
        /// A second handle of the session's key, to observe its wipe.
        pub fn vectors_key(&self) -> KemKeyPair {
            self.key.dup()
        }
    }
}
#[cfg(feature = "vectors")]
pub use vectors::{vectors_seal, vectors_seal_container};
