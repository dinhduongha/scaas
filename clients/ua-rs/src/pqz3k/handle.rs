// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The wallet's handle of one PQZ key with the opening (feature `pqz`; T21 O5 (b), owner 2026-11-16 "ok, as proposed"; design
//! docs/superpowers/specs/2026-11-16-pqz3k-handle-store.md; CLI-SGN-51, spec 2026-11-13-pqz-three-keys §6, §14.1, §14.18):
//! `offchain-shared` (class 2) or `offchain-token` of a token with the opening, at one key version. [`Wallet::pqz_scoped_key`]
//! derives its PQZ seed and its opening KEM seed inside the wallet's `SecretStore` (one arena slot, `seed32 ‖ openKemSeed`):
//! `lock()` revokes the handle for good. Every entry that needs a secret holds a read lease of the store (T21 L82) for the copy's
//! whole use, so `lock()` waits for it. No method returns either secret. [`PqzKeyHandle::check`] runs K3-7 through pqz-ffi
//! `opening::check_recipient` itself; the PQZ seed reaches a function only through [`PqzKeyHandle::with_secret_debit`] (the
//! debit's own part and window together, every part gated) and [`PqzKeyHandle::with_secret_keygen`] (counted apart).
//! UNAUDITED.
//!
//! [`Wallet::pqz_scoped_key`]: crate::wallet::Wallet::pqz_scoped_key
use super::{entry_hash, open_kem_seed, opening_blob, own_tag, scoped_key_seed, slot_marked, slot_trivial, Layout};
use crate::facade::pqz_pack::{unpack, B};
use crate::keccak;
use crate::wallet::{self, Error, Handle, KeyId, SecretStore};
use pqz_ffi::opening::{self as op, Party};
use pqz_ffi::stmt::{N, PK_BYTES};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// This build's set (spec §10.2: one set per build): `P(u)` and `P(v)` sizes of the stored form.
pub const LAYOUT: Layout = Layout::of(N, B);
/// The slot: `seed32` (32) ‖ `openKemSeed` (96, ML-KEM `d ‖ z`, then the X25519 secret).
const SEED: core::ops::Range<usize> = 0..32;
const OPEN_KEM: core::ops::Range<usize> = 32..128;

/// A PQZ key class with the opening (CTR-PQZ-37): `offchain-shared` (class 2) or `offchain-token` on a token with the opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    OffchainShared,
    OffchainToken,
}

/// The scope of a handle, by name: the derivation `account` / `index`, the holder's UA, the chain, the token (`None`:
/// `offchain-shared`; `Some`: `offchain-token` of a token with the opening) and the key version.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub account: u32,
    pub index: u32,
    pub ua: [u8; 32],
    pub chain_uid: [u8; 32],
    pub token: Option<[u8; 20]>,
    pub version: u64,
}

/// Why the handle refused, before the PQZ seed reached any function.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A credit, debit or blob of another token (class 3), recipient or key version than the handle's.
    NotThisHandle,
    /// The inputs are missing or malformed locally (a blob of another length, a TRIVIAL entry, no auditor keys for an audited
    /// leg, an own part on an account that never debited): an error before the check, never a skip (Fable P2-1).
    Input(&'static str),
    /// A window entry of another token, or not accepted by this handle for that token, index and bytes, and neither TRIVIAL nor
    /// skip-marked (spec §6, §14.18).
    Window,
    /// The `ownTag` of the holder's own ciphertext does not verify under this handle's key.
    OwnTag,
    /// `lastDebit > 0` and no own part: the debit's `T` holds the last debit's own ciphertext, which only its tag admits (T21 L43).
    OwnRequired,
    /// No own part and no window entry: nothing of the debit is gated, so the seed is not given (T21 L43).
    EmptyDebit,
    /// A skip that is not reproduced at a finalized block with strict-majority reads (Fable P2-1): no mark.
    Unconfirmed,
    /// The wallet was locked (or freed) after the handle was made (spec §8.2).
    KeyRevoked,
}

/// How the wallet read the state a check used (ARCH-POS-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reads {
    pub block: u64,
    pub finalized: bool,
    pub strict_majority: bool,
}

/// The auditor's public inputs of an audited leg, read by the wallet from the registry: its UA, its PQZ key at the leg's version
/// (`kv[1]`, `PK_BYTES`) and its opening KEM key of that version.
#[derive(Clone, Copy, Debug)]
pub struct AuditorKeys<'a> {
    pub ua: [u8; 32],
    pub pk: &'a [u8],
    pub kem_pk: &'a [u8],
}

/// A pending credit as the wallet read it: the token, its index, the slot word and the blob's code (`STOP ‖ data`).
#[derive(Clone, Copy, Debug)]
pub struct Credit<'a> {
    pub token: [u8; 20],
    pub index: u64,
    pub slot: [u8; 32],
    pub code: &'a [u8],
    pub auditor: Option<AuditorKeys<'a>>,
    pub reads: Reads,
}

/// An accepted credit, made by [`PqzKeyHandle::check`] only: bound to the handle, the token, the index and `h(i)` (slot and blob
/// bytes; T21 L47: the token named).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    handle: [u8; 32],
    token: [u8; 20],
    index: u64,
    content: [u8; 32],
}
impl Accepted {
    pub fn token(&self) -> [u8; 20] {
        self.token
    }
    pub fn index(&self) -> u64 {
        self.index
    }
    /// `h(i)` of the accepted bytes.
    pub fn entry_hash(&self) -> [u8; 32] {
        self.content
    }
}

/// A credit the check refused: the one outcome, with how its inputs were read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skip {
    pub index: u64,
    pub entry_hash: [u8; 32],
    pub reads: Reads,
}

/// The check's outcome: accepted with its amount (`Σ dᵢ·16ⁱ`), or skip.
#[derive(Debug, PartialEq, Eq)]
pub enum Checked {
    Accepted(Accepted, u64),
    Skip(Skip),
}

/// One entry of a debit's window `[p_last, p)`: the token, the slot as read, the blob's code for a credit, and its acceptance.
#[derive(Clone, Copy, Debug)]
pub struct WindowEntry<'a> {
    pub token: [u8; 20],
    pub index: u64,
    pub slot: [u8; 32],
    pub code: Option<&'a [u8]>,
    pub accepted: Option<&'a Accepted>,
}

/// The last own debit's ciphertext `(u_f, v_f)` (or a burn's `(u′, v_f)`) in the stored form, with its `ownTag`. Its counter
/// is the account's: the last own debit is `(ua, lastDebit − 1)`.
#[derive(Clone, Copy, Debug)]
pub struct Own<'a> {
    pub pu: &'a [u8],
    pub pvf: &'a [u8],
    pub own_tag: [u8; 32],
}

/// A debit's parts (CTR-PQZ-33: `T = own (u_f, v_f) + Σ pending[p_last, p) + Trivial(shieldIn)`): the token, the account's
/// `lastDebit`, the own part (exactly when `lastDebit > 0`) and the window.
#[derive(Clone, Copy, Debug)]
pub struct Debit<'a> {
    pub token: [u8; 20],
    pub last_debit: u64,
    pub own: Option<Own<'a>>,
    pub window: &'a [WindowEntry<'a>],
}

/// See the module. Made by [`crate::wallet::Wallet::pqz_scoped_key`] (and, under `vectors`, by its test constructors).
#[cfg_attr(not(feature = "vectors"), doc = r#"
A release build names no raw-seed entry point (T21 O5; positive control first):
```
let s = scaas_ua::pqz3k::Scope { account: 0, index: 0, ua: [0; 32], chain_uid: [0; 32], token: None, version: 0 };
let _ = (s, scaas_ua::pqz3k::LAYOUT);
```
```compile_fail,E0599
let s = scaas_ua::pqz3k::Scope { account: 0, index: 0, ua: [0; 32], chain_uid: [0; 32], token: None, version: 0 };
let _ = scaas_ua::pqz3k::PqzKeyHandle::vectors_from_seed(&[0; 64], &s);
```
```compile_fail,E0599
let s = scaas_ua::pqz3k::Scope { account: 0, index: 0, ua: [0; 32], chain_uid: [0; 32], token: None, version: 0 };
let _ = scaas_ua::pqz3k::PqzKeyHandle::vectors_from_secrets(&[0; 32], &[0; 96], &s);
```
```compile_fail,E0603
let _ = scaas_ua::pqz3k::open_kem_seed(&[0; 64], &[0; 32], &[0; 32], None, 0);
```
```compile_fail,E0603
let _ = scaas_ua::pqz3k::pqz_token_key_seed_without_opening(&[0; 64], 0, 0, &[0; 32], &[0; 20], 0);
```
"#)]
pub struct PqzKeyHandle {
    class: KeyClass,
    scope: [u8; 20],
    ua: [u8; 32],
    chain_uid: [u8; 32],
    version: u64,
    id: [u8; 32],
    pk: Box<[u8; PK_BYTES]>,
    kem_pk: Vec<u8>,
    secret: Handle,
    loads: AtomicU32,
    keygens: AtomicU32,
}

/// `seed32 ‖ openKemSeed` of `s` from the BIP-39 seed (K3-2, K3-6b).
fn secrets(seed: &[u8; 64], s: &Scope) -> Zeroizing<Vec<u8>> {
    let t = s.token.as_ref();
    let p = scoped_key_seed(seed, s.account, s.index, &s.chain_uid, t, s.version);
    let k = open_kem_seed(seed, &s.ua, &s.chain_uid, t, s.version);
    Zeroizing::new([&p[..], &k[..]].concat())
}

/// `pk ‖ kemPk` of a slot's secrets (public).
fn publics(secret: &[u8]) -> wallet::Result<Vec<u8>> {
    let seed32: &[u8; 32] = secret.get(SEED).and_then(|s| s.try_into().ok()).ok_or(Error::Argument)?;
    let ok: &[u8; 96] = secret.get(OPEN_KEM).and_then(|s| s.try_into().ok()).ok_or(Error::Argument)?;
    let key = pqz_ffi::pqzl::keygen(seed32).ok_or(Error::Argument)?;
    Ok([&key.pk[..], &op::open_kem_pk(ok)].concat())
}

/// [`crate::wallet::Wallet::pqz_scoped_key`].
pub(crate) fn derive(store: &Arc<SecretStore>, s: &Scope) -> wallet::Result<PqzKeyHandle> {
    crate::facade::release_or_unlocked()?;
    let id = KeyId::PqzScoped(s.account, s.index, s.ua, s.chain_uid, s.token, s.version);
    let (secret, public) = store.key(id, |seed| {
        let sec = secrets(seed, s);
        let public = publics(&sec)?;
        Ok((sec, public))
    })?;
    PqzKeyHandle::of(secret, &public, s)
}

fn amount(d: &[u8; 16]) -> u64 {
    d.iter().enumerate().map(|(i, x)| u64::from(*x) << (4 * i)).sum()
}

/// The 64-bit lanes of a stored part, exactly `L` bytes of them.
fn lanes<const L: usize>(p: &[u8], what: &'static str) -> Result<Box<[u8; L]>, Refused> {
    unpack(p).and_then(|v| v.into_boxed_slice().try_into().ok()).ok_or(Refused::Input(what))
}

impl PqzKeyHandle {
    fn of(secret: Handle, public: &[u8], s: &Scope) -> wallet::Result<Self> {
        let (pk, kem_pk) = public.split_at_checked(PK_BYTES).ok_or(Error::Argument)?;
        let (class, scope) = match s.token {
            Some(t) => (KeyClass::OffchainToken, t),
            None => (KeyClass::OffchainShared, [0u8; 20]),
        };
        let id = keccak(&[b"scaas.pqz3k.handle.v1", &s.chain_uid, &scope, &s.ua, &s.version.to_be_bytes()]);
        Ok(Self { class, scope, ua: s.ua, chain_uid: s.chain_uid, version: s.version, id,
            pk: Box::new(pk.try_into().map_err(|_| Error::Argument)?), kem_pk: kem_pk.to_vec(), secret,
            loads: AtomicU32::new(0), keygens: AtomicU32::new(0) })
    }

    pub fn class(&self) -> KeyClass {
        self.class
    }
    pub fn scope(&self) -> [u8; 20] {
        self.scope
    }
    pub fn version(&self) -> u64 {
        self.version
    }
    /// This key's PQZ public key `pk = A·s + e` (`PK_BYTES`), computed at derivation.
    pub fn pk(&self) -> Vec<u8> {
        self.pk.to_vec()
    }
    /// This record's opening KEM key `0x01 ‖ ek ‖ X25519 pk` (CTR-UA-32 scheme 1).
    pub fn open_kem_pk(&self) -> Vec<u8> {
        self.kem_pk.clone()
    }
    /// How many times the PQZ seed reached a closure through [`Self::with_secret_debit`].
    pub fn secret_loads(&self) -> u32 {
        self.loads.load(Ordering::SeqCst)
    }
    /// How many times it reached [`Self::with_secret_keygen`].
    pub fn keygens(&self) -> u32 {
        self.keygens.load(Ordering::SeqCst)
    }

    /// `f` over a copy of `at` of the slot, under a read lease of the store for the copy's whole use (T21 L82): `lock()` waits
    /// for it; the copy is wiped on return. `KeyRevoked` once the wallet was locked.
    fn leased<R>(&self, at: core::ops::Range<usize>, f: impl FnOnce(&[u8]) -> Result<R, Refused>) -> Result<R, Refused> {
        let _lease = self.secret.lease();
        let copy = self.secret.with(|s| s.get(at).map(|b| Zeroizing::new(b.to_vec()))).ok().flatten().ok_or(Refused::KeyRevoked)?;
        wallet::copied();
        f(&copy)
    }

    /// `keccak256(seed32)`: the KAT's view of the derivation, never the seed.
    pub fn seed_commitment(&self) -> Result<[u8; 32], Refused> {
        self.leased(SEED, |s| Ok(keccak(&[s])))
    }

    fn token_ok(&self, token: &[u8; 20]) -> bool {
        self.class == KeyClass::OffchainShared || *token == self.scope
    }

    /// K3-7 for `c`: the handle parses the blob, refuses a credit that is not this handle's (token, recipient, the recipient's
    /// key version `kv[0]`) or whose inputs are incomplete, then runs pqz-ffi `opening::check_recipient` with its opening KEM
    /// seed on the blob's own bytes, its own `pk` and `kemPk` and the auditor's keys as given. Every failure of the check is one
    /// outcome, skip; an acceptance is bound to the handle, the token, the index and `h(i)`.
    pub fn check(&self, c: &Credit) -> Result<Checked, Refused> {
        if slot_trivial(&c.slot) {
            return Err(Refused::Input("a TRIVIAL entry: accepted without a check"));
        }
        let Some((&0, data)) = c.code.split_first() else {
            return Err(Refused::Input("the blob's code starts with STOP"));
        };
        let blob = opening_blob(data, LAYOUT).ok_or(Refused::Input("not an opening op 1 blob of this set"))?;
        if !self.token_ok(&c.token) || blob.to_ua != self.ua || blob.kv[0] != self.version {
            return Err(Refused::NotThisHandle);
        }
        let u = lanes::<PK_BYTES>(blob.pu, "P(u)")?;
        let v_t = lanes::<128>(blob.pvt, "P(v_t)")?;
        let auditor = match (blob.pva, blob.o_a, c.auditor) {
            (Some(pva), Some(o_a), Some(a)) => {
                let pk: Box<[u8; PK_BYTES]> =
                    a.pk.to_vec().into_boxed_slice().try_into().map_err(|_| Refused::Input("the auditor's PQZ key length"))?;
                Some((a, pk, lanes::<128>(pva, "P(v_a)")?, o_a))
            }
            (Some(_), _, None) => return Err(Refused::Input("an audited leg without the auditor's keys")),
            _ => None,
        };
        let content = entry_hash(c.index, &c.slot, Some(c.code));
        let digits = self.leased(OPEN_KEM, |ok| {
            let ok: &[u8; 96] = ok.try_into().map_err(|_| Refused::KeyRevoked)?;
            let to = Party { ua: &self.ua, key_version: self.version, pk: &self.pk, kem_pk: &self.kem_pk, v: &v_t, opening: blob.o_t };
            let aud = auditor.as_ref().map(|(a, pk, v_a, o_a)| Party { ua: &a.ua, key_version: blob.kv[1], pk, kem_pk: a.kem_pk, v: v_a,
                opening: o_a });
            Ok(op::check_recipient(ok, &op::Credit { chain_uid: &self.chain_uid, token: &c.token, u: &u, to, auditor: aud }))
        })?;
        Ok(match digits {
            Some(d) => Checked::Accepted(Accepted { handle: self.id, token: c.token, index: c.index, content }, amount(&d)),
            None => Checked::Skip(Skip { index: c.index, entry_hash: content, reads: c.reads }),
        })
    }

    /// The skip marks a wallet may sign (Fable P2-1): every skip reproduced with reads at a finalized block from the node list in
    /// strict-majority mode, ascending; else `Unconfirmed` and no mark.
    pub fn marks(skips: &[Skip]) -> Result<Vec<u64>, Refused> {
        if skips.iter().any(|s| !(s.reads.finalized && s.reads.strict_majority)) {
            return Err(Refused::Unconfirmed);
        }
        let mut m: Vec<u64> = skips.iter().map(|s| s.index).collect();
        m.sort_unstable();
        m.dedup();
        Ok(m)
    }

    /// Spec §6, §14.18, T21 L43: the PQZ seed for one debit, its own part and its window together. Refused, in this order:
    /// another token than the handle's (`NotThisHandle`); `lastDebit > 0` without the own part (`OwnRequired`); an own part at
    /// `lastDebit = 0` (`Input`); no own part and no window entry (`EmptyDebit`); a window entry of another token, or neither
    /// skip-marked, TRIVIAL nor accepted by this handle with the same token, index and bytes (`Window`); then, with the seed
    /// copied under the store's lease, the own part's `ownTag` at counter `lastDebit − 1` not verifying in constant time
    /// (`OwnTag`). Only then `f(seed32)`, counted.
    pub fn with_secret_debit<R>(&self, d: &Debit, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Refused> {
        if !self.token_ok(&d.token) {
            return Err(Refused::NotThisHandle);
        }
        let counter = match (d.last_debit, &d.own) {
            (0, Some(_)) => return Err(Refused::Input("an own part on an account that never debited")),
            (0, None) if d.window.is_empty() => return Err(Refused::EmptyDebit),
            (0, None) => None,
            (_, None) => return Err(Refused::OwnRequired),
            (n, Some(_)) => Some(u32::try_from(n - 1).map_err(|_| Refused::Input("lastDebit − 1 at or above 2^32"))?),
        };
        for e in d.window {
            if e.token != d.token {
                return Err(Refused::Window);
            }
            if slot_marked(&e.slot) || slot_trivial(&e.slot) {
                continue;
            }
            let ok = matches!(e.accepted, Some(a) if a.handle == self.id && a.token == e.token && a.index == e.index
                && e.code.is_some() && a.content == entry_hash(e.index, &e.slot, e.code));
            if !ok {
                return Err(Refused::Window);
            }
        }
        self.leased(SEED, |s| {
            let seed: &[u8; 32] = s.try_into().map_err(|_| Refused::KeyRevoked)?;
            if let (Some(own), Some(ctr)) = (&d.own, counter) {
                // constant time (T21 L42): the tag gates the seed for a ciphertext a node supplies
                let want = own_tag(seed, &self.chain_uid, &d.token, &self.ua, ctr, own.pu, own.pvf);
                if !bool::from(want.ct_eq(&own.own_tag)) {
                    return Err(Refused::OwnTag);
                }
            }
            self.loads.fetch_add(1, Ordering::SeqCst);
            Ok(f(seed))
        })
    }

    /// The PQZ seed for key generation and the `R_REG` proof of this record's registration only (the binding's keygen and
    /// prover); counted apart. [`Self::pk`] gives the public key without it.
    pub fn with_secret_keygen<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Refused> {
        self.leased(SEED, |s| {
            let seed: &[u8; 32] = s.try_into().map_err(|_| Refused::KeyRevoked)?;
            self.keygens.fetch_add(1, Ordering::SeqCst);
            Ok(f(seed))
        })
    }
}

/// Test-only (feature `vectors`): handles in a store of their own (spec §8.2's ephemeral store), from the raw BIP-39 seed (the
/// same derivation as [`crate::wallet::Wallet::pqz_scoped_key`]) or from the two secrets (the rows of `opening.json` key by
/// KeyGen seed). A release build has neither (the `compile_fail` checks above).
#[cfg(feature = "vectors")]
impl PqzKeyHandle {
    pub fn vectors_from_seed(seed: &[u8; 64], s: &Scope) -> wallet::Result<Self> {
        Self::vectors_of(secrets(seed, s), s)
    }
    pub fn vectors_from_secrets(seed32: &[u8; 32], open_kem_seed: &[u8; 96], s: &Scope) -> wallet::Result<Self> {
        Self::vectors_of(Zeroizing::new([&seed32[..], &open_kem_seed[..]].concat()), s)
    }
    fn vectors_of(sec: Zeroizing<Vec<u8>>, s: &Scope) -> wallet::Result<Self> {
        let public = publics(&sec)?;
        Self::of(SecretStore::single(&sec)?, &public, s)
    }
}

impl core::fmt::Debug for PqzKeyHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqzKeyHandle").field("class", &self.class).field("scope", &self.scope).field("version", &self.version)
            .finish_non_exhaustive()
    }
}
