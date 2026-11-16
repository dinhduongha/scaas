// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ three-key model (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, CTR-PQZ-38, CTR-PQZ-40, CTR-PQZ-41), the parts a signer
//! reproduces without PQZ arithmetic: the scoped key seeds of `offchain-shared` / `offchain-token` (K3-2; with the opening only
//! inside [`PqzKeyHandle`]), the opening KEM seed (K3-6b), the leg seed (K3-4), an opening token's `memoHash` and `ownTag`, the
//! opening blob's fields, `h(i)` / `entriesHash` and the holder's `PqzRollOver` digest, the scoped key record digests. The sealed
//! opening's KEM and the arithmetic of the holder check (K3-7) are pqz-ffi's (`opening`), run by the binding inside the
//! handle's gated entries. UNAUDITED.
use crate::keccak;
use hmac::{Hmac, Mac};

/// T21 O5 (owner 2026-11-16, "ok, as proposed"): the entry points that take or return a raw BIP-39-derived seed (the handle's
/// seed constructor, the two raw derivations) are `pub` under the test feature `vectors` only and `pub(crate)` otherwise; the
/// handle is SPECIFIED, not built in ua-rs (no `Wallet` method makes one; signers-clientkeys.md#CLI-SGN-51). A release build
/// cannot name them (the `compile_fail` checks on [`PqzKeyHandle`]).
macro_rules! vectors_pub {
    ($(#[$m:meta])* fn $name:ident $($rest:tt)*) => {
        #[cfg(feature = "vectors")]
        $(#[$m])* pub fn $name $($rest)*
        #[cfg(not(feature = "vectors"))]
        #[allow(dead_code)]
        $(#[$m])* pub(crate) fn $name $($rest)*
    };
}
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

/// Equality of two 32-byte words in constant time (T21 L42): every byte is folded, no early exit, and the fold is hidden from
/// the optimiser. `pqz3k` builds in every cell, `subtle` only with `pqz` (so the lockfiles over ua-rs stay as they are).
fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    core::hint::black_box(a.iter().zip(b).fold(0u8, |d, (x, y)| d | (x ^ y))) == 0
}

fn hmac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("any key length");
    for p in parts {
        Mac::update(&mut m, p);
    }
    m.finalize().into_bytes().into()
}

/// RFC 5869 HKDF-SHA256, `out.len() ≤ 255 · 32`.
fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac(salt, &[ikm]);
    let (mut t, mut done, mut i) = (Vec::new(), 0, 1u8);
    while done < out.len() {
        let b = hmac(&prk, &[&t, info, &[i]]);
        let n = (out.len() - done).min(32);
        out[done..done + n].copy_from_slice(&b[..n]);
        (t, done, i) = (b.to_vec(), done + n, i + 1);
    }
}

/// K3-2: the PQZ key seed of class `offchain-shared` (`token` `None`) or `offchain-token`, 32 bytes:
/// `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = label ‖ u32 account ‖ u32 index ‖ chainUid ‖ [token] ‖ be64 v)`.
/// Private (Fable P1-1 on CLI-SGN-51): a seed of a scope with the opening lives in a [`PqzKeyHandle`] only.
fn scoped_key_seed(seed: &[u8; 64], account: u32, index: u32, chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 32] {
    let label: &[u8] = if token.is_some() { b"scaas.ua.pqz-mlwe.offchain-token.v1" } else { b"scaas.ua.pqz-mlwe.offchain-shared.v1" };
    let info = [label, &account.to_be_bytes(), &index.to_be_bytes(), chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    let mut o = [0u8; 32];
    hkdf(b"scaas.ua.pq.v1", seed, &info, &mut o);
    o
}

vectors_pub! {
/// K3-2, class `offchain-token` of a token WITHOUT the opening only: the accepted exposure of CTR-PQZ-37 (owner 2026-11-13; the
/// wallet decrypts that token's credits as on `PRECOMPILE`). A token with the opening, and every `offchain-shared` key, go
/// through a [`PqzKeyHandle`]. `pub` under `vectors` only (T21 O5).
fn pqz_token_key_seed_without_opening(seed: &[u8; 64], account: u32, index: u32, chain_uid: &[u8; 32], token: &[u8; 20], v: u64)
    -> [u8; 32]
{
    scoped_key_seed(seed, account, index, chain_uid, Some(token), v)
}
}

vectors_pub! {
/// K3-6b: the opening KEM seed of a scoped record, 96 bytes (ML-KEM `d ‖ z`, then the X25519 secret). `pub` under `vectors`
/// only (T21 O5).
fn open_kem_seed(seed: &[u8; 64], ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 96] {
    let label: &[u8] = if token.is_some() { b"scaas.kem.pqz-opening-token.1" } else { b"scaas.kem.pqz-opening.1" };
    let info = [label, ua, chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    let mut o = [0u8; 96];
    hkdf(b"scaas.ua.kem.v1", seed, &info, &mut o);
    o
}
}

/// K3-4: `seed_leg = SHAKE256("SCAAS-PQZ-ENC-LEG-V1" ‖ seed_enc ‖ be4(0) ‖ toUA ‖ keccak256(pk_t))[0..32)`, `keccak256(pk_t)` given.
pub fn leg_seed(seed_enc: &[u8; 32], to_ua: &[u8; 32], pk_t_hash: &[u8; 32]) -> [u8; 32] {
    let mut x = Shake256::default();
    for p in [&b"SCAAS-PQZ-ENC-LEG-V1"[..], seed_enc, &[0u8; 4], to_ua, pk_t_hash] {
        x.update(p);
    }
    let mut o = [0u8; 32];
    x.finalize_xof().read(&mut o);
    o
}

/// CTR-PQZ-40: an opening token's op 1 `memoHash = keccak256(memo ‖ ownTag ‖ keccak256(O_t ‖ [O_a]))`.
pub fn opening_memo_hash(memo: &[u8], own_tag: &[u8; 32], openings: &[&[u8]]) -> [u8; 32] {
    keccak(&[memo, own_tag, &keccak(openings)])
}

/// CTR-PQZ-41: `PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,bytes32 entriesHash,
/// uint64 validUntilBlock,bytes32 chainUid)`, signed by the holder under `zether-auth` in the token's domain.
pub const ROLL_OVER_TYPE: &str = "PqzRollOver(bytes32 ua,uint64 keyVersion,uint64 rollSeq,uint64 rolled,uint64 n,uint64[] skip,\
bytes32 entriesHash,uint64 validUntilBlock,bytes32 chainUid)";

fn w64(x: u64) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&x.to_be_bytes());
    w
}

/// The `PqzRollOver` struct hash: `rollSeq` and `rolled` the token's `pqzAccount(ua, keyVersion)`, `entriesHash` over the
/// entries' contents (`h(i) = keccak256(abi.encode(i, slot without the mark, blob code hash or 0))`).
#[allow(clippy::too_many_arguments)]
pub fn roll_over_struct_hash(ua: &[u8; 32], key_version: u64, roll_seq: u64, rolled: u64, n: u64, skip: &[u64], entries_hash: &[u8; 32],
    valid_until_block: u64, chain_uid: &[u8; 32]) -> [u8; 32] {
    let sk: Vec<u8> = skip.iter().flat_map(|s| w64(*s)).collect();
    keccak(&[&keccak(&[ROLL_OVER_TYPE.as_bytes()]), ua, &w64(key_version), &w64(roll_seq), &w64(rolled), &w64(n), &keccak(&[&sk]),
        entries_hash, &w64(valid_until_block), chain_uid])
}

// ------------------------------------------------------------------ entries and the opening blob (Fable P2-1, P2-2)

/// The skip mark (CTR-PQZ-41): bit 63 of a pending slot's `block` field.
pub const SKIP: u64 = 1 << 63;
/// One stored opening `mlkemCt(1568) ‖ x25519Eph(32) ‖ sealedSeed(48)`.
pub const OPENING: usize = 1648;

/// A pending slot word `blob(160) ‖ offset(16) ‖ length(16) ‖ block(64)` (big-endian, as `pqzPending` returns it).
fn slot_block(slot: &[u8; 32]) -> u64 {
    u64::from_be_bytes(slot[24..].try_into().expect("8 bytes"))
}
/// The slot is skip-marked.
pub fn slot_marked(slot: &[u8; 32]) -> bool {
    slot_block(slot) & SKIP != 0
}
/// The slot is a TRIVIAL entry (no blob: length 0).
pub fn slot_trivial(slot: &[u8; 32]) -> bool {
    slot[22] == 0 && slot[23] == 0
}
fn slot_unmarked(slot: &[u8; 32]) -> [u8; 32] {
    let mut s = *slot;
    s[24] &= 0x7f;
    s
}

/// CTR-PQZ-41 `h(i) = keccak256(abi.encode(i, slot with the mark cleared, keccak256(code) or 0 for a TRIVIAL entry))`, `code` the
/// blob's code (`STOP ‖ data`) as the wallet read and checked it: the wallet hashes the bytes itself and never takes a node's
/// code-hash answer (Fable P2-1).
pub fn entry_hash(index: u64, slot: &[u8; 32], code: Option<&[u8]>) -> [u8; 32] {
    let c = if slot_trivial(slot) { [0u8; 32] } else { keccak(&[code.unwrap_or_default()]) };
    keccak(&[&w64(index), &slot_unmarked(slot), &c])
}
/// `entriesHash = keccak256(h(rolled) ‖ … ‖ h(rolled + n − 1) ‖ h(skip_0) ‖ …)`.
pub fn entries_hash(hs: &[[u8; 32]]) -> [u8; 32] {
    let refs: Vec<&[u8]> = hs.iter().map(|h| &h[..]).collect();
    keccak(&refs)
}

/// A set's packed sizes (P46): `P(u)` = `n · b / 8` bytes, `P(v)` = `16 · b / 8`, `b` = `PACK_BITS`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub pkp: usize,
    pub vp: usize,
}
impl Layout {
    pub const fn of(n: usize, pack_bits: usize) -> Self {
        Self { pkp: n * pack_bits / 8, vp: 16 * pack_bits / 8 }
    }
}

/// An opening token's op 1 blob (CTR-PQZ-40): `salt(16) ‖ P(u) ‖ P(v_t) ‖ [P(v_a)] ‖ toUA ‖ P(u_f) ‖ P(v_f) ‖ O_t ‖ [O_a] ‖ ownTag ‖
/// be64 kv[0..n) ‖ u8(n)`, `n` 1 (no auditor) or 2; `kv[0]` the recipient's key version, `kv[1]` the auditor's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningBlob<'a> {
    pub salt: &'a [u8],
    pub pu: &'a [u8],
    pub pvt: &'a [u8],
    pub pva: Option<&'a [u8]>,
    pub to_ua: [u8; 32],
    pub puf: &'a [u8],
    pub pvf: &'a [u8],
    pub o_t: &'a [u8],
    pub o_a: Option<&'a [u8]>,
    pub own_tag: [u8; 32],
    pub kv: Vec<u64>,
}

/// The fields of an opening blob's data (the code after its STOP byte); `None` for any other length or `n`.
pub fn opening_blob(data: &[u8], l: Layout) -> Option<OpeningBlob<'_>> {
    let n = *data.last()? as usize;
    if n != 1 && n != 2 || data.len() != 16 + 2 * l.pkp + (n + 1) * l.vp + 32 + n * OPENING + 33 + 8 * n {
        return None;
    }
    let mut at = 0;
    let mut take = |k: usize| {
        let s = &data[at..at + k];
        at += k;
        s
    };
    let (salt, pu, pvt) = (take(16), take(l.pkp), take(l.vp));
    let pva = (n == 2).then(|| take(l.vp));
    let to_ua = take(32).try_into().ok()?;
    let (puf, pvf, o_t) = (take(l.pkp), take(l.vp), take(OPENING));
    let o_a = (n == 2).then(|| take(OPENING));
    let own_tag = take(32).try_into().ok()?;
    let kv = (0..n).map(|_| u64::from_be_bytes(take(8).try_into().expect("8 bytes"))).collect();
    Some(OpeningBlob { salt, pu, pvt, pva, to_ua, puf, pvf, o_t, o_a, own_tag, kv })
}

/// CTR-PQZ-40: the sealed seed's `aad = chainUid ‖ token(20) ‖ ua ‖ be8(keyVersion) ‖ keccak256(P(u) ‖ P(v))`.
pub fn opening_aad(chain_uid: &[u8; 32], token: &[u8; 20], ua: &[u8; 32], key_version: u64, pu: &[u8], pv: &[u8]) -> Vec<u8> {
    [&chain_uid[..], token, ua, &key_version.to_be_bytes(), &keccak(&[pu, pv])].concat()
}

/// CTR-PQZ-34 / K3-2 (with the opening: over `u_f`): `ownTag = HMAC-SHA256(K, chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖
/// keccak256(P(u) ‖ P(v_f)))`, `K = HKDF-SHA256(ikm = seed32, salt = ∅, info = "PQZ/owntag/v1")`.
fn own_tag(seed32: &[u8; 32], chain_uid: &[u8; 32], token: &[u8; 20], from_ua: &[u8; 32], send_counter: u32, pu: &[u8], pvf: &[u8])
    -> [u8; 32]
{
    let mut k = [0u8; 32];
    hkdf(b"", seed32, b"PQZ/owntag/v1", &mut k);
    let t = hmac(&k, &[chain_uid, token, from_ua, &send_counter.to_be_bytes(), &keccak(&[pu, pvf])]);
    k.fill(0);
    t
}

// ------------------------------------------------------------------ scoped key records (K3-3, CTR-UA-43; Fable P2-2)

pub const SCOPED_KEY_TYPE: &str = "UAPqzScopedKey(bytes32 ua,uint8 keyClass,bytes32 chainUid,address token,uint64 version,bytes32 pqzKeyHash)";
pub const SCOPED_KEY_RECORD_TYPE: &str = "UAPqzScopedKeyRecord(bytes32 ua,uint8 keyClass,bytes32 chainUid,address token,uint64 version,\
bytes32 pqzKeyHash,bytes32 pqzPopHash,bytes32 openKemHash,uint64 validUntilBlock)";

fn portable(struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], &crate::ua8::PORTABLE_DOMAIN_SEPARATOR, struct_hash])
}
fn addr_word(a: &[u8; 20]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[12..].copy_from_slice(a);
    w
}
/// `keccak256("scaas.ua.purpose.pqz-scoped-key.v1")`.
pub fn purpose_pqz_scoped_key() -> [u8; 32] {
    keccak(&[b"scaas.ua.purpose.pqz-scoped-key.v1"])
}
/// typed(`UAPqzScopedKey`): what a scoped key's `R_REG` proves over, as `uaMessage(0x0142, PURPOSE_PQZ_SCOPED_KEY, ·)`;
/// `key_class` 2 (`token` zero) or 3.
pub fn scoped_key_digest(ua: &[u8; 32], key_class: u8, chain_uid: &[u8; 32], token: &[u8; 20], version: u64, pqz_key_hash: &[u8; 32])
    -> [u8; 32]
{
    portable(&keccak(&[&keccak(&[SCOPED_KEY_TYPE.as_bytes()]), ua, &w64(key_class as u64), chain_uid, &addr_word(token), &w64(version),
        pqz_key_hash]))
}
/// typed(`UAPqzScopedKeyRecord`): what `setPqzScopedKey`'s `sig` signs, as `uaMessage(kind, PURPOSE_PQZ_SCOPED_KEY, ·)`;
/// `open_kem_hash = keccak256(kemPk)` of the opening KEM key, 0 without one.
#[allow(clippy::too_many_arguments)]
pub fn scoped_key_record_digest(ua: &[u8; 32], key_class: u8, chain_uid: &[u8; 32], token: &[u8; 20], version: u64,
    pqz_key_hash: &[u8; 32], pqz_pop_hash: &[u8; 32], open_kem_hash: &[u8; 32], valid_until_block: u64) -> [u8; 32]
{
    portable(&keccak(&[&keccak(&[SCOPED_KEY_RECORD_TYPE.as_bytes()]), ua, &w64(key_class as u64), chain_uid, &addr_word(token),
        &w64(version), pqz_key_hash, pqz_pop_hash, open_kem_hash, &w64(valid_until_block)]))
}

// ------------------------------------------------------------------ the key handle (owner 2026-11-14; Fable P1-1)

/// A PQZ key class with the opening (CTR-PQZ-37): `offchain-shared` (class 2) or `offchain-token` on a token with the opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyClass {
    OffchainShared,
    OffchainToken,
}

/// Why the handle refused, before any secret was derived for the call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A credit or blob of another token (class 3), recipient or key version than the handle's.
    NotThisHandle,
    /// The inputs are missing or malformed locally (a blob of another length, a TRIVIAL entry, no auditor keys for an audited
    /// leg): an error before the check, never a skip (Fable P2-1).
    Input(&'static str),
    /// A window entry that is not accepted by this handle, TRIVIAL or skip-marked (spec §6, §14.18).
    Window,
    /// The `ownTag` of the holder's own ciphertext does not verify under this handle's key.
    OwnTag,
    /// A skip that is not reproduced at a finalized block with strict-majority reads (Fable P2-1): no mark.
    Unconfirmed,
}

/// How the wallet read the state a check used (ARCH-POS-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reads {
    pub block: u64,
    pub finalized: bool,
    pub strict_majority: bool,
}

/// The auditor's public inputs of an audited leg, read by the wallet from the registry: its key at the leg's version (`kv[1]`)
/// and its opening KEM key of that version.
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

/// What the binding's K3-7 check gets besides the opening KEM seed; every `aad` built by the handle from the credit's own bytes.
#[derive(Debug)]
pub struct CheckInput<'a> {
    pub blob: OpeningBlob<'a>,
    pub aad_recipient: Vec<u8>,
    pub aad_auditor: Option<Vec<u8>>,
    pub auditor: Option<AuditorKeys<'a>>,
}

/// An accepted credit, made by [`PqzKeyHandle::check`] only: bound to the handle, the index and `h(i)` (slot and blob bytes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    handle: [u8; 32],
    index: u64,
    content: [u8; 32],
}
impl Accepted {
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

/// The check's outcome: accepted (with the binding's value, the amount) or skip.
#[derive(Debug, PartialEq, Eq)]
pub enum Checked<T> {
    Accepted(Accepted, T),
    Skip(Skip),
}

/// A window entry for [`PqzKeyHandle::with_secret_window`]: the slot as read, the blob's code for a credit, and its acceptance.
#[derive(Clone, Copy, Debug)]
pub struct WindowEntry<'a> {
    pub index: u64,
    pub slot: [u8; 32],
    pub code: Option<&'a [u8]>,
    pub accepted: Option<&'a Accepted>,
}

/// The holder's own ciphertext `(u_f, v_f)` (or a burn's `(u′, v_f)`) with its `ownTag` and the debit's `sendCounter`.
#[derive(Clone, Copy, Debug)]
pub struct Own<'a> {
    pub token: [u8; 20],
    pub send_counter: u32,
    pub pu: &'a [u8],
    pub pvf: &'a [u8],
    pub own_tag: [u8; 32],
}

/// Owner ruling 2026-11-14 (CLI-SGN-51's Change: "no bare class-2 decrypt", enforced in the clients; spec §6, §14.1, §14.18;
/// Fable P1-1): the wallet's handle of one PQZ key with the opening, `offchain-shared` or `offchain-token` of a token with the
/// opening, at one key version. It derives and holds that key's PQZ seed and its opening KEM seed; no method returns either.
/// The PQZ seed reaches a closure only through three gated entries, each counted: [`Self::with_secret_own`] after the
/// holder's own `ownTag` verifies, [`Self::with_secret_window`] when every window entry is accepted by this handle, TRIVIAL
/// or skip-marked, and [`Self::with_secret_keygen`] (the public key and the `R_REG` proof of registration). [`Self::check`]
/// hands the opening KEM seed to the binding's K3-7 check (pqz-ffi `opening::check_recipient`) with the `aad` the handle
/// builds, and returns an acceptance bound to the entry's bytes. UNAUDITED.
#[cfg_attr(not(feature = "vectors"), doc = r#"
A release build names no raw-seed entry point (T21 O5; positive control first):
```
let _ = scaas_ua::pqz3k::Layout::of(2304, 46);
```
```compile_fail,E0624
let _ = scaas_ua::pqz3k::PqzKeyHandle::new(&[0; 64], 0, 0, &[0; 32], &[0; 32], None, 0, scaas_ua::pqz3k::Layout::of(2304, 46));
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
    layout: Layout,
    id: [u8; 32],
    pqz_seed: [u8; 32],
    open_kem_seed: [u8; 96],
    loads: core::cell::Cell<u32>,
    keygens: core::cell::Cell<u32>,
}

impl PqzKeyHandle {
    vectors_pub! {
    /// `token` `None`: `offchain-shared`; `Some`: `offchain-token` of that token, which must carry the opening (a token without
    /// it uses `pqz_token_key_seed_without_opening`). From the raw BIP-39 seed: `pub` under `vectors` only (T21 O5).
    #[allow(clippy::too_many_arguments)]
    fn new(seed: &[u8; 64], account: u32, index: u32, ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, version: u64,
        layout: Layout) -> Self
    {
        let (class, scope) = match token {
            Some(t) => (KeyClass::OffchainToken, *t),
            None => (KeyClass::OffchainShared, [0u8; 20]),
        };
        let id = keccak(&[b"scaas.pqz3k.handle.v1", chain_uid, &scope, ua, &version.to_be_bytes()]);
        Self { class, scope, ua: *ua, chain_uid: *chain_uid, version, layout, id,
            pqz_seed: scoped_key_seed(seed, account, index, chain_uid, token, version),
            open_kem_seed: open_kem_seed(seed, ua, chain_uid, token, version),
            loads: core::cell::Cell::new(0), keygens: core::cell::Cell::new(0) }
    }
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
    /// How many times the PQZ seed reached a closure through [`Self::with_secret_own`] or [`Self::with_secret_window`].
    pub fn secret_loads(&self) -> u32 {
        self.loads.get()
    }
    /// How many times it reached [`Self::with_secret_keygen`].
    pub fn keygens(&self) -> u32 {
        self.keygens.get()
    }
    /// `keccak256(seed32)`: the KAT's view of the derivation, never the seed.
    pub fn seed_commitment(&self) -> [u8; 32] {
        keccak(&[&self.pqz_seed])
    }

    fn token_ok(&self, token: &[u8; 20]) -> bool {
        self.class == KeyClass::OffchainShared || *token == self.scope
    }

    /// The K3-7 holder check of `c` by the binding's `check(open_kem_seed, input)`; the handle first parses the blob, refuses a
    /// credit that is not this handle's (token, recipient, the recipient's key version `kv[0]`) or whose inputs are incomplete,
    /// and builds both `aad`s from the blob's own bytes. `Some(value)` from the check is an acceptance, `None` a skip.
    pub fn check<T>(&self, c: &Credit, check: impl FnOnce(&[u8; 96], &CheckInput) -> Option<T>) -> Result<Checked<T>, Refused> {
        if slot_trivial(&c.slot) {
            return Err(Refused::Input("a TRIVIAL entry: accepted without a check"));
        }
        if c.code.first() != Some(&0) {
            return Err(Refused::Input("the blob's code starts with STOP"));
        }
        let blob = opening_blob(&c.code[1..], self.layout).ok_or(Refused::Input("not an opening op 1 blob of this set"))?;
        if !self.token_ok(&c.token) || blob.to_ua != self.ua || blob.kv[0] != self.version {
            return Err(Refused::NotThisHandle);
        }
        let aad_recipient = opening_aad(&self.chain_uid, &c.token, &self.ua, self.version, blob.pu, blob.pvt);
        let aad_auditor = match (blob.pva, c.auditor) {
            (Some(pva), Some(a)) => Some(opening_aad(&self.chain_uid, &c.token, &a.ua, blob.kv[1], blob.pu, pva)),
            (Some(_), None) => return Err(Refused::Input("an audited leg without the auditor's keys")),
            (None, _) => None,
        };
        let content = entry_hash(c.index, &c.slot, Some(c.code));
        let auditor = if aad_auditor.is_some() { c.auditor } else { None };
        let input = CheckInput { blob, aad_recipient, aad_auditor, auditor };
        Ok(match check(&self.open_kem_seed, &input) {
            Some(v) => Checked::Accepted(Accepted { handle: self.id, index: c.index, content }, v),
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

    /// Spec §6: the PQZ seed for the holder's own ciphertext, after its `ownTag` verifies under this handle's key.
    pub fn with_secret_own<R>(&self, own: &Own, f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Refused> {
        if !self.token_ok(&own.token) {
            return Err(Refused::NotThisHandle);
        }
        // constant time, as path (B)'s `ct_eq` (T21 L42): the tag gates the seed for a ciphertext a node supplies
        let want = own_tag(&self.pqz_seed, &self.chain_uid, &own.token, &self.ua, own.send_counter, own.pu, own.pvf);
        if !ct_eq32(&want, &own.own_tag) {
            return Err(Refused::OwnTag);
        }
        self.loads.set(self.loads.get() + 1);
        Ok(f(&self.pqz_seed))
    }

    /// Spec §6, §14.18: the PQZ seed for a debit's window, only when every entry is skip-marked, TRIVIAL, or accepted by this
    /// handle with the same index and bytes; else `Window`, before the seed is touched.
    pub fn with_secret_window<R>(&self, entries: &[WindowEntry], f: impl FnOnce(&[u8; 32]) -> R) -> Result<R, Refused> {
        for e in entries {
            if slot_marked(&e.slot) || slot_trivial(&e.slot) {
                continue;
            }
            let ok = matches!(e.accepted, Some(a) if a.handle == self.id && a.index == e.index
                && e.code.is_some() && a.content == entry_hash(e.index, &e.slot, e.code));
            if !ok {
                return Err(Refused::Window);
            }
        }
        self.loads.set(self.loads.get() + 1);
        Ok(f(&self.pqz_seed))
    }

    /// The PQZ seed for key generation and the `R_REG` proof of this record's registration only (the binding's keygen and
    /// prover); counted apart.
    pub fn with_secret_keygen<R>(&self, f: impl FnOnce(&[u8; 32]) -> R) -> R {
        self.keygens.set(self.keygens.get() + 1);
        f(&self.pqz_seed)
    }
}

impl core::fmt::Debug for PqzKeyHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PqzKeyHandle").field("class", &self.class).field("scope", &self.scope).field("version", &self.version)
            .finish_non_exhaustive()
    }
}

impl Drop for PqzKeyHandle {
    fn drop(&mut self) {
        self.pqz_seed.fill(0);
        self.open_kem_seed.fill(0);
        core::hint::black_box((&self.pqz_seed, &self.open_kem_seed)); // keep the wipe
    }
}
