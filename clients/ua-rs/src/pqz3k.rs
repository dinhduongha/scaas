// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ three-key model (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, CTR-PQZ-38, CTR-PQZ-40, CTR-PQZ-41), the parts a signer
//! reproduces without PQZ arithmetic: the scoped key seeds of `offchain-shared` / `offchain-token` (K3-2; with the opening only
//! inside [`PqzKeyHandle`]), the opening KEM seed (K3-6b), the leg seed (K3-4), an opening token's `memoHash` and `ownTag`, the
//! opening blob's fields, `h(i)` / `entriesHash` and the holder's `PqzRollOver` digest, the scoped key record digests. The key
//! handle itself (feature `pqz`, `handle.rs`; T21 O5 (b), owner 2026-11-16 "ok, as proposed") lives in the wallet's store and
//! runs the holder check (K3-7) through pqz-ffi `opening::check_recipient`. UNAUDITED.
use crate::keccak;

/// T21 O5 (owner 2026-11-16, "ok, as proposed"): the entry points that take or return a raw BIP-39-derived seed (the two raw
/// derivations) are `pub` under the test feature `vectors` only and `pub(crate)` otherwise; a wallet's key with the opening is
/// [`crate::wallet::Wallet::pqz_scoped_key`] (feature `pqz`). A release build cannot name them (the `compile_fail` checks on
/// [`PqzKeyHandle`]).
#[cfg(feature = "wallet")]
macro_rules! vectors_pub {
    ($(#[$m:meta])* fn $name:ident $($rest:tt)*) => {
        #[cfg(feature = "vectors")]
        $(#[$m])* pub fn $name $($rest)*
        #[cfg(not(feature = "vectors"))]
        #[allow(dead_code)]
        $(#[$m])* pub(crate) fn $name $($rest)*
    };
}
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
#[cfg(feature = "wallet")]
use zeroize::Zeroizing;

/// RFC 5869 HKDF-SHA256 of `L` bytes through `wallet::hkdf_sha256` (`Zeroizing`; T21 L39).
#[cfg(feature = "wallet")]
fn hkdf<const L: usize>(salt: &[u8], ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; L]> {
    let okm = crate::wallet::hkdf_sha256(ikm, salt, info, L).expect("L <= 255 * 32");
    let mut o = Zeroizing::new([0u8; L]);
    o.copy_from_slice(&okm);
    o
}

/// K3-2: the PQZ key seed of class `offchain-shared` (`token` `None`) or `offchain-token`, 32 bytes:
/// `HKDF-SHA256(ikm = BIP-39 seed, salt = "scaas.ua.pq.v1", info = label ‖ u32 account ‖ u32 index ‖ chainUid ‖ [token] ‖ be64 v)`.
/// Private (Fable P1-1 on CLI-SGN-51): a seed of a scope with the opening lives in a [`PqzKeyHandle`] only.
#[cfg(feature = "wallet")]
fn scoped_key_seed(seed: &[u8; 64], account: u32, index: u32, chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64)
    -> Zeroizing<[u8; 32]>
{
    let label: &[u8] = if token.is_some() { b"scaas.ua.pqz-mlwe.offchain-token.v1" } else { b"scaas.ua.pqz-mlwe.offchain-shared.v1" };
    let info = [label, &account.to_be_bytes(), &index.to_be_bytes(), chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    hkdf(b"scaas.ua.pq.v1", seed, &info)
}

#[cfg(feature = "wallet")]
vectors_pub! {
/// K3-2, class `offchain-token` of a token WITHOUT the opening only: the accepted exposure of CTR-PQZ-37 (owner 2026-11-13; the
/// wallet decrypts that token's credits as on `PRECOMPILE`). A token with the opening, and every `offchain-shared` key, go
/// through a [`PqzKeyHandle`]. `pub` under `vectors` only (T21 O5).
fn pqz_token_key_seed_without_opening(seed: &[u8; 64], account: u32, index: u32, chain_uid: &[u8; 32], token: &[u8; 20], v: u64)
    -> Zeroizing<[u8; 32]>
{
    scoped_key_seed(seed, account, index, chain_uid, Some(token), v)
}
}

#[cfg(feature = "wallet")]
vectors_pub! {
/// K3-6b: the opening KEM seed of a scoped record, 96 bytes (ML-KEM `d ‖ z`, then the X25519 secret). `pub` under `vectors`
/// only (T21 O5).
fn open_kem_seed(seed: &[u8; 64], ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> Zeroizing<[u8; 96]> {
    let label: &[u8] = if token.is_some() { b"scaas.kem.pqz-opening-token.1" } else { b"scaas.kem.pqz-opening.1" };
    let info = [label, ua, chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    hkdf(b"scaas.ua.kem.v1", seed, &info)
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
#[cfg(feature = "pqz")]
fn own_tag(seed32: &[u8; 32], chain_uid: &[u8; 32], token: &[u8; 20], from_ua: &[u8; 32], send_counter: u32, pu: &[u8], pvf: &[u8])
    -> [u8; 32]
{
    let k = hkdf::<32>(b"", seed32, b"PQZ/owntag/v1");
    let msg = [&chain_uid[..], token, from_ua, &send_counter.to_be_bytes(), &keccak(&[pu, pvf])].concat();
    crate::wallet::hmac_sha256(&k[..], &msg)
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

// ------------------------------------------------------------------ the key handle (T21 O5 (b); feature `pqz`)

#[cfg(feature = "pqz")]
mod handle;
#[cfg(feature = "pqz")]
pub use handle::*;
