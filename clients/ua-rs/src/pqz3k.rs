// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The PQZ three-key model (spec 2026-11-13 pqz-three-keys; CLI-SGN-50, CTR-PQZ-38, CTR-PQZ-40, CTR-PQZ-41), the parts a signer
//! reproduces without PQZ arithmetic: the scoped key seeds of `offchain-shared` / `offchain-token` (K3-2), the opening KEM seed
//! (K3-6b), the leg seed (K3-4), an opening token's `memoHash`, the holder's `PqzRollOver` digest. The sealed opening's KEM and
//! the holder check (K3-7) are pqz-ffi's (`opening`). UNAUDITED.
use crate::keccak;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

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
pub fn pqz_scoped_key_seed(seed: &[u8; 64], account: u32, index: u32, chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 32] {
    let label: &[u8] = if token.is_some() { b"scaas.ua.pqz-mlwe.offchain-token.v1" } else { b"scaas.ua.pqz-mlwe.offchain-shared.v1" };
    let info = [label, &account.to_be_bytes(), &index.to_be_bytes(), chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    let mut o = [0u8; 32];
    hkdf(b"scaas.ua.pq.v1", seed, &info, &mut o);
    o
}

/// K3-6b: the opening KEM seed of a scoped record, 96 bytes (ML-KEM `d ‖ z`, then the X25519 secret).
pub fn open_kem_seed(seed: &[u8; 64], ua: &[u8; 32], chain_uid: &[u8; 32], token: Option<&[u8; 20]>, v: u64) -> [u8; 96] {
    let label: &[u8] = if token.is_some() { b"scaas.kem.pqz-opening-token.1" } else { b"scaas.kem.pqz-opening.1" };
    let info = [label, ua, chain_uid, token.map_or(&[][..], |t| &t[..]), &v.to_be_bytes()].concat();
    let mut o = [0u8; 96];
    hkdf(b"scaas.ua.kem.v1", seed, &info, &mut o);
    o
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
