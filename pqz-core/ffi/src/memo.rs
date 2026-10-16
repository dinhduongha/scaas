//! The op 7 sender memo (P6-ANON plan §5.4, D11; CTR-PQZ-23 / CTR-ZTH-50 with M legs), feature `prove`:
//!
//! ```text
//! key  = HKDF-SHA256(IKM = pqzKeySeed, salt = ∅, info = "PQZ/memo/v1" ‖ chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt)  (32 B)
//! ks   = HKDF-Expand-SHA256(key, info = "PQZ/memo/ks/v1", L = 2 + 40·M)
//! memo = salt ‖ ((flags ‖ u8(M) ‖ (be8(a_j) ‖ toUA_j)_{j<M}) XOR ks)      flags bit0 = auditorOn      (18 + 40·M B)
//! ```
//!
//! `chainUid`, `token` (its low 20 bytes), `fromUA`, `sendCounter` (< 2^32) and `salt` (the low 16 bytes of the salt
//! word) are the op 7 header's words, so the sender rebuilds the memo key from its seed and chain data alone;
//! `memoHash = keccak256(memo)` goes into header word 19. No MAC (as classical): a wrong key or a tampered memo rebuilds
//! legs that miss the statement. The keystream label `"PQZ/memo/ks/v1"` (classical `"ZTX/memo/ks/v1"`) and the M
//! byte are controller proposals (decisions.md, P6-ANON S3), owner may override.
use hkdf::Hkdf;
use pqz_stmt::{word_u64, Word, H_CHAIN_UID, H_FROM, H_SALT, H_SEND_COUNTER, H_TOKEN};
use sha2::Sha256;

/// `18 + 40·M`
pub const fn memo_len(m: usize) -> usize {
    18 + 40 * m
}

fn stream(key_seed: &[u8], header: &[Word; 20], salt: &[u8], len: usize) -> Option<Vec<u8>> {
    let ctr = u32::try_from(word_u64(&header[H_SEND_COUNTER])?).ok()?;
    let info = [
        &b"PQZ/memo/v1"[..],
        &header[H_CHAIN_UID],
        &header[H_TOKEN][12..],
        &header[H_FROM],
        &ctr.to_be_bytes(),
        salt,
    ]
    .concat();
    let mut key = [0u8; 32];
    Hkdf::<Sha256>::new(None, key_seed).expand(&info, &mut key).ok()?;
    let mut ks = vec![0u8; len];
    Hkdf::<Sha256>::from_prk(&key).ok()?.expand(b"PQZ/memo/ks/v1", &mut ks).ok()?;
    Some(ks)
}

/// The memo of a transfer with `legs` = `(a_j, toUA_j)` in leg order under `header` (its salt, chainUid, token,
/// fromUA, sendCounter); `None` if `sendCounter ≥ 2^32` or M is 0 or over 255.
pub fn seal(key_seed: &[u8], header: &[Word; 20], aud: bool, legs: &[(u64, Word)]) -> Option<Vec<u8>> {
    let m = u8::try_from(legs.len()).ok().filter(|&m| m > 0)?;
    let mut plain = vec![aud as u8, m];
    for (a, ua) in legs {
        plain.extend_from_slice(&a.to_be_bytes());
        plain.extend_from_slice(ua);
    }
    let salt = &header[H_SALT][16..];
    let ks = stream(key_seed, header, salt, plain.len())?;
    let mut memo = salt.to_vec();
    memo.extend(plain.iter().zip(&ks).map(|(p, k)| p ^ k));
    Some(memo)
}

/// [`seal`] backwards (the salt from the memo, the rest of the key's inputs from `header`): `(auditorOn, legs)`;
/// `None` for a length that is not `18 + 40·M`, an M byte that disagrees with it, or a flags byte other than 0 / 1.
pub fn open(key_seed: &[u8], header: &[Word; 20], memo: &[u8]) -> Option<(bool, Vec<(u64, Word)>)> {
    if memo.len() < memo_len(1) || !(memo.len() - 18).is_multiple_of(40) {
        return None;
    }
    let ks = stream(key_seed, header, &memo[..16], memo.len() - 16)?;
    let plain: Vec<u8> = memo[16..].iter().zip(&ks).map(|(c, k)| c ^ k).collect();
    let (flags, m) = (plain[0], plain[1] as usize);
    if flags > 1 || memo_len(m) != memo.len() {
        return None;
    }
    let legs = plain[2..]
        .chunks_exact(40)
        .map(|c| (u64::from_be_bytes(c[..8].try_into().unwrap_or_default()), c[8..].try_into().unwrap_or_default()))
        .collect();
    Some((flags == 1, legs))
}
