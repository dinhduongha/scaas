//! Solidity ABI words: the stored `msig` `pop` = `abi.encode(MemberSig[])` (`{u16 index, bytes keyData, bytes sig}`,
//! UA8-D5; `registration_of` returns EVM's bytes) and the dynamic `bytes` of the WebAuthn signature blob. Every refusal
//! is `Pop`.
use scaas_ua_common::MemberSig;
use soroban_sdk::{panic_with_error, Bytes, Env, Vec};

use crate::Error;

#[cfg(test)]
const MAX_MEMBERS: u32 = 16;

/// The 32-byte big-endian word at `off` as a `u32`; a word above `u32::MAX` is refused.
pub fn word(env: &Env, b: &Bytes, off: u32) -> u32 {
    let end = off.checked_add(32).filter(|e| *e <= b.len()).unwrap_or_else(|| panic_with_error!(env, Error::Pop));
    let mut w = [0u8; 32];
    b.slice(off..end).copy_into_slice(&mut w);
    if w[..28] != [0u8; 28] {
        panic_with_error!(env, Error::Pop);
    }
    u32::from_be_bytes([w[28], w[29], w[30], w[31]])
}

/// The dynamic `bytes` whose offset word sits at `head`, the offset relative to `base`; bounds-checked.
pub fn bytes_at(env: &Env, b: &Bytes, base: u32, head: u32) -> Bytes {
    let o = base.checked_add(word(env, b, head)).unwrap_or_else(|| panic_with_error!(env, Error::Pop));
    let n = word(env, b, o);
    let end = (o + 32).checked_add(n).filter(|e| *e <= b.len()).unwrap_or_else(|| panic_with_error!(env, Error::Pop));
    b.slice(o + 32..end)
}

pub fn put_word(out: &mut Bytes, v: u32) {
    let mut w = [0u8; 32];
    w[28..].copy_from_slice(&v.to_be_bytes());
    out.extend_from_slice(&w);
}

pub fn padded(n: u32) -> u32 {
    n.div_ceil(32) * 32
}

pub fn put_bytes(out: &mut Bytes, b: &Bytes) {
    put_word(out, b.len());
    out.append(b);
    out.extend_from_slice(&[0u8; 32][..(padded(b.len()) - b.len()) as usize]);
}

/// `abi.encode(MemberSig[])`, EVM's stored `pop`; empty for no slots (EVM: `pop` = "").
pub fn encode_member_sigs(env: &Env, sigs: &Vec<MemberSig>) -> Bytes {
    let mut enc = Bytes::new(env);
    if sigs.is_empty() {
        return enc;
    }
    put_word(&mut enc, 32);
    put_word(&mut enc, sigs.len());
    let mut off = 32 * sigs.len();
    for m in sigs.iter() {
        put_word(&mut enc, off);
        off += 96 + 32 + padded(m.key_data.len()) + 32 + padded(m.sig.len());
    }
    for m in sigs.iter() {
        put_word(&mut enc, m.index);
        put_word(&mut enc, 96);
        put_word(&mut enc, 96 + 32 + padded(m.key_data.len()));
        put_bytes(&mut enc, &m.key_data);
        put_bytes(&mut enc, &m.sig);
    }
    enc
}

/// Decodes `abi.encode(MemberSig[])`, canonical only (re-encoded and compared). Test-only since the entries take typed
/// `MemberSig`s: it reads the vectors' `pop` bytes and pins `encode_member_sigs`.
#[cfg(test)]
pub fn decode_member_sigs(env: &Env, b: &Bytes) -> Vec<MemberSig> {
    let n = word(env, b, 32);
    if word(env, b, 0) != 32 || n > MAX_MEMBERS {
        panic_with_error!(env, Error::Pop);
    }
    let mut out: Vec<MemberSig> = Vec::new(env);
    for i in 0..n {
        let t = 64 + word(env, b, 64 + 32 * i);
        let index = word(env, b, t);
        let last = out.last().map(|m| m.index as i64).unwrap_or(-1);
        if index > 0xFFFF || (index as i64) <= last {
            panic_with_error!(env, Error::Pop);
        }
        out.push_back(MemberSig { index, key_data: bytes_at(env, b, t, t + 32), sig: bytes_at(env, b, t, t + 64) });
    }
    if encode_member_sigs(env, &out) != *b {
        panic_with_error!(env, Error::Pop);
    }
    out
}
