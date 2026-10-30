//! `webauthn-p256` (spec §3 row 1). Key data `x ‖ y ‖ rpIdHash` (96); `sig` = `abi.encode(bytes authenticatorData,
//! bytes clientDataJSON, bytes32 r, bytes32 s)` (the EVM encoding). The clientDataJSON grammar is EVM's
//! `WebAuthnClientData.parse` (NET-ALL-04) plus "no `topOrigin`" (NET-SOR-13); **no origin compare** (accounts.md
//! "Passkey id without origin"). The `SmartKeyAccount` parser is not reused: it compares an origin.
use soroban_sdk::{crypto::Hash, panic_with_error, Bytes, BytesN, Env};

use crate::{
    abi::{bytes_at, padded, put_bytes, put_word},
    Error,
};

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
// ponytail: clientDataJSON over 1 KiB is refused (browsers send ~100-250 B); raise if an authenticator needs more.
const MAX_CLIENT_DATA: usize = 1024;

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding of 32 bytes (43 characters).
pub fn b64url32(x: &[u8; 32]) -> [u8; 43] {
    let mut out = [0u8; 43];
    for (k, o) in out.iter_mut().enumerate() {
        let bit = 6 * k;
        let (i, sh) = (bit / 8, bit % 8);
        let pair = (x[i] as u16) << 8 | *x.get(i + 1).unwrap_or(&0) as u16;
        *o = B64[(pair >> (10 - sh) & 63) as usize];
    }
    out
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// `{"type":"webauthn.get","challenge":"<b64url(ua_msg)>","origin":"<any>"` then exactly `}`, or
/// `,"crossOrigin":false` followed by `}` or by `,` … `}`; no `"topOrigin"` member anywhere.
fn client_data_ok(cd: &[u8], ua_msg: &[u8; 32]) -> bool {
    const P1: &[u8] = b"{\"type\":\"webauthn.get\",\"challenge\":\"";
    const P2: &[u8] = b"\",\"origin\":\"";
    const CROSS_FALSE: &[u8] = b",\"crossOrigin\":false";
    let p = P1.len() + 43 + P2.len();
    let n = cd.len();
    if n < p + 2 || &cd[..P1.len()] != P1 || cd[P1.len()..P1.len() + 43] != b64url32(ua_msg) || &cd[P1.len() + 43..p] != P2 {
        return false;
    }
    let Some(end) = cd[p..].iter().position(|c| *c == b'"').map(|i| p + i) else { return false };
    if contains(&cd[end..], b"\"topOrigin\"") || end + 1 >= n {
        return false;
    }
    if cd[end + 1] == b'}' {
        return end + 2 == n;
    }
    let after = end + 1 + CROSS_FALSE.len();
    if after >= n || &cd[end + 1..after] != CROSS_FALSE {
        return false;
    }
    if cd[after] == b'}' {
        return after + 1 == n;
    }
    cd[after] == b',' && cd[n - 1] == b'}'
}

/// The `webauthn-p256` check of `sig` over `ua_msg`; panics on failure (`Pop` for the contract's own checks, a host
/// error for the P-256 verify, which also refuses high `s`, CAP-51).
pub fn check(env: &Env, key_data: &Bytes, ua_msg: &Hash<32>, sig: &Bytes) {
    if key_data.len() != 96 {
        panic_with_error!(env, Error::KeyData);
    }
    if sig.len() < 128 {
        panic_with_error!(env, Error::Pop);
    }
    let auth_data = bytes_at(env, sig, 0, 0);
    let client_data = bytes_at(env, sig, 0, 32);
    let rs: BytesN<64> = sig.slice(64..128).try_into().unwrap_or_else(|_| panic_with_error!(env, Error::Pop));
    // Canonical encoding only (owner 2026-10-30): re-encode and compare, so `pop` bytes (and `pop_hash`) are unique.
    let mut enc = Bytes::new(env);
    put_word(&mut enc, 128);
    put_word(&mut enc, 128 + 32 + padded(auth_data.len()));
    enc.append(&rs.clone().into());
    put_bytes(&mut enc, &auth_data);
    put_bytes(&mut enc, &client_data);
    if enc != *sig {
        panic_with_error!(env, Error::Pop);
    }
    let n = client_data.len() as usize;
    if auth_data.len() < 37 || auth_data.slice(0..32) != key_data.slice(64..96) || n > MAX_CLIENT_DATA {
        panic_with_error!(env, Error::Pop);
    }
    if auth_data.get_unchecked(32) & (FLAG_UP | FLAG_UV) != FLAG_UP | FLAG_UV {
        panic_with_error!(env, Error::Pop);
    }
    let mut buf = [0u8; MAX_CLIENT_DATA];
    client_data.copy_into_slice(&mut buf[..n]);
    if !client_data_ok(&buf[..n], &ua_msg.to_array()) {
        panic_with_error!(env, Error::Pop);
    }
    let mut key = Bytes::from_array(env, &[4u8]);
    key.append(&key_data.slice(0..64));
    let key: BytesN<65> = key.try_into().unwrap_or_else(|_| panic_with_error!(env, Error::KeyData));
    let mut signed = auth_data;
    signed.append(&env.crypto().sha256(&client_data).into());
    env.crypto().secp256r1_verify(&key, &env.crypto().sha256(&signed), &rs);
}
