//! Chữ ký chủ thể (spec §4): bytes ký cố định, văn bản `"<domain>:" ‖ hex(sha256)`, phong bì ed25519 raw / OCMS v1,
//! passkey WebAuthn — kiểm bằng introspection precompile Ed25519 / Secp256r1 (RS12-9, RS12-10).
use anchor_lang::prelude::*;
use solana_instructions_sysvar::{load_current_index_checked, load_instruction_at_checked};

use crate::state::{AuthKey, SCHEME_ED25519, SCHEME_P256};
use crate::ScaasError;

pub const ED25519_PROGRAM: Pubkey = pubkey!("Ed25519SigVerify111111111111111111111111111");
pub const SECP256R1_PROGRAM: Pubkey = pubkey!("Secp256r1SigVerify1111111111111111111111111");

pub const METAOP_LABEL: &str = "scaas.metaop.v1";
pub const KEYOP_LABEL: &str = "scaas.keyop.v1";
pub const MANDATE_LABEL: &str = "scaas.mandate.v1";
pub const MCLOSE_LABEL: &str = "scaas.mclose.v1";
pub const ORDER_LABEL: &str = "scaas.order.v1";
pub const CANCEL_LABEL: &str = "scaas.cancel.v1";
pub const MINNONCE_LABEL: &str = "scaas.minnonce.v1";

pub const OP_PAY: u8 = 0;
pub const OP_MANDATE_PAY: u8 = 2;
pub const OP_REVOKE: u8 = 3;

pub const KIND_RAW: u8 = 0;
pub const KIND_OCMS: u8 = 1;
pub const KIND_PASSKEY: u8 = 2;

/// Offchain message signing domain (`@solana/offchain-messages`), v1 = version byte 1, one signatory.
const OCMS_DOMAIN: &[u8; 16] = b"\xffsolana offchain";

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    solana_sha256_hasher::hashv(parts).to_bytes()
}

/// Bằng chứng chữ ký đi kèm instruction: chỉ số instruction precompile trong tx + chỉ số chữ ký trong nó.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct Auth {
    pub kind: u8,
    pub key_index: u8,
    pub precompile_ix: u8,
    pub sig_index: u8,
    /// clientDataJSON (chỉ `kind 2`).
    pub cdj: Vec<u8>,
}

/// `MetaOp` v1 — 336 byte cố định (spec §4.1).
pub struct MetaOp {
    pub network: [u8; 32],
    pub contract: [u8; 32],
    pub asset: [u8; 32],
    pub op: u8,
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub amount: u64,
    pub pay_ref: [u8; 32],
    pub lane: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub relayer: [u8; 32],
    pub extra: [u8; 32],
}

impl MetaOp {
    pub const LEN: usize = 336;

    pub fn bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(Self::LEN);
        b.extend_from_slice(METAOP_LABEL.as_bytes());
        b.extend_from_slice(&self.network);
        b.extend_from_slice(&self.contract);
        b.extend_from_slice(&self.asset);
        b.push(self.op);
        b.extend_from_slice(&self.from);
        b.extend_from_slice(&self.to);
        b.extend_from_slice(&(self.amount as u128).to_le_bytes());
        b.extend_from_slice(&self.pay_ref);
        b.extend_from_slice(&self.lane);
        b.extend_from_slice(&self.nonce.to_le_bytes());
        b.extend_from_slice(&self.valid_until.to_le_bytes());
        b.extend_from_slice(&self.relayer);
        b.extend_from_slice(&self.extra);
        b
    }

    pub fn digest(&self) -> [u8; 32] {
        sha256(&[&self.bytes()])
    }
}

/// `"<label>:" ‖ hex(digest)` (hex chữ thường).
pub fn text(label: &str, digest: &[u8; 32]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut t = Vec::with_capacity(label.len() + 65);
    t.extend_from_slice(label.as_bytes());
    t.push(b':');
    for b in digest {
        t.push(HEX[(b >> 4) as usize]);
        t.push(HEX[(b & 15) as usize]);
    }
    t
}

/// Offchain message v1 với một người ký: `"\xffsolana offchain" ‖ 1 ‖ 1 ‖ pk ‖ text`.
pub fn ocms(pk: &[u8], text: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(50 + text.len());
    m.extend_from_slice(OCMS_DOMAIN);
    m.push(1);
    m.push(1);
    m.extend_from_slice(pk);
    m.extend_from_slice(text);
    m
}

/// base64url không padding.
pub fn b64url(b: &[u8]) -> Vec<u8> {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut o = Vec::with_capacity(b.len().div_ceil(3) * 4);
    for c in b.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        let k = c.len() + 1;
        for i in 0..k {
            o.push(T[(n >> (18 - 6 * i) & 63) as usize]);
        }
    }
    o
}

fn u16_at(d: &[u8], i: usize) -> Result<usize> {
    let b = d.get(i..i + 2).ok_or(ScaasError::BadPrecompile)?;
    Ok(u16::from_le_bytes([b[0], b[1]]) as usize)
}

/// Chữ ký `sig_index` trong data của instruction precompile (bố cục chung Ed25519/Secp256r1: `num u8, pad u8,
/// {sig_off, sig_ix, pk_off, pk_ix, msg_off, msg_len, msg_ix: u16}`). Mọi `*_instruction_index` PHẢI là `u16::MAX`
/// (dữ liệu nằm trong chính instruction precompile) — trỏ sang instruction khác ⇒ từ chối (RS12-10).
fn entry(data: &[u8], sig_index: u8, pk_len: usize) -> Result<(&[u8], &[u8])> {
    let n = *data.first().ok_or(ScaasError::BadPrecompile)?;
    require!(sig_index < n, ScaasError::BadPrecompile);
    let o = 2 + 14 * sig_index as usize;
    let (sig_off, sig_ix, pk_off, pk_ix) = (u16_at(data, o)?, u16_at(data, o + 2)?, u16_at(data, o + 4)?, u16_at(data, o + 6)?);
    let (msg_off, msg_len, msg_ix) = (u16_at(data, o + 8)?, u16_at(data, o + 10)?, u16_at(data, o + 12)?);
    require!(
        sig_ix == u16::MAX as usize && pk_ix == u16::MAX as usize && msg_ix == u16::MAX as usize,
        ScaasError::BadPrecompile
    );
    data.get(sig_off..sig_off + 64).ok_or(ScaasError::BadPrecompile)?;
    let pk = data.get(pk_off..pk_off + pk_len).ok_or(ScaasError::BadPrecompile)?;
    let msg = data.get(msg_off..msg_off + msg_len).ok_or(ScaasError::BadPrecompile)?;
    Ok((pk, msg))
}

fn precompile(ix_sysvar: &AccountInfo, auth: &Auth, program: &Pubkey) -> Result<Vec<u8>> {
    let current = load_current_index_checked(ix_sysvar)?;
    require!((auth.precompile_ix as u16) < current, ScaasError::BadPrecompile);
    let ix = load_instruction_at_checked(auth.precompile_ix as usize, ix_sysvar)?;
    require_keys_eq!(ix.program_id, *program, ScaasError::BadPrecompile);
    Ok(ix.data)
}

fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// `"origin":"<o>"` — đúng một lần trong clientDataJSON.
fn origin_of(cdj: &[u8]) -> Result<&[u8]> {
    const K: &[u8] = b"\"origin\":\"";
    require!(count(cdj, K) == 1, ScaasError::BadWebAuthn);
    let i = cdj.windows(K.len()).position(|w| w == K).ok_or(ScaasError::BadWebAuthn)? + K.len();
    let j = cdj[i..].iter().position(|c| *c == b'"').ok_or(ScaasError::BadWebAuthn)?;
    Ok(&cdj[i..i + j])
}

/// Assertion WebAuthn qua precompile secp256r1 cho khoá `pk33` và `challenge` (32 byte). Trả `(rpIdHash, origin)`;
/// người gọi kiểm rpIdHash/origin theo Account.
pub fn passkey<'a>(ix_sysvar: &AccountInfo, auth: &'a Auth, pk33: &[u8; 33], challenge: &[u8; 32]) -> Result<([u8; 32], &'a [u8])> {
    require!(auth.kind == KIND_PASSKEY, ScaasError::BadSignature);
    let data = precompile(ix_sysvar, auth, &SECP256R1_PROGRAM)?;
    let (pk, msg) = entry(&data, auth.sig_index, 33)?;
    require!(pk == pk33, ScaasError::BadSignature);
    require!(msg.len() >= 37 + 32, ScaasError::BadWebAuthn);
    let (ad, cd_hash) = msg.split_at(msg.len() - 32);
    require!(cd_hash == sha256(&[&auth.cdj]), ScaasError::BadWebAuthn);
    require!(ad[32] & 0x05 == 0x05, ScaasError::BadWebAuthn); // UP | UV
    let cdj = &auth.cdj;
    require!(count(cdj, b"\"type\":\"webauthn.get\"") == 1, ScaasError::BadWebAuthn);
    let mut ch = b"\"challenge\":\"".to_vec();
    ch.extend_from_slice(&b64url(challenge));
    ch.push(b'"');
    require!(count(cdj, b"\"challenge\":\"") == 1 && count(cdj, &ch) == 1, ScaasError::BadWebAuthn);
    let mut rp = [0u8; 32];
    rp.copy_from_slice(&ad[..32]);
    Ok((rp, origin_of(cdj)?))
}

/// Chữ ký của khoá `keys[auth.key_index]` trên `digest` (văn bản `label`). `origins` của Account; `new_origin`: origin
/// duy nhất được nhận ngoài danh sách (KeyOp add_origin bằng chính passkey cùng rpId — spec §3.3).
pub fn verify(
    ix_sysvar: &AccountInfo,
    auth: &Auth,
    keys: &[AuthKey],
    origins: &[String],
    label: &str,
    digest: &[u8; 32],
    new_origin: Option<&[u8]>,
) -> Result<()> {
    let key = keys.get(auth.key_index as usize).ok_or(ScaasError::UnknownKey)?;
    match auth.kind {
        KIND_RAW | KIND_OCMS => {
            require!(key.scheme == SCHEME_ED25519, ScaasError::BadSignature);
            let data = precompile(ix_sysvar, auth, &ED25519_PROGRAM)?;
            let (pk, msg) = entry(&data, auth.sig_index, 32)?;
            require!(pk == &key.pubkey[..32], ScaasError::BadSignature);
            let t = text(label, digest);
            let ok = if auth.kind == KIND_RAW { msg == t.as_slice() } else { msg == ocms(pk, &t).as_slice() };
            require!(ok, ScaasError::BadSignature);
        }
        KIND_PASSKEY => {
            require!(key.scheme == SCHEME_P256, ScaasError::BadSignature);
            let (rp, origin) = passkey(ix_sysvar, auth, &key.pubkey, digest)?;
            require!(rp == key.rp_id_hash, ScaasError::BadWebAuthn);
            let listed = origins.iter().any(|o| o.as_bytes() == origin);
            require!(listed || new_origin == Some(origin), ScaasError::UnknownOrigin);
        }
        _ => return err!(ScaasError::BadSignature),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_matches_rfc4648() {
        assert_eq!(b64url(b""), b"");
        assert_eq!(b64url(b"f"), b"Zg");
        assert_eq!(b64url(b"fo"), b"Zm8");
        assert_eq!(b64url(b"foo"), b"Zm9v");
        assert_eq!(b64url(&[0xfb, 0xff]), b"-_8");
        assert_eq!(b64url(&[0u8; 32]).len(), 43);
    }

    #[test]
    fn text_and_ocms_layout() {
        let t = text(METAOP_LABEL, &[0xab; 32]);
        assert_eq!(t.len(), 80);
        assert!(t.starts_with(b"scaas.metaop.v1:abab"));
        let m = ocms(&[7; 32], &t);
        assert_eq!(m.len(), 16 + 2 + 32 + 80);
        assert_eq!(&m[..18], b"\xffsolana offchain\x01\x01");
    }
}
