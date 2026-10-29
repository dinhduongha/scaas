//! NEAR (near-algorand T18): the MetaOp digest, the relay-fee `ref` and the native-account id, as in
//! `smartcontracts/near/vectors/near-vectors.json` and scaas-node's NEAR adapter.
use crate::{keccak, keccak256, verify::sha256, Result, UAError};

/// `sha256(op)`, `op` = `"scaas.metaop.v1"` ‖ Borsh(MetaOp) (the vectors' `encoding`).
pub fn metaop_digest(op: &[u8]) -> [u8; 32] {
    sha256(&[op])
}

/// CTR-MTX-27: `keccak256("scaas.relayfee" ‖ network ‖ target ‖ keccak256(call) ‖ salt)`; `target` is `u8 len ‖ account id`.
pub fn relay_ref(network: &[u8; 32], target: &[u8], call: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", network, target, &keccak256(call), salt])
}

/// Kind `0x0017` id: an implicit account (64 lower-case hex) is its 32 key bytes, any other valid account id (named,
/// ETH-implicit) is `sha256(id)`. Upper case and malformed ids are refused (nearcore `AccountId` rules).
pub fn native_id(account: &str) -> Result<[u8; 32]> {
    let b = account.as_bytes();
    let sep = |c: u8| matches!(c, b'-' | b'_' | b'.');
    let ok = (2..=64).contains(&b.len())
        && b.iter().all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || sep(c))
        && !sep(b[0])
        && !sep(b[b.len() - 1])
        && !b.windows(2).any(|w| sep(w[0]) && sep(w[1]));
    if !ok {
        return Err(UAError::IdFormat);
    }
    if b.len() == 64 && b.iter().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(c)) {
        let mut k = [0u8; 32];
        for (o, p) in k.iter_mut().zip(b.chunks(2)) {
            *o = u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap();
        }
        return Ok(k);
    }
    Ok(sha256(&[b]))
}
