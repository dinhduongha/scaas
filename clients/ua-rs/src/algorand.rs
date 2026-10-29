//! Algorand (near-algorand T18): the MetaOp digest, the relay-fee `ref` and address <-> key, as in
//! `smartcontracts/algorand/vectors/algorand-vectors.json` and scaas-node's Algorand adapter.
use crate::{keccak, keccak256, verify::sha256, Result, UAError};
use sha2::{Digest, Sha512_256};

/// `sha256(op)`, `op` = `"scaas.metaop.v1"` ‖ the ARC-4 tuple (the vectors' `encoding`).
pub fn metaop_digest(op: &[u8]) -> [u8; 32] {
    sha256(&[op])
}

/// CTR-MTX-27: `keccak256("scaas.relayfee" ‖ GenesisHash ‖ target app address ‖ keccak256(call) ‖ salt)`.
pub fn relay_ref(network: &[u8; 32], target: &[u8; 32], call: &[u8], salt: &[u8; 32]) -> [u8; 32] {
    keccak(&[b"scaas.relayfee", network, target, &keccak256(call), salt])
}

/// The 32-byte key of a 58-character address (RFC 4648 base32, no padding, upper case; last 4 bytes of `sha512_256(key)`).
pub fn address_to_key(addr: &str) -> Result<[u8; 32]> {
    let s = addr.as_bytes();
    if s.len() != 58 {
        return Err(UAError::IdFormat);
    }
    let (mut raw, mut acc, mut bits) = (Vec::with_capacity(36), 0u32, 0);
    for &c in s {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'2'..=b'7' => c - b'2' + 26,
            _ => return Err(UAError::IdFormat),
        };
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            raw.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    // 58 chars = 290 bits = 36 bytes + 2 padding bits, which must be zero (canonical)
    if raw.len() != 36 || acc != 0 || Sha512_256::digest(&raw[..32])[28..] != raw[32..] {
        return Err(UAError::IdFormat);
    }
    Ok(raw[..32].try_into().unwrap())
}
