//! Relaying a Zether op through the token's one meta-transaction base (zether.md §12, CTR-ZTH-34): the subject signs a
//! `MetaTransaction` whose `data` is the real calldata of an allowlisted Zether function, in the token's salted domain
//! `("SCaaS ZetherToken", "1", chainId, token, chainUid)`; the proof binds the envelope through `envelopeBinding`.
//!
//! Relayed flow: build `m` without data → `binding = envelope_binding(m)` → prove with
//! `Binding::Relayed(binding)` → `m.data = transfer_call(...)` → sign `digest(m)`.

use crate::abi::{self, Tok};
use crate::curve::keccak256;

pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
pub const MODE_FEE_NONE: u32 = 0x00;
pub const MODE_FEE_FIXED: u32 = 0x20;

pub const METATX_TYPE: &str = "MetaTransaction(address from,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

/// `MetaTxLib.MetaTransaction` (CTR-MTX-15): no `to`, no `value`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaTx {
    pub from: [u8; 20],
    pub data: Vec<u8>,
    /// 2D-nonce lane (random per `entryRef`, chosen by the client).
    pub batch: [u8; 32],
    pub nonce: u64,
    pub valid_until: u64,
    pub mode: u32,
    pub relayer: [u8; 20],
    pub fee: u128,
    pub fee_recipient: [u8; 20],
}

fn u128w(v: u128) -> [u8; 32] {
    let mut o = [0u8; 32];
    o[16..].copy_from_slice(&v.to_be_bytes());
    o
}

impl MetaTx {
    /// `MetaTxLib.canon`: unbound relayer / feeRecipient hash as `address(0)`.
    pub fn canon(&self) -> ([u8; 20], [u8; 20]) {
        let r = if self.mode & MODE_RESTRICT_RELAYER != 0 { self.relayer } else { [0; 20] };
        let f = if self.mode & MODE_RESTRICT_FEE_RECIPIENT != 0 { self.fee_recipient } else { [0; 20] };
        (r, f)
    }

    pub fn struct_hash(&self) -> [u8; 32] {
        let (r, f) = self.canon();
        keccak256(
            &[
                keccak256(METATX_TYPE.as_bytes()),
                abi::addr(&self.from),
                keccak256(&self.data),
                self.batch,
                abi::u256(self.nonce),
                abi::u256(self.valid_until),
                abi::u256(self.mode as u64),
                abi::addr(&r),
                u128w(self.fee),
                abi::addr(&f),
            ]
            .concat(),
        )
    }
}

/// The token's salted EIP-712 domain (CTR-MTX-02, CTR-GEN-05).
pub fn domain_separator(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20]) -> [u8; 32] {
    keccak256(
        &[
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"),
            keccak256(b"SCaaS ZetherToken"),
            keccak256(b"1"),
            abi::u256(chain_id),
            abi::addr(token),
            *chain_uid,
        ]
        .concat(),
    )
}

/// EIP-712 digest the subject's signing key signs (`mtxDigest(m)` on the token).
pub fn digest(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
    let mut b = vec![0x19, 0x01];
    b.extend(domain_separator(chain_id, chain_uid, token));
    b.extend(m.struct_hash());
    keccak256(&b)
}

/// `envelopeBinding` (CTR-ZTH-06) — every envelope field except `data`, plus `chainUid`.
pub fn envelope_binding(chain_id: u64, chain_uid: &[u8; 32], token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
    let (r, f) = m.canon();
    keccak256(
        &[
            keccak256(b"SCAAS-ZETHER-ENVELOPE-V1"),
            abi::u256(chain_id),
            *chain_uid,
            abi::addr(token),
            abi::addr(&m.from),
            m.batch,
            abi::u256(m.nonce),
            abi::u256(m.valid_until),
            abi::u256(m.mode as u64),
            abi::addr(&r),
            u128w(m.fee),
            abi::addr(&f),
        ]
        .concat(),
    )
}

/// The binding word of a direct `zetherUnshieldUnwrap` (under `ZTX_V1_DIRECT`): its leg and `minOut` (`min_out` as
/// the 32-byte ABI word). Controller ruling, pending the owner.
pub fn unwrap_binding(underlying: &[u8; 20], min_out: &[u8; 32]) -> [u8; 32] {
    keccak256(&[keccak256(b"SCAAS-ZETHER-UNWRAP-V1"), abi::addr(underlying), *min_out].concat())
}

pub fn selector(sig: &str) -> [u8; 4] {
    keccak256(sig.as_bytes())[..4].try_into().unwrap()
}

/// Calldata of a confidential transfer (`zetherTransfer`, `…Compact`, `…NoBundle`, `…Single`, all
/// `(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary)`): the direct call and, unchanged, the envelope's `data`.
pub fn transfer_call(sig: &str, payload: &[u8], proof: &[u8], auth_sig: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
    let mut d = selector(sig).to_vec();
    d.extend(abi::encode(&[
        Tok::Bytes(payload.to_vec()),
        Tok::Bytes(proof.to_vec()),
        Tok::Bytes(auth_sig.to_vec()),
        Tok::Word(*beneficiary),
    ]));
    d
}

/// `zetherUnshield(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary, address to, uint256 amount)`.
pub fn unshield_call(
    payload: &[u8],
    proof: &[u8],
    auth_sig: &[u8],
    beneficiary: &[u8; 32],
    to: &[u8; 20],
    amount: u64,
) -> Vec<u8> {
    let mut d = selector("zetherUnshield(bytes,bytes,bytes,bytes32,address,uint256)").to_vec();
    d.extend(abi::encode(&[
        Tok::Bytes(payload.to_vec()),
        Tok::Bytes(proof.to_vec()),
        Tok::Bytes(auth_sig.to_vec()),
        Tok::Word(*beneficiary),
        Tok::Word(abi::addr(to)),
        Tok::Word(abi::u256(amount)),
    ]));
    d
}
