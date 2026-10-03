//! Meta-tx envelope for Zether ops (zether-design §10): `envelopeBinding`, the EIP-712
//! digest the subject signs (`MetaTxLib`, domain `("Bamboo ZetherToken", "1", chainId, token)`),
//! and the op calldata carried in `m.data`.
//!
//! Relayed flow: build `m` without data → `binding = envelope_binding(m)` → prove with
//! `Binding::Relayed(binding)` → `m.data = transfer_data(...)` → sign `digest(m)`.

use crate::abi::{self, Tok};
use crate::curve::keccak256;

pub const MODE_RESTRICT_RELAYER: u32 = 0x01;
pub const MODE_RESTRICT_FEE_RECIPIENT: u32 = 0x02;
pub const MODE_FEE_NONE: u32 = 0x00;
pub const MODE_FEE_FIXED: u32 = 0x20;

pub const METATX_TYPE: &str = "MetaTransaction(address from,address to,uint256 value,bytes data,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";

/// `MetaTxLib.MetaTransaction`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MetaTx {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: u128,
    pub data: Vec<u8>,
    /// 2D-nonce lane (R9: random per `entryRef`, chosen by the client).
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
                abi::addr(&self.to),
                u128w(self.value),
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

pub fn domain_separator(chain_id: u64, token: &[u8; 20]) -> [u8; 32] {
    keccak256(
        &[
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
            keccak256(b"Bamboo ZetherToken"),
            keccak256(b"1"),
            abi::u256(chain_id),
            abi::addr(token),
        ]
        .concat(),
    )
}

/// EIP-712 digest the subject's signing key signs.
pub fn digest(chain_id: u64, token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
    let mut b = vec![0x19, 0x01];
    b.extend(domain_separator(chain_id, token));
    b.extend(m.struct_hash());
    keccak256(&b)
}

/// `envelopeBinding` (§10) — every envelope field except `data`.
pub fn envelope_binding(chain_id: u64, token: &[u8; 20], m: &MetaTx) -> [u8; 32] {
    let (r, f) = m.canon();
    keccak256(
        &[
            keccak256(b"BAMBOO-ZETHER-ENVELOPE-V1"),
            abi::u256(chain_id),
            abi::addr(token),
            abi::addr(&m.from),
            abi::addr(&m.to),
            u128w(m.value),
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

pub fn selector(sig: &str) -> [u8; 4] {
    keccak256(sig.as_bytes())[..4].try_into().unwrap()
}

/// `m.data` for `OP_ZTRANSFER`: `op ‖ abi.encode(bytes payload, bytes proof, bytes authSig, bytes32 beneficiary)`.
pub fn transfer_data(payload: &[u8], proof: &[u8], auth_sig: &[u8], beneficiary: &[u8; 32]) -> Vec<u8> {
    let mut d = selector("zetherTransfer(bytes,bytes,bytes,bytes32)").to_vec();
    d.extend(abi::encode(&[
        Tok::Bytes(payload.to_vec()),
        Tok::Bytes(proof.to_vec()),
        Tok::Bytes(auth_sig.to_vec()),
        Tok::Word(*beneficiary),
    ]));
    d
}

/// `m.data` for `OP_ZBURN`: `op ‖ abi.encode(bytes payload, uint256 amount, address recipient,
/// bytes32 beneficiary, bytes proof, bytes authSig)`.
pub fn burn_data(
    payload: &[u8],
    amount: u64,
    recipient: &[u8; 20],
    beneficiary: &[u8; 32],
    proof: &[u8],
    auth_sig: &[u8],
) -> Vec<u8> {
    let mut d = selector("zetherBurn(bytes,uint256,address,bytes32,bytes,bytes)").to_vec();
    d.extend(abi::encode(&[
        Tok::Bytes(payload.to_vec()),
        Tok::Word(abi::u256(amount)),
        Tok::Word(abi::addr(recipient)),
        Tok::Word(*beneficiary),
        Tok::Bytes(proof.to_vec()),
        Tok::Bytes(auth_sig.to_vec()),
    ]));
    d
}
