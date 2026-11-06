// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The EVM pay entries off chain (pay-meta-tax spec §3-§5, ua-mtx-merge T41): `PayMeta` v2 and its commitment
//! `metaPayId`, the `payNo` text rules, and the digests a payer signs: `UAMetaTransfer` (`mtxPay`), `UAPayWithTax`
//! (`mtxPayWithTax`, kinds 8-13) and `UARelayFee` with `batch` / `nonce` (`MtxRelayFee.relay`). An unbound `relayer` /
//! `feeRecipient` is hashed as 0 (`MetaTxLib.canon`). Pinned by `smartcontracts/vectors/metatx/{paymeta,paytax}.json`
//! (forge) and `typed/typed_ops.json` (clientkeys). The contract decides; nothing here is a check of record. UNAUDITED.
use crate::{address_word, keccak, keccak256, word, DOMAIN_TYPE};

pub const PAY_NO_MAX: usize = 256;
pub const UA_METATRANSFER_TYPE: &str = "UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,\
uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
pub const UA_PAY_WITH_TAX_TYPE: &str = "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,\
bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,\
address feeRecipient)";
pub const UA_RELAY_FEE_TYPE: &str = "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,\
uint256 batch,uint256 nonce,uint256 validUntil,address relayer)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayError {
    /// `salt == 0`, or `schema == 0` and a body, or a schema above 0 and none (`PayMetaShape`).
    Shape,
    /// `payNo` over 256 bytes (`PayNoTooLong`).
    PayNoTooLong,
    /// A control character or a bidirectional mark, embedding, override or isolate in `payNo` (display spoofing).
    PayNoText,
    /// `taxMode` not 1 (PERCENT) or 2 (AMOUNT), or `tax > value`.
    Tax,
}

/// `PayMeta {salt, payNo, schema, body}`, the last parameter of every pay entry (spec §3.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayMeta {
    pub salt: [u8; 32],
    pub pay_no: String,
    pub schema: u16,
    pub body: Vec<u8>,
}

/// A `payNo` a wallet signs (spec §3.1): at most 256 bytes of UTF-8 (a Rust `str` is valid UTF-8), no C0 / C1 control
/// or DEL, no bidirectional mark, embedding, override or isolate (U+061C, U+200E, U+200F, U+202A-202E, U+2066-2069).
pub fn check_pay_no(pay_no: &str) -> Result<(), PayError> {
    if pay_no.len() > PAY_NO_MAX {
        return Err(PayError::PayNoTooLong);
    }
    let bad = |c: char| c.is_control()
        || matches!(c, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    if pay_no.chars().any(bad) {
        return Err(PayError::PayNoText);
    }
    Ok(())
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut v = word(b.len() as u64).to_vec();
    v.extend_from_slice(b);
    v.resize(32 + b.len().div_ceil(32) * 32, 0);
    v
}

/// `metaPayId(m) = keccak256("scaas.pay.meta.v2" ‖ salt ‖ keccak256(abi.encode(string payNo, uint16 schema, bytes body)))`
/// (CTR-MTX-26 Change), after the shape and `payNo` checks of `_payMeta` and the wallet rules.
pub fn meta_pay_id_v2(m: &PayMeta) -> Result<[u8; 32], PayError> {
    if m.salt == [0; 32] || (m.schema == 0) != m.body.is_empty() {
        return Err(PayError::Shape);
    }
    check_pay_no(&m.pay_no)?;
    let (no, body) = (padded(m.pay_no.as_bytes()), padded(&m.body));
    let mut enc = word(0x60).to_vec();
    enc.extend_from_slice(&word(m.schema as u64));
    enc.extend_from_slice(&word(0x60 + no.len() as u64));
    enc.extend(no);
    enc.extend(body);
    Ok(keccak(&[b"scaas.pay.meta.v2", &m.salt, &keccak256(&enc)]))
}

/// `MetaTxLib.UAMetaTransfer`, uint256 fields as big-endian words.
#[derive(Debug, Clone, Copy)]
pub struct UAMetaTransfer {
    pub from: [u8; 32],
    pub to: [u8; 32],
    pub value: [u8; 32],
    pub entry_ref: [u8; 32],
    pub batch: [u8; 32],
    pub nonce: [u8; 32],
    pub valid_until: [u8; 32],
    pub mode: u32,
    pub relayer: [u8; 20],
    pub fee: [u8; 32],
    pub fee_recipient: [u8; 20],
}

/// `hashStruct(UAMetaTransfer)`, `relayer` as 0 unless `mode & 1`, `feeRecipient` as 0 unless `mode & 2`.
pub fn transfer_hash(t: &UAMetaTransfer) -> [u8; 32] {
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    keccak(&[&keccak256(UA_METATRANSFER_TYPE.as_bytes()), &t.from, &t.to, &t.value, &t.entry_ref, &t.batch, &t.nonce,
        &t.valid_until, &word(t.mode as u64), &canon(t.mode & 1 != 0, &t.relayer), &t.fee,
        &canon(t.mode & 2 != 0, &t.fee_recipient)])
}

/// `hashStruct(UAPayWithTax{payment, taxMode, tax})` (spec §5.2): `taxMode` 1 PERCENT or 2 AMOUNT, `tax ≤ value`.
pub fn pay_with_tax_hash(t: &UAMetaTransfer, tax_mode: u8, tax: &[u8; 32]) -> Result<[u8; 32], PayError> {
    if !(1..=2).contains(&tax_mode) || tax > &t.value {
        return Err(PayError::Tax);
    }
    Ok(keccak(&[&keccak256(UA_PAY_WITH_TAX_TYPE.as_bytes()), &transfer_hash(t), &word(tax_mode as u64), tax]))
}

/// `UARelayFee` (pay-meta-tax spec §4, O4): the payer's own lane `(batch, nonce)`; `relayer` the router.
#[derive(Debug, Clone, Copy)]
pub struct RelayFee {
    pub from: [u8; 32],
    pub target: [u8; 20],
    pub call_data_hash: [u8; 32],
    pub payee: [u8; 32],
    pub value: [u8; 32],
    pub batch: [u8; 32],
    pub nonce: [u8; 32],
    pub valid_until: [u8; 32],
    pub relayer: [u8; 20],
}

pub fn relay_fee_hash(r: &RelayFee) -> [u8; 32] {
    keccak(&[&keccak256(UA_RELAY_FEE_TYPE.as_bytes()), &r.from, &address_word(&r.target), &r.call_data_hash, &r.payee,
        &r.value, &r.batch, &r.nonce, &r.valid_until, &address_word(&r.relayer)])
}

/// A token's domain: `(name, "1", chainId, token, salt = chainUid)`.
pub fn token_domain_separator(name: &str, chain_id: u64, token: &[u8; 20], chain_uid: &[u8; 32]) -> [u8; 32] {
    keccak(&[&keccak256(DOMAIN_TYPE.as_bytes()), &keccak256(name.as_bytes()), &keccak256(b"1"), &word(chain_id),
        &address_word(token), chain_uid])
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`: what the payer signs.
pub fn typed_digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], domain_separator, struct_hash])
}

/// The tax of a PERCENT payment, `floor(value × ratePpm / 10^6)` (PT-6), for a `value` that fits 128 bits; `None` above.
pub fn percent_tax(value: u128, rate_ppm: u32) -> Option<u128> {
    if rate_ppm > 1_000_000 {
        return None;
    }
    // value × rate as a 160-bit product in two halves, divided by 10^6
    let (hi, lo) = ((value >> 64) * rate_ppm as u128, (value & u64::MAX as u128) * rate_ppm as u128);
    let q_hi = hi / 1_000_000;
    let r = ((hi % 1_000_000) << 64) + lo;
    Some((q_hi << 64) + r / 1_000_000)
}
