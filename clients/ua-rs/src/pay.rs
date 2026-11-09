// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The EVM pay entries off chain (pay-meta-tax spec §3-§5, ua-mtx-merge T41, T83): `PayMeta` v3 and its commitment
//! `metaPayId`, the `payNo` UUIDv7 form, the pay records a payee reads by `eth_call`, and the digests a payer signs:
//! `UAMetaTransfer` (`mtxPay`), `UAPayWithTax` (`mtxPayWithTax`, kinds 8-13) and `UARelayFee` with `batch` / `nonce`
//! (`RelayFeeRouter.relay`). An unbound `relayer` / `feeRecipient` is hashed as 0 (`MetaTxLib.canon`). Pinned by
//! `smartcontracts/vectors/metatx/{paymeta,payrecords,paytax}.json` (forge) and `typed/typed_ops.json` (clientkeys). The v2
//! `payNo` text form is in `legacy/ua-rs-sign/pay_meta_v2.rs`. The contract decides; nothing here is a check of record. UNAUDITED.
use crate::{address_word, keccak, keccak256, word, DOMAIN_TYPE};

pub const UA_METATRANSFER_TYPE: &str = "UAMetaTransfer(bytes32 from,bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,\
uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient)";
pub const UA_PAY_WITH_TAX_TYPE: &str = "UAPayWithTax(UAMetaTransfer payment,uint8 taxMode,uint256 tax)UAMetaTransfer(bytes32 from,\
bytes32 to,uint256 value,bytes32 entryRef,uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,\
address feeRecipient)";
pub const UA_RELAY_FEE_TYPE: &str = "UARelayFee(bytes32 from,address target,bytes32 callDataHash,bytes32 payee,uint256 value,\
uint256 batch,uint256 nonce,uint256 validUntil,address relayer)";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayError {
    /// `salt == 0`, or `schema == 0` and a body, or a schema above 0 and none, or `save` with `payNo == 0` (`PayMetaShape`).
    Shape,
    /// `taxMode` not 1 (PERCENT) or 2 (AMOUNT), or `tax > value`.
    Tax,
}

/// `PayMeta {salt, payNo, save, schema, body}`, the last parameter of every pay entry (spec §3.1, ua-mtx-merge T83): `payNo`
/// 32 bytes, 0 = none, recommended a right-aligned UUIDv7 ([`pay_no_from_uuid`]), any other id accepted and never parsed;
/// `save` the payer's choice to store the payment's record under `payNo` on chain (`paymentsOf`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayMeta {
    pub salt: [u8; 32],
    pub pay_no: [u8; 32],
    pub save: bool,
    pub schema: u16,
    pub body: Vec<u8>,
}

fn padded(b: &[u8]) -> Vec<u8> {
    let mut v = word(b.len() as u64).to_vec();
    v.extend_from_slice(b);
    v.resize(32 + b.len().div_ceil(32) * 32, 0);
    v
}

/// `metaPayId(m) = keccak256("scaas.pay.meta.v3" ‖ salt ‖ keccak256(abi.encode(bytes32 payNo, bool save, uint16 schema,
/// bytes body)))` (CTR-MTX-26, T83), after the shape checks of `_payMeta`.
pub fn meta_pay_id_v3(m: &PayMeta) -> Result<[u8; 32], PayError> {
    if m.salt == [0; 32] || (m.schema == 0) != m.body.is_empty() || (m.save && m.pay_no == [0; 32]) {
        return Err(PayError::Shape);
    }
    let enc = [&m.pay_no[..], &word(m.save as u64), &word(m.schema as u64), &word(0x80), &padded(&m.body)].concat();
    Ok(keccak(&[b"scaas.pay.meta.v3", &m.salt, &keccak256(&enc)]))
}

/// clientkeys `payNoFromUuid`: a UUIDv7 in its canonical text (`8-4-4-4-12` hex digits, any case; version 7, variant 10)
/// right-aligned in 32 bytes, the high 16 bytes zero (as an address is padded). `None` for anything else.
pub fn pay_no_from_uuid(uuid: &str) -> Option<[u8; 32]> {
    let parts: Vec<&str> = uuid.split('-').collect();
    if parts.iter().map(|p| p.len()).ne([8, 4, 4, 4, 12]) || !parts.iter().all(|p| p.bytes().all(|c| c.is_ascii_hexdigit())) {
        return None;
    }
    let h = parts.concat();
    let mut w = [0u8; 32];
    for (i, b) in w.iter_mut().skip(16).enumerate() {
        *b = u8::from_str_radix(h.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    uuid_v7(&w).then_some(w)
}

/// The UUIDv7 rule on a right-aligned `payNo`: the high 16 bytes zero, version 7, variant 10.
fn uuid_v7(w: &[u8; 32]) -> bool {
    w[..16] == [0; 16] && w[22] >> 4 == 7 && w[24] >> 6 == 2
}

/// clientkeys `payNoToUuid`, for display: the UUID text (lowercase) of a right-aligned UUIDv7 `payNo`, else `None` (0, or
/// another 32-byte id: shown as hex).
pub fn pay_no_to_uuid(pay_no: &[u8; 32]) -> Option<String> {
    if !uuid_v7(pay_no) {
        return None;
    }
    let h: String = pay_no[16..].iter().map(|b| format!("{b:02x}")).collect();
    Some(format!("{}-{}-{}-{}-{}", &h[..8], &h[8..12], &h[12..16], &h[16..20], &h[20..]))
}

/// `MetaTxLib.PayRecord {bytes32 to, uint192 amount, uint64 blockNumber}` (T83): one payment saved under a `payNo`; `amount`
/// what `to` received, as a big-endian word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayRecord {
    pub to: [u8; 32],
    pub amount: [u8; 32],
    pub block_number: u64,
}

/// `paymentCount(bytes32 payNo)`'s calldata, for `eth_call` on the token.
pub fn payment_count_call(pay_no: &[u8; 32]) -> Vec<u8> {
    [&keccak256(b"paymentCount(bytes32)")[..4], pay_no].concat()
}

/// `paymentsOf(bytes32 payNo, uint256 offset, uint256 limit)`'s calldata, for `eth_call` on the token (paged).
pub fn payments_of_call(pay_no: &[u8; 32], offset: u64, limit: u64) -> Vec<u8> {
    [&keccak256(b"paymentsOf(bytes32,uint256,uint256)")[..4], pay_no, &word(offset), &word(limit)].concat()
}

/// `paymentsOf`'s return data, `abi.encode(PayRecord[])`, read canonical only: the offset 32, the exact length for its count,
/// `amount < 2^192`, `blockNumber < 2^64`. `None` for anything else (an untrusted node's answer).
pub fn decode_pay_records(ret: &[u8]) -> Option<Vec<PayRecord>> {
    let w = |i: usize| -> Option<&[u8]> { ret.get(32 * i..32 * i + 32) };
    let n = usize::try_from(u64::from_be_bytes(w(1)?.get(24..)?.try_into().ok()?)).ok()?;
    if w(0)? != word(32) || w(1)?[..24] != [0; 24] || ret.len() != n.checked_mul(96)?.checked_add(64)? {
        return None;
    }
    (0..n)
        .map(|i| {
            let (to, amount, block) = (w(2 + 3 * i)?, w(3 + 3 * i)?, w(4 + 3 * i)?);
            (amount[..8] == [0; 8] && block[..24] == [0; 24]).then_some(())?;
            Some(PayRecord { to: to.try_into().ok()?, amount: amount.try_into().ok()?, block_number: u64::from_be_bytes(block[24..].try_into().ok()?) })
        })
        .collect()
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
