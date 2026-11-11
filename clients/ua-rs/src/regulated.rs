// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The regulated kinds 8-13 off chain (regulated-kinds spec §3.1, §3.6, §5; ua-mtx-merge T34): the `GovernanceRouter`'s
//! eight control ops (`UA<Op>`, its EIP-712 digest with `MetaTxLib.canon`'s zeroing of an unbound `relayer` /
//! `feeRecipient`), `recordId`, the relaxation `commit`, and `R` as `canReceive` answers it. Pinned by
//! `smartcontracts/vectors/typed/typed_ops.json` (clientkeys) and `governance/regulated_kat.json` (forge). The contract
//! decides; nothing here is a check of record. UNAUDITED.
use crate::{address_word, keccak, keccak256, word, DOMAIN_TYPE};

pub const ROUTER_NAME: &str = "SCaaS GovernanceRouter";
const ENVELOPE: &str =
    "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient";

/// The eight ops (spec §3.1) and their params after `bytes32 from,address target`, the direct entry's in order; in
/// `UAOperatorTransfer` the moved account is `account`, `from` the signer (CTR-GOV-20 Change, owner 2026-11-06).
pub const REGULATED_OPS: [(&str, &str); 8] = [
    ("UAFreeze", "bytes32 account,bytes32 ref,bytes32 recordId"),
    ("UAUnfreeze", "bytes32 account,bytes32 ref"),
    ("UAForceTransfer", "bytes32 recordId,uint256 amount"),
    ("UAPause", "bytes32 ref,uint64 until"),
    ("UAUnpause", "bytes32 ref"),
    ("UARecordOrder", "bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil"),
    ("UARevokeOrder", "bytes32 recordId,bytes32 reasonRef"),
    ("UAOperatorTransfer", "bytes32 account,bytes32 to,uint256 amount,bytes32 ref"),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouterOpError {
    /// Not one of the eight.
    UnknownOp,
    /// Not one word per param.
    Params,
    /// A `uint64` word over 64 bits.
    Range,
}

/// The envelope a `UA<Op>` signs (`MetaTxLib.UAEnvelope`), uint256 fields as big-endian words.
#[derive(Debug, Clone, Copy)]
pub struct Envelope {
    pub from: [u8; 32],
    pub batch: [u8; 32],
    pub nonce: [u8; 32],
    pub valid_until: [u8; 32],
    pub mode: u32,
    pub relayer: [u8; 20],
    pub fee: [u8; 32],
    pub fee_recipient: [u8; 20],
}

fn params_of(op: &str) -> Option<&'static str> {
    REGULATED_OPS.iter().find(|(n, _)| *n == op).map(|(_, p)| *p)
}

/// `UA<Op>(bytes32 from,address target,<params>,<E>)`.
pub fn type_string(op: &str) -> Option<String> {
    params_of(op).map(|p| format!("{op}(bytes32 from,address target,{p},{ENVELOPE})"))
}

/// `hashStruct(UA<Op>)` over `params` (one ABI word each, in order), `relayer` hashed as 0 unless `mode & 1`,
/// `feeRecipient` as 0 unless `mode & 2` (`MetaTxLib.canon`).
pub fn struct_hash(op: &str, e: &Envelope, target: &[u8; 20], params: &[[u8; 32]]) -> Result<[u8; 32], RouterOpError> {
    let list = params_of(op).ok_or(RouterOpError::UnknownOp)?;
    let types: Vec<&str> = list.split(',').map(|f| f.split_once(' ').map_or(f, |(t, _)| t)).collect();
    if types.len() != params.len() {
        return Err(RouterOpError::Params);
    }
    if types.iter().zip(params).any(|(t, w)| *t == "uint64" && w[..24] != [0; 24]) {
        return Err(RouterOpError::Range);
    }
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let mut words: Vec<[u8; 32]> = vec![keccak256(type_string(op).unwrap().as_bytes()), e.from, address_word(target)];
    words.extend_from_slice(params);
    words.extend([e.batch, e.nonce, e.valid_until, word(e.mode as u64), canon(e.mode & 1 != 0, &e.relayer), e.fee,
        canon(e.mode & 2 != 0, &e.fee_recipient)]);
    Ok(keccak(&words.iter().map(|w| &w[..]).collect::<Vec<_>>()))
}

/// The router's domain: `("SCaaS GovernanceRouter", "1", chainId, router, salt = chainUid)`.
pub fn router_domain_separator(chain_id: u64, router: &[u8; 20], chain_uid: &[u8; 32]) -> [u8; 32] {
    keccak(&[
        &keccak256(DOMAIN_TYPE.as_bytes()),
        &keccak256(ROUTER_NAME.as_bytes()),
        &keccak256(b"1"),
        &word(chain_id),
        &address_word(router),
        chain_uid,
    ])
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`: what the holder signs.
pub fn digest(op: &str, domain_separator: &[u8; 32], e: &Envelope, target: &[u8; 20], params: &[[u8; 32]])
    -> Result<[u8; 32], RouterOpError>
{
    Ok(keccak(&[&[0x19, 0x01], domain_separator, &struct_hash(op, e, target, params)?]))
}

/// `recordId = keccak256(abi.encode(orderId, subject, beneficiary))` (spec §3.1).
pub fn record_id(order_id: &[u8; 32], subject: &[u8; 32], beneficiary: &[u8; 32]) -> [u8; 32] {
    keccak(&[order_id, subject, beneficiary])
}

/// `IGovernance.GrantTerms`.
#[derive(Debug, Clone, Copy)]
pub struct GrantTerms {
    pub min: u128,
    pub max: u128,
    pub total: u128,
    pub per_window: u128,
    pub window: u32,
    pub valid_until: u64,
    pub max_uses: u32,
    pub delegable: bool,
    pub scope: [u8; 32],
}

fn u128_word(v: u128) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[16..].copy_from_slice(&v.to_be_bytes());
    w
}

/// `commit = keccak256(abi.encode(uint8 action, uint8 bit, bytes32 account, argsHash))`, `argsHash` =
/// `keccak256(abi.encode(GrantTerms))` for `SET` (2), else 0 (spec §3.6: `GRANT` 1 .. `DISABLE` 5). `None` for another
/// action, or `terms` given with any action but `SET` or missing with it.
pub fn relax_commit(action: u8, bit: u8, account: &[u8; 32], terms: Option<&GrantTerms>) -> Option<[u8; 32]> {
    if !(1..=5).contains(&action) || (action == 2) != terms.is_some() {
        return None;
    }
    let args = terms.map_or([0; 32], |t| {
        keccak(&[&u128_word(t.min), &u128_word(t.max), &u128_word(t.total), &u128_word(t.per_window), &word(t.window as u64),
            &word(t.valid_until), &word(t.max_uses as u64), &word(t.delegable as u64), &t.scope])
    });
    Some(keccak(&[&word(action as u64), &word(bit as u64), account, &args]))
}

/// One account's `ComplianceRegistry` row as `canReceive` reads it: flags, `validUntil`, whether its attester is enabled.
#[derive(Debug, Clone, Copy)]
pub struct Attestation {
    pub flags: u64,
    pub valid_until: u64,
    pub attester_enabled: bool,
}

const ELIGIBLE_CONTRACT: u64 = 8;

/// `R(account)` as `canReceive` answers it under `KYC` (spec §3.1, §5; round 3s §3): `required` and `denied` are
/// `Some(requiredFlags)`, `Some(deniedFlags)` with bit 28 `KYC` on (both masks; a zero mask constrains nothing), `None` with
/// it off; `(ok, reason)`, reason 1 not attested or flags missing, 2 expired, 3 attester disabled, 4 denied.
/// `ELIGIBLE_CONTRACT` satisfies `required`, never `denied`. The lists come first on chain: `listed`.
pub fn can_receive(required: Option<u64>, denied: Option<u64>, a: &Attestation, now: u64) -> (bool, u8) {
    if required.is_none() && denied.is_none() {
        return (true, 0);
    }
    let active = a.attester_enabled && a.valid_until >= now;
    let req = required.unwrap_or(0);
    if req != 0 && !(active && (a.flags & req == req || a.flags & ELIGIBLE_CONTRACT != 0)) {
        return (false, if a.valid_until == 0 { 1 } else if !a.attester_enabled { 3 } else if !active { 2 } else { 1 });
    }
    if active && a.flags & denied.unwrap_or(0) != 0 {
        return (false, 4);
    }
    (true, 0)
}

// ------------------------------------------------------------------ round 3s (CTR-GOV-24, spec 2026-11-10-token-lists.md)

/// `RegulatedLib`'s `controls` bits of the lists and of `KYC` (bit 28 in byte bit 6), and an account's `listFlagsOf` byte.
pub const C_ALLOW: u8 = 1 << 3;
pub const C_DENY: u8 = 1 << 4;
pub const C_KYC: u8 = 1 << 6;
pub const ALLOWED: u8 = 1;
pub const DENIED: u8 = 2;

/// `L(account)` as `canReceive` answers it first (spec §4.2, §4.3): under `ALLOWLIST` not `ALLOWED` reason 5, under
/// `DENYLIST` `DENIED` reason 6, else `(true, 0)`.
pub fn listed(controls: u8, list_flags: u8) -> (bool, u8) {
    if controls & C_ALLOW != 0 && list_flags & ALLOWED == 0 {
        return (false, 5);
    }
    if controls & C_DENY != 0 && list_flags & DENIED != 0 {
        return (false, 6);
    }
    (true, 0)
}

/// Spec §5.5: the bits of 8, 9, 28 that can still be switched on: valid for the kind, not set, not locked (off), the admin
/// not 0, and for 28 a compliance registry. A wallet prints a bit's `enableable` sentence only then, never for a bit locked off.
pub fn enableable(features: u64, locked: u64, valid: u64, admin: bool, registry: bool) -> u64 {
    if !admin {
        return 0;
    }
    let e = ((1 << 8) | (1 << 9) | (1 << 28)) & valid & !features & !locked;
    if registry { e } else { e & !(1 << 28) }
}

/// `UASetAllowed` (`allow`) or `UASetDenied`: bit 8's or bit 9's holder, 1-256 accounts, at once.
pub fn set_list_type(allow: bool) -> String {
    format!("{}(bytes32 from,address target,bytes32[] accounts,bool on,{ENVELOPE})", if allow { "UASetAllowed" } else { "UASetDenied" })
}

/// `hashStruct(UASetAllowed | UASetDenied)`: `accounts` as EIP-712 hashes an array (`keccak256` of its words).
pub fn set_list_struct_hash(allow: bool, e: &Envelope, target: &[u8; 20], accounts: &[[u8; 32]], on: bool) -> [u8; 32] {
    let words = keccak(&accounts.iter().map(|a| &a[..]).collect::<Vec<_>>());
    crate::wraplimit::struct_hash(keccak256(set_list_type(allow).as_bytes()), e, target, &[words, crate::wraplimit::bool_word(on)])
}

/// `UAEnableFeature`: the admin switches on 8, 9 or 28.
pub fn enable_feature_type() -> String {
    format!("UAEnableFeature(bytes32 from,address target,uint8 bit,{ENVELOPE})")
}

pub fn enable_feature_struct_hash(e: &Envelope, target: &[u8; 20], bit: u8) -> [u8; 32] {
    crate::wraplimit::struct_hash(keccak256(enable_feature_type().as_bytes()), e, target, &[word(bit as u64)])
}
