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
/// `UAOperatorTransfer` the moved account is `account`, `from` the signer (CTR-GOV-20 Change, owner 2026-11-06). The Change of
/// CTR-GOV-28 in round 3zb + 3zc (O6, owner 2026-11-13): each signs the token's chain word last (`chainUid`, one more word).
pub const REGULATED_OPS: [(&str, &str); 8] = [
    ("UAFreeze", "bytes32 account,bytes32 ref,bytes32 recordId,bytes32 chainUid"),
    ("UAUnfreeze", "bytes32 account,bytes32 ref,bytes32 chainUid"),
    ("UAForceTransfer", "bytes32 recordId,uint256 amount,bytes32 chainUid"),
    ("UAPause", "bytes32 ref,uint64 until,bytes32 chainUid"),
    ("UAUnpause", "bytes32 ref,bytes32 chainUid"),
    ("UARecordOrder", "bytes32 orderId,bytes32 documentHash,bytes32 subject,bytes32 beneficiary,uint256 maxAmount,uint64 freezeUntil,bytes32 chainUid"),
    ("UARevokeOrder", "bytes32 recordId,bytes32 reasonRef,bytes32 chainUid"),
    ("UAOperatorTransfer", "bytes32 account,bytes32 to,uint256 amount,bytes32 ref,bytes32 chainUid"),
];

/// The error of the positional form (`params: &[[u8; 32]]`, T21 L45: backed up to `legacy/ua-rs-sign/router_ops_positional.rs`);
/// the typed ops below cannot be malformed, so nothing here returns it now. Kept: never drop an API.
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

/// A field's value as the one word EIP-712 hashes for it: a static field its ABI word (`uintN` / `bool` as the number,
/// `address` right-aligned, `bytes4` left-aligned, `bytes32` / `uint256` as given), a `string` the `keccak256` of its bytes,
/// an array the `keccak256` of its elements' words. The Rust type is the field's Solidity type, so a value over its type
/// cannot be built.
pub trait FieldWord {
    fn field_word(&self) -> [u8; 32];
}
impl FieldWord for [u8; 32] {
    fn field_word(&self) -> [u8; 32] {
        *self
    }
}
impl FieldWord for [u8; 20] {
    fn field_word(&self) -> [u8; 32] {
        address_word(self)
    }
}
impl FieldWord for [u8; 4] {
    fn field_word(&self) -> [u8; 32] {
        let mut w = [0u8; 32];
        w[..4].copy_from_slice(self);
        w
    }
}
macro_rules! uint_field_word {
    ($($t:ty),*) => {$(
        impl FieldWord for $t {
            fn field_word(&self) -> [u8; 32] {
                word(*self as u64)
            }
        }
    )*};
}
uint_field_word!(u8, u16, u32, u64, bool);
impl FieldWord for String {
    fn field_word(&self) -> [u8; 32] {
        keccak256(self.as_bytes())
    }
}
impl<T: FieldWord> FieldWord for Vec<T> {
    fn field_word(&self) -> [u8; 32] {
        let w: Vec<[u8; 32]> = self.iter().map(FieldWord::field_word).collect();
        keccak(&w.iter().map(|x| &x[..]).collect::<Vec<_>>())
    }
}

/// A router op signed as `UA<Op>(bytes32 from,address target,<fields>,<E>)`: `NAME` the `UA<Op>`, `FIELDS` its own fields in
/// the type string's order (Rust names), `field_words` their words in that order (T21 L45, owner option (b): one struct per
/// signed type with named fields, so two fields cannot be passed in each other's place).
pub trait RouterOp {
    const NAME: &'static str;
    const FIELDS: &'static [&'static str];
    fn field_words(&self) -> Vec<[u8; 32]>;
}
/// One of the eight regulated ops (`REGULATED_OPS`), hashed by `struct_hash` / `digest` here.
pub trait RegulatedOp: RouterOp {}

/// `$kind` op structs: `pub struct UA<Op> { pub field: Type, .. }` hashed in declaration order (the type string's).
macro_rules! router_ops {
    ($kind:ident; $( $(#[$m:meta])* $name:ident { $($f:ident : $t:ty),* $(,)? } )*) => {$(
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq)]
        pub struct $name { $(pub $f: $t),* }
        impl $crate::regulated::RouterOp for $name {
            const NAME: &'static str = stringify!($name);
            const FIELDS: &'static [&'static str] = &[$(stringify!($f)),*];
            fn field_words(&self) -> Vec<[u8; 32]> {
                #[allow(unused_imports)]
                use $crate::regulated::FieldWord;
                vec![$(self.$f.field_word()),*]
            }
        }
        impl $kind for $name {}
    )*};
}
pub(crate) use router_ops;

router_ops! { RegulatedOp;
    /// `UAFreeze`: `uint256` fields are big-endian words throughout.
    UAFreeze { account: [u8; 32], r#ref: [u8; 32], record_id: [u8; 32], chain_uid: [u8; 32] }
    UAUnfreeze { account: [u8; 32], r#ref: [u8; 32], chain_uid: [u8; 32] }
    UAForceTransfer { record_id: [u8; 32], amount: [u8; 32], chain_uid: [u8; 32] }
    UAPause { r#ref: [u8; 32], until: u64, chain_uid: [u8; 32] }
    UAUnpause { r#ref: [u8; 32], chain_uid: [u8; 32] }
    UARecordOrder { order_id: [u8; 32], document_hash: [u8; 32], subject: [u8; 32], beneficiary: [u8; 32], max_amount: [u8; 32],
        freeze_until: u64, chain_uid: [u8; 32] }
    UARevokeOrder { record_id: [u8; 32], reason_ref: [u8; 32], chain_uid: [u8; 32] }
    /// `account` the moved account, `to` the receiver (`from`, the envelope's, the signer).
    UAOperatorTransfer { account: [u8; 32], to: [u8; 32], amount: [u8; 32], r#ref: [u8; 32], chain_uid: [u8; 32] }
}

fn params_of(op: &str) -> Option<&'static str> {
    REGULATED_OPS
        .iter()
        .find(|(n, _)| *n == op)
        .map(|(_, p)| *p)
}

/// `UA<Op>(bytes32 from,address target,<params>,<E>)`.
pub fn type_string(op: &str) -> Option<String> {
    params_of(op).map(|p| format!("{op}(bytes32 from,address target,{p},{ENVELOPE})"))
}

/// The words after the type hash: `from`, `target`, the op's own, then the envelope with `relayer` hashed as 0 unless
/// `mode & 1`, `feeRecipient` as 0 unless `mode & 2` (`MetaTxLib.canon`). Shared with `admin`.
pub(crate) fn router_struct_hash(
    type_string: &str,
    e: &Envelope,
    target: &[u8; 20],
    own: Vec<[u8; 32]>,
) -> [u8; 32] {
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let mut words: Vec<[u8; 32]> = vec![
        keccak256(type_string.as_bytes()),
        e.from,
        address_word(target),
    ];
    words.extend(own);
    words.extend([
        e.batch,
        e.nonce,
        e.valid_until,
        word(e.mode as u64),
        canon(e.mode & 1 != 0, &e.relayer),
        e.fee,
        canon(e.mode & 2 != 0, &e.fee_recipient),
    ]);
    keccak(&words.iter().map(|w| &w[..]).collect::<Vec<_>>())
}

/// `hashStruct(UA<Op>)` of one of the eight typed ops (`UAFreeze` .. `UAOperatorTransfer`).
pub fn struct_hash<O: RegulatedOp>(op: &O, e: &Envelope, target: &[u8; 20]) -> [u8; 32] {
    router_struct_hash(
        &type_string(O::NAME).expect("a RegulatedOp is in REGULATED_OPS"),
        e,
        target,
        op.field_words(),
    )
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
pub fn digest<O: RegulatedOp>(
    op: &O,
    domain_separator: &[u8; 32],
    e: &Envelope,
    target: &[u8; 20],
) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], domain_separator, &struct_hash(op, e, target)])
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
pub fn relax_commit(
    action: u8,
    bit: u8,
    account: &[u8; 32],
    terms: Option<&GrantTerms>,
) -> Option<[u8; 32]> {
    if !(1..=5).contains(&action) || (action == 2) != terms.is_some() {
        return None;
    }
    let args = terms.map_or([0; 32], |t| {
        keccak(&[
            &u128_word(t.min),
            &u128_word(t.max),
            &u128_word(t.total),
            &u128_word(t.per_window),
            &word(t.window as u64),
            &word(t.valid_until),
            &word(t.max_uses as u64),
            &word(t.delegable as u64),
            &t.scope,
        ])
    });
    Some(keccak(&[
        &word(action as u64),
        &word(bit as u64),
        account,
        &args,
    ]))
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
pub fn can_receive(
    required: Option<u64>,
    denied: Option<u64>,
    a: &Attestation,
    now: u64,
) -> (bool, u8) {
    if required.is_none() && denied.is_none() {
        return (true, 0);
    }
    let active = a.attester_enabled && a.valid_until >= now;
    let req = required.unwrap_or(0);
    if req != 0 && !(active && (a.flags & req == req || a.flags & ELIGIBLE_CONTRACT != 0)) {
        return (
            false,
            if a.valid_until == 0 {
                1
            } else if !a.attester_enabled {
                3
            } else if !active {
                2
            } else {
                1
            },
        );
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
    if registry {
        e
    } else {
        e & !(1 << 28)
    }
}

/// `UASetAllowed` (`allow`) or `UASetDenied`: bit 8's or bit 9's holder, 1-256 accounts, at once; `chainUid` the token's chain
/// word (the Change of CTR-GOV-28 in round 3zb + 3zc).
pub fn set_list_type(allow: bool) -> String {
    format!(
        "{}(bytes32 from,address target,bytes32[] accounts,bool on,bytes32 chainUid,{ENVELOPE})",
        if allow { "UASetAllowed" } else { "UASetDenied" }
    )
}

/// `hashStruct(UASetAllowed | UASetDenied)`: `accounts` as EIP-712 hashes an array (`keccak256` of its words).
pub fn set_list_struct_hash(
    allow: bool,
    e: &Envelope,
    target: &[u8; 20],
    accounts: &[[u8; 32]],
    on: bool,
    chain_uid: &[u8; 32],
) -> [u8; 32] {
    let words = keccak(&accounts.iter().map(|a| &a[..]).collect::<Vec<_>>());
    crate::wraplimit::struct_hash(
        keccak256(set_list_type(allow).as_bytes()),
        e,
        target,
        &[words, crate::wraplimit::bool_word(on), *chain_uid],
    )
}

/// `UAEnableFeature`: the admin switches on 8, 9 or 28; `chainUid` the token's chain word (CTR-GOV-28).
pub fn enable_feature_type() -> String {
    format!("UAEnableFeature(bytes32 from,address target,uint8 bit,bytes32 chainUid,{ENVELOPE})")
}

pub fn enable_feature_struct_hash(
    e: &Envelope,
    target: &[u8; 20],
    bit: u8,
    chain_uid: &[u8; 32],
) -> [u8; 32] {
    crate::wraplimit::struct_hash(
        keccak256(enable_feature_type().as_bytes()),
        e,
        target,
        &[word(bit as u64), *chain_uid],
    )
}
