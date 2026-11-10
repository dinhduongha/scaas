// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Group 3l (wrap limits spec 2026-11-10-wrap-limits.md §2.1, §6, §9): the `GovernanceRouter`'s two ops on the hybrids of the
//! wrapped kinds, `UASetWrapLimits` (the leg array hashed as EIP-712 does: the concatenated `WrapLegLimits` struct hashes, each
//! over its four `WrapLimit` struct hashes) and `UASetWrapMember`, their struct hashes and digests in the router's domain
//! (`MetaTxLib.canon`'s zeroing of an unbound `relayer` / `feeRecipient`), and the net-wrapped entitlement as the contract
//! computes it (a wallet's preview between reads; R23, R24, R26). Pinned by `smartcontracts/vectors/typed/typed_ops.json`
//! (clientkeys) and `wraplimits/wraplimits.json` (its generator, replayed by forge). The contract decides; nothing here is a
//! check of record. UNAUDITED.
use crate::regulated::Envelope;
use crate::{address_word, keccak, keccak256, word};

const ENVELOPE: &str =
    "uint256 batch,uint256 nonce,uint256 validUntil,uint32 mode,address relayer,uint256 fee,address feeRecipient";
pub const WRAP_LIMIT_TYPE: &str = "WrapLimit(uint24 perUser,uint64 tokenWide,uint32 period)";
pub const WRAP_LEG_LIMITS_TYPE: &str = "WrapLegLimits(address underlying,uint8 unitExp,uint16 decayDays,WrapLimit wrapShort,WrapLimit wrapLong,WrapLimit unwrapShort,WrapLimit unwrapLong)";

/// One limit (`IWrappedToken.WrapLimit`): quanta per id and window, quanta for all ids, the window in seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WrapLimit {
    pub per_user: u32,
    pub token_wide: u64,
    pub period: u32,
}

/// A leg's limits (`IWrappedToken.WrapLegLimits`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WrapLegLimits {
    pub underlying: [u8; 20],
    pub unit_exp: u8,
    pub decay_days: u16,
    pub wrap_short: WrapLimit,
    pub wrap_long: WrapLimit,
    pub unwrap_short: WrapLimit,
    pub unwrap_long: WrapLimit,
}

/// `UASetWrapLimits(…)` with its referenced types in EIP-712 order.
pub fn set_wrap_limits_type() -> String {
    format!("UASetWrapLimits(bytes32 from,address target,WrapLegLimits[] legs,bool netUnwrap,bool wrapList,bool unwrapList,{ENVELOPE}){WRAP_LEG_LIMITS_TYPE}{WRAP_LIMIT_TYPE}")
}

pub fn set_wrap_member_type() -> String {
    format!("UASetWrapMember(bytes32 from,address target,bytes32 account,bool canWrap,bool canUnwrap,{ENVELOPE})")
}

fn limit_hash(l: &WrapLimit) -> [u8; 32] {
    keccak(&[&keccak256(WRAP_LIMIT_TYPE.as_bytes()), &word(l.per_user as u64), &word(l.token_wide), &word(l.period as u64)])
}

fn leg_hash(l: &WrapLegLimits) -> [u8; 32] {
    let th = keccak256(format!("{WRAP_LEG_LIMITS_TYPE}{WRAP_LIMIT_TYPE}").as_bytes());
    keccak(&[&th, &address_word(&l.underlying), &word(l.unit_exp as u64), &word(l.decay_days as u64), &limit_hash(&l.wrap_short),
        &limit_hash(&l.wrap_long), &limit_hash(&l.unwrap_short), &limit_hash(&l.unwrap_long)])
}

/// `hashStruct(WrapLegLimits[])`: `keccak256` of the concatenated struct hashes.
pub fn legs_hash(legs: &[WrapLegLimits]) -> [u8; 32] {
    let hs: Vec<[u8; 32]> = legs.iter().map(leg_hash).collect();
    keccak(&hs.iter().map(|h| &h[..]).collect::<Vec<_>>())
}

fn struct_hash(typehash: [u8; 32], e: &Envelope, target: &[u8; 20], words: &[[u8; 32]]) -> [u8; 32] {
    let canon = |bound: bool, a: &[u8; 20]| if bound { address_word(a) } else { [0; 32] };
    let mut w: Vec<[u8; 32]> = vec![typehash, e.from, address_word(target)];
    w.extend_from_slice(words);
    w.extend([e.batch, e.nonce, e.valid_until, word(e.mode as u64), canon(e.mode & 1 != 0, &e.relayer), e.fee,
        canon(e.mode & 2 != 0, &e.fee_recipient)]);
    keccak(&w.iter().map(|x| &x[..]).collect::<Vec<_>>())
}

fn bool_word(b: bool) -> [u8; 32] {
    word(b as u64)
}

/// `hashStruct(UASetWrapLimits)`.
pub fn set_wrap_limits_struct_hash(e: &Envelope, target: &[u8; 20], legs: &[WrapLegLimits], net_unwrap: bool, wrap_list: bool,
    unwrap_list: bool) -> [u8; 32]
{
    struct_hash(keccak256(set_wrap_limits_type().as_bytes()), e, target,
        &[legs_hash(legs), bool_word(net_unwrap), bool_word(wrap_list), bool_word(unwrap_list)])
}

/// `hashStruct(UASetWrapMember)`.
pub fn set_wrap_member_struct_hash(e: &Envelope, target: &[u8; 20], account: &[u8; 32], can_wrap: bool, can_unwrap: bool)
    -> [u8; 32]
{
    struct_hash(keccak256(set_wrap_member_type().as_bytes()), e, target, &[*account, bool_word(can_wrap), bool_word(can_unwrap)])
}

/// `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`, the router's domain (`regulated::router_domain_separator`).
pub fn digest(domain_separator: &[u8; 32], struct_hash: &[u8; 32]) -> [u8; 32] {
    keccak(&[&[0x19, 0x01], domain_separator, struct_hash])
}

/// An id's net-wrapped line on one leg (spec §2.1 in minutes, R26): `base` in quanta (saturating at `2^32 − 1`), `start_min` an
/// absolute minute; `decay_days` 0 = no decay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NetLine {
    pub base: u64,
    pub start_min: u64,
}

impl NetLine {
    /// `(E, the age clamped)` at `now_min` (`E = base` without the decay).
    fn ent(&self, decay_days: u16, now_min: u64) -> (u128, u128) {
        let g = now_min.saturating_sub(self.start_min) as u128;
        let h = decay_days as u128 * 1440;
        if h == 0 {
            return (self.base as u128, g);
        }
        let g = g.min(h);
        (self.base as u128 * (h - g) / h, g)
    }

    /// The entitlement in quanta at `now_min`.
    pub fn entitlement(&self, decay_days: u16, now_min: u64) -> u64 {
        self.ent(decay_days, now_min).0 as u64
    }

    /// A wrap of `a = ⌊received/unit⌋` quanta: the weighted start rounded older, the base rescaled, `b' ≤ b + a`.
    pub fn credit(&mut self, a: u64, decay_days: u16, now_min: u64) {
        if a == 0 {
            return;
        }
        let (e, g) = self.ent(decay_days, now_min);
        let a = a as u128;
        let g2 = (e * g).div_ceil(e + a);
        let h = decay_days as u128 * 1440;
        let mut b2 = self.base as u128 + a;
        if h != 0 {
            b2 = b2.min((e + a) * h / (h - g2));
        }
        self.base = b2.min(u32::MAX as u128) as u64;
        self.start_min = now_min - g2 as u64;
    }

    /// An unwrap of `q = ⌈out/unit⌉` quanta the rule allows (or a redeemer's): `q ≥ E` ⇒ 0, else `⌊b·(E − q)/E⌋`.
    pub fn debit(&mut self, q: u64, decay_days: u16, now_min: u64) {
        let (e, _) = self.ent(decay_days, now_min);
        let q = q as u128;
        self.base = if q >= e { 0 } else { (self.base as u128 * (e - q) / e) as u64 };
    }
}
