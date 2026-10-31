//! `UaRegistry` (spec §3, §4): the UA records of a Soroban network and the per-kind verifiers. `ua_message` is always
//! computed here, never taken from an argument, and the SDK's `hazmat` feature is never enabled (spec §2): the
//! host-hash-only `Hash<32>` type carries it into the verifiers. No admin, no upgrade, the relayer list fixed at
//! construction (S16, C13).
#![no_std]
use scaas_ua_common::{
    h32, Checked, Registration, UaAttrs, PURPOSE_KEM, PURPOSE_MEMBER, PURPOSE_POP_V2, PURPOSE_PQZ_KEY,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, panic_with_error, xdr::FromXdr, Address,
    Bytes, BytesN, Env, IntoVal, TryFromVal, Val, Vec,
};

pub(crate) mod abi;
pub(crate) mod digest;
pub(crate) mod verify;
pub(crate) mod webauthn;

use digest::*;

/// SOR-D16. A host crypto failure (ed25519 / P-256 / ML-DSA verify) is a host error, not `Pop` (plan finding F1).
#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[repr(u32)]
pub enum Error {
    KindDisabled = 1,
    KeyData = 2,
    IdInNativeSpace = 3,
    AlreadyRegistered = 4,
    KeyInUse = 5,
    MemberUnknown = 6,
    Attrs = 7,
    Pop = 8,
    NotRegistered = 9,
    Unauthorized = 10,
    NotVerifiable = 11,
    RelayerNotListed = 12,
}

const DAY: u32 = 17_280;
const TTL_MIN: u32 = 30 * DAY;
const TTL_BUMP: u32 = 60 * DAY;

/// Persistent, one entry per key (S11); `Relayers` is the only instance entry. `Signer(ua)` holds the kind and key
/// data of a `signable` record, read alone by `require_authorized` and by `msig` member checks, so a check never loads
/// a record's `pop` (msig-pophash I1: a member with a large `pop` costs what any other member costs).
#[contracttype]
#[derive(Clone)]
pub(crate) enum Key {
    Relayers,
    Ua(BytesN<32>),
    Key(BytesN<32>),
    List(u32, u32),
    Count(u32),
    Signer(BytesN<32>),
}

/// `Registration` with `pop` replaced by `pop_hash = keccak256(pop)` (owner ruling 2026-10-30 after T0: the full record
/// overran the 16 384 B contract-events limit); `pop` stays in `Ua(ua)`.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegisteredRecord {
    pub kind: u32,
    pub key_data: Bytes,
    pub attrs: UaAttrs,
    pub pop_hash: BytesN<32>,
    pub pop_checked: Checked,
    pub pqz_pop_checked: Checked,
    pub proven: bool,
    pub signable: bool,
    pub index: u32,
    pub ledger: u32,
}

#[contractevent(topics = ["UaRegistered"], data_format = "vec")]
pub struct UaRegistered {
    #[topic]
    pub ua: BytesN<32>,
    #[topic]
    pub kind: u32,
    pub record: RegisteredRecord,
    pub checked: Checked,
}

/// `keccak256("scaas.ua.group.<g>.v1")` (pinned by `kinds.json` `groups`).
const GROUP_P256: [u8; 32] = h32("42536053999ec2faea9af0b9b0ddeca9a126a2f05231603786f112854f12c1df");
const GROUP_ED25519: [u8; 32] = h32("68b4870b8635a91eb90f5a22ac6c350df50d0ca1f9ba92db6b38b0718ea5b25c");
const GROUP_SECP256K1: [u8; 32] = h32("c9cbec9e3b9b4bf3014d4b68eb88e8d49c151a734c4c73503f7cadf2c8ff2b6e");
const GROUP_MLDSA44: [u8; 32] = h32("97a431380a20af85ba723ef86a2744e0b7f438ae5ef677d03c595ab697478065");
const GROUP_MLDSA65: [u8; 32] = h32("ce664790de9584777bd32d6bbce84b26b1a479d86be05f03ba5120eae90d40b2");
/// The field primes, big-endian: key coordinates must be canonical (`< p`).
const P256_P: [u8; 32] = h32("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const SECP256K1_P: [u8; 32] = h32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");

fn get<V: TryFromVal<Env, Val>>(env: &Env, k: &Key) -> Option<V> {
    let s = env.storage().persistent();
    let v = s.get(k);
    if v.is_some() {
        s.extend_ttl(k, TTL_MIN, TTL_BUMP);
    }
    v
}

fn put<V: IntoVal<Env, Val>>(env: &Env, k: &Key, v: &V) {
    let s = env.storage().persistent();
    s.set(k, v);
    s.extend_ttl(k, TTL_MIN, TTL_BUMP);
}

fn has(env: &Env, k: &Key) -> bool {
    env.storage().persistent().has(k)
}

fn fail(env: &Env, e: Error) -> ! {
    panic_with_error!(env, e)
}

/// CTR-UA-03: a derived id whose top 96 bits are zero is refused (one rule on every family).
pub(crate) fn in_native_space(id: &[u8; 32]) -> bool {
    id[..12] == [0u8; 12]
}

fn word(d: &Bytes, o: u32) -> [u8; 32] {
    let mut w = [0u8; 32];
    d.slice(o..o + 32).copy_into_slice(&mut w);
    w
}

fn u16_at(d: &Bytes, o: u32) -> u32 {
    (d.get_unchecked(o) as u32) << 8 | d.get_unchecked(o + 1) as u32
}

/// `msig` member `i` of validated key data (CTR-UA-09: `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖
/// u16 weight)`).
fn member(d: &Bytes, i: u32) -> (u32, [u8; 32], u32) {
    let o = 4 + 36 * i;
    (u16_at(d, o), word(d, o + 2), u16_at(d, o + 34))
}

/// The member kinds the `msig` layout admits (EVM `UAKinds.isMember` without `hedera-native`, plus the Soroban natives):
/// any other kind is `KeyData`; a kind of this set that Soroban does not enable is `MemberUnknown` (step 6), and so is
/// `soroban-contract` (S10, owner ruling 2026-10-31: a `C…` member would be authorised by Soroban invoker auth).
fn layout_member_ok(kind: u32, id: &[u8; 32]) -> bool {
    match kind {
        EVM_EOA | EVM_CONTRACT => in_native_space(id),
        STELLAR_ACCOUNT | SOROBAN_CONTRACT => true, // 32-byte G… / C… ids share the derived space (spec §2)
        0x0100..=0x0108 | 0x0110..=0x0113 | 0x0130..=0x0133 => !in_native_space(id),
        _ => false,
    }
}

fn msig_layout_ok(d: &Bytes) -> bool {
    if d.len() < 4 {
        return false;
    }
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    if count == 0 || count > 16 || d.len() != 4 + 36 * count {
        return false;
    }
    let (mut total, mut prev) = (0u32, None);
    for i in 0..count {
        let (kind, id, weight) = member(d, i);
        if !layout_member_ok(kind, &id) || weight == 0 || prev.is_some_and(|p| p >= id) {
            return false;
        }
        prev = Some(id);
        total += weight;
    }
    threshold != 0 && threshold <= total
}

/// Step 2: key data canonical (`KeyData`). P-256 / secp256k1 on-curve and the ed25519 "not a point" case are left to
/// the host's verify of the `pop` (a host error, plan finding F1).
fn check_key_data(env: &Env, kind: u32, d: &Bytes) {
    let coords = |p: &[u8; 32]| word(d, 0) < *p && word(d, 32) < *p;
    let ok = match kind {
        WEBAUTHN_P256 => d.len() == 96 && coords(&P256_P),
        P256 => d.len() == 64 && coords(&P256_P),
        SECP256K1 => d.len() == 64 && coords(&SECP256K1_P),
        ED25519 => d.len() == 32 && verify::ed25519_key_ok(&word(d, 0)),
        MLDSA44 => d.len() == 1312,
        MLDSA65 => d.len() == 1952,
        _ => msig_layout_ok(d),
    };
    if !ok {
        fail(env, Error::KeyData);
    }
}

/// CTR-UA-11: `keccak256(GROUP(g) ‖ canonical pubkey)` (x alone for the ECDSA kinds), `None` for `msig`.
pub(crate) fn key_hash(env: &Env, kind: u32, d: &Bytes) -> Option<BytesN<32>> {
    let (group, key) = match kind {
        WEBAUTHN_P256 | P256 => (GROUP_P256, d.slice(0..32)),
        SECP256K1 => (GROUP_SECP256K1, d.slice(0..32)),
        ED25519 => (GROUP_ED25519, d.clone()),
        MLDSA44 => (GROUP_MLDSA44, d.clone()),
        MLDSA65 => (GROUP_MLDSA65, d.clone()),
        _ => return None,
    };
    let mut b = Bytes::from_array(env, &group);
    b.append(&key);
    Some(env.crypto().keccak256(&b).into())
}

/// Step 6 (S10): each member is native (`evm-eoa`, `evm-contract`, `G…`) or a registered signable single-key UA of its
/// stated kind, else `MemberUnknown`. A `soroban-contract` (`C…`) member is `MemberUnknown` (owner ruling 2026-10-31,
/// final review: a contract that calls the registry, such as the token, would meet its own slot by invoker auth).
/// Returns `signable`: the weight Soroban can verify for signing (derived members and `G…`; the EVM natives weigh 0)
/// reaches the threshold.
fn check_members(env: &Env, d: &Bytes) -> bool {
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    let mut weight = 0;
    for i in 0..count {
        let (kind, id, w) = member(d, i);
        match kind {
            EVM_EOA | EVM_CONTRACT => {}
            STELLAR_ACCOUNT => weight += w,
            SOROBAN_CONTRACT => fail(env, Error::MemberUnknown),
            _ => match get::<(u32, Bytes)>(env, &Key::Signer(BytesN::from_array(env, &id))) {
                Some((k, _)) if k == kind => weight += w,
                _ => fail(env, Error::MemberUnknown),
            },
        }
    }
    weight >= threshold
}

/// A `stellar-account` (`G…`) member's `Address` from its 32-byte ed25519 key: the XDR `ScVal::Address` of the account.
fn stellar_account(env: &Env, id: &[u8; 32]) -> Address {
    let mut b = Bytes::from_array(env, &[0, 0, 0, 18]); // SCV_ADDRESS
    b.extend_from_array(&[0, 0, 0, 0, 0, 0, 0, 0]); // SC_ADDRESS_TYPE_ACCOUNT, PUBLIC_KEY_TYPE_ED25519
    b.extend_from_array(id);
    Address::from_xdr(env, &b).unwrap_or_else(|_| fail(env, Error::Pop))
}

/// An `msig` signature over `(ua, purpose, digest)`: `auth` = canonical `abi.encode(MemberSig[])`, strictly increasing
/// indexes below `count`, members under purpose `member` over `member_digest(ua, ua_message(MSIG, purpose, digest))`
/// until the threshold (a slot after it fails). A registered member's slot carries an empty `keyData` (its key read
/// from `Signer(id)` alone; non-empty ⇒ `Pop`); a `G…` member's slot is empty and checked by the host over
/// `(ua, purpose, digest)`; an `evm-eoa` member signs `personal_sign(member_digest)` for `portable` (the `pop` at
/// `register`) only; an `evm-contract` slot, and an `evm-eoa` slot outside `portable`, is `NotVerifiable` (SOR-D6).
/// A slot past the threshold or an unmet threshold is `short`.
fn check_msig(env: &Env, ua: &BytesN<32>, d: &Bytes, purpose: &BytesN<32>, digest: &BytesN<32>, auth: &Bytes, portable: bool, short: Error) {
    let sigs = abi::decode_member_sigs(env, auth);
    let md = member_digest(env, ua, &ua_message(env, MSIG, purpose, digest));
    let pm = BytesN::from_array(env, &PURPOSE_MEMBER);
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    let mut acc = 0;
    for s in sigs.iter() {
        if acc >= threshold || s.index >= count {
            fail(env, short);
        }
        let (kind, id, w) = member(d, s.index);
        if !s.key_data.is_empty() {
            fail(env, Error::Pop);
        }
        match kind {
            EVM_CONTRACT => fail(env, Error::NotVerifiable),
            EVM_EOA if !portable => fail(env, Error::NotVerifiable),
            EVM_EOA => {
                let id20: BytesN<20> = Bytes::from_array(env, &id).slice(12..32).try_into().unwrap();
                verify::check_evm_eoa_personal_sign(env, &id20, &md, &s.sig);
            }
            STELLAR_ACCOUNT => {
                if !s.sig.is_empty() {
                    fail(env, Error::Pop);
                }
                let args = (ua.clone(), purpose.clone(), digest.clone()).into_val(env);
                stellar_account(env, &id).require_auth_for_args(args);
            }
            _ => {
                let (_, key) = get::<(u32, Bytes)>(env, &Key::Signer(BytesN::from_array(env, &id)))
                    .unwrap_or_else(|| fail(env, short));
                verify::check(env, kind, &key, &ua_message(env, kind, &pm, &md), &s.sig);
            }
        }
        acc += w;
    }
    if acc < threshold {
        fail(env, short);
    }
}

fn empty_attrs(env: &Env) -> UaAttrs {
    UaAttrs { pqz_key: Bytes::new(env), pqz_pop_hash: BytesN::from_array(env, &[0; 32]), kem_version: 0, kem_pk: Bytes::new(env) }
}

fn bump_instance(env: &Env) {
    env.storage().instance().extend_ttl(TTL_MIN, TTL_BUMP);
}

#[contract]
pub struct UaRegistry;

#[contractimpl]
impl UaRegistry {
    pub fn __constructor(env: Env, relayers: Vec<Address>) {
        env.storage().instance().set(&Key::Relayers, &relayers);
        bump_instance(&env);
    }

    /// The portable form (UA-8 P1; spec §3 order): kind enabled → key data → id → not registered → keyHash free →
    /// `msig` members → `attrs` empty (UA-Soroban) → `pop` → store, list, event. Nothing is read from the submitter
    /// (CTR-UA-07); `relayer` is accepted and ignored for chain-verified parts (SOR-D6).
    pub fn register(
        env: Env,
        kind: u32,
        key_data: Bytes,
        attrs: UaAttrs,
        pop: Bytes,
        pqz_pop: Bytes,
        relayer: Option<Address>,
    ) -> BytesN<32> {
        let _ = relayer;
        if ![WEBAUTHN_P256, P256, ED25519, SECP256K1, MSIG, MLDSA44, MLDSA65].contains(&kind) {
            fail(&env, Error::KindDisabled);
        }
        check_key_data(&env, kind, &key_data);
        let ua = ua_of(&env, kind, &key_data);
        if in_native_space(&ua.to_array()) {
            fail(&env, Error::IdInNativeSpace);
        }
        if has(&env, &Key::Ua(ua.clone())) {
            fail(&env, Error::AlreadyRegistered);
        }
        let kh = key_hash(&env, kind, &key_data);
        if let Some(kh) = &kh {
            if has(&env, &Key::Key(kh.clone())) {
                fail(&env, Error::KeyInUse);
            }
        }
        let signable = kind != MSIG || check_members(&env, &key_data);
        if attrs != empty_attrs(&env) || !pqz_pop.is_empty() {
            fail(&env, Error::Attrs);
        }
        let zero = BytesN::from_array(&env, &[0; 32]);
        let reg = registration_digest(&env, &portable_pop_digest(&env, &ua, &zero, &zero), &zero);
        let pv2 = BytesN::from_array(&env, &PURPOSE_POP_V2);
        if kind == MSIG {
            check_msig(&env, &ua, &key_data, &pv2, &reg, &pop, true, Error::Pop);
        } else {
            verify::check(&env, kind, &key_data, &ua_message(&env, kind, &pv2, &reg), &pop);
        }

        let index = get::<u32>(&env, &Key::Count(kind)).unwrap_or(0);
        put(&env, &Key::List(kind, index), &ua);
        put(&env, &Key::Count(kind), &(index + 1));
        if let Some(kh) = kh {
            put(&env, &Key::Key(kh), &ua);
        }
        if signable {
            put(&env, &Key::Signer(ua.clone()), &(kind, key_data.clone()));
        }
        let ledger = env.ledger().sequence();
        let record = RegisteredRecord {
            kind,
            key_data: key_data.clone(),
            attrs: attrs.clone(),
            pop_hash: env.crypto().keccak256(&pop).into(),
            pop_checked: Checked::Chain,
            pqz_pop_checked: Checked::None,
            proven: false,
            signable,
            index,
            ledger,
        };
        let r = Registration {
            kind,
            key_data,
            attrs,
            pop,
            pop_checked: Checked::Chain,
            pqz_pop_checked: Checked::None,
            proven: false,
            signable,
            index,
            ledger,
        };
        put(&env, &Key::Ua(ua.clone()), &r);
        bump_instance(&env);
        UaRegistered { ua: ua.clone(), kind, record, checked: Checked::Chain }.publish(&env);
        ua
    }

    /// CTR-UA-17's Soroban form: `NotRegistered`, then `Unauthorized` unless `signable` and `purpose` is not a portable
    /// one (`pop` v2, `kem`, `pqz-key`), then the kind's check over `ua_message(kind, purpose, digest)`; `msig` members
    /// under purpose `member` until the threshold. Extends `Ua(ua)`.
    pub fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: Bytes) {
        let Some((kind, key)) = get::<(u32, Bytes)>(&env, &Key::Signer(ua.clone())) else {
            let e = if has(&env, &Key::Ua(ua.clone())) { Error::Unauthorized } else { Error::NotRegistered };
            fail(&env, e)
        };
        let p = purpose.to_array();
        if p == PURPOSE_POP_V2 || p == PURPOSE_KEM || p == PURPOSE_PQZ_KEY {
            fail(&env, Error::Unauthorized);
        }
        env.storage().persistent().extend_ttl(&Key::Ua(ua.clone()), TTL_MIN, TTL_BUMP);
        bump_instance(&env);
        if kind == MSIG {
            check_msig(&env, &ua, &key, &purpose, &digest, &auth, false, Error::Unauthorized);
        } else {
            verify::check(&env, kind, &key, &ua_message(&env, kind, &purpose, &digest), &auth);
        }
    }

    /// Exactly the `register` arguments `(kind, key_data, attrs, pop, pqz_pop)`.
    pub fn registration_of(env: Env, ua: BytesN<32>) -> Option<(u32, Bytes, UaAttrs, Bytes, Bytes)> {
        get::<Registration>(&env, &Key::Ua(ua)).map(|r| (r.kind, r.key_data, r.attrs, r.pop, Bytes::new(&env)))
    }

    pub fn record_of(env: Env, ua: BytesN<32>) -> Option<Registration> {
        get(&env, &Key::Ua(ua))
    }

    pub fn key_owner(env: Env, key_hash: BytesN<32>) -> Option<BytesN<32>> {
        get(&env, &Key::Key(key_hash))
    }

    pub fn ua_of(env: Env, kind: u32, key_data: Bytes) -> BytesN<32> {
        digest::ua_of(&env, kind, &key_data)
    }

    /// `signable`; `false` for an unregistered id too (SOR-D15).
    pub fn receivable(env: Env, ua: BytesN<32>) -> bool {
        get::<(u32, Bytes)>(&env, &Key::Signer(ua)).is_some()
    }

    pub fn relayers(env: Env) -> Vec<Address> {
        bump_instance(&env);
        env.storage().instance().get(&Key::Relayers).unwrap()
    }

    pub fn ua_count(env: Env, kind: u32) -> u32 {
        get(&env, &Key::Count(kind)).unwrap_or(0)
    }

    /// The `i`-th UA of `kind` (CTR-UA-29); `NotRegistered` past the end.
    pub fn ua_at(env: Env, kind: u32, i: u32) -> BytesN<32> {
        get(&env, &Key::List(kind, i)).unwrap_or_else(|| fail(&env, Error::NotRegistered))
    }

    /// `ua_at(kind, start ..< start + n)`, clamped to the list.
    pub fn ua_page(env: Env, kind: u32, start: u32, n: u32) -> Vec<BytesN<32>> {
        let count = Self::ua_count(env.clone(), kind);
        let mut out = Vec::new(&env);
        for i in start.min(count)..start.saturating_add(n).min(count) {
            out.push_back(Self::ua_at(env.clone(), kind, i));
        }
        out
    }
}

#[cfg(test)]
mod test;
#[cfg(test)]
mod test_verify;
