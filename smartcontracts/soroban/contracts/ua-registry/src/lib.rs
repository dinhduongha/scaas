//! `UaRegistry` (spec §3, §4): the UA records of a Soroban network and the per-kind verifiers. `ua_message` is always
//! computed here, never taken from an argument, and the SDK's `hazmat` feature is never enabled (spec §2): the
//! host-hash-only `Hash<32>` type carries it into the verifiers. No admin, no upgrade, the relayer list fixed at
//! construction (S16, C13).
#![no_std]
use scaas_ua_common::{
    h32, kem_pk, kem_pk_record_hash, kem_record_hash, portable_record_hash, pqz_key_hash, registration_digest, Checked,
    KemKey, MemberSig, MsigStructure, Registration, UaAttrs, UaSig, WebAuthnKey, PURPOSE_KEM, PURPOSE_MEMBER,
    PURPOSE_POP_V2, PURPOSE_PQZ_KEY,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, crypto::Hash, panic_with_error, xdr::FromXdr,
    Address, Bytes, BytesN, Env, IntoVal, String, TryFromVal, Val, Vec,
};

pub(crate) mod abi;
pub(crate) mod digest;
pub(crate) mod verify;
pub(crate) mod webauthn;

use digest::*;

/// SOR-D16, U8S-D5, TS-D5. A host crypto failure (ed25519 / P-256 / ML-DSA verify) is a host error, not `Pop` (plan
/// finding F1). `Attrs` is unused since UA-8 attributes register; it keeps its code point.
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
    PqzHolder = 13,
    KemHolder = 14,
    KemVersion = 15,
    KemKeyLength = 16,
    PqzPopHash = 17,
    KemScheme = 18,
    PqzKeySet = 19,
    KindUnknown = 20,
}

const DAY: u32 = 17_280;
const TTL_MIN: u32 = 30 * DAY;
const TTL_BUMP: u32 = 60 * DAY;

/// Persistent, one entry per key (S11); `Relayers` is the only instance entry. `Signer(ua)` holds the kind and key
/// data of a `signable` record, read alone by `require_authorized` and by `msig` member checks, so a check never loads
/// a record's `pop` (msig-pophash I1: a member with a large `pop` costs what any other member costs). `PqzK(ua)` =
/// `(key, sig, Checked)`, `PqzP(ua)` = the proof bytes, `Kem(ua, version)` = `(pk, sig, Checked)`, `KemMax(ua)` = the
/// highest `set_kem_key` version: the bytes stay in state, `Ua(ua)` holds neither key (U8S-D3).
#[contracttype]
#[derive(Clone)]
pub(crate) enum Key {
    Relayers,
    Ua(BytesN<32>),
    Key(BytesN<32>),
    List(u32, u32),
    Count(u32),
    Signer(BytesN<32>),
    PqzK(BytesN<32>),
    PqzP(BytesN<32>),
    Kem(BytesN<32>, u64),
    KemMax(BytesN<32>),
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

/// U8S-D4: the 16,384 B events limit cannot carry the bytes, so a PQZ key or KEM key is logged by its hashes.
#[contractevent(topics = ["UaPqzKeySet"], data_format = "vec")]
pub struct UaPqzKeySet {
    #[topic]
    pub ua: BytesN<32>,
    pub pqz_key_hash: BytesN<32>,
    pub pqz_pop_hash: BytesN<32>,
    pub sig_hash: BytesN<32>,
    pub checked: Checked,
}

#[contractevent(topics = ["UaPqzPopStored"], data_format = "vec")]
pub struct UaPqzPopStored {
    #[topic]
    pub ua: BytesN<32>,
    pub pqz_pop_hash: BytesN<32>,
}

#[contractevent(topics = ["UaKemKeySet"], data_format = "vec")]
pub struct UaKemKeySet {
    #[topic]
    pub ua: BytesN<32>,
    #[topic]
    pub version: u64,
    pub kem_pk_hash: BytesN<32>,
    pub sig_hash: BytesN<32>,
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
/// `keccak256("")`: refused as a `pqz_pop_hash`, the hash of no proof (EVM `EMPTY_PROOF_HASH`).
const EMPTY_HASH: [u8; 32] = h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
/// CTR-UA-32: scheme 1 = ML-KEM-1024 + X25519, `scheme ‖ ek ‖ x25519` (2 is reserved).
const KEM_SCHEME: u32 = 1;
const KEM_PK_LENGTH: u32 = 1_601;

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

/// EVM `_pqEligible` (CTR-PQZ-12): the members outside 0x0130–0x0133 weigh less than the threshold, so a PQ member must
/// sign. Only such an `msig` has a `pop` of its own (U8S-D2, CTR-UA-07).
fn pq_eligible(d: &Bytes) -> bool {
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    let mut classical = 0;
    for i in 0..count {
        let (kind, _, w) = member(d, i);
        if !(0x0130..=0x0133).contains(&kind) {
            classical += w;
        }
    }
    classical < threshold
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

/// An `msig` signature over `(ua, purpose, digest)`: `sigs` with strictly increasing indexes below `count`, members under
/// purpose `member` over `member_digest(ua, ua_message(MSIG, purpose, digest))` until the threshold (a slot after it
/// fails). A registered member's slot carries an empty `keyData` (its key read
/// from `Signer(id)` alone; non-empty ⇒ `short`); a `G…` member's slot is empty and checked by the host over
/// `(ua, purpose, digest)`; an `evm-eoa` member signs the record's typed digest `portable` itself (ECDSA, the `pop` at
/// `register` only; typed-signing TS-D4, `eth_signTypedData_v4`, no `personal_sign`); an `evm-contract` slot, and an
/// `evm-eoa` slot outside `portable`, is `NotVerifiable` (SOR-D6). A slot past the threshold or an unmet threshold is
/// `short`. `portable` is a stored signature, so it is minimal too (owner 2026-10-31, U8S-D1, every slot's weight counts,
/// native ones included): with T the slots' total weight and N the threshold, T - min(weight) < N, else `short`.
fn check_msig(env: &Env, ua: &BytesN<32>, d: &Bytes, purpose: &BytesN<32>, digest: &BytesN<32>, sigs: &Vec<MemberSig>, portable: Option<&Hash<32>>, short: Error) {
    let md = member_digest(env, ua, &ua_message(env, MSIG, purpose, digest));
    let pm = BytesN::from_array(env, &PURPOSE_MEMBER);
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    let (mut acc, mut w_min, mut next) = (0, u32::MAX, 0);
    for s in sigs.iter() {
        if acc >= threshold || s.index < next || s.index >= count {
            fail(env, short);
        }
        next = s.index + 1;
        let (kind, id, w) = member(d, s.index);
        if !s.key_data.is_empty() {
            fail(env, short);
        }
        match kind {
            EVM_CONTRACT => fail(env, Error::NotVerifiable),
            EVM_EOA => {
                let typed = portable.unwrap_or_else(|| fail(env, Error::NotVerifiable));
                let id20: BytesN<20> = Bytes::from_array(env, &id).slice(12..32).try_into().unwrap();
                verify::check_evm_eoa(env, &id20, typed, &s.sig);
            }
            STELLAR_ACCOUNT => {
                if !s.sig.is_empty() {
                    fail(env, short);
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
        w_min = w_min.min(w);
    }
    if acc < threshold || (portable.is_some() && acc - w_min >= threshold) {
        fail(env, short);
    }
}

fn zero(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

/// A PQZ / KEM holder (EVM `_holder`, U8S-D6): `mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`.
fn holder(kind: u32, d: &Bytes) -> bool {
    matches!(kind, MLDSA44 | MLDSA65 | FNDSA512) || (kind == MSIG && pq_eligible(d))
}

/// Step 5, EVM `_attrs` in its order: holders, the proof hash, the PQZ key's length (one of the four sets), the KEM key
/// (whole or committed; `register` takes no version: it is version 0). Returns the whole KEM key (empty when none or
/// committed), `pqzKeyHash` (0 without a key) and the `UAPortableRecord` struct hash.
fn check_attrs(env: &Env, kind: u32, d: &Bytes, ua: &BytesN<32>, attrs: &UaAttrs, pqz_pop: &Bytes) -> (Bytes, BytesN<32>, BytesN<32>) {
    let none = zero(env);
    let pqz = !attrs.pqz_key.is_empty();
    let commit = attrs.kem_pk_hash != none;
    let pk = if commit { Bytes::new(env) } else { kem_pk(env, &attrs.kem) };
    let hold = holder(kind, d);
    if pqz && !hold {
        fail(env, Error::PqzHolder);
    }
    if (commit || !pk.is_empty()) && !hold {
        fail(env, Error::KemHolder);
    }
    if pqz != (attrs.pqz_pop_hash != none) || attrs.pqz_pop_hash.to_array() == EMPTY_HASH {
        fail(env, Error::PqzPopHash);
    }
    if !pqz_pop.is_empty() && BytesN::from(env.crypto().keccak256(pqz_pop)) != attrs.pqz_pop_hash {
        fail(env, Error::PqzPopHash);
    }
    let n = attrs.pqz_key.len();
    if pqz && (!(16_384..=22_528).contains(&n) || n % 2_048 != 0) {
        fail(env, Error::KeyData);
    }
    let h = if pqz { pqz_key_hash(env, &attrs.pqz_key) } else { none.clone() };
    let kh = if commit {
        if !attrs.kem.mlkem_ek.is_empty() || attrs.kem.x25519 != none {
            fail(env, Error::KemKeyLength);
        }
        if attrs.kem.scheme != KEM_SCHEME {
            fail(env, Error::KemScheme);
        }
        kem_record_hash(env, ua, 0, KEM_SCHEME as u8, &attrs.kem_pk_hash)
    } else {
        if !pk.is_empty() && attrs.kem.scheme != KEM_SCHEME {
            fail(env, Error::KemScheme);
        }
        if !pk.is_empty() && pk.len() != KEM_PK_LENGTH {
            fail(env, Error::KemKeyLength);
        }
        kem_pk_record_hash(env, ua, 0, &pk)
    };
    let rec = portable_record_hash(env, ua, kind, &h, &kh);
    (pk, h, rec)
}

/// The CTR-UA-09 key data of a typed structure (EVM `registerMsig`); `KeyData` for a value its `u16` cannot hold, so no
/// truncated id; the layout itself is `check_key_data`'s.
fn msig_key_data(env: &Env, s: &MsigStructure) -> Bytes {
    if s.threshold > 0xFFFF || s.members.len() > 16 {
        fail(env, Error::KeyData);
    }
    let mut d = Bytes::from_slice(env, &(s.threshold as u16).to_be_bytes());
    d.extend_from_slice(&(s.members.len() as u16).to_be_bytes());
    for m in s.members.iter() {
        if m.kind > 0xFFFF || m.weight > 0xFFFF {
            fail(env, Error::KeyData);
        }
        d.extend_from_slice(&(m.kind as u16).to_be_bytes());
        d.extend_from_array(&m.id.to_array());
        d.extend_from_slice(&(m.weight as u16).to_be_bytes());
    }
    d
}

/// The portable form (UA-8 P1; spec §3 order, EVM `_register`): kind enabled → key data → id → not registered → keyHash
/// free → `msig` members → attributes → `pop` (`sig`, or an `msig`'s `members`) → store, list, events. Nothing is read
/// from the submitter (CTR-UA-07). The PQZ key and proof and the KEM key stay in state (`PqzK`, `PqzP`, `Kem(ua, 0)`),
/// unproven (U8S-D3, U8S-D6: no verifier, no `Key` entry); the events carry hashes (U8S-D4).
fn register_record(env: &Env, kind: u32, key_data: Bytes, attrs: UaAttrs, sig: Bytes, members: Vec<MemberSig>, pqz_pop: Bytes) -> BytesN<32> {
    if ![WEBAUTHN_P256, P256, ED25519, SECP256K1, MSIG, MLDSA44, MLDSA65].contains(&kind) {
        fail(env, Error::KindDisabled);
    }
    check_key_data(env, kind, &key_data);
    let ua = ua_of(env, kind, &key_data);
    if in_native_space(&ua.to_array()) {
        fail(env, Error::IdInNativeSpace);
    }
    if has(env, &Key::Ua(ua.clone())) {
        fail(env, Error::AlreadyRegistered);
    }
    let kh = key_hash(env, kind, &key_data);
    if let Some(kh) = &kh {
        if has(env, &Key::Key(kh.clone())) {
            fail(env, Error::KeyInUse);
        }
    }
    let signable = kind != MSIG || check_members(env, &key_data);
    let (pk, pqz_hash, rec) = check_attrs(env, kind, &key_data, &ua, &attrs, &pqz_pop);
    let typed = registration_digest(env, &rec, &attrs.pqz_pop_hash);
    let reg = typed.to_bytes();
    let pv2 = BytesN::from_array(env, &PURPOSE_POP_V2);
    if kind == MSIG {
        if pq_eligible(&key_data) {
            check_msig(env, &ua, &key_data, &pv2, &reg, &members, Some(&typed), Error::Pop);
        } else if !members.is_empty() {
            fail(env, Error::Pop); // classical-dominant: its members proved theirs, as EVM (U8S-D2)
        }
    } else {
        verify::check(env, kind, &key_data, &ua_message(env, kind, &pv2, &reg), &sig);
    }
    let pop = if kind == MSIG { abi::encode_member_sigs(env, &members) } else { sig };

    let index = get::<u32>(env, &Key::Count(kind)).unwrap_or(0);
    put(env, &Key::List(kind, index), &ua);
    put(env, &Key::Count(kind), &(index + 1));
    if let Some(kh) = kh {
        put(env, &Key::Key(kh), &ua);
    }
    if signable {
        put(env, &Key::Signer(ua.clone()), &(kind, key_data.clone()));
    }
    let no_sig = Bytes::new(env);
    let sig_hash = BytesN::from_array(env, &EMPTY_HASH);
    if !attrs.pqz_key.is_empty() {
        put(env, &Key::PqzK(ua.clone()), &(attrs.pqz_key.clone(), no_sig.clone(), Checked::Chain));
        let pqz_pop_hash = attrs.pqz_pop_hash.clone();
        UaPqzKeySet { ua: ua.clone(), pqz_key_hash: pqz_hash, pqz_pop_hash, sig_hash: sig_hash.clone(), checked: Checked::Chain }.publish(env);
    }
    if !pqz_pop.is_empty() {
        put(env, &Key::PqzP(ua.clone()), &pqz_pop);
        UaPqzPopStored { ua: ua.clone(), pqz_pop_hash: attrs.pqz_pop_hash.clone() }.publish(env);
    }
    if !pk.is_empty() {
        put(env, &Key::Kem(ua.clone(), 0), &(pk.clone(), no_sig, Checked::Chain));
        UaKemKeySet { ua: ua.clone(), version: 0, kem_pk_hash: env.crypto().keccak256(&pk).into(), sig_hash, checked: Checked::Chain }.publish(env);
    }
    let kem = KemKey { scheme: if attrs.kem_pk_hash != zero(env) { attrs.kem.scheme } else { 0 }, ..KemKey::none(env) };
    let attrs = UaAttrs { pqz_key: Bytes::new(env), kem, ..attrs };
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
    put(env, &Key::Ua(ua.clone()), &r);
    bump_instance(env);
    UaRegistered { ua: ua.clone(), kind, record, checked: Checked::Chain }.publish(env);
    ua
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

    /// A single-key `kind` (`register_record`); `msig` only through `register_msig` (`KeyData`, as EVM). `relayer` is
    /// accepted and ignored for chain-verified parts (SOR-D6).
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
        if kind == MSIG {
            fail(&env, Error::KeyData);
        }
        let members = Vec::new(&env);
        register_record(&env, kind, key_data, attrs, pop, members, pqz_pop)
    }

    /// A `webauthn-p256` key from its fields (EVM `registerWebAuthn`, TS-D13): `x ‖ y ‖ rp_id_hash` is assembled here, so
    /// the id, the digests and the record are those of `register(0x0100, …)`, which stays, as EVM.
    pub fn register_webauthn(
        env: Env,
        key: WebAuthnKey,
        attrs: UaAttrs,
        pop: Bytes,
        pqz_pop: Bytes,
        relayer: Option<Address>,
    ) -> BytesN<32> {
        let _ = relayer;
        let mut d = Bytes::from_array(&env, &key.x.to_array());
        d.extend_from_array(&key.y.to_array());
        d.extend_from_array(&key.rp_id_hash.to_array());
        let members = Vec::new(&env);
        register_record(&env, WEBAUTHN_P256, d, attrs, pop, members, pqz_pop)
    }

    /// An `msig` from its typed structure and member signatures (EVM `registerMsig`, TS-D10): the CTR-UA-09 key data is
    /// assembled here, `pop` is stored as `abi.encode(MemberSig[])`, empty for no slots, as EVM.
    pub fn register_msig(
        env: Env,
        structure: MsigStructure,
        attrs: UaAttrs,
        pop: Vec<MemberSig>,
        pqz_pop: Bytes,
        relayer: Option<Address>,
    ) -> BytesN<32> {
        let _ = relayer;
        let d = msig_key_data(&env, &structure);
        register_record(&env, MSIG, d, attrs, Bytes::new(&env), pop, pqz_pop)
    }

    /// CTR-UA-17's Soroban form: `NotRegistered`, then `Unauthorized` unless `signable` and `purpose` is not a portable
    /// one (`pop` v2, `kem`, `pqz-key`), then the kind's check over `ua_message(kind, purpose, digest)`; `msig` members
    /// under purpose `member` until the threshold. `auth` (TS-D12): a single key only `signature`, an `msig` only
    /// `members`, any other field set is `Unauthorized`. Extends `Ua(ua)`.
    pub fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: UaSig) {
        let Some((kind, key)) = get::<(u32, Bytes)>(&env, &Key::Signer(ua.clone())) else {
            let e = if has(&env, &Key::Ua(ua.clone())) { Error::Unauthorized } else { Error::NotRegistered };
            fail(&env, e)
        };
        let p = purpose.to_array();
        if p == PURPOSE_POP_V2 || p == PURPOSE_KEM || p == PURPOSE_PQZ_KEY {
            fail(&env, Error::Unauthorized);
        }
        if !auth.key_data.is_empty() || (kind == MSIG && !auth.signature.is_empty()) || (kind != MSIG && !auth.members.is_empty()) {
            fail(&env, Error::Unauthorized);
        }
        env.storage().persistent().extend_ttl(&Key::Ua(ua.clone()), TTL_MIN, TTL_BUMP);
        bump_instance(&env);
        if kind == MSIG {
            check_msig(&env, &ua, &key, &purpose, &digest, &auth.members, None, Error::Unauthorized);
        } else {
            verify::check(&env, kind, &key, &ua_message(&env, kind, &purpose, &digest), &auth.signature);
        }
    }

    /// Exactly the `register` arguments `(kind, key_data, attrs, pop, pqz_pop)`, EVM `registrationOf` line by line
    /// (U8S-D3): the PQZ key and proof iff `register` carried them, the KEM key at version 0 or its hash commit.
    pub fn registration_of(env: Env, ua: BytesN<32>) -> Option<(u32, Bytes, UaAttrs, Bytes, Bytes)> {
        let r = get::<Registration>(&env, &Key::Ua(ua.clone()))?;
        let mut a = r.attrs;
        let mut pqz_pop = Bytes::new(&env);
        if a.pqz_pop_hash != zero(&env) {
            let (key, _, _) = get::<(Bytes, Bytes, Checked)>(&env, &Key::PqzK(ua.clone())).unwrap();
            a.pqz_key = key;
            pqz_pop = get(&env, &Key::PqzP(ua.clone())).unwrap_or(pqz_pop);
        }
        if a.kem_pk_hash == zero(&env) {
            if let Some((pk, _, _)) = get::<(Bytes, Bytes, Checked)>(&env, &Key::Kem(ua, 0)) {
                let (ek, x) = (pk.slice(1..KEM_PK_LENGTH - 32), pk.slice(KEM_PK_LENGTH - 32..KEM_PK_LENGTH));
                a.kem = KemKey { scheme: KEM_SCHEME, mlkem_ek: ek, x25519: x.try_into().unwrap() };
            }
        }
        Some((r.kind, r.key_data, a, r.pop, pqz_pop))
    }

    /// The stored `pop`, empty for an unregistered id.
    pub fn pop_of(env: Env, ua: BytesN<32>) -> Bytes {
        get::<Registration>(&env, &Key::Ua(ua)).map_or(Bytes::new(&env), |r| r.pop)
    }

    /// The stored PQZ proof, empty when none.
    pub fn pqz_pop_of(env: Env, ua: BytesN<32>) -> Bytes {
        get(&env, &Key::PqzP(ua)).unwrap_or(Bytes::new(&env))
    }

    /// `(pop, pqz_pop, kem)` (EVM CTR-UA-31 `checkedOf`): `kem` is the highest stored record's, `None` without one (a
    /// hash-committed key not filled yet); all `None` for an unregistered id.
    pub fn checked_of(env: Env, ua: BytesN<32>) -> (Checked, Checked, Checked) {
        let Some(r) = get::<Registration>(&env, &Key::Ua(ua.clone())) else {
            return (Checked::None, Checked::None, Checked::None);
        };
        let v = get::<u64>(&env, &Key::KemMax(ua.clone())).unwrap_or(0);
        let kem = get::<(Bytes, Bytes, Checked)>(&env, &Key::Kem(ua, v)).map_or(Checked::None, |e| e.2);
        (r.pop_checked, r.pqz_pop_checked, kem)
    }

    /// TS-D5: the name of a kind id of the table, enabled here or not; `KindUnknown` for any other id.
    pub fn kind_name(env: Env, kind: u32) -> String {
        digest::kind_name(&env, kind)
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
mod test_ua8;
#[cfg(test)]
mod test_verify;
