//! `UaRegistry` (spec §3, §4): the UA records of a Soroban network and the per-kind verifiers. `ua_message` is always
//! computed here, never taken from an argument, and the SDK's `hazmat` feature is never enabled (spec §2): the
//! host-hash-only `Hash<32>` type carries it into the verifiers. No admin, no upgrade, the relayer list fixed at
//! construction (S16, C13). A part the chain cannot verify is stored only on a listed relayer's auth and marked with its
//! id (P11, U8S-D8): such an attestation is never a signature, so it never makes a key able to authorise.
#![no_std]
use scaas_ua_common::{
    attest_digest, h32, kem_pk, kem_pk_record_hash, kem_record_digest, kem_record_hash, membership_digest, portable_record_hash,
    pqz_key_hash, pqz_key_record_digest, registration_digest, Checked, FrostKey, KemKey, MemberSig, MsigStructure, MuSig2Key,
    Registration, UaAttrs, UaSig, WebAuthnKey, PURPOSE_KEM, PURPOSE_MEMBER, PURPOSE_MEMBERSHIP, PURPOSE_POP_V2, PURPOSE_PQZ_KEY,
};
use soroban_sdk::{
    contract, contracterror, contractevent, contractimpl, contracttype, crypto::Hash, panic_with_error, xdr::FromXdr,
    Address, Bytes, BytesN, Env, IntoVal, Map, String, TryFromVal, Val, Vec,
};

pub(crate) mod abi;
pub(crate) mod digest;
pub(crate) mod verify;
pub(crate) mod webauthn;

use digest::*;

/// SOR-D16, U8S-D5, TS-D5. A host crypto failure (ed25519 / P-256 / ML-DSA verify) is a host error, not `Pop` or
/// `Unauthorized` (plan finding F1). `Attrs` is unused since UA-8 attributes register; it keeps its code point.
/// `KemKeyHash`: EVM `UAKemKeyHash`, `set_kem_key(ua, 0, …)` with a key that is not the `register` commit.
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
    KemKeyHash = 21,
}

const DAY: u32 = 17_280;
const TTL_MIN: u32 = 30 * DAY;
const TTL_BUMP: u32 = 60 * DAY;

/// Persistent, one entry per key (S11); `Relayers` is the only instance entry. `Key(kh)` is the key of a `Chain` kind's
/// record, `KeyR(kh)` of a relayer-checked one: the chain proved nothing of a marked record, so it never blocks a `Chain`
/// kind (a relayer kind checks both, a `Chain` kind only `Key`). `Signer(ua)` holds the kind and key
/// data of a `signable` record, read alone by `require_authorized` and by `msig` member checks, so a check never loads
/// a record's `pop` (msig-pophash I1: a member with a large `pop` costs what any other member costs). `PqzK(ua)` =
/// `(key, sig, Checked, pqz_pop_hash)`, `PqzP(ua)` = the proof bytes, `Kem(ua, version)` = `(pk, sig, Checked)`,
/// `KemMax(ua)` = the highest `set_kem_key` version: the bytes stay in state, `Ua(ua)` holds neither key (U8S-D3). A
/// `set_pqz_key` key's hash is only in `PqzK`: `Ua(ua).attrs` keeps the `register` arguments, and is not rewritten.
/// `Accepted(ua)` = an `msig`'s one `AcceptedEntry`, written at registration: read once by a verify, never parsing `pop`.
/// `AcceptSig(ua, index)` = the signature of a slot accepted on a relayer's word, stored for a client's re-check (CTR-UA-34 rule 4), never
/// read by a verify.
#[contracttype]
#[derive(Clone)]
pub(crate) enum Key {
    Relayers,
    Ua(BytesN<32>),
    Key(BytesN<32>),
    KeyR(BytesN<32>),
    List(u32, u32),
    Count(u32),
    Signer(BytesN<32>),
    PqzK(BytesN<32>),
    PqzP(BytesN<32>),
    Kem(BytesN<32>, u64),
    KemMax(BytesN<32>),
    Accepted(BytesN<32>),
    AcceptSig(BytesN<32>, u32),
}

/// `Registration` with `pop` replaced by `pop_hash = keccak256(pop)` (owner ruling 2026-10-30 after T0: the full record
/// overran the 16 384 B contract-events limit); `pop` stays in `Ua(ua)`. `key_data` is EVM's, empty only when too large
/// (`event_key_data`).
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

/// CTR-UA-37: slot `index` of the `msig` `ua`, member `member`, accepted by `accept_membership`; `checked` says whose word it is,
/// `sig_hash` = `keccak256` of the slot's `sig` (U8S-D4; empty for a `G…` member; the bytes of an attested slot: `membership_sig_of`).
/// Slots that signed the `pop` are accepted at registration, without this event: `UaRegistered` and `pop_of` carry them.
#[contractevent(topics = ["UaMembershipAccepted"], data_format = "vec")]
pub struct UaMembershipAccepted {
    #[topic]
    pub ua: BytesN<32>,
    #[topic]
    pub member: BytesN<32>,
    pub index: u32,
    pub sig_hash: BytesN<32>,
    pub checked: Checked,
}

/// `keccak256("scaas.ua.group.<g>.v1")` (pinned by `kinds.json` `groups`).
const GROUP_P256: [u8; 32] = h32("42536053999ec2faea9af0b9b0ddeca9a126a2f05231603786f112854f12c1df");
const GROUP_ED25519: [u8; 32] = h32("68b4870b8635a91eb90f5a22ac6c350df50d0ca1f9ba92db6b38b0718ea5b25c");
const GROUP_SECP256K1: [u8; 32] = h32("c9cbec9e3b9b4bf3014d4b68eb88e8d49c151a734c4c73503f7cadf2c8ff2b6e");
const GROUP_MLDSA44: [u8; 32] = h32("97a431380a20af85ba723ef86a2744e0b7f438ae5ef677d03c595ab697478065");
const GROUP_MLDSA65: [u8; 32] = h32("ce664790de9584777bd32d6bbce84b26b1a479d86be05f03ba5120eae90d40b2");
const GROUP_BN254_G1: [u8; 32] = h32("8cf87f06e45b58fb9da912f12ece897bac88c2018da2c7b86056b954f5a1727b");
const GROUP_BN254_G2: [u8; 32] = h32("68a782d8ba5132c00f8b1f53883b465e3b7b14fcca363ab84ff92754c752aa8d");
const GROUP_BLS12381_G1: [u8; 32] = h32("b99dd1845a1f879279bd9b2cc7716250b1d33bb76a8c4fc8d449681842ed3bf2");
const GROUP_BLS12381_G2: [u8; 32] = h32("3d6646a6b9ee5a5cd8d394330578fb341709fd60ed2650b50f03e40a49b4a46a");
const GROUP_FNDSA512: [u8; 32] = h32("98ab6b49ea930e51296f1a3c6c172339d24402fcdb5b58ff37ddc0e28f450f7a");
const GROUP_SLHDSA128S: [u8; 32] = h32("863cfc243666ba3fca5731a5e7092d62b8cc0f35807b62e9115a270d99fcb2de");
/// The field primes, big-endian: key coordinates must be canonical (`< p`).
const P256_P: [u8; 32] = h32("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff");
const SECP256K1_P: [u8; 32] = h32("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f");
/// `keccak256("")`: refused as a `pqz_pop_hash`, the hash of no proof (EVM `EMPTY_PROOF_HASH`).
const EMPTY_HASH: [u8; 32] = h32("c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
/// CTR-UA-32: scheme 1 = ML-KEM-1024 + X25519, `scheme ‖ ek ‖ x25519` (2 is reserved).
const KEM_SCHEME: u32 = 1;
const KEM_PK_LENGTH: u32 = 1_601;

type PqzEntry = (Bytes, Bytes, Checked, BytesN<32>);
type KemEntry = (Bytes, Bytes, Checked);
/// `Accepted(ua)`: bit `i` = slot `i` accepted, and the relayer of each accepted slot the chain could not verify (P11 rule 3).
pub(crate) type AcceptedEntry = (u32, Map<u32, Address>);

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

/// The stored record; `NotRegistered` for an unregistered id (C17).
fn record(env: &Env, ua: &BytesN<32>) -> Registration {
    get(env, &Key::Ua(ua.clone())).unwrap_or_else(|| fail(env, Error::NotRegistered))
}

/// `msig` member `i` of validated key data (CTR-UA-09: `u16 threshold ‖ u16 count ‖ count × (u16 kind ‖ bytes32 id ‖
/// u16 weight)`).
fn member(d: &Bytes, i: u32) -> (u32, [u8; 32], u32) {
    let o = 4 + 36 * i;
    (u16_at(d, o), word(d, o + 2), u16_at(d, o + 34))
}

/// The member kinds the `msig` layout admits (EVM `UAKinds.isMember` without `hedera-native`, plus the Soroban natives):
/// any other kind is `KeyData`; `soroban-contract` is `MemberUnknown` (step 6; S10, owner ruling 2026-10-31: a `C…` member
/// would be authorised by Soroban invoker auth).
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

/// U8S-D8: the kinds registered through the relayer-checked mode, never signers (S3, P11.5).
fn relayer_checked(kind: u32) -> bool {
    matches!(kind, BIP340..=BLS_BN254_MINSIG | MUSIG2_SECP256K1..=FROST_BN254 | FNDSA512 | SLHDSA128S | ZETHER_BLS12381)
}

/// `aggKey ‖ u16 n ‖ n × key`, `n` in 2..=16 (EVM `_musig2`; its point checks and member order are the relayer's, U8S-D8).
fn musig2_layout_ok(d: &Bytes, size: u32) -> bool {
    if d.len() < size + 2 {
        return false;
    }
    let n = u16_at(d, size);
    (2..=16).contains(&n) && d.len() == size + 2 + n * size
}

/// `groupKey ‖ u16 t ‖ u16 n ‖ n × (t commitments ‖ r ‖ z)`, `2 <= t <= n <= 16` (EVM `_frost`, its layout only).
fn frost_layout_ok(d: &Bytes, size: u32) -> bool {
    if d.len() < size + 4 {
        return false;
    }
    let (t, n) = (u16_at(d, size), u16_at(d, size + 2));
    2 <= t && t <= n && n <= 16 && d.len() == size + 4 + n * ((t + 1) * size + 32)
}

/// Step 2: key data canonical (`KeyData`). P-256 / secp256k1 on-curve and the ed25519 "not a point" case are left to
/// the host's verify of the `pop` (a host error, plan finding F1). A relayer-checked kind: length and layout only, its
/// canonical form is the relayer's check (U8S-D8, `scaas_ua::keydata`).
fn check_key_data(env: &Env, kind: u32, d: &Bytes) {
    let coords = |p: &[u8; 32]| word(d, 0) < *p && word(d, 32) < *p;
    let ok = match kind {
        WEBAUTHN_P256 => d.len() == 96 && coords(&P256_P),
        P256 => d.len() == 64 && coords(&P256_P),
        SECP256K1 => d.len() == 64 && coords(&SECP256K1_P),
        ED25519 => d.len() == 32 && verify::ed25519_key_ok(&word(d, 0)),
        MLDSA44 => d.len() == 1312,
        MLDSA65 => d.len() == 1952,
        BIP340 | SLHDSA128S => d.len() == 32,
        SCHNORR_BN254 => d.len() == 64,
        SCHNORR_BLS12381 | BLS_BN254_MINSIG | ZETHER_BLS12381 => d.len() == 128,
        BLS12381_MINSIG => d.len() == 256,
        FNDSA512 => d.len() == 897,
        MUSIG2_SECP256K1 => musig2_layout_ok(d, 33),
        MUSIG2_BN254 => musig2_layout_ok(d, 64),
        FROST_SECP256K1 => frost_layout_ok(d, 33),
        FROST_BN254 => frost_layout_ok(d, 64),
        _ => msig_layout_ok(d),
    };
    if !ok {
        fail(env, Error::KeyData);
    }
}

/// CTR-UA-11: `keccak256(GROUP(g) ‖ canonical pubkey)` (x alone for the ECDSA kinds and a compressed secp256k1 group key,
/// the group key alone of a MuSig2 / FROST record), `None` for `msig`.
pub(crate) fn key_hash(env: &Env, kind: u32, d: &Bytes) -> Option<BytesN<32>> {
    let (group, key) = match kind {
        WEBAUTHN_P256 | P256 => (GROUP_P256, d.slice(0..32)),
        SECP256K1 => (GROUP_SECP256K1, d.slice(0..32)),
        BIP340 => (GROUP_SECP256K1, d.clone()),
        MUSIG2_SECP256K1 | FROST_SECP256K1 => (GROUP_SECP256K1, d.slice(1..33)),
        ED25519 => (GROUP_ED25519, d.clone()),
        SCHNORR_BN254 => (GROUP_BN254_G1, d.clone()),
        MUSIG2_BN254 | FROST_BN254 => (GROUP_BN254_G1, d.slice(0..64)),
        BLS_BN254_MINSIG => (GROUP_BN254_G2, d.clone()),
        SCHNORR_BLS12381 | ZETHER_BLS12381 => (GROUP_BLS12381_G1, d.clone()),
        BLS12381_MINSIG => (GROUP_BLS12381_G2, d.clone()),
        MLDSA44 => (GROUP_MLDSA44, d.clone()),
        MLDSA65 => (GROUP_MLDSA65, d.clone()),
        FNDSA512 => (GROUP_FNDSA512, d.clone()),
        SLHDSA128S => (GROUP_SLHDSA128S, d.clone()),
        _ => return None,
    };
    let mut b = Bytes::from_array(env, &group);
    b.append(&key);
    Some(env.crypto().keccak256(&b).into())
}

/// Step 6 (S10): each member is native (`evm-eoa`, `evm-contract`, `G…`) or a registered single-key UA of its stated
/// kind, else `MemberUnknown`. A `soroban-contract` (`C…`) member is `MemberUnknown` (owner ruling 2026-10-31, final
/// review: a contract that calls the registry, such as the token, would meet its own slot by invoker auth). Returns
/// `signable`: the weight Soroban can verify for signing (`Signer` members and `G…`; the EVM natives and relayer-checked
/// members weigh 0, U8S-D8) reaches the threshold.
fn check_members(env: &Env, d: &Bytes) -> bool {
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    let mut weight = 0;
    for i in 0..count {
        let (kind, id, w) = member(d, i);
        match kind {
            EVM_EOA | EVM_CONTRACT => {}
            STELLAR_ACCOUNT => weight += w,
            SOROBAN_CONTRACT => fail(env, Error::MemberUnknown),
            k if relayer_checked(k) => {
                if !get::<Registration>(env, &Key::Ua(BytesN::from_array(env, &id))).is_some_and(|r| r.kind == k) {
                    fail(env, Error::MemberUnknown);
                }
            }
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

/// The relayer a write names and `attest_digest` of the write's arguments, `relayer` among them: hashed only when one is named.
type By = Option<(Address, BytesN<32>)>;

fn by(env: &Env, function: &str, relayer: &Option<Address>, args: impl FnOnce() -> Vec<Val>) -> By {
    relayer.as_ref().map(|r| (r.clone(), attest_digest(env, &env.current_contract_address(), function, args())))
}

/// P11 rules 2, 3 (U8S-D8): a part the chain cannot verify, on the authority of `relayer`: `NotVerifiable` without one,
/// `RelayerNotListed` outside the constructor's list, its auth over this very call, and the mark stored with the part. The auth
/// covers one word, the digest of every argument (owner 2026-11-01), so an entry does not carry them all a second time. A part
/// the chain verifies never comes here: it stays open to anyone, and `relayer` is not asked.
fn attest(env: &Env, by: &By) -> Checked {
    let Some((r, digest)) = by else { fail(env, Error::NotVerifiable) };
    let list: Vec<Address> = env.storage().instance().get(&Key::Relayers).unwrap();
    if !list.contains(r) {
        fail(env, Error::RelayerNotListed);
    }
    r.require_auth_for_args((digest.clone(),).into_val(env));
    Checked::Relayer(r.clone())
}

/// `Accepted(ua)`; no bits for an id that holds none (any id but an `msig`).
fn accepted(env: &Env, ua: &BytesN<32>) -> AcceptedEntry {
    get(env, &Key::Accepted(ua.clone())).unwrap_or_else(|| (0, Map::new(env)))
}

/// An `msig` member kind whose signature no Soroban host can read: `attest`ed, never checked here.
fn attested_slot(kind: u32) -> bool {
    kind == EVM_CONTRACT || relayer_checked(kind)
}

/// The signature `s` of the member `(kind, id)` of the `msig` `ua` over `(purpose, digest)`, `md` its member digest. A registered
/// member's slot carries an empty `keyData` (its key read from `Signer(id)` alone; non-empty ⇒ `short`); a `G…` member's slot is empty
/// and checked by the host over `(ua, purpose, digest)`; an `evm-eoa` member signs the record's typed digest `portable` itself (ECDSA,
/// a portable record only; typed-signing TS-D4, `eth_signTypedData_v4`, no `personal_sign`); an `evm-eoa` slot outside `portable` is
/// `NotVerifiable` (SOR-D6). In `portable` an `evm-contract` slot or a relayer-checked member's slot is a part the chain cannot verify
/// (U8S-D8): `attest` once per signature, `checked` keeps the mark. Outside `portable` nothing attests: an `evm-contract` slot is
/// `NotVerifiable`, a relayer-checked member has no `Signer`, so `short`. A refused slot signature is `short`.
#[allow(clippy::too_many_arguments)]
fn check_slot(env: &Env, ua: &BytesN<32>, s: &MemberSig, kind: u32, id: &[u8; 32], purpose: &BytesN<32>, digest: &BytesN<32>, md: &BytesN<32>, portable: Option<&Hash<32>>, relayer: &By, checked: &mut Checked, short: Error) {
    if !s.key_data.is_empty() {
        fail(env, short);
    }
    match kind {
        k if portable.is_some() && attested_slot(k) => {
            if *checked == Checked::Chain {
                *checked = attest(env, relayer);
            }
        }
        EVM_CONTRACT => fail(env, Error::NotVerifiable),
        EVM_EOA => {
            let typed = portable.unwrap_or_else(|| fail(env, Error::NotVerifiable));
            let id20: BytesN<20> = Bytes::from_array(env, id).slice(12..32).try_into().unwrap();
            verify::check_evm_eoa(env, &id20, typed, &s.sig, short);
        }
        STELLAR_ACCOUNT => {
            if !s.sig.is_empty() {
                fail(env, short);
            }
            let args = (ua.clone(), purpose.clone(), digest.clone()).into_val(env);
            stellar_account(env, id).require_auth_for_args(args);
        }
        _ => {
            let (_, key) = get::<(u32, Bytes)>(env, &Key::Signer(BytesN::from_array(env, id)))
                .unwrap_or_else(|| fail(env, short));
            let pm = BytesN::from_array(env, &PURPOSE_MEMBER);
            verify::check(env, kind, &key, &ua_message(env, kind, &pm, md), &s.sig, short);
        }
    }
}

/// An `msig` signature over `(ua, purpose, digest)`: `sigs` with strictly increasing indexes below `count`, each an accepted slot
/// (CTR-UA-37: one read of `Accepted(ua)`, the `pop` exempt, being what accepts its signers), members by `check_slot` under purpose
/// `member` over `member_digest(ua, ua_message(MSIG, purpose, digest))` until the threshold (a slot after it fails). A slot past the
/// threshold, an unaccepted slot or an unmet threshold is `short`. `portable` is a stored signature, so it is minimal too (owner
/// 2026-10-31, U8S-D1, every slot's weight counts, native ones included): with T the slots' total weight and N the threshold,
/// T - min(weight) < N, else `short`. Returns who checked the signature.
#[allow(clippy::too_many_arguments)]
fn check_msig(env: &Env, ua: &BytesN<32>, d: &Bytes, purpose: &BytesN<32>, digest: &BytesN<32>, sigs: &Vec<MemberSig>, portable: Option<&Hash<32>>, relayer: &By, short: Error) -> Checked {
    let md = member_digest(env, ua, &ua_message(env, MSIG, purpose, digest));
    let yes = if purpose.to_array() == PURPOSE_POP_V2 { u32::MAX } else { accepted(env, ua).0 };
    let (threshold, count) = (u16_at(d, 0), u16_at(d, 2));
    let (mut acc, mut w_min, mut next, mut checked) = (0, u32::MAX, 0, Checked::Chain);
    for s in sigs.iter() {
        if acc >= threshold || s.index < next || s.index >= count || yes >> s.index & 1 == 0 {
            fail(env, short);
        }
        next = s.index + 1;
        let (kind, id, w) = member(d, s.index);
        check_slot(env, ua, &s, kind, &id, purpose, digest, &md, portable, relayer, &mut checked, short);
        acc += w;
        w_min = w_min.min(w);
    }
    if acc < threshold || (portable.is_some() && acc - w_min >= threshold) {
        fail(env, short);
    }
    checked
}

/// CTR-UA-33.A on Soroban (owner 2026-11-01): the largest `key_data` `UaRegistered` carries. `register_frost`, the only entry that
/// comes near, emits that one event, 892 B around `key_data`, return value included: 16,252 B of the 16,384 B events limit here.
pub(crate) const EVENT_KEY_DATA_MAX: u32 = 15_360;

/// `key_data` as `UaRegistered` carries it: whole, or empty when it is over `EVENT_KEY_DATA_MAX`, by its length alone. Empty says
/// nothing about the key: `ua` is the topic, and `record_of` / `registration_of` return the bytes.
pub(crate) fn event_key_data(env: &Env, d: &Bytes) -> Bytes {
    if d.len() <= EVENT_KEY_DATA_MAX {
        d.clone()
    } else {
        Bytes::new(env)
    }
}

fn zero(env: &Env) -> BytesN<32> {
    BytesN::from_array(env, &[0; 32])
}

/// A PQZ / KEM holder (EVM `_holder`, U8S-D6): `mldsa44`, `mldsa65`, `fndsa512`, a PQ-eligible `msig`.
fn holder(kind: u32, d: &Bytes) -> bool {
    matches!(kind, MLDSA44 | MLDSA65 | FNDSA512) || (kind == MSIG && pq_eligible(d))
}

/// TS-D12: a single key only `signature`, an `msig` only `members`, `key_data` never.
fn sig_fields_ok(kind: u32, s: &UaSig) -> bool {
    s.key_data.is_empty() && if kind == MSIG { s.signature.is_empty() } else { s.members.is_empty() }
}

/// EVM `_portableOk` + `_portableBytes` for a later portable record (`set_kem_key` ≥ 1, `set_pqz_key`): its signature over
/// `(ua, purpose, rd)`, `Unauthorized`, an `msig` under `check_msig`'s portable rule (U8S-D1), a relayer-checked kind on
/// `attest`; returns the bytes stored for it, the `signature` or EVM's `abi.encode(MemberSig[])`, and who checked them.
#[allow(clippy::too_many_arguments)]
fn check_portable(env: &Env, kind: u32, d: &Bytes, ua: &BytesN<32>, purpose: [u8; 32], rd: &Hash<32>, sig: &UaSig, relayer: &By) -> (Bytes, Checked) {
    if !sig_fields_ok(kind, sig) {
        fail(env, Error::Unauthorized);
    }
    let (p, digest) = (BytesN::from_array(env, &purpose), rd.to_bytes());
    if kind == MSIG {
        let checked = check_msig(env, ua, d, &p, &digest, &sig.members, Some(rd), relayer, Error::Unauthorized);
        return (abi::encode_member_sigs(env, &sig.members), checked);
    }
    if relayer_checked(kind) {
        return (sig.signature.clone(), attest(env, relayer));
    }
    verify::check(env, kind, d, &ua_message(env, kind, &p, &digest), &sig.signature, Error::Unauthorized);
    (sig.signature.clone(), Checked::Chain)
}

/// A PQZ key is of one of the four set lengths (`KeyData`, U8S-D6: Soroban has no set of its own).
fn check_pqz_key(env: &Env, key: &Bytes) {
    let n = key.len();
    if !(16_384..=22_528).contains(&n) || n % 2_048 != 0 {
        fail(env, Error::KeyData);
    }
}

/// EVM `_checkKemPk` on a key that is not empty: scheme 1 (`scheme` is a `u32` here, so the field and not `pk`'s first
/// byte), 1,601 B.
fn check_kem_pk(env: &Env, scheme: u32, pk: &Bytes) {
    if scheme != KEM_SCHEME {
        fail(env, Error::KemScheme);
    }
    if pk.len() != KEM_PK_LENGTH {
        fail(env, Error::KemKeyLength);
    }
}

/// A stored `kem_pk` as its fields (EVM `_kemAt`; scheme 1 is the only stored form).
fn kem_of(pk: &Bytes) -> KemKey {
    let (ek, x) = (pk.slice(1..KEM_PK_LENGTH - 32), pk.slice(KEM_PK_LENGTH - 32..KEM_PK_LENGTH));
    KemKey { scheme: KEM_SCHEME, mlkem_ek: ek, x25519: x.try_into().unwrap() }
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
    if pqz {
        check_pqz_key(env, &attrs.pqz_key);
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
        if !pk.is_empty() {
            check_kem_pk(env, attrs.kem.scheme, &pk);
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

/// `p`, exactly one point of `size` bytes, appended (EVM `_point`: its validity is not checked here).
fn push_point(env: &Env, d: &mut Bytes, p: &Bytes, size: u32) {
    if p.len() != size {
        fail(env, Error::KeyData);
    }
    d.append(p);
}

/// `aggKey ‖ u16 n ‖ n × key` of a typed key (EVM `registerMuSig2`): `KeyData` for another kind, a point of the wrong length
/// or a count its `u16` cannot hold; the layout itself is `check_key_data`'s.
fn musig2_key_data(env: &Env, kind: u32, key: &MuSig2Key) -> Bytes {
    let size = match kind {
        MUSIG2_SECP256K1 => 33,
        MUSIG2_BN254 => 64,
        _ => fail(env, Error::KeyData),
    };
    if key.member_keys.len() > 16 {
        fail(env, Error::KeyData);
    }
    let mut d = Bytes::new(env);
    push_point(env, &mut d, &key.agg_key, size);
    d.extend_from_slice(&(key.member_keys.len() as u16).to_be_bytes());
    for p in key.member_keys.iter() {
        push_point(env, &mut d, &p, size);
    }
    d
}

/// `groupKey ‖ u16 t ‖ u16 n ‖ n × (t commitments ‖ r ‖ z)` of a typed key (EVM `registerFrost`): as `musig2_key_data`, and
/// every member has exactly `threshold` commitments.
fn frost_key_data(env: &Env, kind: u32, key: &FrostKey) -> Bytes {
    let size = match kind {
        FROST_SECP256K1 => 33,
        FROST_BN254 => 64,
        _ => fail(env, Error::KeyData),
    };
    if key.threshold > 0xFFFF || key.members.len() > 16 {
        fail(env, Error::KeyData);
    }
    let mut d = Bytes::new(env);
    push_point(env, &mut d, &key.group_key, size);
    d.extend_from_slice(&(key.threshold as u16).to_be_bytes());
    d.extend_from_slice(&(key.members.len() as u16).to_be_bytes());
    for m in key.members.iter() {
        if m.commitments.len() != key.threshold {
            fail(env, Error::KeyData);
        }
        for c in m.commitments.iter() {
            push_point(env, &mut d, &c, size);
        }
        push_point(env, &mut d, &m.r, size);
        d.extend_from_array(&m.z.to_array());
    }
    d
}

/// `x ‖ y ‖ rp_id_hash` of a typed key (EVM `registerWebAuthn`).
fn webauthn_key_data(env: &Env, key: &WebAuthnKey) -> Bytes {
    let mut d = Bytes::from_array(env, &key.x.to_array());
    d.extend_from_array(&key.y.to_array());
    d.extend_from_array(&key.rp_id_hash.to_array());
    d
}

/// The portable form (UA-8 P1; spec §3 order, EVM `_register`): kind enabled → key data → id → not registered → keyHash
/// free → `msig` members → attributes → `pop` (`sig`, or an `msig`'s `members`) → store, list, events. Nothing is read
/// from the submitter (CTR-UA-07). The PQZ key and proof and the KEM key stay in state (`PqzK`, `PqzP`, `Kem(ua, 0)`),
/// unproven (U8S-D3, U8S-D6: no verifier, no `Key` entry); the events carry hashes (U8S-D4). The `pop` of a relayer-checked
/// kind, and an `msig` slot the chain cannot verify, is `attest`ed instead; the `pop`'s `Checked` marks the attributes it
/// signed too; such a kind is never `signable` and keeps its key in `KeyR` (U8S-D8, P11.5).
#[allow(clippy::too_many_arguments)]
fn register_record(env: &Env, kind: u32, key_data: Bytes, attrs: UaAttrs, sig: Bytes, members: Vec<MemberSig>, pqz_pop: Bytes, relayer: &By) -> BytesN<32> {
    if ![WEBAUTHN_P256, P256, ED25519, SECP256K1, MSIG, MLDSA44, MLDSA65].contains(&kind) && !relayer_checked(kind) {
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
        if has(env, &Key::Key(kh.clone())) || (relayer_checked(kind) && has(env, &Key::KeyR(kh.clone()))) {
            fail(env, Error::KeyInUse);
        }
    }
    let signable = !relayer_checked(kind) && (kind != MSIG || check_members(env, &key_data));
    let (pk, pqz_hash, rec) = check_attrs(env, kind, &key_data, &ua, &attrs, &pqz_pop);
    let typed = registration_digest(env, &rec, &attrs.pqz_pop_hash);
    let reg = typed.to_bytes();
    let pv2 = BytesN::from_array(env, &PURPOSE_POP_V2);
    let checked = if relayer_checked(kind) {
        attest(env, relayer)
    } else if kind != MSIG {
        verify::check(env, kind, &key_data, &ua_message(env, kind, &pv2, &reg), &sig, Error::Pop);
        Checked::Chain
    } else if pq_eligible(&key_data) {
        check_msig(env, &ua, &key_data, &pv2, &reg, &members, Some(&typed), relayer, Error::Pop)
    } else if members.is_empty() {
        Checked::Chain
    } else {
        fail(env, Error::Pop) // classical-dominant: its members proved theirs, as EVM (U8S-D2)
    };
    let pop = if kind == MSIG { abi::encode_member_sigs(env, &members) } else { sig };

    let index = get::<u32>(env, &Key::Count(kind)).unwrap_or(0);
    put(env, &Key::List(kind, index), &ua);
    put(env, &Key::Count(kind), &(index + 1));
    if let Some(kh) = kh {
        put(env, &if relayer_checked(kind) { Key::KeyR(kh) } else { Key::Key(kh) }, &ua);
    }
    if signable {
        put(env, &Key::Signer(ua.clone()), &(kind, key_data.clone()));
    }
    if kind == MSIG {
        let (mut bits, mut marks) = (0u32, Map::new(env));
        for s in members.iter() {
            bits |= 1 << s.index;
            if let (Checked::Relayer(r), true) = (&checked, attested_slot(member(&key_data, s.index).0)) {
                marks.set(s.index, r.clone());
            }
        }
        put(env, &Key::Accepted(ua.clone()), &(bits, marks));
    }
    let no_sig = Bytes::new(env);
    let sig_hash = BytesN::from_array(env, &EMPTY_HASH);
    if !attrs.pqz_key.is_empty() {
        let pqz_pop_hash = attrs.pqz_pop_hash.clone();
        put(env, &Key::PqzK(ua.clone()), &(attrs.pqz_key.clone(), no_sig.clone(), checked.clone(), pqz_pop_hash.clone()));
        UaPqzKeySet { ua: ua.clone(), pqz_key_hash: pqz_hash, pqz_pop_hash, sig_hash: sig_hash.clone(), checked: checked.clone() }.publish(env);
    }
    if !pqz_pop.is_empty() {
        put(env, &Key::PqzP(ua.clone()), &pqz_pop);
        UaPqzPopStored { ua: ua.clone(), pqz_pop_hash: attrs.pqz_pop_hash.clone() }.publish(env);
    }
    if !pk.is_empty() {
        put(env, &Key::Kem(ua.clone(), 0), &(pk.clone(), no_sig, checked.clone()));
        UaKemKeySet { ua: ua.clone(), version: 0, kem_pk_hash: env.crypto().keccak256(&pk).into(), sig_hash, checked: checked.clone() }.publish(env);
    }
    let kem = KemKey { scheme: if attrs.kem_pk_hash != zero(env) { attrs.kem.scheme } else { 0 }, ..KemKey::none(env) };
    let attrs = UaAttrs { pqz_key: Bytes::new(env), kem, ..attrs };
    let ledger = env.ledger().sequence();
    let record = RegisteredRecord {
        kind,
        key_data: event_key_data(env, &key_data),
        attrs: attrs.clone(),
        pop_hash: env.crypto().keccak256(&pop).into(),
        pop_checked: checked.clone(),
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
        pop_checked: checked.clone(),
        pqz_pop_checked: Checked::None,
        proven: false,
        signable,
        index,
        ledger,
    };
    put(env, &Key::Ua(ua.clone()), &r);
    bump_instance(env);
    UaRegistered { ua: ua.clone(), kind, record, checked }.publish(env);
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
    /// accepted and ignored for chain-verified parts (SOR-D6), and the authority for a relayer-checked kind's `pop`
    /// (U8S-D8, `attest`).
    pub fn register(
        env: Env,
        kind: u32,
        key_data: Bytes,
        attrs: UaAttrs,
        pop: Bytes,
        pqz_pop: Bytes,
        relayer: Option<Address>,
    ) -> BytesN<32> {
        if kind == MSIG {
            fail(&env, Error::KeyData);
        }
        let by = by(&env, "register", &relayer, || (kind, key_data.clone(), attrs.clone(), pop.clone(), pqz_pop.clone(), relayer.clone()).into_val(&env));
        let members = Vec::new(&env);
        register_record(&env, kind, key_data, attrs, pop, members, pqz_pop, &by)
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
        let by = by(&env, "register_webauthn", &relayer, || (key.clone(), attrs.clone(), pop.clone(), pqz_pop.clone(), relayer.clone()).into_val(&env));
        let d = webauthn_key_data(&env, &key);
        let members = Vec::new(&env);
        register_record(&env, WEBAUTHN_P256, d, attrs, pop, members, pqz_pop, &by)
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
        let by = by(&env, "register_msig", &relayer, || (structure.clone(), attrs.clone(), pop.clone(), pqz_pop.clone(), relayer.clone()).into_val(&env));
        let d = msig_key_data(&env, &structure);
        register_record(&env, MSIG, d, attrs, Bytes::new(&env), pop, pqz_pop, &by)
    }

    /// `register` of `musig2-secp256k1` / `musig2-bn254` from its typed key (EVM `registerMuSig2`, TS-D13; U8S-D8): `aggKey ‖
    /// u16 n ‖ n × key` is assembled here, the same id and record as the packed `register`, which stays, as EVM.
    pub fn register_musig2(env: Env, kind: u32, key: MuSig2Key, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, relayer: Option<Address>) -> BytesN<32> {
        let by = by(&env, "register_musig2", &relayer, || (kind, key.clone(), attrs.clone(), pop.clone(), pqz_pop.clone(), relayer.clone()).into_val(&env));
        let d = musig2_key_data(&env, kind, &key);
        let members = Vec::new(&env);
        register_record(&env, kind, d, attrs, pop, members, pqz_pop, &by)
    }

    /// `register` of `frost-secp256k1` / `frost-bn254` from its typed key (EVM `registerFrost`, TS-D13; U8S-D8), likewise.
    pub fn register_frost(env: Env, kind: u32, key: FrostKey, attrs: UaAttrs, pop: Bytes, pqz_pop: Bytes, relayer: Option<Address>) -> BytesN<32> {
        let by = by(&env, "register_frost", &relayer, || (kind, key.clone(), attrs.clone(), pop.clone(), pqz_pop.clone(), relayer.clone()).into_val(&env));
        let d = frost_key_data(&env, kind, &key);
        let members = Vec::new(&env);
        register_record(&env, kind, d, attrs, pop, members, pqz_pop, &by)
    }

    /// CTR-UA-17's Soroban form: `NotRegistered`, then `Unauthorized` unless `signable` and `purpose` is not a portable
    /// one (`pop` v2, `kem`, `pqz-key`, `membership`), then the kind's check over `ua_message(kind, purpose, digest)`; `msig` members
    /// under purpose `member` until the threshold, accepted slots only (CTR-UA-37). `auth` (TS-D12): a single key only `signature`, an `msig` only
    /// `members`, any other field set is `Unauthorized`. Extends `Ua(ua)`.
    pub fn require_authorized(env: Env, ua: BytesN<32>, purpose: BytesN<32>, digest: BytesN<32>, auth: UaSig) {
        let Some((kind, key)) = get::<(u32, Bytes)>(&env, &Key::Signer(ua.clone())) else {
            let e = if has(&env, &Key::Ua(ua.clone())) { Error::Unauthorized } else { Error::NotRegistered };
            fail(&env, e)
        };
        let p = purpose.to_array();
        if p == PURPOSE_POP_V2 || p == PURPOSE_KEM || p == PURPOSE_PQZ_KEY || p == PURPOSE_MEMBERSHIP {
            fail(&env, Error::Unauthorized);
        }
        if !sig_fields_ok(kind, &auth) {
            fail(&env, Error::Unauthorized);
        }
        env.storage().persistent().extend_ttl(&Key::Ua(ua.clone()), TTL_MIN, TTL_BUMP);
        bump_instance(&env);
        if kind == MSIG {
            check_msig(&env, &ua, &key, &purpose, &digest, &auth.members, None, &None, Error::Unauthorized);
        } else {
            verify::check(&env, kind, &key, &ua_message(&env, kind, &purpose, &digest), &auth.signature, Error::Unauthorized);
        }
    }

    /// Exactly the `register` arguments `(kind, key_data, attrs, pop, pqz_pop)`, EVM `registrationOf` line by line
    /// (U8S-D3): the PQZ key and proof iff `register` carried them, the KEM key at version 0 or its hash commit.
    pub fn registration_of(env: Env, ua: BytesN<32>) -> Option<(u32, Bytes, UaAttrs, Bytes, Bytes)> {
        let r = get::<Registration>(&env, &Key::Ua(ua.clone()))?;
        let mut a = r.attrs;
        let mut pqz_pop = Bytes::new(&env);
        if a.pqz_pop_hash != zero(&env) {
            a.pqz_key = get::<PqzEntry>(&env, &Key::PqzK(ua.clone())).unwrap().0;
            pqz_pop = get(&env, &Key::PqzP(ua.clone())).unwrap_or(pqz_pop);
        }
        if a.kem_pk_hash == zero(&env) {
            if let Some((pk, _, _)) = get::<KemEntry>(&env, &Key::Kem(ua, 0)) {
                a.kem = kem_of(&pk);
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
        let kem = get::<KemEntry>(&env, &Key::Kem(ua, v)).map_or(Checked::None, |e| e.2);
        (r.pop_checked, r.pqz_pop_checked, kem)
    }

    /// EVM `setKemKey`, anyone (P4, CTR-UA-32), every version write-once in any order, no owner check. Version ≥ 1: `sig`
    /// over `ua_message(kind, PURPOSE_KEM, kem_record_digest(ua, version, pk))`. Version 0 only fills the key `register`
    /// committed by hash, with no `sig` (the `pop` signed it): a key given in whole is not refillable (TS-D9). Check order:
    /// `NotRegistered` → `KemHolder` → `KemVersion` → the key (`KemScheme`, `KemKeyLength`) → signature (`Unauthorized`) /
    /// the commit (`KemKeyHash`). `relayer` as in `register`; a filled commit keeps `pop_checked`: the chain compares the
    /// hash, the `pop` signed it.
    pub fn set_kem_key(env: Env, ua: BytesN<32>, version: u64, kem: KemKey, sig: UaSig, relayer: Option<Address>) {
        let r = record(&env, &ua);
        if !holder(r.kind, &r.key_data) {
            fail(&env, Error::KemHolder);
        }
        let k = Key::Kem(ua.clone(), version);
        let committed = r.attrs.kem_pk_hash;
        if has(&env, &k) || (version == 0 && committed == zero(&env)) {
            fail(&env, Error::KemVersion);
        }
        let pk = kem_pk(&env, &kem);
        if pk.is_empty() {
            fail(&env, Error::KemKeyLength);
        }
        check_kem_pk(&env, kem.scheme, &pk);
        let kem_pk_hash = BytesN::from(env.crypto().keccak256(&pk));
        let (stored, checked) = if version == 0 {
            if !sig.is_empty() {
                fail(&env, Error::Unauthorized);
            }
            if kem_pk_hash != committed {
                fail(&env, Error::KemKeyHash);
            }
            (Bytes::new(&env), r.pop_checked)
        } else {
            let rd = kem_record_digest(&env, &ua, version, &pk);
            let by = by(&env, "set_kem_key", &relayer, || (ua.clone(), version, kem.clone(), sig.clone(), relayer.clone()).into_val(&env));
            let part = check_portable(&env, r.kind, &r.key_data, &ua, PURPOSE_KEM, &rd, &sig, &by);
            if version > get::<u64>(&env, &Key::KemMax(ua.clone())).unwrap_or(0) {
                put(&env, &Key::KemMax(ua.clone()), &version);
            }
            part
        };
        let sig_hash = env.crypto().keccak256(&stored).into();
        put(&env, &k, &(pk, stored, checked.clone()));
        bump_instance(&env);
        UaKemKeySet { ua, version, kem_pk_hash, sig_hash, checked }.publish(&env);
    }

    /// EVM `setPqzKey` without a verifier (U8S-D6): anyone, a holder without a key gets one, unproven, write-once, no `Key`
    /// entry; `sig` over `ua_message(kind, PURPOSE_PQZ_KEY, pqz_key_record_digest(ua, pqzKeyHash, pqz_pop_hash))`. Check
    /// order: `NotRegistered` → `PqzHolder` → `PqzKeySet` → the key's length (`KeyData`) → a zero or `keccak256("")` proof
    /// hash (`PqzPopHash`) → signature (`Unauthorized`). `relayer` as in `register`. `PqzK` holds key and signature in one
    /// entry of 65,536 B (B0), so an `msig`'s signing slots are bounded in bytes, `key + 64 + Σ (192 + sig padded to 32)`: 13 /
    /// 12 ML-DSA-65 slots, 6 / 5 relayer-checked `slhdsa128s` slots.
    pub fn set_pqz_key(env: Env, ua: BytesN<32>, pqz_key: Bytes, pqz_pop_hash: BytesN<32>, sig: UaSig, relayer: Option<Address>) {
        let r = record(&env, &ua);
        if !holder(r.kind, &r.key_data) {
            fail(&env, Error::PqzHolder);
        }
        let k = Key::PqzK(ua.clone());
        if has(&env, &k) {
            fail(&env, Error::PqzKeySet);
        }
        check_pqz_key(&env, &pqz_key);
        if pqz_pop_hash == zero(&env) || pqz_pop_hash.to_array() == EMPTY_HASH {
            fail(&env, Error::PqzPopHash);
        }
        let pqz_key_hash = pqz_key_hash(&env, &pqz_key);
        let rd = pqz_key_record_digest(&env, &ua, &pqz_key_hash, &pqz_pop_hash);
        let by = by(&env, "set_pqz_key", &relayer, || (ua.clone(), pqz_key.clone(), pqz_pop_hash.clone(), sig.clone(), relayer.clone()).into_val(&env));
        let (stored, checked) = check_portable(&env, r.kind, &r.key_data, &ua, PURPOSE_PQZ_KEY, &rd, &sig, &by);
        let sig_hash = env.crypto().keccak256(&stored).into();
        put(&env, &k, &(pqz_key, stored, checked.clone(), pqz_pop_hash.clone()));
        bump_instance(&env);
        UaPqzKeySet { ua, pqz_key_hash, pqz_pop_hash, sig_hash, checked }.publish(&env);
    }

    /// EVM `storePqzPop` without a verifier (U8S-D6): anyone, `NotRegistered`, then `PqzPopHash` for an empty proof or one
    /// that does not hash to the key's `pqz_pop_hash` (also for a UA without a key); stored bytes make it a no-op, no event.
    pub fn store_pqz_pop(env: Env, ua: BytesN<32>, pqz_pop: Bytes) {
        record(&env, &ua);
        if pqz_pop.is_empty() {
            fail(&env, Error::PqzPopHash);
        }
        let Some((_, _, _, pqz_pop_hash)) = get::<PqzEntry>(&env, &Key::PqzK(ua.clone())) else {
            fail(&env, Error::PqzPopHash)
        };
        if BytesN::from(env.crypto().keccak256(&pqz_pop)) != pqz_pop_hash {
            fail(&env, Error::PqzPopHash);
        }
        let k = Key::PqzP(ua.clone());
        if has(&env, &k) {
            return;
        }
        put(&env, &k, &pqz_pop);
        bump_instance(&env);
        UaPqzPopStored { ua, pqz_pop_hash }.publish(&env);
    }

    /// `(version, kem, sig, checked)` of the highest stored version, `None` without one (also a hash commit not filled);
    /// the `register` key alone is version 0 with an empty `sig` (UA8-D4).
    pub fn kem_key_of(env: Env, ua: BytesN<32>) -> Option<(u64, KemKey, Bytes, Checked)> {
        let v = get::<u64>(&env, &Key::KemMax(ua.clone())).unwrap_or(0);
        Self::kem_key_at(env, ua, v).map(|(kem, sig, checked)| (v, kem, sig, checked))
    }

    /// `(kem, sig, checked)` of a stored version.
    pub fn kem_key_at(env: Env, ua: BytesN<32>, version: u64) -> Option<(KemKey, Bytes, Checked)> {
        get::<KemEntry>(&env, &Key::Kem(ua, version)).map(|(pk, sig, checked)| (kem_of(&pk), sig, checked))
    }

    /// `(key, pqz_pop_hash, proven, checked)`: `proven` is `false` on Soroban, nothing verifies `R_REG` (U8S-D6).
    pub fn pqz_key_of(env: Env, ua: BytesN<32>) -> Option<(Bytes, BytesN<32>, bool, Checked)> {
        get::<PqzEntry>(&env, &Key::PqzK(ua)).map(|(key, _, checked, hash)| (key, hash, false, checked))
    }

    /// `set_pqz_key`'s stored signature; empty when the key came with `register` (its consent is the `pop`) or there is none.
    pub fn pqz_key_sig_of(env: Env, ua: BytesN<32>) -> Bytes {
        get::<PqzEntry>(&env, &Key::PqzK(ua)).map_or(Bytes::new(&env), |e| e.1)
    }

    /// CTR-UA-37, EVM `acceptMembership`: slot `member_sig.index` of the `msig` `ua` accepts its place. Anyone submits; `key_data` empty.
    /// `Unauthorized` for an id that is no `msig` here, an index past the members or a bad signature (a host verify's failure is a host
    /// error, plan finding F1). A slot already accepted is a no-op, no second event, whatever the call carries. The member signs
    /// typed(`UAMembership{ua, member}`), so one signature serves every registry; `check_slot` by kind: an `evm-eoa` member that digest,
    /// a registered member `member_digest` under `member`, a `G…` member an auth entry over `(ua, PURPOSE_MEMBERSHIP, typed)`, `sig`
    /// empty. No threshold, no minimal form: one slot speaks for itself. A slot the chain cannot verify takes `relayer` (`attest`, the
    /// digest of these three arguments), keeps its mark in `Accepted(ua)` and its signature in `AcceptSig(ua, index)`, for a client to
    /// re-check (CTR-UA-34 rule 4). No revoke, no decline: the id derives from the structure.
    pub fn accept_membership(env: Env, ua: BytesN<32>, member_sig: MemberSig, relayer: Option<Address>) {
        let Some(r) = get::<Registration>(&env, &Key::Ua(ua.clone())).filter(|r| r.kind == MSIG) else { fail(&env, Error::Unauthorized) };
        let index = member_sig.index;
        if index >= u16_at(&r.key_data, 2) {
            fail(&env, Error::Unauthorized);
        }
        let (bits, mut marks) = accepted(&env, &ua);
        if bits >> index & 1 != 0 {
            return;
        }
        let (kind, id, _) = member(&r.key_data, index);
        let member_id = BytesN::from_array(&env, &id);
        let typed = membership_digest(&env, &ua, &member_id);
        let (p, digest) = (BytesN::from_array(&env, &PURPOSE_MEMBERSHIP), typed.to_bytes());
        let md = member_digest(&env, &ua, &ua_message(&env, MSIG, &p, &digest));
        let by = by(&env, "accept_membership", &relayer, || (ua.clone(), member_sig.clone(), relayer.clone()).into_val(&env));
        let mut checked = Checked::Chain;
        check_slot(&env, &ua, &member_sig, kind, &id, &p, &digest, &md, Some(&typed), &by, &mut checked, Error::Unauthorized);
        if let Checked::Relayer(r) = &checked {
            marks.set(index, r.clone());
            put(&env, &Key::AcceptSig(ua.clone(), index), &member_sig.sig);
        }
        put(&env, &Key::Accepted(ua.clone()), &(bits | 1 << index, marks));
        bump_instance(&env);
        let sig_hash = env.crypto().keccak256(&member_sig.sig).into();
        UaMembershipAccepted { ua, member: member_id, index, sig_hash, checked }.publish(&env);
    }

    /// Has slot `index` of `ua` agreed (CTR-UA-37: it signed the `pop` here, or `accept_membership`)? False for a slot that is only
    /// listed, past the members and for any other id. Only accepted slots count at verify.
    pub fn member_accepted(env: Env, ua: BytesN<32>, index: u32) -> bool {
        accepted(&env, &ua).0.checked_shr(index).is_some_and(|b| b & 1 != 0)
    }

    /// The bytes of a slot accepted on a relayer's word, for a client to re-check (`check_membership`); empty for a slot the chain
    /// checked or that signed the `pop` (`pop_of` holds those) and for a slot not accepted.
    pub fn membership_sig_of(env: Env, ua: BytesN<32>, index: u32) -> Bytes {
        get(&env, &Key::AcceptSig(ua, index)).unwrap_or(Bytes::new(&env))
    }

    /// Whose word the slot's acceptance is (P11): `Chain`, a listed `Relayer`, `None` for a slot not accepted.
    pub fn member_checked(env: Env, ua: BytesN<32>, index: u32) -> Checked {
        let (bits, marks) = accepted(&env, &ua);
        match marks.get(index) {
            Some(r) => Checked::Relayer(r),
            None if bits.checked_shr(index).is_some_and(|b| b & 1 != 0) => Checked::Chain,
            None => Checked::None,
        }
    }

    /// TS-D5: the name of a kind id of the table, enabled here or not; `KindUnknown` for any other id.
    pub fn kind_name(env: Env, kind: u32) -> String {
        digest::kind_name(&env, kind)
    }

    pub fn record_of(env: Env, ua: BytesN<32>) -> Option<Registration> {
        get(&env, &Key::Ua(ua))
    }

    /// The UA holding a key: a record of a `Chain` kind before a marked one (`KeyR`).
    pub fn key_owner(env: Env, key_hash: BytesN<32>) -> Option<BytesN<32>> {
        get(&env, &Key::Key(key_hash.clone())).or_else(|| get(&env, &Key::KeyR(key_hash)))
    }

    pub fn ua_of(env: Env, kind: u32, key_data: Bytes) -> BytesN<32> {
        digest::ua_of(&env, kind, &key_data)
    }

    /// `ua_of` of `register_msig`'s typed structure (packed-bytes inventory): `KeyData` for a value its `u16` cannot hold.
    pub fn ua_of_msig(env: Env, structure: MsigStructure) -> BytesN<32> {
        digest::ua_of(&env, MSIG, &msig_key_data(&env, &structure))
    }

    /// `ua_of` of `register_webauthn`'s typed key.
    pub fn ua_of_webauthn(env: Env, key: WebAuthnKey) -> BytesN<32> {
        digest::ua_of(&env, WEBAUTHN_P256, &webauthn_key_data(&env, &key))
    }

    /// `ua_of` of `register_musig2`'s typed key.
    pub fn ua_of_musig2(env: Env, kind: u32, key: MuSig2Key) -> BytesN<32> {
        digest::ua_of(&env, kind, &musig2_key_data(&env, kind, &key))
    }

    /// `ua_of` of `register_frost`'s typed key.
    pub fn ua_of_frost(env: Env, kind: u32, key: FrostKey) -> BytesN<32> {
        digest::ua_of(&env, kind, &frost_key_data(&env, kind, &key))
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
mod test_membership;
#[cfg(test)]
mod test_ua8;
#[cfg(test)]
mod test_verify;
