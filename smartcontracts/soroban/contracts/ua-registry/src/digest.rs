//! The UA words (CTR-UA-04, -12, -23; UA8-D1), byte-identical to EVM `UAKinds`, over the host's `keccak256`.
use scaas_ua_common::{h32, PURPOSE_POP_V2};
use soroban_sdk::{crypto::Hash, panic_with_error, Bytes, BytesN, Env};

use crate::Error;

pub const WEBAUTHN_P256: u32 = 0x0100;
pub const P256: u32 = 0x0101;
pub const ED25519: u32 = 0x0102;
pub const SECP256K1: u32 = 0x0108;
pub const MSIG: u32 = 0x0120;
pub const MLDSA44: u32 = 0x0130;
pub const MLDSA65: u32 = 0x0131;
/// The `msig` members that are native ids (spec S10): `evm-eoa`, `evm-contract`, `stellar-account` (`G…`),
/// `soroban-contract` (`C…`).
pub const EVM_EOA: u32 = 0x0001;
pub const EVM_CONTRACT: u32 = 0x0002;
pub const STELLAR_ACCOUNT: u32 = 0x0011;
pub const SOROBAN_CONTRACT: u32 = 0x0012;

/// `keccak256("scaas.ua.msg.v1")`.
pub const MSG_TAG: [u8; 32] = h32("30a5cfd6b1d0889ef4a90d8488fa5e6e615322735899e23243d69087b6b66349");

/// `TAG(kind) = keccak256("scaas.ua.<name>.v1")` of the S3 kinds (pinned by `kinds.json`); any other kind is
/// `KindDisabled` on Soroban (spec S3).
#[cfg(test)] // the registry hashes `tag` inline; `TAG` pins it against `kinds.json`
#[allow(non_snake_case)]
pub fn TAG(env: &Env, kind: u32) -> BytesN<32> {
    BytesN::from_array(env, &tag(env, kind))
}

fn tag(env: &Env, kind: u32) -> [u8; 32] {
    match kind {
        WEBAUTHN_P256 => h32("286027ccb5bcb7d6cb8772d146e6db3249ce907b77ce28ddc35576169bd49da0"),
        P256 => h32("482d13b05d563574978ecc47126010977843fd937974af963578f21ef0513f8f"),
        ED25519 => h32("65ca73d2d290503a4785188712dd0b971b5fbf3113c1dc87185a46021b5131bc"),
        SECP256K1 => h32("98521857bce4e5830d7d084b5d6bae9b6b59537ef7e8db7a57c327bf524a6de9"),
        MSIG => h32("0c74d89236d93351f72ba09e86363f0ce977ca1f492ea24ebf6314231157fdd4"),
        MLDSA44 => h32("e16239d49e9fe951af81c8b23998f020775e322bc4ff6de72e681bb29a02eee0"),
        MLDSA65 => h32("226b3748e9e7f43e6976391a3082716487793bbfa41cbc55b27ecf55ac4a2f27"),
        _ => panic_with_error!(env, Error::KindDisabled),
    }
}

fn keccak(env: &Env, parts: &[&[u8]]) -> Hash<32> {
    let mut b = Bytes::new(env);
    for p in parts {
        b.extend_from_slice(p);
    }
    env.crypto().keccak256(&b)
}

/// CTR-UA-04: `keccak256(TAG(kind) ‖ key_data)`.
pub fn ua_of(env: &Env, kind: u32, key_data: &Bytes) -> BytesN<32> {
    let mut b = Bytes::from_array(env, &tag(env, kind));
    b.append(key_data);
    env.crypto().keccak256(&b).into()
}

/// CTR-UA-12: `ua_msg = keccak256(MSG_TAG ‖ TAG(kind) ‖ purposeTag ‖ digest)`.
pub fn ua_message(env: &Env, kind: u32, purpose: &BytesN<32>, digest: &BytesN<32>) -> Hash<32> {
    keccak(env, &[&MSG_TAG, &tag(env, kind), &purpose.to_array(), &digest.to_array()])
}

/// CTR-UA-23: the PQ kinds sign `pq_msg = keccak256(TAG(kind) ‖ ua_msg)` (empty context).
pub fn pq_message(env: &Env, kind: u32, ua_msg: &Hash<32>) -> Bytes {
    keccak(env, &[&tag(env, kind), &ua_msg.to_array()]).into()
}

/// An `msig` member signs `ua_message(member kind, PURPOSE_MEMBER, keccak256(structureUA ‖ ua_msg))`.
pub fn member_digest(env: &Env, structure_ua: &BytesN<32>, ua_msg: &Hash<32>) -> BytesN<32> {
    keccak(env, &[&structure_ua.to_array(), &ua_msg.to_array()]).into()
}

/// UA8-D1: `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)` (each hash 0 when absent).
pub fn portable_pop_digest(env: &Env, ua: &BytesN<32>, pqz_key_hash: &BytesN<32>, kem_record_hash: &BytesN<32>) -> BytesN<32> {
    keccak(env, &[&PURPOSE_POP_V2, &ua.to_array(), &pqz_key_hash.to_array(), &kem_record_hash.to_array()]).into()
}

/// UA8-D1: `keccak256(portablePopDigest ‖ pqzPopHash)`; the `pop` signs `ua_message(kind, PURPOSE_POP_V2, ·)` of it.
pub fn registration_digest(env: &Env, portable: &BytesN<32>, pqz_pop_hash: &BytesN<32>) -> BytesN<32> {
    keccak(env, &[&portable.to_array(), &pqz_pop_hash.to_array()]).into()
}
