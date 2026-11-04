//! The UA words (CTR-UA-04, -12, -23; UA8-D1), byte-identical to EVM `UAKinds`, over the host's `keccak256`. The typed
//! portable records (typed-signing TS-D1) are in `scaas_ua_common` (the token / mandate / DEX / relay-fee tests register
//! UAs by them too); the raw UA-8 digests they replace are in `legacy/typed-signing/`.
use scaas_ua_common::h32;
use soroban_sdk::{crypto::Hash, panic_with_error, Bytes, BytesN, Env, String};

use crate::Error;

pub const WEBAUTHN_P256: u32 = 0x0100;
pub const P256: u32 = 0x0101;
pub const ED25519: u32 = 0x0102;
pub const BIP340: u32 = 0x0103;
pub const SCHNORR_BN254: u32 = 0x0104;
pub const SCHNORR_BLS12381: u32 = 0x0105;
pub const BLS12381_MINSIG: u32 = 0x0106;
pub const BLS_BN254_MINSIG: u32 = 0x0107;
pub const SECP256K1: u32 = 0x0108;
pub const MUSIG2_SECP256K1: u32 = 0x0110;
pub const FROST_SECP256K1: u32 = 0x0111;
pub const MUSIG2_BN254: u32 = 0x0112;
pub const FROST_BN254: u32 = 0x0113;
pub const MSIG: u32 = 0x0120;
pub const MLDSA44: u32 = 0x0130;
pub const MLDSA65: u32 = 0x0131;
pub const FNDSA512: u32 = 0x0132;
pub const SLHDSA128S: u32 = 0x0133;
pub const ZETHER_BLS12381: u32 = 0x0141;
/// The `msig` members that are native ids (spec S10): `evm-eoa`, `evm-contract`, `stellar-account` (`G…`).
/// `soroban-contract` (`C…`) passes the layout and is `MemberUnknown` (owner ruling 2026-10-31: invoker auth).
pub const EVM_EOA: u32 = 0x0001;
pub const EVM_CONTRACT: u32 = 0x0002;
pub const STELLAR_ACCOUNT: u32 = 0x0011;
pub const SOROBAN_CONTRACT: u32 = 0x0012;

/// `keccak256("scaas.ua.msg.v1")`.
pub const MSG_TAG: [u8; 32] = h32("30a5cfd6b1d0889ef4a90d8488fa5e6e615322735899e23243d69087b6b66349");

/// `TAG(kind) = keccak256("scaas.ua.<name>.v1")` of the S3 kinds and the U8S-D8 kinds, whose ids need it (pinned by
/// `kinds.json`); any other kind is `KindDisabled` on Soroban (spec S3).
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
        BIP340 => h32("a9489d15dc0a9a471df06d0603e27ab451e040929292380f241b1ec94e4816b6"),
        SCHNORR_BN254 => h32("aa4cca7b3ce7738561d916c1a4d9f0620a02b80e6b336f5bdd7f219f134290c7"),
        SCHNORR_BLS12381 => h32("3cbeaa356151795c08b46a2c07121f484e14b8da9f8c778a7e116de5e93cd38d"),
        BLS12381_MINSIG => h32("993ba323ff2b0b21b2ee2b7aebb84ed33bc7115df79daae4a52f0ead7ea7b47a"),
        BLS_BN254_MINSIG => h32("2da45c3a55c35bb8e3c0075a827e59faefe7b7ce319c48cbd2768a7e00a93f1c"),
        MUSIG2_SECP256K1 => h32("d59cc66d7dd1c673ef35a25a9b1b289362014425459d0a82b06f3404c6333579"),
        FROST_SECP256K1 => h32("ef3901c6997cfa840489c8732f9792e9bce7c532daad378b192f45cabb2d54fa"),
        MUSIG2_BN254 => h32("2fad7d5e69bec36b5ab549bc7ccc096bbdd8c5c016ad91bdd1939629e94a7e8e"),
        FROST_BN254 => h32("4b4b996f58eda018d4ef95614123de808f3df5444822839e994ec3253b675c07"),
        FNDSA512 => h32("90fb2d1095002504a9f1ca0c10c7714894b25c985d054d8e8b5d36337888edbf"),
        SLHDSA128S => h32("aceb1ed15faba4fd95a04608b27524248da39ec495b39b1de7224ee2c5fe8eab"),
        ZETHER_BLS12381 => h32("310d8f055db5703650f4e4385c184df50c11da516161ef68a7ab2d7363a8a66c"),
        _ => panic_with_error!(env, Error::KindDisabled),
    }
}

/// EVM `UAKinds.name` (TS-D5): every kind id of the table, enabled here or not; any other id is `KindUnknown`.
pub fn kind_name(env: &Env, kind: u32) -> String {
    let name = match kind {
        0x0001 => "evm-eoa",
        0x0002 => "evm-contract",
        0x0003 => "hedera-native",
        0x0010 => "solana-ed25519",
        0x0011 => "stellar-account",
        0x0012 => "soroban-contract",
        0x0013 => "aptos-account",
        0x0014 => "sui-address",
        0x0015 => "cosmos-account",
        0x0016 => "ton-wallet",
        0x0017 => "near-account",
        0x0018 => "algorand-address",
        0x0100 => "webauthn-p256",
        0x0101 => "p256",
        0x0102 => "ed25519",
        0x0103 => "bip340",
        0x0104 => "schnorr-bn254",
        0x0105 => "schnorr-bls12381",
        0x0106 => "bls12381-minsig",
        0x0107 => "bls-bn254-minsig",
        0x0108 => "secp256k1",
        0x0110 => "musig2-secp256k1",
        0x0111 => "frost-secp256k1",
        0x0112 => "musig2-bn254",
        0x0113 => "frost-bn254",
        0x0120 => "msig",
        0x0130 => "mldsa44",
        0x0131 => "mldsa65",
        0x0132 => "fndsa512",
        0x0133 => "slhdsa128s",
        0x0134 => "mldsa87", // CTR-UA-39: named here, refused by `register` until the Soroban round
        0x0135 => "fndsa1024", // CTR-UA-40: the same
        0x0141 => "zether-bls12381",
        0x0142 => "pqz-mlwe",
        _ => panic_with_error!(env, Error::KindUnknown),
    };
    String::from_str(env, name)
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
