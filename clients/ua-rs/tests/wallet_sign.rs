// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! ua-rs-sign T3a: the classic-curve signers (`0x0101` P-256 over `sha256(ua_msg)`, `0x0102` ed25519, `0x0103` BIP-340,
//! `0x0108` secp256k1 over `ua_msg`; the native keys of clientkeys `NETWORKS` and their addresses), the `Signer` trait and
//! `SigRole`, against smartcontracts/vectors/ua/{sign,keys,signatures}.json (written by clientkeys) and the external answers
//! of `sign.json` `external` (RFC 6979 A.2.5, the named secp256k1 set). The `vectors` tests use the test-only entry points
//! (fixed `aux`, raw secrets). UNAUDITED.
use scaas_ua::verify::{native_ecdsa, verify};
use scaas_ua::wallet::{AllowRawDigest, Error, KeyRef, Network, Signer, Wallet};
use scaas_ua::{keccak256, member_digest, purpose_tag, purpose_tag_v, ua_message, UAError};
use serde_json::Value;

fn load(path: &str) -> Value {
    let path = format!("{}/../../smartcontracts/vectors/ua/{path}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}
fn arr<'a>(v: &'a Value, k: &str) -> &'a Vec<Value> {
    v[k].as_array().unwrap()
}
fn bytes(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap().trim_start_matches("0x")).unwrap()
}
fn b32(v: &Value) -> [u8; 32] {
    bytes(v).try_into().unwrap()
}
fn u32_of(v: &Value) -> u32 {
    v.as_u64().unwrap() as u32
}
fn wallet(id: &str) -> Wallet {
    let k = load("keys.json");
    let m = arr(&k, "mnemonics").iter().find(|m| m["id"] == id).unwrap();
    Wallet::from_mnemonic(m["words"].as_str().unwrap(), m["passphrase"].as_str().unwrap()).unwrap()
}
/// The kinds T3a signs.
const T3A: [u16; 4] = [0x0101, 0x0102, 0x0103, 0x0108];
/// Half the order of secp256k1 and of P-256 (low-s: s ≤ n/2).
const SECP_HALF_N: &str = "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0";
const P256_HALF_N: &str = "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8";

fn low_s(kind: u16, sig: &[u8]) {
    let half = if kind == 0x0101 { P256_HALF_N } else { SECP_HALF_N };
    assert!(hex::encode(&sig[32..64]).as_str() <= half, "high s: {}", hex::encode(sig));
}

/// Every `sign.json` `ua` row of the T3a kinds: key data, `ua_msg`, the role, the signed bytes; `compare: bytes` byte-equal
/// through `sign_ua` (deterministic) or, with `fixed.aux`, through the `vectors` entry point; `compare: verify` verified, and
/// the release signature of the same request verifies.
#[test]
fn sign_json_ua_rows() {
    let s = load("sign.json");
    let w = wallet("pq_kat");
    let mut n = 0;
    for r in arr(&s, "ua").iter().filter(|r| T3A.contains(&(r["kind"].as_u64().unwrap() as u16))) {
        let kind = r["kind"].as_u64().unwrap() as u16;
        assert_eq!(r["mnemonic"], "pq_kat");
        let key = w.ua_key(kind, u32_of(&r["account"]), u32_of(&r["index"])).unwrap();
        assert_eq!(key.key_data(), bytes(&r["keyData"]), "{r}");
        let (purpose, digest) = (b32(&r["purposeTag"]), b32(&r["digest"]));
        let ua_msg = ua_message(kind, &purpose, &digest).unwrap();
        assert_eq!(ua_msg, b32(&r["uaMsg"]), "{r}");
        // what the scheme signs: sha256(ua_msg) for 0x0101, ua_msg itself for the rest (no prehash on 0x0108)
        let signed = if kind == 0x0101 { sha256(&ua_msg).to_vec() } else { ua_msg.to_vec() };
        assert_eq!(signed, bytes(&r["signed"]), "{r}");
        let pop = r["role"] == "pop";
        let sig = bytes(&r["signature"]);
        assert!(verify(kind, &key.key_data(), &ua_msg, &sig, pop), "{r}");
        let mine = key.sign_ua(&purpose, &digest).unwrap();
        assert!(verify(kind, &key.key_data(), &ua_msg, &mine, pop), "{r}");
        match (r["compare"].as_str().unwrap(), r["fixed"]["aux"].as_str()) {
            ("bytes", None) => assert_eq!(hex::encode(&mine), hex::encode(&sig), "{r}"),
            ("bytes", Some(_)) => fixed_aux(&key, &purpose, &digest, &b32(&r["fixed"]["aux"]), &sig),
            ("verify", _) => assert_eq!(kind, 0x0103, "{r}"),
            other => panic!("{other:?}"),
        }
        if matches!(kind, 0x0101 | 0x0108) {
            low_s(kind, &mine);
        }
        n += 1;
    }
    assert_eq!(n, 14);
}

#[cfg(feature = "vectors")]
fn fixed_aux(key: &scaas_ua::wallet::UaKey, purpose: &[u8; 32], digest: &[u8; 32], aux: &[u8; 32], sig: &[u8]) {
    assert_eq!(hex::encode(key.vectors_sign_ua_fixed(purpose, digest, aux).unwrap()), hex::encode(sig));
}
#[cfg(not(feature = "vectors"))]
fn fixed_aux(_: &scaas_ua::wallet::UaKey, _: &[u8; 32], _: &[u8; 32], _: &[u8; 32], _: &[u8]) {}

fn sha256(m: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(m).into()
}

/// Every `sign.json` `member` row of the T3a kinds: `uaMessage(kind, member, memberDigest(structureUa, structureUaMsg))`,
/// role authorization, byte-equal (all three deterministic).
#[test]
fn sign_json_member_rows() {
    let s = load("sign.json");
    let w = wallet("pq_kat");
    let mut n = 0;
    for r in arr(&s, "member").iter().filter(|r| T3A.contains(&(r["kind"].as_u64().unwrap() as u16))) {
        let kind = r["kind"].as_u64().unwrap() as u16;
        let key = w.ua_key(kind, u32_of(&r["account"]), u32_of(&r["index"])).unwrap();
        let (sua, smsg) = (b32(&r["structureUa"]), b32(&r["structureUaMsg"]));
        assert_eq!(member_digest(&sua, &smsg), b32(&r["memberDigest"]));
        assert_eq!(ua_message(kind, &purpose_tag("member").unwrap(), &member_digest(&sua, &smsg)).unwrap(), b32(&r["uaMsg"]));
        assert_eq!(r["role"], "authorization");
        assert_eq!(hex::encode(key.sign_member(&sua, &smsg).unwrap()), hex::encode(bytes(&r["signature"])), "{r}");
        n += 1;
    }
    assert_eq!(n, 3);
}

/// `chainSeparation`: the one UA key (0x0108) signs the same `UAMetaTransfer` per chain (digests from the vector, T4 builds
/// them), byte-equal, and the two signatures differ; the EVM key's address is the row's.
#[test]
fn chain_separation_rows() {
    let s = load("sign.json");
    let cs = &s["chainSeparation"];
    let w = wallet("pq_kat");
    let k = &cs["key"];
    let key = w.ua_key(k["kind"].as_u64().unwrap() as u16, u32_of(&k["account"]), u32_of(&k["index"])).unwrap();
    let evm = w.native_key(Network::Evm, u32_of(&k["evm"]["index"]), None).unwrap();
    assert_eq!(evm.address().as_deref(), k["evm"]["address"].as_str());
    let metatx = purpose_tag("metatx").unwrap();
    let mut sigs = Vec::new();
    for r in arr(cs, "typed") {
        let digest = b32(&r["digest"]);
        assert_eq!(ua_message(0x0108, &metatx, &digest).unwrap(), b32(&r["uaMsg"]));
        let sig = key.sign_ua(&metatx, &digest).unwrap();
        assert_eq!(hex::encode(&sig), hex::encode(bytes(&r["signature"])), "{r}");
        sigs.push(sig);
    }
    assert_eq!(sigs.len(), 2);
    assert_ne!(sigs[0], sigs[1]);
}

/// keys.json `native` rows: the address each network prints (EIP-55, bech32 `cosmos`, StrKey `G…`, base58, Sui BLAKE2b,
/// Aptos SHA3), none for `ton` and `hedera_ed25519`.
#[test]
fn keys_json_native_addresses() {
    let k = load("keys.json");
    let mut n = 0;
    for id in ["pq_kat", "bip39_test", "twelve_words", "non_ascii_passphrase"] {
        let w = wallet(id);
        for r in arr(&k, "native").iter().filter(|r| r["mnemonic"] == id) {
            let net = Network::from_name(r["network"].as_str().unwrap()).unwrap();
            let key = w.native_key(net, u32_of(&r["index"]), r["coinType"].as_u64().map(|c| c as u32)).unwrap();
            assert_eq!(key.address().as_deref(), r["address"].as_str(), "{r}");
            n += 1;
        }
    }
    assert_eq!(n, 74);
}

/// The EIP-55 checksum is case-exact: the lower-case form of an EVM row is another string.
#[test]
fn evm_address_is_checksummed() {
    let a = wallet("pq_kat").native_key(Network::Evm, 0, None).unwrap().address().unwrap();
    assert_ne!(a, a.to_lowercase());
    assert!(a.starts_with("0x") && a.len() == 42);
}

/// Key proof `keccak256("scaas-subject-key-proof-v1" ‖ challenge)` and the raw digest behind its marker: secp256k1 keys
/// recover their address (`r ‖ s ‖ v`, low-s, v ∈ {27, 28}, RFC 6979: the same twice), ed25519 keys verify.
#[test]
fn native_key_proof_and_raw_digest() {
    let w = wallet("pq_kat");
    let challenge = b"scaas t3a challenge";
    let proof = keccak256(&[&b"scaas-subject-key-proof-v1"[..], challenge].concat());
    let digest = keccak256(b"a checked batch root");
    for net in [Network::Evm, Network::Cosmos, Network::HederaEcdsa] {
        let key = w.native_key(net, 0, None).unwrap();
        let addr = evm_address_of(&key.public_key());
        for (sig, d) in [(key.sign_key_proof(challenge).unwrap(), proof), (key.sign_digest(&digest, AllowRawDigest).unwrap(), digest)] {
            assert!(native_ecdsa(&addr, &d, &sig), "{net:?}");
            low_s(0x0108, &sig);
        }
        assert_eq!(key.sign_key_proof(challenge).unwrap(), key.sign_key_proof(challenge).unwrap());
        assert!(!native_ecdsa(&addr, &digest, &key.sign_key_proof(challenge).unwrap())); // positive control's negative
    }
    for net in [Network::Solana, Network::Stellar, Network::HederaEd25519, Network::Sui, Network::Ton, Network::Aptos] {
        let key = w.native_key(net, 0, None).unwrap();
        assert!(scaas_ua::verify::ed25519(&key.public_key(), &proof, &key.sign_key_proof(challenge).unwrap()), "{net:?}");
        assert!(scaas_ua::verify::ed25519(&key.public_key(), &digest, &key.sign_digest(&digest, AllowRawDigest).unwrap()));
    }
}

fn evm_address_of(compressed: &[u8]) -> [u8; 20] {
    use k256::elliptic_curve::sec1::ToSec1Point;
    let pk = k256::PublicKey::from_sec1_bytes(compressed).unwrap();
    keccak256(&pk.to_sec1_point(false).as_bytes()[1..])[12..].try_into().unwrap()
}

/// `purpose` must be a tag of `PURPOSES` (v1) or `pop` v2; the off-chain seal purpose is the container builder's only (T8).
#[test]
fn purpose_not_in_purposes_refused() {
    let w = wallet("pq_kat");
    let key = w.ua_key(0x0102, 0, 0).unwrap();
    let d = [7u8; 32];
    assert!(key.sign_ua(&purpose_tag("metatx").unwrap(), &d).is_ok()); // positive control
    assert!(key.sign_ua(&purpose_tag_v("pop", 2).unwrap(), &d).is_ok());
    for bad in [keccak256(b"scaas.ua.purpose.seal.v1"), keccak256(b"scaas.ua.purpose.metatx.v2"), [0u8; 32], d] {
        assert_eq!(key.sign_ua(&bad, &d).err(), Some(Error::Ua(UAError::PurposeUnknown)));
    }
}

/// Kinds outside T3a / T3b: the pairing kinds come with T3c (`KindUnavailable`); a MuSig2 participant signs through its
/// session (`Argument`). The PQ kinds: tests/wallet_pq.rs.
#[test]
fn other_kinds_not_signed_here() {
    let w = wallet("pq_kat");
    let (p, d) = (purpose_tag("metatx").unwrap(), [1u8; 32]);
    for kind in [0x0104, 0x0105, 0x0106, 0x0107] {
        assert_eq!(w.ua_key(kind, 0, 0).unwrap().sign_ua(&p, &d).err(), Some(Error::KindUnavailable), "{kind:#06x}");
    }
    for kind in [0x0110, 0x0112] {
        assert_eq!(w.ua_key(kind, 0, 0).unwrap().sign_ua(&p, &d).err(), Some(Error::Argument), "{kind:#06x}");
    }
}

/// BIP-340 in a release build: `aux` from the OS RNG, so two signatures of one request differ and both verify.
#[test]
fn bip340_release_aux_is_random() {
    let w = wallet("pq_kat");
    let key = w.ua_key(0x0103, 0, 0).unwrap();
    let (p, d) = (purpose_tag("metatx").unwrap(), [3u8; 32]);
    let (a, b) = (key.sign_ua(&p, &d).unwrap(), key.sign_ua(&p, &d).unwrap());
    assert_ne!(a, b);
    let m = ua_message(0x0103, &p, &d).unwrap();
    assert!(verify(0x0103, &key.key_data(), &m, &a, false) && verify(0x0103, &key.key_data(), &m, &b, false));
}

/// A revoked handle signs nothing.
#[test]
fn locked_wallet_handles_sign_nothing() {
    let w = wallet("pq_kat");
    let key = w.ua_key(0x0108, 0, 0).unwrap();
    let native = w.native_key(Network::Evm, 0, None).unwrap();
    let (p, d) = (purpose_tag("metatx").unwrap(), [1u8; 32]);
    assert!(key.sign_ua(&p, &d).is_ok());
    w.lock();
    assert_eq!(key.sign_ua(&p, &d).err(), Some(Error::KeyRevoked));
    assert_eq!(key.sign_member(&d, &d).err(), Some(Error::KeyRevoked));
    assert_eq!(native.sign_key_proof(b"c").err(), Some(Error::KeyRevoked));
}

/// The `Signer` trait over both handle types: `key_ref` names the key; the handles are `Send + Sync` trait objects.
#[test]
fn signer_trait_key_ref() {
    let w = wallet("pq_kat");
    let ua = w.ua_key(0x0101, 0, 0).unwrap();
    let native = w.native_key(Network::Evm, 0, Some(60)).unwrap();
    let signers: [&dyn Signer; 2] = [&ua, &native];
    match signers[0].key_ref() {
        KeyRef::Ua { kind, key_data } => assert_eq!((kind, key_data), (0x0101, ua.key_data())),
        other => panic!("{other:?}"),
    }
    match signers[1].key_ref() {
        KeyRef::Native { network, coin_type, address, public_key } => {
            assert_eq!((network, coin_type, address, public_key), (Network::Evm, Some(60), native.address(), native.public_key()))
        }
        other => panic!("{other:?}"),
    }
}

#[cfg(feature = "vectors")]
mod vectors {
    use super::*;
    use scaas_ua::wallet::sign::sign_raw;
    use scaas_ua::wallet::{SigRole, SignRequest};
    use scaas_ua::PURPOSES;
    const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

    /// The role of every `sign.json` `ua` row (every kind): `pop` for `pop` v2, `kem`, `pqz-key`, else authorization
    /// (`UARegistryLib._sigOk`); each purpose of `PURPOSES` checked once; a member signature is always authorization.
    #[test]
    fn role_follows_the_registry_rule() {
        let s = load("sign.json");
        let w = wallet("pq_kat");
        let mut n = 0;
        for r in arr(&s, "ua") {
            let kind = r["kind"].as_u64().unwrap() as u16;
            let key = w.ua_key(kind, u32_of(&r["account"]), u32_of(&r["index"])).unwrap();
            let want = if r["role"] == "pop" { SigRole::Pop } else { SigRole::Authorization };
            match key.vectors_request(&b32(&r["purposeTag"]), &b32(&r["digest"])).unwrap() {
                SignRequest::UaMsg { kind: k, ua_msg, role, .. } => {
                    assert_eq!((k, ua_msg, role), (kind, b32(&r["uaMsg"]), want), "{r}");
                }
                other => panic!("{other:?}"),
            }
            n += 1;
        }
        assert_eq!(n, arr(&s, "ua").len()); // every kind, Falcon's 4 rows included (T3b)
        let key = w.ua_key(0x0106, 0, 0).unwrap();
        for p in PURPOSES {
            let want = if matches!(*p, "kem" | "pqz-key") { SigRole::Pop } else { SigRole::Authorization };
            let SignRequest::UaMsg { role, .. } = key.vectors_request(&purpose_tag(p).unwrap(), &[0; 32]).unwrap() else { panic!() };
            assert_eq!(role, want, "{p}");
        }
        let SignRequest::UaMsg { role, .. } = key.vectors_request(&purpose_tag_v("pop", 2).unwrap(), &[0; 32]).unwrap() else {
            panic!()
        };
        assert_eq!(role, SigRole::Pop);
        let SignRequest::UaMsg { role, .. } = key.vectors_member_request(&[1; 32], &[2; 32]).unwrap() else { panic!() };
        assert_eq!(role, SigRole::Authorization);
    }

    /// One key, one kind (CLI-SGN-29): a request built for another kind is refused by the key; the same request is signed
    /// by the key it was built for (positive control).
    #[test]
    fn kind_no_of_another_kind_refused() {
        let w = wallet("pq_kat");
        let (p, d) = (purpose_tag("metatx").unwrap(), [5u8; 32]);
        let k108 = w.ua_key(0x0108, 0, 0).unwrap();
        let k101 = w.ua_key(0x0101, 0, 0).unwrap();
        let req = k108.vectors_request(&p, &d).unwrap();
        assert!(k108.sign_request(&req).is_ok());
        assert_eq!(k101.sign_request(&req).err(), Some(Error::Argument));
        let native = w.native_key(Network::Evm, 0, None).unwrap();
        assert_eq!(native.sign_request(&req).err(), Some(Error::Argument));
    }

    /// RFC 6979 A.2.5 (P-256, SHA-256): `0x0101`'s primitive hashes the message with SHA-256 and signs; `r` as published,
    /// `s` as published or `n - s` (the signer returns low-s).
    #[test]
    fn rfc6979_a25_p256() {
        let e = &load("sign.json")["external"]["rfc6979"];
        let x = bytes(&e["x"]);
        let n = hex::decode(P256_N).unwrap();
        let mut rows = 0;
        for r in arr(e, "rows").iter().filter(|r| r["hash"] == "SHA-256") {
            let sig = sign_raw(0x0101, &x, r["message"].as_str().unwrap().as_bytes(), None).unwrap();
            assert_eq!(hex::encode(&sig[..32]), hex::encode(bytes(&r["r"])), "{r}");
            let s = bytes(&r["s"]);
            let low = if hex::encode(&s).as_str() > P256_HALF_N { sub(&n, &s) } else { s };
            assert_eq!(hex::encode(&sig[32..]), hex::encode(low), "{r}");
            low_s(0x0101, &sig);
            rows += 1;
        }
        assert_eq!(rows, 2);
    }

    /// `a - b` of two 32-byte big-endian numbers, `a ≥ b`.
    fn sub(a: &[u8], b: &[u8]) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let d = a[i] as i16 - b[i] as i16 - borrow;
            borrow = (d < 0) as i16;
            out[i] = (d + 256 * borrow) as u8;
        }
        out
    }

    /// The named secp256k1 RFC 6979 set (low-s): `0x0108`'s primitive signs the 32-byte `m` with no prehash; `r ‖ s` and the
    /// recovery id as published.
    #[test]
    fn rfc6979_secp256k1_set() {
        let e = &load("sign.json")["external"]["secp256k1"];
        let mut n = 0;
        for r in arr(e, "rows") {
            let sig = sign_raw(0x0108, &bytes(&r["d"]), &bytes(&r["m"]), None).unwrap();
            assert_eq!(hex::encode(&sig[..64]), r["signature"].as_str().unwrap(), "{r}");
            assert_eq!(u64::from(sig[64] - 27), r["recoveryId"].as_u64().unwrap(), "{r}");
            n += 1;
        }
        assert_eq!(n, 20);
    }

    /// signatures.json `native`: the native EVM signer's `r ‖ s ‖ v` over each `uaAuthDigest`, byte-equal.
    #[test]
    fn signatures_json_native_ecdsa() {
        let n = &load("signatures.json")["native"];
        let secret = bytes(&n["secret"]);
        let mut rows = 0;
        for r in arr(n, "sigs") {
            let sig = sign_raw(0x0001, &secret, &bytes(&r["uaAuthDigest"]), None).unwrap();
            assert_eq!(hex::encode(sig), r["sig"].as_str().unwrap().trim_start_matches("0x"), "{r}");
            rows += 1;
        }
        assert!(rows > 0);
    }

    /// The scheme primitive refuses what is not its message: a 31-byte `0x0108` / `0x0001` digest, a non-T3a kind.
    #[test]
    fn sign_raw_refusals() {
        let sk = [1u8; 32];
        assert!(sign_raw(0x0108, &sk, &[2u8; 32], None).is_ok());
        assert_eq!(sign_raw(0x0108, &sk, &[2u8; 31], None).err(), Some(Error::Argument));
        assert_eq!(sign_raw(0x0001, &sk, &[2u8; 33], None).err(), Some(Error::Argument));
        assert_eq!(sign_raw(0x0103, &sk, &[2u8; 32], None).err(), Some(Error::Argument)); // BIP-340 needs its aux here
        assert_eq!(sign_raw(0x0104, &sk, &[2u8; 32], None).err(), Some(Error::KindUnavailable));
    }
}
