//! `hub.sig` (spec mesh §4.5, R72): Ed25519 thuần (RFC 8032) của node gốc trên một thông điệp nhị phân cố định.
use anyhow::{anyhow, bail, Result};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

use super::envelope::{b32, hex_n, Envelope};
use super::Code;

pub const DOMAIN_TAG: &[u8] = b"scaas-hub/v1";
/// DER của SubjectPublicKeyInfo Ed25519 trước 32 byte khoá: `peer_id = sha256(prefix ‖ pubkey)`.
pub const SPKI_ED25519_PREFIX: [u8; 12] = [0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00];
/// PKCS#8 PrivateKeyInfo Ed25519 (48 byte) = prefix ‖ seed 32 byte (`openssl genpkey -algorithm ed25519`).
const PKCS8_ED25519_PREFIX: [u8; 16] = [0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20];

pub fn peer_id(pubkey: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(SPKI_ED25519_PREFIX);
    h.update(pubkey);
    h.finalize().into()
}

#[allow(clippy::too_many_arguments)]
pub fn hub_msg(chain_key: &str, intent_id: &[u8; 32], body_hash: &[u8; 32], hub_id: &[u8; 32], published_at: u64, private: bool,
               exclusive: Option<(&[u8; 32], u64)>) -> Result<Vec<u8>> {
    let len = u8::try_from(chain_key.len()).map_err(|_| anyhow!("chain_key longer than 255 bytes"))?;
    let mut m = Vec::with_capacity(12 + 1 + chain_key.len() + 96 + 8 + 2 + 32 + 8);
    m.extend_from_slice(DOMAIN_TAG);
    m.push(len);
    m.extend_from_slice(chain_key.as_bytes());
    m.extend_from_slice(intent_id);
    m.extend_from_slice(body_hash);
    m.extend_from_slice(hub_id);
    m.extend_from_slice(&published_at.to_be_bytes());
    m.push(private as u8);
    m.push(exclusive.is_some() as u8);
    m.extend_from_slice(exclusive.map_or(&[0u8; 32], |(id, _)| id));
    m.extend_from_slice(&exclusive.map_or(0, |(_, until)| until).to_be_bytes());
    Ok(m)
}

/// `hub_msg` của một envelope theo đúng các trường trên dây (đã qua L0).
pub fn env_msg(env: &Envelope, intent_id: &[u8; 32], body_hash: &[u8; 32]) -> Result<Vec<u8>, Code> {
    let hub_id = b32(&env.hub.id, false).ok_or(Code::BadEnvelope)?;
    let x = match &env.exclusive {
        Some(x) => Some((b32(&x.relayer_id, false).ok_or(Code::BadEnvelope)?, x.until)),
        None => None,
    };
    hub_msg(&env.chain_key, intent_id, body_hash, &hub_id, env.hub.published_at, env.private(), x.as_ref().map(|(id, u)| (id, *u)))
        .map_err(|_| Code::BadEnvelope)
}

pub fn sign(key: &SigningKey, msg: &[u8]) -> [u8; 64] {
    key.sign(msg).to_bytes()
}

/// `sha256(prefix ‖ pubkey) == hub.id` và chữ ký đúng (strict: từ chối khoá bậc nhỏ, `s` không chính tắc).
pub fn verify(env: &Envelope, intent_id: &[u8; 32], body_hash: &[u8; 32]) -> Result<(), Code> {
    let pubkey = b32(&env.hub.pubkey, false).ok_or(Code::BadEnvelope)?;
    let sig: [u8; 64] = hex_n(&env.hub.sig, 64, false).and_then(|s| s.try_into().ok()).ok_or(Code::BadEnvelope)?;
    if b32(&env.hub.id, false) != Some(peer_id(&pubkey)) {
        return Err(Code::BadHubSig);
    }
    let msg = env_msg(env, intent_id, body_hash)?;
    let key = VerifyingKey::from_bytes(&pubkey).map_err(|_| Code::BadHubSig)?;
    key.verify_strict(&msg, &Signature::from_bytes(&sig)).map_err(|_| Code::BadHubSig)
}

/// Seed của khoá PEM PKCS#8 Ed25519, tự parse (không cần feature `pkcs8`, spec §3.4).
pub fn seed_from_pem(pem: &str) -> Result<[u8; 32]> {
    let body: String = pem.lines().filter(|l| !l.starts_with("-----")).map(str::trim).collect();
    let der = B64.decode(body)?;
    if der.len() != 48 || der[..16] != PKCS8_ED25519_PREFIX {
        bail!("not an Ed25519 PKCS#8 private key");
    }
    Ok(der[16..].try_into().expect("32"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hub_msg_bytes_are_pinned() {
        let m = hub_msg("evm:100", &[1; 32], &[2; 32], &[3; 32], 0x0102, true, Some((&[4; 32], 0x0a0b))).unwrap();
        let want = [
            b"scaas-hub/v1".to_vec(), vec![7], b"evm:100".to_vec(), vec![1; 32], vec![2; 32], vec![3; 32],
            vec![0, 0, 0, 0, 0, 0, 1, 2], vec![1, 1], vec![4; 32], vec![0, 0, 0, 0, 0, 0, 0x0a, 0x0b],
        ]
        .concat();
        assert_eq!(m, want);
        let none = hub_msg("evm:100", &[1; 32], &[2; 32], &[3; 32], 0x0102, false, None).unwrap();
        assert_eq!(none[none.len() - 42..], [[0u8, 0].as_slice(), &[0; 40]].concat());
        assert!(hub_msg(&"x".repeat(256), &[0; 32], &[0; 32], &[0; 32], 0, false, None).is_err());
    }

    #[test]
    fn rfc8032_test_1_and_spki_pin() {
        // RFC 8032 §7.1 TEST 1: seed → khoá công khai và chữ ký của thông điệp rỗng.
        let seed: [u8; 32] = alloy::hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap().try_into().unwrap();
        let k = SigningKey::from_bytes(&seed);
        assert_eq!(alloy::hex::encode(k.verifying_key().to_bytes()), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(alloy::hex::encode(sign(&k, b"")), "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        // peer_id = sha256(DER SPKI): DER = prefix ‖ pubkey, 44 byte.
        let der = [SPKI_ED25519_PREFIX.as_slice(), &k.verifying_key().to_bytes()].concat();
        assert_eq!(der.len(), 44);
        assert_eq!(peer_id(&k.verifying_key().to_bytes()), <[u8; 32]>::from(Sha256::digest(&der)));
    }

    #[test]
    fn pem_seed() {
        let seed = [7u8; 32];
        let der = [PKCS8_ED25519_PREFIX.as_slice(), &seed].concat();
        let pem = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", B64.encode(&der));
        assert_eq!(seed_from_pem(&pem).unwrap(), seed);
        let rsa = format!("-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n", B64.encode([0u8; 48]));
        assert!(seed_from_pem(&rsa).is_err());
        assert!(seed_from_pem("-----BEGIN PRIVATE KEY-----\n!!\n-----END PRIVATE KEY-----").is_err());
    }
}
