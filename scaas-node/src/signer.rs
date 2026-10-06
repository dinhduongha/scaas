//! `Signer` (R59): một trait cho mọi đường cong relayer dùng. `LocalSigner` giữ khoá trong bộ nhớ
//! tiến trình node; KMS/HSM/remote signer cắm vào bằng một impl khác của trait (seam, chưa xây).
use alloy::primitives::keccak256;
use alloy::signers::k256::ecdsa::SigningKey as K256Key;
use anyhow::{anyhow, bail, Result};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use ed25519_dalek::Signer as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Curve {
    Secp256k1,
    Ed25519,
}

pub trait Signer: Send + Sync {
    fn curve(&self) -> Curve;
    /// secp256k1: 33 byte nén; ed25519: 32 byte.
    fn public_key(&self) -> Vec<u8>;
    /// secp256k1: `msg` là prehash 32 byte ⇒ 65 byte `r‖s‖v` (v = 27/28, low-s).
    /// ed25519: ký nguyên `msg` ⇒ 64 byte.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>>;
}

pub enum LocalSigner {
    Secp(K256Key),
    Ed(ed25519_dalek::SigningKey),
}

impl LocalSigner {
    pub fn new(curve: Curve, secret: &[u8; 32]) -> Result<Self> {
        Ok(match curve {
            Curve::Secp256k1 => Self::Secp(K256Key::from_bytes(secret.into()).map_err(|_| anyhow!("invalid secp256k1 key"))?),
            Curve::Ed25519 => Self::Ed(ed25519_dalek::SigningKey::from_bytes(secret)),
        })
    }

    /// Địa chỉ EVM (chỉ secp256k1), chữ thường.
    pub fn address_hex(&self) -> String {
        match self {
            Self::Secp(k) => {
                let pt = k.verifying_key().to_encoded_point(false);
                format!("0x{}", alloy::hex::encode(&keccak256(&pt.as_bytes()[1..])[12..]))
            }
            Self::Ed(_) => String::new(),
        }
    }

    /// `alloy` signer cho đường EVM (cùng khoá).
    pub fn evm(&self) -> Result<alloy::signers::local::PrivateKeySigner> {
        match self {
            Self::Secp(k) => Ok(alloy::signers::local::PrivateKeySigner::from_signing_key(k.clone())),
            Self::Ed(_) => bail!("an ed25519 key cannot sign EVM transactions"),
        }
    }
}

impl Signer for LocalSigner {
    fn curve(&self) -> Curve {
        match self {
            Self::Secp(_) => Curve::Secp256k1,
            Self::Ed(_) => Curve::Ed25519,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            Self::Secp(k) => k.verifying_key().to_encoded_point(true).as_bytes().to_vec(),
            Self::Ed(k) => k.verifying_key().to_bytes().to_vec(),
        }
    }

    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Secp(k) => {
                if msg.len() != 32 {
                    bail!("secp256k1 signs a 32-byte prehash");
                }
                let (sig, rid) = k.sign_prehash_recoverable(msg).map_err(|e| anyhow!("sign: {e}"))?;
                let (sig, rid) = match sig.normalize_s() {
                    Some(low) => (low, alloy::signers::k256::ecdsa::RecoveryId::from_byte(rid.to_byte() ^ 1).expect("rid")),
                    None => (sig, rid),
                };
                let mut out = sig.to_bytes().to_vec();
                out.push(27 + rid.to_byte());
                Ok(out)
            }
            Self::Ed(k) => Ok(k.sign(msg).to_bytes().to_vec()),
        }
    }
}

pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2b::<U32>::new();
    h.update(data);
    h.finalize().into()
}

/// CRC16-XModem (Stellar strkey, TON user-friendly address).
pub fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// RFC 4648 base32, không padding.
pub fn base32(data: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut buf, mut bits) = (0u32, 0u32);
    for &b in data {
        buf = (buf << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            out.push(A[((buf >> (bits - 5)) & 31) as usize] as char);
            bits -= 5;
        }
    }
    if bits > 0 {
        out.push(A[((buf << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// Stellar account strkey `G…` (version byte 6 << 3).
pub fn stellar_account_strkey(pk: &[u8]) -> String {
    let mut payload = vec![6u8 << 3];
    payload.extend_from_slice(pk);
    let crc = crc16_xmodem(&payload);
    payload.extend_from_slice(&crc.to_le_bytes());
    base32(&payload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secp256k1_signature_recovers_and_is_low_s() {
        let k: [u8; 32] = alloy::hex::decode("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
            .unwrap()
            .try_into()
            .unwrap();
        let s = LocalSigner::new(Curve::Secp256k1, &k).unwrap();
        let digest = [0x11u8; 32];
        let sig = s.sign(&digest).unwrap();
        assert_eq!(sig.len(), 65);
        let parsed = alloy::primitives::Signature::try_from(sig.as_slice()).unwrap();
        let rec = parsed.recover_address_from_prehash(&digest.into()).unwrap();
        assert_eq!(format!("{rec:#x}"), s.address_hex());
        let n_half = alloy::primitives::U256::from_str_radix(
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0", 16).unwrap();
        assert!(parsed.s() <= n_half);
        // `cast wallet sign --no-hash 0x11..11` (RFC 6979) gives the same signature.
        assert_eq!(alloy::hex::encode(&sig),
            "0f7ab7fdc86593590dfcf2e79ffe37056ed62d7191979e42979d39942847fbb904f14566b0640bb3c10128294cda733f61fa74f3dc846979c55115e92b0a1b751b");
        assert!(s.sign(b"short").is_err());
    }

    #[test]
    fn ed25519_rfc8032_test_1() {
        let k: [u8; 32] = alloy::hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
            .unwrap()
            .try_into()
            .unwrap();
        let s = LocalSigner::new(Curve::Ed25519, &k).unwrap();
        assert_eq!(alloy::hex::encode(s.public_key()), "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        assert_eq!(alloy::hex::encode(s.sign(b"").unwrap()),
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    }

    #[test]
    fn crc_and_base32_vectors() {
        assert_eq!(crc16_xmodem(b"123456789"), 0x31c3);
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }
}
