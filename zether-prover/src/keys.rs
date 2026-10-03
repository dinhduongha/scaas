//! R33: the Zether conf key `x` comes from the subject's BIP-39 seed on its own tree.
//!
//! * BLS12-381: EIP-2333 exactly, path `m/12381/<coin>/<account>/<use>`.
//! * bn254: the same EIP-2333 construction with bn254's `r` and salt `"BAMBOO-ZETHER-BN254-v1"`,
//!   path `m/254/<coin>/<account>/<use>`.
//!
//! `<use> = 7` is the Zether conf key, `8` is reserved for disclosure/viewing keys. Neither tree
//! is a BIP-32/SLIP-10 tree, so `x` never equals a secp256k1/ed25519 signing scalar of the seed.

use ark_ff::{PrimeField, Zero};
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::curve::{encode_point, encode_scalar, generator, ua_of, Fr, ZCurve, G};
use crate::ZError;

pub const USE_CONF: u32 = 7;
pub const USE_DISCLOSURE: u32 = 8;
const L: usize = 48; // ceil(3 * ceil(log2 r) / 16) for both curves
const K: usize = 255; // EIP-2333 lamport chunks

/// EIP-2333 `HKDF_mod_r` with the curve's salt and `r`.
pub fn hkdf_mod_r<C: ZCurve>(ikm: &[u8], key_info: &[u8]) -> Fr<C> {
    let mut salt = C::KEYGEN_SALT.to_vec();
    let mut ikm0 = ikm.to_vec();
    ikm0.push(0);
    let mut info = key_info.to_vec();
    info.extend_from_slice(&(L as u16).to_be_bytes());
    loop {
        salt = Sha256::digest(&salt).to_vec();
        let mut okm = [0u8; L];
        Hkdf::<Sha256>::new(Some(&salt), &ikm0).expand(&info, &mut okm).expect("L <= 255*32");
        let sk = Fr::<C>::from_be_bytes_mod_order(&okm);
        okm.zeroize();
        if !sk.is_zero() {
            ikm0.zeroize();
            return sk;
        }
    }
}

fn ikm_to_lamport_sk(ikm: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut okm = vec![0u8; K * 32];
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(&[], &mut okm).expect("8160 <= 255*32");
    okm
}

/// EIP-2333 `parent_SK_to_lamport_PK` (compressed).
fn parent_sk_to_lamport_pk<C: ZCurve>(parent: &Fr<C>, index: u32) -> [u8; 32] {
    let salt = index.to_be_bytes();
    let mut ikm = encode_scalar::<C>(parent);
    let mut not_ikm = ikm.map(|b| !b);
    let mut l0 = ikm_to_lamport_sk(&ikm, &salt);
    let mut l1 = ikm_to_lamport_sk(&not_ikm, &salt);
    let mut h = Sha256::new();
    for chunk in l0.chunks(32).chain(l1.chunks(32)) {
        h.update(Sha256::digest(chunk));
    }
    ikm.zeroize();
    not_ikm.zeroize();
    l0.zeroize();
    l1.zeroize();
    h.finalize().into()
}

pub fn derive_master_sk<C: ZCurve>(seed: &[u8]) -> Result<Fr<C>, ZError> {
    if seed.len() < 32 {
        return Err(ZError::BadSeed("EIP-2333 seed must be at least 32 bytes"));
    }
    Ok(hkdf_mod_r::<C>(seed, b""))
}

pub fn derive_child_sk<C: ZCurve>(parent: &Fr<C>, index: u32) -> Fr<C> {
    hkdf_mod_r::<C>(&parent_sk_to_lamport_pk::<C>(parent, index), b"")
}

pub fn derive_path<C: ZCurve>(seed: &[u8], path: &[u32]) -> Result<Fr<C>, ZError> {
    let mut sk = derive_master_sk::<C>(seed)?;
    for &i in path {
        sk = derive_child_sk::<C>(&sk, i);
    }
    Ok(sk)
}

/// BIP-39 seed (64 B) from a 24-word English mnemonic (R32). Checksum is verified.
pub fn seed_from_mnemonic(words: &str, passphrase: &str) -> Result<[u8; 64], ZError> {
    let m = bip39::Mnemonic::parse_normalized(words).map_err(|_| ZError::BadSeed("invalid BIP-39 mnemonic"))?;
    if m.word_count() != 24 {
        return Err(ZError::BadSeed("R32: mnemonic must have 24 words"));
    }
    Ok(m.to_seed_normalized(passphrase))
}

/// A Zether key pair: `x` and `y = g^x` on G1.
#[derive(Clone)]
pub struct ZetherKey<C: ZCurve> {
    pub x: Fr<C>,
    pub y: G<C>,
}

impl<C: ZCurve> Drop for ZetherKey<C> {
    fn drop(&mut self) {
        self.x = Fr::<C>::zero();
    }
}

impl<C: ZCurve> ZetherKey<C> {
    pub fn from_secret(x: Fr<C>) -> Result<Self, ZError> {
        if x.is_zero() {
            return Err(ZError::BadScalar);
        }
        Ok(Self { x, y: generator::<C>() * x })
    }

    /// R33 derivation: `m/<root>/<coin>/<account>/<use>`.
    pub fn derive(seed: &[u8], coin: u32, account: u32, key_use: u32) -> Result<Self, ZError> {
        Self::from_secret(derive_path::<C>(seed, &[C::PATH_ROOT, coin, account, key_use])?)
    }

    /// The Zether conf key (`<use> = 7`).
    pub fn conf(seed: &[u8], coin: u32, account: u32) -> Result<Self, ZError> {
        Self::derive(seed, coin, account, USE_CONF)
    }

    pub fn encoded_y(&self) -> Vec<u8> {
        encode_point::<C>(&self.y)
    }

    pub fn ua(&self) -> [u8; 32] {
        ua_of::<C>(&self.y)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::curve::{Bls12381, Bn254};
    use ark_ff::BigInteger;

    fn dec<C: ZCurve>(s: &Fr<C>) -> String {
        // decimal for comparison with the EIP text
        let mut v = s.into_bigint().to_bytes_be();
        let mut out = Vec::new();
        while v.iter().any(|&b| b != 0) {
            let mut rem = 0u32;
            for b in v.iter_mut() {
                let cur = (rem << 8) | *b as u32;
                *b = (cur / 10) as u8;
                rem = cur % 10;
            }
            out.push(b'0' + rem as u8);
        }
        out.reverse();
        String::from_utf8(out).unwrap()
    }

    /// The four published EIP-2333 test cases.
    #[test]
    fn eip2333_published_vectors() {
        let cases = [
            ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
             "6083874454709270928345386274498605044986640685124978867557563392430687146096", 0u32,
             "20397789859736650942317412262472558107875392172444076792671091975210932703118"),
            ("3141592653589793238462643383279502884197169399375105820974944592",
             "29757020647961307431480504535336562678282505419141012933316116377660817309383", 3141592653,
             "25457201688850691947727629385191704516744796114925897962676248250929345014287"),
            ("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
             "27580842291869792442942448775674722299803720648445448686099262467207037398656", 4294967295,
             "29358610794459428860402234341874281240803786294062035874021252734817515685787"),
            ("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
             "19022158461524446591288038168518313374041767046816487870552872741050760015818", 42,
             "31372231650479070279774297061823572166496564838472787488249775572789064611981"),
        ];
        for (seed, master, idx, child) in cases {
            let m = derive_master_sk::<Bls12381>(&hex::decode(seed).unwrap()).unwrap();
            assert_eq!(dec::<Bls12381>(&m), master);
            assert_eq!(dec::<Bls12381>(&derive_child_sk::<Bls12381>(&m, idx)), child);
        }
    }

    #[test]
    fn short_seed_rejected() {
        assert!(derive_master_sk::<Bn254>(&[0u8; 31]).is_err());
    }
}
