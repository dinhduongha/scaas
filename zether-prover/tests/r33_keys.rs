//! R33: conf key tree — pinned bn254 vectors, independence across paths/curves, and
//! "x never equals a signing scalar of the same seed".

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zether_prover::curve::{decode_point, encode_scalar, keccak256, ua_of, Bls12381, Bn254, ZCurve};
use zether_prover::keys::{derive_child_sk, derive_master_sk, derive_path, seed_from_mnemonic, ZetherKey};

const ABANDON_ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn dec_to_be(d: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    for ch in d.bytes() {
        let mut carry = (ch - b'0') as u32;
        for b in out.iter_mut().rev() {
            let v = *b as u32 * 10 + carry;
            *b = v as u8;
            carry = v >> 8;
        }
        assert_eq!(carry, 0);
    }
    out
}

fn seed() -> [u8; 64] {
    seed_from_mnemonic(ABANDON_ART, "").unwrap()
}

#[test]
fn bip39_seed_and_24_word_rule() {
    assert_eq!(
        hex::encode(seed()),
        "408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840"
    );
    // 12 words: valid BIP-39 but R32 demands 24.
    let twelve = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(seed_from_mnemonic(twelve, "").is_err());
    // bad checksum
    assert!(seed_from_mnemonic(&ABANDON_ART.replace(" art", " abandon"), "").is_err());
}

/// bn254 variant: same EIP-2333 seeds, values pinned from an independent stdlib-Python
/// implementation (tools/eip2333_ref.py).
#[test]
fn bn254_pinned_vectors() {
    let cases = [
        ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
         "11738895756143713593433593005171695756831574404929553644673081037477621758086", 0u32,
         "6102768562893513017562544315614589683693904773272731812322820416824691773609"),
        ("3141592653589793238462643383279502884197169399375105820974944592",
         "11671343213932408160813781834270667369745570977675072255026692393485578917129", 3141592653,
         "10490100399719139266755535087554901534552891971834855079703669358395707483974"),
        ("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
         "16902548629471611453108519997070444046308204219516872528681019605052608412725", 4294967295,
         "12166518292813157851030155837774160276116850026474053667451561157783731217405"),
        ("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
         "11482174731721057836319228340764382565009983300675505412623587040048902764607", 42,
         "10319261423956607007145371596219750929255942836712310181091569924135742469274"),
    ];
    for (s, master, idx, child) in cases {
        let m = derive_master_sk::<Bn254>(&hex::decode(s).unwrap()).unwrap();
        assert_eq!(encode_scalar::<Bn254>(&m), dec_to_be(master));
        assert_eq!(encode_scalar::<Bn254>(&derive_child_sk::<Bn254>(&m, idx)), dec_to_be(child));
    }
}

#[test]
fn conf_key_pinned_for_abandon_art() {
    let bn = ZetherKey::<Bn254>::conf(&seed(), 60, 0).unwrap();
    assert_eq!(hex::encode(encode_scalar::<Bn254>(&bn.x)), "008ce1ff1df3636c2227fdb27270bb37ac070cdf60c1d86da40228c7d2e742b1");
    let bls = ZetherKey::<Bls12381>::conf(&seed(), 60, 0).unwrap();
    assert_eq!(hex::encode(encode_scalar::<Bls12381>(&bls.x)), "67c93b3838eb86a76ead85bd6be7ca97ad82758b4ccd30ec58bff013a3392074");
}

fn scalars<C: ZCurve>() -> Vec<[u8; 32]> {
    let s = seed();
    let mut v = vec![];
    for coin in [60u32, 3030] {
        for account in [0u32, 1] {
            for key_use in [7u32, 8] {
                v.push(encode_scalar::<C>(&ZetherKey::<C>::derive(&s, coin, account, key_use).unwrap().x));
            }
        }
    }
    // A different seed gives a different key.
    let mut s2 = s;
    s2[0] ^= 1;
    v.push(encode_scalar::<C>(&ZetherKey::<C>::conf(&s2, 60, 0).unwrap().x));
    v
}

#[test]
fn keys_independent_across_paths_curves_seeds() {
    let mut all = scalars::<Bn254>();
    all.extend(scalars::<Bls12381>());
    let n = all.len();
    all.sort();
    all.dedup();
    assert_eq!(all.len(), n, "two (curve, coin, account, use, seed) tuples collided");
}

fn bip32_secp256k1(seed: &[u8], path: &str) -> [u8; 32] {
    let xprv = bip32::XPrv::derive_from_path(seed, &path.parse().unwrap()).unwrap();
    xprv.private_key().to_bytes().into()
}

/// SLIP-10 ed25519 (hardened only).
fn slip10_ed25519(seed: &[u8], path: &[u32]) -> [u8; 32] {
    let mut mac = Hmac::<Sha512>::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(seed);
    let mut i = mac.finalize().into_bytes();
    for &idx in path {
        let mut mac = Hmac::<Sha512>::new_from_slice(&i[32..]).unwrap();
        mac.update(&[0]);
        mac.update(&i[..32]);
        mac.update(&(idx | 0x8000_0000).to_be_bytes());
        i = mac.finalize().into_bytes();
    }
    i[..32].try_into().unwrap()
}

#[test]
fn conf_key_never_equals_a_signing_key() {
    let s = seed();
    // Known BIP-32 vector for this mnemonic: m/44'/60'/0'/0/0, cross-checked with tools/bip32_ref.py
    let evm = bip32_secp256k1(&s, "m/44'/60'/0'/0/0");
    assert_eq!(hex::encode(evm), "1053fae1b3ac64f178bcc21026fd06a3f4544ec2f35338b001f02d1d8efa3d5f");
    let mut signing: Vec<[u8; 32]> = vec![
        evm,
        bip32_secp256k1(&s, "m/44'/118'/0'/0/0"),  // Cosmos
        bip32_secp256k1(&s, "m/44'/3030'/0'/0/0"), // Hedera ECDSA
        slip10_ed25519(&s, &[44, 3030, 0, 0, 0]),  // Hedera ED25519
        slip10_ed25519(&s, &[44, 784, 0, 0, 0]),   // Sui
        slip10_ed25519(&s, &[44, 148, 0]),         // Stellar
        slip10_ed25519(&s, &[44, 607, 0]),         // TON
    ];
    // EIP-2334 BLS withdrawal (m/12381/60/0/0) and signing (m/12381/60/0/0/0) keys of the same tree.
    signing.push(encode_scalar::<Bls12381>(&derive_path::<Bls12381>(&s, &[12381, 60, 0, 0]).unwrap()));
    signing.push(encode_scalar::<Bls12381>(&derive_path::<Bls12381>(&s, &[12381, 60, 0, 0, 0]).unwrap()));
    for conf in scalars::<Bn254>().into_iter().chain(scalars::<Bls12381>()) {
        for sk in &signing {
            assert_ne!(&conf, sk);
        }
    }
}

fn ua_roundtrip<C: ZCurve>() {
    let k = ZetherKey::<C>::conf(&seed(), 60, 0).unwrap();
    let enc = k.encoded_y();
    assert_eq!(enc.len(), 2 * C::COORD_LEN);
    let y = decode_point::<C>(&enc).unwrap();
    assert_eq!(y, k.y);
    assert_eq!(ua_of::<C>(&y), k.ua());
    assert_eq!(k.ua(), keccak256(&enc));
}

#[test]
fn ua_pubkey_roundtrip() {
    ua_roundtrip::<Bn254>();
    ua_roundtrip::<Bls12381>();
}
