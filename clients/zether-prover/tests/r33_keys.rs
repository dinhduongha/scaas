//! R33: conf key tree — pinned vectors, independence across paths/curves, and
//! "x never equals a signing scalar of the same seed".

use hmac::{Hmac, Mac};
use sha2::Sha512;
use zether_prover::curve::{decode_point, encode_scalar, keccak256, ua_of, Bls12381, ZCurve};
#[cfg(feature = "bn254")]
use zether_prover::curve::Bn254;
#[cfg(feature = "bn254")]
use zether_prover::keys::{derive_child_sk, derive_master_sk};
use zether_prover::keys::{derive_path, seed_from_mnemonic, ZetherKey};

const ABANDON_ART: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

#[cfg(feature = "bn254")]
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
    *seed_from_mnemonic(ABANDON_ART, "").unwrap()
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
#[cfg(feature = "bn254")]
#[test]
fn bn254_pinned_vectors() {
    let cases = [
        ("c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
         "1802855416675154470868852852860295717629090857147773969970247986303247977404", 0u32,
         "4211156714137627745402192188791465074635791236584106976665684448472813365427"),
        ("3141592653589793238462643383279502884197169399375105820974944592",
         "15972777130008368919276214988558782980542951358159958782990198812430803084399", 3141592653,
         "21831869212311891282481243516028143996033447034956749153120777034340767570648"),
        ("0099FF991111002299DD7744EE3355BBDD8844115566CC55663355668888CC00",
         "3595620084075808580498504623985214964712376740015232645922038711036798417158", 4294967295,
         "10773668880382336903154492684696246694897444539179322046490795739811952983067"),
        ("d4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3",
         "21513959535964185632175133903794170308355799619537385222855151988760283845700", 42,
         "13729494472004552956235825554402447030943696410682530557275295639633841114903"),
    ];
    for (s, master, idx, child) in cases {
        let m = derive_master_sk::<Bn254>(&hex::decode(s).unwrap()).unwrap();
        assert_eq!(encode_scalar::<Bn254>(&m), dec_to_be(master));
        assert_eq!(encode_scalar::<Bn254>(&derive_child_sk::<Bn254>(&m, idx)), dec_to_be(child));
    }
}

#[test]
fn conf_key_pinned_for_abandon_art() {
    #[cfg(feature = "bn254")]
    {
        let bn = ZetherKey::<Bn254>::conf(&seed(), 60, 0).unwrap();
        assert_eq!(hex::encode(encode_scalar::<Bn254>(&bn.x)), "2c6941c0d6c2913b0de687819730f0ee74ee01da6c9906d8cc6feac4a163e87e");
    }
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
    #[allow(unused_mut)]
    let mut all = scalars::<Bls12381>();
    #[cfg(feature = "bn254")]
    all.extend(scalars::<Bn254>());
    // distinct (coin, account, use, seed) tuples, and (with the legacy feature) distinct across curves
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
    #[allow(unused_mut)]
    let mut confs = scalars::<Bls12381>();
    #[cfg(feature = "bn254")]
    confs.extend(scalars::<Bn254>());
    for conf in confs {
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
    let tag = keccak256(format!("scaas.ua.zether-{}.v1", C::NAME).as_bytes());
    assert_eq!(k.ua(), keccak256(&[&tag[..], &enc].concat()), "UA = keccak256(TAG(kind) ‖ Y), CTR-UA-16");
}

#[test]
fn ua_pubkey_roundtrip() {
    #[cfg(feature = "bn254")]
    ua_roundtrip::<Bn254>();
    ua_roundtrip::<Bls12381>();
}

fn hex32(v: &serde_json::Value) -> [u8; 32] {
    hex::decode(&v.as_str().unwrap()[2..]).unwrap().try_into().unwrap()
}

/// The UA identity vectors (UA-1, `smartcontracts/vectors/ua/`): the Zether kinds' `UA` (kinds.json `valid`), their PoP
/// `ua_msg` (kinds.json `messages`) and `popDigest` (structures.json `pop`, contexts A and B) — one derivation for the
/// prover, the registry and the six UA libraries.
#[test]
fn ua_identity_matches_ua_vectors() {
    use zether_prover::curve::decode_point;
    use zether_prover::schnorr::{pop_digest, ua_message};
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../smartcontracts/vectors/ua/");
    let kinds: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}kinds.json")).unwrap()).unwrap();
    let mut n = 0;
    for row in kinds["valid"].as_array().unwrap() {
        let kd = hex::decode(&row["keyData"].as_str().unwrap()[2..]).unwrap();
        let ua = match row["kind"].as_u64().unwrap() {
            #[cfg(feature = "bn254")]
            0x0140 => ua_of::<Bn254>(&decode_point::<Bn254>(&kd).unwrap()),
            0x0141 => ua_of::<Bls12381>(&decode_point::<Bls12381>(&kd).unwrap()),
            _ => continue,
        };
        assert_eq!(ua, hex32(&row["ua"]));
        n += 1;
    }
    for row in kinds["messages"].as_array().unwrap() {
        let (p, d) = (hex32(&row["purposeTag"]), hex32(&row["digest"]));
        let m = match row["kind"].as_u64().unwrap() {
            #[cfg(feature = "bn254")]
            0x0140 => ua_message::<Bn254>(&p, &d),
            0x0141 => ua_message::<Bls12381>(&p, &d),
            _ => continue,
        };
        assert_eq!(m, hex32(&row["uaMsg"]));
        n += 1;
    }
    let st: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(format!("{dir}structures.json")).unwrap()).unwrap();
    for row in st["pop"].as_array().unwrap() {
        let c = &st["contexts"][row["context"].as_str().unwrap()];
        let reg: [u8; 20] = hex::decode(&c["registry"].as_str().unwrap()[2..]).unwrap().try_into().unwrap();
        let d = pop_digest(c["chainId"].as_u64().unwrap(), &hex32(&c["chainUid"]), &reg, &hex32(&row["ua"]), &hex32(&row.get("pqzKeyHash").unwrap_or(&row["authRef"])));
        // ponytail: `authRef` is the pre-UA-6 name of the same (zero) word; Task 8 regenerates the file with `pqzKeyHash`.
        assert_eq!(d, hex32(&row["popDigest"]));
        n += 1;
    }
    assert!(n >= 7, "{n} rows");
}

/// BIP-39 salt is `"mnemonic" ‖ NFKD(passphrase)`. The expected seed is what @scure/bip39
/// `mnemonicToSeedSync` and Python `pbkdf2_hmac` over NFKD both give; NFC and NFD spellings of
/// the same passphrase must land on it.
#[test]
fn bip39_passphrase_is_nfkd_normalized() {
    let want = "e031dc67ae9c173bf9b1989a53fe05b4da4282e0f4f671aad0e7a7a6cd9e401f\
                2683914fbbefe9aee48280d2e415f23d5020ffa80284e037f91b4120757ff519";
    for pass in ["m\u{1ead}t kh\u{1ea9}u", "ma\u{323}\u{302}t kha\u{302}\u{309}u"] {
        assert_eq!(hex::encode(&seed_from_mnemonic(ABANDON_ART, pass).unwrap()[..]), want, "{pass:?}");
    }
    // Same through the JSON API, and a non-string passphrase is an error, not "".
    let call = |key: serde_json::Value| zether_prover::api::call("keygen", &serde_json::json!({"curve": "bls12381", "key": key}).to_string());
    let by_words = call(serde_json::json!({"mnemonic": ABANDON_ART, "passphrase": "m\u{1ead}t kh\u{1ea9}u", "coin": 60, "account": 0}));
    let by_seed = call(serde_json::json!({"seed": format!("0x{want}"), "coin": 60, "account": 0}));
    assert_eq!(by_words.unwrap(), by_seed.unwrap());
    for bad in [serde_json::json!(1), serde_json::json!({}), serde_json::json!(["x"]), serde_json::json!(true)] {
        assert!(call(serde_json::json!({"mnemonic": ABANDON_ART, "passphrase": bad, "coin": 60, "account": 0})).is_err());
    }
    assert!(call(serde_json::json!({"mnemonic": ABANDON_ART, "passphrase": null, "coin": 60, "account": 0})).is_ok());
}
