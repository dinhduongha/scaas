//! Khoá relayer (R60): khoá thô HOẶC mnemonic BIP-39 24 từ, dẫn xuất theo SLIP-44 cho từng họ mạng và
//! account index của từng lane. Nguồn bí mật: biến môi trường, file 0600/0400, hoặc keystore Web3 v3
//! (scrypt + AES-128-CTR) cho cả hai đường cong. Không bao giờ log bí mật; chỉ in địa chỉ dẫn xuất.
use std::path::Path;

use alloy::signers::local::coins_bip39::{English, Mnemonic};
use anyhow::{anyhow, bail, Context, Result};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::signer::Curve;

/// Nơi đọc một bí mật. Đúng một trong ba.
#[derive(Debug, Clone, Deserialize, Default)]
pub struct SecretSource {
    #[serde(default)]
    pub env: Option<String>,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub keystore: Option<String>,
    #[serde(default)]
    pub passphrase_env: Option<String>,
}

impl SecretSource {
    pub fn read(&self) -> Result<Zeroizing<Vec<u8>>> {
        match (&self.env, &self.file, &self.keystore) {
            (Some(name), None, None) => {
                let v = std::env::var(name).with_context(|| format!("environment variable {name} is not set"))?;
                Ok(Zeroizing::new(v.trim().as_bytes().to_vec()))
            }
            (None, Some(path), None) => {
                check_private_file(Path::new(path))?;
                let v = std::fs::read(path).with_context(|| format!("read {path}"))?;
                let s = String::from_utf8(v).map_err(|_| anyhow!("{path} is not UTF-8"))?;
                Ok(Zeroizing::new(s.trim().as_bytes().to_vec()))
            }
            (None, None, Some(path)) => {
                let var = self.passphrase_env.as_deref().ok_or_else(|| anyhow!("keystore {path}: passphrase_env missing"))?;
                let pass = Zeroizing::new(std::env::var(var).with_context(|| format!("environment variable {var} is not set"))?);
                let raw = eth_keystore::decrypt_key(path, pass.as_bytes()).map_err(|e| anyhow!("keystore {path}: {e}"))?;
                Ok(Zeroizing::new(raw))
            }
            _ => bail!("a secret source needs exactly one of env, file, keystore"),
        }
    }
}

/// File bí mật không được ai khác đọc (0600/0400).
pub fn check_private_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path).with_context(|| format!("stat {}", path.display()))?.permissions().mode();
        if mode & 0o077 != 0 {
            bail!("{} is readable by others (mode {:o}); use 0600 or 0400", path.display(), mode & 0o777);
        }
    }
    Ok(())
}

/// Mnemonic đã kiểm checksum. Owner: đúng 24 từ (256 bit entropy).
pub struct Seed(Zeroizing<[u8; 64]>);

impl Seed {
    pub fn from_phrase(phrase: &[u8], passphrase: Option<&str>) -> Result<Self> {
        let text = std::str::from_utf8(phrase).map_err(|_| anyhow!("mnemonic is not UTF-8"))?;
        let words: Vec<&str> = text.split_whitespace().collect();
        if words.len() != 24 {
            bail!("the relayer mnemonic must have 24 words, got {}", words.len());
        }
        Self::from_words(&words.join(" "), passphrase)
    }

    /// Không ép số từ — chỉ cho vector test công bố (12 từ).
    pub fn from_words(phrase: &str, passphrase: Option<&str>) -> Result<Self> {
        let m = Mnemonic::<English>::new_from_phrase(phrase).map_err(|_| anyhow!("invalid BIP-39 mnemonic (word or checksum)"))?;
        let seed = m.to_seed(passphrase).map_err(|e| anyhow!("bip39 seed: {e}"))?;
        Ok(Self(Zeroizing::new(seed)))
    }

    pub fn bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// BIP-32 secp256k1 (`m/44'/60'/0'/0/i`…): khoá 32 byte.
    pub fn secp256k1(&self, path: &str) -> Result<Zeroizing<[u8; 32]>> {
        use coins_bip32::{derived::DerivedXPriv, xkeys::Parent};
        let master = DerivedXPriv::root_from_seed(self.0.as_slice(), None).map_err(|e| anyhow!("bip32 root: {e}"))?;
        let child = master.derive_path(path).map_err(|e| anyhow!("bip32 {path}: {e}"))?;
        let sk: &alloy::signers::k256::ecdsa::SigningKey = child.as_ref();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&sk.to_bytes());
        Ok(out)
    }

    /// SLIP-10 ed25519: chỉ cấp hardened. Trả seed khoá 32 byte.
    pub fn ed25519(&self, path: &str) -> Result<Zeroizing<[u8; 32]>> {
        slip10_ed25519(self.0.as_slice(), path)
    }
}

type HmacSha512 = Hmac<Sha512>;

pub fn slip10_ed25519(seed: &[u8], path: &str) -> Result<Zeroizing<[u8; 32]>> {
    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").expect("hmac key");
    mac.update(seed);
    let i = Zeroizing::new(mac.finalize().into_bytes());
    let mut key = Zeroizing::new([0u8; 32]);
    let mut chain = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&i[..32]);
    chain.copy_from_slice(&i[32..]);
    for index in parse_path(path)? {
        if index & 0x8000_0000 == 0 {
            bail!("ed25519 (SLIP-10) supports hardened levels only: {path}");
        }
        let mut mac = HmacSha512::new_from_slice(chain.as_slice()).expect("hmac key");
        mac.update(&[0u8]);
        mac.update(key.as_slice());
        mac.update(&index.to_be_bytes());
        let i = Zeroizing::new(mac.finalize().into_bytes());
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
    }
    Ok(key)
}

/// `m/44'/784'/0'/0'/0'` ⇒ chỉ số (bit 31 = hardened).
pub fn parse_path(path: &str) -> Result<Vec<u32>> {
    let mut parts = path.split('/');
    if parts.next() != Some("m") {
        bail!("derivation path must start with m/: {path}");
    }
    parts
        .map(|p| {
            let (n, hard) = match p.strip_suffix('\'').or_else(|| p.strip_suffix('h')) {
                Some(n) => (n, true),
                None => (p, false),
            };
            let v: u32 = n.parse().map_err(|_| anyhow!("bad path element {p} in {path}"))?;
            if v & 0x8000_0000 != 0 {
                bail!("path element {p} too large");
            }
            Ok(if hard { v | 0x8000_0000 } else { v })
        })
        .collect()
}

/// Họ mạng ⇒ (đường cong, đường dẫn cho lane `i`). Bảng §B.3 của spec round 3.
pub fn lane_path(family: &str, i: u32) -> Result<(Curve, String)> {
    Ok(match family {
        "evm" => (Curve::Secp256k1, format!("m/44'/60'/0'/0/{i}")),
        "hedera" => (Curve::Secp256k1, format!("m/44'/3030'/0'/0/{i}")),
        "cosmos" => (Curve::Secp256k1, format!("m/44'/118'/0'/0/{i}")),
        "sui" => (Curve::Ed25519, format!("m/44'/784'/{i}'/0'/0'")),
        "soroban" => (Curve::Ed25519, format!("m/44'/148'/{i}'")),
        "ton" => (Curve::Ed25519, format!("m/44'/607'/{i}'")),
        // Phantom/Solflare and `solana-keygen prompt://?full-path=`: m/44'/501'/account'/0' (Ledger Live's 3-level
        // m/44'/501'/i' is not used).
        "solana" => (Curve::Ed25519, format!("m/44'/501'/{i}'/0'")),
        // aptos-core PR #2073 / TS SDK: m/44'/637'/account'/change'/address_index', account index = lane.
        "aptos" => (Curve::Ed25519, format!("m/44'/637'/{i}'/0'/0'")),
        // near-algorand spec §11 (controller call 2026-10-28): fully hardened, lane = the last level.
        "near" => (Curve::Ed25519, format!("m/44'/397'/0'/0'/{i}'")),
        other => bail!("unknown family {other}"),
    })
}

/// `lane_path` với coin type SLIP-44 riêng của chain (`[[chains]] coin_type`) thay cấp coin của họ mạng —
/// Pi Network là họ `soroban` với 314159 thay 148. Coin type phải là chỉ số hardened (< 2^31); họ ed25519
/// giữ đường SLIP-10 toàn hardened.
pub fn lane_path_coin(family: &str, i: u32, coin_type: Option<u32>) -> Result<(Curve, String)> {
    let (curve, path) = lane_path(family, i)?;
    let Some(coin) = coin_type else { return Ok((curve, path)) };
    let rest = path.splitn(4, '/').nth(3).unwrap_or_default();
    let path = format!("m/44'/{coin}'/{rest}");
    let levels = parse_path(&path)?;
    if curve == Curve::Ed25519 && levels.iter().any(|l| l & 0x8000_0000 == 0) {
        bail!("ed25519 (SLIP-10) path must be hardened at every level: {path}");
    }
    Ok((curve, path))
}

/// Khoá 32 byte của lane: từ mnemonic theo bảng, hoặc từ khoá thô (một lane duy nhất).
pub fn lane_secret(seed: &Seed, family: &str, i: u32) -> Result<(Curve, Zeroizing<[u8; 32]>)> {
    lane_secret_coin(seed, family, i, None)
}

pub fn lane_secret_coin(seed: &Seed, family: &str, i: u32, coin_type: Option<u32>) -> Result<(Curve, Zeroizing<[u8; 32]>)> {
    let (curve, path) = lane_path_coin(family, i, coin_type)?;
    let key = match curve {
        Curve::Secp256k1 => seed.secp256k1(&path)?,
        Curve::Ed25519 => seed.ed25519(&path)?,
    };
    Ok((curve, key))
}

/// Khoá thô: hex 32 byte (có hoặc không `0x`).
pub fn parse_raw_key(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let s = std::str::from_utf8(raw).map_err(|_| anyhow!("private key is not text"))?.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = Zeroizing::new(alloy::hex::decode(s).map_err(|_| anyhow!("private key is not hex"))?);
    if bytes.len() != 32 {
        bail!("private key must be 32 bytes, got {}", bytes.len());
    }
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `scaas-node keystore new`: mã hoá một bí mật vào keystore Web3 v3 (dùng chung cho mnemonic,
/// khoá secp256k1 và seed ed25519 — `kind` chỉ để người vận hành nhận ra).
pub fn write_keystore(dir: &Path, name: &str, secret: &[u8], passphrase: &[u8]) -> Result<String> {
    let mut rng = rand::thread_rng();
    eth_keystore::encrypt_key(dir, &mut rng, secret, passphrase, Some(name)).map_err(|e| anyhow!("keystore: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{LocalSigner, Signer};

    const ART24: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn hexs(b: &[u8]) -> String {
        alloy::hex::encode(b)
    }

    #[test]
    fn bip39_trezor_vector_24_words() {
        // BIP-39 test vector (Trezor), entropy 0x00*32, passphrase "TREZOR".
        let s = Seed::from_phrase(ART24.as_bytes(), Some("TREZOR")).unwrap();
        assert_eq!(
            hexs(s.bytes()),
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8"
        );
    }

    #[test]
    fn mnemonic_checksum_and_length_are_enforced() {
        let bad = ART24.replace(" art", " abandon");
        assert!(Seed::from_phrase(bad.as_bytes(), None).is_err());
        assert!(Seed::from_phrase(b"abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", None).is_err());
        assert!(Seed::from_phrase(ART24.replace("art", "artz").as_bytes(), None).is_err());
    }

    #[test]
    fn slip10_ed25519_test_vector_1() {
        let seed = alloy::hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let cases = [
            ("m", "2b4be7f19ee27bbf30c667b642d5f4aa69fd169872f8fc3059c08ebae2eb19e7"),
            ("m/0'", "68e0fe46dfb67e368c75379acec591dad19df3cde26e63b93a8e704f1dade7a3"),
            ("m/0'/1'", "b1d0bad404bf35da785a64ca1ac54b2617211d2777696fbffaf208f746ae84f2"),
            ("m/0'/1'/2'", "92a5b23c0b8a99e37d07df3fb9966917f5d06e02ddbd909c7e184371463e9fc9"),
            ("m/0'/1'/2'/2'", "30d1dc7e5fc04c31219ab25a27ae00b50f6fd66622f6e9c913253d6511d1e662"),
            ("m/0'/1'/2'/2'/1000000000'", "8f94d394a8e8fd6b1bc2f3f49f5c47e385281d5c17e65324b0f62483e37e8793"),
        ];
        for (path, want) in cases {
            assert_eq!(hexs(slip10_ed25519(&seed, path).unwrap().as_slice()), want, "{path}");
        }
        assert!(slip10_ed25519(&seed, "m/0").is_err(), "non-hardened refused");
    }

    #[test]
    fn evm_hedera_cosmos_paths_match_cast() {
        // `cast wallet address|private-key --mnemonic "<ART24>" --mnemonic-derivation-path …`
        let s = Seed::from_phrase(ART24.as_bytes(), None).unwrap();
        let addr = |fam: &str, i: u32| {
            let (c, k) = lane_secret(&s, fam, i).unwrap();
            LocalSigner::new(c, &k).unwrap().address_hex()
        };
        assert_eq!(addr("evm", 0), "0xf278cf59f82edcf871d630f28ecc8056f25c1cdb");
        assert_eq!(addr("evm", 1), "0xf785bd075874b8423d3583728a981399f31e95aa");
        assert_eq!(addr("hedera", 0), "0x04d0f262432d16cea929f228f5e53df042a7d7c5");
        let (_, cosmos) = lane_secret(&s, "cosmos", 0).unwrap();
        assert_eq!(hexs(cosmos.as_slice()), "8088c2ed2149c34f6d6533b774da4e1692eb5cb426fdbaef6898eeda489630b7");
    }

    #[test]
    fn sui_path_matches_sui_keytool() {
        // `sui keytool import "<ART24>" ed25519 "m/44'/784'/{0,1}'/0'/0'"` (sui 1.81)
        let s = Seed::from_phrase(ART24.as_bytes(), None).unwrap();
        for (i, want) in [
            (0, "0xf967e21c16a4757daafec13ee79c0dc5c5329199be5d70c86fd07b8e75db892c"),
            (1, "0xf7f534201ecf22ce18f0776c860d0d43968f7c7993a3af1788671c73487c43fb"),
        ] {
            let (c, k) = lane_secret(&s, "sui", i).unwrap();
            let pk = LocalSigner::new(c, &k).unwrap().public_key();
            // Sui address = blake2b256(0x00 ‖ ed25519 pk)
            let mut flagged = vec![0u8];
            flagged.extend_from_slice(&pk);
            assert_eq!(format!("0x{}", hexs(&crate::signer::blake2b256(&flagged))), want);
        }
    }

    #[test]
    fn solana_path_matches_solana_keygen() {
        // `solana-keygen pubkey "prompt://?full-path=m/44'/501'/{0,1}'/0'"` with "<ART24>" (Agave 4.3.0)
        let s = Seed::from_phrase(ART24.as_bytes(), None).unwrap();
        for (i, want) in [(0, "3Cy3YNTFywCmxoxt8n7UH6hg6dLo5uACowX3CFceaSnx"), (1, "5frqxtii9LeGq2bz3dSNokvZcEooF483MzeU24JrhcTA")] {
            let (c, k) = lane_secret(&s, "solana", i).unwrap();
            assert_eq!(bs58::encode(LocalSigner::new(c, &k).unwrap().public_key()).into_string(), want);
        }
    }

    /// Task 16: NEAR lanes at `m/44'/397'/0'/0'/i'` (spec §11, fully hardened); lane 0 of ART24 is the key of
    /// `smartcontracts/near/vectors/near-tx.json` (its implicit account = the hex public key).
    #[test]
    fn lane_path_near() {
        assert_eq!(lane_path("near", 0).unwrap(), (Curve::Ed25519, "m/44'/397'/0'/0'/0'".to_string()));
        assert_eq!(lane_path("near", 1).unwrap(), (Curve::Ed25519, "m/44'/397'/0'/0'/1'".to_string()));
        let s = Seed::from_phrase(ART24.as_bytes(), None).unwrap();
        let (c, k) = lane_secret(&s, "near", 0).unwrap();
        assert_eq!(hexs(k.as_slice()), "1b46248b085a906e6c934d1056e0778a7b0af8ebb72a1dd8a6cc882e3b0cf977");
        assert_eq!(hexs(&LocalSigner::new(c, &k).unwrap().public_key()), "c5f869f1fa4165f42f2a837376db218644cf0b97dd818b834297e693144695c6");
        assert_ne!(lane_secret(&s, "near", 1).unwrap().1.as_slice(), k.as_slice());
    }

    #[test]
    fn aptos_path_matches_the_ts_sdk() {
        // `Account.fromDerivationPath({path: "m/44'/637'/{0,1}'/0'/0'", mnemonic: ART24})` (@aptos-labs/ts-sdk 7.3.0)
        let s = Seed::from_phrase(ART24.as_bytes(), None).unwrap();
        for (i, want) in [
            (0, "ba489e5562452afe9b4d4b4fdb0a1abcd4ddce7401276675a71715de5d6d16c2"),
            (1, "5ba5dddd21a18488d2f895b10f463c301bc5ed48cf839312915445d450b596ee"),
        ] {
            let (c, k) = lane_secret(&s, "aptos", i).unwrap();
            assert_eq!(hexs(&LocalSigner::new(c, &k).unwrap().public_key()), want);
        }
    }

    #[test]
    fn stellar_sep0005_vector() {
        // SEP-0005 test 1 (12 words), m/44'/148'/0' ⇒ GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6
        let s = Seed::from_words("illness spike retreat truth genius clock brain pass fit cave bargain toe", None).unwrap();
        let k = s.ed25519("m/44'/148'/0'").unwrap();
        let pk = LocalSigner::new(Curve::Ed25519, &k).unwrap().public_key();
        assert_eq!(crate::signer::stellar_account_strkey(&pk), "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6");
    }

    #[test]
    fn pi_network_is_soroban_with_coin_type_314159() {
        // bip_utils 2.9.3 `Bip32Slip10Ed25519.FromSeedAndPath(seed, "m/44'/314159'/{0,1}'")`, SEP-0005 test 1 words.
        let s = Seed::from_words("illness spike retreat truth genius clock brain pass fit cave bargain toe", None).unwrap();
        let addr = |coin: Option<u32>, i: u32| {
            let (c, k) = lane_secret_coin(&s, "soroban", i, coin).unwrap();
            crate::signer::stellar_account_strkey(&LocalSigner::new(c, &k).unwrap().public_key())
        };
        assert_eq!(lane_path_coin("soroban", 0, Some(314159)).unwrap().1, "m/44'/314159'/0'");
        assert_eq!(addr(Some(314159), 0), "GASWRHYE32A5A27TQWNRITIOZKOX7XQ6IVI4WEDGPVGX253D63UW2GJ3");
        assert_eq!(addr(Some(314159), 1), "GBSIS3JSLARC3D5WXRE3343Y2IMQBKRXHPC672RELHWXVUW4QWCWM2UT");
        assert_eq!(addr(None, 0), "GDRXE2BQUC3AZNPVFSCEZ76NJ3WWL25FYFK6RGZGIEKWE4SOOHSUJUJ6", "Stellar default unchanged");
        assert_eq!(addr(Some(148), 1), "GBAW5XGWORWVFE2XTJYDTLDHXTY2Q2MO73HYCGB3XMFMQ562Q2W2GJQX");
        // the override replaces the coin level only, on every family
        assert_eq!(lane_path_coin("evm", 2, Some(1)).unwrap().1, "m/44'/1'/0'/0/2");
        assert_eq!(lane_path_coin("sui", 1, Some(7)).unwrap().1, "m/44'/7'/1'/0'/0'");
        assert_eq!(lane_path_coin("solana", 1, Some(7)).unwrap().1, "m/44'/7'/1'/0'", "ed25519 stays all-hardened");
        assert!(lane_path_coin("soroban", 0, Some(0x8000_0000)).is_err(), "not a hardened index");
    }

    #[test]
    fn raw_keys_and_sources() {
        assert!(parse_raw_key(b"0x1234").is_err());
        let k = parse_raw_key(b" 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80\n").unwrap();
        assert_eq!(
            LocalSigner::new(Curve::Secp256k1, &k).unwrap().address_hex(),
            "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"
        );
        assert!(SecretSource::default().read().is_err());
        let both = SecretSource { env: Some("A".into()), file: Some("b".into()), ..Default::default() };
        assert!(both.read().is_err());
    }

    #[test]
    fn world_readable_secret_file_is_refused_and_keystore_round_trips() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("scaas-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("m.txt");
        std::fs::write(&f, ART24).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o644)).unwrap();
        let src = SecretSource { file: Some(f.display().to_string()), ..Default::default() };
        assert!(src.read().is_err());
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(src.read().unwrap().as_slice(), ART24.as_bytes());
        // keystore holding the mnemonic itself
        write_keystore(&dir, "m.json", ART24.as_bytes(), b"pw").unwrap();
        std::env::set_var("SCAAS_TEST_KS_PW", "pw");
        let ks = SecretSource {
            keystore: Some(dir.join("m.json").display().to_string()),
            passphrase_env: Some("SCAAS_TEST_KS_PW".into()),
            ..Default::default()
        };
        assert_eq!(ks.read().unwrap().as_slice(), ART24.as_bytes());
        std::fs::remove_dir_all(&dir).ok();
    }
}
