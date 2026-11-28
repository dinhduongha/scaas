// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The verdict key's start path (verifier-k256 review VK-1, VK-2, VK-6, VK-8): the password from the environment and the
//! keystore file, with no secret and no file content in any error, and a hostile keystore refused by name, never a panic.

use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

use scaas_pqz_verifier::{password_from_env, VerdictKey};

const SECRET: [u8; 32] = [0x42; 32];
const PASSWORD: &[u8] = b"correct horse";

/// A deterministic rng for eth-keystore's salt, iv and id: the keystore is the same file on every run.
struct Counter(u8);
impl rand_core::RngCore for Counter {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }
    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }
    fn fill_bytes(&mut self, dst: &mut [u8]) {
        for b in dst {
            self.0 = self.0.wrapping_add(1);
            *b = self.0;
        }
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dst);
        Ok(())
    }
}
impl rand_core::CryptoRng for Counter {}

/// A fresh directory per test under the system temp directory (made at run time).
fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "scaas-pqz-verifier-keystore-{}-{name}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The keystore of `SECRET` under `PASSWORD`, eth-keystore's own writer (scrypt n = 2^13, r = 8, p = 1).
fn keystore(name: &str) -> PathBuf {
    let d = dir(name);
    eth_keystore::encrypt_key(&d, &mut Counter(0), SECRET, PASSWORD, Some("k")).unwrap();
    d.join("k")
}

fn json(path: &PathBuf) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn write(path: &PathBuf, v: &serde_json::Value) {
    std::fs::write(path, v.to_string()).unwrap();
}

fn err(path: &PathBuf) -> String {
    format!(
        "{:#}",
        VerdictKey::decrypt_keystore(path, PASSWORD)
            .err()
            .expect("refused")
    )
}

#[test]
fn password_not_unicode_is_not_printed() {
    let name = "SCAAS_PQZ_VERIFIER_TEST_PASSWORD_NOT_UNICODE";
    std::env::set_var(name, std::ffi::OsStr::from_bytes(b"hunter2\xff"));
    let r = password_from_env(name);
    std::env::remove_var(name);
    // a non-UTF-8 password is a valid password: its bytes are kept
    if let Ok(p) = &r {
        assert_eq!(&p[..], b"hunter2\xff");
    }
    if let Err(e) = r {
        let e = format!("{e:#} {e:?}");
        assert!(!e.contains("hunter2"), "the password in the error: {e}");
    }
    let e = format!(
        "{:#}",
        password_from_env("SCAAS_PQZ_VERIFIER_TEST_PASSWORD_UNSET")
            .err()
            .unwrap()
    );
    assert_eq!(
        e,
        "the keystore password: env SCAAS_PQZ_VERIFIER_TEST_PASSWORD_UNSET is not set"
    );
}

#[test]
fn keystore_round_trip_and_wrong_password() {
    let path = keystore("round-trip");
    let want = VerdictKey::from_secret(zeroize::Zeroizing::new(SECRET.to_vec()))
        .unwrap()
        .address();
    assert_eq!(
        VerdictKey::decrypt_keystore(&path, PASSWORD)
            .unwrap()
            .address(),
        want
    );
    let e = format!(
        "{:#}",
        VerdictKey::decrypt_keystore(&path, b"wrong").err().unwrap()
    );
    assert_eq!(
        e,
        "the keystore: MAC mismatch (wrong password or a damaged file)"
    );
    assert!(!e.contains(&alloy::primitives::hex::encode(SECRET)));
}

#[test]
fn keystore_parse_error_quotes_no_content() {
    let path = dir("not-json").join("k");
    let hex = alloy::primitives::hex::encode(SECRET);
    std::fs::write(&path, format!("\"{hex}\"")).unwrap();
    let e = err(&path);
    assert!(
        !e.contains(&hex) && !e.contains("4242"),
        "file content in the error: {e}"
    );
    assert_eq!(e, "the keystore: not a keystore JSON");
}

/// One change to a parsed keystore.
type Edit = Box<dyn Fn(&mut serde_json::Value)>;

/// One field of a good keystore changed: refused with the named reason, before eth-keystore runs (no panic, no OOM).
#[test]
fn keystore_bounds() {
    let good = keystore("bounds");
    let base = json(&good);
    let cases: Vec<(&str, Edit, &str)> = vec![
        (
            "dklen 16",
            Box::new(|v| v["crypto"]["kdfparams"]["dklen"] = 16.into()),
            "kdf dklen not in 32..=64",
        ),
        (
            "iv 8 bytes",
            Box::new(|v| v["crypto"]["cipherparams"]["iv"] = "0102030405060708".into()),
            "iv not 16 bytes",
        ),
        (
            "scrypt n 2^31",
            Box::new(|v| v["crypto"]["kdfparams"]["n"] = (1u64 << 31).into()),
            "scrypt n not a power of two in 2..=2^18",
        ),
        (
            "scrypt n 0",
            Box::new(|v| v["crypto"]["kdfparams"]["n"] = 0.into()),
            "scrypt n not a power of two in 2..=2^18",
        ),
        (
            "scrypt n 3000",
            Box::new(|v| v["crypto"]["kdfparams"]["n"] = 3000.into()),
            "scrypt n not a power of two in 2..=2^18",
        ),
        (
            "scrypt r 64",
            Box::new(|v| v["crypto"]["kdfparams"]["r"] = 64.into()),
            "scrypt r not in 1..=8",
        ),
        (
            "scrypt p 0",
            Box::new(|v| v["crypto"]["kdfparams"]["p"] = 0.into()),
            "scrypt p not in 1..=4",
        ),
        (
            "cipher",
            Box::new(|v| v["crypto"]["cipher"] = "aes-256-gcm".into()),
            "cipher not aes-128-ctr",
        ),
        (
            "kdf",
            Box::new(|v| v["crypto"]["kdf"] = "argon2".into()),
            "kdf not scrypt or pbkdf2",
        ),
        (
            "ciphertext 31 bytes",
            Box::new(|v| v["crypto"]["ciphertext"] = "01".repeat(31).into()),
            "ciphertext not 32 bytes",
        ),
        (
            "mac 16 bytes",
            Box::new(|v| v["crypto"]["mac"] = "01".repeat(16).into()),
            "mac not 32 bytes",
        ),
        (
            "pbkdf2 dklen 16",
            Box::new(|v| {
                v["crypto"]["kdf"] = "pbkdf2".into();
                v["crypto"]["kdfparams"] =
                    serde_json::json!({"c": 1, "dklen": 16, "prf": "hmac-sha256", "salt": "00"});
            }),
            "kdf dklen not in 32..=64",
        ),
        (
            "pbkdf2 c 2^30",
            Box::new(|v| {
                v["crypto"]["kdf"] = "pbkdf2".into();
                v["crypto"]["kdfparams"] = serde_json::json!({"c": 1u64 << 30, "dklen": 32, "prf": "hmac-sha256", "salt": "00"});
            }),
            "pbkdf2 c not in 1..=2^22",
        ),
    ];
    for (what, edit, reason) in cases {
        let mut v = base.clone();
        edit(&mut v);
        write(&good, &v);
        assert_eq!(err(&good), format!("the keystore: {reason}"), "{what}");
    }
    let big = dir("big").join("k");
    std::fs::write(&big, vec![b' '; 64 * 1024 + 1]).unwrap();
    assert_eq!(err(&big), "the keystore: file larger than 64 KiB");
}
