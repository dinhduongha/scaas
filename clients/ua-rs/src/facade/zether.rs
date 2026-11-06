// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `zether` (ua-rs-sign T14; spec §10.1, §8.2, §9.3): the Zether facade over `clients/zether-prover`, BLS12-381 only.
//!
//! - **Keys.** [`crate::wallet::Wallet::zether_key`] derives `x` = zether-prover `ZetherKey::derive(seed, coin, account, use)`
//!   (EIP-2333 `m/12381/<coin>/<account>/<use>`, use 7 the conf key, 8 the viewing key) into the wallet's arena; the handle
//!   holds the store, its generation and the slot (no secret bytes), `Y` and the UA. Every secret operation runs under the
//!   store's read guard, so `lock()` revokes the handle (`KeyRevoked`, for good; spec §8.2).
//! - **Commands.** zether-prover's `api` commands that need the key or are public ([`COMMANDS`]; a release build keeps only
//!   encrypt, the PoP, the owner and UA signatures, the shield calldata, the envelope, typed digests and named calls,
//!   ARCH-POS-13, the rest is feature `vectors` until T14b): encrypt, decrypt and the
//!   pending decrypt, the balance check, the transfer, multi-recipient and burn proofs, the memo, the recovery (with the
//!   sender's openings `SENDER_S` / `SENDER_CP`), the receiver's and auditor's openings (`openDisclosure`), the PoP, the owner
//!   and UA signatures, the shield calldata, the envelope, typed digests and named calls. Not exposed: the verifiers,
//!   `keygen` (the handle gives `Y` and the UA). The command JSON is read by the bounded reader (1 MiB, depth 8), then each
//!   field is checked against the command's **allow-list** (and each nested object against its own), so no `key` object and
//!   none of the prover's secret-returning flags (`revealSecret`, `includeWitness`) can pass; the facade hands the key to
//!   `api::call_with_key` itself. A prover refusal is `Argument` (its text is not passed on: it can name request values).
//! - **Balance cache** (clientkeys `sealBalanceCache` / `openBalanceCache`): AES-256-GCM under
//!   `HKDF-SHA256(x, no salt, "scaas-zether-balance-cache-v1", 32)`, AAD `zether-cache:bls12381`, the box `{iv, ct}` in
//!   unpadded base64url. The bookkeeping over the entries (`setCachedBalance`, `cacheAfterDebit`, `cacheAfterRollOver`) needs
//!   `x` only through the balance check, which is the `checkBalance` command.
//!
//! Randomness: `rand_core` 0.6 `OsRng` inside (the prover's proofs, nonces and openings are hedged on it); the fixed-randomness
//! entry points exist only under feature `vectors`. Residual (spec §8.2): the prover's scalar copies on the stack and its
//! scalar multiplications by `x` (arkworks, not `secret_mul`). UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

use crate::wallet::{aead_open, aead_seal, bounded, hkdf_sha256, Alg, Error, Handle, KeyId, Result, SecretStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use zeroize::Zeroizing;
use zether_prover::curve::{decode_scalar, encode_scalar, Bls12381};
use zether_prover::keys::ZetherKey as ProverKey;

/// The conf key's and the viewing key's `<use>` (zether-prover `USE_CONF`, `USE_DISCLOSURE`).
pub const USE_CONF: u32 = zether_prover::keys::USE_CONF;
pub const USE_VIEWING: u32 = zether_prover::keys::USE_DISCLOSURE;
/// The command JSON's caps (spec §9.3).
pub const CMD_MAX: usize = 1 << 20;
pub const CMD_DEPTH: usize = 8;
/// The balance-cache box JSON's caps: `{iv, ct}` of a plaintext up to [`crate::wallet::MAX_PT`] (1 MiB) in base64url.
pub const BOX_MAX: usize = 2 << 20;
pub const BOX_DEPTH: usize = 1;
/// zether.js `CACHE_INFO` and the AAD of `sealBalanceCache` on BLS12-381.
const CACHE_INFO: &[u8] = b"scaas-zether-balance-cache-v1";
const CACHE_AAD: &[u8] = b"zether-cache:bls12381";

/// The header fields of the transfer and burn proofs (zether-prover `api::header`).
const HEADER: &[&str] =
    &["chainId", "chainUid", "token", "envelopeBinding", "unwrapBinding", "sendCounter", "accSeq", "fee", "beneficiary", "validUntilBlock"];
/// The recovery source and its chain fields (`recovery_source`, `recovery_header`).
const RECOVERY: &[&str] = &["payload", "entry", "sendCounter", "memo", "chainId", "chainUid", "token"];

/// The commands, in this order (the fuzz target `zether_cmd`, built with `vectors`, names them by index).
///
/// ARCH-POS-13 ("never a decryption oracle", owner 2026-11-06; spec no-decryption-oracle §4.8, T15c): a release build (no
/// feature `vectors`) has no command that decrypts or opens a ciphertext its caller chose: `decrypt`, `decryptPending`,
/// `checkBalance`, `proveTransfer`, `proveTransferMulti`, `proveBurn`, `openMemo`, `recoverTransfer` and `openDisclosure` exist
/// only under the test feature `vectors` (which also turns on zether-prover's `hazmat`) until they take proven state (T14b).
/// In a release build they are unknown commands (`Argument`, before the key is touched).
pub const COMMANDS: &[&str] = &[
    "encrypt",
    #[cfg(feature = "vectors")]
    "decrypt",
    #[cfg(feature = "vectors")]
    "decryptPending",
    #[cfg(feature = "vectors")]
    "checkBalance",
    #[cfg(feature = "vectors")]
    "proveTransfer",
    #[cfg(feature = "vectors")]
    "proveTransferMulti",
    #[cfg(feature = "vectors")]
    "proveBurn",
    #[cfg(feature = "vectors")]
    "openMemo",
    #[cfg(feature = "vectors")]
    "recoverTransfer",
    #[cfg(feature = "vectors")]
    "openDisclosure",
    "pop",
    "ownerAuth",
    "uaSig",
    "shieldCalldata",
    "envelope",
    "typedDigest",
    "namedCall",
];

/// The allow-list of `cmd`'s top-level fields (the fields zether-prover's `api` reads for it, never `key`, `revealSecret`,
/// `includeWitness`); `curve` where the command is a curve command.
fn allowed(cmd: &str, field: &str) -> bool {
    let has = |l: &[&str]| l.contains(&field);
    match cmd {
        "encrypt" | "shieldCalldata" => has(&["curve", "Y", "amount"]),
        "decrypt" => has(&["curve", "ct", "tableBits", "boundBits", "allowLargeTable"]),
        "decryptPending" => has(&["curve", "pending", "tableBits", "boundBits", "allowLargeTable"]),
        "checkBalance" => has(&["curve", "acc", "balance"]),
        "proveTransfer" => has(HEADER) || has(&["curve", "disclosureMode", "yTo", "yAud", "auditorMode", "acc", "balance", "amount"]),
        "proveTransferMulti" => {
            has(HEADER)
                || has(&[
                    "curve", "disclosureMode", "mode", "recipients", "yAud", "auditorMode", "decoyFee", "minDecoyFee", "uaSigner",
                    "uaSignerGas", "acc", "balance",
                ])
        }
        "proveBurn" => has(HEADER) || has(&["curve", "amount", "recipient", "acc", "balance"]),
        "openMemo" => has(RECOVERY) || field == "curve",
        "recoverTransfer" => has(RECOVERY) || has(&["curve", "tableBits", "boundBits", "yAud"]),
        "openDisclosure" => has(&[
            "curve", "kind", "chainId", "chainUid", "token", "entryRef", "index", "amount", "Yt", "Cout", "Dout", "Ya", "Caud", "Daud",
        ]),
        "pop" => field == "curve",
        "ownerAuth" => has(&["curve", "digest"]),
        "uaSig" => has(&["curve", "purpose", "digest"]),
        "envelope" => has(&["chainId", "chainUid", "token", "meta"]),
        "typedDigest" => has(&["op", "chainId", "chainUid", "token", "message"]),
        "namedCall" => has(&[
            "op", "env", "payload", "proof", "beneficiary", "sig", "recipient", "amount", "unwrap", "chainId", "chainUid", "token",
        ]),
        _ => false,
    }
}

/// A string, a bool, null, or a number that is a `u64` (the prover reads no other number; a float would not read back to
/// itself, fuzz target `zether_cmd`).
fn scalar(x: &Value) -> bool {
    match x {
        Value::Number(n) => n.is_u64(),
        Value::Object(_) | Value::Array(_) => false,
        _ => true,
    }
}

/// `x` an object of scalars whose fields are all in `fields`.
fn flat(x: &Value, fields: &[&str]) -> bool {
    x.as_object().is_some_and(|o| o.iter().all(|(k, v)| fields.contains(&k.as_str()) && scalar(v)))
}

/// `x` (any depth, bounded by the reader) holds no object member named `key` and only scalars of [`scalar`]'s kinds.
fn clean(x: &Value) -> bool {
    match x {
        Value::Object(o) => o.iter().all(|(k, v)| k != "key" && clean(v)),
        Value::Array(a) => a.iter().all(clean),
        _ => scalar(x),
    }
}

/// The shape of a field's value: the ciphertexts `{C, D}`, the legs `[{yTo, amount}]`, the envelope `meta` / `env`, the
/// `unwrap` arguments, the typed `message` (any struct the prover's typed hasher checks field by field, without a `key`
/// anywhere); every other field a [`scalar`].
fn shape(field: &str, x: &Value) -> bool {
    match field {
        "acc" | "ct" | "pending" => flat(x, &["C", "D"]),
        "recipients" => x.as_array().is_some_and(|a| a.iter().all(|r| flat(r, &["yTo", "amount"]))),
        "meta" => flat(x, &["from", "data", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"]),
        "env" => flat(x, &["from", "batch", "nonce", "validUntil", "mode", "relayer", "fee", "feeRecipient"]),
        "unwrap" => flat(x, &["underlying", "recipient", "amount", "minOut"]),
        "message" => x.is_object() && clean(x),
        "curve" => x.as_str() == Some("bls12381"),
        _ => scalar(x),
    }
}

/// A Zether command as the facade passes it on: its name and its fields, each on the command's allow-list. Public data only.
#[derive(Clone, Debug, PartialEq)]
pub struct ZetherCmd {
    cmd: &'static str,
    v: Map<String, Value>,
}

impl ZetherCmd {
    /// `json` (at most [`CMD_MAX`] bytes, depth [`CMD_DEPTH`], the bounded reader) as command `cmd`: an object whose fields are
    /// all on `cmd`'s allow-list, each of its shape; else `Argument` (an unknown command, a `key` object, a secret-returning
    /// flag, an unknown field, another curve).
    pub fn from_json(cmd: &str, json: &[u8]) -> Result<ZetherCmd> {
        let cmd = *COMMANDS.iter().find(|c| **c == cmd).ok_or(Error::Argument)?;
        let Value::Object(v) = bounded::json(json, CMD_MAX, CMD_DEPTH)? else { return Err(Error::Argument) };
        if !v.iter().all(|(k, x)| allowed(cmd, k) && shape(k, x)) {
            return Err(Error::Argument);
        }
        Ok(ZetherCmd { cmd, v })
    }
    pub fn cmd(&self) -> &'static str {
        self.cmd
    }
    /// The fields as JSON (what [`ZetherCmd::from_json`] reads back to the same command).
    pub fn to_json(&self) -> String {
        Value::Object(self.v.clone()).to_string()
    }
}

/// A Zether key handle (spec §8.2): the wallet's store, the generation and the slot of `x`, and the public `Y` and UA; no
/// secret bytes of its own. Neither `Clone` nor `Debug`:
/// ```compile_fail,E0277
/// fn need<T: Clone>() {}
/// need::<scaas_ua::facade::zether::ZetherKey>();
/// ```
#[cfg_attr(
    not(feature = "vectors"),
    doc = "A release build (no feature `vectors`) takes no RNG and no fixed iv (F-01):",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::facade::zether::ZetherKey) {",
    doc = "    let _ = k.vectors_call(\"pop\", b\"{}\", &mut rand_core::OsRng);",
    doc = "}",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::facade::zether::ZetherKey) {",
    doc = "    let _ = k.vectors_seal_balance_cache(b\"{}\", &[0; 12]);",
    doc = "}",
    doc = "```"
)]
pub struct ZetherKey {
    coin: u32,
    account: u32,
    key_use: u32,
    y: Vec<u8>,
    ua: [u8; 32],
    secret: Handle,
}

impl zeroize::ZeroizeOnDrop for ZetherKey {}

/// [`crate::wallet::Wallet::zether_key`].
pub(crate) fn derive(store: &Arc<SecretStore>, coin: u32, account: u32, key_use: u32) -> Result<ZetherKey> {
    super::release_or_unlocked()?;
    if key_use != USE_CONF && key_use != USE_VIEWING {
        return Err(Error::Argument);
    }
    let (secret, y) = store.key(KeyId::Zether(coin, account, key_use), |seed| {
        let k = ProverKey::<Bls12381>::derive(seed, coin, account, key_use).map_err(|_| Error::Argument)?;
        Ok((Zeroizing::new(encode_scalar::<Bls12381>(&k.x).to_vec()), k.encoded_y()))
    })?;
    let ua = crate::derive_ua(0x0141, &y, false)?;
    Ok(ZetherKey { coin, account, key_use, y, ua, secret })
}

fn b64(b: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(b)
}

impl ZetherKey {
    pub fn coin(&self) -> u32 {
        self.coin
    }
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn key_use(&self) -> u32 {
        self.key_use
    }
    /// `Y = [x]G`, 128 bytes (the contracts' G1 encoding).
    pub fn y(&self) -> Vec<u8> {
        self.y.clone()
    }
    /// The UA of kind `zether-bls12381` (0x0141).
    pub fn ua(&self) -> [u8; 32] {
        self.ua
    }

    /// `f` over `x` under the store's read guard: `KeyRevoked` once the wallet was locked or freed.
    fn with_x<T>(&self, f: impl FnOnce(&[u8]) -> Result<T>) -> Result<T> {
        self.secret.with(f)?
    }

    /// `f` over the prover's key, rebuilt from `x` under the guard (its `x` wiped on drop).
    fn with_key<T>(&self, f: impl FnOnce(&ProverKey<Bls12381>) -> Result<T>) -> Result<T> {
        self.with_x(|x| {
            let k = ProverKey::from_secret(decode_scalar::<Bls12381>(x).map_err(|_| Error::Argument)?).map_err(|_| Error::Argument)?;
            f(&k)
        })
    }

    fn run<Rn: RngCore + CryptoRng>(&self, cmd: &str, request_json: &[u8], rng: &mut Rn) -> Result<String> {
        let c = ZetherCmd::from_json(cmd, request_json)?;
        let v = Value::Object(c.v);
        self.with_key(|k| zether_prover::api::call_with_key(c.cmd, &v, k, rng).map(|o| o.to_string()).map_err(|_| Error::Argument))
    }

    /// Command `cmd` of [`COMMANDS`] on `request_json` (named fields, as zether-prover's `api`, without a key) with this
    /// handle's key; the prover's JSON answer.
    pub fn call(&self, cmd: &str, request_json: &[u8]) -> Result<String> {
        self.run(cmd, request_json, &mut OsRng)
    }

    fn cache_key(x: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let k = hkdf_sha256(x, &[], CACHE_INFO, 32)?;
        Ok(Zeroizing::new(k.as_slice().try_into().map_err(|_| Error::Argument)?))
    }

    fn seal_box(&self, entries_json: &[u8], iv: &[u8; 12]) -> Result<String> {
        if entries_json.len() > crate::wallet::MAX_PT {
            return Err(Error::Argument);
        }
        let ct = self.with_x(|x| aead_seal(Alg::Aes256Gcm, &*Self::cache_key(x)?, iv, CACHE_AAD, entries_json))?;
        Ok(json!({"iv": b64(iv), "ct": b64(&ct)}).to_string())
    }

    /// clientkeys `sealBalanceCache`: the box `{iv, ct}` of the cache entries (the caller's JSON, at most 1 MiB) under this
    /// key, a fresh iv from the OS RNG.
    pub fn seal_balance_cache(&self, entries_json: &[u8]) -> Result<String> {
        let mut iv = [0u8; 12];
        OsRng.try_fill_bytes(&mut iv).map_err(|_| Error::Rng)?;
        self.seal_box(entries_json, &iv)
    }

    /// clientkeys `openBalanceCache`: the entries of a box; `Argument` for a box that is not `{iv, ct}` (base64url, a 12-byte iv),
    /// `Aead` for one that does not open under this key (clientkeys: an empty cache).
    pub fn open_balance_cache(&self, box_json: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let Value::Object(o) = bounded::json(box_json, BOX_MAX, BOX_DEPTH)? else { return Err(Error::Argument) };
        let field = |k: &str| o.get(k).and_then(Value::as_str).and_then(|s| Base64UrlUnpadded::decode_vec(s).ok()).ok_or(Error::Argument);
        if o.len() != 2 {
            return Err(Error::Argument);
        }
        let iv: [u8; 12] = field("iv")?.try_into().map_err(|_| Error::Argument)?;
        let ct = field("ct")?;
        self.with_x(|x| aead_open(Alg::Aes256Gcm, &*Self::cache_key(x)?, &iv, CACHE_AAD, &ct))
    }
}

/// Test-only (feature `vectors`, never in a release build): the generator's randomness.
#[cfg(feature = "vectors")]
impl ZetherKey {
    /// [`ZetherKey::call`] at `rng` (zether-prover's vector files are made at fixed seeds).
    pub fn vectors_call<Rn: RngCore + CryptoRng>(&self, cmd: &str, request_json: &[u8], rng: &mut Rn) -> Result<String> {
        self.run(cmd, request_json, rng)
    }
    /// [`ZetherKey::seal_balance_cache`] at a given iv.
    pub fn vectors_seal_balance_cache(&self, entries_json: &[u8], iv: &[u8; 12]) -> Result<String> {
        self.seal_box(entries_json, iv)
    }
}
