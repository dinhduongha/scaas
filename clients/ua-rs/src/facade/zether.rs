// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `zether` (ua-rs-sign T14; spec §10.1, §8.2, §9.3): the Zether facade over `clients/zether-prover`, BLS12-381 only.
//!
//! - **Keys.** [`crate::wallet::Wallet::zether_key`] derives `x` = zether-prover `ZetherKey::derive(seed, coin, account, use)`
//!   (EIP-2333 `m/12381/<coin>/<account>/<use>`, use 7 the conf key, 8 the viewing key) into the wallet's arena; the handle
//!   holds the store, its generation and the slot (no secret bytes), `Y` and the UA. Every secret operation runs under the
//!   store's read guard, so `lock()` revokes the handle (`KeyRevoked`, for good; spec §8.2).
//! - **Commands** ([`COMMANDS`]): encrypt, the PoP, the owner and UA signatures, the shield calldata, the envelope, typed
//!   digests and named calls (zether-prover's `api`), and the **words commands** (zether-prover's `state`; ARCH-POS-13, T14b):
//!   `balance`, `pendingBalance`, `checkBalance`, `proveTransfer`, `proveTransferMulti`, `proveBurn`, `openMemo`,
//!   `recoverTransfer` (with the sender's openings `SENDER_S` / `SENDER_CP`), `openDisclosure` (the receiver's and the
//!   auditor's openings, the amount decrypted inside). Not exposed: the verifiers, `keygen` (the handle gives `Y` and the UA).
//!   The command JSON is read by the bounded reader (1 MiB, depth 8), then each field is checked against the command's
//!   **allow-list** (and each nested object against its own), so no `key` object and none of the prover's secret-returning
//!   flags (`revealSecret`, `includeWitness`) can pass; the facade hands the key to zether-prover itself. A prover refusal is
//!   `Argument` (its text is not passed on: it can name request values).
//! - **No decryption oracle** (ARCH-POS-13, owner 2026-11-06; spec no-decryption-oracle §4.3, §4.7, T14b): a command that
//!   decrypts takes a named location (`family`, `chainId`, `chainUid`, `token`, `block`, `ua`, the entry's `fromUA` and
//!   `sendCounter`, a leg `index`) and the **raw** storage words the reading layer read at one block (the account struct's
//!   slots, the `bytes` data slots, `entries` / `entryPtrs` / `memos` and the SSTORE2 code, the token's `psid`, `modes` and
//!   `auditorKey` words), never a ciphertext, an entry, a memo or a parsed state field. zether-prover's `state::prepare`
//!   checks `psid` and the family, parses the words by the pinned layout (`ua-mtx-merge` T19c), checks them, binds the leg
//!   and the role to this handle's `Y` and rebuilds the ciphertexts exactly as `ZetherLib`; only then is the key used
//!   (`state::run`). Every refusal before that is `Argument`; after it only `KeyRevoked` and `Argument` to the caller (a
//!   balance below a debit). Whether the words are real chain state of a catalogued token is the reading layer's duty
//!   (R1–R7), not this library's (spec §4.12). The raw forms (`decrypt`, `decryptPending`, `raw*`) exist only under the test
//!   feature `vectors`.
//! - **Balance cache** (clientkeys `sealBalanceCache` / `openBalanceCache`): AES-256-GCM under
//!   `HKDF-SHA256(x, no salt, "scaas-zether-balance-cache-v1", 32)`, AAD `zether-cache:bls12381`, the box `{iv, ct}` in
//!   unpadded base64url. The bookkeeping over the entries (`setCachedBalance`, `cacheAfterDebit`, `cacheAfterRollOver`) needs
//!   `x` only through the balance check, which is the `checkBalance` command: it takes the box itself (`cacheBox`), opens it
//!   inside and checks its entry `<UA>:<token>` at the words' `accSeq` against the rebuilt `acc`; a debit's balance hint is the
//!   same box (T15l, Fable P3-1: never a caller's number, so a check is no balance-equality test for whoever builds requests).
//!
//! Randomness: `rand_core` 0.6 `OsRng` inside (the prover's proofs, nonces and openings are hedged on it); the fixed-randomness
//! entry points exist only under feature `vectors`. Every multiplication of a supplied point by `x` (and by the proofs'
//! nonce over `x`) runs through `scaas_ct::secret_mul` in zether-prover (T14b, Codex C6). Residual (spec §8.2): the
//! prover's scalar copies on the stack, its fixed-base multiplications `[x]G`, and the per-transfer secrets `s`, `t_j` on
//! supplied keys (arkworks). UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

use crate::wallet::{aead_open, aead_seal, bounded, hkdf_sha256, Alg, Error, Handle, KeyId, Result, SecretStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use rand_core::{CryptoRng, OsRng, RngCore};
use serde_json::{json, Map, Value};
use std::sync::Arc;
use zeroize::Zeroizing;
use zether_prover::curve::{decode_point, decode_scalar, encode_scalar, Bls12381};
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

/// The header fields of the transfer and burn proofs (zether-prover `api::header`; the raw commands, feature `vectors`).
#[cfg(feature = "vectors")]
const HEADER: &[&str] =
    &["chainId", "chainUid", "token", "envelopeBinding", "unwrapBinding", "sendCounter", "accSeq", "fee", "beneficiary", "validUntilBlock"];
/// The recovery source and its chain fields (`recovery_source`, `recovery_header`; the raw commands, feature `vectors`).
#[cfg(feature = "vectors")]
const RECOVERY: &[&str] = &["payload", "entry", "sendCounter", "memo", "chainId", "chainUid", "token"];

/// The commands, in this order (the fuzz target `zether_cmd`, built with `vectors`, names them by index). `pickDecoys`
/// `{candidates, exclude, count, weights?}` → `{decoys}` (T15n, CTR-UA-29: [`super::decoys`]; the multi-recipient
/// transfer's decoys; the handle's key is not used).
///
/// ARCH-POS-13 ("never a decryption oracle", owner 2026-11-06; spec no-decryption-oracle §4.7, §4.8, T15c, T14b): a release
/// build (no feature `vectors`) has no command that decrypts or opens a ciphertext its caller chose. The decrypting commands
/// take raw words ([`zether_prover::state`]); their raw forms `decrypt`, `decryptPending` and `raw*` (zether-prover's raw
/// commands, `hazmat`) exist only under the test feature `vectors`: in a release build they are unknown commands
/// (`Argument`, before the key is touched).
pub const COMMANDS: &[&str] = &[
    "encrypt",
    #[cfg(feature = "vectors")]
    "decrypt",
    #[cfg(feature = "vectors")]
    "decryptPending",
    #[cfg(feature = "vectors")]
    "rawCheckBalance",
    #[cfg(feature = "vectors")]
    "rawProveTransfer",
    #[cfg(feature = "vectors")]
    "rawProveTransferMulti",
    #[cfg(feature = "vectors")]
    "rawProveBurn",
    #[cfg(feature = "vectors")]
    "rawOpenMemo",
    #[cfg(feature = "vectors")]
    "rawRecoverTransfer",
    #[cfg(feature = "vectors")]
    "rawOpenDisclosure",
    "pop",
    "ownerAuth",
    "uaSig",
    "shieldCalldata",
    "envelope",
    "typedDigest",
    "namedCall",
    "balance",
    "pendingBalance",
    "checkBalance",
    "proveTransfer",
    "proveTransferMulti",
    "proveBurn",
    "openMemo",
    "recoverTransfer",
    "openDisclosure",
    "pickDecoys",
];

/// The words commands: zether-prover's `state` (its allow-lists, `prepare` before the key, `run` with it).
fn words(cmd: &str) -> bool {
    zether_prover::state::COMMANDS.contains(&cmd)
}

/// zether-prover's `api` name of a raw command (feature `vectors`): `rawX` → `x`.
#[cfg(feature = "vectors")]
fn prover_name(cmd: &str) -> String {
    match cmd.strip_prefix("raw") {
        Some(r) => r.get(..1).map(str::to_lowercase).unwrap_or_default() + r.get(1..).unwrap_or_default(),
        None => cmd.to_string(),
    }
}

/// The allow-list of `cmd`'s top-level fields (the fields zether-prover's `api` reads for it, never `key`, `revealSecret`,
/// `includeWitness`); `curve` where the command is a curve command.
fn allowed(cmd: &str, field: &str) -> bool {
    let has = |l: &[&str]| l.contains(&field);
    if words(cmd) {
        return zether_prover::state::allowed(cmd, field);
    }
    match cmd {
        "encrypt" | "shieldCalldata" => has(&["curve", "Y", "amount"]),
        #[cfg(feature = "vectors")]
        "decrypt" => has(&["curve", "ct", "tableBits", "boundBits", "allowLargeTable"]),
        #[cfg(feature = "vectors")]
        "decryptPending" => has(&["curve", "pending", "tableBits", "boundBits", "allowLargeTable"]),
        #[cfg(feature = "vectors")]
        "rawCheckBalance" => has(&["curve", "acc", "balance"]),
        #[cfg(feature = "vectors")]
        "rawProveTransfer" => has(HEADER) || has(&["curve", "disclosureMode", "yTo", "yAud", "auditorMode", "acc", "balance", "amount"]),
        #[cfg(feature = "vectors")]
        "rawProveTransferMulti" => {
            has(HEADER)
                || has(&[
                    "curve", "disclosureMode", "mode", "recipients", "yAud", "auditorMode", "decoyFee", "minDecoyFee", "uaSigner",
                    "uaSignerGas", "acc", "balance",
                ])
        }
        #[cfg(feature = "vectors")]
        "rawProveBurn" => has(HEADER) || has(&["curve", "amount", "recipient", "acc", "balance"]),
        #[cfg(feature = "vectors")]
        "rawOpenMemo" => has(RECOVERY) || field == "curve",
        #[cfg(feature = "vectors")]
        "rawRecoverTransfer" => has(RECOVERY) || has(&["curve", "tableBits", "boundBits", "yAud"]),
        #[cfg(feature = "vectors")]
        "rawOpenDisclosure" => has(&[
            "curve", "kind", "chainId", "chainUid", "token", "entryRef", "index", "amount", "Yt", "Cout", "Dout", "Ya", "Caud", "Daud",
        ]),
        "pickDecoys" => has(&["candidates", "exclude", "count", "weights"]),
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

/// The shape of a field's value: the holder's sealed balance-cache box `{iv, ct}` (T15l), the ciphertexts `{C, D}`, the legs `[{yTo, amount}]`, the envelope `meta` / `env`, the
/// `unwrap` arguments, the typed `message` (any struct the prover's typed hasher checks field by field, without a `key`
/// anywhere); every other field a [`scalar`].
fn shape(field: &str, x: &Value) -> bool {
    match field {
        "acc" | "ct" | "pending" => flat(x, &["C", "D"]),
        "account" => x.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
        "accountData" | "entryWords" | "memoWords" | "auditorKeyWords" => {
            x.as_array().is_some_and(|a| a.iter().all(|w| flat(w, &["slot", "word"])))
        }
        "blob" => flat(x, &["address", "code"]),
        "cacheBox" => flat(x, &["iv", "ct"]),
        "candidates" | "exclude" => x.as_array().is_some_and(|a| a.iter().all(Value::is_string)),
        "weights" => x.as_array().is_some_and(|a| a.iter().all(Value::is_u64)),
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
        #[cfg(feature = "vectors")]
        KEY_USES.with(|n| n.set(n.get() + 1));
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
        if c.cmd == "pickDecoys" {
            // T15n (CTR-UA-29): the multi-recipient transfer's decoys, by the OS CSPRNG; the key is not used
            return super::decoys::Request::from_map(&c.v)?.pick();
        }
        let v = Value::Object(c.v);
        if words(c.cmd) {
            // the words parsed, checked, bound to this handle's `Y` and rebuilt before the key is touched (ARCH-POS-13)
            let y = decode_point::<Bls12381>(&self.y).map_err(|_| Error::Argument)?;
            let p = zether_prover::state::prepare(c.cmd, &v, &y).map_err(|_| Error::Argument)?;
            return self.with_key(|k| zether_prover::state::run(&p, k, rng).map(|o| o.to_string()).map_err(|_| Error::Argument));
        }
        #[cfg(feature = "vectors")]
        let owned = prover_name(c.cmd);
        #[cfg(feature = "vectors")]
        let name = owned.as_str();
        #[cfg(not(feature = "vectors"))]
        let name = c.cmd;
        self.with_key(|k| zether_prover::api::call_with_key(name, &v, k, rng).map(|o| o.to_string()).map_err(|_| Error::Argument))
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

thread_local! {
    static KEY_USES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Test-only (feature `vectors`): how many times a Zether handle on this thread used its key (every secret operation of a
/// command). A refusal of the words (location, parse, consistency, leg, role) comes before any (spec no-decryption-oracle §5:
/// "key unused").
#[cfg(feature = "vectors")]
pub fn vectors_key_uses() -> usize {
    KEY_USES.with(|n| n.get())
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
