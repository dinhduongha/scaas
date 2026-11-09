// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `pqz` (ua-rs-sign T15; spec §10.2, §8.2, §8.4, §9.3): the PQZ facade over `pqz-core/ffi` (feature `prove`, the Rust
//! PQZL backend; PQZH where the set has it). One parameter set per build (`pqz-set-<set>` → pqz-ffi `set-<set>`).
//!
//! - **Key.** [`crate::wallet::Wallet::pqz_key`]: `seed32 = HKDF-SHA256(seed, "scaas.ua.pq.v1", utf8("scaas.ua.pqz-mlwe.v1") ‖
//!   be32(account) ‖ be32(index))` (CTR-PQZ-13), key version v ≥ 1 with `‖ be64(v)` ([`crate::wallet::Wallet::pqz_key_version`],
//!   group 3g C8) into the wallet's arena; the handle holds the store, its generation and the slot
//!   (no secret bytes) and the public `pk`. Every secret operation rebuilds `s`, `e` by `pqzl::keygen(seed32)` under the store's
//!   read guard (wiped on drop), so `lock()` revokes the handle (`KeyRevoked`, for good; spec §8.2).
//!   [`crate::wallet::Wallet::export_pqz_leaf_raw`] is the one export of `seed32` (marker [`AllowSecretExport`]).
//! - **Set.** [`pqz_set`] names this build's set, `PK` length and `proofSystemId`s; [`check_set`] compares a token's deployed
//!   `PqzSet` with it, and every proving command names the token's `proofSystemId`: another set's is `PqzSetMismatch`.
//! - **No decryption oracle** (ARCH-POS-13, owner 2026-11-06; spec no-decryption-oracle §4.3–§4.6, T15e): a command that
//!   decrypts takes a named location and the **raw** storage words the reading layer read at one block (account struct slots,
//!   pending slots, `acc` slots, SSTORE2 codes, the registry's key record), never a ciphertext, statement, `T`, `p` or parsed
//!   field. The facade alone checks `psid`, parses the words by the pinned layout ([`STATE_LAYOUT`]), checks them (public data
//!   only), binds the selected leg and the role to the handle's registered key, rebuilds `T`, `p`, the entries and the op 5
//!   statement exactly as `PqzCore`, and only then uses the key. Every refusal before that is `Argument` (another set's `psid`:
//!   `PqzSetMismatch`); after it only `KeyRevoked` and, for a debit over the balance, `Argument` to the caller. Whether the words
//!   are real chain state of a catalogued token is the reading layer's duty (R1–R7), not this library's (§4.12).
//! - **Commands** ([`COMMANDS`], [`PqzKey::call`]: `enc`, `proveRegister`, `proveKeyRecord` and the words commands `balance`,
//!   `proveTransfer`, `proveBurn`, `proveRefresh`, `proveTransferMulti`, `auditRead`, `proveDisclose`, `proveDiscloseSender`,
//!   `openMemo`; the raw `dec` and `raw*` commands only under feature `vectors`): named-field JSON (bounded reader, 4 MiB, depth 8), each field on its
//!   command's allow-list (so no `key`, `seed32`, `s`, `e` or witness field passes, at any depth: the only nested objects are
//!   the legs `{pk, ua, amount}`), parsed into typed values. `enc` (`pqzl::enc`), `dec` (`dec` / `dec_win`), the proofs
//!   `proveRegister` / `proveKeyRecord` (op 3 `R_REG` over `pqz_reg_message` / the `setPqzKey` message of the named key
//!   `version`: `UAPqzKey` at 0, `UAPqzKeyVersion` from 1, group 3g), `proveTransfer`
//!   (op 1, `R_TX` / `R_TX0`) and `proveTransferMulti` (op 7), each with an explicit `mode` (owner 2026-11-06; T15b, T15k): `HASH`
//!   with the sender memo `memo::seal` under `seed32` (op 1: op 7's encoding with M = 1, `PqzCore.SEALED` = 42, T36a),
//!   `BUNDLE` without; `proveBurn`, `proveRefresh` (op 2). Every debit carries release 3h's `ownTag` (proof-path spec PP-3, C4:
//!   `HMAC-SHA256(HKDF-SHA256(seed32, "", "PQZ/owntag/v1", 32), chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖
//!   keccak256(P(u) ‖ P(v_f)))`, `u` its `u_0` / `u′`, `P` the stored form, `seed32` the debited version's) in its answer and
//!   `memoHash = keccak256(memo ‖ ownTag)` in its statement (C3; the memo `salt ‖ sealedMemo` on `HASH`, empty on `BUNDLE`,
//!   a burn and a refresh), as the 3h `PqzCore` statements; the pre-3h words are in `legacy/ua-rs-sign/`, never built
//!   (ua-rs-sign T20d2). `proveDiscloseSender` (op 4 of the
//!   sender's own entry: `r, e1, e2_j` re-derived, the amount read from the entry, T15l), `proveDisclose` (op 5, receiver or
//!   auditor), `openMemo`; path (B) `provenOpen`, `provenAdd`, `provenCancel`, `balanceProven` (submodule `proven`). Statements are `pqz-stmt`'s builders, witnesses pqz-ffi's layouts (`fixture::wit_*`), proofs
//!   `pqz_ffi::prove` with `rnd32` from the OS RNG (hedged, CTR-PQZ-19). The debit's balance is `Dec(T)` with the handle's key.
//! - **Encryption randomness** (CTR-PQZ-19): a transfer (op 1, op 7) draws a fresh 16-byte `salt` and encrypts from
//!   `seed_enc = HKDF-SHA256(seed32, "SCAAS-PQZ-ENC-V2", chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt)`, so the
//!   sender re-derives it for `SENDER_S`; burn and refresh encrypt from a fresh OS-RNG seed.
//! - **Balance cache** (as §10.1's box): AES-256-GCM under `HKDF-SHA256(seed32, no salt, "scaas-pqz-balance-cache-v1", 32)`,
//!   AAD `pqz-cache:<set>`, the box `{iv, ct}` in unpadded base64url.
//!
//! Not exposed: the verifiers, the precompile, the self-test, `test-hooks`, `fuzz`, the C core (spec §10). The raw debits
//! (feature `vectors`) take `memoHash` as the vector files give it (pqz-core's statement rows, not a release's formula). The fixed-randomness entry points
//! exist only under feature `vectors`. Residual (spec §8.2): pqz-core's copies of `seed32`, `s`, `e` and the witness on its
//! worker thread and in the prover. UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

use crate::wallet::{aead_open, aead_seal, bounded, from_hex, hkdf_sha256, to_hex, Alg, Error, Handle, KeyId, Result, SecretStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use super::pqz_pack::{unpack, ACC_WORDS, CTP, PKP, VP};
use pqz_ffi::fixture::{wit_debit, wit_ds, wit_key, wit_multi};
use pqz_ffi::pqzl::{self, Key, CT_BYTES, PK_BYTES};
use pqz_ffi::selftest::digits;
use pqz_ffi::stmt::{
    built_legs, check_pk, coeffs_ok, legs_per_group, u64_word, Debit, Disclose, Form, Multi, Register, Stmt, Word, DELTA,
    DISC_WORDS, DW_AMOUNT, H_AMOUNT, H_BENEFICIARY, H_CHAIN_ID, H_CHAIN_UID, H_ENVELOPE, H_FEE, H_FROM, H_MEMO_HASH, H_PLAIN_USED, H_P,
    H_RECIPIENT, H_RECIPIENTS_HASH, H_REGISTRY, H_SALT, H_SEND_COUNTER, H_TO, H_TOKEN, H_VALID_UNTIL, K_MAX, PQZH_ID, PQZL_ID, Q,
};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::sync::Arc;
use subtle::{Choice, ConstantTimeEq, ConstantTimeLess};
// ARCH-POS-13 (Fable P3-3, T15c2): what only the raw commands use (`dec`, the `raw*` commands) compiles only under the test
// feature `vectors`, so a release build cannot construct `Req::Dec` or a request from a caller's `T`, statement or memo.
#[cfg(feature = "vectors")]
use pqz_ffi::stmt::{check_ct, parse};
use zeroize::{Zeroize, Zeroizing};

/// Path (B), the proof path (no-oracle spec §4.14; T20d4).
mod proven;

// one parameter set per build (owner 2026-10-21): pqz-stmt refuses two, and silently takes n2048-kmax1024 for none
const _: () = assert!(
    crate::build::PQZ_SETS[0] as u8 + crate::build::PQZ_SETS[1] as u8 + crate::build::PQZ_SETS[2] as u8 + crate::build::PQZ_SETS[3] as u8
        == 1,
    "feature pqz needs exactly one pqz-set-<set> feature"
);

/// The PQZ key's tag (CTR-PQZ-13): `utf8` in the HKDF info, as every PQ seed.
pub const TAG: &str = "scaas.ua.pqz-mlwe.v1";
/// The command JSON's caps (spec §9.3; T15e: 4 MiB, not 1 MiB, for the raw words of a debit: up to `INLINE_MAX` pending blobs
/// of an audited 8-leg op 7, the `acc` blob or slots and the key's code, in hex, at `n2816-kmax65536` ≈ 2.3 MiB).
pub const CMD_MAX: usize = 4 << 20;
pub const CMD_DEPTH: usize = 8;
/// The balance-cache box JSON's caps: `{iv, ct}` of a plaintext up to [`crate::wallet::MAX_PT`] (1 MiB) in base64url.
pub const BOX_MAX: usize = 2 << 20;
pub const BOX_DEPTH: usize = 1;
/// The longest answer of [`PqzKey::call`]: a statement and its proof fit in the precompile's `MAX_INPUT` (in hex: twice),
/// plus the memo (at most 18 + 40·8 bytes), a debit's `ownTag` (32), the `R_REG` message and the JSON. A proof's length varies from build to build
/// (rejection sampling), so a caller sizes its buffer by this bound, never by an earlier answer.
pub const OUT_MAX: usize = 2 * pqz_ffi::MAX_INPUT + 4096;
/// The set-description JSON's caps ([`PqzSet::from_json`]).
pub const SET_MAX: usize = 1024;
const CACHE_INFO: &[u8] = b"scaas-pqz-balance-cache-v1";
/// CTR-PQZ-19's HKDF salt of a transfer's `seed_enc`.
const ENC_SALT: &[u8] = b"SCAAS-PQZ-ENC-V2";

/// The explicit opt-in of [`crate::wallet::Wallet::export_pqz_leaf_raw`] (spec §8.4: the raw-digest treatment).
#[derive(Clone, Copy, Debug)]
pub struct AllowSecretExport;

/// A parameter set as a token deploys it: name, `PK` length, `proofSystemId`s (PQZH's `None` at a set without PQZH).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqzSet {
    pub name: String,
    pub pk_len: usize,
    pub pqzl_id: [u8; 32],
    pub pqzh_id: Option<[u8; 32]>,
}

impl PqzSet {
    /// `{"set", "pkLen", "pqzlId", "pqzhId"}` (ids `0x` hex, `pqzhId` null without PQZH).
    pub fn to_json(&self) -> String {
        json!({"set": self.name, "pkLen": self.pk_len, "pqzlId": to_hex(&self.pqzl_id), "pqzhId": self.pqzh_id.map(|i| to_hex(&i))})
            .to_string()
    }
    /// [`PqzSet::to_json`] back (at most [`SET_MAX`] bytes, depth 1, exactly those four fields), else `Argument`.
    pub fn from_json(json: &[u8]) -> Result<PqzSet> {
        let Value::Object(o) = bounded::json(json, SET_MAX, 1)? else { return Err(Error::Argument) };
        let f = Fields::new(&o, &["set", "pkLen", "pqzlId", "pqzhId"])?;
        let name = o.get("set").and_then(Value::as_str).ok_or(Error::Argument)?.to_string();
        let pk_len = usize::try_from(f.u64("pkLen")?).map_err(|_| Error::Argument)?;
        let pqzh_id = match o.get("pqzhId") {
            Some(Value::Null) => None,
            _ => Some(f.word("pqzhId")?),
        };
        Ok(PqzSet { name, pk_len, pqzl_id: f.word("pqzlId")?, pqzh_id })
    }
}

/// This build's parameter set.
pub fn pqz_set() -> PqzSet {
    PqzSet {
        name: pqz_ffi::stmt::SET.to_string(),
        pk_len: PK_BYTES,
        pqzl_id: PQZL_ID,
        pqzh_id: pqz_ffi::PQZH.then_some(PQZH_ID),
    }
}

/// `Ok` if `deployed` (a token's `PqzSet`) is this build's set, else `PqzSetMismatch`.
pub fn check_set(deployed: &PqzSet) -> Result<()> {
    if *deployed == pqz_set() {
        Ok(())
    } else {
        Err(Error::PqzSetMismatch)
    }
}

/// `id` if it is one of this build's `proofSystemId`s, else `PqzSetMismatch`.
fn system(id: &Word) -> Result<Word> {
    if *id == PQZL_ID || (pqz_ffi::PQZH && *id == PQZH_ID) {
        Ok(*id)
    } else {
        Err(Error::PqzSetMismatch)
    }
}

/// A statement's `proofSystemId` word (bytes 32..64), checked by [`system`] before the statement is parsed (pqz-stmt refuses
/// every id it does not know as a malformed statement).
#[cfg(feature = "vectors")]
fn stmt_id(stmt: &[u8]) -> Result<Word> {
    system(&stmt.get(32..64).and_then(|w| w.try_into().ok()).ok_or(Error::Argument)?)
}

/// `pqzl::enc` to `pks` (each `PK` bytes, canonical) of `values` (one each), from a fresh OS-RNG seed: `u` and one `v` per
/// recipient. Public data only (the randomness is dropped).
pub fn enc(pks: &[Vec<u8>], values: &[u64]) -> Result<(Vec<u8>, Vec<Vec<u8>>)> {
    if pks.is_empty() || pks.len() != values.len() {
        return Err(Error::Argument);
    }
    let pks: Vec<&[u8; PK_BYTES]> = pks.iter().map(|p| pk_ref(p)).collect::<Result<_>>()?;
    let msgs: Vec<[u8; 16]> = values.iter().map(|&v| digits(v)).collect();
    let c = Wiped(pqzl::enc(&pks, &msgs, &os32()?).ok_or(Error::Argument)?);
    Ok((c.0.u.to_vec(), c.0.vs.iter().map(|v| v.to_vec()).collect()))
}

/// The commands of [`PqzKey::call`], in this order (the fuzz target `pqz_cmd`, built with `vectors`, names them by index).
///
/// ARCH-POS-13 ("never a decryption oracle", owner 2026-11-06; spec no-decryption-oracle §4.3–§4.6, T15c, T15e): no command of
/// a release build decrypts or opens a ciphertext, statement or `T` its caller chose. The decrypting commands take a named
/// location and raw storage words and rebuild every ciphertext themselves (the words to read: [`STATE_LAYOUT`] and each
/// command's line below). The raw forms, `dec` and the `raw*` commands (the vector files' `T`, statements and memos), exist only
/// under the test feature `vectors`; in a release build they are unknown commands (`Argument`, before the key is touched), and
/// their parsers do not compile (Fable P3-3, T15c2). `enc` is public, `proveRegister` and `proveKeyRecord` prove the own key.
/// `rawProveDiscloseSender` (the op 4 statement form, a caller's statement and amount: an equality test on the holder's sent
/// amounts, Fable P2-1) exists only under `vectors` too; `proveDiscloseSender` takes the entry's words (T15l).
///
/// The words commands, each `{chainUid, token, block, psid, blobs, keyRecord, …}` (+ the fields of its line):
/// - `balance {ua, account, pending, accWords, sendCounterWord, keyVersion, keyVersions, forOp7}` → `{value, p, sendCounter}`
///   (the holder's own balance of key version `keyVersion` at the `p` a debit would use: `forOp7` true for an op 7, whose
///   inline window on a PQZH token is `INLINE_MAX_PQZH`, false for op 1 / op 2);
/// - `proveTransfer {…balance, chainId, registry, beneficiaryUA?, fee, validUntilBlock, shieldIn, envelopeBinding, toUA, pkT,
///   pkA?, amount, mode}`, `proveBurn {…, amount, recipient}`, `proveRefresh {…}`,
///   `proveTransferMulti {…, legs, pkA?, mode}` → `{stmt, proof, p, ownTag}` (+ `memo` on `HASH`; `ownTag` the debit's 3h tag, the
///   typed args' `ownTag`): `T`, `p` and `sendCounter` from the words;
///   group 3g's rules (KV-8, KV-9; T15o) before any key use: a debit names its `keyVersion`, at most the registry's `current`; a
///   stale one (below `current`) only migrates (`proveTransfer` with `toUA` the debited UA, `pkT` its current key) or refreshes
///   (`proveRefresh`); `toUA` equal to the debited UA at the current version is the contract's `SelfTransfer`; every key a
///   statement names (`pk_f`, `pkT` or each leg's `pk`, `pkA`) differs from the others (the contract's `KeyReused`: one
///   randomness under one key twice would cancel the masks, and a reverted transaction's calldata is public too);
/// - `auditRead {chainId, entryRef, fromUA, sendCounter, entryPtr, leg, auditorMode, auditorUA}` on the auditor's handle → `{amount}`;
/// - `proveDisclose {chainId, registry, entryRef, fromUA, sendCounter, entryPtr, leg, kind, [auditorMode, auditorUA]}`, `kind`
///   `RECEIVER_X` (the leg's owner's handle) or `AUDITOR` (the auditor's) → `{stmt, proof, amount}` (op 5);
/// - `proveDiscloseSender {chainId, registry, entryRef, fromUA, sendCounter, entryPtr, leg, legKeyRecords}` on the sender's handle
///   (`keyRecord` `fromUA`'s at the handle's version, `legKeyRecords` the registry's `pqzKey[UA_j][x]` of each version x the
///   leg may be under, 1 to 64, each code in `blobs`) → `{stmt, proof, amount, legKey}`, `legKey` the index in
///   `legKeyRecords` of the leg's version. Group 3g's additive recovery (KV-11, T15o): the entry's `u` must be this handle's
///   re-derivation (else `Argument` before any leg is tried: another version of the sender, try the next), then each listed
///   key is tried on its own, so a sender with `n` versions and a leg UA with `m` costs `n + m` tries, never `n · m`
///   (op 4 `SENDER_S`, the amount the entry's own);
/// - `openMemo {chainId, entryRef, fromUA, sendCounter, entryPtr, memo}` on the sender's handle → `{auditorOn, legs}`;
/// - `pickDecoys {candidates, exclude, count, weights?, recipient?}` → `{decoys}`, with `recipient` `{decoys, legs}` (`legs` the
///   shuffled leg order to use) (T15n, CTR-UA-29: [`super::decoys`]; op 7's decoy legs; the handle's key is not used).
///
/// Path (B), the proof path of release 3h (no-oracle spec §4.14, T20d4: `proven`), one session per handle:
/// - `provenOpen {…balance, chainId, registry, auditorUA, lastRecord?}` (`lastRecord` `{w0, w1}` of `debitRec[ua][lastDebit −
///   1]`, absent exactly when `lastDebit = 0`; `pending` exactly `[p_last, p)`; `blobs` the key's and `accBlob`'s codes) →
///   `{session, p, sendCounter, need}`: the own `v_f` checked by its `ownTag` (`K_v` from the seed, never `s`);
/// - `provenAdd {session, blobs, credits}` (each credit `{index, fromUA, sendCounter, form, record, senderPending?,
///   keyRecords?, proof?, header? | call?}`, the codes once per request) → `{accepted, refused}`: each credit checked on its own,
///   keyless (P over the rebuilt statement with the handle's `pk` at its leg, a migration credit by re-encryption, else by P);
/// - `provenCancel {session}` → `{}`; `balanceProven {session}` → `{value, p, sendCounter, parts}` once every `need` index is
///   accepted (the key's one use).
pub const COMMANDS: &[&str] = &[
    "enc",
    #[cfg(feature = "vectors")]
    "dec",
    "proveRegister",
    "proveKeyRecord",
    #[cfg(feature = "vectors")]
    "rawProveTransfer",
    #[cfg(feature = "vectors")]
    "rawProveBurn",
    #[cfg(feature = "vectors")]
    "rawProveRefresh",
    #[cfg(feature = "vectors")]
    "rawProveTransferMulti",
    "proveDiscloseSender",
    #[cfg(feature = "vectors")]
    "rawProveDisclose",
    #[cfg(feature = "vectors")]
    "rawOpenMemo",
    "balance",
    "proveTransfer",
    "proveBurn",
    "proveRefresh",
    "proveTransferMulti",
    "auditRead",
    "proveDisclose",
    "openMemo",
    #[cfg(feature = "vectors")]
    "rawProveDiscloseSender",
    "pickDecoys",
    "provenOpen",
    "provenAdd",
    "provenCancel",
    "balanceProven",
];

/// The storage layout the words commands parse (`ua-mtx-merge`, `PqzCore.Account` / `PqzStorage` in the ERC-7201 namespace
/// `scaas.pqz`, pinned by T19c in `test/v2/layout/namespaces.json`, moved by group 3g T52; `tests/facade_pqz_state.rs` compares
/// this table with the pin the forge rows carry): `(label, slot, inner, byte, width)`, `slot` in the namespace, `inner` the slot
/// inside `acct[ua][v]`, `byte` counted from the low end of the word (solc's packing). Group 3g (KV-6): the account is keyed
/// `(ua, key version)`, `sendCounter` is one per UA. Group 3h (T58, PP-2): `lastDebit` in the account's slot 2, so `accHash`,
/// `pending` and `accWords` sit one slot later; tokens of release 3h only (no-oracle spec §4.14.1, owner 2026-11-09: the reading
/// layer refuses an earlier release by name). The reading layer reads, at one block, for key version `v`:
/// - `account`: `acct[ua][v]` slots `inner` 0 to 3 (`acct = keccak256(v ‖ keccak256(ua ‖ root + 8))`, then `+ inner`), in order;
/// - `pending`: `{index, word}` for every index in `[rolled, p)`, `p = min(pendingCount, rolled + INLINE_MAX, rolled + K_MAX − 1 −
///   accUnits)` (`INLINE_MAX` 16, 10 for op 7 of a PQZH token; CTR-PQZ-06), the word at `keccak256(index ‖ acct + 4)`:
///   `blob(160) ‖ uOff(16) ‖ vOff(16) ‖ block(64)` (`PqzCore._credit`);
/// - `accWords`: with `flags & 1` the `ACC_WORDS` slots from `acct + 5` as stored (`not()` of the packed stream), else none;
/// - `sendCounterWord`: `sendCounter[ua]` (slot 12, `keccak256(ua ‖ root + 12)`), the UA's, advanced by a debit of any version;
/// - `blobs`: `{address, code}` by `eth_getCode` of every SSTORE2 pointer used: the `acc` reference's (without `flags & 1`),
///   each pending credit's, the entry's (`entryPtr`) and the key's;
/// - `keyRecord`: the registry's `pqzKey[ua][v]` word (`UAStore.Layout` slot 2, per version: `keccak256(v ‖ keccak256(ua ‖ 2))`,
///   `ptr(160) ‖ proven(8) ‖ added(8)`), the holder's; `keyVersions`: the registry's `pqzVersions[ua]` (slot 17,
///   `keccak256(ua ‖ 17)`: `latest(64) ‖ current(64) ‖ listed(8)`); `keyVersion` the `v` read;
/// - `psid`: slot 2; `auditorMode`: slot 0 (`pqz(160) ‖ disclosureMode(8) ‖ auditorMode(8)`); `auditorUA`: slot 7;
///   `entryPtr`: `entryPtr[entryRef]` (slot 9); `memo`: the bytes of `memos[entryRef]` (slot 10).
pub const STATE_LAYOUT: &[(&str, u64, u64, usize, usize)] = &[
    ("disclosureMode", 0, 0, 20, 1),
    ("auditorMode", 0, 0, 21, 1),
    ("psid", 2, 0, 0, 32),
    ("auditorUA", 7, 0, 0, 32),
    ("acct[U][7].pendingCount", 8, 0, 0, 8),
    ("acct[U][7].rolled", 8, 0, 8, 8),
    ("acct[U][7].floor", 8, 0, 16, 8),
    ("acct[U][7].cleared", 8, 0, 24, 8),
    ("acct[U][7].accBlob", 8, 1, 0, 20),
    ("acct[U][7].accU", 8, 1, 20, 2),
    ("acct[U][7].accV", 8, 1, 22, 2),
    ("acct[U][7].accUnits", 8, 1, 24, 4),
    ("acct[U][7].flags", 8, 1, 28, 1),
    ("acct[U][7].lastDebit", 8, 2, 0, 8),
    ("acct[U][7].accHash", 8, 3, 0, 32),
    ("acct[U][7].pending[3]", 8, 4, 0, 32),
    ("acct[U][7].accWords[0]", 8, 5, 0, 32),
    ("entryPtr[V]", 9, 0, 0, 20),
    ("memos[V]", 10, 0, 0, 32),
    ("sendCounter[U]", 12, 0, 0, 8),
];

/// `PqzCore.INLINE_MAX`, `INLINE_MAX_PQZH` (op 7 of a PQZH token), the `MAT` flag (`acc` in `accWords`).
const INLINE_MAX: u64 = 16;
const INLINE_MAX_PQZH: u64 = 10;
const MAT: u8 = 1;

/// `proveDiscloseSender`'s `legKeyRecords`: at most this many versions of the leg's owner, tried in order.
const LEG_KEYS_MAX: usize = 64;
/// The location fields every words command takes.
const LOC: &[&str] = &["chainUid", "token", "block", "psid", "blobs", "keyRecord"];
/// An account's words and a debit's caller fields (the facade sets opTag, the id, `auditorOn`, `salt`, `p`, `sendCounter`).
const ACCT: &[&str] = &["ua", "account", "pending", "accWords", "sendCounterWord", "keyVersion", "keyVersions"];
const DEBIT: &[&str] = &["chainId", "registry", "beneficiaryUA", "fee", "validUntilBlock", "shieldIn", "envelopeBinding"];
/// An old entry's location.
const ENTRY: &[&str] = &["chainId", "entryRef", "fromUA", "sendCounter", "entryPtr"];
/// The raw debits' header fields (feature `vectors`: the vector files give `T` and `p`).
#[cfg(feature = "vectors")]
const HEADER: &[&str] =
    &["chainId", "token", "registry", "fromUA", "beneficiaryUA", "fee", "sendCounter", "p", "validUntilBlock", "plainUsed", "chainUid", "envelopeBinding"];
const LEG: &[&str] = &["pk", "ua", "amount"];

/// The allow-list of `cmd`'s fields.
fn allowed(cmd: &str, field: &str) -> bool {
    let has = |l: &[&str]| l.contains(&field);
    let debit = |l: &[&str]| has(LOC) || has(ACCT) || has(DEBIT) || has(l);
    match cmd {
        "enc" => has(&["pks", "values"]),
        #[cfg(feature = "vectors")]
        "dec" => has(&["ct", "window"]),
        "proveRegister" => has(&["proofSystemId", "kind", "ua", "kemPk"]),
        "proveKeyRecord" => has(&["proofSystemId", "ua", "version"]),
        #[cfg(feature = "vectors")]
        "rawProveTransfer" => has(HEADER) || has(&["proofSystemId", "toUA", "pkT", "pkA", "T", "amount", "memoHash"]),
        #[cfg(feature = "vectors")]
        "rawProveBurn" => has(HEADER) || has(&["proofSystemId", "amount", "recipient", "T", "memoHash"]),
        #[cfg(feature = "vectors")]
        "rawProveRefresh" => has(HEADER) || has(&["proofSystemId", "T", "memoHash"]),
        #[cfg(feature = "vectors")]
        "rawProveTransferMulti" => has(HEADER) || has(&["proofSystemId", "legs", "pkA", "T", "mode", "memoHash"]),
        #[cfg(feature = "vectors")]
        "rawProveDiscloseSender" => has(&["stmt", "fromUA", "sendCounter", "salt", "auditorOn", "M", "leg"]),
        "proveDiscloseSender" => has(LOC) || has(ENTRY) || has(&["registry", "leg", "legKeyRecords"]),
        #[cfg(feature = "vectors")]
        "rawProveDisclose" => field == "stmt",
        #[cfg(feature = "vectors")]
        "rawOpenMemo" => has(&["chainUid", "token", "fromUA", "sendCounter", "memo"]),
        "balance" => has(LOC) || has(ACCT) || field == "forOp7",
        "proveTransfer" => debit(&["toUA", "pkT", "pkA", "amount", "mode"]),
        "proveBurn" => debit(&["amount", "recipient"]),
        "proveRefresh" => debit(&[]),
        "proveTransferMulti" => debit(&["legs", "pkA", "mode"]),
        "auditRead" => has(LOC) || has(ENTRY) || has(&["ua", "leg", "auditorMode", "auditorUA"]),
        "proveDisclose" => has(LOC) || has(ENTRY) || has(&["ua", "registry", "leg", "kind", "auditorMode", "auditorUA"]),
        "openMemo" => has(LOC) || has(ENTRY) || field == "memo",
        "pickDecoys" => has(&["candidates", "exclude", "count", "weights", "recipient"]),
        "provenOpen" => has(LOC) || has(ACCT) || has(&["forOp7", "lastRecord", "auditorUA", "chainId", "registry"]),
        "provenAdd" => has(&["session", "blobs", "credits"]),
        "provenCancel" | "balanceProven" => field == "session",
        _ => false,
    }
}

/// An object's fields, each on `list`, read by name and type.
struct Fields<'a>(&'a Map<String, Value>);

impl<'a> Fields<'a> {
    fn new(o: &'a Map<String, Value>, list: &[&str]) -> Result<Fields<'a>> {
        if o.keys().all(|k| list.contains(&k.as_str())) {
            Ok(Fields(o))
        } else {
            Err(Error::Argument)
        }
    }
    fn get(&self, k: &str) -> Result<&'a Value> {
        self.0.get(k).ok_or(Error::Argument)
    }
    fn has(&self, k: &str) -> bool {
        self.0.contains_key(k)
    }
    fn u64(&self, k: &str) -> Result<u64> {
        self.get(k)?.as_u64().ok_or(Error::Argument)
    }
    fn bytes(&self, k: &str) -> Result<Vec<u8>> {
        hex(self.get(k)?)
    }
    fn arr<const L: usize>(&self, k: &str) -> Result<[u8; L]> {
        self.bytes(k)?.try_into().map_err(|_| Error::Argument)
    }
    fn word(&self, k: &str) -> Result<Word> {
        self.arr(k)
    }
    fn opt_word(&self, k: &str) -> Result<Word> {
        if self.has(k) {
            self.word(k)
        } else {
            Ok([0; 32])
        }
    }
    fn list(&self, k: &str) -> Result<&'a Vec<Value>> {
        self.get(k)?.as_array().ok_or(Error::Argument)
    }
    /// An array of 32-byte words.
    fn words(&self, k: &str) -> Result<Vec<Word>> {
        self.list(k)?.iter().map(|w| hex(w)?.try_into().map_err(|_| Error::Argument)).collect()
    }
    fn pk(&self, k: &str) -> Result<Vec<u8>> {
        pk(hex(self.get(k)?)?)
    }
    fn opt_pk(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.has(k).then(|| self.pk(k)).transpose()
    }
    #[cfg(feature = "vectors")]
    fn ct(&self, k: &str) -> Result<Vec<u8>> {
        let b = self.bytes(k)?;
        check_ct(&b).map_err(|_| Error::Argument)?;
        Ok(b)
    }
    #[cfg(feature = "vectors")]
    fn header(&self) -> Result<Header> {
        Ok(Header {
            chain_id: self.u64("chainId")?,
            token: self.arr("token")?,
            registry: self.arr("registry")?,
            from_ua: self.word("fromUA")?,
            beneficiary_ua: self.opt_word("beneficiaryUA")?,
            fee: self.u64("fee")?,
            send_counter: self.u64("sendCounter")?,
            p: self.u64("p")?,
            valid_until_block: self.u64("validUntilBlock")?,
            plain_used: self.u64("plainUsed")?,
            chain_uid: self.word("chainUid")?,
            envelope_binding: self.word("envelopeBinding")?,
        })
    }
    fn id(&self) -> Result<Word> {
        system(&self.word("proofSystemId")?)
    }
    /// The op 7 legs `{pk, ua, amount}`.
    fn legs(&self) -> Result<Vec<(Vec<u8>, Word, u64)>> {
        self.list("legs")?
            .iter()
            .map(|l| {
                let l = Fields::new(l.as_object().ok_or(Error::Argument)?, LEG)?;
                Ok((l.pk("pk")?, l.word("ua")?, l.u64("amount")?))
            })
            .collect()
    }
    /// Op 7's `mode`, no default.
    fn mode(&self) -> Result<Mode> {
        match self.get("mode")?.as_str() {
            Some("HASH") => Ok(Mode::Hash),
            Some("BUNDLE") => Ok(Mode::Bundle),
            _ => Err(Error::Argument),
        }
    }
}

fn hex(v: &Value) -> Result<Vec<u8>> {
    v.as_str().and_then(from_hex).ok_or(Error::Argument)
}

fn pk(b: Vec<u8>) -> Result<Vec<u8>> {
    check_pk(&b).map_err(|_| Error::Argument)?;
    Ok(b)
}

fn pk_ref(b: &[u8]) -> Result<&[u8; PK_BYTES]> {
    b.try_into().map_err(|_| Error::Argument)
}

/// The debit header words a caller gives.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Header {
    chain_id: u64,
    token: [u8; 20],
    registry: [u8; 20],
    from_ua: Word,
    beneficiary_ua: Word,
    fee: u64,
    send_counter: u64,
    p: u64,
    valid_until_block: u64,
    plain_used: u64,
    chain_uid: Word,
    envelope_binding: Word,
}

fn addr(a: &[u8; 20]) -> Word {
    let mut w = [0u8; 32];
    w.iter_mut().skip(12).zip(a).for_each(|(o, b)| *o = *b);
    w
}

impl Header {
    /// `h` (opTag, id, auditorOn, `M` already set) with the given words.
    fn fill(&self, mut h: [Word; 20]) -> [Word; 20] {
        for (i, w) in [
            (H_CHAIN_ID, u64_word(self.chain_id)),
            (H_TOKEN, addr(&self.token)),
            (H_REGISTRY, addr(&self.registry)),
            (H_FROM, self.from_ua),
            (H_BENEFICIARY, self.beneficiary_ua),
            (H_FEE, u64_word(self.fee)),
            (H_SEND_COUNTER, u64_word(self.send_counter)),
            (H_P, u64_word(self.p)),
            (H_VALID_UNTIL, u64_word(self.valid_until_block)),
            (H_PLAIN_USED, u64_word(self.plain_used)),
            (H_CHAIN_UID, self.chain_uid),
            (H_ENVELOPE, self.envelope_binding),
        ] {
            if let Some(x) = h.get_mut(i) {
                *x = w;
            }
        }
        h
    }
}

/// Op 7's storage mode (`ZetherTypes.TransferMode`, a named request field with no default; owner 2026-11-06): `HASH`
/// (commit-reveal) keeps the sender memo, `memoHash = keccak256(salt ‖ sealedMemo ‖ ownTag)`; `BUNDLE` has no memo,
/// `memoHash = keccak256(ownTag)` (release 3h, `PqzCore._parseMulti`).
/// The token's `disclosureMode` decides which one a caller may use; the facade does not guess it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Hash,
    Bundle,
}

// ------------------------------------------------------------------------------------------------------------------------------
// Raw words → ciphertexts (spec no-decryption-oracle §4.3, §4.4): public data only, before any key use; every refusal `Argument`.
// ------------------------------------------------------------------------------------------------------------------------------

/// `n` bytes of a storage word from byte `at` counted from its low end (solc's packing).
fn lo(w: &Word, at: usize, n: usize) -> Result<&[u8]> {
    w.get(32 - at - n..32 - at).ok_or(Error::Argument)
}

fn lo_u64(w: &Word, at: usize, n: usize) -> Result<u64> {
    Ok(lo(w, at, n)?.iter().fold(0u64, |a, b| a << 8 | u64::from(*b)))
}

fn lo_addr(w: &Word, at: usize) -> Result<[u8; 20]> {
    lo(w, at, 20)?.try_into().map_err(|_| Error::Argument)
}

/// Every byte of `w` above the low `used` bytes is zero (nothing else is packed there).
fn only_low(w: &Word, used: usize) -> Result<()> {
    w.get(..32 - used).filter(|h| h.iter().all(|b| *b == 0)).map(|_| ()).ok_or(Error::Argument)
}

/// The SSTORE2 codes of one request (`{address, code}`, each address once); [`Blobs::done`] refuses one that was not used.
struct Blobs(Vec<([u8; 20], Vec<u8>, bool)>);

impl Blobs {
    fn new(f: &Fields<'_>) -> Result<Blobs> {
        let mut v: Vec<([u8; 20], Vec<u8>, bool)> = Vec::new();
        for b in f.list("blobs")? {
            let b = Fields::new(b.as_object().ok_or(Error::Argument)?, &["address", "code"])?;
            let a: [u8; 20] = b.arr("address")?;
            if v.iter().any(|x| x.0 == a) {
                return Err(Error::Argument);
            }
            v.push((a, b.bytes("code")?, false));
        }
        Ok(Blobs(v))
    }
    /// The data of the SSTORE2 code at `a` (after its STOP byte).
    fn data(&mut self, a: &[u8; 20]) -> Result<&[u8]> {
        let b = self.0.iter_mut().find(|x| x.0 == *a && *a != [0; 20]).ok_or(Error::Argument)?;
        b.2 = true;
        match b.1.split_first() {
            Some((0, d)) => Ok(d),
            _ => Err(Error::Argument),
        }
    }
    fn done(&self) -> Result<()> {
        if self.0.iter().all(|x| x.2) {
            Ok(())
        } else {
            Err(Error::Argument)
        }
    }
}

/// The registered PQZ key of the holder whose registry word `pqzKey[ua]` is `record` (`ptr ‖ proven ‖ added`): proven, its
/// code `0x00 ‖ pk` of this set's length (`PqzCore._keyPtr`). The caller compares it with the handle's key before any use.
fn registered_key(record: &Word, blobs: &mut Blobs) -> Result<Vec<u8>> {
    only_low(record, 22)?;
    let (ptr, proven, added) = (lo_addr(record, 0)?, lo_u64(record, 20, 1)?, lo_u64(record, 21, 1)?);
    if proven != 1 || added > 1 {
        return Err(Error::Argument);
    }
    pk(blobs.data(&ptr)?.to_vec())
}

/// `u ‖ v` (64-bit lanes) of a stored entry: the packed `u` at byte `u_off`, `v` at `v_off` of the data (`PqzCt.loadBlob`); an
/// offset outside the data is refused (the contract would read zeros past the code).
fn load(d: &[u8], u_off: usize, v_off: usize) -> Result<Vec<u8>> {
    let part = |o: usize, n: usize| d.get(o..o.checked_add(n)?).and_then(unpack);
    Ok([part(u_off, PKP).ok_or(Error::Argument)?, part(v_off, VP).ok_or(Error::Argument)?].concat())
}

/// `c += x` lane-wise (`x` 64-bit lanes); the sums stay below 2^64 (at most `INLINE_MAX + 2` terms `< q < 2^54`).
fn add(c: &mut [u64], x: &[u8]) {
    c.iter_mut().zip(x.chunks_exact(8)).for_each(|(a, b)| *a += b.iter().fold(0u64, |s, y| s << 8 | u64::from(*y)));
}

/// `c += Trivial(digits(amount))`: `v[i] += Δ·digit_i` (`PqzCt.addTrivial`).
fn add_trivial(c: &mut [u64], amount: u64) {
    let delta = DELTA.unsigned_abs();
    c.iter_mut().skip(PK_BYTES / 8).take(16).enumerate().for_each(|(i, a)| *a += delta * ((amount >> (4 * i)) & 15));
}

/// The account struct `acct[ua][v]` (`PqzCore.Account`, slots 0..3 as pinned) and the UA's `sendCounter[ua]` word.
struct Acct {
    count: u64,
    rolled: u64,
    floor: u64,
    cleared: u64,
    acc_blob: [u8; 20],
    acc_u: usize,
    acc_v: usize,
    units: u64,
    flags: u8,
    send_counter: u64,
    acc_hash: Word,
    last_debit: u64,
}

/// The 4 slots of `acct[ua][v]` (3h): the counters, the `acc` reference, `lastDebit` (a `uint64`: path (A) does not use it, the
/// proof path does) and `accHash`.
fn acct(w: &[Word], counter: &Word) -> Result<Acct> {
    let [s0, s1, last_debit, s2] = w else { return Err(Error::Argument) };
    only_low(s1, 29)?;
    only_low(last_debit, 8)?;
    only_low(counter, 8)?;
    Ok(Acct {
        count: lo_u64(s0, 0, 8)?,
        rolled: lo_u64(s0, 8, 8)?,
        floor: lo_u64(s0, 16, 8)?,
        cleared: lo_u64(s0, 24, 8)?,
        acc_blob: lo_addr(s1, 0)?,
        acc_u: lo_u64(s1, 20, 2)? as usize,
        acc_v: lo_u64(s1, 22, 2)? as usize,
        units: lo_u64(s1, 24, 4)?,
        flags: lo_u64(s1, 28, 1)? as u8,
        send_counter: lo_u64(counter, 0, 8)?,
        acc_hash: *s2,
        last_debit: lo_u64(last_debit, 0, 8)?,
    })
}

/// Group 3g (KV-3, KV-8): the request's `keyVersion` and the registry's `pqzVersions[ua]` word `keyVersions` (`latest(64) ‖
/// current(64) ‖ listed(8)`): `current ≤ latest`, `listed` a bool, and `keyVersion ≤ current` (a version above current holds no
/// credited state, the contract's `KeyVersionUnknown`); whether `keyVersion` is stale (below `current`).
fn stale(f: &Fields<'_>) -> Result<bool> {
    let (v, w) = (f.u64("keyVersion")?, f.word("keyVersions")?);
    only_low(&w, 17)?;
    let (latest, current) = (lo_u64(&w, 0, 8)?, lo_u64(&w, 8, 8)?);
    if lo_u64(&w, 16, 1)? > 1 || current > latest || v > current {
        return Err(Error::Argument);
    }
    Ok(v < current)
}

/// The contract's `KeyReused` (group 3g KV-9, Codex #1): the keys a statement names are pairwise distinct, else `Argument`.
fn distinct(keys: &[&[u8]]) -> Result<()> {
    if keys.iter().enumerate().any(|(i, a)| keys.iter().skip(i + 1).any(|b| a == b)) {
        return Err(Error::Argument);
    }
    Ok(())
}

/// `ua`'s own account from its raw words: the rebuilt `T` (`T = acc + Σ pending[rolled, p) + Trivial(shieldIn)`, reduced, as
/// `PqzCore._total` with `p ≥ rolled`), the `p` the facade chooses (CTR-PQZ-06: `pendingCount` or the largest `p` the inline
/// window and `K_MAX` allow; never from the request), the UA's `sendCounter`, the version's registered key and whether the
/// version is stale ([`stale`]).
struct Own {
    t: Vec<u8>,
    p: u64,
    send_counter: u64,
    key: Vec<u8>,
    stale: bool,
}

/// [`Own`] of a request (`psid` first, then the words); `op7`: op 7 (its PQZH inline window); `debit`: a debit's
/// `Trivial(shieldIn)` term.
fn own(f: &Fields<'_>, op7: bool, debit: bool) -> Result<(Word, Own)> {
    let id = system(&f.word("psid")?)?;
    let shield_in = if debit { f.u64("shieldIn")? } else { 0 };
    let mut blobs = Blobs::new(f)?;
    let key = registered_key(&f.word("keyRecord")?, &mut blobs)?;
    let stale = stale(f)?;
    let a = acct(&f.words("account")?, &f.word("sendCounterWord")?)?;
    let acc_words = f.words("accWords")?;
    let pending: Vec<(u64, Word)> = f
        .list("pending")?
        .iter()
        .map(|e| {
            let e = Fields::new(e.as_object().ok_or(Error::Argument)?, &["index", "word"])?;
            Ok((e.u64("index")?, e.word("word")?))
        })
        .collect::<Result<_>>()?;
    if !(a.cleared <= a.floor && a.floor <= a.rolled && a.rolled <= a.count) {
        return Err(Error::Argument);
    }
    // unitsOf(T) = accUnits + 1 + (p − rolled) ≤ K_MAX
    let room = (K_MAX as u64).checked_sub(a.units + 1).ok_or(Error::Argument)?;
    let inline = if op7 && id == PQZH_ID { INLINE_MAX_PQZH } else { INLINE_MAX };
    let p = a.count.min(a.rolled.saturating_add(inline.min(room)));
    let mut c = vec![0u64; CT_BYTES / 8];
    if a.flags & MAT != 0 {
        // the slots hold not(stream word); the stream (CTP bytes) hashes to accHash
        if acc_words.len() != ACC_WORDS {
            return Err(Error::Argument);
        }
        let stream: Vec<u8> = acc_words.iter().flat_map(|w| w.map(|b| !b)).take(CTP).collect();
        if crate::keccak256(&stream) != a.acc_hash {
            return Err(Error::Argument);
        }
        add(&mut c, &unpack(&stream).ok_or(Error::Argument)?);
    } else if !acc_words.is_empty() {
        return Err(Error::Argument);
    } else if a.acc_blob != [0; 20] {
        add(&mut c, &load(blobs.data(&a.acc_blob)?, a.acc_u, a.acc_v)?);
    }
    // the window [rolled, p), selected by index only: exactly those, in order
    if pending.len() as u64 != p - a.rolled {
        return Err(Error::Argument);
    }
    for (k, (i, e)) in pending.iter().enumerate() {
        if *i != a.rolled + k as u64 || *e == [0; 32] {
            return Err(Error::Argument);
        }
        // `vOff == 0`: a TRIVIAL entry, its amount the low 64 bits of the blob field (never `blob == 0`)
        let v_off = lo_u64(e, 8, 2)? as usize;
        if v_off == 0 {
            add_trivial(&mut c, lo_u64(e, 12, 8)?);
        } else {
            add(&mut c, &load(blobs.data(&lo_addr(e, 12)?)?, lo_u64(e, 10, 2)? as usize, v_off)?);
        }
    }
    add_trivial(&mut c, shield_in);
    blobs.done()?;
    let t = c.iter().flat_map(|x| (x % Q).to_be_bytes()).collect();
    Ok((id, Own { t, p, send_counter: a.send_counter, key, stale }))
}

/// `entryRef = keccak256(abi.encode(TAG_ENTRY, chainId, chainUid, token, fromUA, sendCounter))` (`PqzCore.entryRefOf`).
fn entry_ref(chain_id: u64, chain_uid: &Word, token: &[u8; 20], from: &Word, counter: u64) -> Word {
    let tag = crate::keccak256(b"SCAAS-PQZ-ENTRY-V1");
    crate::keccak256(&[tag, u64_word(chain_id), *chain_uid, addr(token), *from, u64_word(counter)].concat())
}

/// An old entry, located by its sender's `fromUA` and `sendCounter` (the request's `entryRef` must recompute from them):
/// `R` of its op blob (3h: the data before `P(v_f)` and the tail, [`super::pqz_path::tail`]) and the blob's shape `(G, M,
/// auditorOn)`.
struct Entry {
    r: Vec<u8>,
    g: usize,
    m: usize,
    aud: bool,
    entry_ref: Word,
}

fn entry(f: &Fields<'_>, blobs: &mut Blobs) -> Result<Entry> {
    let (chain_uid, token) = (f.word("chainUid")?, f.arr("token")?);
    let er = entry_ref(f.u64("chainId")?, &chain_uid, &token, &f.word("fromUA")?, f.u64("sendCounter")?);
    if er != f.word("entryRef")? {
        return Err(Error::Argument);
    }
    let ptr = f.word("entryPtr")?;
    only_low(&ptr, 20)?;
    let d = blobs.data(&lo_addr(&ptr, 0)?)?;
    let r = d.get(..super::pqz_path::tail(d)?.r_len).ok_or(Error::Argument)?.to_vec();
    // `PqzCore._bundleShape`, exactly one fit (Fable P3-6)
    let (g, m, aud) = super::pqz_path::bundle_shape(r.len(), PKP, VP)?;
    Ok(Entry { r, g, m, aud, entry_ref: er })
}

impl Entry {
    fn leg_at(&self, j: usize) -> usize {
        16 + PKP * self.g + (32 + VP * (1 + self.aud as usize)) * j
    }
    /// `UA_j` of leg `j`.
    fn owner(&self, j: usize) -> Result<Word> {
        let end = self.leg_at(j + 1);
        self.r.get(end - 32..end).and_then(|w| w.try_into().ok()).ok_or(Error::Argument)
    }
    /// Leg `j` as a ciphertext (`PqzCore._legOf`): `u_{g(j)} ‖ v_j`, or the auditor copy `v_{a,j}`; canonical.
    fn ct(&self, j: usize, auditor: bool) -> Result<Vec<u8>> {
        if j >= self.m || (auditor && !self.aud) {
            return Err(Error::Argument);
        }
        let u_off = 16 + PKP * (j / legs_per_group(self.aud));
        let leg = self.leg_at(j);
        let ct = load(&self.r, u_off, if auditor { leg + VP } else { leg })?;
        if coeffs_ok(&ct) {
            Ok(ct)
        } else {
            Err(Error::Argument)
        }
    }
}

/// The auditor of the token (`auditorMode` not NONE, `auditorUA`) from its two raw words.
fn auditor(f: &Fields<'_>) -> Result<Word> {
    let w = f.word("auditorMode")?;
    only_low(&w, 22)?;
    if !matches!(lo_u64(&w, 21, 1)?, 1 | 2) {
        return Err(Error::Argument);
    }
    f.word("auditorUA")
}

/// Op 1's `memoHash`: per the request's `mode` (T15k), or (feature `vectors`, the raw debits) the vector file's word.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Memo {
    Mode(Mode),
    #[cfg(feature = "vectors")]
    Given(Word),
}

/// The op 4 / op 5 statement words of an old entry (CTR-PQZ-14, `PqzCore._discHead`): opTag, the id, `chainId`, `chainUid`,
/// `token`, `registry`, `entryRef`; the amount (word 7) and the kind word (word 8) are the caller's to fill.
fn disc_words(f: &Fields<'_>, form: Form, id: &Word, entry_ref: &Word) -> Result<[Word; DISC_WORDS]> {
    let mut words = Disclose::words(form, id);
    for (i, w) in [
        (2, u64_word(f.u64("chainId")?)),
        (3, f.word("chainUid")?),
        (4, addr(&f.arr("token")?)),
        (5, addr(&f.arr("registry")?)),
        (6, *entry_ref),
    ] {
        *words.get_mut(i).ok_or(Error::Argument)? = w;
    }
    Ok(words)
}

/// The typed request of a command.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Req {
    Enc { pks: Vec<Vec<u8>>, values: Vec<u64> },
    #[cfg(feature = "vectors")]
    Dec { ct: Vec<u8>, window: usize },
    Register { id: Word, kind: u16, ua: Word, kem_pk: Option<Vec<u8>> },
    KeyRecord { id: Word, ua: Word, version: u64 },
    Balance { t: Vec<u8>, p: u64, send_counter: u64 },
    Transfer { id: Word, h: Header, to_ua: Word, pk_t: Vec<u8>, pk_a: Option<Vec<u8>>, t: Vec<u8>, amount: u64, memo: Memo },
    /// `memo_hash`: `None` the 3h word `keccak256(ownTag)` (no-oracle spec §4.14.5), `Some` the vector file's (feature `vectors`)
    Burn { id: Word, h: Header, amount: u64, recipient: Word, t: Vec<u8>, memo_hash: Option<Word> },
    Refresh { id: Word, h: Header, t: Vec<u8>, memo_hash: Option<Word> },
    /// `memo_hash`: `None` the 3h word `keccak256(memo ‖ ownTag)`, `Some` the vector file's (feature `vectors`)
    Multi { id: Word, h: Header, legs: Vec<(Vec<u8>, Word, u64)>, pk_a: Option<Vec<u8>>, t: Vec<u8>, mode: Mode, memo_hash: Option<Word> },
    #[cfg(feature = "vectors")]
    DiscloseSender { stmt: Vec<u8>, from_ua: Word, send_counter: u64, salt: [u8; 16], aud: bool, multi: Option<(usize, usize)> },
    /// Op 4 of leg `j` of the sender's own entry (`proveDiscloseSender`): the statement's words (the amount filled from the
    /// entry), the leg owner's registered keys (its versions, tried in order), the leg rebuilt from the op blob, the blob's salt
    /// and shape `(auditorOn, M)`.
    SenderLeg { words: [Word; DISC_WORDS], pk_ts: Vec<Vec<u8>>, ct: Vec<u8>, from_ua: Word, send_counter: u64, salt: [u8; 16], aud: bool, m: usize, j: usize },
    #[cfg(feature = "vectors")]
    Disclose { stmt: Vec<u8> },
    /// A rebuilt leg: `auditRead` (`form` `None`) or `proveDisclose` (op 5 `words`, the amount filled after decryption).
    Leg { form: Option<Form>, words: [Word; DISC_WORDS], ct: Vec<u8>, window: usize },
    /// `pickDecoys` (T15n): op 7's decoys from the reading layer's candidates; no key.
    PickDecoys(super::decoys::Request),
    /// `expect`: the entry's `(auditorOn, UA_j)` the opened memo must name (`None` only for the raw form).
    OpenMemo { chain_uid: Word, token: [u8; 20], from_ua: Word, send_counter: u64, memo: Vec<u8>, expect: Option<(bool, Vec<Word>)> },
    /// Path (B) (no-oracle spec §4.14.2): the session's commands.
    ProvenOpen(Box<proven::Open>),
    ProvenAdd { session: [u8; 16], blobs: proven::Codes, credits: Vec<proven::Credit> },
    ProvenCancel([u8; 16]),
    BalanceProven([u8; 16]),
}

/// A words debit's header: the caller's fields, `p` and `sendCounter` from the account.
fn own_header(f: &Fields<'_>, o: &Own) -> Result<Header> {
    Ok(Header {
        chain_id: f.u64("chainId")?,
        token: f.arr("token")?,
        registry: f.arr("registry")?,
        from_ua: f.word("ua")?,
        beneficiary_ua: f.opt_word("beneficiaryUA")?,
        fee: f.u64("fee")?,
        send_counter: o.send_counter,
        p: o.p,
        valid_until_block: f.u64("validUntilBlock")?,
        plain_used: f.u64("shieldIn")?,
        chain_uid: f.word("chainUid")?,
        envelope_binding: f.word("envelopeBinding")?,
    })
}

/// The typed request and, for a words command, the registered key the handle must hold (checked before any key use).
fn req(cmd: &str, f: &Fields<'_>) -> Result<(Req, Option<Vec<u8>>)> {
    let debit = |op7: bool| -> Result<(Word, Own, Header)> {
        let (id, o) = own(f, op7, true)?;
        let h = own_header(f, &o)?;
        Ok((id, o, h))
    };
    Ok(match cmd {
        "pickDecoys" => (Req::PickDecoys(super::decoys::Request::from_map(f.0)?), None),
        "provenOpen" => {
            let (o, key) = proven::open(f)?;
            (Req::ProvenOpen(Box::new(o)), Some(key))
        }
        "provenAdd" => {
            let (blobs, credits) = proven::credits(f)?;
            (Req::ProvenAdd { session: f.arr("session")?, blobs, credits }, None)
        }
        "provenCancel" => (Req::ProvenCancel(f.arr("session")?), None),
        "balanceProven" => (Req::BalanceProven(f.arr("session")?), None),
        "enc" => {
            let pks = f.list("pks")?.iter().map(|p| pk(hex(p)?)).collect::<Result<_>>()?;
            let values = f.list("values")?.iter().map(|v| v.as_u64().ok_or(Error::Argument));
            (Req::Enc { pks, values: values.collect::<Result<_>>()? }, None)
        }
        #[cfg(feature = "vectors")]
        "dec" => {
            let window = if f.has("window") { f.u64("window")? } else { 0 };
            (Req::Dec { ct: f.ct("ct")?, window: usize::try_from(window).ok().filter(|w| *w < 4).ok_or(Error::Argument)? }, None)
        }
        "proveRegister" => (
            Req::Register {
                id: f.id()?,
                kind: u16::try_from(f.u64("kind")?).map_err(|_| Error::Argument)?,
                ua: f.word("ua")?,
                kem_pk: f.has("kemPk").then(|| f.bytes("kemPk")).transpose()?,
            },
            None,
        ),
        "proveKeyRecord" => (Req::KeyRecord { id: f.id()?, ua: f.word("ua")?, version: f.u64("version")? }, None),
        #[cfg(feature = "vectors")]
        "rawProveTransfer" => (
            Req::Transfer {
                id: f.id()?,
                h: f.header()?,
                to_ua: f.word("toUA")?,
                pk_t: f.pk("pkT")?,
                pk_a: f.opt_pk("pkA")?,
                t: f.ct("T")?,
                amount: f.u64("amount")?,
                memo: Memo::Given(f.word("memoHash")?),
            },
            None,
        ),
        #[cfg(feature = "vectors")]
        "rawProveBurn" => (
            Req::Burn {
                id: f.id()?,
                h: f.header()?,
                amount: f.u64("amount")?,
                recipient: f.word("recipient")?,
                t: f.ct("T")?,
                memo_hash: Some(f.word("memoHash")?),
            },
            None,
        ),
        #[cfg(feature = "vectors")]
        "rawProveRefresh" => (Req::Refresh { id: f.id()?, h: f.header()?, t: f.ct("T")?, memo_hash: Some(f.word("memoHash")?) }, None),
        #[cfg(feature = "vectors")]
        "rawProveTransferMulti" => (
            Req::Multi {
                id: f.id()?,
                h: f.header()?,
                legs: f.legs()?,
                pk_a: f.opt_pk("pkA")?,
                t: f.ct("T")?,
                mode: f.mode()?,
                memo_hash: Some(f.word("memoHash")?),
            },
            None,
        ),
        #[cfg(feature = "vectors")]
        "rawProveDiscloseSender" => {
            let multi = match (f.has("M"), f.has("leg")) {
                (false, false) => None,
                (true, true) => Some((
                    usize::try_from(f.u64("M")?).map_err(|_| Error::Argument)?,
                    usize::try_from(f.u64("leg")?).map_err(|_| Error::Argument)?,
                )),
                _ => return Err(Error::Argument),
            };
            (
                Req::DiscloseSender {
                    stmt: f.bytes("stmt")?,
                    from_ua: f.word("fromUA")?,
                    send_counter: f.u64("sendCounter")?,
                    salt: f.arr("salt")?,
                    aud: f.get("auditorOn")?.as_bool().ok_or(Error::Argument)?,
                    multi,
                },
                None,
            )
        }
        #[cfg(feature = "vectors")]
        "rawProveDisclose" => (Req::Disclose { stmt: f.bytes("stmt")? }, None),
        #[cfg(feature = "vectors")]
        "rawOpenMemo" => (
            Req::OpenMemo {
                chain_uid: f.word("chainUid")?,
                token: f.arr("token")?,
                from_ua: f.word("fromUA")?,
                send_counter: f.u64("sendCounter")?,
                memo: f.bytes("memo")?,
                expect: None,
            },
            None,
        ),
        "balance" => {
            // `forOp7`: the `p` (and value) an op 7 would use (`INLINE_MAX_PQZH` on a PQZH token), else op 1 / op 2's
            system(&f.word("psid")?)?;
            let op7 = f.get("forOp7")?.as_bool().ok_or(Error::Argument)?;
            let (_, o) = own(f, op7, false)?;
            (Req::Balance { t: o.t, p: o.p, send_counter: o.send_counter }, Some(o.key))
        }
        "proveTransfer" => {
            let (id, o, h) = debit(false)?;
            // KV-8 / KV-9: a stale version only migrates to its own UA; the current one never pays itself (`SelfTransfer`)
            if o.stale != (f.word("toUA")? == h.from_ua) {
                return Err(Error::Argument);
            }
            let (pk_t, pk_a) = (f.pk("pkT")?, f.opt_pk("pkA")?);
            distinct(&[Some(&o.key[..]), Some(&pk_t[..]), pk_a.as_deref()].into_iter().flatten().collect::<Vec<_>>())?;
            let r = Req::Transfer {
                id,
                h,
                to_ua: f.word("toUA")?,
                pk_t,
                pk_a,
                t: o.t,
                amount: f.u64("amount")?,
                memo: Memo::Mode(f.mode()?),
            };
            (r, Some(o.key))
        }
        "proveBurn" => {
            let (id, o, h) = debit(false)?;
            if o.stale {
                return Err(Error::Argument); // KV-8: a stale version burns nothing (its refresh is `proveRefresh`)
            }
            (Req::Burn { id, h, amount: f.u64("amount")?, recipient: f.word("recipient")?, t: o.t, memo_hash: None }, Some(o.key))
        }
        "proveRefresh" => {
            let (id, o, h) = debit(false)?;
            (Req::Refresh { id, h, t: o.t, memo_hash: None }, Some(o.key))
        }
        "proveTransferMulti" => {
            let (id, o, h) = debit(true)?;
            if o.stale {
                return Err(Error::Argument); // KV-8: no op 7 from a stale version
            }
            let pks: Vec<Vec<u8>> = f.legs()?.into_iter().map(|l| l.0).chain(f.opt_pk("pkA")?).collect();
            distinct(&std::iter::once(&o.key[..]).chain(pks.iter().map(|k| &k[..])).collect::<Vec<_>>())?;
            (Req::Multi { id, h, legs: f.legs()?, pk_a: f.opt_pk("pkA")?, t: o.t, mode: f.mode()?, memo_hash: None }, Some(o.key))
        }
        "auditRead" | "proveDisclose" => {
            let id = system(&f.word("psid")?)?;
            let mut blobs = Blobs::new(f)?;
            let key = registered_key(&f.word("keyRecord")?, &mut blobs)?;
            let e = entry(f, &mut blobs)?;
            blobs.done()?;
            let j = usize::try_from(f.u64("leg")?).map_err(|_| Error::Argument)?;
            let form = match (cmd, f.has("kind").then(|| f.get("kind").map(Value::as_str))) {
                ("auditRead", None) => None,
                ("proveDisclose", Some(Ok(Some("RECEIVER_X")))) => Some(Form::DiscloseReceiver),
                ("proveDisclose", Some(Ok(Some("AUDITOR")))) => Some(Form::DiscloseAuditor),
                _ => return Err(Error::Argument),
            };
            let auditor_read = form != Some(Form::DiscloseReceiver);
            // the role: the leg's owner, or the token's auditor (its words only then, and the entry has the copies)
            if f.has("auditorMode") != auditor_read || f.has("auditorUA") != auditor_read {
                return Err(Error::Argument);
            }
            let holder = if auditor_read { auditor(f)? } else { e.owner(j)? };
            let ct = e.ct(j, auditor_read)?;
            let window = if auditor_read { j % legs_per_group(true) } else { 0 };
            let mut words = Disclose::words(Form::DiscloseAuditor, &id);
            if let Some(form) = form {
                words = disc_words(f, form, &id, &e.entry_ref)?;
                *words.get_mut(8).ok_or(Error::Argument)? = u64_word(if form == Form::DiscloseAuditor { 2 + 256 * window as u64 } else { 1 });
            } else if f.has("registry") {
                return Err(Error::Argument);
            }
            // `keyRecord` is `ua`'s; `ua` is the leg's owner `UA_j` or the token's auditor
            if holder != f.word("ua")? {
                return Err(Error::Argument);
            }
            (Req::Leg { form, words, ct, window }, Some(key))
        }
        "proveDiscloseSender" => {
            let id = system(&f.word("psid")?)?;
            let mut blobs = Blobs::new(f)?;
            // `keyRecord` is `fromUA`'s (the handle's own: the sender), `legKeyRecords` the leg owner's versions (one is the
            // statement's `pk`), at most 64
            let key = registered_key(&f.word("keyRecord")?, &mut blobs)?;
            let records = f.words("legKeyRecords")?;
            if records.is_empty() || records.len() > LEG_KEYS_MAX {
                return Err(Error::Argument);
            }
            let pk_ts = records.iter().map(|r| registered_key(r, &mut blobs)).collect::<Result<Vec<_>>>()?;
            let e = entry(f, &mut blobs)?;
            blobs.done()?;
            let j = usize::try_from(f.u64("leg")?).map_err(|_| Error::Argument)?;
            let ct = e.ct(j, false)?;
            let salt = e.r.get(..16).and_then(|x| x.try_into().ok()).ok_or(Error::Argument)?;
            let r = Req::SenderLeg {
                words: disc_words(f, Form::DiscloseSender, &id, &e.entry_ref)?,
                pk_ts,
                ct,
                from_ua: f.word("fromUA")?,
                send_counter: f.u64("sendCounter")?,
                salt,
                aud: e.aud,
                m: e.m,
                j,
            };
            (r, Some(key))
        }
        "openMemo" => {
            system(&f.word("psid")?)?;
            let mut blobs = Blobs::new(f)?;
            let key = registered_key(&f.word("keyRecord")?, &mut blobs)?;
            let e = entry(f, &mut blobs)?;
            blobs.done()?;
            let memo = f.bytes("memo")?;
            // the memo of this entry: its salt the blob's, its length `16 + 2 + 40·M` for the blob's M
            if memo.get(..16) != e.r.get(..16) || memo.len() != pqz_ffi::memo::memo_len(e.m) {
                return Err(Error::Argument);
            }
            let uas = (0..e.m).map(|j| e.owner(j)).collect::<Result<_>>()?;
            let r = Req::OpenMemo {
                chain_uid: f.word("chainUid")?,
                token: f.arr("token")?,
                from_ua: f.word("fromUA")?,
                send_counter: f.u64("sendCounter")?,
                memo,
                expect: Some((e.aud, uas)),
            };
            (r, Some(key))
        }
        _ => return Err(Error::Argument),
    })
}

/// A PQZ command as the facade runs it: its name, its fields (each on the command's allow-list), their typed values and, for a
/// words command, the registered key the handle must hold. Public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqzCmd {
    cmd: &'static str,
    v: Map<String, Value>,
    req: Req,
    key: Option<Vec<u8>>,
}

impl PqzCmd {
    /// `json` (at most [`CMD_MAX`] bytes, depth [`CMD_DEPTH`], the bounded reader) as command `cmd`: an object whose fields
    /// are all on `cmd`'s allow-list and each of its type; else `Argument` (an unknown command, a `key` or any other field
    /// not on the list, a missing field, a number other than a `u64`, a key or ciphertext of another length or not
    /// canonical, raw words that do not parse, check or rebuild) or `PqzSetMismatch` (a `proofSystemId` or `psid` not of this
    /// build).
    pub fn from_json(cmd: &str, json: &[u8]) -> Result<PqzCmd> {
        let cmd = *COMMANDS.iter().find(|c| **c == cmd).ok_or(Error::Argument)?;
        let Value::Object(v) = bounded::json(json, CMD_MAX, CMD_DEPTH)? else { return Err(Error::Argument) };
        if !v.keys().all(|k| allowed(cmd, k)) {
            return Err(Error::Argument);
        }
        let (req, key) = req(cmd, &Fields(&v))?;
        Ok(PqzCmd { cmd, v, req, key })
    }
    pub fn cmd(&self) -> &'static str {
        self.cmd
    }
    /// Test-only (feature `vectors`): what a words command rebuilt from its words, before any key use: `{T, p, sendCounter}`
    /// of an account, `{ct, window, words}` of an entry leg, `{ct, legKeys, salt, auditorOn, M, words}` of a sender's leg,
    /// `{auditorOn, uas}` a memo must name; the registered `key`.
    #[cfg(feature = "vectors")]
    pub fn vectors_rebuilt(&self) -> Value {
        let mut v = match &self.req {
            Req::Balance { t, p, send_counter } => json!({"T": to_hex(t), "p": p, "sendCounter": send_counter}),
            Req::Transfer { h, t, .. } | Req::Burn { h, t, .. } | Req::Refresh { h, t, .. } | Req::Multi { h, t, .. } => {
                json!({"T": to_hex(t), "p": h.p, "sendCounter": h.send_counter})
            }
            Req::Leg { words, ct, window, .. } => {
                json!({"ct": to_hex(ct), "window": window, "words": words.iter().map(|w| to_hex(w)).collect::<Vec<_>>()})
            }
            Req::OpenMemo { expect: Some((aud, uas)), .. } => json!({"auditorOn": aud, "uas": uas.iter().map(|w| to_hex(w)).collect::<Vec<_>>()}),
            Req::SenderLeg { words, pk_ts, ct, salt, aud, m, .. } => json!({"ct": to_hex(ct), "legKeys": pk_ts.iter().map(|k| to_hex(k)).collect::<Vec<_>>(), "salt": to_hex(salt),
                "auditorOn": aud, "M": m, "words": words.iter().map(|w| to_hex(w)).collect::<Vec<_>>()}),
            _ => json!({}),
        };
        if let (Some(o), Some(k)) = (v.as_object_mut(), &self.key) {
            o.insert("key".into(), to_hex(k).into());
        }
        v
    }
    /// The fields as JSON (what [`PqzCmd::from_json`] reads back to the same command).
    pub fn to_json(&self) -> String {
        Value::Object(self.v.clone()).to_string()
    }
}

/// The randomness of one call: `rnd32` from the OS RNG and, unless given (feature `vectors`), the transfer's salt, the
/// encryption seed and the memo key derived or drawn inside.
pub struct Draw {
    rnd32: [u8; 32],
    seed_enc: Option<[u8; 32]>,
    #[cfg(feature = "vectors")]
    salt: Option<[u8; 16]>,
    #[cfg(feature = "vectors")]
    memo_key: Option<[u8; 32]>,
}

impl Draw {
    fn os() -> Result<Draw> {
        Ok(Draw {
            rnd32: os32()?,
            seed_enc: None,
            #[cfg(feature = "vectors")]
            salt: None,
            #[cfg(feature = "vectors")]
            memo_key: None,
        })
    }
    /// A transfer's salt: fresh from the OS RNG (feature `vectors`: the generator's, when given).
    fn salt(&self) -> Result<[u8; 16]> {
        #[cfg(feature = "vectors")]
        if let Some(s) = self.salt {
            return Ok(s);
        }
        os16()
    }
    /// The memo's key seed: `seed32` (feature `vectors`: the generator's, when given).
    fn memo_key<'a>(&'a self, seed32: &'a [u8]) -> &'a [u8] {
        #[cfg(feature = "vectors")]
        if let Some(k) = &self.memo_key {
            return k;
        }
        seed32
    }
    /// Test-only (feature `vectors`): the generator's randomness (`seed_enc`, `salt`, the memo key in place of `seed32`).
    #[cfg(feature = "vectors")]
    pub fn vectors(rnd32: [u8; 32], seed_enc: Option<[u8; 32]>, salt: Option<[u8; 16]>, memo_key: Option<[u8; 32]>) -> Draw {
        Draw { rnd32, seed_enc, salt, memo_key }
    }
}

fn os32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

fn os16() -> Result<[u8; 16]> {
    let mut b = [0u8; 16];
    OsRng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
    Ok(b)
}

/// A key pair rebuilt from `seed32` for one operation: `s`, `e` wiped on drop.
struct Sk(Key);

impl Drop for Sk {
    fn drop(&mut self) {
        self.0.s.zeroize();
        self.0.e.zeroize();
    }
}

/// An encryption's short vectors (the witness's randomness) wiped on drop.
struct Wiped(pqzl::Enc);

impl Drop for Wiped {
    fn drop(&mut self) {
        self.0.r.zeroize();
        self.0.e1.zeroize();
        self.0.e2.zeroize();
    }
}

struct WipedMulti(pqzl::EncMulti);

impl Drop for WipedMulti {
    fn drop(&mut self) {
        for g in &mut self.0.groups {
            g.r.zeroize();
            g.e1.zeroize();
            g.e2.zeroize();
        }
        self.0.e2.zeroize();
        self.0.e2_f.zeroize();
        self.0.e2_a.zeroize();
    }
}

/// `Σ M_i 16^i` of a decryption, as a `u64` (else `Argument`: not a balance); the noise wiped (CTR-PQZ-14: it never leaves).
fn value(d: Option<([i64; 16], [i64; 16])>) -> Result<u64> {
    let (m, mut noise) = d.ok_or(Error::Argument)?;
    noise.zeroize();
    let v = m.iter().rev().try_fold(0i128, |a, &x| a.checked_mul(16)?.checked_add(i128::from(x)));
    v.and_then(|v| u64::try_from(v).ok()).ok_or(Error::Argument)
}

/// The amount a leg `v` carries over the sender's re-encryption of zero `v0` (the same randomness and key): each of the 16
/// coefficients `(v − v0) mod q` is `Δ·digit`, the digit counted branch-free (`digit < 16`); and whether `v` is exactly `v0 +
/// Δ·digits` (constant time). A `v` that is not the sender's encryption of some amount gives `false`.
fn sender_amount(v: &[u8], v0: &[u8]) -> (u64, Choice) {
    let delta = DELTA.unsigned_abs();
    let lane = |b: &[u8]| b.iter().fold(0u64, |a, x| a << 8 | u64::from(*x));
    let (mut amount, mut want) = (0u64, Vec::with_capacity(v0.len()));
    for (i, (a, z)) in v.chunks_exact(8).zip(v0.chunks_exact(8)).enumerate() {
        let (a, z) = (lane(a) % Q, lane(z) % Q);
        let diff = (a + Q - z) % Q;
        let k = (1..16u64).fold(0u64, |k, t| k + u64::from((!diff.ct_lt(&(t * delta))).unwrap_u8()));
        amount |= k << (4 * i);
        want.extend(((z + delta * k) % Q).to_be_bytes());
    }
    (amount, want.ct_eq(v))
}

fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>> {
    #[cfg(feature = "vectors")]
    PROVER_CALLS.with(|n| n.set(n.get() + 1));
    pqz_ffi::prove(op, stmt, wit, rnd32).map_err(|_| Error::Argument)
}

#[cfg(feature = "vectors")]
thread_local! {
    static PROVER_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static KEY_USES: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    static SENDER_TRIALS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Test-only (feature `vectors`): how many leg keys `proveDiscloseSender` tried on this thread (one re-encryption each; group
/// 3g's additive recovery: another version of the sender stops at the first, before any other leg key).
#[cfg(feature = "vectors")]
pub fn vectors_sender_trials() -> usize {
    SENDER_TRIALS.with(|n| n.get())
}

/// Test-only (feature `vectors`): how many times a handle on this thread rebuilt its key (every secret operation of a command).
/// A refusal of the words (parse, consistency, leg, role) comes before any (spec no-decryption-oracle §5: "key unused").
#[cfg(feature = "vectors")]
pub fn vectors_key_uses() -> usize {
    KEY_USES.with(|n| n.get())
}

/// Test-only (feature `vectors`): how many calls on this thread reached pqz-core's prover. A refusal of the facade's own
/// checks (a balance below the debit, a statement not of this key, a re-derived `u` / `v` that is not the statement's) must
/// come before it, which the prover's own refusal of an unsatisfied witness would hide.
#[cfg(feature = "vectors")]
pub fn vectors_prover_calls() -> usize {
    PROVER_CALLS.with(|n| n.get())
}

/// A debit's answer with the `p` it was proven at (the transaction's `p`).
fn with_p(mut v: Value, h: &Header) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.insert("p".into(), h.p.into());
    }
    v
}

fn proved(stmt: &[u8], proof: &[u8]) -> Value {
    json!({"stmt": to_hex(stmt), "proof": to_hex(proof)})
}

/// CTR-PQZ-19: a transfer's `seed_enc` from `seed32` and the build's public words.
fn seed_enc(seed32: &[u8], chain_uid: &Word, token: &[u8; 20], from_ua: &Word, send_counter: u64, salt: &[u8; 16]) -> Result<[u8; 32]> {
    let ctr = u32::try_from(send_counter).map_err(|_| Error::Argument)?;
    let info = [&chain_uid[..], token, from_ua, &ctr.to_be_bytes(), salt].concat();
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(ENC_SALT), seed32).expand(&info, &mut out).map_err(|_| Error::Argument)?;
    Ok(out)
}

/// `ownTag` (proof-path spec §3.1 PP-3, C4; no-oracle spec §4.14.5): `K = HKDF-SHA256(seed32, "", "PQZ/owntag/v1", 32)` of the
/// debited version's seed, `ownTag = HMAC-SHA256(K, chainUid ‖ token ‖ fromUA ‖ be32(sendCounter) ‖ keccak256(P(u) ‖ P(v_f)))`, the
/// location from the debit's header `hd`, `u` its `u_0` / `u′` and `v_f` in 64-bit lanes, `P` the stored form. A counter at or
/// above 2^32 is `Argument` (as `seed_enc`).
fn own_tag(seed32: &[u8], hd: &[Word; 20], u: &[u8], v_f: &[u8]) -> Result<Word> {
    let w = |i: usize| hd.get(i).ok_or(Error::Argument);
    let ctr = u32::try_from(pqz_ffi::stmt::word_u64(w(H_SEND_COUNTER)?).ok_or(Error::Argument)?).map_err(|_| Error::Argument)?;
    let parts = [super::pqz_pack::pack(u).ok_or(Error::Argument)?, super::pqz_pack::pack(v_f).ok_or(Error::Argument)?].concat();
    let token = w(H_TOKEN)?.get(12..).ok_or(Error::Argument)?;
    let msg = [&w(H_CHAIN_UID)?[..], token, &w(H_FROM)?[..], &ctr.to_be_bytes(), &crate::keccak256(&parts)].concat();
    Ok(crate::wallet::hmac_sha256(&own_tag_key(seed32)?, &msg))
}

/// `K = HKDF-SHA256(seed32, "", "PQZ/owntag/v1", 32)`.
fn own_tag_key(seed32: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    hkdf_sha256(seed32, &[], OWN_TAG_LABEL, 32)
}

/// `ownTag`'s HKDF info (proof-path spec PP-3).
const OWN_TAG_LABEL: &[u8] = b"PQZ/owntag/v1";

/// Test-only (feature `vectors`): `K` of a given seed and `HMAC-SHA256(K, message)`, so the shared KAT rows (`pq_kat.json`
/// `ownTag`) are reproduced here; a release build has no seed-taking entry.
#[cfg(feature = "vectors")]
pub fn vectors_own_tag(seed32: &[u8], message: &[u8]) -> Result<(Vec<u8>, Word)> {
    let k = own_tag_key(seed32)?;
    Ok((k.to_vec(), crate::wallet::hmac_sha256(&k, message)))
}

/// A debit's answer with its `ownTag` (the payload's `ownTag` field, a node job's `args.ownTag`).
fn with_tag(mut v: Value, tag: &Word) -> Value {
    if let Some(o) = v.as_object_mut() {
        o.insert("ownTag".into(), to_hex(tag).into());
    }
    v
}

/// A PQZ key handle (spec §8.2): the wallet's store, the generation and the slot of `seed32`, and the public `pk`; no secret
/// bytes of its own. Neither `Clone` nor `Debug`:
/// ```compile_fail,E0277
/// fn need<T: Clone>() {}
/// need::<scaas_ua::facade::pqz::PqzKey>();
/// ```
#[cfg_attr(
    not(feature = "vectors"),
    doc = "A release build (no feature `vectors`) takes no fixed randomness and no given `R_REG` message (F-01):",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::facade::pqz::PqzKey) {",
    doc = "    let _ = k.vectors_call(\"enc\", b\"{}\", &scaas_ua::facade::pqz::Draw::vectors([0; 32], None, None, None));",
    doc = "}",
    doc = "```",
    doc = "```compile_fail,E0599",
    doc = "fn f(k: &scaas_ua::facade::pqz::PqzKey) {",
    doc = "    let _ = k.vectors_register_message(&[0; 32], &[0; 32], &[0; 32]);",
    doc = "}",
    doc = "```",
    doc = "nor the test-only marker that lets a `vectors` build make key handles (Codex C1, T15c2):",
    doc = "```compile_fail,E0425",
    doc = "scaas_ua::facade::vectors_unlock(scaas_ua::facade::TestOnly);",
    doc = "```"
)]
pub struct PqzKey {
    account: u32,
    index: u32,
    pk: Vec<u8>,
    secret: Handle,
    /// Path (B)'s one session (no-oracle spec §4.14.2): public sums only, never exported; dropped by a second `provenOpen`, a
    /// cancel, a closing command, the handle's drop or, at the next command, the wallet's lock.
    session: std::sync::Mutex<Option<proven::Session>>,
}

impl zeroize::ZeroizeOnDrop for PqzKey {}

fn keygen(seed32: &[u8]) -> Result<Sk> {
    let seed: &[u8; 32] = seed32.try_into().map_err(|_| Error::Argument)?;
    Ok(Sk(pqzl::keygen(seed).ok_or(Error::Argument)?))
}

/// [`crate::wallet::Wallet::pqz_key_version`].
pub(crate) fn derive(store: &Arc<SecretStore>, account: u32, index: u32, version: u64) -> Result<PqzKey> {
    use crate::wallet::derive::{hkdf_pq_version, HARDENED};
    super::release_or_unlocked()?;
    if account >= HARDENED || index >= HARDENED {
        return Err(Error::Argument);
    }
    let (secret, pk) = store.key(KeyId::Pqz(account, index, version), |seed| {
        let seed32 = hkdf_pq_version(seed, TAG, account, index, version, 32)?;
        let pk = keygen(&seed32)?.0.pk.to_vec();
        Ok((seed32, pk))
    })?;
    Ok(PqzKey { account, index, pk, secret, session: Default::default() })
}

/// A key rebuilt from an `msig`'s k-of-n backup (T16a): `seed32` into `store` by its key hash, only if `pqzl::keygen(seed32)`
/// hashes to `pqz_key_hash` (else `Argument`, nothing stored). Its `account` and `index` are `u32::MAX` (no derivation path).
pub(crate) fn install(store: &Arc<SecretStore>, seed32: &[u8; 32], pqz_key_hash: &[u8; 32]) -> Result<PqzKey> {
    let pk = keygen(seed32)?.0.pk.to_vec();
    if crate::key_hash_of(crate::PQZ_SCHEME, &pk)? != Some(*pqz_key_hash) {
        return Err(Error::Argument);
    }
    let (secret, pk) = store.key(KeyId::PqzHeld(*pqz_key_hash), |_| Ok((Zeroizing::new(seed32.to_vec()), pk)))?;
    Ok(PqzKey { account: u32::MAX, index: u32::MAX, pk, secret, session: Default::default() })
}

/// The key [`install`] put in `store` under `pqz_key_hash` (`Argument` if it holds none).
pub(crate) fn held(store: &Arc<SecretStore>, pqz_key_hash: &[u8; 32]) -> Result<PqzKey> {
    super::release_or_unlocked()?;
    let (secret, pk) = store.key(KeyId::PqzHeld(*pqz_key_hash), |_| Err(Error::Argument))?;
    Ok(PqzKey { account: u32::MAX, index: u32::MAX, pk, secret, session: Default::default() })
}

impl PqzKey {
    /// The derivation account (`u32::MAX` for a key rebuilt from a k-of-n backup).
    pub fn account(&self) -> u32 {
        self.account
    }
    pub fn index(&self) -> u32 {
        self.index
    }
    /// `pk = A·s + e`, `PK` bytes of this build's set.
    pub fn pk(&self) -> Vec<u8> {
        self.pk.clone()
    }

    /// `seed32` in the clear ([`crate::wallet::Wallet::export_pqz_leaf_raw`] only).
    pub(crate) fn leaf(&self) -> Result<Zeroizing<[u8; 32]>> {
        self.secret.with(|s| s.try_into().map(Zeroizing::new).map_err(|_| Error::Argument))?
    }

    /// `f` over `seed32` and the key pair rebuilt from it, under the store's read guard: `KeyRevoked` once the wallet was
    /// locked or freed.
    fn with_sk<T>(&self, f: impl FnOnce(&[u8], &Sk) -> Result<T>) -> Result<T> {
        #[cfg(feature = "vectors")]
        KEY_USES.with(|n| n.set(n.get() + 1));
        self.secret.with(|seed32| f(seed32, &keygen(seed32)?))?
    }

    /// Command `cmd` of [`COMMANDS`] on `request_json` (named fields, `0x` hex bytes, `u64` numbers) with this handle's key:
    /// its JSON answer (`enc`: `{u, vs}`; `dec`: `{value}`; a proof: `{stmt, proof}` and `message` (op 3) or `memo` (op 1 and op 7, `HASH`);
    /// `openMemo`: `{auditorOn, legs: [{amount, ua}]}`). A prover refusal (a balance below amount and fee, a statement that is not
    /// the key's) is `Argument`, no detail.
    pub fn call(&self, cmd: &str, request_json: &[u8]) -> Result<String> {
        self.run(&PqzCmd::from_json(cmd, request_json)?, &Draw::os()?)
    }

    fn run(&self, c: &PqzCmd, d: &Draw) -> Result<String> {
        // a words command: the handle holds the key registered for the account, leg or role the words name (before any use)
        if c.key.as_ref().is_some_and(|k| *k != self.pk) {
            return Err(Error::Argument);
        }
        let out = match &c.req {
            // no key (CTR-UA-29: the reading layer's candidates, the OS CSPRNG)
            Req::PickDecoys(r) => return r.pick(),
            Req::ProvenOpen(o) => self.proven_open(o)?,
            Req::ProvenAdd { session, blobs, credits } => self.proven_add(session, blobs, credits)?,
            Req::ProvenCancel(sid) => self.proven_cancel(sid)?,
            Req::BalanceProven(sid) => self.balance_proven(sid)?,
            Req::Enc { pks, values } => {
                let (u, vs) = enc(pks, values)?;
                json!({"u": to_hex(&u), "vs": vs.iter().map(|v| to_hex(v)).collect::<Vec<_>>()})
            }
            #[cfg(feature = "vectors")]
            Req::Dec { ct, window } => {
                let ct: &[u8; CT_BYTES] = ct.as_slice().try_into().map_err(|_| Error::Argument)?;
                json!({"value": self.with_sk(|_, sk| value(pqzl::dec_win(&sk.0.s, ct, *window)))?})
            }
            Req::Register { id, kind, ua, kem_pk } => {
                let message = crate::pqz_reg_message(*kind, ua, &self.pk, kem_pk.as_deref())?;
                self.register(id, &message, &d.rnd32)?
            }
            Req::KeyRecord { id, ua, version } => {
                let kh = crate::key_hash_of(crate::PQZ_SCHEME, &self.pk)?.ok_or(Error::Argument)?;
                let tag = crate::purpose_tag("pqz-key")?;
                // group 3g (KV-1, KV-2): version 0 over `UAPqzKey{ua, pqzKeyHash}`, v ≥ 1 over `UAPqzKeyVersion{ua, v, pqzKeyHash}`
                let digest = match version {
                    0 => crate::ua8::pqz_key_digest(ua, &kh),
                    v => crate::ua8::pqz_key_version_digest(ua, *v, &kh),
                };
                let message = crate::ua_message(crate::PQZ_SCHEME, &tag, &digest)?;
                self.register(id, &message, &d.rnd32)?
            }
            Req::Balance { t, p, send_counter } => {
                let t: &[u8; CT_BYTES] = t.as_slice().try_into().map_err(|_| Error::Argument)?;
                json!({"value": self.with_sk(|_, sk| value(pqzl::dec(&sk.0.s, t)))?, "p": p, "sendCounter": send_counter})
            }
            Req::Transfer { id, h, to_ua, pk_t, pk_a, t, amount, memo } => {
                with_p(self.with_sk(|seed32, sk| self.transfer(seed32, sk, d, id, h, to_ua, pk_t, pk_a.as_deref(), t, *amount, memo))?, h)
            }
            Req::Burn { id, h, amount, recipient, t, memo_hash } => self.with_sk(|seed32, sk| {
                let mut hd = h.fill(Debit::header(Form::Burn, id));
                *hd.get_mut(H_AMOUNT).ok_or(Error::Argument)? = u64_word(*amount);
                *hd.get_mut(H_RECIPIENT).ok_or(Error::Argument)? = *recipient;
                self.debit_own(seed32, sk, d, Form::Burn, hd, t, amount.checked_add(h.fee), memo_hash.as_ref())
            }).map(|v| with_p(v, h))?,
            Req::Refresh { id, h, t, memo_hash } => self.with_sk(|seed32, sk| {
                self.debit_own(seed32, sk, d, Form::Refresh, h.fill(Debit::header(Form::Refresh, id)), t, Some(h.fee), memo_hash.as_ref())
            }).map(|v| with_p(v, h))?,
            Req::Multi { id, h, legs, pk_a, t, mode, memo_hash } => {
                with_p(self.with_sk(|seed32, sk| self.multi(seed32, sk, d, id, h, legs, pk_a.as_deref(), t, *mode, memo_hash.as_ref()))?, h)
            }
            #[cfg(feature = "vectors")]
            Req::DiscloseSender { stmt, from_ua, send_counter, salt, aud, multi } => {
                stmt_id(stmt)?;
                let Ok(Stmt::Disclose(s)) = parse(Form::DiscloseSender.op(), stmt) else { return Err(Error::Argument) };
                self.with_sk(|seed32, _| self.disclose_sender(seed32, d, stmt, &s, from_ua, *send_counter, salt, *aud, *multi))?
            }
            Req::SenderLeg { words, pk_ts, ct, from_ua, send_counter, salt, aud, m, j } => self.with_sk(|seed32, _| {
                self.disclose_sender_leg(seed32, d, *words, pk_ts, ct, from_ua, *send_counter, salt, *aud, *m, *j)
            })?,
            #[cfg(feature = "vectors")]
            Req::Disclose { stmt } => {
                stmt_id(stmt)?;
                let Ok(Stmt::Disclose(s)) = parse(Form::DiscloseReceiver.op(), stmt) else { return Err(Error::Argument) };
                if s.pk != &self.pk[..] {
                    return Err(Error::Argument);
                }
                let wit = Zeroizing::new(self.with_sk(|_, sk| Ok(wit_key(&sk.0)))?);
                proved(stmt, &prove(Form::DiscloseReceiver.op(), stmt, &wit, &d.rnd32)?)
            }
            Req::Leg { form, words, ct, window } => {
                let ct: &[u8; CT_BYTES] = ct.as_slice().try_into().map_err(|_| Error::Argument)?;
                let amount = self.with_sk(|_, sk| value(pqzl::dec_win(&sk.0.s, ct, *window)))?;
                match form {
                    None => json!({"amount": amount}),
                    Some(form) => {
                        let mut words = *words;
                        *words.get_mut(DW_AMOUNT).ok_or(Error::Argument)? = u64_word(amount);
                        let (u, v) = ct.split_at(PK_BYTES);
                        let stmt = Stmt::Disclose(Disclose { form: *form, words, pk: &self.pk, u, v }).encode().map_err(|_| Error::Argument)?;
                        let wit = Zeroizing::new(self.with_sk(|_, sk| Ok(wit_key(&sk.0)))?);
                        let mut out = proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?);
                        if let Some(o) = out.as_object_mut() {
                            o.insert("amount".into(), amount.into());
                        }
                        out
                    }
                }
            }
            Req::OpenMemo { chain_uid, token, from_ua, send_counter, memo, expect } => self.with_sk(|seed32, _| {
                let mut hd = [[0u8; 32]; 20];
                for (i, w) in [(H_CHAIN_UID, *chain_uid), (H_TOKEN, addr(token)), (H_FROM, *from_ua), (H_SEND_COUNTER, u64_word(*send_counter))] {
                    *hd.get_mut(i).ok_or(Error::Argument)? = w;
                }
                let (aud, legs) = pqz_ffi::memo::open(seed32, &hd, memo).ok_or(Error::Argument)?;
                // the opened memo names the entry's legs (no MAC: a memo of another key or entry rebuilds other UAs); compared in
                // constant time (Fable P3-2: the opened UAs come from the key's keystream); the counts are public (the memo's length)
                if let Some((a, uas)) = expect {
                    let same = legs.iter().zip(uas).fold(u8::from(*a).ct_eq(&u8::from(aud)), |c, (l, w)| c & l.1.ct_eq(w));
                    if legs.len() != uas.len() || !bool::from(same) {
                        return Err(Error::Argument);
                    }
                }
                let legs: Vec<Value> = legs.iter().map(|(a, ua)| json!({"amount": a, "ua": to_hex(ua)})).collect();
                Ok(json!({"auditorOn": aud, "legs": legs}))
            })?,
        };
        Ok(out.to_string())
    }

    /// Op 3 `R_REG` over `message` with this key.
    fn register(&self, id: &Word, message: &Word, rnd32: &[u8; 32]) -> Result<Value> {
        let stmt = Stmt::Register(Register { words: [Form::Register.op_tag(), *id, *message], pk: &self.pk })
            .encode()
            .map_err(|_| Error::Argument)?;
        let proof = self.with_sk(|_, sk| prove(Form::Register.op(), &stmt, &Zeroizing::new(wit_key(&sk.0)), rnd32))?;
        let mut v = proved(&stmt, &proof);
        if let Some(o) = v.as_object_mut() {
            o.insert("message".into(), to_hex(message).into());
        }
        Ok(v)
    }

    /// The balance of `t` (this key's `T`) less `debit`, as digits, else `Argument`.
    fn rest(sk: &Sk, t: &[u8], debit: Option<u64>) -> Result<(u64, [u8; 16])> {
        let t: &[u8; CT_BYTES] = t.try_into().map_err(|_| Error::Argument)?;
        let bal = value(pqzl::dec(&sk.0.s, t))?;
        let rest = debit.and_then(|x| bal.checked_sub(x)).ok_or(Error::Argument)?;
        Ok((rest, digits(rest)))
    }

    /// Op 2 (burn, refresh): `Enc(pk_f, balance − debit)` from a fresh seed (CTR-PQZ-19: never the counter's); `memoHash =
    /// keccak256(ownTag)` (3h, the memo empty) or, feature `vectors`, the vector file's word.
    #[allow(clippy::too_many_arguments)]
    fn debit_own(
        &self, seed32: &[u8], sk: &Sk, d: &Draw, form: Form, mut hd: [Word; 20], t: &[u8], debit: Option<u64>, memo_hash: Option<&Word>,
    ) -> Result<Value> {
        system(hd.get(1).ok_or(Error::Argument)?)?;
        let (_, dr) = Self::rest(sk, t, debit)?;
        let seed = Zeroizing::new(match d.seed_enc {
            Some(s) => s,
            None => os32()?,
        });
        let c = Wiped(pqzl::enc(&[&sk.0.pk], &[dr], &seed).ok_or(Error::Argument)?);
        let v_f = c.0.vs.first().ok_or(Error::Argument)?;
        // 3h (proof-path spec C3): `memoHash = keccak256(ownTag)` on a burn, a refresh and an unwrap (the memo is empty)
        let tag = own_tag(seed32, &hd, &c.0.u[..], v_f)?;
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = match memo_hash {
            Some(w) => *w,
            None => crate::keccak256(&tag),
        };
        let st = Debit { form, header: hd, pk_f: &sk.0.pk[..], pk_t: None, pk_a: None, t, u: &c.0.u[..], v_t: None, v_f, v_a: None };
        let stmt = Stmt::Debit(st).encode().map_err(|_| Error::Argument)?;
        let wit = Zeroizing::new(wit_debit(&sk.0, &c.0, &[dr]));
        Ok(with_tag(proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?), &tag))
    }

    /// Op 1: `Enc([pk_t, pk_f, pk_a], [amount, balance − amount − fee, amount])` from CTR-PQZ-19's `seed_enc`; on `HASH` the
    /// sender memo in op 7's encoding with the one leg `(amount, toUA)` (`PqzCore.SEALED` = 42, T36a), on `BUNDLE` none;
    /// `memoHash = keccak256(memo ‖ ownTag)` over `u_0` and `v_f` (3h, `PqzCore._parseTransfer`; T15k, T20d2).
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self, seed32: &[u8], sk: &Sk, d: &Draw, id: &Word, h: &Header, to_ua: &Word, pk_t: &[u8], pk_a: Option<&[u8]>, t: &[u8],
        amount: u64, memo: &Memo,
    ) -> Result<Value> {
        let form = if pk_a.is_some() { Form::Transfer } else { Form::Transfer0 };
        let salt = d.salt()?;
        let mut hd = h.fill(Debit::header(form, id));
        *hd.get_mut(H_TO).ok_or(Error::Argument)? = *to_ua;
        hd.get_mut(H_SALT).ok_or(Error::Argument)?.iter_mut().skip(16).zip(salt).for_each(|(o, b)| *o = b);
        let sealed = match memo {
            Memo::Mode(Mode::Hash) => {
                Some(pqz_ffi::memo::seal(d.memo_key(seed32), &hd, pk_a.is_some(), &[(amount, *to_ua)]).ok_or(Error::Argument)?)
            }
            _ => None,
        };
        let (_, dr) = Self::rest(sk, t, amount.checked_add(h.fee))?;
        let seed = Zeroizing::new(match d.seed_enc {
            Some(s) => s,
            None => seed_enc(seed32, &h.chain_uid, &h.token, &h.from_ua, h.send_counter, &salt)?,
        });
        let dv = digits(amount);
        let mut pks = vec![pk_ref(pk_t)?, &*sk.0.pk];
        let mut msgs = vec![dv, dr];
        if let Some(a) = pk_a {
            pks.push(pk_ref(a)?);
            msgs.push(dv);
        }
        let c = Wiped(pqzl::enc(&pks, &msgs, &seed).ok_or(Error::Argument)?);
        let v = |i: usize| c.0.vs.get(i).map(|v| &v[..]).ok_or(Error::Argument);
        // 3h (proof-path spec C3): `memoHash = keccak256(memo ‖ ownTag)`, the memo `salt ‖ sealedMemo` on HASH, empty on BUNDLE
        let tag = own_tag(seed32, &hd, &c.0.u[..], v(1)?)?;
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = match memo {
            #[cfg(feature = "vectors")]
            Memo::Given(w) => *w,
            Memo::Mode(_) => crate::keccak256(&[sealed.as_deref().unwrap_or_default(), &tag[..]].concat()),
        };
        let st = Debit {
            form,
            header: hd,
            pk_f: &sk.0.pk[..],
            pk_t: Some(pk_t),
            pk_a,
            t,
            u: &c.0.u[..],
            v_t: Some(v(0)?),
            v_f: v(1)?,
            v_a: pk_a.map(|_| v(2)).transpose()?,
        };
        let stmt = Stmt::Debit(st).encode().map_err(|_| Error::Argument)?;
        let wit = Zeroizing::new(wit_debit(&sk.0, &c.0, &[dv, dr]));
        let mut v = with_tag(proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?), &tag);
        if let (Some(o), Some(m)) = (v.as_object_mut(), sealed) {
            o.insert("memo".into(), to_hex(&m).into());
        }
        Ok(v)
    }

    /// Op 7: `pqzl::enc_multi` from CTR-PQZ-19's `seed_enc`, `recipientsHash` over the legs' UAs; on `HASH` the sender memo
    /// `salt ‖ sealedMemo` under `seed32`, on `BUNDLE` none; `memoHash = keccak256(memo ‖ ownTag)` over `u_0` and `v_f` (3h) or,
    /// feature `vectors`, the vector file's word.
    #[allow(clippy::too_many_arguments)]
    fn multi(
        &self, seed32: &[u8], sk: &Sk, d: &Draw, id: &Word, h: &Header, legs: &[(Vec<u8>, Word, u64)], pk_a: Option<&[u8]>, t: &[u8],
        mode: Mode, memo_hash: Option<&Word>,
    ) -> Result<Value> {
        let (m, aud) = (legs.len(), pk_a.is_some());
        if !built_legs(id).contains(&m) {
            return Err(Error::Argument);
        }
        let total = legs.iter().try_fold(h.fee, |a, l| a.checked_add(l.2));
        let (_, df) = Self::rest(sk, t, total)?;
        let salt = d.salt()?;
        let mut hd = h.fill(Multi::header(id, m, aud));
        *hd.get_mut(H_RECIPIENTS_HASH).ok_or(Error::Argument)? = crate::keccak256(&legs.iter().flat_map(|l| l.1).collect::<Vec<u8>>());
        hd.get_mut(H_SALT).ok_or(Error::Argument)?.iter_mut().skip(16).zip(salt).for_each(|(o, b)| *o = b);
        let memo_legs: Vec<(u64, Word)> = legs.iter().map(|l| (l.2, l.1)).collect();
        let memo_key = d.memo_key(seed32);
        let memo = match mode {
            Mode::Hash => Some(pqz_ffi::memo::seal(memo_key, &hd, aud, &memo_legs).ok_or(Error::Argument)?),
            Mode::Bundle => None,
        };
        let seed = Zeroizing::new(match d.seed_enc {
            Some(s) => s,
            None => seed_enc(seed32, &h.chain_uid, &h.token, &h.from_ua, h.send_counter, &salt)?,
        });
        let d_legs: Vec<[u8; 16]> = legs.iter().map(|l| digits(l.2)).collect();
        let enc_legs: Vec<(&[u8; PK_BYTES], [u8; 16])> = legs.iter().zip(&d_legs).map(|(l, dl)| Ok((pk_ref(&l.0)?, *dl))).collect::<Result<_>>()?;
        let pk_a_ref = pk_a.map(pk_ref).transpose()?;
        let c = WipedMulti(pqzl::enc_multi(&sk.0.pk, df, &enc_legs, pk_a_ref, &seed).ok_or(Error::Argument)?);
        // 3h (proof-path spec C3): `memoHash = keccak256(memo ‖ ownTag)` over `u_0` and `v_f`, the memo empty on BUNDLE
        let tag = own_tag(seed32, &hd, &c.0.groups.first().ok_or(Error::Argument)?.u[..], &c.0.v_f[..])?;
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = match memo_hash {
            Some(w) => *w,
            None => crate::keccak256(&[memo.as_deref().unwrap_or_default(), &tag[..]].concat()),
        };
        let pks = legs.iter().flat_map(|l| l.0.iter().copied()).collect::<Vec<u8>>();
        let us = c.0.groups.iter().flat_map(|g| g.u.iter().copied()).collect::<Vec<u8>>();
        let (vs, v_as) = (c.0.v.concat(), c.0.v_a.concat());
        let st = Multi {
            header: hd,
            m,
            pk_f: &sk.0.pk[..],
            pks: &pks,
            pk_a,
            t,
            us: &us,
            vs: &vs,
            v_f: &c.0.v_f,
            v_as: aud.then_some(&v_as[..]),
        };
        let stmt = st.encode().map_err(|_| Error::Argument)?;
        let wit = Zeroizing::new(wit_multi(&sk.0, &c.0, &d_legs, df));
        let mut v = with_tag(proved(&stmt, &prove(pqz_ffi::stmt::OP_TRANSFER_MULTI, &stmt, &wit, &d.rnd32)?), &tag);
        if let (Some(o), Some(memo)) = (v.as_object_mut(), memo) {
            o.insert("memo".into(), to_hex(&memo).into());
        }
        Ok(v)
    }

    /// Op 4 `SENDER_S` of leg 0 of an op 1 transfer (`multi` `None`, `aud` its auditorOn) or leg `j` of an op 7 transfer of `M`
    /// legs (`multi` `Some((M, j))`) from a caller's statement (feature `vectors`, the vector files' rows): `r, e1, e2_t`
    /// re-derived from CTR-PQZ-19's `seed_enc` (the transfer's `fromUA`, `sendCounter`, `salt`; `chainUid` and `token` from the
    /// statement), checked against the statement's `u` and `v`.
    #[cfg(feature = "vectors")]
    #[allow(clippy::too_many_arguments)]
    fn disclose_sender(
        &self, seed32: &[u8], d: &Draw, stmt: &[u8], s: &Disclose<'_>, from_ua: &Word, send_counter: u64, salt: &[u8; 16],
        aud: bool, multi: Option<(usize, usize)>,
    ) -> Result<Value> {
        let Disclose { words, pk: pk_t, u, v, .. } = s.clone();
        let seed = self.sender_seed(seed32, d, &words, from_ua, send_counter, salt)?;
        let (mut c, i) = self.sender_enc(&seed, pk_t, aud, multi, &words, digits(s.amount()))?;
        // Fable P3-1: the re-derived `u`, `v` against the statement's in constant time (`subtle`)
        let v_eq = c.0.vs.get(i).map_or(Choice::from(0), |x| x[..].ct_eq(v));
        if !bool::from(c.0.u[..].ct_eq(u) & v_eq) {
            return Err(Error::Argument);
        }
        c.0.e2.swap(0, i);
        let wit = Zeroizing::new(wit_ds(&c.0));
        Ok(proved(stmt, &prove(Form::DiscloseSender.op(), stmt, &wit, &d.rnd32)?))
    }

    /// Op 4 `SENDER_S` of leg `j` of the handle's own entry, rebuilt from its words (T15l, Fable P2-1; spec no-decryption-oracle
    /// §4.6): `r, e1, e2_j` re-derived from CTR-PQZ-19's `seed_enc` (`fromUA`, `sendCounter`, the blob's salt; `chainUid` and
    /// `token` the location's) by encrypting zero to the leg owner's registered key; the amount is the entry's own, read from the
    /// leg's `v` less that encryption (`Δ·digit` per coefficient, never a caller's guess); the leg's `u` and `v` must equal the
    /// re-derivation at that amount (constant time), else `Argument`. An `M = 1` entry is op 1's or op 7's (one shape, and one
    /// re-derivation: op 1 is op 7's encryption with `M = 1`, group 0's seed `seed_enc`). Group 3g's additive recovery (KV-11):
    /// `u` depends on no recipient key, so it is checked once (another version of the sender: `Argument` before any leg key),
    /// then each of the leg owner's keys `pk_ts` on its own; the first whose `v` matches is the leg's version. Then the
    /// statement (`pk` that key, `u`, `v` the leg's) and its proof: `{stmt, proof, amount, legKey}` (`legKey` its index).
    #[allow(clippy::too_many_arguments)]
    fn disclose_sender_leg(
        &self, seed32: &[u8], d: &Draw, mut words: [Word; DISC_WORDS], pk_ts: &[Vec<u8>], ct: &[u8], from_ua: &Word, send_counter: u64,
        salt: &[u8; 16], aud: bool, m: usize, j: usize,
    ) -> Result<Value> {
        let seed = self.sender_seed(seed32, d, &words, from_ua, send_counter, salt)?;
        let (u, v) = ct.split_at(PK_BYTES);
        let mut found = None;
        for (x, pk_t) in pk_ts.iter().enumerate() {
            #[cfg(feature = "vectors")]
            SENDER_TRIALS.with(|n| n.set(n.get() + 1));
            let (c, i) = self.sender_enc(&seed, pk_t, aud, Some((m, j)), &words, [0; 16])?;
            if x == 0 && !bool::from(c.0.u[..].ct_eq(u)) {
                return Err(Error::Argument);
            }
            let (amount, v_eq) = sender_amount(v, c.0.vs.get(i).ok_or(Error::Argument)?);
            if bool::from(v_eq) {
                found = Some((x, pk_t, c, i, amount));
                break;
            }
        }
        let (x, pk_t, mut c, i, amount) = found.ok_or(Error::Argument)?;
        *words.get_mut(DW_AMOUNT).ok_or(Error::Argument)? = u64_word(amount);
        let stmt = Stmt::Disclose(Disclose { form: Form::DiscloseSender, words, pk: pk_t, u, v }).encode().map_err(|_| Error::Argument)?;
        c.0.e2.swap(0, i);
        let wit = Zeroizing::new(wit_ds(&c.0));
        let mut out = proved(&stmt, &prove(Form::DiscloseSender.op(), &stmt, &wit, &d.rnd32)?);
        if let Some(o) = out.as_object_mut() {
            o.insert("amount".into(), amount.into());
            o.insert("legKey".into(), x.into());
        }
        Ok(out)
    }

    /// CTR-PQZ-19's `seed_enc` of the sender's transfer named by op 4's `words` (`chainUid` word 3, `token` word 4).
    fn sender_seed(
        &self, seed32: &[u8], d: &Draw, words: &[Word; DISC_WORDS], from_ua: &Word, send_counter: u64, salt: &[u8; 16],
    ) -> Result<Zeroizing<[u8; 32]>> {
        let (chain_uid, token) = (words.get(3).ok_or(Error::Argument)?, words.get(4).ok_or(Error::Argument)?);
        let token: [u8; 20] = token.get(12..).and_then(|t| t.try_into().ok()).ok_or(Error::Argument)?;
        Ok(Zeroizing::new(match d.seed_enc {
            Some(x) => x,
            None => seed_enc(seed32, chain_uid, &token, from_ua, send_counter, salt)?,
        }))
    }

    /// The sender's re-encryption of the transfer's leg: op 1 (`multi` `None`: `[pk_t, pk_f, (pk_a)]`, leg 0) or op 7 group
    /// `j / per` (`multi` `Some((M, j))`), `dv` at the leg, zero elsewhere; this handle's `pk` stands in for the other recipients
    /// (the randomness does not depend on them). The encryption and the leg's index in it.
    fn sender_enc(
        &self, seed: &[u8; 32], pk_t: &[u8], aud: bool, multi: Option<(usize, usize)>, words: &[Word; DISC_WORDS], dv: [u8; 16],
    ) -> Result<(Wiped, usize)> {
        let id = system(words.get(1).ok_or(Error::Argument)?)?;
        let own = pk_ref(&self.pk)?;
        Ok(match multi {
            None => {
                let n = 2 + aud as usize;
                let pks = [pk_ref(pk_t)?, own, own];
                let msgs = [dv, [0; 16], [0; 16]];
                let (pks, msgs) = (pks.get(..n).ok_or(Error::Argument)?, msgs.get(..n).ok_or(Error::Argument)?);
                (Wiped(pqzl::enc(pks, msgs, seed).ok_or(Error::Argument)?), 0)
            }
            Some((m, j)) => {
                if !built_legs(&id).contains(&m) || j >= m {
                    return Err(Error::Argument);
                }
                let per = legs_per_group(aud);
                let (g, lo) = (j / per, j / per * per);
                let (n, i) = ((lo + per).min(m) - lo, j - lo);
                let mut pks: Vec<&[u8; PK_BYTES]> = (0..n).map(|k| if k == i { pk_ref(pk_t) } else { Ok(own) }).collect::<Result<_>>()?;
                if g == 0 {
                    pks.push(own);
                }
                let mut win = vec![0u8; pks.len()];
                if aud {
                    pks.extend(std::iter::repeat_n(own, n));
                    win.extend((0..n).map(|w| w as u8));
                }
                let mut msgs = vec![[0u8; 16]; pks.len()];
                *msgs.get_mut(i).ok_or(Error::Argument)? = dv;
                (Wiped(pqzl::enc_win(&pks, Some(&win), &msgs, &pqzl::enc_group_seed(seed, g)).ok_or(Error::Argument)?), i)
            }
        })
    }

    fn cache_key(seed32: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let k = hkdf_sha256(seed32, &[], CACHE_INFO, 32)?;
        Ok(Zeroizing::new(k.as_slice().try_into().map_err(|_| Error::Argument)?))
    }

    fn cache_aad() -> Vec<u8> {
        [b"pqz-cache:", pqz_ffi::stmt::SET.as_bytes()].concat()
    }

    fn seal_box(&self, entries: &[u8], iv: &[u8; 12]) -> Result<String> {
        if entries.len() > crate::wallet::MAX_PT {
            return Err(Error::Argument);
        }
        let ct = self.secret.with(|s| aead_seal(Alg::Aes256Gcm, &*Self::cache_key(s)?, iv, &Self::cache_aad(), entries))??;
        Ok(json!({"iv": Base64UrlUnpadded::encode_string(iv), "ct": Base64UrlUnpadded::encode_string(&ct)}).to_string())
    }

    /// The balance-cache box `{iv, ct}` of `entries` (the caller's bytes, at most 1 MiB) under this key, a fresh iv.
    pub fn seal_balance_cache(&self, entries: &[u8]) -> Result<String> {
        let mut iv = [0u8; 12];
        OsRng.try_fill_bytes(&mut iv).map_err(|_| Error::Rng)?;
        self.seal_box(entries, &iv)
    }

    /// The entries of a box; `Argument` for a box that is not `{iv, ct}` (base64url, a 12-byte iv), `Aead` for one that does
    /// not open under this key and set (an empty cache).
    pub fn open_balance_cache(&self, box_json: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let Value::Object(o) = bounded::json(box_json, BOX_MAX, BOX_DEPTH)? else { return Err(Error::Argument) };
        let field = |k: &str| o.get(k).and_then(Value::as_str).and_then(|s| Base64UrlUnpadded::decode_vec(s).ok()).ok_or(Error::Argument);
        if o.len() != 2 {
            return Err(Error::Argument);
        }
        let iv: [u8; 12] = field("iv")?.try_into().map_err(|_| Error::Argument)?;
        let ct = field("ct")?;
        self.secret.with(|s| aead_open(Alg::Aes256Gcm, &*Self::cache_key(s)?, &iv, &Self::cache_aad(), &ct))?
    }
}

/// Test-only (feature `vectors`, never in a release build): pqz-core's vector keys and randomness.
#[cfg(feature = "vectors")]
impl PqzKey {
    /// A handle over `seed32` in a store of its own (the vector files key by KeyGen seed).
    pub fn vectors_from_seed32(seed32: &[u8; 32]) -> Result<PqzKey> {
        let pk = keygen(seed32)?.0.pk.to_vec();
        Ok(PqzKey { account: 0, index: 0, pk, secret: SecretStore::single(seed32)?, session: Default::default() })
    }
    /// [`PqzKey::call`] at the given randomness.
    pub fn vectors_call(&self, cmd: &str, request_json: &[u8], d: &Draw) -> Result<String> {
        self.run(&PqzCmd::from_json(cmd, request_json)?, d)
    }
    /// Op 3 over a given `message` (the vector files' `R_REG` is the self-test's): `(stmt, proof)`.
    pub fn vectors_register_message(&self, id: &Word, message: &Word, rnd32: &[u8; 32]) -> Result<(Vec<u8>, Vec<u8>)> {
        let v = self.register(&system(id)?, message, rnd32)?;
        let get = |k: &str| v.get(k).and_then(Value::as_str).and_then(from_hex).ok_or(Error::Argument);
        Ok((get("stmt")?, get("proof")?))
    }
    /// [`PqzKey::seal_balance_cache`] at a given iv.
    pub fn vectors_seal_balance_cache(&self, entries: &[u8], iv: &[u8; 12]) -> Result<String> {
        self.seal_box(entries, iv)
    }
}
