// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Feature `pqz` (ua-rs-sign T15; spec §10.2, §8.2, §8.4, §9.3): the PQZ facade over `pqz-core/ffi` (feature `prove`, the Rust
//! PQZL backend; PQZH where the set has it). One parameter set per build (`pqz-set-<set>` → pqz-ffi `set-<set>`).
//!
//! - **Key.** [`crate::wallet::Wallet::pqz_key`]: `seed32 = HKDF-SHA256(seed, "scaas.ua.pq.v1", utf8("scaas.ua.pqz-mlwe.v1") ‖
//!   be32(account) ‖ be32(index))` (CTR-PQZ-13) into the wallet's arena; the handle holds the store, its generation and the slot
//!   (no secret bytes) and the public `pk`. Every secret operation rebuilds `s`, `e` by `pqzl::keygen(seed32)` under the store's
//!   read guard (wiped on drop), so `lock()` revokes the handle (`KeyRevoked`, for good; spec §8.2).
//!   [`crate::wallet::Wallet::export_pqz_leaf_raw`] is the one export of `seed32` (marker [`AllowSecretExport`]).
//! - **Set.** [`pqz_set`] names this build's set, `PK` length and `proofSystemId`s; [`check_set`] compares a token's deployed
//!   `PqzSet` with it, and every proving command names the token's `proofSystemId`: another set's is `PqzSetMismatch`.
//! - **Commands** ([`COMMANDS`], [`PqzKey::call`]; a release build has only `enc`, `proveRegister`, `proveKeyRecord` and
//!   `proveDiscloseSender`, ARCH-POS-13, the rest is feature `vectors` until T15e): named-field JSON (bounded reader, 1 MiB, depth 8), each field on its
//!   command's allow-list (so no `key`, `seed32`, `s`, `e` or witness field passes, at any depth: the only nested objects are
//!   the legs `{pk, ua, amount}`), parsed into typed values. `enc` (`pqzl::enc`), `dec` (`dec` / `dec_win`), the proofs
//!   `proveRegister` / `proveKeyRecord` (op 3 `R_REG` over `pqz_reg_message` / the `setPqzKey` message), `proveTransfer`
//!   (op 1, `R_TX` / `R_TX0`), `proveBurn`, `proveRefresh` (op 2), `proveTransferMulti` (op 7; an explicit `mode`, `HASH`
//!   with the sender memo `memo::seal` under `seed32` and `memoHash = keccak256(salt ‖ sealedMemo)`, `BUNDLE` with neither,
//!   as `PqzCore._parseMulti`; owner 2026-11-06), `proveDiscloseSender` (op 4, `r, e1, e2_t` re-derived), `proveDisclose` (op 5, receiver or
//!   auditor), `openMemo`. Statements are `pqz-stmt`'s builders, witnesses pqz-ffi's layouts (`fixture::wit_*`), proofs
//!   `pqz_ffi::prove` with `rnd32` from the OS RNG (hedged, CTR-PQZ-19). The debit's balance is `Dec(T)` with the handle's key.
//! - **Encryption randomness** (CTR-PQZ-19): a transfer (op 1, op 7) draws a fresh 16-byte `salt` and encrypts from
//!   `seed_enc = HKDF-SHA256(seed32, "SCAAS-PQZ-ENC-V2", chainUid ‖ token(20) ‖ fromUA ‖ be32(sendCounter) ‖ salt)`, so the
//!   sender re-derives it for `SENDER_S`; burn and refresh encrypt from a fresh OS-RNG seed.
//! - **Balance cache** (as §10.1's box): AES-256-GCM under `HKDF-SHA256(seed32, no salt, "scaas-pqz-balance-cache-v1", 32)`,
//!   AAD `pqz-cache:<set>`, the box `{iv, ct}` in unpadded base64url.
//!
//! Not exposed: the verifiers, the precompile, the self-test, `test-hooks`, `fuzz`, the C core (spec §10). Op 1's sender memo
//! (CTR-PQZ-23's 57-byte form) is not in pqz-core: `proveTransfer` takes `memoHash` as given. The fixed-randomness entry points
//! exist only under feature `vectors`. Residual (spec §8.2): pqz-core's copies of `seed32`, `s`, `e` and the witness on its
//! worker thread and in the prover. UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing, clippy::disallowed_methods)]

use crate::wallet::{aead_open, aead_seal, bounded, from_hex, hkdf_sha256, to_hex, Alg, Error, Handle, KeyId, Result, SecretStore};
use base64ct::{Base64UrlUnpadded, Encoding};
use hkdf::Hkdf;
use pqz_ffi::fixture::{wit_debit, wit_ds, wit_key, wit_multi};
use pqz_ffi::pqzl::{self, Key, CT_BYTES, PK_BYTES};
use pqz_ffi::selftest::digits;
use pqz_ffi::stmt::{
    built_legs, check_ct, check_pk, legs_per_group, parse, u64_word, Debit, Disclose, Form, Multi, Register, Stmt, Word,
    H_AMOUNT, H_BENEFICIARY, H_CHAIN_ID, H_CHAIN_UID, H_ENVELOPE, H_FEE, H_FROM, H_MEMO_HASH, H_PLAIN_USED, H_P, H_RECIPIENT,
    H_RECIPIENTS_HASH, H_REGISTRY, H_SALT, H_SEND_COUNTER, H_TO, H_TOKEN, H_VALID_UNTIL, PQZH_ID, PQZL_ID,
};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Map, Value};
use sha2::Sha256;
use std::sync::Arc;
use zeroize::{Zeroize, Zeroizing};

// one parameter set per build (owner 2026-10-21): pqz-stmt refuses two, and silently takes n2048-kmax1024 for none
const _: () = assert!(
    crate::build::PQZ_SETS[0] as u8 + crate::build::PQZ_SETS[1] as u8 + crate::build::PQZ_SETS[2] as u8 + crate::build::PQZ_SETS[3] as u8
        == 1,
    "feature pqz needs exactly one pqz-set-<set> feature"
);

/// The PQZ key's tag (CTR-PQZ-13): `utf8` in the HKDF info, as every PQ seed.
pub const TAG: &str = "scaas.ua.pqz-mlwe.v1";
/// The command JSON's caps (spec §9.3).
pub const CMD_MAX: usize = 1 << 20;
pub const CMD_DEPTH: usize = 8;
/// The balance-cache box JSON's caps: `{iv, ct}` of a plaintext up to [`crate::wallet::MAX_PT`] (1 MiB) in base64url.
pub const BOX_MAX: usize = 2 << 20;
pub const BOX_DEPTH: usize = 1;
/// The longest answer of [`PqzKey::call`]: a statement and its proof fit in the precompile's `MAX_INPUT` (in hex: twice),
/// plus the memo (at most 18 + 40·8 bytes), the `R_REG` message and the JSON. A proof's length varies from build to build
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
/// ARCH-POS-13 ("never a decryption oracle", owner 2026-11-06; spec no-decryption-oracle §4.1, T15c): a release build (no
/// feature `vectors`) has no command that decrypts or opens a ciphertext, statement or `T` its caller chose: `dec`,
/// `proveTransfer`, `proveBurn`, `proveRefresh`, `proveTransferMulti`, `proveDisclose` and `openMemo` exist only under the test
/// feature `vectors` (the vector files feed `T` and `ct`) until they take proven state (T15e). In a release build they are
/// unknown commands (`Argument`, before the key is touched). Kept: `enc` (public), `proveRegister`, `proveKeyRecord` (own key)
/// and `proveDiscloseSender` (decrypts nothing: a re-derivation compared with the statement).
pub const COMMANDS: &[&str] = &[
    "enc",
    #[cfg(feature = "vectors")]
    "dec",
    "proveRegister",
    "proveKeyRecord",
    #[cfg(feature = "vectors")]
    "proveTransfer",
    #[cfg(feature = "vectors")]
    "proveBurn",
    #[cfg(feature = "vectors")]
    "proveRefresh",
    #[cfg(feature = "vectors")]
    "proveTransferMulti",
    "proveDiscloseSender",
    #[cfg(feature = "vectors")]
    "proveDisclose",
    #[cfg(feature = "vectors")]
    "openMemo",
];

/// The debit header fields a caller gives (the facade sets opTag, the id, `auditorOn`, `salt` and what it computes).
const HEADER: &[&str] =
    &["chainId", "token", "registry", "fromUA", "beneficiaryUA", "fee", "sendCounter", "p", "validUntilBlock", "plainUsed", "chainUid", "envelopeBinding"];
const LEG: &[&str] = &["pk", "ua", "amount"];

/// The allow-list of `cmd`'s fields.
fn allowed(cmd: &str, field: &str) -> bool {
    let has = |l: &[&str]| l.contains(&field);
    match cmd {
        "enc" => has(&["pks", "values"]),
        "dec" => has(&["ct", "window"]),
        "proveRegister" => has(&["proofSystemId", "kind", "ua", "kemPk"]),
        "proveKeyRecord" => has(&["proofSystemId", "ua"]),
        "proveTransfer" => has(HEADER) || has(&["proofSystemId", "toUA", "pkT", "pkA", "T", "amount", "memoHash"]),
        "proveBurn" => has(HEADER) || has(&["proofSystemId", "amount", "recipient", "T", "memoHash"]),
        "proveRefresh" => has(HEADER) || has(&["proofSystemId", "T", "memoHash"]),
        "proveTransferMulti" => has(HEADER) || has(&["proofSystemId", "legs", "pkA", "T", "mode"]),
        "proveDiscloseSender" => has(&["stmt", "fromUA", "sendCounter", "salt", "auditorOn", "M", "leg"]),
        "proveDisclose" => field == "stmt",
        "openMemo" => has(&["chainUid", "token", "fromUA", "sendCounter", "memo"]),
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
    fn pk(&self, k: &str) -> Result<Vec<u8>> {
        pk(hex(self.get(k)?)?)
    }
    fn opt_pk(&self, k: &str) -> Result<Option<Vec<u8>>> {
        self.has(k).then(|| self.pk(k)).transpose()
    }
    fn ct(&self, k: &str) -> Result<Vec<u8>> {
        let b = self.bytes(k)?;
        check_ct(&b).map_err(|_| Error::Argument)?;
        Ok(b)
    }
    fn header(&self) -> Result<Header> {
        Ok(Header {
            chain_id: self.u64("chainId")?,
            token: self.arr("token")?,
            registry: self.arr("registry")?,
            from_ua: self.word("fromUA")?,
            beneficiary_ua: if self.has("beneficiaryUA") { self.word("beneficiaryUA")? } else { [0; 32] },
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
/// (commit-reveal) keeps the sender memo and its `memoHash`, `BUNDLE` has no memo and `memoHash` 0 (`PqzCore._parseMulti`).
/// The token's `disclosureMode` decides which one a caller may use; the facade does not guess it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Hash,
    Bundle,
}

/// The typed request of a command.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Req {
    Enc { pks: Vec<Vec<u8>>, values: Vec<u64> },
    Dec { ct: Vec<u8>, window: usize },
    Register { id: Word, kind: u16, ua: Word, kem_pk: Option<Vec<u8>> },
    KeyRecord { id: Word, ua: Word },
    Transfer { id: Word, h: Header, to_ua: Word, pk_t: Vec<u8>, pk_a: Option<Vec<u8>>, t: Vec<u8>, amount: u64, memo_hash: Word },
    Burn { id: Word, h: Header, amount: u64, recipient: Word, t: Vec<u8>, memo_hash: Word },
    Refresh { id: Word, h: Header, t: Vec<u8>, memo_hash: Word },
    Multi { id: Word, h: Header, legs: Vec<(Vec<u8>, Word, u64)>, pk_a: Option<Vec<u8>>, t: Vec<u8>, mode: Mode },
    DiscloseSender { stmt: Vec<u8>, from_ua: Word, send_counter: u64, salt: [u8; 16], aud: bool, multi: Option<(usize, usize)> },
    Disclose { stmt: Vec<u8> },
    OpenMemo { chain_uid: Word, token: [u8; 20], from_ua: Word, send_counter: u64, memo: Vec<u8> },
}

fn req(cmd: &str, f: &Fields<'_>) -> Result<Req> {
    Ok(match cmd {
        "enc" => {
            let pks = f.get("pks")?.as_array().ok_or(Error::Argument)?.iter().map(|p| pk(hex(p)?)).collect::<Result<_>>()?;
            let values = f.get("values")?.as_array().ok_or(Error::Argument)?.iter().map(|v| v.as_u64().ok_or(Error::Argument));
            Req::Enc { pks, values: values.collect::<Result<_>>()? }
        }
        "dec" => {
            let window = if f.has("window") { f.u64("window")? } else { 0 };
            Req::Dec { ct: f.ct("ct")?, window: usize::try_from(window).ok().filter(|w| *w < 4).ok_or(Error::Argument)? }
        }
        "proveRegister" => Req::Register {
            id: f.id()?,
            kind: u16::try_from(f.u64("kind")?).map_err(|_| Error::Argument)?,
            ua: f.word("ua")?,
            kem_pk: f.has("kemPk").then(|| f.bytes("kemPk")).transpose()?,
        },
        "proveKeyRecord" => Req::KeyRecord { id: f.id()?, ua: f.word("ua")? },
        "proveTransfer" => Req::Transfer {
            id: f.id()?,
            h: f.header()?,
            to_ua: f.word("toUA")?,
            pk_t: f.pk("pkT")?,
            pk_a: f.opt_pk("pkA")?,
            t: f.ct("T")?,
            amount: f.u64("amount")?,
            memo_hash: f.word("memoHash")?,
        },
        "proveBurn" => Req::Burn {
            id: f.id()?,
            h: f.header()?,
            amount: f.u64("amount")?,
            recipient: f.word("recipient")?,
            t: f.ct("T")?,
            memo_hash: f.word("memoHash")?,
        },
        "proveRefresh" => Req::Refresh { id: f.id()?, h: f.header()?, t: f.ct("T")?, memo_hash: f.word("memoHash")? },
        "proveTransferMulti" => {
            let legs = f.get("legs")?.as_array().ok_or(Error::Argument)?.iter().map(|l| {
                let l = Fields::new(l.as_object().ok_or(Error::Argument)?, LEG)?;
                Ok((l.pk("pk")?, l.word("ua")?, l.u64("amount")?))
            });
            let mode = match f.get("mode")?.as_str() {
                Some("HASH") => Mode::Hash,
                Some("BUNDLE") => Mode::Bundle,
                _ => return Err(Error::Argument),
            };
            Req::Multi { id: f.id()?, h: f.header()?, legs: legs.collect::<Result<_>>()?, pk_a: f.opt_pk("pkA")?, t: f.ct("T")?, mode }
        }
        "proveDiscloseSender" => {
            let multi = match (f.has("M"), f.has("leg")) {
                (false, false) => None,
                (true, true) => Some((
                    usize::try_from(f.u64("M")?).map_err(|_| Error::Argument)?,
                    usize::try_from(f.u64("leg")?).map_err(|_| Error::Argument)?,
                )),
                _ => return Err(Error::Argument),
            };
            Req::DiscloseSender {
                stmt: f.bytes("stmt")?,
                from_ua: f.word("fromUA")?,
                send_counter: f.u64("sendCounter")?,
                salt: f.arr("salt")?,
                aud: f.get("auditorOn")?.as_bool().ok_or(Error::Argument)?,
                multi,
            }
        }
        "proveDisclose" => Req::Disclose { stmt: f.bytes("stmt")? },
        "openMemo" => Req::OpenMemo {
            chain_uid: f.word("chainUid")?,
            token: f.arr("token")?,
            from_ua: f.word("fromUA")?,
            send_counter: f.u64("sendCounter")?,
            memo: f.bytes("memo")?,
        },
        _ => return Err(Error::Argument),
    })
}

/// A PQZ command as the facade runs it: its name, its fields (each on the command's allow-list) and their typed values.
/// Public data only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqzCmd {
    cmd: &'static str,
    v: Map<String, Value>,
    req: Req,
}

impl PqzCmd {
    /// `json` (at most [`CMD_MAX`] bytes, depth [`CMD_DEPTH`], the bounded reader) as command `cmd`: an object whose fields
    /// are all on `cmd`'s allow-list and each of its type; else `Argument` (an unknown command, a `key` or any other field
    /// not on the list, a missing field, a number other than a `u64`, a key or ciphertext of another length or not
    /// canonical) or `PqzSetMismatch` (a `proofSystemId` not of this build).
    pub fn from_json(cmd: &str, json: &[u8]) -> Result<PqzCmd> {
        let cmd = *COMMANDS.iter().find(|c| **c == cmd).ok_or(Error::Argument)?;
        let Value::Object(v) = bounded::json(json, CMD_MAX, CMD_DEPTH)? else { return Err(Error::Argument) };
        if !v.keys().all(|k| allowed(cmd, k)) {
            return Err(Error::Argument);
        }
        let req = req(cmd, &Fields(&v))?;
        Ok(PqzCmd { cmd, v, req })
    }
    pub fn cmd(&self) -> &'static str {
        self.cmd
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
    salt: Option<[u8; 16]>,
    memo_key: Option<[u8; 32]>,
}

impl Draw {
    fn os() -> Result<Draw> {
        Ok(Draw { rnd32: os32()?, seed_enc: None, salt: None, memo_key: None })
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

fn prove(op: u8, stmt: &[u8], wit: &[u8], rnd32: &[u8; 32]) -> Result<Vec<u8>> {
    #[cfg(feature = "vectors")]
    PROVER_CALLS.with(|n| n.set(n.get() + 1));
    pqz_ffi::prove(op, stmt, wit, rnd32).map_err(|_| Error::Argument)
}

#[cfg(feature = "vectors")]
thread_local! {
    static PROVER_CALLS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

/// Test-only (feature `vectors`): how many calls on this thread reached pqz-core's prover. A refusal of the facade's own
/// checks (a balance below the debit, a statement not of this key, a re-derived `u` / `v` that is not the statement's) must
/// come before it, which the prover's own refusal of an unsatisfied witness would hide.
#[cfg(feature = "vectors")]
pub fn vectors_prover_calls() -> usize {
    PROVER_CALLS.with(|n| n.get())
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
    doc = "```"
)]
pub struct PqzKey {
    account: u32,
    index: u32,
    pk: Vec<u8>,
    secret: Handle,
}

impl zeroize::ZeroizeOnDrop for PqzKey {}

fn keygen(seed32: &[u8]) -> Result<Sk> {
    let seed: &[u8; 32] = seed32.try_into().map_err(|_| Error::Argument)?;
    Ok(Sk(pqzl::keygen(seed).ok_or(Error::Argument)?))
}

/// [`crate::wallet::Wallet::pqz_key`].
pub(crate) fn derive(store: &Arc<SecretStore>, account: u32, index: u32) -> Result<PqzKey> {
    use crate::wallet::derive::{hkdf_pq, HARDENED};
    if account >= HARDENED || index >= HARDENED {
        return Err(Error::Argument);
    }
    let (secret, pk) = store.key(KeyId::Pqz(account, index), |seed| {
        let seed32 = hkdf_pq(seed, TAG, account, index, 32)?;
        let pk = keygen(&seed32)?.0.pk.to_vec();
        Ok((seed32, pk))
    })?;
    Ok(PqzKey { account, index, pk, secret })
}

/// A key rebuilt from an `msig`'s k-of-n backup (T16a): `seed32` into `store` by its key hash, only if `pqzl::keygen(seed32)`
/// hashes to `pqz_key_hash` (else `Argument`, nothing stored). Its `account` and `index` are `u32::MAX` (no derivation path).
pub(crate) fn install(store: &Arc<SecretStore>, seed32: &[u8; 32], pqz_key_hash: &[u8; 32]) -> Result<PqzKey> {
    let pk = keygen(seed32)?.0.pk.to_vec();
    if crate::key_hash_of(crate::PQZ_SCHEME, &pk)? != Some(*pqz_key_hash) {
        return Err(Error::Argument);
    }
    let (secret, pk) = store.key(KeyId::PqzHeld(*pqz_key_hash), |_| Ok((Zeroizing::new(seed32.to_vec()), pk)))?;
    Ok(PqzKey { account: u32::MAX, index: u32::MAX, pk, secret })
}

/// The key [`install`] put in `store` under `pqz_key_hash` (`Argument` if it holds none).
pub(crate) fn held(store: &Arc<SecretStore>, pqz_key_hash: &[u8; 32]) -> Result<PqzKey> {
    let (secret, pk) = store.key(KeyId::PqzHeld(*pqz_key_hash), |_| Err(Error::Argument))?;
    Ok(PqzKey { account: u32::MAX, index: u32::MAX, pk, secret })
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
        self.secret.with(|seed32| f(seed32, &keygen(seed32)?))?
    }

    /// Command `cmd` of [`COMMANDS`] on `request_json` (named fields, `0x` hex bytes, `u64` numbers) with this handle's key:
    /// its JSON answer (`enc`: `{u, vs}`; `dec`: `{value}`; a proof: `{stmt, proof}` and `message` (op 3) or `memo` (op 7, `HASH`);
    /// `openMemo`: `{auditorOn, legs: [{amount, ua}]}`). A prover refusal (a balance below amount and fee, a statement that is not
    /// the key's) is `Argument`, no detail.
    pub fn call(&self, cmd: &str, request_json: &[u8]) -> Result<String> {
        self.run(&PqzCmd::from_json(cmd, request_json)?, &Draw::os()?)
    }

    fn run(&self, c: &PqzCmd, d: &Draw) -> Result<String> {
        let out = match &c.req {
            Req::Enc { pks, values } => {
                let (u, vs) = enc(pks, values)?;
                json!({"u": to_hex(&u), "vs": vs.iter().map(|v| to_hex(v)).collect::<Vec<_>>()})
            }
            Req::Dec { ct, window } => {
                let ct: &[u8; CT_BYTES] = ct.as_slice().try_into().map_err(|_| Error::Argument)?;
                json!({"value": self.with_sk(|_, sk| value(pqzl::dec_win(&sk.0.s, ct, *window)))?})
            }
            Req::Register { id, kind, ua, kem_pk } => {
                let message = crate::pqz_reg_message(*kind, ua, &self.pk, kem_pk.as_deref())?;
                self.register(id, &message, &d.rnd32)?
            }
            Req::KeyRecord { id, ua } => {
                let kh = crate::key_hash_of(crate::PQZ_SCHEME, &self.pk)?.ok_or(Error::Argument)?;
                let tag = crate::purpose_tag("pqz-key")?;
                let message = crate::ua_message(crate::PQZ_SCHEME, &tag, &crate::ua8::pqz_key_digest(ua, &kh))?;
                self.register(id, &message, &d.rnd32)?
            }
            Req::Transfer { id, h, to_ua, pk_t, pk_a, t, amount, memo_hash } => {
                self.with_sk(|seed32, sk| self.transfer(seed32, sk, d, id, h, to_ua, pk_t, pk_a.as_deref(), t, *amount, memo_hash))?
            }
            Req::Burn { id, h, amount, recipient, t, memo_hash } => self.with_sk(|_, sk| {
                let mut hd = h.fill(Debit::header(Form::Burn, id));
                *hd.get_mut(H_AMOUNT).ok_or(Error::Argument)? = u64_word(*amount);
                *hd.get_mut(H_RECIPIENT).ok_or(Error::Argument)? = *recipient;
                self.debit_own(sk, d, Form::Burn, hd, t, amount.checked_add(h.fee), memo_hash)
            })?,
            Req::Refresh { id, h, t, memo_hash } => self.with_sk(|_, sk| {
                self.debit_own(sk, d, Form::Refresh, h.fill(Debit::header(Form::Refresh, id)), t, Some(h.fee), memo_hash)
            })?,
            Req::Multi { id, h, legs, pk_a, t, mode } => {
                self.with_sk(|seed32, sk| self.multi(seed32, sk, d, id, h, legs, pk_a.as_deref(), t, *mode))?
            }
            Req::DiscloseSender { stmt, from_ua, send_counter, salt, aud, multi } => {
                stmt_id(stmt)?;
                let Ok(Stmt::Disclose(s)) = parse(Form::DiscloseSender.op(), stmt) else { return Err(Error::Argument) };
                self.with_sk(|seed32, _| self.disclose_sender(seed32, d, stmt, &s, from_ua, *send_counter, salt, *aud, *multi))?
            }
            Req::Disclose { stmt } => {
                stmt_id(stmt)?;
                let Ok(Stmt::Disclose(s)) = parse(Form::DiscloseReceiver.op(), stmt) else { return Err(Error::Argument) };
                if s.pk != &self.pk[..] {
                    return Err(Error::Argument);
                }
                let wit = Zeroizing::new(self.with_sk(|_, sk| Ok(wit_key(&sk.0)))?);
                proved(stmt, &prove(Form::DiscloseReceiver.op(), stmt, &wit, &d.rnd32)?)
            }
            Req::OpenMemo { chain_uid, token, from_ua, send_counter, memo } => self.with_sk(|seed32, _| {
                let mut hd = [[0u8; 32]; 20];
                for (i, w) in [(H_CHAIN_UID, *chain_uid), (H_TOKEN, addr(token)), (H_FROM, *from_ua), (H_SEND_COUNTER, u64_word(*send_counter))] {
                    *hd.get_mut(i).ok_or(Error::Argument)? = w;
                }
                let (aud, legs) = pqz_ffi::memo::open(seed32, &hd, memo).ok_or(Error::Argument)?;
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

    /// Op 2 (burn, refresh): `Enc(pk_f, balance − debit)` from a fresh seed (CTR-PQZ-19: never the counter's).
    #[allow(clippy::too_many_arguments)]
    fn debit_own(&self, sk: &Sk, d: &Draw, form: Form, mut hd: [Word; 20], t: &[u8], debit: Option<u64>, memo_hash: &Word) -> Result<Value> {
        system(hd.get(1).ok_or(Error::Argument)?)?;
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = *memo_hash;
        let (_, dr) = Self::rest(sk, t, debit)?;
        let seed = Zeroizing::new(match d.seed_enc {
            Some(s) => s,
            None => os32()?,
        });
        let c = Wiped(pqzl::enc(&[&sk.0.pk], &[dr], &seed).ok_or(Error::Argument)?);
        let v_f = c.0.vs.first().ok_or(Error::Argument)?;
        let st = Debit { form, header: hd, pk_f: &sk.0.pk[..], pk_t: None, pk_a: None, t, u: &c.0.u[..], v_t: None, v_f, v_a: None };
        let stmt = Stmt::Debit(st).encode().map_err(|_| Error::Argument)?;
        let wit = Zeroizing::new(wit_debit(&sk.0, &c.0, &[dr]));
        Ok(proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?))
    }

    /// Op 1: `Enc([pk_t, pk_f, pk_a], [amount, balance − amount − fee, amount])` from CTR-PQZ-19's `seed_enc`.
    #[allow(clippy::too_many_arguments)]
    fn transfer(
        &self, seed32: &[u8], sk: &Sk, d: &Draw, id: &Word, h: &Header, to_ua: &Word, pk_t: &[u8], pk_a: Option<&[u8]>, t: &[u8],
        amount: u64, memo_hash: &Word,
    ) -> Result<Value> {
        let form = if pk_a.is_some() { Form::Transfer } else { Form::Transfer0 };
        let salt = match d.salt {
            Some(s) => s,
            None => os16()?,
        };
        let mut hd = h.fill(Debit::header(form, id));
        *hd.get_mut(H_TO).ok_or(Error::Argument)? = *to_ua;
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = *memo_hash;
        hd.get_mut(H_SALT).ok_or(Error::Argument)?.iter_mut().skip(16).zip(salt).for_each(|(o, b)| *o = b);
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
        Ok(proved(&stmt, &prove(form.op(), &stmt, &wit, &d.rnd32)?))
    }

    /// Op 7: `pqzl::enc_multi` from CTR-PQZ-19's `seed_enc`, `recipientsHash` over the legs' UAs; on `HASH` the sender memo
    /// `salt ‖ sealedMemo` under `seed32` and `memoHash = keccak256(salt ‖ sealedMemo)`, on `BUNDLE` no memo and `memoHash` 0.
    #[allow(clippy::too_many_arguments)]
    fn multi(
        &self, seed32: &[u8], sk: &Sk, d: &Draw, id: &Word, h: &Header, legs: &[(Vec<u8>, Word, u64)], pk_a: Option<&[u8]>, t: &[u8],
        mode: Mode,
    ) -> Result<Value> {
        let (m, aud) = (legs.len(), pk_a.is_some());
        if !built_legs(id).contains(&m) {
            return Err(Error::Argument);
        }
        let total = legs.iter().try_fold(h.fee, |a, l| a.checked_add(l.2));
        let (_, df) = Self::rest(sk, t, total)?;
        let salt = match d.salt {
            Some(s) => s,
            None => os16()?,
        };
        let mut hd = h.fill(Multi::header(id, m, aud));
        *hd.get_mut(H_RECIPIENTS_HASH).ok_or(Error::Argument)? = crate::keccak256(&legs.iter().flat_map(|l| l.1).collect::<Vec<u8>>());
        hd.get_mut(H_SALT).ok_or(Error::Argument)?.iter_mut().skip(16).zip(salt).for_each(|(o, b)| *o = b);
        let memo_legs: Vec<(u64, Word)> = legs.iter().map(|l| (l.2, l.1)).collect();
        let memo_key: &[u8] = match &d.memo_key {
            Some(k) => k,
            None => seed32,
        };
        let memo = match mode {
            Mode::Hash => Some(pqz_ffi::memo::seal(memo_key, &hd, aud, &memo_legs).ok_or(Error::Argument)?),
            Mode::Bundle => None,
        };
        *hd.get_mut(H_MEMO_HASH).ok_or(Error::Argument)? = memo.as_deref().map_or([0; 32], crate::keccak256);
        let seed = Zeroizing::new(match d.seed_enc {
            Some(s) => s,
            None => seed_enc(seed32, &h.chain_uid, &h.token, &h.from_ua, h.send_counter, &salt)?,
        });
        let d_legs: Vec<[u8; 16]> = legs.iter().map(|l| digits(l.2)).collect();
        let enc_legs: Vec<(&[u8; PK_BYTES], [u8; 16])> = legs.iter().zip(&d_legs).map(|(l, dl)| Ok((pk_ref(&l.0)?, *dl))).collect::<Result<_>>()?;
        let pk_a_ref = pk_a.map(pk_ref).transpose()?;
        let c = WipedMulti(pqzl::enc_multi(&sk.0.pk, df, &enc_legs, pk_a_ref, &seed).ok_or(Error::Argument)?);
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
        let mut v = proved(&stmt, &prove(pqz_ffi::stmt::OP_TRANSFER_MULTI, &stmt, &wit, &d.rnd32)?);
        if let (Some(o), Some(memo)) = (v.as_object_mut(), memo) {
            o.insert("memo".into(), to_hex(&memo).into());
        }
        Ok(v)
    }

    /// Op 4 `SENDER_S` of leg 0 of an op 1 transfer (`multi` `None`, `aud` its auditorOn) or leg `j` of an op 7 transfer of `M`
    /// legs (`multi` `Some((M, j))`): `r, e1, e2_t` re-derived from CTR-PQZ-19's `seed_enc` (the transfer's `fromUA`,
    /// `sendCounter`, `salt`; `chainUid` and `token` from the statement), checked against the statement's `u` and `v`.
    #[allow(clippy::too_many_arguments)]
    fn disclose_sender(
        &self, seed32: &[u8], d: &Draw, stmt: &[u8], s: &Disclose<'_>, from_ua: &Word, send_counter: u64, salt: &[u8; 16],
        aud: bool, multi: Option<(usize, usize)>,
    ) -> Result<Value> {
        let Disclose { words, pk: pk_t, u, v, .. } = s.clone();
        let id = system(words.get(1).ok_or(Error::Argument)?)?;
        let (chain_uid, token) = (words.get(3).ok_or(Error::Argument)?, words.get(4).ok_or(Error::Argument)?);
        let token: [u8; 20] = token.get(12..).and_then(|t| t.try_into().ok()).ok_or(Error::Argument)?;
        let seed = Zeroizing::new(match d.seed_enc {
            Some(x) => x,
            None => seed_enc(seed32, chain_uid, &token, from_ua, send_counter, salt)?,
        });
        let own = pk_ref(&self.pk)?;
        let dv = digits(s.amount());
        let (mut c, i) = match multi {
            None => {
                let n = 2 + aud as usize;
                let pks = [pk_ref(pk_t)?, own, own];
                let msgs = [dv, [0; 16], [0; 16]];
                let (pks, msgs) = (pks.get(..n).ok_or(Error::Argument)?, msgs.get(..n).ok_or(Error::Argument)?);
                (Wiped(pqzl::enc(pks, msgs, &seed).ok_or(Error::Argument)?), 0)
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
                let c = pqzl::enc_win(&pks, Some(&win), &msgs, &pqzl::enc_group_seed(&seed, g)).ok_or(Error::Argument)?;
                (Wiped(c), i)
            }
        };
        if c.0.u[..] != *u || c.0.vs.get(i).map(|x| &x[..]) != Some(v) {
            return Err(Error::Argument);
        }
        c.0.e2.swap(0, i);
        let wit = Zeroizing::new(wit_ds(&c.0));
        Ok(proved(stmt, &prove(Form::DiscloseSender.op(), stmt, &wit, &d.rnd32)?))
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
        Ok(PqzKey { account: 0, index: 0, pk, secret: SecretStore::single(seed32)? })
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
