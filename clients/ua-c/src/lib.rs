// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! C ABI over `scaas-ua`; the header `include/scaas_ua.h` is generated from this file by cbindgen (tests/header.rs).
//! The caller owns every buffer; since ABI 6 (ua-rs-sign T12, spec §9.2) the opaque handles (`ScaasUaWallet`, `ScaasUaKey`,
//! `ScaasUaKemKey`, `ScaasUaLinkSession`, `ScaasUaSeedBackup`; T14: `ScaasUaZetherKey`) are the only Rust allocations that cross it. Every export runs
//! inside `guard` (the one `catch_unwind`; `profile.release` keeps `panic = "unwind"`): a panic never unwinds into C, it is
//! `SCAAS_UA_ERR_INTERNAL` (frost-core's OS-RNG panics included, though no FROST call is exported). Status-returning exports go
//! through `run`, which also sets the thread-local `scaas_ua_last_error` detail; no detail carries an argument (a wallet error is
//! its status name). UNAUDITED.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
use scaas_ua as ua;
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};
use std::{ptr, slice};
use ua::wallet as uw;

/// Bumped on any breaking signature or layout change; compare with `scaas_ua_abi_version()`. 5 -> 6: ua-rs-sign T12.
pub const SCAAS_UA_ABI_VERSION: u32 = 6;

// The shared library never holds the test-only entry points (feature `vectors` of scaas-ua: secrets through hooks, F-01).
const _: () = assert!(!ua::build::VECTORS, "ua-c must not build scaas-ua with feature `vectors`");

/// The result of every fallible call: `SCAAS_UA_OK` or one of `SCAAS_UA_ERR_*`.
pub type ScaasUaStatus = i32;
pub const SCAAS_UA_OK: ScaasUaStatus = 0;
/// "UAKeyData": malformed key data, raw id or fixed-size input.
pub const SCAAS_UA_ERR_KEY_DATA: ScaasUaStatus = 1;
/// "UAIdInNativeSpace"
pub const SCAAS_UA_ERR_ID_IN_NATIVE_SPACE: ScaasUaStatus = 2;
/// "UAKindUnknown"
pub const SCAAS_UA_ERR_KIND_UNKNOWN: ScaasUaStatus = 3;
/// "UAKindNotDerived"
pub const SCAAS_UA_ERR_KIND_NOT_DERIVED: ScaasUaStatus = 4;
/// "UAKindNotNative"
pub const SCAAS_UA_ERR_KIND_NOT_NATIVE: ScaasUaStatus = 5;
/// "UAIdFormat"
pub const SCAAS_UA_ERR_ID_FORMAT: ScaasUaStatus = 6;
/// "UAPurposeUnknown"
pub const SCAAS_UA_ERR_PURPOSE_UNKNOWN: ScaasUaStatus = 7;
/// "UAArgument": NULL where a pointer is required, or a kind-table index out of range.
pub const SCAAS_UA_ERR_ARGUMENT: ScaasUaStatus = 8;
/// "UABuffer": `*out_len` was too small; it now holds the size needed.
pub const SCAAS_UA_ERR_BUFFER: ScaasUaStatus = 9;
/// "UAInternal": a caught panic (a bug).
pub const SCAAS_UA_ERR_INTERNAL: ScaasUaStatus = 10;
/// "UAPqzHolder": a PQZ key given for a kind that may not hold one (only 0x0130-0x0132, 0x0134, 0x0135 and a PQ-eligible msig may).
pub const SCAAS_UA_ERR_PQZ_HOLDER: ScaasUaStatus = 11;
/// "UAKemHolder": a KEM record given for a kind that may not hold one.
pub const SCAAS_UA_ERR_KEM_HOLDER: ScaasUaStatus = 12;
/// "UAKemVersion": a `setKemKey` record of version 0 (version 0 is the `register` key's) or past 2^64 − 1.
pub const SCAAS_UA_ERR_KEM_VERSION: ScaasUaStatus = 13;
/// "UAKemKeyLength": a KEM key that is empty or not 1,601 bytes (scheme byte + key).
pub const SCAAS_UA_ERR_KEM_KEY_LENGTH: ScaasUaStatus = 14;
/// "UAPqzPopHash": a PQZ key without its proof hash (or the reverse), a hash that is not 32 bytes, differs from the proof's
/// or is `keccak256("")`.
pub const SCAAS_UA_ERR_PQZ_POP_HASH: ScaasUaStatus = 15;
/// "UAPqzKeySet": `setPqzKey` on a registration that already has a PQZ key (write-once).
pub const SCAAS_UA_ERR_PQZ_KEY_SET: ScaasUaStatus = 16;
/// "UAKemScheme": the first byte of a KEM key is not an enabled KEM scheme id (only 1; 2 is reserved).
pub const SCAAS_UA_ERR_KEM_SCHEME: ScaasUaStatus = 17;
/// "UAMemberUnknown": an `msig` member's record is needed and was not given: key data alone does not show an `msig` member's eligibility.
/// The `_with` calls read it from `inner`; there it means an `inner` without that member, or one whose entry holds an `msig` (a third level).
pub const SCAAS_UA_ERR_MEMBER_UNKNOWN: ScaasUaStatus = 18;
/// "UAPoP": a registration's `msig` signature is not minimal at both levels: the registry would refuse it, so it is never built.
pub const SCAAS_UA_ERR_POP: ScaasUaStatus = 19;
/// "UAUnauthorized": `scaas_ua_replayed_member_sig`'s stored bytes are not that slot's acceptance, or the index is past the members.
pub const SCAAS_UA_ERR_UNAUTHORIZED: ScaasUaStatus = 20;
// ABI 6 (ua-rs-sign T12, spec §9.2): appended, nothing renumbered. A KEM key asked of a kind that holds none is UAKemHolder (12).
/// "UASealOpen": a seal that does not open with this key, purpose and aad, or a container whose sender signature, `UASig` form or
/// member set does not verify.
pub const SCAAS_UA_ERR_SEAL_OPEN: ScaasUaStatus = 21;
/// "UASealVersion": a seal or container of a version or scheme other than 1.
pub const SCAAS_UA_ERR_SEAL_VERSION: ScaasUaStatus = 22;
/// "UAKemCheck": a KEM input refused by its checks (kemPk scheme, length or modulus, ciphertext length, a small-order X25519 key).
pub const SCAAS_UA_ERR_KEM_CHECK: ScaasUaStatus = 23;
/// "UAAead": an AEAD tag that does not verify; nothing is written.
pub const SCAAS_UA_ERR_AEAD: ScaasUaStatus = 24;
/// "UAVaultOpen": a vault that does not open with this passphrase or PRF secret, or a seed vault whose payload is not BIP-39 entropy.
pub const SCAAS_UA_ERR_VAULT_OPEN: ScaasUaStatus = 25;
/// "UAVaultParams": a pin envelope outside N in {2^15, 2^16, 2^17}, r = 8, p = 1 (refused before scrypt runs).
pub const SCAAS_UA_ERR_VAULT_PARAMS: ScaasUaStatus = 26;
/// "UAVaultVersion": a vault of a version other than 1.
pub const SCAAS_UA_ERR_VAULT_VERSION: ScaasUaStatus = 27;
/// "UARawDigestRefused": `scaas_ua_sign_digest_raw` with a UA key (a UA key signs only the `ua_msg` it builds itself).
pub const SCAAS_UA_ERR_RAW_DIGEST_REFUSED: ScaasUaStatus = 28;
/// "UAPolicyRefused": the typed data is not what `expect_json` says the user confirmed (or `Any` without its opt-in).
pub const SCAAS_UA_ERR_POLICY_REFUSED: ScaasUaStatus = 29;
/// "UAExternalSignature": an external key's signature that does not verify against its key (phase 2; reserved).
pub const SCAAS_UA_ERR_EXTERNAL_SIGNATURE: ScaasUaStatus = 30;
/// "UAWalletLocked": the call needs the wallet's secrets and the wallet is locked.
pub const SCAAS_UA_ERR_WALLET_LOCKED: ScaasUaStatus = 31;
/// "UAKeyRevoked": the handle's wallet was locked or freed after the handle was made, or the link session was used.
pub const SCAAS_UA_ERR_KEY_REVOKED: ScaasUaStatus = 32;
/// "UAContainerSender": a container whose purpose, recipient, sender or key data is not the expected one, an `msig` sender without
/// `accepted_json` or with a signer not accepted, an unknown member key; a backup whose entropy does not derive its sender.
pub const SCAAS_UA_ERR_CONTAINER_SENDER: ScaasUaStatus = 33;
/// "UAContainerReplay": a link container created outside its session's window.
pub const SCAAS_UA_ERR_CONTAINER_REPLAY: ScaasUaStatus = 34;
/// "UABackupRollback": a backup older than the one the current wallet holds, without `scaas_ua_wallet_restore_backup_rollback`.
pub const SCAAS_UA_ERR_BACKUP_ROLLBACK: ScaasUaStatus = 35;
/// "UAWebAuthnAssertion": an assertion that is not the chains' form for the expected challenge, or does not verify.
pub const SCAAS_UA_ERR_WEBAUTHN_ASSERTION: ScaasUaStatus = 36;
/// "UAKindUnavailable": the kind exists but this build lacks it (Falcon without its C build, an external key in a release build,
/// a facade feature off); distinct from SCAAS_UA_ERR_KIND_UNKNOWN.
pub const SCAAS_UA_ERR_KIND_UNAVAILABLE: ScaasUaStatus = 37;
/// "UAWalletMismatch": `scaas_ua_wallet_unlock` with a seed vault (or BIP-39 passphrase) of another wallet; the wallet stays locked.
pub const SCAAS_UA_ERR_WALLET_MISMATCH: ScaasUaStatus = 38;
/// "UARng": the OS random number generator failed.
pub const SCAAS_UA_ERR_RNG: ScaasUaStatus = 39;

/// One row of the kind table. `name` and `group` are static NUL-terminated strings (never freed); `group` is NULL when
/// the kind has no group. `lengths[0..lengths_len]` are the accepted key-data lengths; `lengths_len == 0` means variable
/// length.
#[repr(C)]
pub struct ScaasUaKind {
    pub kind: u16,
    pub native: bool,
    pub lengths_len: u8,
    pub lengths: [u32; 2],
    pub name: *const c_char,
    pub group: *const c_char,
}

/// One `msig` member: `id` is the member's 32-byte UA.
#[repr(C)]
pub struct ScaasUaMember {
    pub kind: u16,
    pub id: [u8; 32],
    pub weight: u16,
}

struct Fail(ScaasUaStatus, String);
type R<T> = Result<T, Fail>;

impl From<ua::UAError> for Fail {
    fn from(e: ua::UAError) -> Self {
        use ua::UAError::*;
        let status = match e {
            KeyData(_) => SCAAS_UA_ERR_KEY_DATA,
            IdInNativeSpace => SCAAS_UA_ERR_ID_IN_NATIVE_SPACE,
            KindUnknown(_) => SCAAS_UA_ERR_KIND_UNKNOWN,
            KindNotDerived(_) => SCAAS_UA_ERR_KIND_NOT_DERIVED,
            KindNotNative(_) => SCAAS_UA_ERR_KIND_NOT_NATIVE,
            IdFormat => SCAAS_UA_ERR_ID_FORMAT,
            PurposeUnknown => SCAAS_UA_ERR_PURPOSE_UNKNOWN,
            PqzHolder(_) => SCAAS_UA_ERR_PQZ_HOLDER,
            KemHolder(_) => SCAAS_UA_ERR_KEM_HOLDER,
            KemVersion => SCAAS_UA_ERR_KEM_VERSION,
            KemKeyLength => SCAAS_UA_ERR_KEM_KEY_LENGTH,
            PqzPopHash => SCAAS_UA_ERR_PQZ_POP_HASH,
            PqzKeySet => SCAAS_UA_ERR_PQZ_KEY_SET,
            KemScheme => SCAAS_UA_ERR_KEM_SCHEME,
            MemberUnknown => SCAAS_UA_ERR_MEMBER_UNKNOWN,
            Pop => SCAAS_UA_ERR_POP,
            Unauthorized => SCAAS_UA_ERR_UNAUTHORIZED,
            NotVerifiable => SCAAS_UA_ERR_INTERNAL, // ua8::check_* only, not exported here
        };
        Fail(status, e.to_string())
    }
}
fn argument(what: &str) -> Fail {
    Fail(SCAAS_UA_ERR_ARGUMENT, format!("UAArgument: {what}"))
}
/// A wallet error: its status, the detail its name alone (`Display` of `uw::Error` never shows an input either).
impl From<uw::Error> for Fail {
    fn from(e: uw::Error) -> Self {
        use uw::Error as E;
        let status = match e {
            E::Ua(e) => return e.into(),
            E::Argument => SCAAS_UA_ERR_ARGUMENT,
            E::KeyRevoked => SCAAS_UA_ERR_KEY_REVOKED,
            E::WalletLocked => SCAAS_UA_ERR_WALLET_LOCKED,
            E::KindUnavailable => SCAAS_UA_ERR_KIND_UNAVAILABLE,
            E::Rng => SCAAS_UA_ERR_RNG,
            E::PolicyRefused => SCAAS_UA_ERR_POLICY_REFUSED,
            E::WebAuthnAssertion => SCAAS_UA_ERR_WEBAUTHN_ASSERTION,
            E::KemHolder => SCAAS_UA_ERR_KEM_HOLDER,
            E::KemCheck => SCAAS_UA_ERR_KEM_CHECK,
            E::Aead => SCAAS_UA_ERR_AEAD,
            E::SealOpen => SCAAS_UA_ERR_SEAL_OPEN,
            E::SealVersion => SCAAS_UA_ERR_SEAL_VERSION,
            E::ContainerSender => SCAAS_UA_ERR_CONTAINER_SENDER,
            E::ContainerReplay => SCAAS_UA_ERR_CONTAINER_REPLAY,
            E::VaultOpen => SCAAS_UA_ERR_VAULT_OPEN,
            E::VaultParams => SCAAS_UA_ERR_VAULT_PARAMS,
            E::VaultVersion => SCAAS_UA_ERR_VAULT_VERSION,
            E::BackupRollback => SCAAS_UA_ERR_BACKUP_ROLLBACK,
            E::WalletMismatch => SCAAS_UA_ERR_WALLET_MISMATCH,
            _ => SCAAS_UA_ERR_INTERNAL, // `#[non_exhaustive]`: a variant added later maps here until it has its status
        };
        fail(status)
    }
}
/// A failure whose detail is the status name.
fn fail(status: ScaasUaStatus) -> Fail {
    Fail(status, status_cstr(status).to_string_lossy().into_owned())
}
impl From<ua::json::JsonError> for Fail {
    fn from(e: ua::json::JsonError) -> Self {
        match e {
            ua::json::JsonError::Argument => argument("JSON"),
            ua::json::JsonError::Ua(e) => e.into(),
        }
    }
}

thread_local! {
    static LAST_ERROR: RefCell<CString> = RefCell::new(CString::default());
}

/// The one `catch_unwind`: a panic becomes `SCAAS_UA_ERR_INTERNAL`.
fn guard<T>(f: impl FnOnce() -> R<T>) -> R<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(Fail(SCAAS_UA_ERR_INTERNAL, "UAInternal: panic".into())))
}
/// A status-returning export: the status, with the detail ("" on success) stored for `scaas_ua_last_error`.
fn run(f: impl FnOnce() -> R<()>) -> ScaasUaStatus {
    let (status, detail) = match guard(f) {
        Ok(()) => (SCAAS_UA_OK, String::new()),
        Err(Fail(status, detail)) => (status, detail),
    };
    let _ = LAST_ERROR.try_with(|e| *e.borrow_mut() = CString::new(detail).unwrap_or_default());
    status
}
/// An infallible export: `fallback` on a panic.
fn safe<T>(fallback: T, f: impl FnOnce() -> T) -> T {
    guard(|| Ok(f())).unwrap_or(fallback)
}

fn arr<'a, const N: usize>(p: *const u8) -> R<&'a [u8; N]> {
    if p.is_null() {
        return Err(argument("NULL"));
    }
    Ok(unsafe { &*p.cast::<[u8; N]>() })
}
/// `len` items at `p`; NULL with `len == 0` is the empty slice.
fn bytes<'a, T>(p: *const T, len: usize) -> R<&'a [T]> {
    if len == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(argument("NULL"));
    }
    Ok(unsafe { slice::from_raw_parts(p, len) })
}
fn put<T>(p: *mut T, value: T) -> R<()> {
    if p.is_null() {
        return Err(argument("NULL"));
    }
    unsafe { p.write(value) };
    Ok(())
}
/// The bytes of a NUL-terminated string; the caller decodes them as UTF-8 and maps a failure per call.
fn cstr<'a>(p: *const c_char) -> R<&'a [u8]> {
    if p.is_null() {
        return Err(argument("NULL"));
    }
    Ok(unsafe { CStr::from_ptr(p) }.to_bytes())
}
/// Variable-size output: `*out_len` is the capacity on entry and the size written (or needed) on return.
fn write_var(out: *mut u8, out_len: *mut usize, b: &[u8]) -> R<()> {
    if out_len.is_null() {
        return Err(argument("NULL"));
    }
    let cap = unsafe { out_len.replace(b.len()) };
    if cap < b.len() {
        return Err(Fail(SCAAS_UA_ERR_BUFFER, format!("UABuffer: need {}", b.len())));
    }
    if b.is_empty() {
        return Ok(()); // an empty output (an empty plaintext) writes nothing: `out` may be NULL
    }
    if out.is_null() {
        return Err(argument("NULL"));
    }
    unsafe { ptr::copy_nonoverlapping(b.as_ptr(), out, b.len()) };
    Ok(())
}
/// `s` NUL-terminated; `*out_len` counts the NUL.
fn write_str(out: *mut c_char, out_len: *mut usize, s: &str) -> R<()> {
    write_var(out.cast(), out_len, CString::new(s).unwrap_or_default().as_bytes_with_nul())
}

fn kind_row(i: usize) -> R<ScaasUaKind> {
    static STRINGS: OnceLock<Vec<(CString, Option<CString>)>> = OnceLock::new();
    let c = |s: &str| CString::new(s).unwrap_or_default();
    let strings = STRINGS.get_or_init(|| ua::KINDS.iter().map(|k| (c(k.name), k.group.map(c))).collect());
    let (k, s) = ua::KINDS.get(i).zip(strings.get(i)).ok_or_else(|| argument("index"))?;
    if k.lengths.len() > 2 {
        return Err(fail(SCAAS_UA_ERR_INTERNAL)); // ScaasUaKind holds two lengths
    }
    let mut lengths = [0u32; 2];
    lengths.iter_mut().zip(k.lengths).for_each(|(d, l)| *d = *l as u32);
    Ok(ScaasUaKind {
        kind: k.kind,
        native: k.native,
        lengths_len: k.lengths.len() as u8,
        lengths,
        name: s.0.as_ptr(),
        group: s.1.as_ref().map_or(ptr::null(), |g| g.as_ptr()),
    })
}

/// The library's `SCAAS_UA_ABI_VERSION`.
#[no_mangle]
pub extern "C" fn scaas_ua_abi_version() -> u32 {
    safe(0, || SCAAS_UA_ABI_VERSION)
}

/// The static code string of a status: "UAOk", "UAKeyData" ... "UAPurposeUnknown" (the vector files' `error` values),
/// "UAArgument", "UABuffer", "UAInternal", "UAPqzHolder", "UAKemHolder", "UAKemVersion", "UAKemKeyLength", "UAPqzPopHash",
/// "UAPqzKeySet", "UAKemScheme", "UAMemberUnknown", "UAPoP", "UAUnauthorized", then (ABI 6) "UA" and the wallet vector files'
/// `error` value: "UASealOpen" ... "UAWalletMismatch", "UARng"; "UAStatusUnknown" for any other value.
#[no_mangle]
pub extern "C" fn scaas_ua_status_name(status: ScaasUaStatus) -> *const c_char {
    safe(c"UAStatusUnknown".as_ptr(), || status_cstr(status).as_ptr())
}

fn status_cstr(status: ScaasUaStatus) -> &'static CStr {
    match status {
        SCAAS_UA_OK => c"UAOk",
        SCAAS_UA_ERR_KEY_DATA => c"UAKeyData",
        SCAAS_UA_ERR_ID_IN_NATIVE_SPACE => c"UAIdInNativeSpace",
        SCAAS_UA_ERR_KIND_UNKNOWN => c"UAKindUnknown",
        SCAAS_UA_ERR_KIND_NOT_DERIVED => c"UAKindNotDerived",
        SCAAS_UA_ERR_KIND_NOT_NATIVE => c"UAKindNotNative",
        SCAAS_UA_ERR_ID_FORMAT => c"UAIdFormat",
        SCAAS_UA_ERR_PURPOSE_UNKNOWN => c"UAPurposeUnknown",
        SCAAS_UA_ERR_ARGUMENT => c"UAArgument",
        SCAAS_UA_ERR_BUFFER => c"UABuffer",
        SCAAS_UA_ERR_INTERNAL => c"UAInternal",
        SCAAS_UA_ERR_PQZ_HOLDER => c"UAPqzHolder",
        SCAAS_UA_ERR_KEM_HOLDER => c"UAKemHolder",
        SCAAS_UA_ERR_KEM_VERSION => c"UAKemVersion",
        SCAAS_UA_ERR_KEM_KEY_LENGTH => c"UAKemKeyLength",
        SCAAS_UA_ERR_PQZ_POP_HASH => c"UAPqzPopHash",
        SCAAS_UA_ERR_PQZ_KEY_SET => c"UAPqzKeySet",
        SCAAS_UA_ERR_KEM_SCHEME => c"UAKemScheme",
        SCAAS_UA_ERR_MEMBER_UNKNOWN => c"UAMemberUnknown",
        SCAAS_UA_ERR_POP => c"UAPoP",
        SCAAS_UA_ERR_UNAUTHORIZED => c"UAUnauthorized",
        SCAAS_UA_ERR_SEAL_OPEN => c"UASealOpen",
        SCAAS_UA_ERR_SEAL_VERSION => c"UASealVersion",
        SCAAS_UA_ERR_KEM_CHECK => c"UAKemCheck",
        SCAAS_UA_ERR_AEAD => c"UAAead",
        SCAAS_UA_ERR_VAULT_OPEN => c"UAVaultOpen",
        SCAAS_UA_ERR_VAULT_PARAMS => c"UAVaultParams",
        SCAAS_UA_ERR_VAULT_VERSION => c"UAVaultVersion",
        SCAAS_UA_ERR_RAW_DIGEST_REFUSED => c"UARawDigestRefused",
        SCAAS_UA_ERR_POLICY_REFUSED => c"UAPolicyRefused",
        SCAAS_UA_ERR_EXTERNAL_SIGNATURE => c"UAExternalSignature",
        SCAAS_UA_ERR_WALLET_LOCKED => c"UAWalletLocked",
        SCAAS_UA_ERR_KEY_REVOKED => c"UAKeyRevoked",
        SCAAS_UA_ERR_CONTAINER_SENDER => c"UAContainerSender",
        SCAAS_UA_ERR_CONTAINER_REPLAY => c"UAContainerReplay",
        SCAAS_UA_ERR_BACKUP_ROLLBACK => c"UABackupRollback",
        SCAAS_UA_ERR_WEBAUTHN_ASSERTION => c"UAWebAuthnAssertion",
        SCAAS_UA_ERR_KIND_UNAVAILABLE => c"UAKindUnavailable",
        SCAAS_UA_ERR_WALLET_MISMATCH => c"UAWalletMismatch",
        SCAAS_UA_ERR_RNG => c"UARng",
        _ => c"UAStatusUnknown",
    }
}

/// The detail of this thread's last status-returning call, e.g. "UAKeyData: length"; "" after a success. Valid until
/// the next `scaas_ua_*` call on the same thread.
#[no_mangle]
pub extern "C" fn scaas_ua_last_error() -> *const c_char {
    safe(c"".as_ptr(), || LAST_ERROR.with(|e| e.borrow().as_ptr()))
}

/// The number of rows in the kind table.
#[no_mangle]
pub extern "C" fn scaas_ua_kind_count() -> usize {
    safe(0, || ua::KINDS.len())
}

/// Row `index` (below `scaas_ua_kind_count()`, else `SCAAS_UA_ERR_ARGUMENT`) of the kind table, in table order.
#[no_mangle]
pub extern "C" fn scaas_ua_kind_at(index: usize, out: *mut ScaasUaKind) -> ScaasUaStatus {
    run(|| {
        put(out, kind_row(index)?)
    })
}

/// The kind-table row of `kind`.
#[no_mangle]
pub extern "C" fn scaas_ua_kind_info(kind: u16, out: *mut ScaasUaKind) -> ScaasUaStatus {
    run(|| {
        let i = ua::KINDS.iter().position(|k| k.kind == kind).ok_or(ua::UAError::KindUnknown(kind))?;
        put(out, kind_row(i)?)
    })
}

#[no_mangle]
pub extern "C" fn scaas_ua_is_native(kind: u16) -> bool {
    safe(false, || ua::is_native(kind))
}

#[no_mangle]
pub extern "C" fn scaas_ua_is_zether(kind: u16) -> bool {
    safe(false, || ua::is_zether(kind))
}

#[no_mangle]
pub extern "C" fn scaas_ua_is_signing(kind: u16) -> bool {
    safe(false, || ua::is_signing(kind))
}

#[no_mangle]
pub extern "C" fn scaas_ua_is_member(kind: u16, hedera_native: bool) -> bool {
    safe(false, || ua::is_member(kind, hedera_native))
}

/// Whether `kind` may hold a PQZ key attribute (mldsa44, mldsa65, fndsa512, mldsa87, fndsa1024).
#[no_mangle]
pub extern "C" fn scaas_ua_is_pqz_holder(kind: u16) -> bool {
    safe(false, || ua::is_pqz_holder(kind))
}

/// `*out = true` iff the `msig` key data is PQ-eligible: its members outside 0x0130-0x0135 weigh less than the threshold. An `msig`
/// member is `SCAAS_UA_ERR_MEMBER_UNKNOWN` here: `scaas_ua_msig_pqz_eligible_with` reads its record.
#[no_mangle]
pub extern "C" fn scaas_ua_msig_pqz_eligible(key_data: *const u8, key_data_len: usize, out: *mut bool) -> ScaasUaStatus {
    scaas_ua_msig_pqz_eligible_with(key_data, key_data_len, ptr::null(), out)
}

// `inner` of the `_with` calls (ua::json::inner_json): NULL is none.
fn inner_of(p: *const c_char) -> R<Vec<([u8; 32], Vec<u8>)>> {
    if p.is_null() {
        return Ok(vec![]);
    }
    Ok(ua::json::inner_json(std::str::from_utf8(cstr(p)?).map_err(|_| argument("JSON"))?)?)
}

/// `scaas_ua_msig_pqz_eligible` with `inner`, the `msig` members' structures: the JSON `{id: keyData}` of `scaas_ua_registration_args`'
/// `inner` (NUL-terminated, bytes as "0x..." hex; NULL, "" or "null" is none; over 65,536 bytes, more than 16 entries or key data over 580
/// bytes is `SCAAS_UA_ERR_ARGUMENT`). An `msig` member is PQ iff it is PQ-eligible itself, read from its entry. A member without an entry,
/// or an entry that holds an `msig` (two levels only), is `SCAAS_UA_ERR_MEMBER_UNKNOWN`.
#[no_mangle]
pub extern "C" fn scaas_ua_msig_pqz_eligible_with(
    key_data: *const u8,
    key_data_len: usize,
    inner: *const c_char,
    out: *mut bool,
) -> ScaasUaStatus {
    run(|| {
        let i = inner_of(inner)?;
        let eligible = ua::msig_pqz_eligible_with(bytes(key_data, key_data_len)?, &ua::json::lookup(&i))?;
        put(out, eligible)
    })
}

/// The 32-byte TAG of a derived kind, or of the PQZ scheme 0x0142.
#[no_mangle]
pub extern "C" fn scaas_ua_tag(kind: u16, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::tag(kind)?))
}

/// The tag string of a derived kind or of the PQZ scheme 0x0142 (NUL-terminated; `*out_len` counts the NUL).
#[no_mangle]
pub extern "C" fn scaas_ua_kind_tag_string(kind: u16, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| write_str(out, out_len, &ua::kind_tag_string(kind)?))
}

/// Governance bit `bit`'s row of `governance_bits.json` (spec 2026-11-02-governance §1.2) as JSON, `{bit, name, type, sentences}`
/// (NUL-terminated; `*out_len` counts the NUL). Bits 0-21; any other bit is `SCAAS_UA_ERR_ARGUMENT` (22-127 free, 128-255 the
/// application's `bitLabel`).
#[no_mangle]
pub extern "C" fn scaas_ua_governance_bit(bit: u8, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| write_str(out, out_len, ua::governance_bit(bit).ok_or_else(|| argument("bit"))?))
}

/// The 32-byte GROUP tag of `group`; `*present = false` (and `out32` untouched) for an unknown or non-UTF-8 group.
#[no_mangle]
pub extern "C" fn scaas_ua_group_tag(group: *const c_char, out32: *mut u8, present: *mut bool) -> ScaasUaStatus {
    run(|| match std::str::from_utf8(cstr(group)?).ok().and_then(ua::group_tag) {
        Some(t) => {
            put(present, true)?;
            put(out32.cast(), t)
        }
        None => put(present, false),
    })
}

/// The group tag string (NUL-terminated); `*present = false` (and `out` untouched) for an unknown or non-UTF-8 group.
#[no_mangle]
pub extern "C" fn scaas_ua_group_tag_string(
    group: *const c_char,
    out: *mut c_char,
    out_len: *mut usize,
    present: *mut bool,
) -> ScaasUaStatus {
    run(|| match std::str::from_utf8(cstr(group)?).ok().and_then(ua::group_tag_string) {
        Some(s) => {
            put(present, true)?;
            write_str(out, out_len, &s)
        }
        None => put(present, false),
    })
}

/// The 32-byte MSG_TAG.
#[no_mangle]
pub extern "C" fn scaas_ua_msg_tag(out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::msg_tag()))
}

/// The 32-byte purpose tag (version 1); a non-UTF-8 purpose is `SCAAS_UA_ERR_PURPOSE_UNKNOWN`.
#[no_mangle]
pub extern "C" fn scaas_ua_purpose_tag(purpose: *const c_char, out32: *mut u8) -> ScaasUaStatus {
    scaas_ua_purpose_tag_v(purpose, 1, out32)
}

/// The 32-byte tag of a purpose version: every purpose is v1, `pop` is also v2 (the portable PoP); any other pair is
/// `SCAAS_UA_ERR_PURPOSE_UNKNOWN`.
#[no_mangle]
pub extern "C" fn scaas_ua_purpose_tag_v(purpose: *const c_char, version: u32, out32: *mut u8) -> ScaasUaStatus {
    run(|| {
        let p = std::str::from_utf8(cstr(purpose)?).map_err(|_| ua::UAError::PurposeUnknown)?;
        put(out32.cast(), ua::purpose_tag_v(p, version)?)
    })
}

/// The 32-byte UA of a derived kind's key data (no member-rule checks; see `scaas_ua_derive_ua`).
#[no_mangle]
pub extern "C" fn scaas_ua_ua_of(kind: u16, key_data: *const u8, key_data_len: usize, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua_of(kind, bytes(key_data, key_data_len)?)?))
}

/// The 32-byte UA after full key-data validation.
#[no_mangle]
pub extern "C" fn scaas_ua_derive_ua(
    kind: u16,
    key_data: *const u8,
    key_data_len: usize,
    hedera_native: bool,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::derive_ua(kind, bytes(key_data, key_data_len)?, hedera_native)?))
}

/// The 32-byte id of a native kind's raw address.
#[no_mangle]
pub extern "C" fn scaas_ua_native_id(kind: u16, raw: *const u8, raw_len: usize, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::native_id(kind, bytes(raw, raw_len)?)?))
}

/// The 32-byte keyHash; `*present = false` (and `out32` untouched) for structure kinds.
#[no_mangle]
pub extern "C" fn scaas_ua_key_hash_of(
    kind: u16,
    key_data: *const u8,
    key_data_len: usize,
    out32: *mut u8,
    present: *mut bool,
) -> ScaasUaStatus {
    run(|| match ua::key_hash_of(kind, bytes(key_data, key_data_len)?)? {
        Some(h) => {
            put(present, true)?;
            put(out32.cast(), h)
        }
        None => put(present, false),
    })
}

/// `SCAAS_UA_OK` when the key data is valid for `kind`.
#[no_mangle]
pub extern "C" fn scaas_ua_validate_key_data(
    kind: u16,
    key_data: *const u8,
    key_data_len: usize,
    hedera_native: bool,
) -> ScaasUaStatus {
    run(|| Ok(ua::validate_key_data(kind, bytes(key_data, key_data_len)?, hedera_native)?))
}

/// Whether the 32-byte id is in the native id space.
#[no_mangle]
pub extern "C" fn scaas_ua_in_native_space(id32: *const u8, out: *mut bool) -> ScaasUaStatus {
    run(|| put(out, ua::in_native_space(arr(id32)?)))
}

/// The 32-byte ua_msg over a 32-byte purpose tag and a 32-byte digest.
#[no_mangle]
pub extern "C" fn scaas_ua_ua_message(
    kind: u16,
    purpose32: *const u8,
    digest32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua_message(kind, arr(purpose32)?, arr(digest32)?)?))
}

/// The 32-byte chain keyHash.
#[no_mangle]
pub extern "C" fn scaas_ua_chain_key_hash(chain_id: u64, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::chain_key_hash(chain_id)))
}

/// `keccak256(data)`: what a member checks its own signature bytes against (`memberSigHashOf`, an `msig`'s `popOf`).
#[no_mangle]
pub extern "C" fn scaas_ua_keccak256(data: *const u8, data_len: usize, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::keccak256(bytes(data, data_len)?)))
}

/// The 32-byte portable EIP-712 domain separator `DS_P` (`EIP712Domain(string name,string version)` = ("SCaaS UA Portable",
/// "1"), no chain id, verifying contract or salt; typed-signing TS-D1). Every portable digest is `keccak256(0x1901 ‖ DS_P ‖ hashStruct)`.
#[no_mangle]
pub extern "C" fn scaas_ua_portable_domain_separator(out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::PORTABLE_DOMAIN_SEPARATOR))
}

/// `hashStruct(UAKemRecord{ua, version, scheme: kem_pk[0], kemPkHash: keccak256(kem_pk)})`: the `kem` word of a portable
/// record. Version 0 with an empty key is the zero record `UAKemRecord{ua, 0, 0, 0}` (no KEM record); version 0 with a key
/// is the `register` key's record (owner 2026-10-31); otherwise the rules of `scaas_ua_kem_record_digest`.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_record_hash(
    ua32: *const u8,
    version: u64,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::kem_record_hash(arr(ua32)?, version, bytes(kem_pk, kem_pk_len)?)?))
}

/// The typed `UAPortableRecord{ua, kind, pqzKeyHash, kem}` digest (what `R_REG` proves over at `register`); every hash input 32
/// bytes, `pqz_key_hash32` all zero without a key, `kem_record_hash32` = `scaas_ua_kem_record_hash` (the zero record's without one).
#[no_mangle]
pub extern "C" fn scaas_ua_portable_record_digest(
    ua32: *const u8,
    kind: u16,
    pqz_key_hash32: *const u8,
    kem_record_hash32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::portable_record_digest(arr(ua32)?, kind, arr(pqz_key_hash32)?, arr(kem_record_hash32)?)))
}

/// The typed `UARegistration{UAPortableRecord{ua, kind, pqzKeyHash, kem}, pqzPopHash}` digest: what the signer's `pop` signs
/// under `ua_message(kind, POP_V2, ·)` and what a native `msig` member signs itself (`eth_signTypedData_v4`, TS-D4).
#[no_mangle]
pub extern "C" fn scaas_ua_registration_digest(
    ua32: *const u8,
    kind: u16,
    pqz_key_hash32: *const u8,
    kem_record_hash32: *const u8,
    pqz_pop_hash32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let d = ua::ua8::registration_digest(arr(ua32)?, kind, arr(pqz_key_hash32)?, arr(kem_record_hash32)?, arr(pqz_pop_hash32)?);
        put(out32.cast(), d)
    })
}

/// The typed `UAKemRecord{ua, version, scheme, kemPkHash}` digest `setKemKey` signs: version 1 ... 2^64 - 1
/// (`SCAAS_UA_ERR_KEM_VERSION` for 0), a 1,601-byte key, scheme byte first (`SCAAS_UA_ERR_KEM_SCHEME` for an id other than 1, `SCAAS_UA_ERR_KEM_KEY_LENGTH`).
#[no_mangle]
pub extern "C" fn scaas_ua_kem_record_digest(
    ua32: *const u8,
    version: u64,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::kem_record_digest(arr(ua32)?, version, bytes(kem_pk, kem_pk_len)?)?))
}

/// What the UA signs for a KEM record: `ua_message(kind, PURPOSE_KEM, kem_record_digest)`.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_record_message(
    kind: u16,
    ua32: *const u8,
    version: u64,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::kem_record_message(kind, arr(ua32)?, version, bytes(kem_pk, kem_pk_len)?)?))
}

/// The portable PoP of a registration, as `scaas_ua_holder_pop_message` writes it (all hashes 32 bytes). `message` is
/// `ua_message(kind, POP_V2, registration_digest)`: what the signer's `pop` signs. `has_member_digest` (an `msig` only) says
/// `member_digest` is set: what each derived member signs under `member`; a native member signs `registration_digest` itself
/// (TS-D4).
#[repr(C)]
pub struct ScaasUaHolderPop {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub kem_record_hash: [u8; 32],
    pub portable_record_digest: [u8; 32],
    pub registration_digest: [u8; 32],
    pub message: [u8; 32],
    pub has_member_digest: bool,
    pub member_digest: [u8; 32],
}

/// The optional proof hash: NULL or length 0 = absent; any other length than 32 is `SCAAS_UA_ERR_PQZ_POP_HASH`.
fn opt_hash<'a>(p: *const u8, len: usize) -> R<Option<&'a [u8; 32]>> {
    let b = bytes(p, len)?;
    if b.is_empty() {
        return Ok(None);
    }
    Ok(Some(b.try_into().map_err(|_| ua::UAError::PqzPopHash)?))
}
/// The optional bytes: NULL or length 0 = absent.
fn opt_bytes<'a>(p: *const u8, len: usize) -> R<Option<&'a [u8]>> {
    Ok(Some(bytes(p, len)?).filter(|b| !b.is_empty()))
}

/// The portable PoP message of a registration (UA-8 P1, P2) into `*out`. `key_data` (needed for an `msig`, to show it is
/// PQ-eligible), `pqz_key` with its proof `pqz_pop` (or only the 32-byte `pqz_pop_hash`; NULL / length 0 = absent) and the
/// initial KEM key `kem_pk` (its record is always version 0, owner 2026-10-31; NULL / length 0 = absent). Only holders carry
/// a key or a record
/// (`SCAAS_UA_ERR_PQZ_HOLDER`, `SCAAS_UA_ERR_KEM_HOLDER`); a PQZ key always comes with its proof hash and only with it
/// (`SCAAS_UA_ERR_PQZ_POP_HASH`).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_holder_pop_message(
    kind: u16,
    ua32: *const u8,
    key_data: *const u8,
    key_data_len: usize,
    pqz_key: *const u8,
    pqz_key_len: usize,
    pqz_pop: *const u8,
    pqz_pop_len: usize,
    pqz_pop_hash: *const u8,
    pqz_pop_hash_len: usize,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out: *mut ScaasUaHolderPop,
) -> ScaasUaStatus {
    let (p, h) = ((pqz_pop, pqz_pop_len), (pqz_pop_hash, pqz_pop_hash_len));
    scaas_ua_holder_pop_message_with(kind, ua32, key_data, key_data_len, pqz_key, pqz_key_len, p.0, p.1, h.0, h.1, kem_pk, kem_pk_len, ptr::null(), out)
}

/// `scaas_ua_holder_pop_message` for an `msig` with `msig` members: `inner` gives their key data, as in `scaas_ua_msig_pqz_eligible_with`
/// (NULL = none: a holder check that needs an `msig` member's record is then `SCAAS_UA_ERR_MEMBER_UNKNOWN`).
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_holder_pop_message_with(
    kind: u16,
    ua32: *const u8,
    key_data: *const u8,
    key_data_len: usize,
    pqz_key: *const u8,
    pqz_key_len: usize,
    pqz_pop: *const u8,
    pqz_pop_len: usize,
    pqz_pop_hash: *const u8,
    pqz_pop_hash_len: usize,
    kem_pk: *const u8,
    kem_pk_len: usize,
    inner: *const c_char,
    out: *mut ScaasUaHolderPop,
) -> ScaasUaStatus {
    run(|| {
        let i = inner_of(inner)?;
        let h = ua::ua8::holder_pop_message_with(
            kind,
            arr(ua32)?,
            bytes(key_data, key_data_len)?,
            opt_bytes(pqz_key, pqz_key_len)?,
            opt_bytes(pqz_pop, pqz_pop_len)?,
            opt_hash(pqz_pop_hash, pqz_pop_hash_len)?,
            opt_bytes(kem_pk, kem_pk_len)?,
            &ua::json::lookup(&i),
        )?;
        put(
            out,
            ScaasUaHolderPop {
                pqz_key_hash: h.pqz_key_hash,
                pqz_pop_hash: h.pqz_pop_hash,
                kem_record_hash: h.kem_record_hash,
                portable_record_digest: h.portable_record_digest,
                registration_digest: h.registration_digest,
                message: h.message,
                has_member_digest: h.member_digest.is_some(),
                member_digest: h.member_digest.unwrap_or_default(),
            },
        )
    })
}

/// The 32-byte message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_record_digest(ua, kind, key_hash(pqz_key),
/// kem_record_hash))`, `kind` the registering kind; `kem_pk` the register KEM key (version 0), NULL / length 0 when absent.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_pqz_reg_message(
    kind: u16,
    ua32: *const u8,
    pqz_key: *const u8,
    pqz_key_len: usize,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let m = ua::pqz_reg_message(kind, arr(ua32)?, bytes(pqz_key, pqz_key_len)?, opt_bytes(kem_pk, kem_pk_len)?)?;
        put(out32.cast(), m)
    })
}

/// The typed `UAPqzKey{ua, pqzKeyHash}` digest: what a later PQZ key's `R_REG` proves over.
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_key_digest(ua32: *const u8, pqz_key_hash32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::pqz_key_digest(arr(ua32)?, arr(pqz_key_hash32)?)))
}

/// The typed `UAPqzKeyRecord{UAPqzKey{ua, pqzKeyHash}, pqzPopHash}` digest: what `setPqzKey`'s signature signs under
/// `ua_message(kind, PURPOSE_PQZ_KEY, ·)` (and a native `msig` member signs itself, TS-D4).
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_key_record_digest(
    ua32: *const u8,
    pqz_key_hash32: *const u8,
    pqz_pop_hash32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::pqz_key_record_digest(arr(ua32)?, arr(pqz_key_hash32)?, arr(pqz_pop_hash32)?)))
}

/// The typed `UAMembership{ua, member}` digest: what `member` signs to accept its slot in the `msig` `ua` (CTR-UA-37): a native
/// member this digest itself, a derived member `member_digest(ua, ua_message(MSIG, PURPOSE_MEMBERSHIP, ·))` under `member`.
#[no_mangle]
pub extern "C" fn scaas_ua_membership_digest(ua32: *const u8, member32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::membership_digest(arr(ua32)?, arr(member32)?)))
}

/// The PQZ key record of `setPqzKey` (ruling A1-I1), as `scaas_ua_pqz_key_record_message` writes it. `message` is what the UA
/// signs, `pqz_reg_message` what the key's `R_REG` proves over; `member_digest` as in `ScaasUaHolderPop`.
#[repr(C)]
pub struct ScaasUaPqzKeyRecord {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub pqz_key_digest: [u8; 32],
    pub record_digest: [u8; 32],
    pub message: [u8; 32],
    pub pqz_reg_message: [u8; 32],
    pub has_member_digest: bool,
    pub member_digest: [u8; 32],
}

/// The signed, portable, write-once PQZ key record into `*out`: accepted only by a registration without a PQZ key
/// (`already_set` = it has one: `SCAAS_UA_ERR_PQZ_KEY_SET`). The holder rules of `scaas_ua_holder_pop_message`; the key and
/// its proof (or 32-byte hash) are both required.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_pqz_key_record_message(
    kind: u16,
    ua32: *const u8,
    key_data: *const u8,
    key_data_len: usize,
    pqz_key: *const u8,
    pqz_key_len: usize,
    pqz_pop: *const u8,
    pqz_pop_len: usize,
    pqz_pop_hash: *const u8,
    pqz_pop_hash_len: usize,
    already_set: bool,
    out: *mut ScaasUaPqzKeyRecord,
) -> ScaasUaStatus {
    let (p, h) = ((pqz_pop, pqz_pop_len), (pqz_pop_hash, pqz_pop_hash_len));
    scaas_ua_pqz_key_record_message_with(kind, ua32, key_data, key_data_len, pqz_key, pqz_key_len, p.0, p.1, h.0, h.1, already_set, ptr::null(), out)
}

/// `scaas_ua_pqz_key_record_message` for an `msig` with `msig` members: `inner` as in `scaas_ua_holder_pop_message_with`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_pqz_key_record_message_with(
    kind: u16,
    ua32: *const u8,
    key_data: *const u8,
    key_data_len: usize,
    pqz_key: *const u8,
    pqz_key_len: usize,
    pqz_pop: *const u8,
    pqz_pop_len: usize,
    pqz_pop_hash: *const u8,
    pqz_pop_hash_len: usize,
    already_set: bool,
    inner: *const c_char,
    out: *mut ScaasUaPqzKeyRecord,
) -> ScaasUaStatus {
    run(|| {
        let i = inner_of(inner)?;
        let r = ua::ua8::pqz_key_record_message_with(
            kind,
            arr(ua32)?,
            bytes(key_data, key_data_len)?,
            bytes(pqz_key, pqz_key_len)?,
            opt_bytes(pqz_pop, pqz_pop_len)?,
            opt_hash(pqz_pop_hash, pqz_pop_hash_len)?,
            already_set,
            &ua::json::lookup(&i),
        )?;
        put(
            out,
            ScaasUaPqzKeyRecord {
                pqz_key_hash: r.pqz_key_hash,
                pqz_pop_hash: r.pqz_pop_hash,
                pqz_key_digest: r.pqz_key_digest,
                record_digest: r.record_digest,
                message: r.message,
                pqz_reg_message: r.pqz_reg_message,
                has_member_digest: r.member_digest.is_some(),
                member_digest: r.member_digest.unwrap_or_default(),
            },
        )
    })
}

/// The `MemberSig` a copy sends to `acceptMembership` from the bytes of its `UAMemberSig` alone, which hash to `memberSigHashOf(ua, index)` (CTR-UA-37), as one slot JSON
/// `{index, members: [{index, sig}], sig}` (the shape of a `pop` entry of `scaas_ua_registration_args`; NUL-terminated, `*out_len` counts
/// the NUL). `key_data` is the `msig` `ua`'s; `stored` the bytes `UAMemberSig` carried: a signing slot's `sig`, an `msig` slot's
/// `abi.encode(InnerSig[])`, canonical, at most 16 entries. Anything else, or an index past the members, is `SCAAS_UA_ERR_UNAUTHORIZED`;
/// malformed key data `SCAAS_UA_ERR_KEY_DATA`.
#[no_mangle]
pub extern "C" fn scaas_ua_replayed_member_sig(
    key_data: *const u8,
    key_data_len: usize,
    index: u16,
    stored: *const u8,
    stored_len: usize,
    out: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let j = ua::json::replayed_member_sig_json(bytes(key_data, key_data_len)?, index, bytes(stored, stored_len)?)?;
        write_str(out, out_len, &j)
    })
}

/// `*out = true` iff the 32-byte purpose tag is POP_V2, KEM or PQZ_KEY: the only ones where a code-less or EIP-7702-designator
/// native `msig` member signs the record's typed digest itself (`eth_signTypedData_v4`, TS-D4); every other purpose stays UAAuth.
#[no_mangle]
pub extern "C" fn scaas_ua_is_portable_purpose(tag32: *const u8, out: *mut bool) -> ScaasUaStatus {
    run(|| put(out, ua::ua8::is_portable_purpose(arr(tag32)?)))
}

fn domain(generation: u32, chain_id: u64, registry20: *const u8, chain_uid32: *const u8) -> R<ua::Domain> {
    Ok(ua::Domain { generation, chain_id, registry: *arr(registry20)?, chain_uid: *arr(chain_uid32)? })
}

/// The 32-byte UARegistry EIP-712 domain separator; `registry20` is 20 bytes, `chain_uid32` 32 bytes.
#[no_mangle]
pub extern "C" fn scaas_ua_ua_auth_domain_separator(
    generation: u32,
    chain_id: u64,
    registry20: *const u8,
    chain_uid32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua_auth_domain_separator(&domain(generation, chain_id, registry20, chain_uid32)?)))
}

/// The 32-byte UAAuth digest; `registry20` is 20 bytes, every other input 32 bytes.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_ua_auth_digest(
    generation: u32,
    chain_id: u64,
    registry20: *const u8,
    chain_uid32: *const u8,
    ua32: *const u8,
    purpose32: *const u8,
    digest32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let d = domain(generation, chain_id, registry20, chain_uid32)?;
        put(out32.cast(), ua::ua_auth_digest(&d, arr(ua32)?, arr(purpose32)?, arr(digest32)?))
    })
}

/// The 32-byte member digest.
#[no_mangle]
pub extern "C" fn scaas_ua_member_digest(structure_ua32: *const u8, ua_msg32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::member_digest(arr(structure_ua32)?, arr(ua_msg32)?)))
}

/// The canonical form of an id (NUL-terminated); non-UTF-8 text is `SCAAS_UA_ERR_ID_FORMAT`.
#[no_mangle]
pub extern "C" fn scaas_ua_canonical_id(text: *const c_char, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| {
        let t = std::str::from_utf8(cstr(text)?).map_err(|_| ua::UAError::IdFormat)?;
        write_str(out, out_len, &ua::canonical_id(t)?)
    })
}

fn json_call(f: fn(&str) -> ua::json::JsonResult<String>, input: *const c_char, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| {
        let t = std::str::from_utf8(cstr(input)?).map_err(|_| argument("JSON"))?;
        write_str(out, out_len, &f(t)?)
    })
}

/// The registry's explicit arguments of a registration, JSON in and out (NUL-terminated; `*out_len` counts the NUL).
/// `input`: `{kind, keyData, pqzKey, pqzPopHash, pqzPop, kemPk, pop, kemCommit, inner}` (bytes as "0x..." hex, an absent field is
/// empty, an msig's `pop` is `[{index, members: [{index, sig}], sig}]`, `inner` `{id: keyData}` its msig members' structures,
/// `kemCommit` true / false forces the KEM form, absent: the hash commit
/// only when the full call is over 261,909 B). Out: `{args, kemFill, calldataLength, kemFillCalldataLength}`, `args.entry` =
/// `register`, `registerMsig`, `registerWebAuthn`, `registerMuSig2` or `registerFrost`, `kemFill` the `setKemKey(ua, 0, ...)`
/// that stores a hash-committed key (null otherwise). `SCAAS_UA_ERR_ARGUMENT` when the input is not this JSON.
#[no_mangle]
pub extern "C" fn scaas_ua_registration_args(input: *const c_char, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    json_call(ua::json::registration_args_json, input, out, out_len)
}

/// `setKemKey`'s explicit arguments, JSON in and out as `scaas_ua_registration_args`. `input`: `{ua, version, kemPk, sig}`, `sig`
/// the `UASig` `{keyData, signature, members: [{index, members: [{index, sig}], sig}]}` (absent: empty, the version-0 fill of a hash commit).
/// Out: `{ua, version, kem, sig}`.
#[no_mangle]
pub extern "C" fn scaas_ua_set_kem_key_args(input: *const c_char, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    json_call(ua::json::set_kem_key_args_json, input, out, out_len)
}

/// `setPqzKey`'s explicit arguments, JSON in and out as `scaas_ua_registration_args`. `input`: `{ua, pqzKey, pqzPopHash, sig}`,
/// `sig` as in `scaas_ua_set_kem_key_args`. Out: the same fields, `sig` complete.
#[no_mangle]
pub extern "C" fn scaas_ua_set_pqz_key_args(input: *const c_char, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    json_call(ua::json::set_pqz_key_args_json, input, out, out_len)
}

/// The `msig` key data for `n` members (`members` may be NULL when `n == 0`): 4 + 36 * n bytes.
#[no_mangle]
pub extern "C" fn scaas_ua_encode_msig(
    threshold: u16,
    members: *const ScaasUaMember,
    n: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let m: Vec<_> = bytes(members, n)?.iter().map(|m| (m.kind, m.id, m.weight)).collect();
        write_var(out, out_len, &ua::encode_msig(threshold, &m))
    })
}

// ---------------------------------------------------------------------------------------------------------------------------
// ABI 6 (ua-rs-sign T12, spec §9.2): the wallet, its key handles, signing, KEM, seal / open, containers, vault, AEAD / HKDF /
// HMAC, WebAuthn, build discovery. Every JSON argument is read by scaas-ua's bounded decoders (spec §9.3: length and depth
// before any parse); no callback crosses the ABI.
// ---------------------------------------------------------------------------------------------------------------------------

/// `scaas_ua_features()` bits: what this build holds. A binding checks them (and `scaas_ua_abi_version()`) at load.
pub const SCAAS_UA_FEATURE_WALLET: u64 = 1 << 0;
pub const SCAAS_UA_FEATURE_PQ: u64 = 1 << 1;
/// The Falcon kinds 0x0132, 0x0135 sign and verify (PQClean built); clear: they are SCAAS_UA_ERR_KIND_UNAVAILABLE.
pub const SCAAS_UA_FEATURE_FALCON: u64 = 1 << 2;
pub const SCAAS_UA_FEATURE_ZETHER: u64 = 1 << 3;
pub const SCAAS_UA_FEATURE_PQZ: u64 = 1 << 4;
pub const SCAAS_UA_FEATURE_PQZ_SET_N2048_KMAX1024: u64 = 1 << 5;
pub const SCAAS_UA_FEATURE_PQZ_SET_N2304_KMAX4096: u64 = 1 << 6;
pub const SCAAS_UA_FEATURE_PQZ_SET_N2560_KMAX16384: u64 = 1 << 7;
pub const SCAAS_UA_FEATURE_PQZ_SET_N2816_KMAX65536: u64 = 1 << 8;
/// External keys (phase 2, MD-13): clear in every build of this round; `scaas_ua_external_key_new` is KIND_UNAVAILABLE.
pub const SCAAS_UA_FEATURE_EXTERNAL: u64 = 1 << 9;
/// The secret arena is `mlock`ed and no-dump (Unix; best effort, `scaas_ua_wallet_memory_protection` reports it).
pub const SCAAS_UA_FEATURE_MLOCK: u64 = 1 << 10;

/// The networks of `scaas_ua_wallet_native_key` (clientkeys `NETWORKS`).
pub const SCAAS_UA_NETWORK_EVM: u32 = 0;
pub const SCAAS_UA_NETWORK_COSMOS: u32 = 1;
pub const SCAAS_UA_NETWORK_HEDERA_ECDSA: u32 = 2;
pub const SCAAS_UA_NETWORK_HEDERA_ED25519: u32 = 3;
pub const SCAAS_UA_NETWORK_SUI: u32 = 4;
pub const SCAAS_UA_NETWORK_STELLAR: u32 = 5;
pub const SCAAS_UA_NETWORK_TON: u32 = 6;
pub const SCAAS_UA_NETWORK_APTOS: u32 = 7;
pub const SCAAS_UA_NETWORK_SOLANA: u32 = 8;
const NETWORKS: [&str; 9] = ["evm", "cosmos", "hedera_ecdsa", "hedera_ed25519", "sui", "stellar", "ton", "aptos", "solana"];
/// `coin_type` of `scaas_ua_wallet_native_key`: the network's own SLIP-44 coin type (any other value replaces it: Pi Network is
/// `SCAAS_UA_NETWORK_STELLAR` with 314159).
pub const SCAAS_UA_COIN_DEFAULT: u32 = u32::MAX;
/// `alg` of `scaas_ua_aead_seal` / `_open`.
pub const SCAAS_UA_AEAD_AES256_GCM: u32 = 1;
pub const SCAAS_UA_AEAD_AES256_GCM_SIV: u32 = 2;
/// A KEM public key: scheme byte 1, the ML-KEM-1024 key, the X25519 key.
pub const SCAAS_UA_KEM_PK_LEN: usize = 1601;
/// An ML-KEM-1024 ciphertext.
pub const SCAAS_UA_KEM_CT_LEN: usize = 1568;
/// The buffer `scaas_ua_seed_backup_reveal` needs: 24 words of at most 8 letters, their spaces and the NUL fit.
pub const SCAAS_UA_MNEMONIC_MAX: usize = 256;
/// The buffer `scaas_ua_seed_backup_take` needs: BIP-39 entropy is 16 to 32 bytes.
pub const SCAAS_UA_ENTROPY_MAX: usize = 32;

/// A wallet: its secret store and manifest. Free it with `scaas_ua_wallet_free` (which locks it first).
pub struct ScaasUaWallet(uw::Wallet);
/// A key handle: a UA key (`scaas_ua_wallet_ua_key`) or a native key (`scaas_ua_wallet_native_key`, an imported key); its
/// wallet's store, a generation and a slot, no secret bytes. Free it with `scaas_ua_key_free`.
pub struct ScaasUaKey(Key);
enum Key {
    Ua(uw::UaKey),
    Native(uw::NativeKey),
}
/// A KEM key pair: a UA's (`scaas_ua_kem_key`) or an ephemeral one (`scaas_ua_kem_ephemeral`). Free it with `scaas_ua_kem_free`.
pub struct ScaasUaKemKey(uw::KemKeyPair);
/// A device-link session (the new device's ephemeral key, short code and window); `scaas_ua_wallet_from_link` consumes it, after
/// which every call on it is SCAAS_UA_ERR_KEY_REVOKED. Free it with `scaas_ua_link_session_free`.
pub struct ScaasUaLinkSession(Mutex<Option<uw::LinkSession>>);
/// The recovery phrase of `scaas_ua_wallet_generate`: reveal once, challenge, verify, take. Free it with `scaas_ua_seed_backup_free`.
pub struct ScaasUaSeedBackup(Mutex<uw::SeedBackup>);
/// A Zether key (spec §10.1, feature `zether`; `scaas_ua_wallet_zether_key`): its wallet's store, a generation and the slot of
/// `x`, and the public `Y` and UA. Free it with `scaas_ua_zether_key_free`.
pub struct ScaasUaZetherKey(ZetherInner);
#[cfg(feature = "zether")]
type ZetherInner = ua::facade::zether::ZetherKey;
#[cfg(not(feature = "zether"))]
type ZetherInner = ();

/// `Y` of a Zether key (`scaas_ua_zether_public`): the contracts' G1 encoding, 128 bytes.
pub const SCAAS_UA_ZETHER_Y_LEN: usize = 128;
/// `key_use` of `scaas_ua_wallet_zether_key`: the conf key and the viewing key.
pub const SCAAS_UA_ZETHER_USE_CONF: u32 = 7;
pub const SCAAS_UA_ZETHER_USE_VIEWING: u32 = 8;

/// The arena's memory protection now (`scaas_ua_wallet_memory_protection`): chunks, of them `mlock`ed, of them no-dump; all 0
/// while locked.
#[repr(C)]
pub struct ScaasUaMemoryProtection {
    pub chunks: usize,
    pub locked: usize,
    pub no_dump: usize,
}

/// A recipient of `scaas_ua_wallet_backup_seal`: the KEM key `kem_pk` of record `version` of the UA of (`kind`, `key_data`), a
/// single-key KEM holder (an `msig` has no KEM key: SCAAS_UA_ERR_KEM_HOLDER; seal to each accepted member); or, with `ephemeral`,
/// an ephemeral key named by keccak256(kem_pk) (`kind`, `key_data`, `version` unread).
#[repr(C)]
pub struct ScaasUaRecipient {
    pub kind: u16,
    pub key_data: *const u8,
    pub key_data_len: usize,
    pub version: u64,
    pub kem_pk: *const u8,
    pub kem_pk_len: usize,
    pub ephemeral: bool,
}

/// An external signer (phase 2, spec §9.4, MD-13), reserved: `sign` gets the request as named-field JSON and writes the kind's
/// signature bytes; `release` is called once when the key is freed. No build of this round takes one.
#[repr(C)]
pub struct ScaasUaExternalSigner {
    pub ctx: *mut std::ffi::c_void,
    pub sign: Option<
        unsafe extern "C" fn(ctx: *mut std::ffi::c_void, request_json: *const c_char, sig: *mut u8, sig_len: *mut usize) -> ScaasUaStatus,
    >,
    pub release: Option<unsafe extern "C" fn(ctx: *mut std::ffi::c_void)>,
}

fn handle<'a, T>(p: *const T) -> R<&'a T> {
    if p.is_null() {
        return Err(argument("NULL"));
    }
    Ok(unsafe { &*p })
}
/// `*out = a new handle of v`; `out` checked first, so nothing is allocated for a NULL `out`.
fn give<T>(out: *mut *mut T, v: T) -> R<()> {
    if out.is_null() {
        return Err(argument("NULL"));
    }
    unsafe { out.write(Box::into_raw(Box::new(v))) };
    Ok(())
}
fn free<T>(p: *mut T) {
    safe((), || {
        if !p.is_null() {
            drop(unsafe { Box::from_raw(p) });
        }
    })
}
fn text<'a>(p: *const c_char) -> R<&'a str> {
    std::str::from_utf8(cstr(p)?).map_err(|_| argument("UTF-8"))
}
/// NULL is `None`.
fn opt_text<'a>(p: *const c_char) -> R<Option<&'a str>> {
    if p.is_null() {
        return Ok(None);
    }
    text(p).map(Some)
}
/// The capacity check of a variable output before the call runs (an opened plaintext or a revealed phrase is made once).
fn need(out_len: *mut usize, n: usize) -> R<()> {
    if out_len.is_null() {
        return Err(argument("NULL"));
    }
    if unsafe { *out_len } < n {
        unsafe { out_len.write(n) };
        return Err(Fail(SCAAS_UA_ERR_BUFFER, format!("UABuffer: need {n}")));
    }
    Ok(())
}
/// `s` NUL-terminated into `out` with no copy of its own (a secret: nothing left to wipe on this side).
fn write_secret_str(out: *mut c_char, out_len: *mut usize, s: &str) -> R<()> {
    need(out_len, s.len() + 1)?;
    if out.is_null() {
        return Err(argument("NULL"));
    }
    unsafe {
        ptr::copy_nonoverlapping(s.as_ptr(), out.cast::<u8>(), s.len());
        out.add(s.len()).write(0);
        out_len.write(s.len() + 1);
    }
    Ok(())
}
fn lock<'a, T>(m: &'a Mutex<T>) -> R<std::sync::MutexGuard<'a, T>> {
    m.lock().map_err(|_| fail(SCAAS_UA_ERR_INTERNAL))
}
fn ua_key(k: &ScaasUaKey) -> R<&uw::UaKey> {
    match &k.0 {
        Key::Ua(u) => Ok(u),
        Key::Native(_) => Err(argument("a UA key")),
    }
}
fn native_key(k: &ScaasUaKey) -> R<&uw::NativeKey> {
    match &k.0 {
        Key::Native(n) => Ok(n),
        Key::Ua(_) => Err(argument("a native key")),
    }
}
fn signer(k: &ScaasUaKey) -> &dyn uw::Signer {
    match &k.0 {
        Key::Ua(u) => u,
        Key::Native(n) => n,
    }
}
fn network(n: u32) -> R<uw::Network> {
    usize::try_from(n).ok().and_then(|i| NETWORKS.get(i)).and_then(|s| uw::Network::from_name(s)).ok_or_else(|| argument("network"))
}
/// Exactly one of the two unlock secrets is meant: the PRF secret first when both are given (clientkeys `dekFrom`: the
/// passphrase is then not tried); neither is SCAAS_UA_ERR_ARGUMENT.
fn unlock<'a>(vault_passphrase: *const c_char, prf32: *const u8) -> R<uw::Unlock<'a>> {
    if !prf32.is_null() {
        return Ok(uw::Unlock::Prf(arr(prf32)?));
    }
    Ok(uw::Unlock::VaultPassphrase(opt_text(vault_passphrase)?.ok_or_else(|| argument("unlock"))?))
}
fn vault(json: *const c_char) -> R<uw::Vault> {
    Ok(uw::Vault::from_json(cstr(json)?)?)
}
fn container(json: *const c_char) -> R<uw::SealedContainer> {
    Ok(uw::SealedContainer::from_json(cstr(json)?)?)
}

/// The opener's three JSON inputs: `expect_json` required, `members_json` NULL = none, `accepted_json` NULL = no lookup.
struct Opening {
    expect: uw::ContainerExpectJson,
    members: uw::MembersJson,
    accepted: Option<uw::AcceptedJson>,
}
impl Opening {
    fn read(expect_json: *const c_char, members_json: *const c_char, accepted_json: *const c_char) -> R<Opening> {
        if expect_json.is_null() {
            return Err(argument("expect_json"));
        }
        let members = if members_json.is_null() { uw::MembersJson::default() } else { uw::MembersJson::from_json(cstr(members_json)?)? };
        let accepted = if accepted_json.is_null() { None } else { Some(uw::AcceptedJson::from_json(cstr(accepted_json)?)?) };
        Ok(Opening { expect: uw::ContainerExpectJson::from_json(cstr(expect_json)?)?, members, accepted })
    }
    /// `f(expect, members, accepted)` with the lookups as the opener takes them.
    fn with<T>(&self, f: impl FnOnce(&uw::ContainerExpect, &ua::ua8::Members, Option<&ua::ua8::Accepted>) -> T) -> T {
        let members = |id: [u8; 32]| self.members.lookup(id);
        let accepted = |id: [u8; 32], i: u16| self.accepted.as_ref().is_some_and(|a| a.accepted(id, i));
        f(&self.expect.get(), &members, self.accepted.as_ref().map(|_| &accepted as &ua::ua8::Accepted))
    }
}

/// The bits of what this build holds (`SCAAS_UA_FEATURE_*`), read from scaas-ua's own `cfg` (`scaas_ua::build`).
#[no_mangle]
pub extern "C" fn scaas_ua_features() -> u64 {
    safe(0, || {
        use ua::build as b;
        let sets = [
            SCAAS_UA_FEATURE_PQZ_SET_N2048_KMAX1024,
            SCAAS_UA_FEATURE_PQZ_SET_N2304_KMAX4096,
            SCAAS_UA_FEATURE_PQZ_SET_N2560_KMAX16384,
            SCAAS_UA_FEATURE_PQZ_SET_N2816_KMAX65536,
        ];
        let on = |x: bool, bit: u64| if x { bit } else { 0 };
        on(b::WALLET, SCAAS_UA_FEATURE_WALLET)
            | on(b::PQ, SCAAS_UA_FEATURE_PQ)
            | on(b::FALCON, SCAAS_UA_FEATURE_FALCON)
            | on(b::ZETHER, SCAAS_UA_FEATURE_ZETHER)
            | on(b::PQZ, SCAAS_UA_FEATURE_PQZ)
            | b::PQZ_SETS.iter().zip(sets).fold(0, |a, (x, bit)| a | on(*x, bit))
            | on(b::MLOCK, SCAAS_UA_FEATURE_MLOCK)
    })
}

/// A new wallet of 24 words (OS entropy, no BIP-39 passphrase) into `*out`, and its recovery phrase into `*backup`.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_generate(out: *mut *mut ScaasUaWallet, backup: *mut *mut ScaasUaSeedBackup) -> ScaasUaStatus {
    run(|| {
        if out.is_null() || backup.is_null() {
            return Err(argument("NULL"));
        }
        let (w, b) = uw::Wallet::generate()?;
        give(backup, ScaasUaSeedBackup(Mutex::new(b)))?;
        give(out, ScaasUaWallet(w))
    })
}

/// The wallet of a 12- to 24-word English mnemonic (at most 1 KiB) and its BIP-39 passphrase (NULL = empty).
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_from_mnemonic(
    words: *const c_char,
    bip39_passphrase: *const c_char,
    out: *mut *mut ScaasUaWallet,
) -> ScaasUaStatus {
    run(|| give(out, ScaasUaWallet(uw::Wallet::from_mnemonic(text(words)?, opt_text(bip39_passphrase)?.unwrap_or(""))?)))
}

/// The wallet of a seed vault (clientkeys vault v1 JSON): exactly one of `vault_passphrase` and `prf32` is meant (both: the PRF
/// secret, the passphrase not tried; neither: SCAAS_UA_ERR_ARGUMENT); `bip39_passphrase` NULL = empty (asked at every unlock,
/// never stored). SCAAS_UA_ERR_VAULT_OPEN, _VAULT_PARAMS, _VAULT_VERSION as the vault.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_open_vault(
    vault_json: *const c_char,
    vault_passphrase: *const c_char,
    prf32: *const u8,
    bip39_passphrase: *const c_char,
    out: *mut *mut ScaasUaWallet,
) -> ScaasUaStatus {
    run(|| {
        let v = vault(vault_json)?;
        let w = uw::Wallet::open_vault(&v, unlock(vault_passphrase, prf32)?, opt_text(bip39_passphrase)?.unwrap_or(""))?;
        give(out, ScaasUaWallet(w))
    })
}

/// Reopens a locked wallet from its seed vault (unlock as `scaas_ua_wallet_open_vault`) at a new generation: earlier handles
/// stay SCAAS_UA_ERR_KEY_REVOKED. SCAAS_UA_ERR_ARGUMENT while unlocked; SCAAS_UA_ERR_WALLET_MISMATCH for another wallet's vault.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_unlock(
    w: *const ScaasUaWallet,
    vault_json: *const c_char,
    vault_passphrase: *const c_char,
    prf32: *const u8,
    bip39_passphrase: *const c_char,
) -> ScaasUaStatus {
    run(|| {
        let w = handle(w)?;
        let v = vault(vault_json)?;
        Ok(w.0.unlock(&v, unlock(vault_passphrase, prf32)?, opt_text(bip39_passphrase)?.unwrap_or(""))?)
    })
}

/// The seed vault JSON of this wallet under `vault_passphrase` (the new-passphrase policy: SCAAS_UA_ERR_ARGUMENT); a PRF
/// envelope is added by `scaas_ua_vault_enable_prf`. Each call makes a new vault (a size query too).
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_seal_vault(
    w: *const ScaasUaWallet,
    vault_passphrase: *const c_char,
    out_json: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| write_str(out_json, out_len, &handle(w)?.0.seal_vault(text(vault_passphrase)?, None)?.to_json()))
}

/// Waits for calls in flight, wipes the secrets and revokes every child handle (SCAAS_UA_ERR_KEY_REVOKED); the manifest stays.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_lock(w: *const ScaasUaWallet) -> ScaasUaStatus {
    run(|| {
        handle(w)?.0.lock();
        Ok(())
    })
}

/// Locks the wallet (as `scaas_ua_wallet_lock`) and frees it; its children stay valid memory and answer SCAAS_UA_ERR_KEY_REVOKED.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_free(w: *mut ScaasUaWallet) {
    free(w)
}

/// The arena's memory protection now.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_memory_protection(w: *const ScaasUaWallet, out: *mut ScaasUaMemoryProtection) -> ScaasUaStatus {
    run(|| {
        let m = handle(w)?.0.memory_protection();
        put(out, ScaasUaMemoryProtection { chunks: m.chunks, locked: m.locked, no_dump: m.no_dump })
    })
}

/// The UA key `kind` of `account` / `index` (each below 2^31; index 0 only for the EIP-2333 kinds); SCAAS_UA_ERR_WALLET_LOCKED
/// while locked.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_ua_key(
    w: *const ScaasUaWallet,
    kind: u16,
    account: u32,
    index: u32,
    out: *mut *mut ScaasUaKey,
) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        give(out, ScaasUaKey(Key::Ua(handle(w)?.0.ua_key(kind, account, index)?)))
    })
}

/// Key `index` of `network` (`SCAAS_UA_NETWORK_*`), `coin_type` SCAAS_UA_COIN_DEFAULT or a coin type below 2^31.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_native_key(
    w: *const ScaasUaWallet,
    network: u32,
    index: u32,
    coin_type: u32,
    out: *mut *mut ScaasUaKey,
) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        let coin = (coin_type != SCAAS_UA_COIN_DEFAULT).then_some(coin_type);
        give(out, ScaasUaKey(Key::Native(handle(w)?.0.native_key(self::network(network)?, index, coin)?)))
    })
}

/// Imports a 32-byte key of `network` (a secp256k1 secret for evm, cosmos, hedera_ecdsa; an ed25519 seed for the others) as
/// `native-import:<network>:<n>`, listed in the manifest and the backup; its handle into `*out`. The caller zeroizes `secret`.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_import_native_key(
    w: *const ScaasUaWallet,
    network: u32,
    secret: *const u8,
    secret_len: usize,
    out: *mut *mut ScaasUaKey,
) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        let k = handle(w)?.0.import_native_key(self::network(network)?, bytes(secret, secret_len)?)?;
        give(out, ScaasUaKey(Key::Native(k)))
    })
}

/// The public manifest JSON `{v, entries, natives, kem, imports, backupGeneration, backupSenders}` (kept by lock).
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_manifest_json(w: *const ScaasUaWallet, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| write_str(out, out_len, &handle(w)?.0.manifest().to_json()))
}

/// `[{index, ua}]` of the UA keys `kind` of `account` at indices `0..gap` (gap at most 1024; index 0 alone for EIP-2333 kinds),
/// derived and dropped; the registry scan is the caller's.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_discover_candidates(
    w: *const ScaasUaWallet,
    kind: u16,
    account: u32,
    gap: u32,
    out: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let c = handle(w)?.0.discover_candidates(kind, account, gap)?;
        let hex = |u: &[u8; 32]| u.iter().fold(String::from("0x"), |s, b| s + &format!("{b:02x}"));
        let rows: Vec<String> = c.iter().map(|(i, u)| format!("{{\"index\":{i},\"ua\":\"{}\"}}", hex(u))).collect();
        write_str(out, out_len, &format!("[{}]", rows.join(",")))
    })
}

/// The backup of this wallet, one `scaas/backup/v1` container per recipient, signed by `sender` (a UA key of this wallet of a
/// kind that signs containers), as a JSON array of the container JSONs. Each call raises the wallet's backup generation once,
/// a size query or a too-small buffer included (generations need not be consecutive: a restore only compares them).
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_backup_seal(
    w: *const ScaasUaWallet,
    sender: *const ScaasUaKey,
    recipients: *const ScaasUaRecipient,
    n: usize,
    out_json: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        if out_len.is_null() {
            return Err(argument("NULL"));
        }
        let (w, sender) = (handle(w)?, ua_key(handle(sender)?)?);
        let rs = bytes(recipients, n)?
            .iter()
            .map(|r| {
                let pk = bytes(r.kem_pk, r.kem_pk_len)?;
                if r.ephemeral {
                    return Ok(uw::Recipient::ephemeral(pk));
                }
                Ok(uw::Recipient::ua(r.kind, bytes(r.key_data, r.key_data_len)?, r.version, pk)?)
            })
            .collect::<R<Vec<_>>>()?;
        let cs = w.0.backup_seal(sender, &rs)?;
        write_str(out_json, out_len, &format!("[{}]", cs.iter().map(uw::SealedContainer::to_json).collect::<Vec<_>>().join(",")))
    })
}

#[allow(clippy::too_many_arguments)]
fn restore(
    kk: *const ScaasUaKemKey,
    container_json: *const c_char,
    expect_json: *const c_char,
    members_json: *const c_char,
    accepted_json: *const c_char,
    current: *const ScaasUaWallet,
    bip39_passphrase: *const c_char,
    out: *mut *mut ScaasUaWallet,
    installed: *mut bool,
    rollback: Option<uw::AllowRollback>,
) -> ScaasUaStatus {
    run(|| {
        if out.is_null() || installed.is_null() {
            return Err(argument("NULL"));
        }
        let (kk, c) = (handle(kk)?, container(container_json)?);
        let o = Opening::read(expect_json, members_json, accepted_json)?;
        let cur = if current.is_null() { None } else { Some(&handle(current)?.0) };
        let pass = opt_text(bip39_passphrase)?.unwrap_or("");
        let r = o.with(|e, m, a| uw::Wallet::restore_backup(&kk.0, &c, e, m, a, cur, rollback, pass))?;
        put(installed, r.is_some())?;
        match r {
            Some(w) => give(out, ScaasUaWallet(w)),
            None => put(out, ptr::null_mut()),
        }
    })
}

/// The wallet a backup container carries, opened by `kk` against `expect_json` (`{purpose: "scaas/backup/v1", sender: {ua} |
/// {set}, recipient: {ua, version} | {kemPkHash}}`), `members_json` (`{"<id>": {kind, keyData}}`, NULL = none) and
/// `accepted_json` (`{"<msig id>": [accepted member indices]}`, the caller's `memberAccepted` reads; NULL for a single-key sender,
/// SCAAS_UA_ERR_CONTAINER_SENDER for an `msig` one). Over `current` (NULL = none), a wallet holding the sender's UA: an older
/// generation is SCAAS_UA_ERR_BACKUP_ROLLBACK, an equal one installs nothing: `*installed = false`, `*out = NULL`, SCAAS_UA_OK.
/// Otherwise `*installed = true` and the new wallet in `*out`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_wallet_restore_backup(
    kk: *const ScaasUaKemKey,
    container_json: *const c_char,
    expect_json: *const c_char,
    members_json: *const c_char,
    accepted_json: *const c_char,
    current: *const ScaasUaWallet,
    bip39_passphrase: *const c_char,
    out: *mut *mut ScaasUaWallet,
    installed: *mut bool,
) -> ScaasUaStatus {
    restore(kk, container_json, expect_json, members_json, accepted_json, current, bip39_passphrase, out, installed, None)
}

/// `scaas_ua_wallet_restore_backup` that may install an older backup over newer state (the `AllowRollback` marker): call it only
/// after the user confirmed the rollback.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_wallet_restore_backup_rollback(
    kk: *const ScaasUaKemKey,
    container_json: *const c_char,
    expect_json: *const c_char,
    members_json: *const c_char,
    accepted_json: *const c_char,
    current: *const ScaasUaWallet,
    bip39_passphrase: *const c_char,
    out: *mut *mut ScaasUaWallet,
    installed: *mut bool,
) -> ScaasUaStatus {
    let allow = Some(uw::AllowRollback);
    restore(kk, container_json, expect_json, members_json, accepted_json, current, bip39_passphrase, out, installed, allow)
}

/// The wallet a link container carries to `session` (`expect_json` purpose `scaas/link/v1`, the other inputs as
/// `scaas_ua_wallet_restore_backup`; `created` in the session's 10-minute window, else SCAAS_UA_ERR_CONTAINER_REPLAY). Once the
/// inputs parse, the session is consumed whatever the outcome: every later call on it is SCAAS_UA_ERR_KEY_REVOKED (free it still).
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_from_link(
    session: *const ScaasUaLinkSession,
    container_json: *const c_char,
    expect_json: *const c_char,
    members_json: *const c_char,
    accepted_json: *const c_char,
    bip39_passphrase: *const c_char,
    out: *mut *mut ScaasUaWallet,
) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        let (s, c) = (handle(session)?, container(container_json)?);
        let o = Opening::read(expect_json, members_json, accepted_json)?;
        let pass = opt_text(bip39_passphrase)?.unwrap_or("");
        let taken = lock(&s.0)?.take().ok_or_else(|| fail(SCAAS_UA_ERR_KEY_REVOKED))?;
        let w = o.with(|e, m, a| uw::Wallet::from_link(taken, &c, e, m, a, pass))?;
        give(out, ScaasUaWallet(w))
    })
}

/// The recovery phrase, once, into a buffer of at least SCAAS_UA_MNEMONIC_MAX bytes (smaller: SCAAS_UA_ERR_BUFFER, nothing
/// revealed); SCAAS_UA_ERR_ARGUMENT after. The caller zeroizes it.
#[no_mangle]
pub extern "C" fn scaas_ua_seed_backup_reveal(b: *const ScaasUaSeedBackup, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| {
        let b = handle(b)?;
        need(out_len, SCAAS_UA_MNEMONIC_MAX)?;
        let words = lock(&b.0)?.reveal()?;
        write_secret_str(out, out_len, &words)
    })
}

/// Three word positions to ask, 1-based and ascending, into `out3[3]`; again after a miss. SCAAS_UA_ERR_ARGUMENT before reveal.
#[no_mangle]
pub extern "C" fn scaas_ua_seed_backup_challenge(b: *const ScaasUaSeedBackup, out3: *mut u32) -> ScaasUaStatus {
    run(|| {
        let b = handle(b)?;
        if out3.is_null() {
            return Err(argument("NULL"));
        }
        let p = lock(&b.0)?.challenge()?;
        let p = p.map(|i| u32::try_from(i).unwrap_or(u32::MAX));
        put(out3.cast::<[u32; 3]>(), p)
    })
}

/// `*ok = true` iff the `n` answers are the words at the asked positions, in order (case and surrounding space ignored); then the
/// entropy can be taken. SCAAS_UA_ERR_ARGUMENT before a challenge.
#[no_mangle]
pub extern "C" fn scaas_ua_seed_backup_verify(
    b: *const ScaasUaSeedBackup,
    answers: *const *const c_char,
    n: usize,
    ok: *mut bool,
) -> ScaasUaStatus {
    run(|| {
        let b = handle(b)?;
        let a = bytes(answers, n)?.iter().map(|p| text(*p)).collect::<R<Vec<_>>>()?;
        let v = lock(&b.0)?.verify(&a)?;
        put(ok, v)
    })
}

/// The entropy once the words were confirmed, into a buffer of at least SCAAS_UA_ENTROPY_MAX bytes: `*taken = true` and its
/// length in `*out_len`; before that and after the first take `*taken = false`, `*out_len = 0`. The caller zeroizes it.
#[no_mangle]
pub extern "C" fn scaas_ua_seed_backup_take(
    b: *const ScaasUaSeedBackup,
    out: *mut u8,
    out_len: *mut usize,
    taken: *mut bool,
) -> ScaasUaStatus {
    run(|| {
        let b = handle(b)?;
        need(out_len, SCAAS_UA_ENTROPY_MAX)?;
        if out.is_null() || taken.is_null() {
            return Err(argument("NULL"));
        }
        match lock(&b.0)?.take() {
            Some(e) => {
                write_var(out, out_len, &e)?;
                put(taken, true)
            }
            None => {
                put(out_len, 0)?;
                put(taken, false)
            }
        }
    })
}

#[no_mangle]
pub extern "C" fn scaas_ua_seed_backup_free(b: *mut ScaasUaSeedBackup) {
    free(b)
}

#[no_mangle]
pub extern "C" fn scaas_ua_key_free(k: *mut ScaasUaKey) {
    free(k)
}

/// A UA key's key data, or a native key's public key (compressed secp256k1 or ed25519). Readable after its wallet is locked.
#[no_mangle]
pub extern "C" fn scaas_ua_key_data(k: *const ScaasUaKey, out: *mut u8, out_len: *mut usize) -> ScaasUaStatus {
    run(|| {
        let d = match &handle(k)?.0 {
            Key::Ua(u) => u.key_data(),
            Key::Native(n) => n.public_key(),
        };
        write_var(out, out_len, &d)
    })
}

/// A UA key's signature over `uaMessage(kind, purpose, digest)`, the purpose a tag of PURPOSES or pop v2 (else
/// SCAAS_UA_ERR_PURPOSE_UNKNOWN); a native key: SCAAS_UA_ERR_ARGUMENT.
#[no_mangle]
pub extern "C" fn scaas_ua_sign_ua(
    k: *const ScaasUaKey,
    purpose32: *const u8,
    digest32: *const u8,
    sig: *mut u8,
    sig_len: *mut usize,
) -> ScaasUaStatus {
    run(|| write_var(sig, sig_len, &ua_key(handle(k)?)?.sign_ua(arr(purpose32)?, arr(digest32)?)?))
}

/// A UA key's signature as a member of the structure `structure_ua32` over its `ua_msg` (the `member` purpose).
#[no_mangle]
pub extern "C" fn scaas_ua_sign_member(
    k: *const ScaasUaKey,
    structure_ua32: *const u8,
    structure_ua_msg32: *const u8,
    sig: *mut u8,
    sig_len: *mut usize,
) -> ScaasUaStatus {
    run(|| write_var(sig, sig_len, &ua_key(handle(k)?)?.sign_member(arr(structure_ua32)?, arr(structure_ua_msg32)?)?))
}

/// A native EVM key's EIP-712 signature (r || s || v) of `typed_data_json` (64 KiB, depth 8), only if it is what `expect_json`
/// (clientkeys `expectDigest` input `{check, ...}`, 16 KiB, depth 4) says the user confirmed: else SCAAS_UA_ERR_POLICY_REFUSED.
#[no_mangle]
pub extern "C" fn scaas_ua_sign_typed(
    k: *const ScaasUaKey,
    typed_data_json: *const c_char,
    expect_json: *const c_char,
    sig: *mut u8,
    sig_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let k = native_key(handle(k)?)?;
        let td = uw::TypedData::from_json(cstr(typed_data_json)?)?;
        write_var(sig, sig_len, &k.sign_typed(&td, uw::Expect::from_json(cstr(expect_json)?)?)?)
    })
}

/// `scaas_ua_sign_typed` with no SCaaS check (`Expect::Any`, the general EVM wallet's opt-in by this call's name): the standard
/// digest of the values as supplied.
#[no_mangle]
pub extern "C" fn scaas_ua_sign_typed_any(
    k: *const ScaasUaKey,
    typed_data_json: *const c_char,
    sig: *mut u8,
    sig_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let k = native_key(handle(k)?)?;
        let td = uw::TypedData::from_json(cstr(typed_data_json)?)?;
        write_var(sig, sig_len, &k.sign_typed(&td, uw::Expect::Any(uw::AllowAnyTypedData))?)
    })
}

/// A native EVM key's signed transaction of types 0-3 (`tx_json` named fields, 16 KiB, depth 4; never chain id 0, no type 4):
/// the raw transaction, as `eth_sendRawTransaction` takes it (its y parity, r and s are inside; the RLP decodes them).
#[no_mangle]
pub extern "C" fn scaas_ua_sign_transaction(
    k: *const ScaasUaKey,
    tx_json: *const c_char,
    out: *mut u8,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let k = native_key(handle(k)?)?;
        write_var(out, out_len, &k.sign_transaction(&uw::EvmTx::from_json(cstr(tx_json)?)?)?.raw)
    })
}

/// A native key's proof of control: its signature of `keccak256("scaas-subject-key-proof-v1" || challenge)`.
#[no_mangle]
pub extern "C" fn scaas_ua_sign_key_proof(
    k: *const ScaasUaKey,
    challenge: *const u8,
    challenge_len: usize,
    sig: *mut u8,
    sig_len: *mut usize,
) -> ScaasUaStatus {
    run(|| write_var(sig, sig_len, &native_key(handle(k)?)?.sign_key_proof(bytes(challenge, challenge_len)?)?))
}

/// A native key's signature of a raw 32-byte digest, by this call's own name (no flag argument); a UA key:
/// SCAAS_UA_ERR_RAW_DIGEST_REFUSED.
#[no_mangle]
pub extern "C" fn scaas_ua_sign_digest_raw(
    k: *const ScaasUaKey,
    digest32: *const u8,
    sig: *mut u8,
    sig_len: *mut usize,
) -> ScaasUaStatus {
    run(|| match &handle(k)?.0 {
        Key::Ua(_) => Err(fail(SCAAS_UA_ERR_RAW_DIGEST_REFUSED)),
        Key::Native(n) => write_var(sig, sig_len, &n.sign_digest(arr(digest32)?, uw::AllowRawDigest)?),
    })
}

/// The `UASig` builder as one JSON call: `request_json` (64 KiB, depth 6) names its signing keys by position in `keys[0..n_keys]`:
/// `{purpose, digest, domain?, key}` (one key) or `{purpose, digest, domain?, msig: {keyData, inner?, slots: [{index, key} |
/// {index, members: [{index, key}]}]}}`, `domain` `{generation, chainId, registry, chainUid}` (bytes "0x..." hex). Out: the
/// `UASig` `{keyData, signature, members: [{index, members: [{index, sig}], sig}]}`, the `sig` of the `_args` calls. An `msig` set
/// not minimal at both levels: SCAAS_UA_ERR_POP, nothing signed.
#[no_mangle]
pub extern "C" fn scaas_ua_uasig(
    request_json: *const c_char,
    keys: *const *const ScaasUaKey,
    n_keys: usize,
    out: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let req = uw::UaSigRequest::from_json(cstr(request_json)?)?;
        let ks = bytes(keys, n_keys)?.iter().map(|k| handle(*k).map(signer)).collect::<R<Vec<_>>>()?;
        write_str(out, out_len, &ua::json::uasig_json(&req.sign(&ks)?))
    })
}

/// Reserved (phase 2, MD-13): a key handle over an external signer (`key_ref_json` `{kind, keyData}` | `{network, coinType,
/// address}`). No build of this round has one: SCAAS_UA_ERR_KIND_UNAVAILABLE, `cb` neither kept nor called, `*out` untouched.
#[no_mangle]
pub extern "C" fn scaas_ua_external_key_new(
    key_ref_json: *const c_char,
    cb: *const ScaasUaExternalSigner,
    out: *mut *mut ScaasUaKey,
) -> ScaasUaStatus {
    run(|| {
        let _ = (key_ref_json, cb, out);
        Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))
    })
}

/// The UA's KEM key of record `version` (0 = the register key), derived through the UA key handle's own store: no wallet
/// argument. SCAAS_UA_ERR_KEM_HOLDER for a kind that holds none; SCAAS_UA_ERR_KEY_REVOKED once the wallet was locked.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_key(ua_key: *const ScaasUaKey, version: u64, out: *mut *mut ScaasUaKemKey) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        give(out, ScaasUaKemKey(self::ua_key(handle(ua_key)?)?.kem_key(version)?))
    })
}

/// An ephemeral KEM key (OS RNG, never stored): a device without a seed yet.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_ephemeral(out: *mut *mut ScaasUaKemKey) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        give(out, ScaasUaKemKey(uw::KemKeyPair::generate_ephemeral()?))
    })
}

#[no_mangle]
pub extern "C" fn scaas_ua_kem_free(kk: *mut ScaasUaKemKey) {
    free(kk)
}

/// The key's `kemPk` (SCAAS_UA_KEM_PK_LEN bytes).
#[no_mangle]
pub extern "C" fn scaas_ua_kem_pk(kk: *const ScaasUaKemKey, out1601: *mut u8) -> ScaasUaStatus {
    run(|| {
        let pk: [u8; SCAAS_UA_KEM_PK_LEN] = handle(kk)?.0.kem_pk().try_into().map_err(|_| fail(SCAAS_UA_ERR_INTERNAL))?;
        put(out1601.cast(), pk)
    })
}

/// The 32-byte shared secret of (`mlkem_ct`, `x25519_eph32`): SCAAS_UA_ERR_KEM_CHECK for a ciphertext of other than 1,568 bytes
/// or a small-order key (ML-KEM's implicit rejection kept: a wrong ciphertext gives another secret). The caller zeroizes `ss32`.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_decaps(
    kk: *const ScaasUaKemKey,
    mlkem_ct: *const u8,
    mlkem_ct_len: usize,
    x25519_eph32: *const u8,
    ss32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let kk = handle(kk)?;
        if ss32.is_null() {
            return Err(argument("NULL"));
        }
        let ss = kk.0.decaps(bytes(mlkem_ct, mlkem_ct_len)?, arr(x25519_eph32)?)?;
        put(ss32.cast::<[u8; 32]>(), *ss)
    })
}

/// An encapsulation to `kem_pk` (scheme, length and modulus checked: SCAAS_UA_ERR_KEM_CHECK): the ciphertext, the ephemeral
/// X25519 key and the shared secret (OS RNG inside). The caller zeroizes `ss32`.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_encaps(
    kem_pk: *const u8,
    kem_pk_len: usize,
    mlkem_ct1568: *mut u8,
    x25519_eph32: *mut u8,
    ss32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        if mlkem_ct1568.is_null() || x25519_eph32.is_null() || ss32.is_null() {
            return Err(argument("NULL"));
        }
        let (ct, e, ss) = uw::kem_encaps(bytes(kem_pk, kem_pk_len)?)?;
        let ct: [u8; SCAAS_UA_KEM_CT_LEN] = ct.try_into().map_err(|_| fail(SCAAS_UA_ERR_INTERNAL))?;
        put(mlkem_ct1568.cast(), ct)?;
        put(x25519_eph32.cast(), e)?;
        put(ss32.cast::<[u8; 32]>(), *ss)
    })
}

/// A seal of `pt` (at most 1 MiB) to `kem_pk` under `purpose` (`[a-z0-9./-]`, 1-64 bytes) and `aad`, version and scheme 1:
/// `mlkem_ct` (SCAAS_UA_KEM_CT_LEN), `x25519_eph32` and `ct` (`pt_len` + 16), both capacities checked before it runs. A seal
/// authenticates no sender: anyone can seal to any key.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_seal(
    kem_pk: *const u8,
    kem_pk_len: usize,
    purpose: *const c_char,
    aad: *const u8,
    aad_len: usize,
    pt: *const u8,
    pt_len: usize,
    mlkem_ct: *mut u8,
    mlkem_ct_len: *mut usize,
    x25519_eph32: *mut u8,
    ct: *mut u8,
    ct_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let a = need(mlkem_ct_len, SCAAS_UA_KEM_CT_LEN);
        let b = need(ct_len, pt_len.saturating_add(16));
        a.and(b)?;
        if x25519_eph32.is_null() {
            return Err(argument("NULL"));
        }
        let s = uw::seal(bytes(kem_pk, kem_pk_len)?, text(purpose)?, bytes(aad, aad_len)?, bytes(pt, pt_len)?)?;
        write_var(mlkem_ct, mlkem_ct_len, &s.mlkem_ct)?;
        put(x25519_eph32.cast(), s.x25519_eph)?;
        write_var(ct, ct_len, &s.ciphertext)
    })
}

/// The plaintext of a seal (version and scheme 1) under `purpose` and `aad`, into `pt` (capacity `ct_len` - 16, checked first):
/// SCAAS_UA_ERR_SEAL_OPEN for any failure. No replay protection: a valid seal opens again. The caller zeroizes `pt`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_open(
    kk: *const ScaasUaKemKey,
    purpose: *const c_char,
    aad: *const u8,
    aad_len: usize,
    mlkem_ct: *const u8,
    mlkem_ct_len: usize,
    x25519_eph32: *const u8,
    ct: *const u8,
    ct_len: usize,
    pt: *mut u8,
    pt_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let kk = handle(kk)?;
        need(pt_len, ct_len.saturating_sub(16))?;
        let s = uw::Sealed {
            version: 1,
            scheme: 1,
            mlkem_ct: bytes(mlkem_ct, mlkem_ct_len)?.to_vec(),
            x25519_eph: *arr(x25519_eph32)?,
            ciphertext: bytes(ct, ct_len)?.to_vec(),
        };
        write_var(pt, pt_len, &kk.0.open(text(purpose)?, bytes(aad, aad_len)?, &s)?)
    })
}

/// The plaintext of a sealed container (`container_json`, 4 MiB, depth 7), accepted only as `expect_json` says, with
/// `members_json` and `accepted_json` as `scaas_ua_wallet_restore_backup` (all checks before decapsulation; no container call
/// without `expect_json`). `pt` needs the ciphertext's length - 16 (checked first). No replay protection. The caller zeroizes `pt`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_open_container(
    kk: *const ScaasUaKemKey,
    container_json: *const c_char,
    expect_json: *const c_char,
    members_json: *const c_char,
    accepted_json: *const c_char,
    pt: *mut u8,
    pt_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let o = Opening::read(expect_json, members_json, accepted_json)?;
        let (kk, c) = (handle(kk)?, container(container_json)?);
        need(pt_len, c.sealed.ciphertext.len().saturating_sub(16))?;
        let p = o.with(|e, m, a| kk.0.open_container(&c, e, m, a))?;
        write_var(pt, pt_len, &p)
    })
}

/// A link session on the new device: an ephemeral KEM key, an 8-digit short code, its start now (window 10 minutes).
#[no_mangle]
pub extern "C" fn scaas_ua_link_session_new(out: *mut *mut ScaasUaLinkSession) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        give(out, ScaasUaLinkSession(Mutex::new(Some(uw::LinkSession::new()?))))
    })
}

/// The session's `kemPk`, the key the existing device seals to.
#[no_mangle]
pub extern "C" fn scaas_ua_link_session_kem_pk(s: *const ScaasUaLinkSession, out1601: *mut u8) -> ScaasUaStatus {
    run(|| {
        let s = handle(s)?;
        let g = lock(&s.0)?;
        let pk: [u8; SCAAS_UA_KEM_PK_LEN] =
            g.as_ref().ok_or_else(|| fail(SCAAS_UA_ERR_KEY_REVOKED))?.kem_pk().try_into().map_err(|_| fail(SCAAS_UA_ERR_INTERNAL))?;
        put(out1601.cast(), pk)
    })
}

/// The 8-digit short code both screens show (NUL-terminated).
#[no_mangle]
pub extern "C" fn scaas_ua_link_session_short_code(s: *const ScaasUaLinkSession, out: *mut c_char, out_len: *mut usize) -> ScaasUaStatus {
    run(|| {
        let s = handle(s)?;
        let code = lock(&s.0)?.as_ref().ok_or_else(|| fail(SCAAS_UA_ERR_KEY_REVOKED))?.short_code();
        write_str(out, out_len, &code)
    })
}

#[no_mangle]
pub extern "C" fn scaas_ua_link_session_free(s: *mut ScaasUaLinkSession) {
    free(s)
}

/// `*out = true` iff the vault's pin envelope is weaker than today's parameters (rewrap it on unlock).
#[no_mangle]
pub extern "C" fn scaas_ua_vault_needs_rewrap(vault_json: *const c_char, out: *mut bool) -> ScaasUaStatus {
    run(|| put(out, vault(vault_json)?.needs_rewrap()))
}

/// The vault with a new pin envelope under `new_passphrase` (today's parameters, the new-passphrase policy) over the same DEK:
/// it rotates the passphrase KEK, not the DEK.
#[no_mangle]
pub extern "C" fn scaas_ua_vault_rewrap_pin(
    vault_json: *const c_char,
    old_passphrase: *const c_char,
    new_passphrase: *const c_char,
    out_json: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| write_str(out_json, out_len, &vault(vault_json)?.rewrap_pin(text(old_passphrase)?, text(new_passphrase)?)?.to_json()))
}

/// The vault with a PRF envelope (`prf32` the platform secret, `credential_id` the credential id or key alias, `salt` what the
/// platform was asked with), opened once by `vault_passphrase`. The caller zeroizes `prf32`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_vault_enable_prf(
    vault_json: *const c_char,
    vault_passphrase: *const c_char,
    prf32: *const u8,
    credential_id: *const c_char,
    salt: *const u8,
    salt_len: usize,
    out_json: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let prf = uw::PrfEnvelope { output: arr(prf32)?, credential_id: text(credential_id)?, salt: bytes(salt, salt_len)? };
        write_str(out_json, out_len, &vault(vault_json)?.enable_prf(text(vault_passphrase)?, &prf)?.to_json())
    })
}

fn alg(a: u32) -> R<uw::Alg> {
    match a {
        SCAAS_UA_AEAD_AES256_GCM => Ok(uw::Alg::Aes256Gcm),
        SCAAS_UA_AEAD_AES256_GCM_SIV => Ok(uw::Alg::Aes256GcmSiv),
        _ => Err(argument("alg")),
    }
}

/// `ct || tag` (`data_len` + 16, checked first) of `data` under the caller's session key; nonce uniqueness is the caller's.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_aead_seal(
    alg: u32,
    key32: *const u8,
    nonce12: *const u8,
    aad: *const u8,
    aad_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        need(out_len, data_len.saturating_add(16))?;
        let c = uw::aead_seal(self::alg(alg)?, arr(key32)?, arr(nonce12)?, bytes(aad, aad_len)?, bytes(data, data_len)?)?;
        write_var(out, out_len, &c)
    })
}

/// The plaintext (`data_len` - 16, checked first) of `ct || tag`: SCAAS_UA_ERR_AEAD for a bad tag, nothing written. The caller
/// zeroizes it.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_aead_open(
    alg: u32,
    key32: *const u8,
    nonce12: *const u8,
    aad: *const u8,
    aad_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        need(out_len, data_len.saturating_sub(16))?;
        let p = uw::aead_open(self::alg(alg)?, arr(key32)?, arr(nonce12)?, bytes(aad, aad_len)?, bytes(data, data_len)?)?;
        write_var(out, out_len, &p)
    })
}

/// HKDF-SHA256 (RFC 5869) of `ikm`, `salt` and `info`: `len` bytes (at most 255 x 32) into `out`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_hkdf_sha256(
    ikm: *const u8,
    ikm_len: usize,
    salt: *const u8,
    salt_len: usize,
    info: *const u8,
    info_len: usize,
    out: *mut u8,
    len: usize,
) -> ScaasUaStatus {
    run(|| {
        let k = uw::hkdf_sha256(bytes(ikm, ikm_len)?, bytes(salt, salt_len)?, bytes(info, info_len)?, len)?;
        let mut cap = len;
        write_var(out, &mut cap, &k)
    })
}

/// HMAC-SHA256 of `data` under `key` into `out32`.
#[no_mangle]
pub extern "C" fn scaas_ua_hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const u8,
    data_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), uw::hmac_sha256(bytes(key, key_len)?, bytes(data, data_len)?)))
}

/// The WebAuthn challenge of `purpose32` (a tag of PURPOSES or pop v2) and `digest32`: `uaMessage(0x0100, purpose, digest)`.
#[no_mangle]
pub extern "C" fn scaas_ua_webauthn_challenge(purpose32: *const u8, digest32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), uw::webauthn_challenge(arr(purpose32)?, arr(digest32)?)?))
}

// ---------------------------------------------------------------------------------------------------------------------------
// The Zether facade (ua-rs-sign T14, spec §10.1; feature `zether`, in the default build): the key handle, zether-prover's
// commands with the handle's key, the balance-cache box. Without the feature every call is SCAAS_UA_ERR_KIND_UNAVAILABLE.
// ---------------------------------------------------------------------------------------------------------------------------

#[cfg(feature = "zether")]
fn zether<'a>(k: *const ScaasUaZetherKey) -> R<&'a ZetherInner> {
    Ok(&handle(k)?.0)
}

/// The Zether key of `coin` / `account` (`key_use`: SCAAS_UA_ZETHER_USE_CONF or _VIEWING, else SCAAS_UA_ERR_ARGUMENT), BLS12-381,
/// EIP-2333 path m/12381/<coin>/<account>/<use>; `x` stays in the wallet's store (lock and free revoke the handle:
/// SCAAS_UA_ERR_KEY_REVOKED). SCAAS_UA_ERR_WALLET_LOCKED while locked.
#[no_mangle]
pub extern "C" fn scaas_ua_wallet_zether_key(
    w: *const ScaasUaWallet,
    coin: u32,
    account: u32,
    key_use: u32,
    out: *mut *mut ScaasUaZetherKey,
) -> ScaasUaStatus {
    run(|| {
        if out.is_null() {
            return Err(argument("NULL"));
        }
        #[cfg(feature = "zether")]
        return give(out, ScaasUaZetherKey(handle(w)?.0.zether_key(coin, account, key_use)?));
        #[cfg(not(feature = "zether"))]
        {
            let _ = (w, coin, account, key_use);
            Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))
        }
    })
}

#[no_mangle]
pub extern "C" fn scaas_ua_zether_key_free(k: *mut ScaasUaZetherKey) {
    free(k)
}

/// The key's `Y` (SCAAS_UA_ZETHER_Y_LEN bytes) and its UA (kind 0x0141); public, readable after lock.
#[no_mangle]
pub extern "C" fn scaas_ua_zether_public(k: *const ScaasUaZetherKey, y128: *mut u8, ua32: *mut u8) -> ScaasUaStatus {
    run(|| {
        #[cfg(feature = "zether")]
        {
            let k = zether(k)?;
            let y: [u8; SCAAS_UA_ZETHER_Y_LEN] = k.y().try_into().map_err(|_| fail(SCAAS_UA_ERR_INTERNAL))?;
            if y128.is_null() || ua32.is_null() {
                return Err(argument("NULL"));
            }
            put(y128.cast(), y)?;
            put(ua32.cast(), k.ua())
        }
        #[cfg(not(feature = "zether"))]
        {
            let _ = (k, y128, ua32);
            Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))
        }
    })
}

/// zether-prover's command `cmd` (encrypt, decrypt, decryptPending, checkBalance, proveTransfer, proveTransferMulti, proveBurn,
/// openMemo, recoverTransfer, openDisclosure, pop, ownerAuth, uaSig, shieldCalldata, envelope, typedDigest, namedCall) on
/// `request_json` (named fields, at most 1 MiB, depth 8) with the handle's key: its JSON answer into `out_json`. Every field is
/// checked against the command's allow-list: a `key` object, `revealSecret`, `includeWitness`, an unknown field or another
/// curve is SCAAS_UA_ERR_ARGUMENT, and so is a refusal of the prover (no detail: it could name a request value). A size query
/// runs the command again (a proof is made again, with new randomness).
#[no_mangle]
pub extern "C" fn scaas_ua_zether_call(
    k: *const ScaasUaZetherKey,
    cmd: *const c_char,
    request_json: *const c_char,
    out_json: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        #[cfg(feature = "zether")]
        return write_str(out_json, out_len, &zether(k)?.call(text(cmd)?, cstr(request_json)?)?);
        #[cfg(not(feature = "zether"))]
        {
            let _ = (k, cmd, request_json, out_json, out_len);
            Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))
        }
    })
}

/// clientkeys `sealBalanceCache`: the box `{"iv", "ct"}` (JSON) of the cache entries `entries_json` (at most 1 MiB) under the
/// key's `x` (AES-256-GCM, a fresh iv; a size query seals again).
#[no_mangle]
pub extern "C" fn scaas_ua_zether_seal_balance_cache(
    k: *const ScaasUaZetherKey,
    entries_json: *const u8,
    entries_json_len: usize,
    out_json: *mut c_char,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        #[cfg(feature = "zether")]
        return write_str(out_json, out_len, &zether(k)?.seal_balance_cache(bytes(entries_json, entries_json_len)?)?);
        #[cfg(not(feature = "zether"))]
        {
            let _ = (k, entries_json, entries_json_len, out_json, out_len);
            Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))
        }
    })
}

/// clientkeys `openBalanceCache`: the entries of a box into `out`. SCAAS_UA_ERR_AEAD for a box that does not open under this key
/// (clientkeys: an empty cache), SCAAS_UA_ERR_ARGUMENT for one that is not `{iv, ct}`. The caller zeroizes `out`.
#[no_mangle]
pub extern "C" fn scaas_ua_zether_open_balance_cache(
    k: *const ScaasUaZetherKey,
    box_json: *const c_char,
    out: *mut u8,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        #[cfg(feature = "zether")]
        return write_var(out, out_len, &zether(k)?.open_balance_cache(cstr(box_json)?)?);
        #[cfg(not(feature = "zether"))]
        {
            let _ = (k, box_json, out, out_len);
            Err(fail(SCAAS_UA_ERR_KIND_UNAVAILABLE))
        }
    })
}

/// The `webauthn-p256` signature `abi.encode(authData, clientDataJSON, r, s)` of an assertion against `expected_challenge32`
/// (low-s, the chains' clientDataJSON rule), verified with `key_data` before it is written: SCAAS_UA_ERR_WEBAUTHN_ASSERTION.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_webauthn_assertion(
    key_data: *const u8,
    key_data_len: usize,
    expected_challenge32: *const u8,
    auth_data: *const u8,
    auth_data_len: usize,
    client_data_json: *const u8,
    client_data_json_len: usize,
    r32: *const u8,
    s32: *const u8,
    out: *mut u8,
    out_len: *mut usize,
) -> ScaasUaStatus {
    run(|| {
        let a = uw::webauthn_assertion(
            bytes(key_data, key_data_len)?,
            arr(expected_challenge32)?,
            bytes(auth_data, auth_data_len)?,
            bytes(client_data_json, client_data_json_len)?,
            arr(r32)?,
            arr(s32)?,
        )?;
        write_var(out, out_len, &a)
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn abi_version_is_6() {
        assert_eq!(scaas_ua_abi_version(), 6);
    }

    /// Each bit against the build: ua-c's own forwarded features, and the Falcon bit against whether a Falcon key derives.
    #[test]
    fn features_bits_match_the_build() {
        let f = scaas_ua_features();
        let has = |bit: u64| f & bit != 0;
        assert!(has(SCAAS_UA_FEATURE_WALLET) && has(SCAAS_UA_FEATURE_PQ), "ua-c always builds the wallet");
        assert_eq!(has(SCAAS_UA_FEATURE_MLOCK), cfg!(all(unix, feature = "mlock")));
        assert_eq!(has(SCAAS_UA_FEATURE_ZETHER), cfg!(feature = "zether"));
        assert_eq!(has(SCAAS_UA_FEATURE_PQZ), cfg!(feature = "pqz"));
        let sets = [
            (SCAAS_UA_FEATURE_PQZ_SET_N2048_KMAX1024, cfg!(feature = "pqz-set-n2048-kmax1024")),
            (SCAAS_UA_FEATURE_PQZ_SET_N2304_KMAX4096, cfg!(feature = "pqz-set-n2304-kmax4096")),
            (SCAAS_UA_FEATURE_PQZ_SET_N2560_KMAX16384, cfg!(feature = "pqz-set-n2560-kmax16384")),
            (SCAAS_UA_FEATURE_PQZ_SET_N2816_KMAX65536, cfg!(feature = "pqz-set-n2816-kmax65536")),
        ];
        sets.iter().for_each(|(bit, on)| assert_eq!(has(*bit), *on));
        assert!(!has(SCAAS_UA_FEATURE_EXTERNAL), "MD-13: no external key in a release build");
        assert_eq!(f >> 11, 0, "no bit past SCAAS_UA_FEATURE_MLOCK");
        let w = uw::Wallet::from_mnemonic("legal winner thank year wave sausage worth useful legal winner thank yellow", "").unwrap();
        let falcon = w.ua_key(0x0132, 0, 0);
        assert_eq!(has(SCAAS_UA_FEATURE_FALCON), falcon.is_ok());
        if let Err(e) = falcon {
            assert_eq!(e, uw::Error::KindUnavailable);
        }
    }

    /// Spec §9.2 "`_free` zeroizes": each type a handle wraps is `ZeroizeOnDrop` (scaas-ua says where its wipe happens).
    #[test]
    fn handles_wipe_on_free() {
        fn wipes<T: uw::ZeroizeOnDrop>() {}
        wipes::<uw::Wallet>();
        wipes::<uw::UaKey>();
        wipes::<uw::NativeKey>();
        wipes::<uw::KemKeyPair>();
        wipes::<uw::LinkSession>();
        wipes::<uw::SeedBackup>();
        #[cfg(feature = "zether")]
        wipes::<ZetherInner>();
    }

    #[test]
    fn a_panic_is_internal_never_an_unwind() {
        assert_eq!(run(|| panic!("a bug")), SCAAS_UA_ERR_INTERNAL);
        assert_eq!(last_error_str(), "UAInternal: panic");
        assert_eq!(safe(7u8, || panic!("a bug")), 7);
    }

    fn last_error_str() -> String {
        unsafe { CStr::from_ptr(scaas_ua_last_error()) }.to_string_lossy().into_owned()
    }
}
