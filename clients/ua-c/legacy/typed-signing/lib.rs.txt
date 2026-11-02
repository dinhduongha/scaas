// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! C ABI over `scaas-ua`; the header `include/scaas_ua.h` is generated from this file by cbindgen (tests/header.rs).
//! The caller owns every buffer, so no Rust allocation crosses the ABI. Every export runs inside `guard` (the one
//! `catch_unwind`): a panic never unwinds into C. Status-returning exports go through `run`, which also sets the
//! thread-local `scaas_ua_last_error` detail. UNAUDITED.
use scaas_ua as ua;
use std::cell::RefCell;
use std::ffi::{c_char, CStr, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::OnceLock;
use std::{ptr, slice};

/// Bumped on any breaking signature or layout change; compare with `scaas_ua_abi_version()`.
pub const SCAAS_UA_ABI_VERSION: u32 = 2;

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
/// "UAPqzHolder": a PQZ key given for a kind that may not hold one (only 0x0130-0x0132 and a PQ-eligible msig may).
pub const SCAAS_UA_ERR_PQZ_HOLDER: ScaasUaStatus = 11;
/// "UAKemHolder": a KEM record given for a kind that may not hold one.
pub const SCAAS_UA_ERR_KEM_HOLDER: ScaasUaStatus = 12;
/// "UAKemVersion": a KEM record version of 0.
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
        };
        Fail(status, e.to_string())
    }
}
fn argument(what: &str) -> Fail {
    Fail(SCAAS_UA_ERR_ARGUMENT, format!("UAArgument: {what}"))
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

fn kind_row(i: usize) -> ScaasUaKind {
    static STRINGS: OnceLock<Vec<(CString, Option<CString>)>> = OnceLock::new();
    let c = |s: &str| CString::new(s).unwrap();
    let strings = STRINGS.get_or_init(|| ua::KINDS.iter().map(|k| (c(k.name), k.group.map(c))).collect());
    let k = &ua::KINDS[i];
    let mut lengths = [0u32; 2];
    for (n, l) in k.lengths.iter().enumerate() {
        lengths[n] = *l as u32; // ponytail: panics (UAInternal) if a kind ever gets more than two lengths
    }
    ScaasUaKind {
        kind: k.kind,
        native: k.native,
        lengths_len: k.lengths.len() as u8,
        lengths,
        name: strings[i].0.as_ptr(),
        group: strings[i].1.as_ref().map_or(ptr::null(), |g| g.as_ptr()),
    }
}

/// The library's `SCAAS_UA_ABI_VERSION`.
#[no_mangle]
pub extern "C" fn scaas_ua_abi_version() -> u32 {
    safe(0, || SCAAS_UA_ABI_VERSION)
}

/// The static code string of a status: "UAOk", "UAKeyData" ... "UAPurposeUnknown" (the vector files' `error` values),
/// "UAArgument", "UABuffer", "UAInternal", "UAPqzHolder", "UAKemHolder", "UAKemVersion", "UAKemKeyLength", "UAPqzPopHash",
/// "UAPqzKeySet", "UAKemScheme"; "UAStatusUnknown" for any other value.
#[no_mangle]
pub extern "C" fn scaas_ua_status_name(status: ScaasUaStatus) -> *const c_char {
    let name: &'static CStr = match status {
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
        _ => c"UAStatusUnknown",
    };
    name.as_ptr()
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
        if index >= ua::KINDS.len() {
            return Err(argument("index"));
        }
        put(out, kind_row(index))
    })
}

/// The kind-table row of `kind`.
#[no_mangle]
pub extern "C" fn scaas_ua_kind_info(kind: u16, out: *mut ScaasUaKind) -> ScaasUaStatus {
    run(|| {
        let i = ua::KINDS.iter().position(|k| k.kind == kind).ok_or(ua::UAError::KindUnknown(kind))?;
        put(out, kind_row(i))
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

/// Whether `kind` may hold a PQZ key attribute (mldsa44, mldsa65, fndsa512).
#[no_mangle]
pub extern "C" fn scaas_ua_is_pqz_holder(kind: u16) -> bool {
    safe(false, || ua::is_pqz_holder(kind))
}

/// `*out = true` iff the `msig` key data is PQ-eligible: its members outside 0x0130-0x0133 weigh less than the threshold.
#[no_mangle]
pub extern "C" fn scaas_ua_msig_pqz_eligible(key_data: *const u8, key_data_len: usize, out: *mut bool) -> ScaasUaStatus {
    run(|| put(out, ua::msig_pqz_eligible(bytes(key_data, key_data_len)?)?))
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

/// The 32-byte KEM_RECORD_TAG.
#[no_mangle]
pub extern "C" fn scaas_ua_kem_record_tag(out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::kem_record_tag()))
}

/// The 32-byte PQZ_KEY_RECORD_TAG.
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_key_record_tag(out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::pqz_key_record_tag()))
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

/// `keccak256(PURPOSE_POP_V2 ‖ ua ‖ pqzKeyHash ‖ kemRecordHash)`; every input 32 bytes, a hash all zero when absent.
#[no_mangle]
pub extern "C" fn scaas_ua_portable_pop_digest(
    ua32: *const u8,
    pqz_key_hash32: *const u8,
    kem_record_hash32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::portable_pop_digest(arr(ua32)?, arr(pqz_key_hash32)?, arr(kem_record_hash32)?)))
}

/// `keccak256(portablePopDigest ‖ pqzPopHash)`: what the signer's `pop` signs under `ua_message(kind, POP_V2, ·)`.
#[no_mangle]
pub extern "C" fn scaas_ua_registration_digest(portable32: *const u8, pqz_pop_hash32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::registration_digest(arr(portable32)?, arr(pqz_pop_hash32)?)))
}

/// `keccak256(KEM_RECORD_TAG ‖ ua ‖ uint256(version) ‖ keccak256(kem_pk))`: version 1 ... 2^64 - 1
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
/// `member_digest` is set: what each member signs under `member`; a code-less or EIP-7702-designator native member signs
/// `scaas_ua_personal_sign_digest` of it (ruling C7).
#[repr(C)]
pub struct ScaasUaHolderPop {
    pub pqz_key_hash: [u8; 32],
    pub pqz_pop_hash: [u8; 32],
    pub kem_record_hash: [u8; 32],
    pub portable_pop_digest: [u8; 32],
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
/// The optional KEM record: `version == 0` with an empty key = absent.
fn opt_kem<'a>(version: u64, pk: *const u8, len: usize) -> R<Option<(u64, &'a [u8])>> {
    Ok(Some((version, bytes(pk, len)?)).filter(|(v, k)| *v != 0 || !k.is_empty()))
}

/// The portable PoP message of a registration (UA-8 P1, P2) into `*out`. `key_data` (needed for an `msig`, to show it is
/// PQ-eligible), `pqz_key` with its proof `pqz_pop` (or only the 32-byte `pqz_pop_hash`; NULL / length 0 = absent) and the
/// initial KEM record `(kem_version, kem_pk)` (`0` and empty = absent). Only holders carry a key or a record
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
    kem_version: u64,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out: *mut ScaasUaHolderPop,
) -> ScaasUaStatus {
    run(|| {
        let h = ua::holder_pop_message(
            kind,
            arr(ua32)?,
            bytes(key_data, key_data_len)?,
            opt_bytes(pqz_key, pqz_key_len)?,
            opt_bytes(pqz_pop, pqz_pop_len)?,
            opt_hash(pqz_pop_hash, pqz_pop_hash_len)?,
            opt_kem(kem_version, kem_pk, kem_pk_len)?,
        )?;
        put(
            out,
            ScaasUaHolderPop {
                pqz_key_hash: h.pqz_key_hash,
                pqz_pop_hash: h.pqz_pop_hash,
                kem_record_hash: h.kem_record_hash,
                portable_pop_digest: h.portable_pop_digest,
                registration_digest: h.registration_digest,
                message: h.message,
                has_member_digest: h.member_digest.is_some(),
                member_digest: h.member_digest.unwrap_or_default(),
            },
        )
    })
}

/// The 32-byte message `R_REG` proves over: `ua_message(0x0142, POP_V2, portable_pop_digest(ua, key_hash(pqz_key),
/// kem_record_hash))`; the KEM record `(kem_version, kem_pk)` is `0` and empty when absent.
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_reg_message(
    ua32: *const u8,
    pqz_key: *const u8,
    pqz_key_len: usize,
    kem_version: u64,
    kem_pk: *const u8,
    kem_pk_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let m = ua::pqz_reg_message(arr(ua32)?, bytes(pqz_key, pqz_key_len)?, opt_kem(kem_version, kem_pk, kem_pk_len)?)?;
        put(out32.cast(), m)
    })
}

/// `keccak256(PQZ_KEY_RECORD_TAG ‖ ua ‖ pqzKeyHash)`: what a later PQZ key's `R_REG` proves over.
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_key_digest(ua32: *const u8, pqz_key_hash32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::pqz_key_digest(arr(ua32)?, arr(pqz_key_hash32)?)))
}

/// `keccak256(pqzKeyDigest ‖ pqzPopHash)`: what `setPqzKey`'s signature signs under `ua_message(kind, PURPOSE_PQZ_KEY, ·)`.
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_key_record_digest(key_digest32: *const u8, pqz_pop_hash32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::ua8::pqz_key_record_digest(arr(key_digest32)?, arr(pqz_pop_hash32)?)))
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
    run(|| {
        let r = ua::ua8::pqz_key_record_message(
            kind,
            arr(ua32)?,
            bytes(key_data, key_data_len)?,
            bytes(pqz_key, pqz_key_len)?,
            opt_bytes(pqz_pop, pqz_pop_len)?,
            opt_hash(pqz_pop_hash, pqz_pop_hash_len)?,
            already_set,
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

/// EIP-191 `personal_sign` of a 32-byte digest: `keccak256(0x19 ‖ "Ethereum Signed Message:\n32" ‖ digest)`. What a code-less
/// native (EOA) `msig` member signs over the `member_digest` of a portable record only (POP_V2, KEM, PQZ_KEY; ruling C7);
/// every other purpose stays UAAuth.
#[no_mangle]
pub extern "C" fn scaas_ua_personal_sign_digest(digest32: *const u8, out32: *mut u8) -> ScaasUaStatus {
    run(|| put(out32.cast(), ua::personal_sign_digest(arr(digest32)?)))
}

/// `*out = true` iff the 32-byte purpose tag is POP_V2, KEM or PQZ_KEY: the only ones a code-less or EIP-7702-designator native `msig` member signs
/// by `personal_sign`.
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
