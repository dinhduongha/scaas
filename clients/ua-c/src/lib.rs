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
pub const SCAAS_UA_ABI_VERSION: u32 = 1;

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
/// "UAPqzHolder": a PQZ key given for a kind that may not hold one (only 0x0130-0x0132 may).
pub const SCAAS_UA_ERR_PQZ_HOLDER: ScaasUaStatus = 11;

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
/// "UAArgument", "UABuffer", "UAInternal", "UAPqzHolder"; "UAStatusUnknown" for any other value.
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

/// The 32-byte purpose tag; a non-UTF-8 purpose is `SCAAS_UA_ERR_PURPOSE_UNKNOWN`.
#[no_mangle]
pub extern "C" fn scaas_ua_purpose_tag(purpose: *const c_char, out32: *mut u8) -> ScaasUaStatus {
    run(|| {
        let p = std::str::from_utf8(cstr(purpose)?).map_err(|_| ua::UAError::PurposeUnknown)?;
        put(out32.cast(), ua::purpose_tag(p)?)
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

/// The 32-byte popDigest; `chain_uid32`, `ua32`, `pqz_key_hash32` are 32 bytes (the keyHash of the UA's PQZ key, all
/// zero without one), `registry20` is 20 bytes.
#[no_mangle]
pub extern "C" fn scaas_ua_pop_digest(
    chain_id: u64,
    chain_uid32: *const u8,
    registry20: *const u8,
    ua32: *const u8,
    pqz_key_hash32: *const u8,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let d = ua::pop_digest(chain_id, arr(chain_uid32)?, arr(registry20)?, arr(ua32)?, arr(pqz_key_hash32)?);
        put(out32.cast(), d)
    })
}

/// What a PQ holder signs to register: `out_pqz_key_hash32`, `out_pop_digest32` and `out_message32` (the ua_msg over the pop
/// digest). `pqz_key` NULL = no key (hash 0, the plain pop); a key for a kind that may not hold one is `SCAAS_UA_ERR_PQZ_HOLDER`.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub extern "C" fn scaas_ua_holder_pop_message(
    kind: u16,
    chain_id: u64,
    chain_uid32: *const u8,
    registry20: *const u8,
    ua32: *const u8,
    pqz_key: *const u8,
    pqz_key_len: usize,
    out_pqz_key_hash32: *mut u8,
    out_pop_digest32: *mut u8,
    out_message32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let key = if pqz_key.is_null() { None } else { Some(bytes(pqz_key, pqz_key_len)?) };
        let (h, d, m) = ua::holder_pop_message(kind, chain_id, arr(chain_uid32)?, arr(registry20)?, arr(ua32)?, key)?;
        put(out_pqz_key_hash32.cast(), h)?;
        put(out_pop_digest32.cast(), d)?;
        put(out_message32.cast(), m)
    })
}

/// The 32-byte message `R_REG` proves over for `pqz_key` (the PQZ scheme 0x0142).
#[no_mangle]
pub extern "C" fn scaas_ua_pqz_reg_message(
    chain_id: u64,
    chain_uid32: *const u8,
    registry20: *const u8,
    ua32: *const u8,
    pqz_key: *const u8,
    pqz_key_len: usize,
    out32: *mut u8,
) -> ScaasUaStatus {
    run(|| {
        let m = ua::pqz_reg_message(chain_id, arr(chain_uid32)?, arr(registry20)?, arr(ua32)?, bytes(pqz_key, pqz_key_len)?)?;
        put(out32.cast(), m)
    })
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
