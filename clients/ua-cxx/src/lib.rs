// SPDX-License-Identifier: LicenseRef-SCaaS-Community-1.0
//! cxx bridge over `scaas-ua`. Byte data crosses as `&[u8]` / `Vec<u8>`; fixed-size inputs are length-checked here, so a
//! malformed call is an `Err` (thrown as `rust::Error` in C++), never UB. Fallible calls return `Result`; the message is
//! `UAError`'s Display (`"<code>"` or `"UAKeyData: <reason>"`), which `include/scaas_ua.hpp` turns into code + reason.
use scaas_ua as ua;
use std::panic::{catch_unwind, AssertUnwindSafe};

pub struct UaErr(String);
impl core::fmt::Display for UaErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}
impl From<ua::UAError> for UaErr {
    fn from(e: ua::UAError) -> Self {
        UaErr(e.to_string())
    }
}
type R<T> = Result<T, UaErr>;

/// Run `f`, turning a (never expected) panic into an error instead of unwinding into C++.
fn guard<T>(f: impl FnOnce() -> R<T>) -> R<T> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or_else(|_| Err(UaErr("UAKeyData: internal".into())))
}
fn a<const N: usize>(b: &[u8]) -> R<[u8; N]> {
    b.try_into().map_err(|_| UaErr("UAKeyData: length".into()))
}

#[cxx::bridge(namespace = "scaas::ua::ffi")]
mod ffi {
    struct KindInfo {
        kind: u16,
        name: String,
        native: bool,
        lengths: Vec<usize>,
        group: String,
        has_group: bool,
    }
    struct Member {
        kind: u16,
        id: Vec<u8>,
        weight: u16,
    }
    extern "Rust" {
        fn kind_info(kind: u16) -> Result<KindInfo>;
        fn kind_count() -> usize;
        fn kind_at(index: usize) -> KindInfo;
        fn tag(kind: u16) -> Result<Vec<u8>>;
        fn kind_tag_string(kind: u16) -> Result<String>;
        fn group_tag(group: &str) -> Vec<u8>; // empty = unknown group
        fn group_tag_string(group: &str) -> String; // empty = unknown group
        fn msg_tag() -> Vec<u8>;
        fn purpose_tag(purpose: &str) -> Result<Vec<u8>>;
        fn ua_of(kind: u16, key_data: &[u8]) -> Result<Vec<u8>>;
        fn derive_ua(kind: u16, key_data: &[u8], hedera_native: bool) -> Result<Vec<u8>>;
        fn native_id(kind: u16, raw: &[u8]) -> Result<Vec<u8>>;
        fn key_hash_of(kind: u16, key_data: &[u8]) -> Result<Vec<u8>>; // empty = none (structure kinds)
        fn validate_key_data(kind: u16, key_data: &[u8], hedera_native: bool) -> Result<()>;
        fn in_native_space(id: &[u8]) -> Result<bool>;
        fn is_native(kind: u16) -> bool;
        fn is_zether(kind: u16) -> bool;
        fn is_signing(kind: u16) -> bool;
        fn is_member(kind: u16, hedera_native: bool) -> bool;
        fn ua_message(kind: u16, purpose: &[u8], digest: &[u8]) -> Result<Vec<u8>>;
        fn chain_key_hash(chain_id: u64) -> Vec<u8>;
        fn pop_digest(chain_id: u64, chain_uid: &[u8], registry: &[u8], ua: &[u8], auth_ref: &[u8]) -> Result<Vec<u8>>;
        fn ua_auth_domain_separator(generation: u32, chain_id: u64, registry: &[u8], chain_uid: &[u8]) -> Result<Vec<u8>>;
        #[allow(clippy::too_many_arguments)]
        fn ua_auth_digest(
            generation: u32,
            chain_id: u64,
            registry: &[u8],
            chain_uid: &[u8],
            ua: &[u8],
            purpose: &[u8],
            digest: &[u8],
        ) -> Result<Vec<u8>>;
        fn member_digest(structure_ua: &[u8], ua_msg: &[u8]) -> Result<Vec<u8>>;
        fn canonical_id(text: &str) -> Result<String>;
        fn encode_msig(threshold: u16, members: &[Member]) -> Result<Vec<u8>>;
    }
}
use ffi::{KindInfo, Member};

fn info(k: &ua::Kind) -> KindInfo {
    KindInfo {
        kind: k.kind,
        name: k.name.into(),
        native: k.native,
        lengths: k.lengths.to_vec(),
        group: k.group.unwrap_or("").into(),
        has_group: k.group.is_some(),
    }
}
fn kind_info(kind: u16) -> R<KindInfo> {
    guard(|| Ok(info(ua::kind_info(kind)?)))
}
fn kind_count() -> usize {
    ua::KINDS.len()
}
fn kind_at(index: usize) -> KindInfo {
    info(&ua::KINDS[index]) // ponytail: caller (hpp kinds()) iterates 0..kind_count()
}
fn tag(kind: u16) -> R<Vec<u8>> {
    guard(|| Ok(ua::tag(kind)?.to_vec()))
}
fn kind_tag_string(kind: u16) -> R<String> {
    guard(|| Ok(ua::kind_tag_string(kind)?))
}
fn group_tag(group: &str) -> Vec<u8> {
    ua::group_tag(group).map(|t| t.to_vec()).unwrap_or_default()
}
fn group_tag_string(group: &str) -> String {
    ua::group_tag_string(group).unwrap_or_default()
}
fn msg_tag() -> Vec<u8> {
    ua::msg_tag().to_vec()
}
fn purpose_tag(purpose: &str) -> R<Vec<u8>> {
    guard(|| Ok(ua::purpose_tag(purpose)?.to_vec()))
}
fn ua_of(kind: u16, key_data: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::ua_of(kind, key_data)?.to_vec()))
}
fn derive_ua(kind: u16, key_data: &[u8], hedera_native: bool) -> R<Vec<u8>> {
    guard(|| Ok(ua::derive_ua(kind, key_data, hedera_native)?.to_vec()))
}
fn native_id(kind: u16, raw: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::native_id(kind, raw)?.to_vec()))
}
fn key_hash_of(kind: u16, key_data: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::key_hash_of(kind, key_data)?.map(|h| h.to_vec()).unwrap_or_default()))
}
fn validate_key_data(kind: u16, key_data: &[u8], hedera_native: bool) -> R<()> {
    guard(|| Ok(ua::validate_key_data(kind, key_data, hedera_native)?))
}
fn in_native_space(id: &[u8]) -> R<bool> {
    guard(|| Ok(ua::in_native_space(&a(id)?)))
}
fn is_native(kind: u16) -> bool {
    ua::is_native(kind)
}
fn is_zether(kind: u16) -> bool {
    ua::is_zether(kind)
}
fn is_signing(kind: u16) -> bool {
    ua::is_signing(kind)
}
fn is_member(kind: u16, hedera_native: bool) -> bool {
    ua::is_member(kind, hedera_native)
}
fn ua_message(kind: u16, purpose: &[u8], digest: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::ua_message(kind, &a(purpose)?, &a(digest)?)?.to_vec()))
}
fn chain_key_hash(chain_id: u64) -> Vec<u8> {
    ua::chain_key_hash(chain_id).to_vec()
}
fn pop_digest(chain_id: u64, chain_uid: &[u8], registry: &[u8], ua_id: &[u8], auth_ref: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::pop_digest(chain_id, &a(chain_uid)?, &a(registry)?, &a(ua_id)?, &a(auth_ref)?).to_vec()))
}
fn domain(generation: u32, chain_id: u64, registry: &[u8], chain_uid: &[u8]) -> R<ua::Domain> {
    Ok(ua::Domain { generation, chain_id, registry: a(registry)?, chain_uid: a(chain_uid)? })
}
fn ua_auth_domain_separator(generation: u32, chain_id: u64, registry: &[u8], chain_uid: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::ua_auth_domain_separator(&domain(generation, chain_id, registry, chain_uid)?).to_vec()))
}
fn ua_auth_digest(
    generation: u32,
    chain_id: u64,
    registry: &[u8],
    chain_uid: &[u8],
    ua_id: &[u8],
    purpose: &[u8],
    digest: &[u8],
) -> R<Vec<u8>> {
    guard(|| {
        let d = domain(generation, chain_id, registry, chain_uid)?;
        Ok(ua::ua_auth_digest(&d, &a(ua_id)?, &a(purpose)?, &a(digest)?).to_vec())
    })
}
fn member_digest(structure_ua: &[u8], ua_msg: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua::member_digest(&a(structure_ua)?, &a(ua_msg)?).to_vec()))
}
fn canonical_id(text: &str) -> R<String> {
    guard(|| Ok(ua::canonical_id(text)?))
}
fn encode_msig(threshold: u16, members: &[Member]) -> R<Vec<u8>> {
    guard(|| {
        let m = members.iter().map(|m| Ok((m.kind, a(&m.id)?, m.weight))).collect::<R<Vec<_>>>()?;
        Ok(ua::encode_msig(threshold, &m))
    })
}
