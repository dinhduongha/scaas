// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! `PqVault`'s signed records, PqVault's dedicated signing path (owner 2026-11-22, CLI-PQV-12; feature `app-core`): the generic
//! app signing ([`super::sign_app_record`]) refuses PqVault's domain "SCaaS PqVault" and its purpose `P_V`, so a vault record is
//! signed and verified here only. It takes typed data, never a digest, and accepts exactly the contract's records
//! (`PqVaultTypes.sol`): a primary type of [`RECORDS`] whose `encodeType` is its type string, in mode 0's domain `DS_V`
//! (`name, version, salt`, "SCaaS PqVault", "1", `salt = APP_ID`) on the portable path `requirePortableApp(APP_ID)`, or in mode
//! 1's `DS_B` (`name, version, chainId, verifyingContract`, the same name and version; the chain id and the instance are the
//! caller's to check against its profile) on the chain-bound path under `P_V = appPurpose(APP_ID)`. Then it signs and verifies
//! as the generic path does (a UA key on either path, a native EVM key on the chain-bound one, an `msig` by its members).
//! Vectors: `smartcontracts/vectors/pqvault/records.json`. UNAUDITED.
use super::eip712::TypedData;
use super::signer::Signer;
use super::uasig::{sign_app_digest, verify_app_digest};
use super::{AppPath, AppRecordState, Error, Result};
use crate::ua_portable::{app_purpose_ns, UASig};
use crate::{keccak256, Domain};

/// The signed records and their `encodeType` strings, exactly as `PqVaultTypes.sol` hashes them (`*_TYPEHASH`).
pub const RECORDS: &[(&str, &str)] = &[
    (
        "PqVaultCreate",
        "PqVaultCreate(bytes32 creator,uint64 nonce,uint8 mode,bytes32 homeChain,address homeVaultContract,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo,uint8 groupMode)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
    ),
    (
        "PqVaultEpoch",
        "PqVaultEpoch(bytes32 vaultId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,MemberKey[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo)MemberKey(bytes32 ua,uint64 keyId,bytes32 via)",
    ),
    (
        "PqVaultLeave",
        "PqVaultLeave(bytes32 vaultId,bytes32 epochId,bytes32 member,uint64 nonce)",
    ),
    (
        "PqVaultRemove",
        "PqVaultRemove(bytes32 vaultId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)",
    ),
    (
        "PqVaultItem",
        "PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)",
    ),
    (
        "PqVaultEdit",
        "PqVaultEdit(bytes32 itemId,bytes32 epochId,bytes32 author,uint64 nonce,uint32 version,bytes ciphertext)",
    ),
    (
        "PqVaultBatch",
        "PqVaultBatch(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,PqVaultItem[] items)PqVaultItem(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)",
    ),
];

pub const DOMAIN_NAME: &str = "SCaaS PqVault";
pub const DOMAIN_VERSION: &str = "1";

/// `APP_ID = keccak256("scaas.pqvault.v1")`, PqVault's id in the registry's open app namespace.
pub fn app_id() -> [u8; 32] {
    keccak256(b"scaas.pqvault.v1")
}

/// `P_V = appPurpose(APP_ID) = keccak256(abi.encode(APP_PURPOSE_NS, APP_ID))`: what every PqVault record is signed under.
pub fn purpose() -> [u8; 32] {
    keccak256(&[app_purpose_ns(), app_id()].concat())
}

/// `DS_V = keccak256(abi.encode(keccak256("EIP712Domain(string name,string version,bytes32 salt)"), keccak256(name),
/// keccak256(version), APP_ID))`.
fn ds_v() -> [u8; 32] {
    keccak256(
        &[
            keccak256(b"EIP712Domain(string name,string version,bytes32 salt)"),
            keccak256(DOMAIN_NAME.as_bytes()),
            keccak256(DOMAIN_VERSION.as_bytes()),
            app_id(),
        ]
        .concat(),
    )
}

/// The path `typed`'s domain puts a record on: `DS_V` portable under `APP_ID`, `DS_B` chain-bound under `P_V`; any other
/// domain none.
fn path_of(typed: &TypedData) -> Option<AppPath> {
    let v = typed.to_value();
    let d = v.get("domain")?.as_object()?;
    if d.get("name")?.as_str()? != DOMAIN_NAME || d.get("version")?.as_str()? != DOMAIN_VERSION {
        return None;
    }
    let mut keys: Vec<&str> = d.keys().map(String::as_str).collect();
    keys.sort_unstable();
    match keys[..] {
        ["name", "salt", "version"] => (typed.domain_separator().ok()? == ds_v())
            .then_some(AppPath::Portable { app_id: app_id() }),
        ["chainId", "name", "verifyingContract", "version"] => {
            Some(AppPath::ChainBound { purpose: purpose() })
        }
        _ => None,
    }
}

/// The typed digest of the PqVault record `typed` on `path`: a primary type outside [`RECORDS`] or another `encodeType`
/// (`Argument`); a domain other than `DS_V` or `DS_B`, or one whose path is not `path` (`AppDomainRefused`).
pub fn digest(path: &AppPath, typed: &TypedData) -> Result<[u8; 32]> {
    let t = typed.primary_type();
    if !RECORDS
        .iter()
        .any(|(n, s)| *n == t && typed.encode_type() == *s)
    {
        return Err(Error::Argument);
    }
    if path_of(typed).as_ref() != Some(path) {
        return Err(Error::AppDomainRefused);
    }
    typed.digest()
}

/// The `UASig` of a single key over the PqVault record `typed` on `path` ([`digest`]'s refusals first), signed as
/// [`super::sign_app_record`] signs: path A a UA key (a native key: `Argument`), path B a UA key or a native EVM key over
/// `UAAuth` under `registry`; a key claiming the `msig` kind: `Argument`.
pub fn sign(
    key: &dyn Signer,
    registry: Option<&Domain>,
    path: &AppPath,
    typed: &TypedData,
) -> Result<UASig> {
    sign_app_digest(key, registry, path, &digest(path, typed)?)
}

/// The `UASig` of the `msig` whose first structure is `first` over the PqVault record `typed` on `path` (owner 2026-11-22):
/// [`digest`]'s refusals first, then as the generic `msig` paths sign: path A [`super::msig_sig_app`] (a native member over
/// the record itself), path B the members over `memberDigest(ua, uaMessage(msig, P_V, digest))` under `member`, a native
/// member over `UAAuth(id, member, md)` in `registry` (the registry generation's domain). The same bounds and checks: a
/// disabled slot or a set not minimal at either level refused before anything is signed.
pub fn sign_msig(
    first: &[u8],
    current: &crate::ua_portable::Current,
    inner: &crate::ua_portable::Inner,
    registry: Option<&Domain>,
    path: &AppPath,
    typed: &TypedData,
    slots: &[super::Slot],
) -> Result<UASig> {
    let d = digest(path, typed)?;
    match path {
        AppPath::Portable { app_id } => {
            super::msig_sig_app(first, current, inner, app_id, typed, slots)
        }
        AppPath::ChainBound { purpose } => {
            super::uasig::msig_sig_app_chain(first, current, inner, purpose, &d, registry, slots)
        }
    }
}

/// Whether `sig` is `ua`'s signature of the PqVault record `typed` on `path`, as the registry judges it on `state`
/// ([`super::verify_app_record`]'s checks after [`digest`]'s refusals). A refused record: `false`, no detail.
pub fn verify(
    ua: &[u8; 32],
    path: &AppPath,
    typed: &TypedData,
    sig: &UASig,
    state: &AppRecordState,
) -> bool {
    digest(path, typed).is_ok_and(|d| verify_app_digest(ua, path, &d, sig, state))
}
