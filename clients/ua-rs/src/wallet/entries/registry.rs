// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! scaas-sdk T13: the `UARegistry` writes as named entries (no typed struct of their own: a registration signs its portable
//! record, CTR-UA-07). A copy of the registry rows of `scaas-node/src/typed.rs` `PLAIN`, held equal by `tests/entries.rs`; the
//! calldata built from named JSON by the same strict parse as the typed rows (every field present, no other, lists and bytes
//! bounded). UNAUDITED.
use super::{abi_type, fields_of, seq, take, Error, Result};
use crate::keccak256;
use serde_json::Value;

/// `(entry, arguments)`: the node's `PLAIN` rows on the registry, in its order.
const ROWS: &[(&str, &str)] = &[
    ("register", "uint16 kind,bytes keyData,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("registerMsig", "MsigStructure structure,UAAttrs attrs,MemberSig[] pop,bytes pqzPop"),
    ("registerWebAuthn", "WebAuthnKey key,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("registerMuSig2", "uint16 kind,MuSig2Key key,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("registerFrost", "uint16 kind,FrostKey key,UAAttrs attrs,bytes pop,bytes pqzPop"),
    ("setKemKey", "bytes32 ua,uint64 version,KemKey kem,UASig sig"),
    ("storePqzPop", "bytes32 ua,uint64 version,bytes pqzPop"),
    ("setPqzKey", "bytes32 ua,uint64 version,bytes pqzKey,bytes32 pqzPopHash,UASig sig"),
    ("setPqzScopedKey", "bytes32 ua,address scope,uint64 version,bytes pqzKey,bytes32 pqzPopHash,KemKey openKem,uint64 validUntilBlock,UASig sig"),
    ("storePqzScopedPop", "bytes32 ua,address scope,uint64 version,bytes pqzPop"),
    ("cacheExpandedKey", "uint16 kind,bytes pk,uint256 part"),
    ("acceptMembership", "bytes32 ua,MemberSig memberSig"),
    ("updateMsig", "bytes32 ua,uint64 version,MsigStructure structure,uint256 enabled,uint64 validUntilBlock,MemberSig[] sigs,bytes32 chainUid"),
];

/// One registry row as the tests and the SDK read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryRow {
    pub entry: &'static str,
    /// `type name` pairs, comma-joined, as the node's row
    pub fields: &'static str,
    /// the ABI signature (struct names as tuples): its keccak's first four bytes are the selector
    pub signature: String,
}

/// Every registry row.
pub fn registry_rows() -> Vec<RegistryRow> {
    ROWS.iter()
        .filter_map(|(entry, fields)| {
            let types = fields_of(fields).ok()?;
            let abi: Vec<String> = types
                .iter()
                .map(|(t, _)| abi_type(t))
                .collect::<Result<_>>()
                .ok()?;
            Some(RegistryRow {
                entry,
                fields,
                signature: format!("{entry}({})", abi.join(",")),
            })
        })
        .collect()
}

/// The calldata of registry write `entry` from its arguments by name (`{"entry": …}` may stay in the object, as
/// `ua_portable` JSON rows carry it, and must then name `entry`). `Argument`: no such row, a field missing or unknown, a
/// value its type refuses.
pub fn registry_call(entry: &str, args: &Value) -> Result<Vec<u8>> {
    let (_, f) = ROWS
        .iter()
        .find(|(e, _)| *e == entry)
        .ok_or(Error::Argument)?;
    let mut o = args.as_object().ok_or(Error::Argument)?.clone();
    if let Some(e) = o.remove("entry") {
        if e.as_str() != Some(entry) {
            return Err(Error::Argument);
        }
    }
    let fields = fields_of(f)?;
    let vals = take(&fields, &o)?;
    let types: Vec<String> = fields.iter().map(|(t, _)| t.clone()).collect();
    let abi: Vec<String> = types.iter().map(|t| abi_type(t)).collect::<Result<_>>()?;
    let sig = format!("{entry}({})", abi.join(","));
    let mut out = keccak256(sig.as_bytes())
        .get(..4)
        .ok_or(Error::Argument)?
        .to_vec();
    out.extend(seq(&types, &vals)?);
    Ok(out)
}
