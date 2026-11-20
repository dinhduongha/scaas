// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The keystore container (spec §6.1, CLI-SDK-03): the reader and writer of clientkeys `src/keystore.js`, held to
//! `smartcontracts/vectors/keystore/keystore.json`. Only the canonical text is accepted (compact JSON, the fields in their
//! written order, the vaults by key): every refusal is `VaultFormat`, a `format` or `v` other than `scaas.keystore` / 2
//! `VaultVersion` (container v 2 holds vault v2 texts; owner 2026-11-19, T13b ruling 3: v 1 refused, no migration). The size
//! and depth are checked before anything is parsed; a vault text is read only to compare its `label` with its key, its `v` with
//! 2 and its `id` with the seed's.

use crate::error::SdkError;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use unicode_normalization::is_nfc;

pub const FORMAT: &str = "scaas.keystore";
pub const MAX_BYTES: usize = 16 << 20;
pub const MAX_DEPTH: usize = 5;
pub const MAX_SEEDS: usize = 64;
pub const MAX_VAULTS: usize = 64;
pub const MAX_VAULT_BYTES: usize = 2 << 20;
pub const MAX_ACCOUNTS: usize = 1024;
/// JavaScript's largest exact integer: a larger number reads differently in clientkeys.
const MAX_SAFE: u64 = (1 << 53) - 1;
const WORDS: [u64; 5] = [12, 15, 18, 21, 24];
const ORIGINS: [&str; 5] = ["generated", "imported", "bip85", "eoa-sig", "raw-key"];
const CLASSES: [&str; 2] = ["full", "classical-rooted"];
const WARNINGS: [&str; 2] = ["short_seed", "imported_key"];
const BACKUPS: [&str; 2] = ["pending", "verified"];
const TOP: [&str; 4] = ["format", "v", "rev", "seeds"];
const SEED: [&str; 11] = [
    "id",
    "label",
    "words",
    "fingerprint",
    "origin",
    "class",
    "warnings",
    "backup",
    "vaults",
    "accounts",
    "indexMac",
];

#[cfg(test)]
std::thread_local! {
    /// Texts that passed the size and depth checks and reached `serde_json` on this thread (the scan-before-parse test).
    pub(crate) static PARSED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The keystore: its revision and its seeds in display order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub struct Keystore {
    pub rev: u64,
    pub seeds: Vec<SeedEntry>,
}

/// One seed entry (public fields and vault ciphertexts only).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
pub struct SeedEntry {
    pub id: String,
    pub label: String,
    pub words: u32,
    pub fingerprint: String,
    pub origin: String,
    pub class: String,
    pub warnings: Vec<String>,
    pub backup: String,
    /// label → the exact vault v1 JSON text
    pub vaults: BTreeMap<String, String>,
    pub accounts: Vec<AccountRow>,
    pub index_mac: String,
}

/// An account row, by shape (spec §6.1), each with its fields in the written order.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(frb_expand, doc = frb_hint!(non_opaque))]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum AccountRow {
    Ua {
        id: String,
        name: String,
        kind: u64,
        account: u64,
        index: u64,
        ua: String,
    },
    Native {
        id: String,
        name: String,
        network: String,
        index: u64,
        coin_type: Option<u64>,
        change: Option<u64>,
        path: Option<String>,
        ss58_prefix: Option<u64>,
        address: String,
    },
    Key {
        id: String,
        name: String,
        kind: u64,
        key_data: String,
        credential_id: Option<String>,
        handle: Option<String>,
        ua: String,
    },
    Watch {
        id: String,
        name: String,
        watch: String,
    },
}

fn bad() -> SdkError {
    SdkError::VaultFormat
}

/// The fields of `o`: every key in `allowed` (a trailing `?` optional), every required one present.
fn only<'a>(v: &'a Value, allowed: &[&str]) -> Result<&'a Map<String, Value>, SdkError> {
    let o = v.as_object().ok_or_else(bad)?;
    let names: Vec<&str> = allowed.iter().map(|f| f.trim_end_matches('?')).collect();
    if o.keys().any(|k| !names.contains(&k.as_str())) {
        return Err(bad());
    }
    if allowed
        .iter()
        .any(|f| !f.ends_with('?') && !o.contains_key(*f))
    {
        return Err(bad());
    }
    Ok(o)
}

fn string(o: &Map<String, Value>, k: &str) -> Result<String, SdkError> {
    o.get(k)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(bad)
}

fn uint(o: &Map<String, Value>, k: &str) -> Result<u64, SdkError> {
    o.get(k)
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE)
        .ok_or_else(bad)
}

fn opt_string(o: &Map<String, Value>, k: &str) -> Result<Option<String>, SdkError> {
    o.get(k).map(|_| string(o, k)).transpose()
}

fn opt_uint(o: &Map<String, Value>, k: &str) -> Result<Option<u64>, SdkError> {
    o.get(k).map(|_| uint(o, k)).transpose()
}

fn hex_of(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A lower-case UUID v4.
pub fn is_uuid4(s: &str) -> bool {
    let b = s.as_bytes();
    let hexes = [(0, 8), (9, 13), (14, 18), (19, 23), (24, 36)];
    b.len() == 36
        && [8, 13, 18, 23].iter().all(|i| b.get(*i) == Some(&b'-'))
        && hexes
            .iter()
            .all(|(a, z)| s.get(*a..*z).is_some_and(|h| hex_of(h, z - a)))
        && b.get(14) == Some(&b'4')
        && matches!(b.get(19), Some(b'8' | b'9' | b'a' | b'b'))
}

/// A stored seed label: 1 to 64 Unicode scalar values, NFC, no control character (clientkeys' parse rule, held equal).
pub fn label_ok(label: &str) -> bool {
    let n = label.chars().count();
    (1..=64).contains(&n) && !label.chars().any(char::is_control) && is_nfc(label)
}

/// A label the SDK writes (a new seed): [`label_ok`] and no format (`Cf`, bidi) character either, the account names' rule, one
/// check for both (owner 2026-11-19, ruling E). A container read keeps clientkeys' parse rule ([`label_ok`]).
pub fn new_label_ok(label: &str) -> bool {
    label_ok(label) && !label.chars().any(crate::text::hidden)
}

fn row(v: &Value) -> Result<AccountRow, SdkError> {
    let o = v.as_object().ok_or_else(bad)?;
    let shape: &[&str] = if o.contains_key("watch") {
        &["id", "name", "watch"]
    } else if o.contains_key("network") {
        &[
            "id",
            "name",
            "network",
            "index",
            "coinType?",
            "change?",
            "path?",
            "ss58Prefix?",
            "address",
        ]
    } else if o.contains_key("keyData") {
        &[
            "id",
            "name",
            "kind",
            "keyData",
            "credentialId?",
            "handle?",
            "ua",
        ]
    } else {
        &["id", "name", "kind", "account", "index", "ua"]
    };
    let o = only(v, shape)?;
    let (id, name) = (string(o, "id")?, string(o, "name")?);
    Ok(if o.contains_key("watch") {
        AccountRow::Watch {
            id,
            name,
            watch: string(o, "watch")?,
        }
    } else if o.contains_key("network") {
        AccountRow::Native {
            id,
            name,
            network: string(o, "network")?,
            index: uint(o, "index")?,
            coin_type: opt_uint(o, "coinType")?,
            change: opt_uint(o, "change")?,
            path: opt_string(o, "path")?,
            ss58_prefix: opt_uint(o, "ss58Prefix")?,
            address: string(o, "address")?,
        }
    } else if o.contains_key("keyData") {
        AccountRow::Key {
            id,
            name,
            kind: uint(o, "kind")?,
            key_data: string(o, "keyData")?,
            credential_id: opt_string(o, "credentialId")?,
            handle: opt_string(o, "handle")?,
            ua: string(o, "ua")?,
        }
    } else {
        AccountRow::Ua {
            id,
            name,
            kind: uint(o, "kind")?,
            account: uint(o, "account")?,
            index: uint(o, "index")?,
            ua: string(o, "ua")?,
        }
    })
}

fn vault_label_ok(key: &str, text: &str, seed_id: &str) -> bool {
    let printable =
        (1..=128).contains(&key.len()) && key.bytes().all(|b| (0x21..=0x7e).contains(&b));
    printable
        && text.len() <= MAX_VAULT_BYTES
        && scaas_ua::json::depth_within(text.as_bytes(), 2).is_ok()
        && serde_json::from_str::<Value>(text).ok().is_some_and(|v| {
            v.get("label").and_then(Value::as_str) == Some(key)
                && v.get("v").and_then(Value::as_f64) == Some(2.0)
                && v.get("id").and_then(Value::as_str) == Some(seed_id)
        })
}

fn seed(v: &Value) -> Result<SeedEntry, SdkError> {
    let o = only(v, &SEED)?;
    let id = string(o, "id")?;
    let label = string(o, "label")?;
    let words = uint(o, "words")?;
    let fingerprint = string(o, "fingerprint")?;
    let origin = string(o, "origin")?;
    let class = string(o, "class")?;
    let backup = string(o, "backup")?;
    let index_mac = string(o, "indexMac")?;
    let warnings: Vec<String> = o
        .get("warnings")
        .and_then(Value::as_array)
        .ok_or_else(bad)?
        .iter()
        .map(|w| w.as_str().map(str::to_owned).ok_or_else(bad))
        .collect::<Result<_, _>>()?;
    let mut distinct = warnings.clone();
    distinct.sort();
    distinct.dedup();
    let ok = is_uuid4(&id)
        && label_ok(&label)
        && WORDS.contains(&words)
        && hex_of(&fingerprint, 8)
        && ORIGINS.contains(&origin.as_str())
        && CLASSES.contains(&class.as_str())
        && warnings.iter().all(|w| WARNINGS.contains(&w.as_str()))
        && distinct.len() == warnings.len()
        && BACKUPS.contains(&backup.as_str())
        && hex_of(&index_mac, 64);
    if !ok {
        return Err(bad());
    }
    let vo = o.get("vaults").and_then(Value::as_object).ok_or_else(bad)?;
    if vo.len() > MAX_VAULTS || !vo.contains_key("seed") {
        return Err(bad());
    }
    let mut vaults = BTreeMap::new();
    for (k, t) in vo {
        let t = t.as_str().ok_or_else(bad)?;
        if !vault_label_ok(k, t, &id) {
            return Err(bad());
        }
        vaults.insert(k.clone(), t.to_owned());
    }
    let rows = o
        .get("accounts")
        .and_then(Value::as_array)
        .ok_or_else(bad)?;
    if rows.len() > MAX_ACCOUNTS {
        return Err(bad());
    }
    let accounts = rows.iter().map(row).collect::<Result<_, _>>()?;
    Ok(SeedEntry {
        id,
        label,
        words: u32::try_from(words).map_err(|_| bad())?,
        fingerprint,
        origin,
        class,
        warnings,
        backup,
        vaults,
        accounts,
        index_mac,
    })
}

#[cfg_attr(frb_expand, doc = frb_hint!(ignore))]
impl Keystore {
    /// The container of `bytes`, every rule of clientkeys `parse` checked, and only its canonical text accepted.
    pub fn parse(bytes: &[u8]) -> Result<Keystore, SdkError> {
        if bytes.len() > MAX_BYTES || scaas_ua::json::depth_within(bytes, MAX_DEPTH).is_err() {
            return Err(bad());
        }
        #[cfg(test)]
        PARSED.with(|n| n.set(n.get() + 1));
        let v: Value = serde_json::from_slice(bytes).map_err(|_| bad())?;
        let top = v.as_object().ok_or_else(bad)?;
        let format_ok = top.get("format").and_then(Value::as_str) == Some(FORMAT);
        // clientkeys compares numbers (`1.0 === 1`): a `v` of 1.0 passes here and fails the canonical form below
        if !format_ok || top.get("v").and_then(Value::as_f64) != Some(2.0) {
            return Err(SdkError::VaultVersion);
        }
        let top = only(&v, &TOP)?;
        let rev = uint(top, "rev")?;
        let list = top.get("seeds").and_then(Value::as_array).ok_or_else(bad)?;
        if list.len() > MAX_SEEDS {
            return Err(bad());
        }
        let seeds: Vec<SeedEntry> = list.iter().map(seed).collect::<Result<_, _>>()?;
        let ks = Keystore { rev, seeds };
        ks.check_unique()?;
        if ks.serialize_unchecked().as_bytes() != bytes {
            return Err(bad());
        }
        Ok(ks)
    }

    fn check_unique(&self) -> Result<(), SdkError> {
        for (i, s) in self.seeds.iter().enumerate() {
            let earlier = self.seeds.get(..i).unwrap_or_default();
            if earlier.iter().any(|e| e.id == s.id || e.label == s.label) {
                return Err(bad());
            }
        }
        Ok(())
    }

    /// The canonical text (clientkeys `serialize`), after the rules every reader checks: what `parse` accepts.
    pub fn serialize(&self) -> Result<String, SdkError> {
        let text = self.serialize_unchecked();
        Keystore::parse(text.as_bytes())?;
        Ok(text)
    }

    fn serialize_unchecked(&self) -> String {
        let seeds: Vec<String> = self.seeds.iter().map(seed_json).collect();
        format!(
            "{{\"format\":{},\"v\":2,\"rev\":{},\"seeds\":[{}]}}",
            js(FORMAT),
            self.rev,
            seeds.join(",")
        )
    }
}

/// A string as `JSON.stringify` writes it (serde_json escapes the same characters, in lower-case hex).
fn js(s: &str) -> String {
    Value::from(s).to_string()
}

fn seed_json(s: &SeedEntry) -> String {
    let warnings: Vec<String> = s.warnings.iter().map(|w| js(w)).collect();
    let vaults: Vec<String> = s
        .vaults
        .iter()
        .map(|(k, t)| format!("{}:{}", js(k), js(t)))
        .collect();
    let accounts: Vec<String> = s.accounts.iter().map(row_json).collect();
    format!(
        "{{\"id\":{},\"label\":{},\"words\":{},\"fingerprint\":{},\"origin\":{},\"class\":{},\"warnings\":[{}],\"backup\":{},\"vaults\":{{{}}},\"accounts\":[{}],\"indexMac\":{}}}",
        js(&s.id),
        js(&s.label),
        s.words,
        js(&s.fingerprint),
        js(&s.origin),
        js(&s.class),
        warnings.join(","),
        js(&s.backup),
        vaults.join(","),
        accounts.join(","),
        js(&s.index_mac)
    )
}

/// The `accounts` array of an entry as the container writes it: the text the index MAC covers (spec §6.2).
pub fn accounts_json(rows: &[AccountRow]) -> String {
    let rows: Vec<String> = rows.iter().map(row_json).collect();
    format!("[{}]", rows.join(","))
}

fn row_json(r: &AccountRow) -> String {
    let mut f: Vec<(&str, String)> = Vec::new();
    match r {
        AccountRow::Ua {
            id,
            name,
            kind,
            account,
            index,
            ua,
        } => {
            f.extend([("id", js(id)), ("name", js(name))]);
            f.extend([
                ("kind", kind.to_string()),
                ("account", account.to_string()),
                ("index", index.to_string()),
                ("ua", js(ua)),
            ]);
        }
        AccountRow::Native {
            id,
            name,
            network,
            index,
            coin_type,
            change,
            path,
            ss58_prefix,
            address,
        } => {
            f.extend([("id", js(id)), ("name", js(name)), ("network", js(network))]);
            f.push(("index", index.to_string()));
            f.extend(coin_type.map(|c| ("coinType", c.to_string())));
            f.extend(change.map(|c| ("change", c.to_string())));
            f.extend(path.as_deref().map(|p| ("path", js(p))));
            f.extend(ss58_prefix.map(|p| ("ss58Prefix", p.to_string())));
            f.push(("address", js(address)));
        }
        AccountRow::Key {
            id,
            name,
            kind,
            key_data,
            credential_id,
            handle,
            ua,
        } => {
            f.extend([
                ("id", js(id)),
                ("name", js(name)),
                ("kind", kind.to_string()),
            ]);
            f.push(("keyData", js(key_data)));
            f.extend(credential_id.as_deref().map(|c| ("credentialId", js(c))));
            f.extend(handle.as_deref().map(|h| ("handle", js(h))));
            f.push(("ua", js(ua)));
        }
        AccountRow::Watch { id, name, watch } => {
            f.extend([("id", js(id)), ("name", js(name)), ("watch", js(watch))]);
        }
    }
    let fields: Vec<String> = f.iter().map(|(k, v)| format!("\"{k}\":{v}")).collect();
    format!("{{{}}}", fields.join(","))
}
