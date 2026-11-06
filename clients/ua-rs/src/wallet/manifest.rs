// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! The manifest, discovery, import and the sealed backup (spec §6.3, §8.3, §8.4, C-03, C-11; clientkeys `seal.js`; T9).
//!
//! The [`Manifest`] is the wallet's public record: the UA keys, native keys and KEM keys written at their first use, the
//! imported keys, `backup_generation` and `backup_senders`; `lock()` keeps it, it travels in the backup and link payloads (its
//! `entries`) and in a vault of label `manifest`. It is never a trust anchor. An imported key ([`Wallet::import_native_key`])
//! is tagged with its network (CLI-SGN-11: refused for any other) and stored as `native-import:<network>:<n>`.
//!
//! A backup ([`Wallet::backup_seal`]) is the container `scaas/backup/v1` of `BackupPayload {v: 1, generation, entropy, secrets:
//! [{label, bytes}], manifest: {entries: [{kind, account, index, ua}]}}`, JSON in this field order (owner 2026-11-05), each
//! seal raising `backup_generation`; the BIP-39 passphrase is never in it. [`Wallet::restore_backup`] opens it only as
//! [`super::KemKeyPair::open_container`] accepts it, then the payload's entropy must derive `sender.ua` at the manifest entry
//! naming it (`ContainerSender`), and over a device that holds this wallet an older generation is `BackupRollback` unless the
//! caller passes [`AllowRollback`]; an equal generation installs nothing. UNAUDITED.
use super::eip712::{from_hex, to_hex};
use super::seal::{is_sender_kind, now, seal_container, ContainerExpect, ContainerSigner, Recipient, SealedContainer, PURPOSE_BACKUP};
use super::vault::{Unlock, Vault, PrfEnvelope, SEED_LENGTHS};
use super::{bounded, derive, seed_of, Error, KemKeyPair, KeyId, Network, NativeKey, Result, UaKey, Wallet};
use crate::derive_ua;
use crate::ua8::{Accepted, Members};
use base64ct::{Base64UrlUnpadded, Encoding};
use serde_json::Value;
use zeroize::Zeroizing;

/// A UA key the wallet used: `{kind, account, index, ua}` (index 0 for the EIP-2333 kinds).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub kind: u16,
    pub account: u32,
    pub index: u32,
    pub ua: [u8; 32],
}

/// A native key the wallet used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeEntry {
    pub network: Network,
    pub coin_type: Option<u32>,
    pub index: u32,
}

/// A KEM key the wallet used (derived from its UA key: spec §6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KemEntry {
    pub ua: [u8; 32],
    pub version: u64,
}

/// An imported key: `native-import:<network>:<n>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImportEntry {
    pub network: Network,
    pub n: u32,
}

/// The wallet's public record (spec §8.3).
// ponytail: no `label` / `created` per entry, no KEM `origin` and no FROST shares: nothing produces them in this round; add
// them with their first producer (a random KEM key, a DKG share, a naming call).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Manifest {
    pub entries: Vec<ManifestEntry>,
    pub natives: Vec<NativeEntry>,
    pub kem: Vec<KemEntry>,
    pub imports: Vec<ImportEntry>,
    /// The generation of the last backup this wallet sealed or restored (§6.3).
    pub backup_generation: u64,
    /// The UAs whose backups this wallet agreed to hold: a restore's approved sender set (§6.3).
    pub backup_senders: Vec<[u8; 32]>,
}

/// A manifest vault's JSON (spec §9.3): 1 MiB, `{entries: [{…}]}` is depth 3.
const MANIFEST_JSON: usize = 1 << 20;
const MANIFEST_DEPTH: usize = 3;
/// A backup payload: `{manifest: {entries: [{…}]}}` is depth 4.
const PAYLOAD_DEPTH: usize = 4;
/// `gap` of [`Wallet::discover_candidates`].
const GAP_MAX: u32 = 1024;
/// The prefix of an imported key's label.
const IMPORT: &str = "native-import:";

impl Manifest {
    pub(crate) fn add_ua(&mut self, kind: u16, account: u32, index: u32, ua: [u8; 32]) {
        let e = ManifestEntry { kind, account, index, ua };
        if !self.entries.contains(&e) {
            self.entries.push(e);
        }
    }
    pub(crate) fn add_native(&mut self, network: Network, coin_type: Option<u32>, index: u32) {
        let e = NativeEntry { network, coin_type, index };
        if !self.natives.contains(&e) {
            self.natives.push(e);
        }
    }
    pub(crate) fn add_kem(&mut self, ua: [u8; 32], version: u64) {
        let e = KemEntry { ua, version };
        if !self.kem.contains(&e) {
            self.kem.push(e);
        }
    }

    /// `{v: 1, entries, natives, kem, imports, backupGeneration, backupSenders}` (UAs `0x` hex).
    pub fn to_json(&self) -> String {
        let list = |v: Vec<String>| v.join(",");
        let entries = list(self.entries.iter().map(entry_json).collect());
        let natives = list(
            self.natives
                .iter()
                .map(|n| {
                    let c = n.coin_type.map_or("null".to_owned(), |c| c.to_string());
                    format!("{{\"network\":\"{}\",\"coinType\":{c},\"index\":{}}}", n.network.name(), n.index)
                })
                .collect(),
        );
        let kem = list(self.kem.iter().map(|k| format!("{{\"ua\":\"{}\",\"version\":{}}}", to_hex(&k.ua), k.version)).collect());
        let imports = list(self.imports.iter().map(|i| format!("{{\"network\":\"{}\",\"n\":{}}}", i.network.name(), i.n)).collect());
        let senders = list(self.backup_senders.iter().map(|u| format!("\"{}\"", to_hex(u))).collect());
        format!(
            "{{\"v\":1,\"entries\":[{entries}],\"natives\":[{natives}],\"kem\":[{kem}],\"imports\":[{imports}],\"backupGeneration\":{},\
             \"backupSenders\":[{senders}]}}",
            self.backup_generation
        )
    }

    /// The named fields of a manifest JSON: `Argument` past 1 MiB or depth 3 or for a malformed field.
    pub fn from_json(json: &[u8]) -> Result<Manifest> {
        let v = bounded::json(json, MANIFEST_JSON, MANIFEST_DEPTH)?;
        parse_manifest(&v).ok_or(Error::Argument)
    }
}

fn entry_json(e: &ManifestEntry) -> String {
    format!("{{\"kind\":{},\"account\":{},\"index\":{},\"ua\":\"{}\"}}", e.kind, e.account, e.index, to_hex(&e.ua))
}

fn list<'a>(v: &'a Value, k: &str) -> Option<&'a [Value]> {
    v.get(k)?.as_array().map(Vec::as_slice)
}
fn u31(v: &Value, k: &str) -> Option<u32> {
    u32::try_from(v.get(k)?.as_u64()?).ok().filter(|x| *x < derive::HARDENED)
}
/// A UA as `0x` and 64 lower-case hex digits (as clientkeys `hex` writes it), nothing else.
fn ua_of(v: &Value) -> Option<[u8; 32]> {
    let s = v.as_str()?;
    let b: [u8; 32] = from_hex(s)?.try_into().ok()?;
    (to_hex(&b) == s).then_some(b)
}
fn network_of(v: &Value) -> Option<Network> {
    Network::from_name(v.get("network")?.as_str()?)
}
fn entry_of(v: &Value) -> Option<ManifestEntry> {
    let kind = u16::try_from(v.get("kind")?.as_u64()?).ok()?;
    Some(ManifestEntry { kind, account: u31(v, "account")?, index: u31(v, "index")?, ua: ua_of(v.get("ua")?)? })
}

fn parse_manifest(v: &Value) -> Option<Manifest> {
    if v.get("v")?.as_u64()? != 1 {
        return None;
    }
    let natives = list(v, "natives")?
        .iter()
        .map(|n| {
            let coin_type = match n.get("coinType")? {
                Value::Null => None,
                c => Some(u32::try_from(c.as_u64()?).ok().filter(|x| *x < derive::HARDENED)?),
            };
            Some(NativeEntry { network: network_of(n)?, coin_type, index: u31(n, "index")? })
        })
        .collect::<Option<_>>()?;
    Some(Manifest {
        entries: list(v, "entries")?.iter().map(entry_of).collect::<Option<_>>()?,
        natives,
        kem: list(v, "kem")?.iter().map(|k| Some(KemEntry { ua: ua_of(k.get("ua")?)?, version: k.get("version")?.as_u64()? })).collect::<Option<_>>()?,
        imports: list(v, "imports")?.iter().map(|i| Some(ImportEntry { network: network_of(i)?, n: u32::try_from(i.get("n")?.as_u64()?).ok()? })).collect::<Option<_>>()?,
        backup_generation: v.get("backupGeneration")?.as_u64()?,
        backup_senders: list(v, "backupSenders")?.iter().map(ua_of).collect::<Option<_>>()?,
    })
}

fn import_label(i: &ImportEntry) -> String {
    format!("{IMPORT}{}:{}", i.network.name(), i.n)
}

/// `native-import:<network>:<n>` (`n` canonical decimal), else `Argument`.
fn parse_import_label(label: &str) -> Result<ImportEntry> {
    let (net, n) = label.strip_prefix(IMPORT).and_then(|r| r.split_once(':')).ok_or(Error::Argument)?;
    let n: u32 = n.parse().map_err(|_| Error::Argument)?;
    let network = Network::from_name(net).ok_or(Error::Argument)?;
    let e = ImportEntry { network, n };
    (import_label(&e) == label).then_some(e).ok_or(Error::Argument)
}

/// The marker of a restore that may install an older backup over newer state, passed after the user confirmed it (spec §6.3;
/// clientkeys `allowRollback: true`).
#[derive(Clone, Copy, Debug)]
pub struct AllowRollback;

/// `BackupPayload` (spec §8.4): every secret `Zeroizing`.
struct BackupPayload {
    generation: u64,
    entropy: Zeroizing<Vec<u8>>,
    secrets: Vec<(ImportEntry, Zeroizing<Vec<u8>>)>,
    entries: Vec<ManifestEntry>,
}

impl BackupPayload {
    /// `{v, generation, entropy, secrets: [{label, bytes}], manifest: {entries: [{kind, account, index, ua}]}}`, the bytes
    /// base64url: clientkeys `encodeBackup`'s bytes.
    fn to_json(&self) -> Zeroizing<String> {
        let mut s = Zeroizing::new(String::with_capacity(256));
        s.push_str(&format!("{{\"v\":1,\"generation\":{},\"entropy\":\"", self.generation));
        s.push_str(&Zeroizing::new(Base64UrlUnpadded::encode_string(&self.entropy)));
        s.push_str("\",\"secrets\":[");
        for (n, (e, b)) in self.secrets.iter().enumerate() {
            s.push_str(if n == 0 { "{\"label\":\"" } else { ",{\"label\":\"" });
            s.push_str(&import_label(e));
            s.push_str("\",\"bytes\":\"");
            s.push_str(&Zeroizing::new(Base64UrlUnpadded::encode_string(b)));
            s.push_str("\"}");
        }
        s.push_str("],\"manifest\":{\"entries\":[");
        s.push_str(&self.entries.iter().map(entry_json).collect::<Vec<_>>().join(","));
        s.push_str("]}}");
        s
    }

    /// `Argument` for anything malformed (owner 2026-11-05): `v` ≠ 1, an entropy of other than 16, 20, 24, 28 or 32 bytes, a
    /// secret of another label than `native-import:`, an entry out of range. The JSON's strings are wiped after the read.
    fn from_json(pt: &[u8]) -> Result<BackupPayload> {
        let mut v = bounded::json(pt, super::seal::MAX_PT, PAYLOAD_DEPTH)?;
        let p = parse_payload(&v);
        bounded::wipe(&mut v);
        p.ok_or(Error::Argument)
    }
}

fn parse_payload(v: &Value) -> Option<BackupPayload> {
    let b64 = |x: &Value| Base64UrlUnpadded::decode_vec(x.as_str()?).ok().map(Zeroizing::new);
    if v.get("v")?.as_u64()? != 1 {
        return None;
    }
    let entropy = b64(v.get("entropy")?).filter(|e| SEED_LENGTHS.contains(&e.len()))?;
    let secrets = match v.get("secrets") {
        None => vec![],
        Some(l) => l
            .as_array()?
            .iter()
            .map(|s| Some((parse_import_label(s.get("label")?.as_str()?).ok()?, b64(s.get("bytes")?)?)))
            .collect::<Option<_>>()?,
    };
    let entries = list(v.get("manifest")?, "entries")?.iter().map(entry_of).collect::<Option<_>>()?;
    Some(BackupPayload { generation: v.get("generation")?.as_u64()?, entropy, secrets, entries })
}

/// Whether the payload's entropy (with `bip39_passphrase`) derives `sender` at the manifest entry naming it.
fn derives_sender(p: &BackupPayload, sender: &[u8; 32], bip39_passphrase: &str) -> bool {
    let Some(e) = p.entries.iter().find(|e| e.ua == *sender) else { return false };
    let derived = || -> Result<[u8; 32]> {
        let seed = seed_of(&p.entropy, bip39_passphrase)?;
        let (_secret, key_data) = derive::ua_key(e.kind, derive::ua_secret(&*seed, e.kind, e.account, e.index)?)?;
        Ok(derive_ua(e.kind, &key_data, false)?)
    };
    derived().ok() == Some(*sender)
}

impl Wallet {
    /// The public manifest (kept by `lock()`).
    pub fn manifest(&self) -> Manifest {
        self.store.manifest()
    }

    /// Records `ua` as a UA whose backups this wallet agreed to hold (the restore's approved sender set).
    pub fn add_backup_sender(&self, ua: [u8; 32]) {
        self.store.note(|m| {
            if !m.backup_senders.contains(&ua) {
                m.backup_senders.push(ua);
            }
        });
    }

    /// `(index, ua)` of the UA keys `kind` of `account` at indices `0..gap` (BIP-44 style, gap 20; index 0 alone for the
    /// EIP-2333 kinds `0x0104`–`0x0107`), derived and dropped: nothing is stored or written to the manifest. The registry scan
    /// is the caller's. `Argument` for `gap > 1024`, an account ≥ 2^31 or a kind with no UA of its own (`0x0110`, `0x0112`).
    pub fn discover_candidates(&self, kind: u16, account: u32, gap: u32) -> Result<Vec<(u32, [u8; 32])>> {
        if gap > GAP_MAX || matches!(kind, 0x0110 | 0x0112) {
            return Err(Error::Argument);
        }
        let n = if (0x0104..=0x0107).contains(&kind) { gap.min(1) } else { gap };
        self.store.with_seed(|seed| {
            (0..n)
                .map(|i| {
                    let (_secret, key_data) = derive::ua_key(kind, derive::ua_secret(seed, kind, account, i)?)?;
                    Ok((i, derive_ua(kind, &key_data, false)?))
                })
                .collect()
        })
    }

    /// Imports an existing key of `network` (a 32-byte secp256k1 secret for `evm`, `cosmos`, `hedera_ecdsa`; a 32-byte ed25519
    /// seed for the others): stored as `native-import:<network>:<n>` (`n` the next free number), tagged with its network,
    /// listed in the manifest and the backup. `Argument` for another length or an invalid secret; `WalletLocked` while locked.
    // ponytail: raw 32-byte secrets only; a Stellar `S…` strkey or a 64-byte Solana keypair is the caller's to split.
    pub fn import_native_key(&self, network: Network, secret: &[u8]) -> Result<NativeKey> {
        let n = self.store.manifest().imports.iter().map(|i| i.n.saturating_add(1)).max().unwrap_or(0);
        self.import_at(ImportEntry { network, n }, secret)?;
        self.imported_key(network, n)
    }

    /// Imported key `n`, only for the network it was imported for (CLI-SGN-11): `Argument` for another network or an unknown
    /// `n`. Its `index()` is `n`.
    pub fn imported_key(&self, network: Network, n: u32) -> Result<NativeKey> {
        if !self.store.manifest().imports.contains(&ImportEntry { network, n }) {
            return Err(Error::Argument);
        }
        let (secret, public_key) = self.store.key(KeyId::Import(n), |_| Err(Error::Argument))?;
        Ok(NativeKey { network, index: n, coin_type: None, public_key, secret })
    }

    /// `secret` as import `e`: already held with the same bytes, a no-op; listed (a manifest vault opened first) and not held,
    /// installed; another network or other bytes under the same `n`: `Argument`.
    fn import_at(&self, e: ImportEntry, secret: &[u8]) -> Result<()> {
        if secret.len() != 32 {
            return Err(Error::Argument);
        }
        let public = derive::native_public(e.network, secret)?;
        self.store.with_all(|a, m| {
            if m.imports.iter().any(|i| i.n == e.n && i.network != e.network) {
                return Err(Error::Argument);
            }
            match a.secret(KeyId::Import(e.n)) {
                Some(s) if s == secret => {}
                Some(_) => return Err(Error::Argument),
                None => a.insert(KeyId::Import(e.n), secret, public)?,
            }
            if !m.imports.contains(&e) {
                m.imports.push(e);
            }
            Ok(())
        })
    }

    /// A vault of label `manifest` (the manifest JSON) or `native-import:<network>:<n>` (that imported key), as
    /// [`Wallet::seal_vault`]; `Argument` for another label or a key the wallet does not hold.
    pub fn seal_label_vault(&self, label: &str, vault_passphrase: &str, prf: Option<&PrfEnvelope>) -> Result<Vault> {
        let secret = if label == "manifest" {
            Zeroizing::new(self.manifest().to_json().into_bytes())
        } else {
            let e = parse_import_label(label)?;
            self.store.with_all(|a, m| {
                let held = m.imports.contains(&e).then(|| a.secret(KeyId::Import(e.n))).flatten();
                held.map(|s| Zeroizing::new(s.to_vec())).ok_or(Error::Argument)
            })?
        };
        Vault::seal(label, &secret, vault_passphrase, prf)
    }

    /// Opens a vault of [`Wallet::seal_label_vault`] into this wallet: `manifest` replaces the manifest, `native-import:…`
    /// installs that key. `Argument` for another label (the seed vault opens with [`Wallet::open_vault`]); errors of the
    /// vault as [`Wallet::open_vault`].
    pub fn open_label_vault(&self, vault: &Vault, unlock: Unlock) -> Result<()> {
        if vault.label() == "manifest" {
            let m = Manifest::from_json(&vault.open(unlock)?)?;
            self.store.note(|x| *x = m);
            return Ok(());
        }
        let e = parse_import_label(vault.label())?;
        self.import_at(e, &vault.open(unlock)?)
    }

    /// The backup of this wallet (spec §6.3, §8.4): `backup_generation` raised once, then one container `scaas/backup/v1` per
    /// recipient of `BackupPayload {v: 1, generation, entropy, secrets, manifest: {entries}}` (the entropy at its own length,
    /// the imported keys, the UA entries with `sender`'s), signed by `sender`, a UA key of this wallet of a kind that signs
    /// containers (`Argument` otherwise, or for no recipient); `created` the clock. The BIP-39 passphrase is never in it.
    // ponytail: the payload is built once for every recipient; per-recipient generations if a holder ever needs its own.
    pub fn backup_seal(&self, sender: &UaKey, recipients: &[Recipient]) -> Result<Vec<SealedContainer>> {
        let ua = sender.ua.filter(|_| is_sender_kind(sender.kind) && sender.secret.of_store(&self.store)).ok_or(Error::Argument)?;
        if recipients.is_empty() {
            return Err(Error::Argument);
        }
        let created = now()?;
        let pt = self.store.with_all(|a, m| {
            m.add_ua(sender.kind, sender.account, sender.index, ua);
            let secrets = m
                .imports
                .iter()
                .map(|i| Ok((*i, Zeroizing::new(a.secret(KeyId::Import(i.n)).ok_or(Error::Argument)?.to_vec()))))
                .collect::<Result<Vec<_>>>()?;
            let entropy = Zeroizing::new(a.entropy()?.to_vec());
            m.backup_generation = m.backup_generation.checked_add(1).ok_or(Error::Argument)?;
            Ok(BackupPayload { generation: m.backup_generation, entropy, secrets, entries: m.entries.clone() }.to_json())
        })?;
        let signer = ContainerSigner::Key(sender);
        recipients.iter().map(|r| seal_container(r, PURPOSE_BACKUP, &signer, created, pt.as_bytes(), None)).collect()
    }

    /// The wallet a backup container carries (spec §6.3, C-03, C-11): `expect.purpose` must be `scaas/backup/v1`
    /// (`Argument`); [`KemKeyPair::open_container`]'s acceptance; the payload (`Argument` if malformed); its entropy (with
    /// `bip39_passphrase`, never carried) must derive `sender.ua` at the manifest entry naming it (`ContainerSender`: the backup
    /// is the sender's own wallet). Over `current`, a wallet holding `sender.ua` in its manifest: an older generation is
    /// `BackupRollback` unless `rollback` is [`AllowRollback`], an equal one installs nothing (`Ok(None)`). Otherwise the new
    /// wallet: the entropy, the imported keys, the manifest entries, `backup_generation` = the payload's. **No replay
    /// protection** beyond the generation: an archived backup still opens.
    #[allow(clippy::too_many_arguments)]
    pub fn restore_backup(
        recipient: &KemKeyPair, c: &SealedContainer, expect: &ContainerExpect, members: &Members, accepted: Option<&Accepted>,
        current: Option<&Wallet>, rollback: Option<AllowRollback>, bip39_passphrase: &str,
    ) -> Result<Option<Wallet>> {
        if expect.purpose != PURPOSE_BACKUP {
            return Err(Error::Argument);
        }
        let p = BackupPayload::from_json(&recipient.open_container(c, expect, members, accepted)?)?;
        if !derives_sender(&p, &c.sender_ua, bip39_passphrase) {
            return Err(Error::ContainerSender);
        }
        if let Some(m) = current.map(Wallet::manifest).filter(|m| m.entries.iter().any(|e| e.ua == c.sender_ua)) {
            if p.generation < m.backup_generation && rollback.is_none() {
                return Err(Error::BackupRollback);
            }
            if p.generation == m.backup_generation {
                return Ok(None);
            }
        }
        install(p, bip39_passphrase).map(Some)
    }
}

/// The wallet of a payload: the entropy, the imported keys, the manifest entries and the generation.
fn install(p: BackupPayload, bip39_passphrase: &str) -> Result<Wallet> {
    let w = Wallet::from_entropy(&p.entropy, bip39_passphrase)?;
    for (e, secret) in &p.secrets {
        w.import_at(*e, secret)?;
    }
    w.store.note(|m| {
        m.entries = p.entries.clone();
        m.backup_generation = p.generation;
    });
    Ok(w)
}

/// The wallet of a link payload (the same `BackupPayload`; [`Wallet::from_link`]).
pub(super) fn install_link(pt: &[u8], bip39_passphrase: &str) -> Result<Wallet> {
    install(BackupPayload::from_json(pt)?, bip39_passphrase)
}

/// Test-only (feature `vectors`): a backup payload read and written back.
#[cfg(feature = "vectors")]
pub fn vectors_backup_payload(pt: &[u8]) -> Result<Zeroizing<String>> {
    Ok(BackupPayload::from_json(pt)?.to_json())
}
