// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! Vaults (spec §6.1, §6.5, §6.7, §6.9, §7): reading a vault's state from the contract's views alone (CTR-PQV-10), verifying
//! its signature chain before anything is trusted (VC15), unlocking it into epoch keys (handles), and building every record
//! a user signs. Reading never depends on what opened: a vault's state, its removals and the user's wraps are all read
//! before any key is tried, and an item page is read whole, so nothing a node sees follows from a decryption (ARCH-POS-13).
//! UNAUDITED.
use crate::content::{self, Merge};
use crate::keys::{self, ItemAt};
use crate::records::*;
use crate::{Error, PqVault, Result};
use scaas_sdk::app_core::{AppCall, AppKey, AppKeyUsage, AppPath, AppSigned, SecretBytes};
use scaas_sdk::op::KeyRef;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

// ------------------------------------------------------------------ the contract's entries (IPqVault.sol)

const MEMBER: &str = "(bytes32 ua,uint64 keyId,bytes32 via)";
const WRAP: &str = "(bytes32 member,uint64 keyId,bytes mlkemCt,bytes32 x25519Eph,bytes sealedKey)";
const UASIG: &str = "(bytes keyData,bytes signature,(uint16 index,(uint16 index,bytes sig)[] members,bytes sig)[] members)";
const ITEM: &str = "(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,bytes ciphertext)";
const LEAVE: &str = "(bytes32 vaultId,bytes32 epochId,bytes32 member,uint64 nonce)";
const REMOVE: &str = "(bytes32 vaultId,bytes32 epochId,uint64 nextEpoch,bytes32[] members,bytes32 admin,uint64 nonce)";
const EDIT: &str =
    "(bytes32 itemId,bytes32 epochId,bytes32 author,uint64 nonce,uint32 version,bytes ciphertext)";

fn create_t() -> String {
    format!(
        "(bytes32 creator,uint64 nonce,uint8 mode,bytes32 homeChain,address homeVaultContract,bytes32[] admins,\
         {MEMBER}[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo,uint8 groupMode)"
    )
}
fn epoch_t() -> String {
    format!(
        "(bytes32 vaultId,bytes32 author,uint64 nonce,uint64 epoch,bytes32 parentEpochId,bytes32[] admins,\
         {MEMBER}[] members,bytes32[] wrapHashes,uint16 passKdf,bytes32 passSalt,bytes sealedInfo)"
    )
}
fn batch_t() -> String {
    format!("(bytes32 vaultId,bytes32 epochId,bytes32 author,uint64 nonce,{ITEM}[] items)")
}

/// The contract's range caps (`VAULTS_RANGE_MAX`, `EPOCHS_RANGE_MAX`, `LATEST_RANGE_MAX`).
const RANGE: u64 = 128;
const LATEST: u64 = 16;
/// The removals read per epoch at most (each a `REMOVE_MAX` list): past it the state is not trusted.
const REMOVALS_MAX: u64 = 64;
/// The epochs of a vault read at most (ponytail: one cap; a longer history needs paging by the caller).
const EPOCHS_MAX: u64 = 1024;
/// The SDK's typed-data parser takes 64 KiB: a batch's typed JSON stays under it.
const TYPED_MAX: usize = 64 * 1024;
/// The recovery scan's gap limit (spec §6.1): 20 empty per-vault indexes end it.
pub const GAP: u32 = 20;

// ------------------------------------------------------------------ public types

/// A PqVault instance on an SDK profile: the profile's key, its chain id (the domain of mode 1) and the instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    pub chain: String,
    pub chain_id: u64,
    pub contract: Addr,
}

/// A vault's mode (spec §5.15): `Portable` (mode 0, the default, VC23) or `ChainBound` (mode 1, this instance its home).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Portable,
    ChainBound,
}

impl Mode {
    fn byte(self) -> u8 {
        match self {
            Mode::Portable => 0,
            Mode::ChainBound => 1,
        }
    }
}

/// The vault passphrase as typed (never stored): `Off`, `On` (a user-chosen one, at least 16 characters at creation and at a
/// change), or `Given` (a passphrase the client generated, or one typed to unlock: no length rule).
#[derive(Clone)]
pub enum Passphrase {
    Off,
    On(Arc<SecretBytes>),
    Given(Arc<SecretBytes>),
}

impl Passphrase {
    fn secret(&self) -> Option<&Arc<SecretBytes>> {
        match self {
            Passphrase::Off => None,
            Passphrase::On(s) | Passphrase::Given(s) => Some(s),
        }
    }
    /// VC19: a user-chosen passphrase of at least 16 characters (Unicode scalars of its UTF-8).
    fn check_new(&self) -> Result<()> {
        if let Passphrase::On(s) = self {
            let n = s.with(|b| std::str::from_utf8(b).map(|t| t.chars().count()));
            if n.map_err(|_| Error::PassphraseInvalid)? < 16 {
                return Err(Error::PassphraseTooShort);
            }
        }
        Ok(())
    }
}

/// Whether a rekey writes `prev` (spec §6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Prev,
    None,
}

/// What `sealedInfo` holds besides `prev` (spec §6.4): the name, whether the vault is shared (fixed at creation), an icon and
/// settings.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultInfo {
    pub name: String,
    pub shared: bool,
    pub icon: Option<String>,
    pub settings: Option<Value>,
}

/// One epoch as read and checked (epoch 0 is the vault's create record).
#[derive(Debug, Clone, PartialEq)]
pub struct EpochState {
    pub id: B32,
    pub number: u64,
    pub parent: B32,
    pub author: B32,
    pub admins: Vec<B32>,
    pub members: Vec<MemberKey>,
    pub wrap_hashes: Vec<B32>,
    pub pass_kdf: u16,
    pub pass_salt: B32,
    pub sealed_info: Vec<u8>,
    pub nonce: u64,
    pub sig: UaSig,
    /// the members `removeVaultMembers` records of this epoch name, with their records (verified with the rest)
    pub removals: Vec<Signed<VaultRemove>>,
    /// the user's own wraps in this epoch by member index, one per `(ua, keyId)` entry of the user (owner (M) 2026-11-23: a
    /// member may hold several KEM keys; one by default), empty when the user is no member
    pub own_wraps: Vec<(usize, Wrap)>,
}

impl EpochState {
    pub fn removed(&self) -> BTreeSet<B32> {
        self.removals
            .iter()
            .flat_map(|r| r.record.members.iter().copied())
            .collect()
    }
    fn member_at(&self, ua: B32) -> Option<usize> {
        self.members.iter().position(|m| m.ua == ua)
    }
}

/// A vault's state read from one instance: locked until [`PqVault::unlock`]; `verified` once [`PqVault::verify`] passed.
#[derive(Debug, Clone, PartialEq)]
pub struct VaultState {
    pub at: Instance,
    /// the instance's `chain_uid` (`factoryInfo`)
    pub chain_uid: B32,
    pub vault_id: B32,
    pub create: VaultCreate,
    pub epochs: Vec<EpochState>,
    /// the UA this state was read for (its wraps)
    pub me: B32,
    pub verified: bool,
    /// a vault the user did not create and has not accepted (VC18)
    pub pending: bool,
}

impl VaultState {
    pub fn mode(&self) -> Mode {
        if self.create.mode.0 == 1 {
            Mode::ChainBound
        } else {
            Mode::Portable
        }
    }
    pub fn newest(&self) -> Option<&EpochState> {
        self.epochs.last()
    }
    fn domain(&self) -> Domain {
        domain_of(self.mode(), &self.at, self.create.home_vault_contract)
    }
}

fn domain_of(mode: Mode, at: &Instance, home: Addr) -> Domain {
    match mode {
        Mode::Portable => Domain::Portable,
        Mode::ChainBound => Domain::ChainBound {
            chain_id: at.chain_id,
            instance: home,
        },
    }
}

fn path_of(mode: Mode, at: &Instance) -> AppPath {
    match mode {
        Mode::Portable => AppPath::Portable,
        Mode::ChainBound => AppPath::ChainBound {
            chain: at.chain.clone(),
            purpose: None,
        },
    }
}

/// A vault unlocked on this device: its verified state, the epoch keys it could open (handles, dropped at [`Self::lock`]) and
/// their `sealedInfo` contents.
pub struct Unlocked {
    pub state: VaultState,
    pub account: KeyRef,
    seed: String,
    keys: BTreeMap<B32, Arc<AppKey>>,
    /// `P_k` per `(passKdf, passSalt)` this unlock computed
    pass_keys: Vec<((u16, B32), Arc<AppKey>)>,
    pub infos: BTreeMap<B32, Value>,
    /// the newest epoch, when its keys did not open while an older one did: "epoch N by <author> cannot be opened"
    pub unopenable: Option<(u64, B32)>,
    /// an epoch whose `prev` key did not open the epoch it names: "epoch N by <author> carries a wrong history key"
    pub wrong_history: Option<(u64, B32)>,
    /// the items and their version counts seen by the last [`PqVault::open_latest`] (the exposure figures)
    seen_items: std::sync::Mutex<BTreeMap<B32, (u32, B32)>>,
}

impl Unlocked {
    /// The epochs whose keys this device holds.
    pub fn readable(&self) -> Vec<B32> {
        self.keys.keys().copied().collect()
    }
    /// The handle of epoch `epoch`'s `K_v` (no byte: a key of PqVault's scope, wiped at [`PqVault::lock`]).
    pub fn epoch_key(&self, epoch: B32) -> Option<Arc<AppKey>> {
        self.keys.get(&epoch).cloned()
    }
    pub fn info(&self) -> Option<&Value> {
        self.newest_open().and_then(|e| self.infos.get(&e.id))
    }
    fn newest_open(&self) -> Option<&EpochState> {
        self.state
            .epochs
            .iter()
            .rev()
            .find(|e| self.keys.contains_key(&e.id))
    }
    /// The epoch a write goes under: the newest, if it opened.
    fn write_epoch(&self) -> Result<&EpochState> {
        let n = self.state.newest().ok_or(Error::ChainUnverified)?;
        if let Some((epoch, author)) = self.unopenable {
            return Err(Error::EpochUnopenable { epoch, author });
        }
        self.keys
            .contains_key(&n.id)
            .then_some(n)
            .ok_or(Error::Unreadable)
    }
    fn at(&self, epoch: B32, item: B32, version: u32, author: B32) -> ItemAt {
        ItemAt {
            vault: self.state.vault_id,
            epoch,
            item,
            version,
            author,
            home_chain: self.state.create.home_chain,
            home: self.state.create.home_vault_contract,
        }
    }
}

/// An item version read and opened (or not): `value` is the item, else `Unreadable`, shown on the device only.
#[derive(Debug)]
pub struct ItemVersion {
    pub item_id: B32,
    pub version: u32,
    pub version_count: u32,
    pub epoch_id: B32,
    pub author: B32,
    pub value: Result<Value>,
}

/// What a weaker rekey that links `prev` would expose (spec §6.5): the items and versions reachable through it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Exposure {
    pub weaker: bool,
    pub items: u64,
    pub versions: u64,
}

/// An item whose latest version a removed member could read (V5): its secrets are to be changed at their services.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AffectedItem {
    pub item_id: B32,
    pub version: u32,
}

/// The chain's limits a batch is sized by (spec §7 "Batching"): the most gas one transaction may take (the block's share or
/// the EIP-7825 cap, whichever is lower), and the per-chain measured costs: a batch's fixed part (the author's verifier, the
/// header), each item, each ciphertext byte. Never a constant of this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainLimits {
    pub max_gas: u64,
    pub base_gas: u64,
    pub item_gas: u64,
    pub byte_gas: u64,
}

/// The highest version per item and epoch number per vault seen this session (spec §7 "Recovery": a lower one later is a
/// rollback).
#[derive(Default)]
pub struct Seen {
    items: BTreeMap<B32, u32>,
    epochs: BTreeMap<B32, u64>,
}

/// A migration's plan (VC12): what moves, and what the user must be told before anything is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPlan {
    pub items: Vec<(B32, B32)>,
    pub skipped_tombstones: u64,
    /// latest versions that do not open on this device: they cannot be copied (shown, not moved)
    pub unreadable: Vec<(B32, B32)>,
    pub warning: &'static str,
}

pub const MIGRATION_WARNING: &str =
    "The old ciphertexts stay on chain for ever, readable with the old seed (and the old \
     passphrase). Every secret listed must be changed at its service.";

fn nonce_of(b: &[u8]) -> u64 {
    // ponytail: 53 bits, so every JSON reader (clientkeys included) holds it exactly; a collision is a refused write
    let mut w = [0u8; 8];
    for (d, s) in w.iter_mut().zip(b) {
        *d = *s;
    }
    u64::from_be_bytes(w) & ((1 << 53) - 1)
}

fn sig_of_signed(s: AppSigned) -> UaSig {
    UaSig {
        key_data: s.key_data,
        signature: s.signature,
        members: s.members,
    }
}

fn get<T: serde::de::DeserializeOwned>(v: &Value, k: &str) -> Result<T> {
    serde_json::from_value(v.get(k).cloned().ok_or(Error::ChainUnverified)?)
        .map_err(|_| Error::ChainUnverified)
}

fn u16_of(n: Num) -> Result<u16> {
    u16::try_from(n.0).map_err(|_| Error::ChainUnverified)
}

// ------------------------------------------------------------------ reading and verifying (spec §5.9, §6.9)

impl PqVault {
    async fn read(&self, at: &Instance, sig: &str, args: Value) -> Result<Value> {
        Ok(self.net.read(&at.chain, at.contract, sig, args).await?)
    }

    /// The instance's `chain_uid` (`factoryInfo`), the home a record of mode 0 names when it is created here.
    pub async fn chain_uid(&self, at: &Instance) -> Result<B32> {
        let v = self
            .read(
                at,
                "function factoryInfo() view returns ((address factory,bytes32 chainUid,uint16 contractClass,\
                 uint16 kind,uint64 version,bool initialized) info)",
                json!({}),
            )
            .await?;
        get(v.get("info").ok_or(Error::ChainUnverified)?, "chainUid")
    }

    /// `ua`'s member entry at its newest KEM key (`kemKeyOf` of the instance's registry, `chainEnv`): a read that chooses the
    /// key a wrap goes to, so one that feeds a decryption. A UA without a KEM key: `NotMember`.
    pub async fn member_key(&self, at: &Instance, ua: B32) -> Result<MemberKey> {
        let env = self
            .read(
                at,
                "function chainEnv() view returns ((bytes32 chainUid,address registry,address govRouter,\
                 address smartKeyAccountImpl,bool hedera,address[] deps,bytes32[] params) env)",
                json!({}),
            )
            .await?;
        let registry: Addr = get(env.get("env").ok_or(Error::ChainUnverified)?, "registry")?;
        let k = self
            .net
            .read(
                &at.chain,
                registry,
                "function kemKeyOf(bytes32 ua) view returns (uint64 version,(uint8 scheme,bytes mlkemEk,\
                 bytes32 x25519) kem,bytes sig)",
                json!({"ua": ua}),
            )
            .await?;
        let scheme: Num = get(k.get("kem").ok_or(Error::ChainUnverified)?, "scheme")?;
        if scheme.0 != 1 {
            return Err(Error::NotMember);
        }
        Ok(MemberKey {
            ua,
            key_id: get(&k, "version")?,
            via: B32::default(),
        })
    }

    /// A generated vault passphrase (owner 2026-11-22): 6 BIP-39 English words drawn in `scaas-ua` (about 66 bits), as the
    /// secret buffer the SDK gives; shown once for the user to keep, never stored here.
    pub fn generate_passphrase(&self, seed: &str) -> Result<Passphrase> {
        Ok(Passphrase::Given(self.core.generate_passphrase(seed)?))
    }

    /// The share box for `recipients` (spec §6.7, controller call 2026-11-21): among the user's unlocked vaults, the shared
    /// one the user created whose newest epoch's members are exactly the user and `recipients`, the user its one admin;
    /// `None` when the first share makes one.
    pub fn share_box(vaults: &[&Unlocked], recipients: &[B32]) -> Option<B32> {
        vaults.iter().find_map(|v| {
            let e = v.state.newest()?;
            let mut want: Vec<B32> = recipients.iter().copied().chain([v.state.me]).collect();
            want.sort();
            want.dedup();
            let mut have: Vec<B32> = e.members.iter().map(|m| m.ua).collect();
            have.dedup(); // a member's several keys are one member (owner (M))
            let shared = v.info()?.get("shared").and_then(Value::as_bool) == Some(true);
            (shared
                && v.state.create.creator == v.state.me
                && have == want
                && e.admins == [v.state.me])
            .then_some(v.state.vault_id)
        })
    }

    /// The vaults that list `ua` (`vaultsOf`, every page).
    pub async fn vaults_of(&self, at: &Instance, ua: B32) -> Result<Vec<B32>> {
        let mut out = Vec::new();
        loop {
            let v = self
                .read(
                    at,
                    "function vaultsOf(bytes32 ua,uint256 offset,uint256 limit) view returns (bytes32[] ids)",
                    json!({"ua": ua, "offset": out.len().to_string(), "limit": RANGE.to_string()}),
                )
                .await?;
            let page: Vec<B32> = get(&v, "ids")?;
            let n = page.len() as u64;
            out.extend(page);
            if n < RANGE || out.len() as u64 >= EPOCHS_MAX {
                return Ok(out);
            }
        }
    }

    /// A vault's whole state at `at` for the user `me`: its record, every epoch (`epochsOf`, `epochOf`), every removal record
    /// (`removalAt`) and the user's wrap of each epoch it is a member of (`wrapAt`). Every read is fixed by the state, none by
    /// a decryption.
    pub async fn fetch(&self, at: &Instance, vault_id: B32, me: B32) -> Result<VaultState> {
        let chain_uid = self.chain_uid(at).await?;
        let sig_t = format!(
            "function vaultOf(bytes32 vaultId) view returns ({} v, {UASIG} sig)",
            create_t()
        );
        let v = self.read(at, &sig_t, json!({"vaultId": vault_id})).await?;
        let create: VaultCreate = get(&v, "v")?;
        let sig =
            sig_of(v.get("sig").ok_or(Error::ChainUnverified)?).ok_or(Error::ChainUnverified)?;
        let mut ids: Vec<B32> = Vec::new();
        loop {
            let p = self
                .read(
                    at,
                    "function epochsOf(bytes32 vaultId,uint256 offset,uint256 limit) view returns (bytes32[] ids)",
                    json!({"vaultId": vault_id, "offset": ids.len().to_string(), "limit": RANGE.to_string()}),
                )
                .await?;
            let page: Vec<B32> = get(&p, "ids")?;
            let n = page.len() as u64;
            ids.extend(page);
            if n < RANGE {
                break;
            }
            if ids.len() as u64 >= EPOCHS_MAX {
                return Err(Error::ChainUnverified);
            }
        }
        let mut epochs = vec![EpochState {
            id: vault_id,
            number: 0,
            parent: B32::default(),
            author: create.creator,
            admins: create.admins.clone(),
            members: create.members.clone(),
            wrap_hashes: create.wrap_hashes.clone(),
            pass_kdf: u16_of(create.pass_kdf)?,
            pass_salt: create.pass_salt,
            sealed_info: create.sealed_info.0.clone(),
            nonce: create.nonce.0,
            sig,
            removals: vec![],
            own_wraps: vec![],
        }];
        let ep_t = format!(
            "function epochOf(bytes32 epochId) view returns ({} e, {UASIG} sig)",
            epoch_t()
        );
        for id in ids.iter().skip(1) {
            let r = self.read(at, &ep_t, json!({"epochId": id})).await?;
            let e: VaultEpoch = get(&r, "e")?;
            let sig = sig_of(r.get("sig").ok_or(Error::ChainUnverified)?)
                .ok_or(Error::ChainUnverified)?;
            if e.vault_id != vault_id {
                return Err(Error::ChainUnverified);
            }
            epochs.push(EpochState {
                id: *id,
                number: e.epoch.0,
                parent: e.parent_epoch_id,
                author: e.author,
                admins: e.admins,
                members: e.members,
                wrap_hashes: e.wrap_hashes,
                pass_kdf: u16_of(e.pass_kdf)?,
                pass_salt: e.pass_salt,
                sealed_info: e.sealed_info.0,
                nonce: e.nonce.0,
                sig,
                removals: vec![],
                own_wraps: vec![],
            });
        }
        let rm_t = format!(
            "function removalAt(bytes32 epochId,uint256 index) view returns ({REMOVE} r, {UASIG} sig)"
        );
        for e in epochs.iter_mut() {
            let c = self
                .read(
                    at,
                    "function removalCount(bytes32 epochId) view returns (uint256 n)",
                    json!({"epochId": e.id}),
                )
                .await?;
            let n: Num = get(&c, "n")?;
            if n.0 > REMOVALS_MAX {
                return Err(Error::ChainUnverified);
            }
            for i in 0..n.0 {
                let r = self
                    .read(at, &rm_t, json!({"epochId": e.id, "index": i.to_string()}))
                    .await?;
                e.removals.push(Signed {
                    record: get(&r, "r")?,
                    sig: sig_of(r.get("sig").ok_or(Error::ChainUnverified)?)
                        .ok_or(Error::ChainUnverified)?,
                });
            }
            let mine: Vec<usize> = e
                .members
                .iter()
                .enumerate()
                .filter_map(|(i, m)| (m.ua == me).then_some(i))
                .collect();
            for i in mine {
                let w = self
                    .read(
                        at,
                        &format!(
                            "function wrapAt(bytes32 epochId,uint256 i) view returns ({WRAP} w)"
                        ),
                        json!({"epochId": e.id, "i": i.to_string()}),
                    )
                    .await?;
                e.own_wraps.push((i, get(&w, "w")?));
            }
        }
        Ok(VaultState {
            at: at.clone(),
            chain_uid,
            vault_id,
            create,
            epochs,
            me,
            verified: false,
            pending: false,
        })
    }

    async fn verify_sig<R: Record>(
        &self,
        s: &VaultState,
        ua: B32,
        r: &R,
        sig: &UaSig,
    ) -> Result<bool> {
        let typed = typed_json(r, s.domain()).map_err(|_| Error::ChainUnverified)?;
        Ok(self
            .net
            .verify(
                &s.at.chain,
                ua,
                path_of(s.mode(), &s.at),
                typed,
                sig.clone(),
            )
            .await
            .unwrap_or(false))
    }

    /// Spec §6.9 on a fetched state: the creator's signature in the domain its mode names and `vaultId` recomputed; in mode 1
    /// the instance read is the home and chain the record names; each epoch from 1 to the newest signed by an admin of its
    /// verified parent not removed from it by a verified removal, its parent and number chained, its id recomputed; each
    /// removal signed by an admin of its epoch; the user's wraps against the signed `wrapHashes`. Every signature through the
    /// SDK's `verify_pqvault_record` (the registry's records read as a read that feeds a decryption). `ChainUnverified` else.
    pub async fn verify(&self, mut s: VaultState) -> Result<VaultState> {
        let c = &s.create;
        let mode = u8::try_from(c.mode.0).map_err(|_| Error::ChainUnverified)?;
        if mode > 1
            || c.group_mode.0 != 0
            || vault_id(
                c.creator,
                c.nonce.0,
                mode,
                c.home_chain,
                c.home_vault_contract,
            ) != s.vault_id
            || !c.admins.contains(&c.creator)
            || (mode == 1
                && (c.home_vault_contract != s.at.contract || c.home_chain != s.chain_uid))
            || ((c.pass_kdf.0 == 0) != (c.pass_salt == B32::default()))
        {
            return Err(Error::ChainUnverified);
        }
        if !self
            .verify_sig(
                &s,
                c.creator,
                c,
                &s.epochs.first().ok_or(Error::ChainUnverified)?.sig,
            )
            .await?
        {
            return Err(Error::ChainUnverified);
        }
        for i in 0..s.epochs.len() {
            let e = s.epochs.get(i).ok_or(Error::ChainUnverified)?;
            if i > 0 {
                let p = s.epochs.get(i - 1).ok_or(Error::ChainUnverified)?;
                let rec = VaultEpoch {
                    vault_id: s.vault_id,
                    author: e.author,
                    nonce: Num(e.nonce),
                    epoch: Num(e.number),
                    parent_epoch_id: e.parent,
                    admins: e.admins.clone(),
                    members: e.members.clone(),
                    wrap_hashes: e.wrap_hashes.clone(),
                    pass_kdf: Num(u64::from(e.pass_kdf)),
                    pass_salt: e.pass_salt,
                    sealed_info: Bytes(e.sealed_info.clone()),
                };
                if e.parent != p.id
                    || e.number != p.number + 1
                    || epoch_id(s.vault_id, e.author, e.nonce) != e.id
                    || !p.admins.contains(&e.author)
                    || p.removed().contains(&e.author)
                    || (e.pass_kdf == 0) != (e.pass_salt == B32::default())
                    || !self.verify_sig(&s, e.author, &rec, &e.sig).await?
                {
                    return Err(Error::ChainUnverified);
                }
            }
            for r in &e.removals {
                let x = &r.record;
                if x.vault_id != s.vault_id
                    || x.epoch_id != e.id
                    || !e.admins.contains(&x.admin)
                    || !self.verify_sig(&s, x.admin, x, &r.sig).await?
                {
                    return Err(Error::ChainUnverified);
                }
            }
            for (j, w) in &e.own_wraps {
                let m = e.members.get(*j).ok_or(Error::ChainUnverified)?;
                if e.wrap_hashes.get(*j) != Some(&wrap_hash(w))
                    || w.member != s.me
                    || m.ua != s.me
                    || w.key_id != m.key_id
                {
                    return Err(Error::ChainUnverified);
                }
            }
        }
        s.verified = true;
        Ok(s)
    }

    /// A vault read at `at` and verified: [`Self::fetch`] then [`Self::verify`].
    pub async fn load(&self, at: &Instance, vault_id: B32, me: B32) -> Result<VaultState> {
        let s = self.fetch(at, vault_id, me).await?;
        let s = self.verify(s).await?;
        self.check_epochs(&s)?;
        Ok(s)
    }

    fn check_epochs(&self, s: &VaultState) -> Result<()> {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let n = s.newest().map_or(0, |e| e.number);
        let prev = seen.epochs.entry(s.vault_id).or_insert(n);
        if n < *prev {
            return Err(Error::Rollback);
        }
        *prev = n;
        Ok(())
    }

    // ------------------------------------------------------------------ unlocking (spec §6.5)

    /// Unlocks a verified, accepted vault for `account` (P1 first): the newest epoch's own wrap, `P_k` of the passphrase,
    /// `K_v`, then its `sealedInfo`'s tag. If that tag fails, the parent epoch is tried with the same passphrase: if it opens,
    /// the newest epoch is reported unopenable (with its author) and older items stay readable; if neither opens,
    /// `PassphraseWrong`. Then the history: each `prev` key against the `sealedInfo` of the epoch it names, and the user's own
    /// wraps of the other epochs. No network call: the state was read whole before.
    pub async fn unlock(
        &self,
        account: &KeyRef,
        s: VaultState,
        pass: &Passphrase,
    ) -> Result<Unlocked> {
        let seed = self.p1(account).await?;
        if !s.verified {
            return Err(Error::ChainUnverified);
        }
        if s.pending {
            return Err(Error::Pending);
        }
        if s.me != self.ua(account)? {
            return Err(Error::NotMember);
        }
        let mut u = Unlocked {
            state: s,
            account: account.clone(),
            seed,
            keys: BTreeMap::new(),
            pass_keys: vec![],
            infos: BTreeMap::new(),
            unopenable: None,
            wrong_history: None,
            seen_items: Default::default(),
        };
        let n = u.state.epochs.len();
        let newest = n.checked_sub(1).ok_or(Error::ChainUnverified)?;
        let mut opened = None;
        let mut any_unwrapped = false;
        for (k, i) in [newest, newest.wrapping_sub(1)].into_iter().enumerate() {
            if i >= n {
                break;
            }
            match self.open_epoch(&mut u, i, pass).await? {
                Some(true) => {
                    opened = Some(i);
                    if k == 1 {
                        let e = u.state.epochs.get(newest).ok_or(Error::ChainUnverified)?;
                        u.unopenable = Some((e.number, e.author));
                    }
                    break;
                }
                Some(false) => any_unwrapped = true,
                None => {}
            }
        }
        let Some(top) = opened else {
            let e = u.state.epochs.get(newest).ok_or(Error::ChainUnverified)?;
            return Err(if any_unwrapped && e.pass_kdf != 0 {
                Error::PassphraseWrong
            } else {
                Error::EpochUnopenable {
                    epoch: e.number,
                    author: e.author,
                }
            });
        };
        // the history: prev links down from the opened epoch, then the user's own wraps of what is left
        let mut i = top;
        loop {
            let (id, number, author) = {
                let e = u.state.epochs.get(i).ok_or(Error::ChainUnverified)?;
                (e.id, e.number, e.author)
            };
            let info = u.infos.get(&id).cloned().unwrap_or(Value::Null);
            let Some(prev) = info.get("prev") else { break };
            let (Some(pid), Some(wire)) = (
                prev.get("epochId")
                    .and_then(Value::as_str)
                    .and_then(|h| unhex(h, 32)),
                prev.get("keyWrap")
                    .and_then(Value::as_str)
                    .and_then(|h| unhex(h, 60)),
            ) else {
                u.wrong_history = Some((number, author));
                break;
            };
            let pid = B32(pid.try_into().map_err(|_| Error::ChainUnverified)?);
            let Some(j) = u
                .state
                .epochs
                .iter()
                .position(|e| e.id == pid)
                .filter(|j| *j < i)
            else {
                u.wrong_history = Some((number, author));
                break;
            };
            let kv = u.keys.get(&id).cloned().ok_or(Error::ChainUnverified)?;
            let pe = u.state.epochs.get(j).ok_or(Error::ChainUnverified)?;
            let back = keys::open_prev(&self.core, &kv, u.state.vault_id, id, pid, &wire);
            let pinfo = back.as_ref().and_then(|k| {
                keys::open_info(&self.core, k, u.state.vault_id, pid, &pe.sealed_info)
            });
            match (back, pinfo) {
                (Some(k), Some(pi)) => {
                    u.keys.insert(pid, k);
                    u.infos.insert(pid, pi);
                    i = j;
                }
                _ => {
                    u.wrong_history = Some((number, author));
                    break;
                }
            }
        }
        for i in (0..n).rev() {
            let has = u
                .state
                .epochs
                .get(i)
                .is_some_and(|e| u.keys.contains_key(&e.id));
            if !has {
                // the user's own wrap of an older epoch, with the passphrase given (the same one, or none)
                let _ = self.open_epoch(&mut u, i, pass).await;
            }
        }
        // O1 (c): `shared` is fixed at creation; an opened epoch that changes it is not trusted
        let shared: BTreeSet<Option<bool>> = u
            .infos
            .values()
            .map(|v| v.get("shared").and_then(Value::as_bool))
            .collect();
        if shared.len() > 1 || shared.contains(&None) {
            return Err(Error::ChainUnverified);
        }
        Ok(u)
    }

    /// Epoch `i`'s keys into `u`: `None` when the user holds no wrap or it does not open, `Some(false)` when the wrap opened and
    /// the `sealedInfo` tag failed (a wrong passphrase), `Some(true)` when it opened.
    async fn open_epoch(
        &self,
        u: &mut Unlocked,
        i: usize,
        pass: &Passphrase,
    ) -> Result<Option<bool>> {
        let e = u.state.epochs.get(i).ok_or(Error::ChainUnverified)?.clone();
        // the first of the user's wraps this account opens (a device key it does not hold is skipped; owner (M))
        let Some(ke) = e.own_wraps.iter().find_map(|(_, w)| {
            keys::unwrap(&self.core, &u.account, w, u.state.vault_id, e.id).ok()
        }) else {
            return Ok(None);
        };
        let pk = match u
            .pass_keys
            .iter()
            .find(|(k, _)| *k == (e.pass_kdf, e.pass_salt))
        {
            Some((_, h)) => Some(h.clone()),
            None => {
                let h = keys::pass_key(&self.core, &u.seed, e.pass_kdf, pass.secret(), e.pass_salt)
                    .await?;
                if let Some(h) = &h {
                    u.pass_keys.push(((e.pass_kdf, e.pass_salt), h.clone()));
                }
                h
            }
        };
        let kv = keys::vault_key(&self.core, ke, pk, u.state.vault_id, e.id, e.pass_kdf)?;
        match keys::open_info(&self.core, &kv, u.state.vault_id, e.id, &e.sealed_info) {
            Some(info) => {
                u.keys.insert(e.id, kv);
                u.infos.insert(e.id, info);
                Ok(Some(true))
            }
            None => Ok(Some(false)),
        }
    }

    /// Locks `u` now (auto-lock, VC13): every key handle it holds wiped in `scaas-ua`.
    pub fn lock(&self, u: Unlocked) {
        for k in u
            .keys
            .into_values()
            .chain(u.pass_keys.into_iter().map(|(_, h)| h))
        {
            let _ = self.core.destroy(k);
        }
    }

    /// Spec §6.5: `pass` for a shared vault refused (`PassphraseReused`) when it equals the passphrase of `personal`, an
    /// unlocked personal vault of the user (one Argon2id under that vault's salt, the two keys compared in `scaas-ua`).
    pub async fn check_not_reused(&self, pass: &Passphrase, personal: &Unlocked) -> Result<()> {
        let Some(secret) = pass.secret() else {
            return Ok(());
        };
        for ((kdf, salt), h) in &personal.pass_keys {
            let k = keys::pass_key(&self.core, &personal.seed, *kdf, Some(secret), *salt).await?;
            if let Some(k) = k {
                if self.core.same_key(k, h.clone())? {
                    return Err(Error::PassphraseReused);
                }
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------ vaults and epochs (spec §5.5, §6.7)

    async fn sign<R: Record>(
        &self,
        account: &KeyRef,
        mode: Mode,
        at: &Instance,
        home: Addr,
        r: R,
    ) -> Result<Signed<R>> {
        let typed = typed_json(&r, domain_of(mode, at, home)).map_err(|_| Error::Shape)?;
        let s = self
            .net
            .sign(&at.chain, account, path_of(mode, at), typed)
            .await?;
        Ok(Signed {
            record: r,
            sig: sig_of_signed(s),
        })
    }

    fn info_json(info: &VaultInfo) -> Value {
        let mut o = serde_json::Map::new();
        o.insert("name".into(), json!(info.name));
        o.insert("shared".into(), json!(info.shared));
        if let Some(i) = &info.icon {
            o.insert("icon".into(), json!(i));
        }
        if let Some(s) = &info.settings {
            o.insert("settings".into(), s.clone());
        }
        Value::Object(o)
    }

    async fn pass_parts(
        &self,
        seed: &str,
        pass: &Passphrase,
    ) -> Result<(u16, B32, Option<Arc<AppKey>>)> {
        match pass.secret() {
            None => Ok((0, B32::default(), None)),
            Some(_) => {
                let mut salt = [0u8; 32];
                salt.copy_from_slice(&self.core.random_bytes(seed, 32)?);
                let salt = B32(salt);
                let pk = keys::pass_key(&self.core, seed, 1, pass.secret(), salt).await?;
                Ok((1, salt, pk))
            }
        }
    }

    /// Epoch 0 of a new vault by `account` at `at` (its home): P1 first; `members` (the creator included, each at the KEM key
    /// version it names), the creator its one admin, a fresh random `K_e` wrapped to each member, the passphrase (VC19) into
    /// `P_k` with a fresh salt, `sealedInfo`; signed by the SDK's PqVault call in the domain `mode` names.
    pub async fn create_vault(
        &self,
        account: &KeyRef,
        info: &VaultInfo,
        members: &[MemberKey],
        at: &Instance,
        mode: Mode,
        pass: &Passphrase,
    ) -> Result<(Signed<VaultCreate>, Vec<Wrap>)> {
        let seed = self.p1(account).await?;
        pass.check_new()?;
        let me = self.ua(account)?;
        let mut members = members.to_vec();
        members.sort_by_key(|m| m.ua);
        members.dedup_by_key(|m| m.ua);
        if !members.iter().any(|m| m.ua == me) {
            return Err(Error::NotMember);
        }
        let home_chain = self.chain_uid(at).await?;
        let nonce = nonce_of(&self.core.random_bytes(&seed, 8)?);
        let vid = vault_id(me, nonce, mode.byte(), home_chain, at.contract);
        let ke = self.core.random_key(&seed, AppKeyUsage::Derive)?;
        let mut wraps = Vec::with_capacity(members.len());
        for m in &members {
            wraps.push(
                keys::wrap_to(
                    &*self.net,
                    &at.chain,
                    ke.clone(),
                    vid,
                    vid,
                    m.ua,
                    m.key_id.0,
                )
                .await?,
            );
        }
        let (pass_kdf, pass_salt, pk) = self.pass_parts(&seed, pass).await?;
        let kv = keys::vault_key(&self.core, ke, pk, vid, vid, pass_kdf)?;
        let sealed = keys::seal_info(&self.core, &kv, vid, vid, &Self::info_json(info))?;
        let rec = VaultCreate {
            creator: me,
            nonce: Num(nonce),
            mode: Num(u64::from(mode.byte())),
            home_chain,
            home_vault_contract: at.contract,
            group_mode: Num(0),
            admins: vec![me],
            members,
            wrap_hashes: wraps.iter().map(wrap_hash).collect(),
            pass_kdf: Num(u64::from(pass_kdf)),
            pass_salt,
            sealed_info: Bytes(sealed),
        };
        Ok((self.sign(account, mode, at, at.contract, rec).await?, wraps))
    }

    /// A new epoch of `v` by its admin (spec §6.7, VC16): `members` and `admins` (sorted here), a fresh `K_e` wrapped to each
    /// member; `pass` `None` keeps the parent's passphrase (its `passKdf` and salt), `Some` changes it (a fresh salt) or turns
    /// it off; `link` writes `prev` (the parent's `K_v` sealed under this epoch's `kPrev`). The exposure: whether the new epoch
    /// is weaker (the passphrase off after on, a member added) and, if it links `prev`, the items and versions it exposes.
    pub async fn rekey(
        &self,
        v: &Unlocked,
        members: &[MemberKey],
        admins: &[B32],
        pass: Option<&Passphrase>,
        link: Link,
    ) -> Result<(Signed<VaultEpoch>, Vec<Wrap>, Exposure)> {
        let (signer, me) = (v.account.clone(), v.state.me);
        self.rekey_by(v, &signer, me, members, admins, pass, link)
            .await
    }

    /// [`Self::rekey`] authored by another admin of the newest epoch, `author`, signing by `signer` (an `msig` admin by its
    /// member slots, `KeyRef::Msig`); the keys are the unlocking user's (`v`), the author's admin right checked as the
    /// contract checks it.
    #[allow(clippy::too_many_arguments)]
    pub async fn rekey_by(
        &self,
        v: &Unlocked,
        signer: &KeyRef,
        author: B32,
        members: &[MemberKey],
        admins: &[B32],
        pass: Option<&Passphrase>,
        link: Link,
    ) -> Result<(Signed<VaultEpoch>, Vec<Wrap>, Exposure)> {
        self.p1(&v.account).await?;
        let me = author;
        let parent = v.write_epoch()?;
        if !parent.admins.contains(&me) || parent.removed().contains(&me) {
            return Err(Error::NotAdmin);
        }
        if let Some(p) = pass {
            p.check_new()?;
        }
        let mut members = members.to_vec();
        members.sort_by_key(|m| m.ua);
        members.dedup_by_key(|m| m.ua);
        let mut admins = admins.to_vec();
        admins.sort();
        admins.dedup();
        let vid = v.state.vault_id;
        let nonce = nonce_of(&self.core.random_bytes(&v.seed, 8)?);
        let eid = epoch_id(vid, me, nonce);
        let ke = self.core.random_key(&v.seed, AppKeyUsage::Derive)?;
        let at = &v.state.at;
        let mut wraps = Vec::with_capacity(members.len());
        for m in &members {
            wraps.push(
                keys::wrap_to(
                    &*self.net,
                    &at.chain,
                    ke.clone(),
                    vid,
                    eid,
                    m.ua,
                    m.key_id.0,
                )
                .await?,
            );
        }
        let (pass_kdf, pass_salt, pk) = match pass {
            None => {
                let pk = v
                    .pass_keys
                    .iter()
                    .find(|(k, _)| *k == (parent.pass_kdf, parent.pass_salt))
                    .map(|(_, h)| h.clone());
                if parent.pass_kdf != 0 && pk.is_none() {
                    return Err(Error::PassphraseRequired);
                }
                (parent.pass_kdf, parent.pass_salt, pk)
            }
            Some(p) => self.pass_parts(&v.seed, p).await?,
        };
        let kv = keys::vault_key(&self.core, ke, pk, vid, eid, pass_kdf)?;
        let mut info = v.infos.get(&parent.id).cloned().ok_or(Error::Unreadable)?;
        let o = info.as_object_mut().ok_or(Error::Unreadable)?;
        o.remove("prev");
        if link == Link::Prev {
            let kv_prev = v.keys.get(&parent.id).cloned().ok_or(Error::Unreadable)?;
            let wire = keys::seal_prev(&self.core, &kv, vid, eid, parent.id, kv_prev)?;
            o.insert(
                "prev".into(),
                json!({"epochId": parent.id, "keyWrap": hex(&wire)}),
            );
        }
        let sealed = keys::seal_info(&self.core, &kv, vid, eid, &info)?;
        let added = members.iter().any(|m| parent.member_at(m.ua).is_none());
        let weaker = (parent.pass_kdf != 0 && pass_kdf == 0) || added;
        let mut exposure = Exposure {
            weaker,
            ..Exposure::default()
        };
        if weaker && link == Link::Prev {
            let seen = v
                .seen_items
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            exposure.items = seen.len() as u64;
            exposure.versions = seen.values().map(|(n, _)| u64::from(*n)).sum();
        }
        let rec = VaultEpoch {
            vault_id: vid,
            author: me,
            nonce: Num(nonce),
            epoch: Num(parent.number + 1),
            parent_epoch_id: parent.id,
            admins,
            members,
            wrap_hashes: wraps.iter().map(wrap_hash).collect(),
            pass_kdf: Num(u64::from(pass_kdf)),
            pass_salt,
            sealed_info: Bytes(sealed),
        };
        let home = v.state.create.home_vault_contract;
        Ok((
            self.sign(signer, v.state.mode(), at, home, rec).await?,
            wraps,
            exposure,
        ))
    }

    /// The user leaves the newest epoch of `v` (O3 (b)).
    pub async fn leave(&self, v: &Unlocked) -> Result<Signed<VaultLeave>> {
        self.p1(&v.account).await?;
        let e = v.state.newest().ok_or(Error::ChainUnverified)?;
        let nonce = nonce_of(&self.core.random_bytes(&v.seed, 8)?);
        let rec = VaultLeave {
            vault_id: v.state.vault_id,
            epoch_id: e.id,
            member: v.state.me,
            nonce: Num(nonce),
        };
        let home = v.state.create.home_vault_contract;
        self.sign(&v.account, v.state.mode(), &v.state.at, home, rec)
            .await
    }

    /// An admin removes `members` from the newest epoch (V5), and the items whose latest version they could read (through
    /// the epochs they were in and every epoch those link back to with `prev`), from the last [`Self::open_latest`].
    pub async fn remove(
        &self,
        v: &Unlocked,
        members: &[B32],
    ) -> Result<(Signed<VaultRemove>, Vec<AffectedItem>)> {
        self.p1(&v.account).await?;
        let e = v.state.newest().ok_or(Error::ChainUnverified)?;
        if !e.admins.contains(&v.state.me) || members.is_empty() || members.len() > 16 {
            return Err(Error::NotAdmin);
        }
        let mut list = members.to_vec();
        list.sort();
        list.dedup();
        let nonce = nonce_of(&self.core.random_bytes(&v.seed, 8)?);
        let rec = VaultRemove {
            vault_id: v.state.vault_id,
            epoch_id: e.id,
            next_epoch: Num(e.number + 1),
            members: list.clone(),
            admin: v.state.me,
            nonce: Num(nonce),
        };
        let readable = readable_by(v, &list);
        let affected = v
            .seen_items
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, (_, epoch))| readable.contains(epoch))
            .map(|(id, (n, _))| AffectedItem {
                item_id: *id,
                version: *n,
            })
            .collect();
        let home = v.state.create.home_vault_contract;
        Ok((
            self.sign(&v.account, v.state.mode(), &v.state.at, home, rec)
                .await?,
            affected,
        ))
    }

    // ------------------------------------------------------------------ items (spec §6.4, §6.8)

    fn ciphertext(
        &self,
        v: &Unlocked,
        epoch: B32,
        item: B32,
        version: u32,
        value: &Value,
    ) -> Result<Bytes> {
        let kv = v.keys.get(&epoch).ok_or(Error::Unreadable)?;
        let pt = content::item_plaintext(value)?;
        let x = v.at(epoch, item, version, v.state.me);
        Ok(Bytes(keys::encrypt_item(&self.core, &v.seed, kv, &x, pt)?))
    }

    fn item_record(&self, v: &Unlocked, value: &Value) -> Result<ItemRecord> {
        let e = v.write_epoch()?;
        if e.member_at(v.state.me).is_none() || e.removed().contains(&v.state.me) {
            return Err(Error::NotMember);
        }
        let nonce = nonce_of(&self.core.random_bytes(&v.seed, 8)?);
        let iid = item_id(v.state.vault_id, v.state.me, nonce);
        Ok(ItemRecord {
            vault_id: v.state.vault_id,
            epoch_id: e.id,
            author: v.state.me,
            nonce: Num(nonce),
            ciphertext: self.ciphertext(v, e.id, iid, 1, value)?,
        })
    }

    /// A new item (version 1) under the newest epoch; its id `itemId(vaultId, author, nonce)` known before it is signed.
    pub async fn create_item(&self, v: &Unlocked, value: &Value) -> Result<Signed<ItemRecord>> {
        self.p1(&v.account).await?;
        let rec = self.item_record(v, value)?;
        let home = v.state.create.home_vault_contract;
        self.sign(&v.account, v.state.mode(), &v.state.at, home, rec)
            .await
    }

    /// The next version of `base`'s item (its `version_count + 1`) holding `value`, under the newest epoch.
    pub async fn edit_item(
        &self,
        v: &Unlocked,
        base: &ItemVersion,
        value: &Value,
    ) -> Result<Signed<EditRecord>> {
        self.p1(&v.account).await?;
        let e = v.write_epoch()?;
        if e.member_at(v.state.me).is_none() || e.removed().contains(&v.state.me) {
            return Err(Error::NotMember);
        }
        let version = base.version_count.checked_add(1).ok_or(Error::Shape)?;
        let nonce = nonce_of(&self.core.random_bytes(&v.seed, 8)?);
        let rec = EditRecord {
            item_id: base.item_id,
            epoch_id: e.id,
            author: v.state.me,
            nonce: Num(nonce),
            version: Num(u64::from(version)),
            ciphertext: self.ciphertext(v, e.id, base.item_id, version, value)?,
        };
        let home = v.state.create.home_vault_contract;
        self.sign(&v.account, v.state.mode(), &v.state.at, home, rec)
            .await
    }

    /// An edit whose base is no longer the latest (another device wrote it first, `PqVaultVersion`): the three-way merge of
    /// `ours` against the latest (read again, whole), and the edit of the merged item on top of it; `Conflict` carries the merge
    /// when fields clashed, for the UI to ask (the edit is built either way).
    pub async fn resolve(
        &self,
        v: &Unlocked,
        base: &Value,
        ours: &Value,
        item_id: B32,
    ) -> Result<(Signed<EditRecord>, Merge)> {
        let history = self.history(v, item_id).await?;
        let latest = history.last().ok_or(Error::Unreadable)?;
        let theirs = latest.value.as_ref().map_err(|_| Error::Unreadable)?;
        let m = content::merge(base, ours, theirs);
        let merged = match &m {
            Merge::Clean(x) | Merge::Conflict(x, _) => x.clone(),
        };
        Ok((self.edit_item(v, latest, &merged).await?, m))
    }

    /// `items` as batches sized by `limits` (each under the gas bound and the SDK's 64-KiB typed-data cap), each one record.
    pub async fn create_items(
        &self,
        v: &Unlocked,
        items: &[Value],
        limits: &ChainLimits,
    ) -> Result<Vec<Signed<BatchRecord>>> {
        self.p1(&v.account).await?;
        let e = v.write_epoch()?.id;
        let mut groups: Vec<Vec<ItemRecord>> = vec![];
        let mut cur: Vec<ItemRecord> = vec![];
        for value in items {
            let it = self.item_record(v, value)?;
            let mut next = cur.clone();
            next.push(it.clone());
            if !cur.is_empty() && !fits(&self.batch(v, e, next.clone(), false)?, v, limits) {
                groups.push(std::mem::take(&mut cur));
                cur.push(it);
            } else {
                cur = next;
            }
            if !fits(&self.batch(v, e, cur.clone(), false)?, v, limits) {
                return Err(Error::Shape);
            }
        }
        if !cur.is_empty() {
            groups.push(cur);
        }
        let home = v.state.create.home_vault_contract;
        let mut out = vec![];
        for g in groups {
            let b = self.batch(v, e, g, true)?;
            out.push(
                self.sign(&v.account, v.state.mode(), &v.state.at, home, b)
                    .await?,
            );
        }
        Ok(out)
    }

    /// A batch of `items`; `nonce` `None` the largest (for sizing), else drawn fresh.
    fn batch(
        &self,
        v: &Unlocked,
        epoch: B32,
        items: Vec<ItemRecord>,
        fresh: bool,
    ) -> Result<BatchRecord> {
        let nonce = if fresh {
            nonce_of(&self.core.random_bytes(&v.seed, 8)?)
        } else {
            (1 << 53) - 1
        };
        Ok(BatchRecord {
            vault_id: v.state.vault_id,
            epoch_id: epoch,
            author: v.state.me,
            nonce: Num(nonce),
            items,
        })
    }

    fn open_version(
        &self,
        v: &Unlocked,
        item: B32,
        version: u32,
        epoch: B32,
        author: B32,
        ct: &[u8],
    ) -> Result<Value> {
        let kv = v.keys.get(&epoch).ok_or(Error::Unreadable)?;
        keys::decrypt_item(&self.core, kv, &v.at(epoch, item, version, author), ct)
    }

    fn seen_item(&self, id: B32, n: u32) -> Result<()> {
        let mut seen = self
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let prev = seen.items.entry(id).or_insert(n);
        if n < *prev {
            return Err(Error::Rollback);
        }
        *prev = n;
        Ok(())
    }

    /// The latest version of every item of `v` (`itemCount`, then `latestRange` pages of 16), each opened locally: a version
    /// that does not open is `Unreadable` on the device and changes nothing that is read or sent next. A lower version count
    /// than seen before is `Rollback`.
    pub async fn open_latest(&self, v: &Unlocked) -> Result<Vec<ItemVersion>> {
        let views = self.latest_views(&v.state.at, v.state.vault_id).await?;
        let mut out = vec![];
        for x in views {
            let item: B32 = get(&x, "itemId")?;
            let count = u32::try_from(get::<Num>(&x, "versionCount")?.0)
                .map_err(|_| Error::ChainUnverified)?;
            let epoch: B32 = get(&x, "epochId")?;
            let author: B32 = get(&x, "author")?;
            let ct: Bytes = get(&x, "ciphertext")?;
            self.seen_item(item, count)?;
            v.seen_items
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(item, (count, epoch));
            out.push(ItemVersion {
                item_id: item,
                version: count,
                version_count: count,
                epoch_id: epoch,
                author,
                value: self.open_version(v, item, count, epoch, author, &ct.0),
            });
        }
        Ok(out)
    }

    /// The latest version of every item of the vault at `at` as the views answer them (`itemCount`, `latestRange` pages).
    async fn latest_views(&self, at: &Instance, vault: B32) -> Result<Vec<Value>> {
        let c = self
            .read(
                at,
                "function itemCount(bytes32 vaultId) view returns (uint256 n)",
                json!({"vaultId": vault}),
            )
            .await?;
        let n: Num = get(&c, "n")?;
        let mut views = vec![];
        let mut off = 0u64;
        while off < n.0 {
            let p = self
                .read(
                    at,
                    "function latestRange(bytes32 vaultId,uint256 offset,uint256 limit) view returns ((bytes32 itemId,\
                     uint32 versionCount,bytes32 epochId,bytes32 author,bytes ciphertext)[] items)",
                    json!({"vaultId": vault, "offset": off.to_string(), "limit": LATEST.to_string()}),
                )
                .await?;
            let page = p
                .get("items")
                .and_then(Value::as_array)
                .cloned()
                .ok_or(Error::ChainUnverified)?;
            if page.is_empty() {
                break;
            }
            off += page.len() as u64;
            views.extend(page);
        }
        Ok(views)
    }

    async fn version_at(&self, at: &Instance, item: B32, n: u32) -> Result<Value> {
        let r = self
            .read(
                at,
                "function versionAt(bytes32 itemId,uint32 version) view returns ((bytes32 epochId,bytes32 author,\
                 uint64 nonce,uint32 version,bytes ciphertext,bytes32 sigHash) v)",
                json!({"itemId": item, "version": n.to_string()}),
            )
            .await?;
        r.get("v").cloned().ok_or(Error::ChainUnverified)
    }

    /// VC17: whether the vault read at `replica` holds the home state's records byte for byte (the create record, each epoch
    /// it has, its signatures), and each item's latest version there is the home's version of the same number (an item the
    /// home lacks, or another ciphertext or author, is a divergence). Items are read at home (recovery); this flags a replica.
    pub async fn replica_agrees(&self, home: &VaultState, replica: &Instance) -> Result<bool> {
        let r = self.fetch(replica, home.vault_id, home.me).await?;
        if r.create != home.create || r.epochs.len() > home.epochs.len() {
            return Ok(false);
        }
        let same = r.epochs.iter().zip(&home.epochs).all(|(a, b)| {
            a.id == b.id
                && a.sig == b.sig
                && a.sealed_info == b.sealed_info
                && a.members == b.members
                && a.admins == b.admins
        });
        if !same {
            return Ok(false);
        }
        for x in self.latest_views(replica, home.vault_id).await? {
            let item: B32 = get(&x, "itemId")?;
            let n = u32::try_from(get::<Num>(&x, "versionCount")?.0)
                .map_err(|_| Error::ChainUnverified)?;
            let Ok(h) = self.version_at(&home.at, item, n).await else {
                return Ok(false);
            };
            if get::<Bytes>(&h, "ciphertext")? != get::<Bytes>(&x, "ciphertext")?
                || get::<B32>(&h, "author")? != get::<B32>(&x, "author")?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Every version of `item_id` (`itemOf`, then `versionAt` 1..count, all read before any is opened), oldest first.
    pub async fn history(&self, v: &Unlocked, item_id: B32) -> Result<Vec<ItemVersion>> {
        let at = &v.state.at;
        let i = self
            .read(
                at,
                "function itemOf(bytes32 itemId) view returns ((bytes32 vaultId,uint32 versionCount,bytes32 batchId) item)",
                json!({"itemId": item_id}),
            )
            .await?;
        let item = i.get("item").ok_or(Error::ChainUnverified)?;
        if get::<B32>(item, "vaultId")? != v.state.vault_id {
            return Err(Error::ChainUnverified);
        }
        let count = u32::try_from(get::<Num>(item, "versionCount")?.0)
            .map_err(|_| Error::ChainUnverified)?;
        self.seen_item(item_id, count)?;
        let mut raw = vec![];
        for n in 1..=count {
            raw.push(self.version_at(at, item_id, n).await?);
        }
        let mut out = vec![];
        for (k, x) in raw.iter().enumerate() {
            let n = u32::try_from(k + 1).map_err(|_| Error::ChainUnverified)?;
            if u32::try_from(get::<Num>(x, "version")?.0).ok() != Some(n) {
                return Err(Error::ChainUnverified);
            }
            let epoch: B32 = get(x, "epochId")?;
            let author: B32 = get(x, "author")?;
            let ct: Bytes = get(x, "ciphertext")?;
            out.push(ItemVersion {
                item_id,
                version: n,
                version_count: count,
                epoch_id: epoch,
                author,
                value: self.open_version(v, item_id, n, epoch, author, &ct.0),
            });
        }
        Ok(out)
    }

    /// The newest version of a history that opens (a member's unreadable latest version shown as such, the one before it
    /// read): spec §10 "Malicious member".
    pub fn newest_readable(history: Vec<ItemVersion>) -> Option<ItemVersion> {
        history.into_iter().rev().find(|x| x.value.is_ok())
    }

    // ------------------------------------------------------------------ the calls (what the user reviews and the SDK sends)

    /// The prepared call of a signed record (`AppCore::prepare_app_call`: the entry, the contract, each argument and the
    /// payer's quote, shown to the user before `Wallet::submit_native_send` sends it). Anyone may submit a signed record.
    pub async fn prepare_create(
        &self,
        at: &Instance,
        s: &Signed<VaultCreate>,
        wraps: &[Wrap],
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!(
            "function createVault({} v,{WRAP}[] wraps,{UASIG} sig) returns (bytes32 vaultId)",
            create_t()
        );
        let args = json!({"v": s.record, "wraps": wraps, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    pub async fn prepare_rekey(
        &self,
        at: &Instance,
        s: &Signed<VaultEpoch>,
        wraps: &[Wrap],
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!(
            "function rekeyVault({} e,{WRAP}[] wraps,{UASIG} sig) returns (bytes32 epochId)",
            epoch_t()
        );
        let args = json!({"e": s.record, "wraps": wraps, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    pub async fn prepare_leave(
        &self,
        at: &Instance,
        s: &Signed<VaultLeave>,
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!("function leaveVault({LEAVE} l,{UASIG} sig)");
        let args = json!({"l": s.record, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    pub async fn prepare_remove(
        &self,
        at: &Instance,
        s: &Signed<VaultRemove>,
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!("function removeVaultMembers({REMOVE} r,{UASIG} sig)");
        let args = json!({"r": s.record, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    pub async fn prepare_item(
        &self,
        at: &Instance,
        s: &Signed<ItemRecord>,
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!("function createItem({ITEM} it,{UASIG} sig) returns (bytes32 itemId)");
        let args = json!({"it": s.record, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    pub async fn prepare_edit(
        &self,
        at: &Instance,
        s: &Signed<EditRecord>,
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!("function editItem({EDIT} d,{UASIG} sig)");
        let args = json!({"d": s.record, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    pub async fn prepare_batch(
        &self,
        at: &Instance,
        s: &Signed<BatchRecord>,
        payer: KeyRef,
    ) -> Result<AppCall> {
        let sig = format!(
            "function createItems({} b,{UASIG} sig) returns (bytes32 batchId)",
            batch_t()
        );
        let args = json!({"b": s.record, "sig": sig_json(&s.sig)});
        Ok(self
            .net
            .call(&at.chain, at.contract, &sig, args, payer)
            .await?)
    }

    // ------------------------------------------------------------------ recovery, acceptance, sharing, migration (spec §6.1, §7)

    /// The user's vaults from state alone (spec §6.1, §5.9; CTR-PQV-10), locked: P1 first; the index vault (the per-vault UA
    /// at index 0) unlocked without a passphrase and its `vaultRef` items read; the vaults listing the main UA `account`; the
    /// personal vaults the refs name; with no index vault, the scan of per-vault indexes 1.. up to [`GAP`] empty ones. A vault
    /// the user did not create and whose ref is not `accepted` (at its accepted epoch) is pending. Each vault verified.
    pub async fn recover(&self, account: &KeyRef, at: &Instance) -> Result<Vec<VaultState>> {
        let seed = self.p1(account).await?;
        let main = self.ua(account)?;
        let mut out: Vec<VaultState> = vec![];
        let mut refs: BTreeMap<B32, Value> = BTreeMap::new();
        let mut personal: Vec<u32> = vec![];
        let idx_key = Self::vault_key(&seed, 0);
        let idx_ua = self.ua(&idx_key)?;
        let idx = self.own_vaults(at, idx_ua).await?;
        if let Some(s) = idx.into_iter().next() {
            let u = self.unlock(&idx_key, s.clone(), &Passphrase::Off).await?;
            for x in self.open_latest(&u).await? {
                let Ok(r) = x.value else { continue };
                if r.get("type").and_then(Value::as_str) == Some("vaultRef") {
                    let id: Option<B32> = r
                        .get("vaultId")
                        .cloned()
                        .and_then(|v| serde_json::from_value(v).ok());
                    if let (Some(id), Some(i)) = (id, r.get("index").and_then(Value::as_u64)) {
                        personal.extend(u32::try_from(i).ok());
                        refs.insert(id, r.clone());
                    } else if let Some(id) = id {
                        refs.insert(id, r.clone());
                    }
                }
            }
            out.push(s);
        } else {
            let mut gap = 0;
            let mut i = 1u32;
            while gap < GAP {
                let k = Self::vault_key(&seed, i);
                let found = self.own_vaults(at, self.ua(&k)?).await?;
                if found.is_empty() {
                    gap += 1;
                } else {
                    gap = 0;
                    out.extend(found);
                }
                i += 1;
            }
        }
        for i in personal {
            let k = Self::vault_key(&seed, i);
            out.extend(self.own_vaults(at, self.ua(&k)?).await?);
        }
        for id in self.vaults_of(at, main).await? {
            if out.iter().any(|s| s.vault_id == id) {
                continue;
            }
            let mut s = self.load(at, id, main).await?;
            let accepted = refs.get(&id).is_some_and(|r| {
                r.get("state").and_then(Value::as_str) == Some("accepted")
                    && r.get("mode").and_then(Value::as_u64) == Some(s.create.mode.0)
            });
            if refs
                .get(&id)
                .and_then(|r| r.get("mode"))
                .and_then(Value::as_u64)
                .is_some_and(|m| m != s.create.mode.0)
            {
                return Err(Error::ChainUnverified);
            }
            s.pending = s.create.creator != main && !accepted;
            out.push(s);
        }
        Ok(out)
    }

    /// The vaults a per-vault UA created itself (a per-vault UA accepts only the vault it created, VC18).
    async fn own_vaults(&self, at: &Instance, ua: B32) -> Result<Vec<VaultState>> {
        let mut out = vec![];
        for id in self.vaults_of(at, ua).await? {
            let s = self.load(at, id, ua).await?;
            if s.create.creator == ua {
                out.push(s);
            }
        }
        Ok(out)
    }

    /// The `vaultRef` item (spec §6.8) that accepts or declines `vault` in the user's unlocked index vault `index`.
    pub async fn accept(
        &self,
        index: &Unlocked,
        vault: &VaultState,
        accept: bool,
        personal: Option<u32>,
    ) -> Result<Signed<ItemRecord>> {
        self.p1(&index.account).await?;
        let e = vault.newest().ok_or(Error::ChainUnverified)?;
        let mut r = json!({
            "type": "vaultRef",
            "title": "vault",
            "vaultId": vault.vault_id,
            "homeChain": vault.create.home_chain,
            "homeVaultContract": vault.create.home_vault_contract,
            "mode": vault.create.mode.0,
            "acceptedEpoch": e.id,
            "state": if accept { "accepted" } else { "declined" },
        });
        if let (Some(i), Some(o)) = (personal, r.as_object_mut()) {
            o.insert("index".into(), json!(i));
        }
        self.create_item(index, &r).await
    }

    /// The migration plan of `from` (VC12): the latest version of every live item (tombstones skipped), and the warning the
    /// user reads before anything is signed.
    pub fn migration_plan(from: &[(B32, Vec<ItemVersion>)]) -> MigrationPlan {
        let mut items = vec![];
        let mut unreadable = vec![];
        let mut skipped = 0;
        for (vault, latest) in from {
            for x in latest {
                match &x.value {
                    Ok(v) if v.get("type").and_then(Value::as_str) == Some("deleted") => {
                        skipped += 1
                    }
                    Ok(_) => items.push((*vault, x.item_id)),
                    Err(_) => unreadable.push((*vault, x.item_id)),
                }
            }
        }
        MigrationPlan {
            items,
            skipped_tombstones: skipped,
            unreadable,
            warning: MIGRATION_WARNING,
        }
    }
}

/// The epochs `members` could read in `v`: those they were members of, and every epoch those link back to with `prev`.
fn readable_by(v: &Unlocked, members: &[B32]) -> BTreeSet<B32> {
    let mut out = BTreeSet::new();
    for e in v.state.epochs.iter().rev() {
        if members.iter().any(|m| e.member_at(*m).is_some()) || out.contains(&e.id) {
            out.insert(e.id);
            let mut id = e.id;
            while let Some(p) = v
                .infos
                .get(&id)
                .and_then(|i| i.get("prev"))
                .and_then(|p| p.get("epochId"))
                .and_then(|h| serde_json::from_value::<B32>(h.clone()).ok())
            {
                if !out.insert(p) {
                    break;
                }
                id = p;
            }
        }
    }
    out
}

/// Whether `b` fits one transaction under `limits` and its typed JSON the SDK's cap.
fn fits(b: &BatchRecord, v: &Unlocked, limits: &ChainLimits) -> bool {
    let bytes: u64 = b.items.iter().map(|i| i.ciphertext.0.len() as u64).sum();
    let gas = limits
        .base_gas
        .saturating_add(limits.item_gas.saturating_mul(b.items.len() as u64))
        .saturating_add(limits.byte_gas.saturating_mul(bytes));
    let typed = typed_json(b, v.state.domain())
        .map(|t| t.len())
        .unwrap_or(usize::MAX);
    gas <= limits.max_gas && typed <= TYPED_MAX
}
