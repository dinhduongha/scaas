// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! cxx bridge over `scaas_ua::wallet` and the facades (ua-rs-sign T13a, spec §9.1, §9.2, §10): the Rust API, not the C ABI.
//! Handles are opaque Rust types behind `rust::Box` (`include/scaas_ua.hpp` wraps each in a move-only class); a key handle holds
//! its wallet's store, a generation and a slot, never secret bytes. Secret **inputs** (mnemonic, passphrases, PRF secret, an
//! imported key, the seed-backup answers) cross as `&mut [u8]` and are zeroized here before the call returns, whatever its
//! outcome; secret **outputs** (an opened plaintext, a shared secret, a revealed phrase, the PQZ leaf) cross as `rust::Vec`
//! that the C++ `Secret` wipes. Every call runs in `guard` (no unwind into C++). An error is its code (`"UAKeyRevoked"`);
//! no error carries an input. UNAUDITED.
use crate::{guard, UaErr, R};
use scaas_ua as ua;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use ua::facade::{pqz as fpqz, zether as fzether};
use ua::wallet as uw;
use zeroize::Zeroize;

/// The surface generation of this bridge, in step with the C ABI's `SCAAS_UA_ABI_VERSION` (6, ua-rs-sign T12).
pub const ABI_VERSION: u32 = 6;
/// The PQZ facade's largest output (`SCAAS_UA_PQZ_OUT_MAX`): a proof is sized by this bound, never by a size query.
pub const PQZ_OUT_MAX: usize = 1_052_672;
const _: () = assert!(PQZ_OUT_MAX >= fpqz::OUT_MAX);
const _: () = assert!(!ua::build::VECTORS, "ua-cxx must not build scaas-ua with feature `vectors`");

impl From<uw::Error> for UaErr {
    fn from(e: uw::Error) -> Self {
        match e {
            uw::Error::Ua(e) => e.into(),
            e => UaErr(format!("UA{}", e.code())),
        }
    }
}
fn argument() -> UaErr {
    UaErr("UAArgument".into())
}

#[cxx::bridge(namespace = "scaas::ua::ffi")]
mod ffi {
    /// The arena's protection now (spec §8.2); all 0 while locked.
    struct MemoryProtection {
        chunks: usize,
        locked: usize,
        no_dump: usize,
    }
    /// A recipient of `wallet_backup_seal`: the KEM key `kem_pk` of record `version` of the UA of (`kind`, `key_data`), or with
    /// `ephemeral` an ephemeral key (kind, key data and version unread).
    struct Recipient {
        kind: u16,
        key_data: Vec<u8>,
        version: u64,
        kem_pk: Vec<u8>,
        ephemeral: bool,
    }
    /// `kem_encaps`: `ss` is a secret (the C++ side wipes it).
    struct Encapsulated {
        mlkem_ct: Vec<u8>,
        x25519_eph: Vec<u8>,
        ss: Vec<u8>,
    }
    /// A seal's named fields (version and scheme 1).
    struct Sealed {
        mlkem_ct: Vec<u8>,
        x25519_eph: Vec<u8>,
        ciphertext: Vec<u8>,
    }
    struct Generated {
        wallet: Box<Wallet>,
        backup: Box<SeedBackup>,
    }

    extern "Rust" {
        type Wallet;
        type Key;
        type KeyList;
        type KemKey;
        type LinkSession;
        type SeedBackup;
        type Restored;
        type ZetherKey;
        type PqzKey;

        fn abi_version() -> u32;
        fn features() -> u64;
        fn live_handles() -> i64;
        fn pqz_out_max() -> usize;

        fn wallet_generate() -> Result<Generated>;
        fn wallet_from_mnemonic(words: &mut [u8], bip39_passphrase: &mut [u8]) -> Result<Box<Wallet>>;
        // exactly one of `vault_passphrase` / `prf32` is meant (empty = absent; both: the PRF secret, the passphrase not tried)
        fn wallet_open_vault(vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8], bip39_passphrase: &mut [u8])
            -> Result<Box<Wallet>>;
        fn wallet_unlock(w: &Wallet, vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8], bip39_passphrase: &mut [u8])
            -> Result<()>;
        fn wallet_seal_vault(w: &Wallet, vault_passphrase: &mut [u8]) -> Result<String>;
        fn wallet_lock(w: &Wallet);
        fn wallet_memory_protection(w: &Wallet) -> MemoryProtection;
        fn wallet_ua_key(w: &Wallet, kind: u16, account: u32, index: u32) -> Result<Box<Key>>;
        // `network` the clientkeys name (`evm`, `hedera_ecdsa`, ...); `coin_type` u32::MAX = the network's own
        fn wallet_native_key(w: &Wallet, network: &str, index: u32, coin_type: u32) -> Result<Box<Key>>;
        fn wallet_import_native_key(w: &Wallet, network: &str, secret: &mut [u8]) -> Result<Box<Key>>;
        fn wallet_imported_key(w: &Wallet, network: &str, n: u32) -> Result<Box<Key>>;
        // T20c: the UA of an imported key, `kind` its scheme's derived kind (0x0108 / 0x0102) only
        fn wallet_imported_ua_key(w: &Wallet, network: &str, n: u32, kind: u16) -> Result<Box<Key>>;
        fn wallet_seal_label_vault(w: &Wallet, label: &str, vault_passphrase: &mut [u8]) -> Result<String>;
        fn wallet_open_label_vault(w: &Wallet, vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8]) -> Result<()>;
        fn wallet_manifest_json(w: &Wallet) -> String;
        fn wallet_discover_candidates(w: &Wallet, kind: u16, account: u32, gap: u32) -> Result<String>;
        fn wallet_backup_seal(w: &Wallet, sender: &Key, recipients: &[Recipient]) -> Result<Vec<String>>;
        // `members_json` / `accepted_json`: "" = none / no lookup
        fn wallet_restore_backup(kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str,
            bip39_passphrase: &mut [u8]) -> Result<Box<Restored>>;
        fn wallet_restore_backup_over(kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str,
            accepted_json: &str, current: &Wallet, bip39_passphrase: &mut [u8]) -> Result<Box<Restored>>;
        fn wallet_restore_backup_rollback(kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str,
            accepted_json: &str, current: &Wallet, bip39_passphrase: &mut [u8]) -> Result<Box<Restored>>;
        fn restored_installed(r: &Restored) -> bool;
        fn restored_take(r: &mut Restored) -> Result<Box<Wallet>>;
        fn wallet_link_seal(w: &Wallet, sender: &Key, session_kem_pk: &[u8], short_code: &str) -> Result<String>;
        fn wallet_from_link(s: &LinkSession, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str,
            bip39_passphrase: &mut [u8]) -> Result<Box<Wallet>>;
        fn wallet_zether_key(w: &Wallet, coin: u32, account: u32, key_use: u32) -> Result<Box<ZetherKey>>;
        fn wallet_pqz_key(w: &Wallet, account: u32, index: u32) -> Result<Box<PqzKey>>;
        fn wallet_export_pqz_leaf_raw(w: &Wallet, account: u32, index: u32) -> Result<Vec<u8>>;
        fn wallet_pqz_key_version(w: &Wallet, account: u32, index: u32, version: u64) -> Result<Box<PqzKey>>;
        fn wallet_export_pqz_leaf_raw_version(w: &Wallet, account: u32, index: u32, version: u64) -> Result<Vec<u8>>;

        fn seed_backup_reveal(b: &SeedBackup) -> Result<Vec<u8>>;
        fn seed_backup_challenge(b: &SeedBackup) -> Result<Vec<u32>>;
        fn seed_backup_verify(b: &SeedBackup, word1: &mut [u8], word2: &mut [u8], word3: &mut [u8]) -> Result<bool>;
        fn seed_backup_take(b: &SeedBackup) -> Result<Vec<u8>>;

        fn key_is_ua(k: &Key) -> bool;
        fn key_kind(k: &Key) -> u16;
        fn key_data(k: &Key) -> Vec<u8>;
        fn key_ua(k: &Key) -> Result<Vec<u8>>;
        fn key_network(k: &Key) -> String;
        fn key_address(k: &Key) -> Result<String>;
        fn sign_ua(k: &Key, purpose: &[u8], digest: &[u8]) -> Result<Vec<u8>>;
        fn sign_member(k: &Key, structure_ua: &[u8], structure_ua_msg: &[u8]) -> Result<Vec<u8>>;
        fn sign_typed(k: &Key, typed_data_json: &str, expect_json: &str) -> Result<Vec<u8>>;
        fn sign_typed_any(k: &Key, typed_data_json: &str) -> Result<Vec<u8>>;
        fn sign_transaction(k: &Key, tx_json: &str) -> Result<Vec<u8>>;
        fn sign_key_proof(k: &Key, challenge: &[u8]) -> Result<Vec<u8>>;
        fn sign_digest_raw(k: &Key, digest: &[u8]) -> Result<Vec<u8>>;
        fn key_list_new() -> Box<KeyList>;
        fn key_list_push(l: &mut KeyList, k: &Key);
        fn uasig(request_json: &str, keys: &KeyList) -> Result<String>;
        fn kem_key(k: &Key, version: u64) -> Result<Box<KemKey>>;
        // ua-rs-sign T13b: a key handle by id for a script layer (ua-qt's QML singleton), which never holds the handle itself;
        // the id names a shared handle (revoked with its wallet as any other), never a secret
        fn key_register(k: &Key) -> u64;
        fn key_release(id: u64) -> bool;

        fn kem_ephemeral() -> Result<Box<KemKey>>;
        fn kem_pk(kk: &KemKey) -> Vec<u8>;
        fn kem_decaps(kk: &KemKey, mlkem_ct: &[u8], x25519_eph: &[u8]) -> Result<Vec<u8>>;
        fn kem_encaps(kem_pk: &[u8]) -> Result<Encapsulated>;
        fn seal(kem_pk: &[u8], purpose: &str, aad: &[u8], pt: &[u8]) -> Result<Sealed>;
        fn open(kk: &KemKey, purpose: &str, aad: &[u8], mlkem_ct: &[u8], x25519_eph: &[u8], ct: &[u8]) -> Result<Vec<u8>>;
        fn open_container(kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str)
            -> Result<Vec<u8>>;
        fn link_session_new() -> Result<Box<LinkSession>>;
        fn link_session_kem_pk(s: &LinkSession) -> Result<Vec<u8>>;
        fn link_session_short_code(s: &LinkSession) -> Result<String>;

        fn vault_needs_rewrap(vault_json: &str) -> Result<bool>;
        fn vault_rewrap_pin(vault_json: &str, old_passphrase: &mut [u8], new_passphrase: &mut [u8]) -> Result<String>;
        fn vault_enable_prf(vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8], credential_id: &str, salt: &[u8])
            -> Result<String>;

        // `alg` 1 = AES-256-GCM, 2 = AES-256-GCM-SIV
        fn aead_seal(alg: u32, key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Vec<u8>>;
        fn aead_open(alg: u32, key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> Result<Vec<u8>>;
        fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>>;
        fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8>;
        fn webauthn_challenge(purpose: &[u8], digest: &[u8]) -> Result<Vec<u8>>;
        fn webauthn_assertion(key_data: &[u8], expected_challenge: &[u8], auth_data: &[u8], client_data_json: &[u8], r: &[u8],
            s: &[u8]) -> Result<Vec<u8>>;

        fn zether_y(k: &ZetherKey) -> Vec<u8>;
        fn zether_ua(k: &ZetherKey) -> Vec<u8>;
        fn zether_call(k: &ZetherKey, cmd: &str, request_json: &str) -> Result<String>;
        fn zether_seal_balance_cache(k: &ZetherKey, entries_json: &[u8]) -> Result<String>;
        fn zether_open_balance_cache(k: &ZetherKey, box_json: &str) -> Result<Vec<u8>>;

        fn pqz_pk(k: &PqzKey) -> Vec<u8>;
        fn pqz_call(k: &PqzKey, cmd: &str, request_json: &str) -> Result<String>;
        fn pqz_seal_balance_cache(k: &PqzKey, entries: &[u8]) -> Result<String>;
        fn pqz_open_balance_cache(k: &PqzKey, box_json: &str) -> Result<Vec<u8>>;
        fn pqz_set() -> String;
        fn pqz_check_set(deployed_json: &str) -> Result<()>;
        fn pqz_check(request_json: &str) -> Result<String>;
    }
}

// --- handles ---------------------------------------------------------------------------------------------------------------

static LIVE: AtomicI64 = AtomicI64::new(0);
/// Counts the handles alive (`live_handles`): a handle dropped twice shows as a count below its start.
pub struct Live;
impl Live {
    fn new() -> Live {
        LIVE.fetch_add(1, Ordering::SeqCst);
        Live
    }
}
impl Drop for Live {
    fn drop(&mut self) {
        LIVE.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct Wallet(uw::Wallet, Live);
enum KeyInner {
    Ua(uw::UaKey),
    Native(uw::NativeKey),
}
/// A UA or native key handle; shared (`Arc`) so a key list or the id registry can hold it beside its owner.
pub struct Key(Arc<KeyInner>, Live);
pub struct KeyList(Vec<Arc<KeyInner>>);
pub struct KemKey(uw::KemKeyPair, Live);
pub struct LinkSession(Mutex<Option<uw::LinkSession>>, Live);
pub struct SeedBackup(Mutex<uw::SeedBackup>, Live);
pub struct Restored(Option<uw::Wallet>);
pub struct ZetherKey(fzether::ZetherKey, Live);
pub struct PqzKey(fpqz::PqzKey, Live);

impl Key {
    /// Another handle of the same key (a key list, the id registry).
    pub fn share(&self) -> Key {
        Key(Arc::clone(&self.0), Live::new())
    }
    /// The UA key, or `None` for a native key.
    pub fn ua_key(&self) -> Option<&uw::UaKey> {
        match &*self.0 {
            KeyInner::Ua(u) => Some(u),
            KeyInner::Native(_) => None,
        }
    }
    /// The native key, or `None` for a UA key.
    pub fn native_key(&self) -> Option<&uw::NativeKey> {
        match &*self.0 {
            KeyInner::Native(n) => Some(n),
            KeyInner::Ua(_) => None,
        }
    }
    pub fn signer(&self) -> &dyn uw::Signer {
        signer(&self.0)
    }
}

/// The handles registered by id (`key_register`), for a script layer that gets ids, never handles (ua-qt's QML).
static REGISTRY: Mutex<BTreeMap<u64, Key>> = Mutex::new(BTreeMap::new());
static NEXT_ID: AtomicU64 = AtomicU64::new(1);
fn key_register(k: &Key) -> u64 {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    if let Ok(mut r) = REGISTRY.lock() {
        r.insert(id, k.share());
    }
    id
}
/// Frees the registry's handle of `id` once: `false` for an id it does not hold (released already, or never given).
fn key_release(id: u64) -> bool {
    REGISTRY.lock().map(|mut r| r.remove(&id).is_some()).unwrap_or(false)
}
/// A handle of the key registered as `id` (another share of it), or `None`.
pub fn registered(id: u64) -> Option<Key> {
    REGISTRY.lock().ok()?.get(&id).map(Key::share)
}

fn abi_version() -> u32 {
    ABI_VERSION
}
/// The bits of `scaas_ua_features()` (ua-c), read from scaas-ua's own `cfg`.
pub fn features() -> u64 {
    use ua::build as b;
    let on = |x: bool, bit: u32| if x { 1u64 << bit } else { 0 };
    on(b::WALLET, 0)
        | on(b::PQ, 1)
        | on(b::FALCON, 2)
        | on(b::ZETHER, 3)
        | on(b::PQZ, 4)
        | b::PQZ_SETS.iter().zip(5..).fold(0, |a, (x, bit)| a | on(*x, bit))
        | on(b::MLOCK, 10)
        | on(b::VECTORS, 11)
}
fn live_handles() -> i64 {
    LIVE.load(Ordering::SeqCst)
}
fn pqz_out_max() -> usize {
    PQZ_OUT_MAX
}

// --- helpers ---------------------------------------------------------------------------------------------------------------

fn text(b: &[u8]) -> R<&str> {
    std::str::from_utf8(b).map_err(|_| argument())
}
/// Zeroizes each caller-held secret: every call that takes one runs this before it returns, success or not.
fn wipe(secrets: &mut [&mut [u8]]) {
    secrets.iter_mut().for_each(|s| s.zeroize());
}
fn a<const N: usize>(b: &[u8]) -> R<[u8; N]> {
    b.try_into().map_err(|_| argument())
}
fn network(name: &str) -> R<uw::Network> {
    uw::Network::from_name(name).ok_or_else(argument)
}
fn unlock<'a>(vault_passphrase: &'a [u8], prf32: &'a [u8]) -> R<uw::Unlock<'a>> {
    if !prf32.is_empty() {
        return Ok(uw::Unlock::Prf(prf32.try_into().map_err(|_| argument())?));
    }
    if vault_passphrase.is_empty() {
        return Err(argument());
    }
    Ok(uw::Unlock::VaultPassphrase(text(vault_passphrase)?))
}
fn ua_key(k: &Key) -> R<&uw::UaKey> {
    match &*k.0 {
        KeyInner::Ua(u) => Ok(u),
        KeyInner::Native(_) => Err(argument()),
    }
}
fn native_key(k: &Key) -> R<&uw::NativeKey> {
    match &*k.0 {
        KeyInner::Native(n) => Ok(n),
        KeyInner::Ua(_) => Err(argument()),
    }
}
fn signer(k: &KeyInner) -> &dyn uw::Signer {
    match k {
        KeyInner::Ua(u) => u,
        KeyInner::Native(n) => n,
    }
}
fn container(json: &str) -> R<uw::SealedContainer> {
    Ok(uw::SealedContainer::from_json(json.as_bytes())?)
}
fn key(k: KeyInner) -> Box<Key> {
    Box::new(Key(Arc::new(k), Live::new()))
}

/// The opener's three JSON inputs, as ua-c's: `expect_json` required, `members_json` "" = none, `accepted_json` "" = no lookup.
struct Opening {
    expect: uw::ContainerExpectJson,
    members: uw::MembersJson,
    accepted: Option<uw::AcceptedJson>,
}
impl Opening {
    fn read(expect_json: &str, members_json: &str, accepted_json: &str) -> R<Opening> {
        let members = if members_json.is_empty() { uw::MembersJson::default() } else { uw::MembersJson::from_json(members_json.as_bytes())? };
        let accepted = if accepted_json.is_empty() { None } else { Some(uw::AcceptedJson::from_json(accepted_json.as_bytes())?) };
        Ok(Opening { expect: uw::ContainerExpectJson::from_json(expect_json.as_bytes())?, members, accepted })
    }
    fn with<T>(&self, f: impl FnOnce(&uw::ContainerExpect, &ua::ua8::Members, Option<&ua::ua8::Accepted>) -> T) -> T {
        let members = |id: [u8; 32]| self.members.lookup(id);
        let accepted = |id: [u8; 32], i: u16| self.accepted.as_ref().is_some_and(|a| a.accepted(id, i));
        f(&self.expect.get(), &members, self.accepted.as_ref().map(|_| &accepted as &ua::ua8::Accepted))
    }
}

// --- wallet ----------------------------------------------------------------------------------------------------------------

fn wallet_generate() -> R<ffi::Generated> {
    guard(|| {
        let (w, b) = uw::Wallet::generate()?;
        Ok(ffi::Generated { wallet: Box::new(Wallet(w, Live::new())), backup: Box::new(SeedBackup(Mutex::new(b), Live::new())) })
    })
}
fn wallet_from_mnemonic(words: &mut [u8], bip39_passphrase: &mut [u8]) -> R<Box<Wallet>> {
    let r = guard(|| Ok(Box::new(Wallet(uw::Wallet::from_mnemonic(text(words)?, text(bip39_passphrase)?)?, Live::new()))));
    wipe(&mut [words, bip39_passphrase]);
    r
}
fn wallet_open_vault(vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8], bip39_passphrase: &mut [u8]) -> R<Box<Wallet>> {
    let r = guard(|| {
        let v = uw::Vault::from_json(vault_json.as_bytes())?;
        Ok(Box::new(Wallet(uw::Wallet::open_vault(&v, unlock(vault_passphrase, prf32)?, text(bip39_passphrase)?)?, Live::new())))
    });
    wipe(&mut [vault_passphrase, prf32, bip39_passphrase]);
    r
}
fn wallet_unlock(w: &Wallet, vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8], bip39_passphrase: &mut [u8]) -> R<()> {
    let r = guard(|| {
        let v = uw::Vault::from_json(vault_json.as_bytes())?;
        Ok(w.0.unlock(&v, unlock(vault_passphrase, prf32)?, text(bip39_passphrase)?)?)
    });
    wipe(&mut [vault_passphrase, prf32, bip39_passphrase]);
    r
}
fn wallet_seal_vault(w: &Wallet, vault_passphrase: &mut [u8]) -> R<String> {
    let r = guard(|| Ok(w.0.seal_vault(text(vault_passphrase)?, None)?.to_json()));
    wipe(&mut [vault_passphrase]);
    r
}
fn wallet_lock(w: &Wallet) {
    let _ = guard(|| {
        w.0.lock();
        Ok(())
    });
}
fn wallet_memory_protection(w: &Wallet) -> ffi::MemoryProtection {
    let m = w.0.memory_protection();
    ffi::MemoryProtection { chunks: m.chunks, locked: m.locked, no_dump: m.no_dump }
}
fn wallet_ua_key(w: &Wallet, kind: u16, account: u32, index: u32) -> R<Box<Key>> {
    guard(|| Ok(key(KeyInner::Ua(w.0.ua_key(kind, account, index)?))))
}
fn wallet_native_key(w: &Wallet, net: &str, index: u32, coin_type: u32) -> R<Box<Key>> {
    let coin = (coin_type != u32::MAX).then_some(coin_type);
    guard(|| Ok(key(KeyInner::Native(w.0.native_key(network(net)?, index, coin)?))))
}
fn wallet_import_native_key(w: &Wallet, net: &str, secret: &mut [u8]) -> R<Box<Key>> {
    let r = guard(|| Ok(key(KeyInner::Native(w.0.import_native_key(network(net)?, secret)?))));
    wipe(&mut [secret]);
    r
}
fn wallet_imported_key(w: &Wallet, net: &str, n: u32) -> R<Box<Key>> {
    guard(|| Ok(key(KeyInner::Native(w.0.imported_key(network(net)?, n)?))))
}
fn wallet_imported_ua_key(w: &Wallet, net: &str, n: u32, kind: u16) -> R<Box<Key>> {
    guard(|| Ok(key(KeyInner::Ua(w.0.imported_ua_key(network(net)?, n, kind)?))))
}
fn wallet_seal_label_vault(w: &Wallet, label: &str, vault_passphrase: &mut [u8]) -> R<String> {
    let r = guard(|| Ok(w.0.seal_label_vault(label, text(vault_passphrase)?, None)?.to_json()));
    wipe(&mut [vault_passphrase]);
    r
}
fn wallet_open_label_vault(w: &Wallet, vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8]) -> R<()> {
    let r = guard(|| {
        let v = uw::Vault::from_json(vault_json.as_bytes())?;
        Ok(w.0.open_label_vault(&v, unlock(vault_passphrase, prf32)?)?)
    });
    wipe(&mut [vault_passphrase, prf32]);
    r
}
fn wallet_manifest_json(w: &Wallet) -> String {
    w.0.manifest().to_json()
}
fn wallet_discover_candidates(w: &Wallet, kind: u16, account: u32, gap: u32) -> R<String> {
    guard(|| {
        let hex = |u: &[u8; 32]| u.iter().fold(String::from("0x"), |s, b| s + &format!("{b:02x}"));
        let rows: Vec<String> =
            w.0.discover_candidates(kind, account, gap)?.iter().map(|(i, u)| format!("{{\"index\":{i},\"ua\":\"{}\"}}", hex(u))).collect();
        Ok(format!("[{}]", rows.join(",")))
    })
}
fn wallet_backup_seal(w: &Wallet, sender: &Key, recipients: &[ffi::Recipient]) -> R<Vec<String>> {
    guard(|| {
        let rs = recipients
            .iter()
            .map(|r| if r.ephemeral { Ok(uw::Recipient::ephemeral(&r.kem_pk)) } else { uw::Recipient::ua(r.kind, &r.key_data, r.version, &r.kem_pk) })
            .collect::<uw::Result<Vec<_>>>()?;
        Ok(w.0.backup_seal(ua_key(sender)?, &rs)?.iter().map(uw::SealedContainer::to_json).collect())
    })
}
#[allow(clippy::too_many_arguments)]
fn restore(
    kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str, current: Option<&Wallet>,
    rollback: Option<uw::AllowRollback>, bip39_passphrase: &mut [u8],
) -> R<Box<Restored>> {
    let r = guard(|| {
        let (c, o) = (container(container_json)?, Opening::read(expect_json, members_json, accepted_json)?);
        let pass = text(bip39_passphrase)?;
        let w = o.with(|e, m, acc| uw::Wallet::restore_backup(&kk.0, &c, e, m, acc, current.map(|w| &w.0), rollback, pass))?;
        Ok(Box::new(Restored(w)))
    });
    wipe(&mut [bip39_passphrase]);
    r
}
fn wallet_restore_backup(
    kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str, bip39_passphrase: &mut [u8],
) -> R<Box<Restored>> {
    restore(kk, container_json, expect_json, members_json, accepted_json, None, None, bip39_passphrase)
}
fn wallet_restore_backup_over(
    kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str, current: &Wallet,
    bip39_passphrase: &mut [u8],
) -> R<Box<Restored>> {
    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), None, bip39_passphrase)
}
fn wallet_restore_backup_rollback(
    kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str, current: &Wallet,
    bip39_passphrase: &mut [u8],
) -> R<Box<Restored>> {
    let allow = Some(uw::AllowRollback);
    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), allow, bip39_passphrase)
}
fn restored_installed(r: &Restored) -> bool {
    r.0.is_some()
}
fn restored_take(r: &mut Restored) -> R<Box<Wallet>> {
    r.0.take().map(|w| Box::new(Wallet(w, Live::new()))).ok_or_else(argument)
}
fn wallet_link_seal(w: &Wallet, sender: &Key, session_kem_pk: &[u8], short_code: &str) -> R<String> {
    guard(|| Ok(w.0.link_seal(ua_key(sender)?, session_kem_pk, short_code)?.to_json()))
}
fn wallet_from_link(
    s: &LinkSession, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str, bip39_passphrase: &mut [u8],
) -> R<Box<Wallet>> {
    let r = guard(|| {
        let (c, o) = (container(container_json)?, Opening::read(expect_json, members_json, accepted_json)?);
        let pass = text(bip39_passphrase)?;
        let taken = s.0.lock().map_err(|_| argument())?.take().ok_or_else(|| UaErr("UAKeyRevoked".into()))?;
        let w = o.with(|e, m, acc| uw::Wallet::from_link(taken, &c, e, m, acc, pass))?;
        Ok(Box::new(Wallet(w, Live::new())))
    });
    wipe(&mut [bip39_passphrase]);
    r
}
fn wallet_zether_key(w: &Wallet, coin: u32, account: u32, key_use: u32) -> R<Box<ZetherKey>> {
    guard(|| Ok(Box::new(ZetherKey(w.0.zether_key(coin, account, key_use)?, Live::new()))))
}
fn wallet_pqz_key(w: &Wallet, account: u32, index: u32) -> R<Box<PqzKey>> {
    guard(|| Ok(Box::new(PqzKey(w.0.pqz_key(account, index)?, Live::new()))))
}
fn wallet_export_pqz_leaf_raw(w: &Wallet, account: u32, index: u32) -> R<Vec<u8>> {
    guard(|| Ok(w.0.export_pqz_leaf_raw(account, index, fpqz::AllowSecretExport)?.to_vec()))
}
/// Group 3g (T15o): the PQZ key and leaf of a key version.
fn wallet_pqz_key_version(w: &Wallet, account: u32, index: u32, version: u64) -> R<Box<PqzKey>> {
    guard(|| Ok(Box::new(PqzKey(w.0.pqz_key_version(account, index, version)?, Live::new()))))
}
fn wallet_export_pqz_leaf_raw_version(w: &Wallet, account: u32, index: u32, version: u64) -> R<Vec<u8>> {
    guard(|| Ok(w.0.export_pqz_leaf_raw_version(account, index, version, fpqz::AllowSecretExport)?.to_vec()))
}

// --- seed backup -----------------------------------------------------------------------------------------------------------

fn backup(b: &SeedBackup) -> R<std::sync::MutexGuard<'_, uw::SeedBackup>> {
    b.0.lock().map_err(|_| argument())
}
fn seed_backup_reveal(b: &SeedBackup) -> R<Vec<u8>> {
    guard(|| Ok(backup(b)?.reveal()?.as_bytes().to_vec()))
}
fn seed_backup_challenge(b: &SeedBackup) -> R<Vec<u32>> {
    guard(|| Ok(backup(b)?.challenge()?.iter().map(|i| u32::try_from(*i).unwrap_or(u32::MAX)).collect()))
}
fn seed_backup_verify(b: &SeedBackup, word1: &mut [u8], word2: &mut [u8], word3: &mut [u8]) -> R<bool> {
    let r = guard(|| Ok(backup(b)?.verify(&[text(word1)?, text(word2)?, text(word3)?])?));
    wipe(&mut [word1, word2, word3]);
    r
}
fn seed_backup_take(b: &SeedBackup) -> R<Vec<u8>> {
    guard(|| Ok(backup(b)?.take().map(|e| e.to_vec()).unwrap_or_default()))
}

// --- keys and signing ------------------------------------------------------------------------------------------------------

fn key_is_ua(k: &Key) -> bool {
    matches!(&*k.0, KeyInner::Ua(_))
}
fn key_kind(k: &Key) -> u16 {
    match &*k.0 {
        KeyInner::Ua(u) => u.kind(),
        KeyInner::Native(_) => 0,
    }
}
fn key_data(k: &Key) -> Vec<u8> {
    match &*k.0 {
        KeyInner::Ua(u) => u.key_data(),
        KeyInner::Native(n) => n.public_key(),
    }
}
fn key_ua(k: &Key) -> R<Vec<u8>> {
    ua_key(k)?.ua().map(|u| u.to_vec()).ok_or_else(argument)
}
fn key_network(k: &Key) -> String {
    match &*k.0 {
        KeyInner::Native(n) => n.network().name().into(),
        KeyInner::Ua(_) => String::new(),
    }
}
fn key_address(k: &Key) -> R<String> {
    native_key(k)?.address().ok_or_else(argument)
}
fn sign_ua(k: &Key, purpose: &[u8], digest: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua_key(k)?.sign_ua(&a(purpose)?, &a(digest)?)?))
}
fn sign_member(k: &Key, structure_ua: &[u8], structure_ua_msg: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(ua_key(k)?.sign_member(&a(structure_ua)?, &a(structure_ua_msg)?)?))
}
fn sign_typed(k: &Key, typed_data_json: &str, expect_json: &str) -> R<Vec<u8>> {
    guard(|| {
        let td = uw::TypedData::from_json(typed_data_json.as_bytes())?;
        Ok(native_key(k)?.sign_typed(&td, uw::Expect::from_json(expect_json.as_bytes())?)?)
    })
}
fn sign_typed_any(k: &Key, typed_data_json: &str) -> R<Vec<u8>> {
    guard(|| {
        let td = uw::TypedData::from_json(typed_data_json.as_bytes())?;
        Ok(native_key(k)?.sign_typed(&td, uw::Expect::Any(uw::AllowAnyTypedData))?)
    })
}
fn sign_transaction(k: &Key, tx_json: &str) -> R<Vec<u8>> {
    guard(|| Ok(native_key(k)?.sign_transaction(&uw::EvmTx::from_json(tx_json.as_bytes())?)?.raw))
}
fn sign_key_proof(k: &Key, challenge: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(native_key(k)?.sign_key_proof(challenge)?))
}
fn sign_digest_raw(k: &Key, digest: &[u8]) -> R<Vec<u8>> {
    guard(|| match &*k.0 {
        KeyInner::Ua(_) => Err(UaErr("UARawDigestRefused".into())),
        KeyInner::Native(n) => Ok(n.sign_digest(&a(digest)?, uw::AllowRawDigest)?),
    })
}
fn key_list_new() -> Box<KeyList> {
    Box::new(KeyList(Vec::new()))
}
fn key_list_push(l: &mut KeyList, k: &Key) {
    l.0.push(Arc::clone(&k.0));
}
fn uasig(request_json: &str, keys: &KeyList) -> R<String> {
    guard(|| {
        let req = uw::UaSigRequest::from_json(request_json.as_bytes())?;
        let ks: Vec<&dyn uw::Signer> = keys.0.iter().map(|k| signer(k)).collect();
        Ok(ua::json::uasig_json(&req.sign(&ks)?))
    })
}
fn kem_key(k: &Key, version: u64) -> R<Box<KemKey>> {
    guard(|| Ok(Box::new(KemKey(ua_key(k)?.kem_key(version)?, Live::new()))))
}

// --- KEM, seal / open, link ------------------------------------------------------------------------------------------------

fn kem_ephemeral() -> R<Box<KemKey>> {
    guard(|| Ok(Box::new(KemKey(uw::KemKeyPair::generate_ephemeral()?, Live::new()))))
}
fn kem_pk(kk: &KemKey) -> Vec<u8> {
    kk.0.kem_pk()
}
fn kem_decaps(kk: &KemKey, mlkem_ct: &[u8], x25519_eph: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(kk.0.decaps(mlkem_ct, &a(x25519_eph)?)?.to_vec()))
}
fn kem_encaps(kem_pk: &[u8]) -> R<ffi::Encapsulated> {
    guard(|| {
        let (ct, e, ss) = uw::kem_encaps(kem_pk)?;
        Ok(ffi::Encapsulated { mlkem_ct: ct, x25519_eph: e.to_vec(), ss: ss.to_vec() })
    })
}
fn seal(kem_pk: &[u8], purpose: &str, aad: &[u8], pt: &[u8]) -> R<ffi::Sealed> {
    guard(|| {
        let s = uw::seal(kem_pk, purpose, aad, pt)?;
        Ok(ffi::Sealed { mlkem_ct: s.mlkem_ct, x25519_eph: s.x25519_eph.to_vec(), ciphertext: s.ciphertext })
    })
}
fn open(kk: &KemKey, purpose: &str, aad: &[u8], mlkem_ct: &[u8], x25519_eph: &[u8], ct: &[u8]) -> R<Vec<u8>> {
    guard(|| {
        let s = uw::Sealed { version: 1, scheme: 1, mlkem_ct: mlkem_ct.to_vec(), x25519_eph: a(x25519_eph)?, ciphertext: ct.to_vec() };
        Ok(kk.0.open(purpose, aad, &s)?.to_vec())
    })
}
fn open_container(kk: &KemKey, container_json: &str, expect_json: &str, members_json: &str, accepted_json: &str) -> R<Vec<u8>> {
    guard(|| {
        let (c, o) = (container(container_json)?, Opening::read(expect_json, members_json, accepted_json)?);
        Ok(o.with(|e, m, acc| kk.0.open_container(&c, e, m, acc))?.to_vec())
    })
}
fn link_session_new() -> R<Box<LinkSession>> {
    guard(|| Ok(Box::new(LinkSession(Mutex::new(Some(uw::LinkSession::new()?)), Live::new()))))
}
fn session<T>(s: &LinkSession, f: impl FnOnce(&uw::LinkSession) -> T) -> R<T> {
    s.0.lock().map_err(|_| argument())?.as_ref().map(f).ok_or_else(|| UaErr("UAKeyRevoked".into()))
}
fn link_session_kem_pk(s: &LinkSession) -> R<Vec<u8>> {
    session(s, uw::LinkSession::kem_pk)
}
fn link_session_short_code(s: &LinkSession) -> R<String> {
    session(s, uw::LinkSession::short_code)
}

// --- vault -----------------------------------------------------------------------------------------------------------------

fn vault_needs_rewrap(vault_json: &str) -> R<bool> {
    guard(|| Ok(uw::Vault::from_json(vault_json.as_bytes())?.needs_rewrap()))
}
fn vault_rewrap_pin(vault_json: &str, old_passphrase: &mut [u8], new_passphrase: &mut [u8]) -> R<String> {
    let r = guard(|| Ok(uw::Vault::from_json(vault_json.as_bytes())?.rewrap_pin(text(old_passphrase)?, text(new_passphrase)?)?.to_json()));
    wipe(&mut [old_passphrase, new_passphrase]);
    r
}
fn vault_enable_prf(vault_json: &str, vault_passphrase: &mut [u8], prf32: &mut [u8], credential_id: &str, salt: &[u8]) -> R<String> {
    let r = guard(|| {
        let output: &[u8; 32] = (&*prf32).try_into().map_err(|_| argument())?;
        let prf = uw::PrfEnvelope { output, credential_id, salt };
        Ok(uw::Vault::from_json(vault_json.as_bytes())?.enable_prf(text(vault_passphrase)?, &prf)?.to_json())
    });
    wipe(&mut [vault_passphrase, prf32]);
    r
}

// --- AEAD, HKDF, HMAC, WebAuthn --------------------------------------------------------------------------------------------

fn alg(a: u32) -> R<uw::Alg> {
    match a {
        1 => Ok(uw::Alg::Aes256Gcm),
        2 => Ok(uw::Alg::Aes256GcmSiv),
        _ => Err(argument()),
    }
}
fn aead_seal(al: u32, key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(uw::aead_seal(alg(al)?, &a(key)?, &a(nonce)?, aad, data)?))
}
fn aead_open(al: u32, key: &[u8], nonce: &[u8], aad: &[u8], data: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(uw::aead_open(alg(al)?, &a(key)?, &a(nonce)?, aad, data)?.to_vec()))
}
fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> R<Vec<u8>> {
    guard(|| Ok(uw::hkdf_sha256(ikm, salt, info, len)?.to_vec()))
}
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    uw::hmac_sha256(key, data).to_vec()
}
fn webauthn_challenge(purpose: &[u8], digest: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(uw::webauthn_challenge(&a(purpose)?, &a(digest)?)?.to_vec()))
}
fn webauthn_assertion(key_data: &[u8], expected_challenge: &[u8], auth_data: &[u8], client_data_json: &[u8], r: &[u8], s: &[u8]) -> R<Vec<u8>> {
    guard(|| Ok(uw::webauthn_assertion(key_data, &a(expected_challenge)?, auth_data, client_data_json, &a(r)?, &a(s)?)?))
}

// --- facades: Zether and PQZ (separate handles; neither calls the other) ---------------------------------------------------

fn zether_y(k: &ZetherKey) -> Vec<u8> {
    k.0.y()
}
fn zether_ua(k: &ZetherKey) -> Vec<u8> {
    k.0.ua().to_vec()
}
fn zether_call(k: &ZetherKey, cmd: &str, request_json: &str) -> R<String> {
    guard(|| Ok(k.0.call(cmd, request_json.as_bytes())?))
}
fn zether_seal_balance_cache(k: &ZetherKey, entries_json: &[u8]) -> R<String> {
    guard(|| Ok(k.0.seal_balance_cache(entries_json)?))
}
fn zether_open_balance_cache(k: &ZetherKey, box_json: &str) -> R<Vec<u8>> {
    guard(|| Ok(k.0.open_balance_cache(box_json.as_bytes())?.to_vec()))
}
fn pqz_pk(k: &PqzKey) -> Vec<u8> {
    k.0.pk()
}
fn pqz_call(k: &PqzKey, cmd: &str, request_json: &str) -> R<String> {
    guard(|| Ok(k.0.call(cmd, request_json.as_bytes())?))
}
fn pqz_seal_balance_cache(k: &PqzKey, entries: &[u8]) -> R<String> {
    guard(|| Ok(k.0.seal_balance_cache(entries)?))
}
fn pqz_open_balance_cache(k: &PqzKey, box_json: &str) -> R<Vec<u8>> {
    guard(|| Ok(k.0.open_balance_cache(box_json.as_bytes())?.to_vec()))
}
fn pqz_set() -> String {
    fpqz::pqz_set().to_json()
}
fn pqz_check(request_json: &str) -> R<String> {
    guard(|| Ok(fpqz::check_proven(request_json.as_bytes())?))
}
fn pqz_check_set(deployed_json: &str) -> R<()> {
    guard(|| Ok(fpqz::check_set(&fpqz::PqzSet::from_json(deployed_json.as_bytes())?)?))
}
