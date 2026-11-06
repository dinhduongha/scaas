// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! flutter_rust_bridge surface over `scaas_ua::wallet` and the Zether and PQZ facades (ua-rs-sign T13c, spec §9.1, §9.2, §10):
//! the Rust API, not the C ABI. Handles are frb opaque types (`UaWallet`, `UaKey`, `UaKemKey`, ...): Dart holds a reference,
//! never a secret; a key handle holds its wallet's store, a generation and a slot, so after `lock()` or the wallet's disposal it
//! answers `UAKeyRevoked`. The entry points that take a secret or need the load check are free functions, wrapped by the Dart
//! facade (`lib/src/wallet.dart`), which checks `abi_version` / `features` and wipes the caller's `Uint8List` after the call;
//! the Rust copy of every secret input is `Zeroizing`. Errors are `UAError { code, reason }` with the vector files' codes
//! ("UAKeyRevoked", ...), never an input. UNAUDITED.
use crate::api::ua::UAError;
use flutter_rust_bridge::frb;
use scaas_ua::facade::{pqz as fpqz, zether as fzether};
use scaas_ua::wallet as uw;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroizing;

type R<T> = Result<T, UAError>;

/// The surface generation of this binding, in step with the C ABI's `SCAAS_UA_ABI_VERSION` (6, ua-rs-sign T12).
const ABI_VERSION: u32 = 6;
const _: () = assert!(!scaas_ua::build::VECTORS, "ua-dart-frb must not build scaas-ua with feature `vectors`");
/// The PQZ facade's largest output (`SCAAS_UA_PQZ_OUT_MAX`); a call returns its whole JSON, never sized by a query.
const _: () = assert!(1_052_672 >= fpqz::OUT_MAX);

impl From<uw::Error> for UAError {
    fn from(e: uw::Error) -> Self {
        match e {
            uw::Error::Ua(e) => e.into(),
            e => UAError { code: format!("UA{}", e.code()), reason: String::new() },
        }
    }
}
fn arg() -> UAError {
    UAError { code: "UAArgument".into(), reason: String::new() }
}

static LIVE: AtomicI64 = AtomicI64::new(0);
/// Counts the live handles (`live_handles`): a handle freed twice shows as a count below its start.
struct Live;
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

#[frb(opaque)]
pub struct UaWallet(uw::Wallet, Live);
enum KeyInner {
    Ua(uw::UaKey),
    Native(uw::NativeKey),
}
/// A UA or native key handle.
#[frb(opaque)]
pub struct UaKey(Arc<KeyInner>, Live);
/// The keys of a UASig request, by position.
#[frb(opaque)]
pub struct UaKeyList(Vec<Arc<KeyInner>>);
#[frb(opaque)]
pub struct UaKemKey(uw::KemKeyPair, Live);
/// A device-link session; `wallet_from_link` consumes it (later calls: `UAKeyRevoked`).
#[frb(opaque)]
pub struct UaLinkSession(Mutex<Option<uw::LinkSession>>, Live);
/// The recovery phrase of `wallet_generate`: reveal once, challenge, verify, take.
#[frb(opaque)]
pub struct UaSeedBackup(Mutex<uw::SeedBackup>, Live);
#[frb(opaque)]
pub struct UaZetherKey(fzether::ZetherKey, Live);
#[frb(opaque)]
pub struct UaPqzKey(fpqz::PqzKey, Live);

/// The arena's protection now (spec §8.2); all 0 while locked.
pub struct UaMemoryProtection {
    pub chunks: u32,
    pub locked: u32,
    pub no_dump: u32,
}
/// A recipient of `backup_seal`: the KEM key `kem_pk` of record `version` of the UA of (`kind`, `key_data`); with `ephemeral`,
/// an ephemeral key (kind, key data and version unread).
pub struct UaRecipient {
    pub kind: u16,
    pub key_data: Vec<u8>,
    pub version: u64,
    pub kem_pk: Vec<u8>,
    pub ephemeral: bool,
}
/// A seal's named fields (version and scheme 1).
pub struct UaSealed {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: Vec<u8>,
    pub ciphertext: Vec<u8>,
}
/// `kem_encaps`: `ss` is a secret (the caller wipes it).
pub struct UaEncapsulated {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: Vec<u8>,
    pub ss: Vec<u8>,
}

// --- load ------------------------------------------------------------------------------------------------------------------

#[frb(sync)]
pub fn abi_version() -> u32 {
    ABI_VERSION
}
/// The bits of `scaas_ua_features()` (ua-c), from scaas-ua's own `cfg`.
#[frb(sync)]
pub fn features() -> u64 {
    use scaas_ua::build as b;
    let on = |x: bool, bit: u32| if x { 1u64 << bit } else { 0 };
    on(b::WALLET, 0)
        | on(b::PQ, 1)
        | on(b::FALCON, 2)
        | on(b::ZETHER, 3)
        | on(b::PQZ, 4)
        | b::PQZ_SETS.iter().zip(5..).fold(0, |a, (x, bit)| a | on(*x, bit))
        | on(b::MLOCK, 10)
}
/// Handles alive now (a test of "freed exactly once").
#[frb(sync)]
pub fn live_handles() -> i64 {
    LIVE.load(Ordering::SeqCst)
}

// --- helpers ---------------------------------------------------------------------------------------------------------------

fn text(b: &[u8]) -> R<&str> {
    std::str::from_utf8(b).map_err(|_| arg())
}
fn a<const N: usize>(b: &[u8]) -> R<[u8; N]> {
    b.try_into().map_err(|_| arg())
}
fn secret(v: Option<Vec<u8>>) -> Option<Zeroizing<Vec<u8>>> {
    v.map(Zeroizing::new)
}
fn network(name: &str) -> R<uw::Network> {
    uw::Network::from_name(name).ok_or_else(arg)
}
/// Exactly one unlock secret: the PRF secret first when both are given (clientkeys `dekFrom`); neither is `UAArgument`.
fn unlock<'a>(vault_passphrase: &'a Option<Zeroizing<Vec<u8>>>, prf32: &'a Option<Zeroizing<Vec<u8>>>) -> R<uw::Unlock<'a>> {
    if let Some(p) = prf32 {
        return Ok(uw::Unlock::Prf(p.as_slice().try_into().map_err(|_| arg())?));
    }
    Ok(uw::Unlock::VaultPassphrase(text(vault_passphrase.as_ref().ok_or_else(arg)?)?))
}
fn key(k: KeyInner) -> UaKey {
    UaKey(Arc::new(k), Live::new())
}
fn container(json: &str) -> R<uw::SealedContainer> {
    Ok(uw::SealedContainer::from_json(json.as_bytes())?)
}
struct Opening {
    expect: uw::ContainerExpectJson,
    members: uw::MembersJson,
    accepted: Option<uw::AcceptedJson>,
}
impl Opening {
    fn read(expect_json: &str, members_json: Option<String>, accepted_json: Option<String>) -> R<Opening> {
        let members = match members_json {
            Some(m) => uw::MembersJson::from_json(m.as_bytes())?,
            None => uw::MembersJson::default(),
        };
        let accepted = accepted_json.map(|a| uw::AcceptedJson::from_json(a.as_bytes())).transpose()?;
        Ok(Opening { expect: uw::ContainerExpectJson::from_json(expect_json.as_bytes())?, members, accepted })
    }
    fn with<T>(&self, f: impl FnOnce(&uw::ContainerExpect, &scaas_ua::ua8::Members, Option<&scaas_ua::ua8::Accepted>) -> T) -> T {
        let members = |id: [u8; 32]| self.members.lookup(id);
        let accepted = |id: [u8; 32], i: u16| self.accepted.as_ref().is_some_and(|a| a.accepted(id, i));
        f(&self.expect.get(), &members, self.accepted.as_ref().map(|_| &accepted as &scaas_ua::ua8::Accepted))
    }
}

// --- entry points: the Dart facade checks the load and wipes the caller's secrets ---------------------------------------

pub fn wallet_generate() -> R<(UaWallet, UaSeedBackup)> {
    let (w, b) = uw::Wallet::generate()?;
    Ok((UaWallet(w, Live::new()), UaSeedBackup(Mutex::new(b), Live::new())))
}
pub fn wallet_from_mnemonic(words: Vec<u8>, bip39_passphrase: Vec<u8>) -> R<UaWallet> {
    let (words, pass) = (Zeroizing::new(words), Zeroizing::new(bip39_passphrase));
    Ok(UaWallet(uw::Wallet::from_mnemonic(text(&words)?, text(&pass)?)?, Live::new()))
}
/// Exactly one of `vault_passphrase` / `prf32` (null = absent; both: the PRF secret, the passphrase not tried).
pub fn wallet_open_vault(
    vault_json: String, vault_passphrase: Option<Vec<u8>>, prf32: Option<Vec<u8>>, bip39_passphrase: Vec<u8>,
) -> R<UaWallet> {
    let (vp, prf, pass) = (secret(vault_passphrase), secret(prf32), Zeroizing::new(bip39_passphrase));
    let v = uw::Vault::from_json(vault_json.as_bytes())?;
    Ok(UaWallet(uw::Wallet::open_vault(&v, unlock(&vp, &prf)?, text(&pass)?)?, Live::new()))
}
pub fn wallet_unlock(
    w: &UaWallet, vault_json: String, vault_passphrase: Option<Vec<u8>>, prf32: Option<Vec<u8>>, bip39_passphrase: Vec<u8>,
) -> R<()> {
    let (vp, prf, pass) = (secret(vault_passphrase), secret(prf32), Zeroizing::new(bip39_passphrase));
    let v = uw::Vault::from_json(vault_json.as_bytes())?;
    Ok(w.0.unlock(&v, unlock(&vp, &prf)?, text(&pass)?)?)
}
pub fn wallet_seal_vault(w: &UaWallet, vault_passphrase: Vec<u8>) -> R<String> {
    let vp = Zeroizing::new(vault_passphrase);
    Ok(w.0.seal_vault(text(&vp)?, None)?.to_json())
}
pub fn wallet_import_native_key(w: &UaWallet, network_name: String, secret_key: Vec<u8>) -> R<UaKey> {
    let s = Zeroizing::new(secret_key);
    Ok(key(KeyInner::Native(w.0.import_native_key(network(&network_name)?, &s)?)))
}
pub fn wallet_seal_label_vault(w: &UaWallet, label: String, vault_passphrase: Vec<u8>) -> R<String> {
    let vp = Zeroizing::new(vault_passphrase);
    Ok(w.0.seal_label_vault(&label, text(&vp)?, None)?.to_json())
}
pub fn wallet_open_label_vault(w: &UaWallet, vault_json: String, vault_passphrase: Option<Vec<u8>>, prf32: Option<Vec<u8>>) -> R<()> {
    let (vp, prf) = (secret(vault_passphrase), secret(prf32));
    let v = uw::Vault::from_json(vault_json.as_bytes())?;
    Ok(w.0.open_label_vault(&v, unlock(&vp, &prf)?)?)
}
#[allow(clippy::too_many_arguments)]
fn restore(
    kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>, accepted_json: Option<String>,
    current: Option<&UaWallet>, rollback: Option<uw::AllowRollback>, bip39_passphrase: Vec<u8>,
) -> R<Option<UaWallet>> {
    let pass = Zeroizing::new(bip39_passphrase);
    let (c, o) = (container(&container_json)?, Opening::read(&expect_json, members_json, accepted_json)?);
    let pass = text(&pass)?;
    let w = o.with(|e, m, acc| uw::Wallet::restore_backup(&kk.0, &c, e, m, acc, current.map(|w| &w.0), rollback, pass))?;
    Ok(w.map(|w| UaWallet(w, Live::new())))
}
/// The wallet of a backup container (`None`: an equal generation installed nothing). `members_json` / `accepted_json` null = none.
pub fn wallet_restore_backup(
    kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>, accepted_json: Option<String>,
    bip39_passphrase: Vec<u8>,
) -> R<Option<UaWallet>> {
    restore(kk, container_json, expect_json, members_json, accepted_json, None, None, bip39_passphrase)
}
/// As `wallet_restore_backup` over the wallet `current` holds (an older generation: `UABackupRollback`).
pub fn wallet_restore_backup_over(
    current: &UaWallet, kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>,
    accepted_json: Option<String>, bip39_passphrase: Vec<u8>,
) -> R<Option<UaWallet>> {
    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), None, bip39_passphrase)
}
/// The rollback, by its own name.
pub fn wallet_restore_backup_rollback(
    current: &UaWallet, kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>,
    accepted_json: Option<String>, bip39_passphrase: Vec<u8>,
) -> R<Option<UaWallet>> {
    let allow = Some(uw::AllowRollback);
    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), allow, bip39_passphrase)
}
pub fn wallet_from_link(
    session: &UaLinkSession, container_json: String, expect_json: String, members_json: Option<String>,
    accepted_json: Option<String>, bip39_passphrase: Vec<u8>,
) -> R<UaWallet> {
    let pass = Zeroizing::new(bip39_passphrase);
    let (c, o) = (container(&container_json)?, Opening::read(&expect_json, members_json, accepted_json)?);
    let pass = text(&pass)?;
    let taken = session.0.lock().map_err(|_| arg())?.take().ok_or_else(|| UAError { code: "UAKeyRevoked".into(), reason: String::new() })?;
    let w = o.with(|e, m, acc| uw::Wallet::from_link(taken, &c, e, m, acc, pass))?;
    Ok(UaWallet(w, Live::new()))
}
/// Whether `answers` are the words at the challenged positions, in order.
pub fn seed_backup_verify(b: &UaSeedBackup, answers: Vec<Vec<u8>>) -> R<bool> {
    let answers: Vec<Zeroizing<Vec<u8>>> = answers.into_iter().map(Zeroizing::new).collect();
    let words = answers.iter().map(|a| text(a)).collect::<R<Vec<&str>>>()?;
    Ok(b.0.lock().map_err(|_| arg())?.verify(&words)?)
}
pub fn vault_needs_rewrap(vault_json: String) -> R<bool> {
    Ok(uw::Vault::from_json(vault_json.as_bytes())?.needs_rewrap())
}
pub fn vault_rewrap_pin(vault_json: String, old_passphrase: Vec<u8>, new_passphrase: Vec<u8>) -> R<String> {
    let (o, n) = (Zeroizing::new(old_passphrase), Zeroizing::new(new_passphrase));
    Ok(uw::Vault::from_json(vault_json.as_bytes())?.rewrap_pin(text(&o)?, text(&n)?)?.to_json())
}
pub fn vault_enable_prf(vault_json: String, vault_passphrase: Vec<u8>, prf32: Vec<u8>, credential_id: String, salt: Vec<u8>) -> R<String> {
    let (vp, prf) = (Zeroizing::new(vault_passphrase), Zeroizing::new(prf32));
    let output: &[u8; 32] = prf.as_slice().try_into().map_err(|_| arg())?;
    let env = uw::PrfEnvelope { output, credential_id: &credential_id, salt: &salt };
    Ok(uw::Vault::from_json(vault_json.as_bytes())?.enable_prf(text(&vp)?, &env)?.to_json())
}
/// One container JSON per recipient; raises the backup generation once. (A free function: the Dart facade refuses a version
/// outside u64 before frb's 64-bit encoding wraps it.)
pub fn wallet_backup_seal(w: &UaWallet, sender: &UaKey, recipients: Vec<UaRecipient>) -> R<Vec<String>> {
    let rs = recipients
        .iter()
        .map(|r| if r.ephemeral { Ok(uw::Recipient::ephemeral(&r.kem_pk)) } else { uw::Recipient::ua(r.kind, &r.key_data, r.version, &r.kem_pk) })
        .collect::<uw::Result<Vec<_>>>()?;
    Ok(w.0.backup_seal(sender.ua()?, &rs)?.iter().map(uw::SealedContainer::to_json).collect())
}
/// The UA's KEM key of record `version` (a free function for the same reason).
pub fn key_kem_key(k: &UaKey, version: u64) -> R<UaKemKey> {
    Ok(UaKemKey(k.ua()?.kem_key(version)?, Live::new()))
}
pub fn kem_ephemeral() -> R<UaKemKey> {
    Ok(UaKemKey(uw::KemKeyPair::generate_ephemeral()?, Live::new()))
}
pub fn kem_encaps(kem_pk: Vec<u8>) -> R<UaEncapsulated> {
    let (ct, e, ss) = uw::kem_encaps(&kem_pk)?;
    Ok(UaEncapsulated { mlkem_ct: ct, x25519_eph: e.to_vec(), ss: ss.to_vec() })
}
/// A seal to `kem_pk` (authenticates no sender).
pub fn seal(kem_pk: Vec<u8>, purpose: String, aad: Vec<u8>, pt: Vec<u8>) -> R<UaSealed> {
    let pt = Zeroizing::new(pt);
    let s = uw::seal(&kem_pk, &purpose, &aad, &pt)?;
    Ok(UaSealed { mlkem_ct: s.mlkem_ct, x25519_eph: s.x25519_eph.to_vec(), ciphertext: s.ciphertext })
}
pub fn link_session_new() -> R<UaLinkSession> {
    Ok(UaLinkSession(Mutex::new(Some(uw::LinkSession::new()?)), Live::new()))
}
pub fn key_list_new() -> UaKeyList {
    UaKeyList(Vec::new())
}
/// The UASig builder: `request_json` as ua-c's `scaas_ua_uasig`, keys by position in `keys`.
pub fn uasig(request_json: String, keys: &UaKeyList) -> R<String> {
    let req = uw::UaSigRequest::from_json(request_json.as_bytes())?;
    let ks: Vec<&dyn uw::Signer> = keys.0.iter().map(|k| signer(k)).collect();
    Ok(scaas_ua::json::uasig_json(&req.sign(&ks)?))
}
fn signer(k: &KeyInner) -> &dyn uw::Signer {
    match k {
        KeyInner::Ua(u) => u,
        KeyInner::Native(n) => n,
    }
}
fn alg(x: u32) -> R<uw::Alg> {
    match x {
        1 => Ok(uw::Alg::Aes256Gcm),
        2 => Ok(uw::Alg::Aes256GcmSiv),
        _ => Err(arg()),
    }
}
/// `alg` 1 = AES-256-GCM, 2 = AES-256-GCM-SIV.
pub fn aead_seal(alg_id: u32, key32: Vec<u8>, nonce12: Vec<u8>, aad: Vec<u8>, data: Vec<u8>) -> R<Vec<u8>> {
    Ok(uw::aead_seal(alg(alg_id)?, &a(&key32)?, &a(&nonce12)?, &aad, &data)?)
}
pub fn aead_open(alg_id: u32, key32: Vec<u8>, nonce12: Vec<u8>, aad: Vec<u8>, data: Vec<u8>) -> R<Vec<u8>> {
    Ok(uw::aead_open(alg(alg_id)?, &a(&key32)?, &a(&nonce12)?, &aad, &data)?.to_vec())
}
pub fn hkdf_sha256(ikm: Vec<u8>, salt: Vec<u8>, info: Vec<u8>, len: u32) -> R<Vec<u8>> {
    Ok(uw::hkdf_sha256(&ikm, &salt, &info, usize::try_from(len).map_err(|_| arg())?)?.to_vec())
}
pub fn hmac_sha256(key_bytes: Vec<u8>, data: Vec<u8>) -> Vec<u8> {
    uw::hmac_sha256(&key_bytes, &data).to_vec()
}
pub fn webauthn_challenge(purpose: Vec<u8>, digest: Vec<u8>) -> R<Vec<u8>> {
    Ok(uw::webauthn_challenge(&a(&purpose)?, &a(&digest)?)?.to_vec())
}
pub fn webauthn_assertion(
    key_data: Vec<u8>, expected_challenge: Vec<u8>, auth_data: Vec<u8>, client_data_json: Vec<u8>, r: Vec<u8>, s: Vec<u8>,
) -> R<Vec<u8>> {
    Ok(uw::webauthn_assertion(&key_data, &a(&expected_challenge)?, &auth_data, &client_data_json, &a(&r)?, &a(&s)?)?)
}
/// `{set, pkLen, pqzlId, pqzhId}` of this build.
pub fn pqz_set() -> String {
    fpqz::pqz_set().to_json()
}
pub fn pqz_check_set(deployed_json: String) -> R<()> {
    Ok(fpqz::check_set(&fpqz::PqzSet::from_json(deployed_json.as_bytes())?)?)
}

// --- handle methods (public data and calls on a handle; no secret input) --------------------------------------------------

impl UaWallet {
    #[frb(sync)]
    pub fn lock(&self) {
        self.0.lock();
    }
    #[frb(sync)]
    pub fn memory_protection(&self) -> UaMemoryProtection {
        let m = self.0.memory_protection();
        let c = |n: usize| u32::try_from(n).unwrap_or(u32::MAX);
        UaMemoryProtection { chunks: c(m.chunks), locked: c(m.locked), no_dump: c(m.no_dump) }
    }
    pub fn ua_key(&self, kind: u16, account: u32, index: u32) -> R<UaKey> {
        Ok(key(KeyInner::Ua(self.0.ua_key(kind, account, index)?)))
    }
    /// `network_name` the clientkeys name (`evm`, `hedera_ecdsa`, ...); `coin_type` null = the network's own.
    pub fn native_key(&self, network_name: String, index: u32, coin_type: Option<u32>) -> R<UaKey> {
        Ok(key(KeyInner::Native(self.0.native_key(network(&network_name)?, index, coin_type)?)))
    }
    pub fn imported_key(&self, network_name: String, n: u32) -> R<UaKey> {
        Ok(key(KeyInner::Native(self.0.imported_key(network(&network_name)?, n)?)))
    }
    #[frb(sync)]
    pub fn manifest_json(&self) -> String {
        self.0.manifest().to_json()
    }
    /// JSON `[{index, ua}]`.
    pub fn discover_candidates(&self, kind: u16, account: u32, gap: u32) -> R<String> {
        let hex = |u: &[u8; 32]| u.iter().fold(String::from("0x"), |s, b| s + &format!("{b:02x}"));
        let rows: Vec<String> =
            self.0.discover_candidates(kind, account, gap)?.iter().map(|(i, u)| format!("{{\"index\":{i},\"ua\":\"{}\"}}", hex(u))).collect();
        Ok(format!("[{}]", rows.join(",")))
    }
    pub fn link_seal(&self, sender: &UaKey, session_kem_pk: Vec<u8>, short_code: String) -> R<String> {
        Ok(self.0.link_seal(sender.ua()?, &session_kem_pk, &short_code)?.to_json())
    }
    pub fn zether_key(&self, coin: u32, account: u32, key_use: u32) -> R<UaZetherKey> {
        Ok(UaZetherKey(self.0.zether_key(coin, account, key_use)?, Live::new()))
    }
    pub fn pqz_key(&self, account: u32, index: u32) -> R<UaPqzKey> {
        Ok(UaPqzKey(self.0.pqz_key(account, index)?, Live::new()))
    }
    /// The PQZ leaf `seed32`: the explicit export (spec §8.4); the caller wipes it.
    pub fn export_pqz_leaf_raw(&self, account: u32, index: u32) -> R<Vec<u8>> {
        Ok(self.0.export_pqz_leaf_raw(account, index, fpqz::AllowSecretExport)?.to_vec())
    }
}

impl UaSeedBackup {
    /// The words, once (the caller wipes them).
    pub fn reveal(&self) -> R<Vec<u8>> {
        Ok(self.0.lock().map_err(|_| arg())?.reveal()?.as_bytes().to_vec())
    }
    /// Three 1-based positions to ask.
    pub fn challenge(&self) -> R<Vec<u32>> {
        let p = self.0.lock().map_err(|_| arg())?.challenge()?;
        Ok(p.iter().map(|i| u32::try_from(*i).unwrap_or(u32::MAX)).collect())
    }
    /// The entropy, once confirmed; null before that and after the first call.
    pub fn take(&self) -> R<Option<Vec<u8>>> {
        Ok(self.0.lock().map_err(|_| arg())?.take().map(|e| e.to_vec()))
    }
}

impl UaKey {
    fn ua(&self) -> R<&uw::UaKey> {
        match &*self.0 {
            KeyInner::Ua(u) => Ok(u),
            KeyInner::Native(_) => Err(arg()),
        }
    }
    fn native(&self) -> R<&uw::NativeKey> {
        match &*self.0 {
            KeyInner::Native(n) => Ok(n),
            KeyInner::Ua(_) => Err(arg()),
        }
    }
    #[frb(sync)]
    pub fn is_ua(&self) -> bool {
        matches!(&*self.0, KeyInner::Ua(_))
    }
    /// A UA key's kind; 0 for a native key.
    #[frb(sync)]
    pub fn kind(&self) -> u16 {
        self.ua().map_or(0, uw::UaKey::kind)
    }
    /// A UA key's key data, a native key's public key.
    #[frb(sync)]
    pub fn key_data(&self) -> Vec<u8> {
        match &*self.0 {
            KeyInner::Ua(u) => u.key_data(),
            KeyInner::Native(n) => n.public_key(),
        }
    }
    #[frb(sync)]
    pub fn ua_id(&self) -> R<Vec<u8>> {
        self.ua()?.ua().map(|u| u.to_vec()).ok_or_else(arg)
    }
    /// "" for a UA key.
    #[frb(sync)]
    pub fn network_name(&self) -> String {
        self.native().map(|n| n.network().name().to_string()).unwrap_or_default()
    }
    #[frb(sync)]
    pub fn address(&self) -> R<String> {
        self.native()?.address().ok_or_else(arg)
    }
    pub fn sign_ua(&self, purpose: Vec<u8>, digest: Vec<u8>) -> R<Vec<u8>> {
        Ok(self.ua()?.sign_ua(&a(&purpose)?, &a(&digest)?)?)
    }
    pub fn sign_member(&self, structure_ua: Vec<u8>, structure_ua_msg: Vec<u8>) -> R<Vec<u8>> {
        Ok(self.ua()?.sign_member(&a(&structure_ua)?, &a(&structure_ua_msg)?)?)
    }
    /// Typed data through the signing policy (`expect_json`: what the user confirmed, spec §5.4).
    pub fn sign_typed(&self, typed_data_json: String, expect_json: String) -> R<Vec<u8>> {
        let td = uw::TypedData::from_json(typed_data_json.as_bytes())?;
        Ok(self.native()?.sign_typed(&td, uw::Expect::from_json(expect_json.as_bytes())?)?)
    }
    /// Any typed data, as supplied (the explicit opt-in of `AllowAnyTypedData`).
    pub fn sign_typed_any(&self, typed_data_json: String) -> R<Vec<u8>> {
        let td = uw::TypedData::from_json(typed_data_json.as_bytes())?;
        Ok(self.native()?.sign_typed(&td, uw::Expect::Any(uw::AllowAnyTypedData))?)
    }
    /// The raw transaction.
    pub fn sign_transaction(&self, tx_json: String) -> R<Vec<u8>> {
        Ok(self.native()?.sign_transaction(&uw::EvmTx::from_json(tx_json.as_bytes())?)?.raw)
    }
    pub fn sign_key_proof(&self, challenge: Vec<u8>) -> R<Vec<u8>> {
        Ok(self.native()?.sign_key_proof(&challenge)?)
    }
    /// A native key only: `UARawDigestRefused` for a UA key.
    pub fn sign_digest_raw(&self, digest: Vec<u8>) -> R<Vec<u8>> {
        match &*self.0 {
            KeyInner::Ua(_) => Err(UAError { code: "UARawDigestRefused".into(), reason: String::new() }),
            KeyInner::Native(n) => Ok(n.sign_digest(&a(&digest)?, uw::AllowRawDigest)?),
        }
    }
}

impl UaKeyList {
    /// Adds `k` at the next position (the list shares the handle).
    #[frb(sync)]
    pub fn push(&mut self, k: &UaKey) {
        self.0.push(Arc::clone(&k.0));
    }
}

impl UaKemKey {
    #[frb(sync)]
    pub fn kem_pk(&self) -> Vec<u8> {
        self.0.kem_pk()
    }
    /// The shared secret (the caller wipes it).
    pub fn decaps(&self, mlkem_ct: Vec<u8>, x25519_eph: Vec<u8>) -> R<Vec<u8>> {
        Ok(self.0.decaps(&mlkem_ct, &a(&x25519_eph)?)?.to_vec())
    }
    /// The plaintext (the caller wipes it).
    pub fn open(&self, purpose: String, aad: Vec<u8>, sealed: UaSealed) -> R<Vec<u8>> {
        let s = uw::Sealed { version: 1, scheme: 1, mlkem_ct: sealed.mlkem_ct, x25519_eph: a(&sealed.x25519_eph)?, ciphertext: sealed.ciphertext };
        Ok(self.0.open(&purpose, &aad, &s)?.to_vec())
    }
    /// A container's plaintext, accepted as `expect_json` says (spec §6.3); `members_json` / `accepted_json` null = none.
    pub fn open_container(
        &self, container_json: String, expect_json: String, members_json: Option<String>, accepted_json: Option<String>,
    ) -> R<Vec<u8>> {
        let (c, o) = (container(&container_json)?, Opening::read(&expect_json, members_json, accepted_json)?);
        Ok(o.with(|e, m, acc| self.0.open_container(&c, e, m, acc))?.to_vec())
    }
}

impl UaLinkSession {
    fn with<T>(&self, f: impl FnOnce(&uw::LinkSession) -> T) -> R<T> {
        self.0.lock().map_err(|_| arg())?.as_ref().map(f).ok_or_else(|| UAError { code: "UAKeyRevoked".into(), reason: String::new() })
    }
    #[frb(sync)]
    pub fn kem_pk(&self) -> R<Vec<u8>> {
        self.with(uw::LinkSession::kem_pk)
    }
    #[frb(sync)]
    pub fn short_code(&self) -> R<String> {
        self.with(uw::LinkSession::short_code)
    }
}

impl UaZetherKey {
    /// `Y`, 128 bytes.
    #[frb(sync)]
    pub fn y(&self) -> Vec<u8> {
        self.0.y()
    }
    #[frb(sync)]
    pub fn ua_id(&self) -> Vec<u8> {
        self.0.ua().to_vec()
    }
    /// zether-prover's commands with this handle's key; no request field carries a key.
    pub fn call(&self, cmd: String, request_json: String) -> R<String> {
        Ok(self.0.call(&cmd, request_json.as_bytes())?)
    }
    pub fn seal_balance_cache(&self, entries_json: Vec<u8>) -> R<String> {
        Ok(self.0.seal_balance_cache(&entries_json)?)
    }
    /// The cache's plaintext (the caller wipes it).
    pub fn open_balance_cache(&self, box_json: String) -> R<Vec<u8>> {
        Ok(self.0.open_balance_cache(box_json.as_bytes())?.to_vec())
    }
}

impl UaPqzKey {
    #[frb(sync)]
    pub fn pk(&self) -> Vec<u8> {
        self.0.pk()
    }
    /// The PQZ commands with this handle's key; the whole JSON (at most 1,052,672 bytes), never sized by a query.
    pub fn call(&self, cmd: String, request_json: String) -> R<String> {
        Ok(self.0.call(&cmd, request_json.as_bytes())?)
    }
    pub fn seal_balance_cache(&self, entries: Vec<u8>) -> R<String> {
        Ok(self.0.seal_balance_cache(&entries)?)
    }
    /// The cache's plaintext (the caller wipes it).
    pub fn open_balance_cache(&self, box_json: String) -> R<Vec<u8>> {
        Ok(self.0.open_balance_cache(box_json.as_bytes())?.to_vec())
    }
}
