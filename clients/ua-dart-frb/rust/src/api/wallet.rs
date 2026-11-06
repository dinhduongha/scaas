// SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0
//! flutter_rust_bridge surface over `scaas_ua::wallet` and the Zether and PQZ facades (ua-rs-sign T13c, spec §9.1, §9.2, §10):
//! the Rust API, not the C ABI. Handles are frb opaque types (`UaWallet`, `UaKey`, `UaKemKey`, ...): Dart holds a reference,
//! never a secret; a key handle holds its wallet's store, a generation and a slot, so after `lock()` or the wallet's disposal it
//! answers `UAKeyRevoked`. The entry points without a handle are free functions, wrapped by the Dart facade
//! (`lib/src/wallet.dart`), which checks `abi_version` / `features`. Every secret, in or out, is a [`SecretBytes`]: Rust-owned
//! memory that Dart fills and reads in place through `dart:ffi`, never through frb's codec (whose transfer buffers are freed,
//! not zeroed). Errors are `UAError { code, reason }` with the vector files' codes ("UAKeyRevoked", ...), never an input.
//! UNAUDITED.
use crate::api::ua::UAError;
use crate::frb_generated::RustAutoOpaque;
use flutter_rust_bridge::frb;
use scaas_ua::facade::{pqz as fpqz, zether as fzether};
use scaas_ua::wallet as uw;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use zeroize::Zeroize;

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

// --- secrets ---------------------------------------------------------------------------------------------------------------

/// ua-rs's arena chunk: 16 KiB, page-aligned (the largest page of a listed target).
const BLOCK: usize = 16384;
#[repr(C, align(16384))]
struct Block([u8; BLOCK]);
/// The largest secret (16 MiB; the PQZ facade's output is at most 1,052,672 bytes).
const SECRET_MAX: usize = 1 << 24;

/// A secret in Rust-owned memory: `len` bytes at the start of whole 16 KiB page-aligned blocks of its own (at least one),
/// allocated once at their final size and never moved or grown, so no stale copy; locked in RAM and no-dump with ua-rs's
/// [`uw::protect`] (feature `mlock`, best effort, as the wallet's arena: a refusal fails nothing); on drop zeroed, then
/// unmarked and unlocked. Dart writes an input and reads an output in place (`addr`, `size`, `dart:ffi`), never through
/// frb's codec. `SecretBytes.take(src)` (Dart) allocates, writes and zeroes `src`; `dispose()` drops this side.
#[frb(opaque, dart_code = "
import 'dart:ffi' as ffi;

  /// A new secret holding [src], written in place (no codec copy); [src] is zeroed afterwards, whatever the outcome. Native
  /// targets only: this package imports `dart:ffi` and does not build for the web.
  static SecretBytes take(Uint8List src) {
    try {
      final s = secretAlloc(len: src.length);
      ffi.Pointer<ffi.Uint8>.fromAddress(s.addr().toInt()).asTypedList(src.length).setAll(0, src);
      return s;
    } finally {
      src.fillRange(0, src.length, 0);
    }
  }

  /// A view of [s] in Rust memory, no copy; valid until [s] is disposed (a view kept past that reads freed memory).
  static Uint8List view(SecretBytes s) => ffi.Pointer<ffi.Uint8>.fromAddress(s.addr().toInt()).asTypedList(s.size());
")]
pub struct SecretBytes {
    mem: Box<[Block]>,
    len: usize,
    locked: bool,
    no_dump: bool,
}
impl SecretBytes {
    fn alloc(len: usize) -> R<SecretBytes> {
        if len > SECRET_MAX {
            return Err(arg());
        }
        let mut mem: Box<[Block]> = (0..len.div_ceil(BLOCK).max(1)).map(|_| Block([0; BLOCK])).collect();
        let (locked, no_dump) = uw::protect::on(mem.as_mut_ptr().cast(), mem.len() * BLOCK);
        Ok(SecretBytes { mem, len, locked, no_dump })
    }
    fn get(&self) -> &[u8] {
        // SAFETY: `mem` is `mem.len() * BLOCK` contiguous initialised bytes (`Block` is `repr(C)`, its size its alignment), and
        // `len` is at most that
        unsafe { std::slice::from_raw_parts(self.mem.as_ptr().cast::<u8>(), self.len) }
    }
    fn get_mut(&mut self) -> &mut [u8] {
        // SAFETY: as in `get`, borrowed mutably through `self`
        unsafe { std::slice::from_raw_parts_mut(self.mem.as_mut_ptr().cast::<u8>(), self.len) }
    }
    /// The address of the first byte, for Dart's in-place write or read; the same for the buffer's life.
    #[frb(sync)]
    pub fn addr(&mut self) -> usize {
        self.mem.as_mut_ptr() as usize
    }
    /// The secret's length in bytes.
    #[frb(sync)]
    pub fn size(&self) -> u32 {
        u32::try_from(self.len).unwrap_or(u32::MAX)
    }
}
impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.mem.iter_mut().for_each(|b| b.0.zeroize());
        #[cfg(test)]
        tests::released(&self.mem);
        uw::protect::off(self.mem.as_mut_ptr().cast(), self.mem.len() * BLOCK, self.locked, self.no_dump);
    }
}
/// A new secret of `len` zero bytes (`UAArgument` above 16 MiB); Dart's `SecretBytes.take` fills it.
#[frb(sync)]
pub fn secret_alloc(len: u32) -> R<SecretBytes> {
    SecretBytes::alloc(usize::try_from(len).map_err(|_| arg())?)
}
/// A secret output: a copy of `b` (its `Zeroizing` source in ua-rs wipes itself).
fn out(b: &[u8]) -> R<SecretBytes> {
    let mut s = SecretBytes::alloc(b.len())?;
    s.get_mut().copy_from_slice(b);
    Ok(s)
}

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
/// `kem_encaps`: `ss` is the shared secret.
#[frb(non_opaque)]
pub struct UaEncapsulated {
    pub mlkem_ct: Vec<u8>,
    pub x25519_eph: Vec<u8>,
    pub ss: SecretBytes,
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
        | on(b::VECTORS, 11)
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
fn network(name: &str) -> R<uw::Network> {
    uw::Network::from_name(name).ok_or_else(arg)
}
/// Exactly one unlock secret: the PRF secret first when both are given (clientkeys `dekFrom`); neither is `UAArgument`.
/// An optional secret: frb takes no `Option<&T>`, so the handle itself (shared, not consumed), read under its lock.
type Secret = RustAutoOpaque<SecretBytes>;
fn read(s: &Option<Secret>) -> Option<impl std::ops::Deref<Target = SecretBytes> + '_> {
    s.as_ref().map(|s| s.blocking_read())
}
fn unlock<'a>(vault_passphrase: Option<&'a SecretBytes>, prf32: Option<&'a SecretBytes>) -> R<uw::Unlock<'a>> {
    if let Some(p) = prf32 {
        return Ok(uw::Unlock::Prf(p.get().try_into().map_err(|_| arg())?));
    }
    Ok(uw::Unlock::VaultPassphrase(text(vault_passphrase.ok_or_else(arg)?.get())?))
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

// --- entry points: the Dart facade checks the load -----------------------------------------------------------------------

pub fn wallet_generate() -> R<(UaWallet, UaSeedBackup)> {
    let (w, b) = uw::Wallet::generate()?;
    Ok((UaWallet(w, Live::new()), UaSeedBackup(Mutex::new(b), Live::new())))
}
pub fn wallet_from_mnemonic(words: &SecretBytes, bip39_passphrase: &SecretBytes) -> R<UaWallet> {
    Ok(UaWallet(uw::Wallet::from_mnemonic(text(words.get())?, text(bip39_passphrase.get())?)?, Live::new()))
}
/// Exactly one of `vault_passphrase` / `prf32` (null = absent; both: the PRF secret, the passphrase not tried).
pub fn wallet_open_vault(
    vault_json: String, vault_passphrase: Option<Secret>, prf32: Option<Secret>, bip39_passphrase: &SecretBytes,
) -> R<UaWallet> {
    let (vp, prf, v) = (read(&vault_passphrase), read(&prf32), uw::Vault::from_json(vault_json.as_bytes())?);
    Ok(UaWallet(uw::Wallet::open_vault(&v, unlock(vp.as_deref(), prf.as_deref())?, text(bip39_passphrase.get())?)?, Live::new()))
}
pub fn wallet_unlock(
    w: &UaWallet, vault_json: String, vault_passphrase: Option<Secret>, prf32: Option<Secret>,
    bip39_passphrase: &SecretBytes,
) -> R<()> {
    let (vp, prf, v) = (read(&vault_passphrase), read(&prf32), uw::Vault::from_json(vault_json.as_bytes())?);
    Ok(w.0.unlock(&v, unlock(vp.as_deref(), prf.as_deref())?, text(bip39_passphrase.get())?)?)
}
pub fn wallet_seal_vault(w: &UaWallet, vault_passphrase: &SecretBytes) -> R<String> {
    Ok(w.0.seal_vault(text(vault_passphrase.get())?, None)?.to_json())
}
pub fn wallet_import_native_key(w: &UaWallet, network_name: String, secret_key: &SecretBytes) -> R<UaKey> {
    Ok(key(KeyInner::Native(w.0.import_native_key(network(&network_name)?, secret_key.get())?)))
}
pub fn wallet_seal_label_vault(w: &UaWallet, label: String, vault_passphrase: &SecretBytes) -> R<String> {
    Ok(w.0.seal_label_vault(&label, text(vault_passphrase.get())?, None)?.to_json())
}
pub fn wallet_open_label_vault(
    w: &UaWallet, vault_json: String, vault_passphrase: Option<Secret>, prf32: Option<Secret>,
) -> R<()> {
    let (vp, prf, v) = (read(&vault_passphrase), read(&prf32), uw::Vault::from_json(vault_json.as_bytes())?);
    Ok(w.0.open_label_vault(&v, unlock(vp.as_deref(), prf.as_deref())?)?)
}
#[allow(clippy::too_many_arguments)]
fn restore(
    kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>, accepted_json: Option<String>,
    current: Option<&UaWallet>, rollback: Option<uw::AllowRollback>, bip39_passphrase: &SecretBytes,
) -> R<Option<UaWallet>> {
    let (c, o) = (container(&container_json)?, Opening::read(&expect_json, members_json, accepted_json)?);
    let pass = text(bip39_passphrase.get())?;
    let w = o.with(|e, m, acc| uw::Wallet::restore_backup(&kk.0, &c, e, m, acc, current.map(|w| &w.0), rollback, pass))?;
    Ok(w.map(|w| UaWallet(w, Live::new())))
}
/// The wallet of a backup container (`None`: an equal generation installed nothing). `members_json` / `accepted_json` null = none.
pub fn wallet_restore_backup(
    kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>, accepted_json: Option<String>,
    bip39_passphrase: &SecretBytes,
) -> R<Option<UaWallet>> {
    restore(kk, container_json, expect_json, members_json, accepted_json, None, None, bip39_passphrase)
}
/// As `wallet_restore_backup` over the wallet `current` holds (an older generation: `UABackupRollback`).
pub fn wallet_restore_backup_over(
    current: &UaWallet, kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>,
    accepted_json: Option<String>, bip39_passphrase: &SecretBytes,
) -> R<Option<UaWallet>> {
    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), None, bip39_passphrase)
}
/// The rollback, by its own name.
pub fn wallet_restore_backup_rollback(
    current: &UaWallet, kk: &UaKemKey, container_json: String, expect_json: String, members_json: Option<String>,
    accepted_json: Option<String>, bip39_passphrase: &SecretBytes,
) -> R<Option<UaWallet>> {
    let allow = Some(uw::AllowRollback);
    restore(kk, container_json, expect_json, members_json, accepted_json, Some(current), allow, bip39_passphrase)
}
pub fn wallet_from_link(
    session: &UaLinkSession, container_json: String, expect_json: String, members_json: Option<String>,
    accepted_json: Option<String>, bip39_passphrase: &SecretBytes,
) -> R<UaWallet> {
    let (c, o) = (container(&container_json)?, Opening::read(&expect_json, members_json, accepted_json)?);
    let pass = text(bip39_passphrase.get())?;
    let taken = session.0.lock().map_err(|_| arg())?.take().ok_or_else(|| UAError { code: "UAKeyRevoked".into(), reason: String::new() })?;
    let w = o.with(|e, m, acc| uw::Wallet::from_link(taken, &c, e, m, acc, pass))?;
    Ok(UaWallet(w, Live::new()))
}
/// Whether `answers` are the words at the challenged positions, in order (the call consumes them).
pub fn seed_backup_verify(b: &UaSeedBackup, answers: Vec<SecretBytes>) -> R<bool> {
    let words = answers.iter().map(|a| text(a.get())).collect::<R<Vec<&str>>>()?;
    Ok(b.0.lock().map_err(|_| arg())?.verify(&words)?)
}
pub fn vault_needs_rewrap(vault_json: String) -> R<bool> {
    Ok(uw::Vault::from_json(vault_json.as_bytes())?.needs_rewrap())
}
pub fn vault_rewrap_pin(vault_json: String, old_passphrase: &SecretBytes, new_passphrase: &SecretBytes) -> R<String> {
    let (o, n) = (text(old_passphrase.get())?, text(new_passphrase.get())?);
    Ok(uw::Vault::from_json(vault_json.as_bytes())?.rewrap_pin(o, n)?.to_json())
}
pub fn vault_enable_prf(
    vault_json: String, vault_passphrase: &SecretBytes, prf32: &SecretBytes, credential_id: String, salt: Vec<u8>,
) -> R<String> {
    let output: &[u8; 32] = prf32.get().try_into().map_err(|_| arg())?;
    let env = uw::PrfEnvelope { output, credential_id: &credential_id, salt: &salt };
    Ok(uw::Vault::from_json(vault_json.as_bytes())?.enable_prf(text(vault_passphrase.get())?, &env)?.to_json())
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
    Ok(UaEncapsulated { mlkem_ct: ct, x25519_eph: e.to_vec(), ss: out(&*ss)? })
}
/// A seal to `kem_pk` (authenticates no sender).
pub fn seal(kem_pk: Vec<u8>, purpose: String, aad: Vec<u8>, pt: &SecretBytes) -> R<UaSealed> {
    let s = uw::seal(&kem_pk, &purpose, &aad, pt.get())?;
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
fn k32(k: &SecretBytes) -> R<&[u8; 32]> {
    k.get().try_into().map_err(|_| arg())
}
/// `alg` 1 = AES-256-GCM, 2 = AES-256-GCM-SIV; `pt` the plaintext.
pub fn aead_seal(alg_id: u32, key32: &SecretBytes, nonce12: Vec<u8>, aad: Vec<u8>, pt: &SecretBytes) -> R<Vec<u8>> {
    Ok(uw::aead_seal(alg(alg_id)?, k32(key32)?, &a(&nonce12)?, &aad, pt.get())?)
}
/// The plaintext of `data`.
pub fn aead_open(alg_id: u32, key32: &SecretBytes, nonce12: Vec<u8>, aad: Vec<u8>, data: Vec<u8>) -> R<SecretBytes> {
    out(&uw::aead_open(alg(alg_id)?, k32(key32)?, &a(&nonce12)?, &aad, &data)?)
}
/// The output keying material.
pub fn hkdf_sha256(ikm: &SecretBytes, salt: Vec<u8>, info: Vec<u8>, len: u32) -> R<SecretBytes> {
    out(&uw::hkdf_sha256(ikm.get(), &salt, &info, usize::try_from(len).map_err(|_| arg())?)?)
}
/// The MAC (not a secret).
pub fn hmac_sha256(key_bytes: &SecretBytes, data: Vec<u8>) -> Vec<u8> {
    uw::hmac_sha256(key_bytes.get(), &data).to_vec()
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
    /// The PQZ leaf `seed32`: the explicit export (spec §8.4).
    pub fn export_pqz_leaf_raw(&self, account: u32, index: u32) -> R<SecretBytes> {
        out(&*self.0.export_pqz_leaf_raw(account, index, fpqz::AllowSecretExport)?)
    }
}

impl UaSeedBackup {
    /// The words, once.
    pub fn reveal(&self) -> R<SecretBytes> {
        out(self.0.lock().map_err(|_| arg())?.reveal()?.as_bytes())
    }
    /// Three 1-based positions to ask.
    pub fn challenge(&self) -> R<Vec<u32>> {
        let p = self.0.lock().map_err(|_| arg())?.challenge()?;
        Ok(p.iter().map(|i| u32::try_from(*i).unwrap_or(u32::MAX)).collect())
    }
    /// The entropy, once confirmed; null before that and after the first call.
    pub fn take(&self) -> R<Option<SecretBytes>> {
        self.0.lock().map_err(|_| arg())?.take().map(|e| out(&e)).transpose()
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
    /// The shared secret.
    pub fn decaps(&self, mlkem_ct: Vec<u8>, x25519_eph: Vec<u8>) -> R<SecretBytes> {
        out(&*self.0.decaps(&mlkem_ct, &a(&x25519_eph)?)?)
    }
    /// The plaintext.
    pub fn open(&self, purpose: String, aad: Vec<u8>, sealed: UaSealed) -> R<SecretBytes> {
        let s = uw::Sealed { version: 1, scheme: 1, mlkem_ct: sealed.mlkem_ct, x25519_eph: a(&sealed.x25519_eph)?, ciphertext: sealed.ciphertext };
        out(&self.0.open(&purpose, &aad, &s)?)
    }
    /// A container's plaintext, accepted as `expect_json` says (spec §6.3); `members_json` / `accepted_json` null = none.
    pub fn open_container(
        &self, container_json: String, expect_json: String, members_json: Option<String>, accepted_json: Option<String>,
    ) -> R<SecretBytes> {
        let (c, o) = (container(&container_json)?, Opening::read(&expect_json, members_json, accepted_json)?);
        out(&o.with(|e, m, acc| self.0.open_container(&c, e, m, acc))?)
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
    pub fn seal_balance_cache(&self, entries_json: &SecretBytes) -> R<String> {
        Ok(self.0.seal_balance_cache(entries_json.get())?)
    }
    /// The cache's plaintext.
    pub fn open_balance_cache(&self, box_json: String) -> R<SecretBytes> {
        out(&self.0.open_balance_cache(box_json.as_bytes())?)
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
    pub fn seal_balance_cache(&self, entries: &SecretBytes) -> R<String> {
        Ok(self.0.seal_balance_cache(entries.get())?)
    }
    /// The cache's plaintext.
    pub fn open_balance_cache(&self, box_json: String) -> R<SecretBytes> {
        out(&self.0.open_balance_cache(box_json.as_bytes())?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    thread_local! {
        /// Buffers released on this thread, and those released with a non-zero byte (ua-rs's `vectors::released` pattern).
        static RELEASED: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    }
    pub(super) fn released(mem: &[Block]) {
        let nonzero = mem.iter().any(|b| b.0.iter().any(|x| *x != 0));
        RELEASED.with(|r| r.set((r.get().0 + 1, r.get().1 + usize::from(nonzero))));
    }

    #[test]
    fn secret_fixed_locked_and_zeroed_on_drop() {
        let mut s = secret_alloc(100).unwrap();
        let p = s.addr();
        assert_eq!((p % BLOCK, s.size(), s.mem.len()), (0, 100, 1));
        // Dart's in-place write
        // SAFETY: `p` is the first of `s`'s 100 bytes, `s` alive and not borrowed
        unsafe { std::ptr::write_bytes(p as *mut u8, 0xa5, 100) };
        assert_eq!(s.get(), &[0xa5; 100][..]);
        assert_eq!(s.addr(), p, "never moved");
        assert!(s.mem[0].0[100..].iter().all(|x| *x == 0), "the tail stays zero");
        assert_eq!(s.locked, cfg!(unix), "mlock (best effort; RLIMIT_MEMLOCK here is above 16 KiB)");
        let before = RELEASED.with(Cell::get);
        drop(s);
        assert_eq!(RELEASED.with(Cell::get), (before.0 + 1, before.1), "released once, every byte zero");
        // a positive control: the hook sees a non-zero block
        released(&[Block([1; BLOCK])]);
        assert_eq!(RELEASED.with(Cell::get), (before.0 + 2, before.1 + 1));
    }

    #[test]
    fn secret_sizes_and_outputs() {
        let e = secret_alloc(0).unwrap();
        assert_eq!((e.size(), e.mem.len(), e.get().len()), (0, 1, 0), "an empty secret: one block, nothing in it");
        let big = secret_alloc(u32::try_from(BLOCK).unwrap() + 1).unwrap();
        assert_eq!(big.mem.len(), 2);
        assert_eq!(secret_alloc(u32::try_from(SECRET_MAX + 1).unwrap()).err().map(|e| e.code), Some("UAArgument".into()));
        assert_eq!(out(b"words").unwrap().get(), b"words");
    }

    /// Every secret parameter of this file is a `SecretBytes`, every secret output too (the surface frb generates from).
    #[test]
    fn secrets_never_cross_the_codec() {
        let src = include_str!("wallet.rs");
        let src = &src[..src.find("#[cfg(test)]\nmod tests").unwrap()];
        for p in ["words", "bip39_passphrase", "vault_passphrase", "prf32", "secret_key", "answers", "old_passphrase",
                  "new_passphrase", "pt", "key32", "ikm", "key_bytes", "entries_json", "entries"] {
            let decl = format!("{p}: ");
            let at: Vec<usize> = src
                .match_indices(&decl)
                .map(|(i, _)| i)
                .filter(|i| !src[..*i].ends_with(|c: char| c.is_alphanumeric() || c == '_'))
                .collect();
            assert!(!at.is_empty(), "{p} not found");
            for i in at {
                let ty = &src[i + decl.len()..];
                assert!(["&SecretBytes", "Option<Secret>", "Vec<SecretBytes>", "Option<&'a SecretBytes>"].iter().any(|t| ty.starts_with(t)), "{p} crosses the codec");
            }
        }
        for f in ["fn decaps(", "fn open(", "fn open_container(", "fn aead_open(", "fn hkdf_sha256(", "fn export_pqz_leaf_raw(",
                  "fn reveal(", "fn take(", "fn open_balance_cache("] {
            for at in src.match_indices(f).map(|(i, _)| i) {
                let sig = &src[at..at + src[at..].find('{').unwrap()];
                assert!(sig.contains("SecretBytes>"), "{f} returns bytes through the codec");
            }
        }
        assert!(src.contains("pub ss: SecretBytes,"));
    }
}
