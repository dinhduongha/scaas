> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Mobile key storage for scaas-app: Android Keystore, iOS Keychain and Secure Enclave, passkeys, toolkits (2026-11-27)

Research of 2026-11-27 for the owner, who asked how scaas-app's mobile builds (Flutter, Qt, Dioxus, Tauri v2 on Android and
iOS) protect SCaaS secrets. This note starts from what SCaaS has already specified: the user-profiles spec
[2026-11-27-user-profiles.md](../superpowers/specs/2026-11-27-user-profiles.md) (§7.1 envelope, §7.4 per-item passphrases, §7.5 KDF,
§7.6 biometrics, §11 `ProfileKeychain`, §13 mobile notes, §14 threat model; rules [CLI-UPR-12](../clients/scaas-sdk.md#CLI-UPR-12),
[CLI-UPR-21](../clients/scaas-sdk.md#CLI-UPR-21), [CLI-UPR-23](../clients/scaas-sdk.md#CLI-UPR-23)), the seed unlock rule
[CLI-SDK-06](../clients/scaas-sdk.md#CLI-SDK-06) and its code (`clients/scaas-sdk/src/vault/prf.rs`, `src/platform.rs`
`Authenticator`, `KeyPolicy`), PqVault's rulings O7 (b) and O8 ([pqvault spec](../superpowers/specs/2026-11-17-pqvault.md) §14),
and scaas-app's spec §5 (`scaas-app:docs/superpowers/specs/2026-11-17-scaas-app-three-frontends.md`, a path in the scaas-app
repository). Nothing here is built, specified or ruled; every recommendation is a proposal for the owner. The profile layer and the
SDK's vault are **UNAUDITED** ([ARCH-POS-14](../decisions.md#ARCH-POS-14)). External claims carry a source tag; §8 lists the sources,
all read on 2026-11-27. Claims marked *(inference)* are this note's reasoning, not a source's.

## Summary

**Recommendation.** On both mobile OSes the hardware gates one 32-byte secret and nothing else: the platform secret behind
`K_plat`, which unwraps the profile's data key `DEK_p` (spec §7.1). Every PQ key, the Argon2id KDF, `DEK_p` and every item key run
in `ua-rs` in the app's memory, because no mobile secure hardware read for this note computes a PQ algorithm or Argon2id
([A2], [M1]). Concretely:

1. **One native adapter per OS, shared by all four toolkits** (one Kotlin file, one Swift file), implementing the SDK's
   `Authenticator::platform_secret` and `ProfileKeychain`. Android: an HMAC-SHA256 Android Keystore key, authorised per use by a
   Class 3 biometric only, invalidated by a new enrollment, StrongBox when present, through `BiometricPrompt` with a `Mac`
   `CryptoObject`. iOS: a 32-byte random Keychain item under `biometryCurrentSet` and `WhenPasscodeSetThisDeviceOnly`, never
   synchronizable; the output is HMAC-SHA256 of it over the salt. Do not use a plugin that only returns success or failure
   (`local_auth`, Tauri's `authenticate`, `robius-authentication`) for `K_plat`, and do not use Tauri Stronghold for SCaaS secrets.
2. **Keep the profile root out of cloud backup and device transfer**: Android `getNoBackupFilesDir()`, iOS a directory marked
   `isExcludedFromBackup` with Complete file protection. The profile export (CLI-UPR-17) stays the one portable path.
3. **The SDK and the user-profiles spec should add**: a pinned adapter contract per OS with a conformance test; a distinct
   "invalidated" answer from the adapter, after which the SDK drops the dead platform wrap; a security-level report at enable that
   refuses a software-only key; no key-attestation policy (an HMAC key cannot be attested, and Google advises against verifying on
   the device itself); the mobile screen, snapshot and clipboard rules of §3.4 in the per-client notes (CLI-UPR-16).
4. **Passkeys stay a seed unlock, not a profile unlock.** A synced passkey puts its PRF secret in the user's Google or Apple
   account; the profile seal in front of the seed keeps that from being enough on its own.

## 1. Android

### 1.1 Android Keystore and StrongBox

- **Key material stays out of the app.** "Key material never enters the application process"; an attacker who compromises the
  app "might be able to use the app's keys but can't extract their key material", and with secure hardware (TEE or a secure
  element) "its key material is never exposed outside of secure hardware" even when the OS is compromised [M1]. The app checks
  where a key lives through `KeyInfo.getSecurityLevel()` (`TRUSTED_ENVIRONMENT`, `STRONGBOX`) and whether user authentication is
  enforced by the hardware through `KeyInfo.isUserAuthenticationRequirementEnforcedBySecureHardware()` [M1].
- **StrongBox** (Android 9, API 28, and later; optional per device): a KeyMint in an embedded secure element with its own CPU,
  storage, TRNG and secure timer; it supports only RSA 2048, AES 128 and 256, ECDSA and ECDH P-256, **HMAC-SHA256** (keys of 8 to
  64 bytes), Triple DES. Asked with `setIsStrongBoxBacked(true)`; an unsupported algorithm throws
  `StrongBoxUnavailableException`, and the app retries without StrongBox. Google warns it is slower and supports fewer concurrent
  operations [M1]. One HMAC per profile open is well inside that *(inference)*.
- **No PQ algorithm and no memory-hard KDF** in the Keystore algorithm list or the StrongBox list [M1].

### 1.2 Keys bound to user authentication

- `setUserAuthenticationRequired(true)` (API 23) makes the key usable only after the user authenticated;
  `setUserAuthenticationParameters(timeout, type)` (API 30) sets the window: **`0` means "user authentication must take place for
  every use of the key"**, which is also the default; `type` is `AUTH_BIOMETRIC_STRONG`, `AUTH_DEVICE_CREDENTIAL` or both [M2].
- **Per use needs a `CryptoObject`.** An operation-bound key is authorised through `BiometricPrompt.authenticate()` with a
  `CryptoObject` wrapping a `Signature`, `Cipher`, `Mac` or `KeyAgreement`; a key that also accepts the screen-lock credential
  is time-bound and cannot pass a `CryptoObject` [M3]. The `KeyAgreement` form is new: an API diff and the AndroidX annotation
  place it at Android 16 (API 36) [M9]. **`Mac` is the portable form**, so the SDK's existing contract, "HMAC of a Keychain or
  Android Keystore key" (CLI-SDK-06), fits Android as written.
- **Biometric classes.** `BIOMETRIC_STRONG` is Class 3, `BIOMETRIC_WEAK` Class 2 [M3]. "Only Class 3 (BIOMETRIC_STRONG) supports
  both time-based and operation-based Keystore keys. Class 2 and Class 1 support neither" [M4]. A Class 2 face unlock can only
  feed a boolean gate, which an attacker who controls the app process bypasses *(inference)*.
- **Invalidation.** A key that requires authentication "will become irreversibly invalidated once the secure lock screen is
  disabled ... or forcibly reset"; a per-use key is also invalidated "once a new biometric is enrolled or once no more biometrics
  are enrolled, unless `setInvalidatedByBiometricEnrollment(false)` ... or `AUTH_DEVICE_CREDENTIAL` is specified"; later use
  throws `KeyPermanentlyInvalidatedException` [M2]. The default of `setInvalidatedByBiometricEnrollment` is `true` [M2].
  **So the SDK's `KeyPolicy { biometry_current_set, invalidated_by_enrollment }` maps on Android to: `AUTH_BIOMETRIC_STRONG`
  alone (adding `AUTH_DEVICE_CREDENTIAL` would silently switch off enrollment invalidation), timeout `0`, and
  `setInvalidatedByBiometricEnrollment(true)`** *(inference from [M2])*.
- `setUnlockedDeviceRequired(true)` (API 28) is a separate bound; Google reports bugs in Android 12 to 14 and advises using it only
  on Android 15 and later [M2]. A per-use biometric key needs no extra unlocked-device bound *(inference)*.

### 1.3 Key attestation

Attestation proves, through a certificate chain to a Google root, that a key is in TEE or StrongBox and carries the stated
authorisations [M5]. Three limits matter for SCaaS:

- **Only asymmetric keys have certificates.** "Symmetric keys, such as AES and HMAC keys, do not have public key certificates";
  asking for an attestation challenge on one throws [M2]. The HMAC key behind `K_plat` cannot be attested.
- **Verification belongs off the device.** Google: "Don't complete the following validation process on the same device. If the
  Android system on that device is compromised, that could cause the validation process to trust something that is untrustworthy"
  [M5]. SCaaS has no server for profiles (the node is open and knows nothing of them, spec §2).
- A device without a Google root may carry a software attestation signed by a key "hardcoded in Android source code" [M5].

*(inference)* An attestation policy for platform unlock would cost a companion EC key per profile, a revocation-list fetch and an
on-device check Google advises against, to prove something about a different key. The adapter's self-report of the security
level (§1.1) is weaker but free; §6 proposes using it.

### 1.4 Backup, device transfer, restore

- **Auto Backup includes the app's files by default**: `getFilesDir()`, `getDir()`, databases, shared preferences,
  `getExternalFilesDir()`; it excludes `getCacheDir()`, `getCodeCacheDir()` and `getNoBackupFilesDir()`, which are "always excluded
  even if you try to include them" [M6]. Backups go to the user's Google Drive, end-to-end encrypted with the device's screen-lock
  credential on Android 9 and later [M6].
- **`allowBackup="false"` is not enough**: for apps targeting API 31 and later, "on devices from some device manufacturers" it
  "disables cloud-based backup ... but doesn't disable device-to-device transfers" [M6]. `dataExtractionRules` has separate
  `<cloud-backup>` and `<device-transfer>` sections, and since Android 16 QPR2 a `<cross-platform-transfer platform="ios">`
  section; a mode without rules is fully enabled except the no-backup and cache directories [M6].
- **Keystore keys never travel**: they are non-exportable [M1]. A restored or transferred profile directory therefore carries a
  `platform` wrap whose key does not exist on the new device; the passphrase still opens (spec §7.6) *(inference)*.
- `flutter_secure_storage` documents the consequence: after a restore its data fails with
  `InvalidKeyException: Failed to unwrap key`, and it advises disabling Auto Backup or excluding its preferences [T1].
- **scaas-app today** (read in the scaas-app repository at `31660a570c`): the Qt fork's manifest keeps `allowBackup="true"` and
  excludes only its two keychain preference files from cloud backup and device transfer. A profile root under `getFilesDir()`
  would go to Google Drive and to a new phone *(inference)*.

## 2. iOS

### 2.1 Keychain classes and access control

- **Accessibility classes** [A1]: `WhenUnlocked`; `AfterFirstUnlock` (for background refresh);
  `WhenPasscodeSetThisDeviceOnly`, "available only when the device is configured with a passcode", never synced to iCloud
  Keychain, not backed up, not in escrow keybags. If the passcode is removed, "the system discards the class keys for
  WhenPasscodeSet items". `ThisDeviceOnly` items in a backup are wrapped with the device's UID key, so they cannot be used on
  another device [A1]; such an item "isn't eligible for the iCloud keychain and won't be included if the user restores a device
  backup to a new device" [A4].
- **Access control lists** require Face ID, Touch ID, Optic ID or the passcode, "can also be invalidated when biometric enrollment
  changes", and "the Secure Enclave evaluates these ACLs and releases access to the kernel only when the constraints are met" [A1];
  "No user space or operating system software ever has access to the underlying authentication data" [A4].
- **`biometryCurrentSet`** (iOS 11.3): "The item is invalidated if fingers are added or removed for Touch ID, or if the user
  re-enrolls for Face ID" [A3]. Apple's own sample uses `.userPresence`, which falls back to the passcode [A4]; the SDK's
  policy (spec §7.6: "no passcode fallback") needs `.biometryCurrentSet` without `.devicePasscode` *(inference)*.
- *(inference)* An `LAContext.evaluatePolicy` result alone is a boolean in the app's process; only a Keychain ACL or a Secure
  Enclave key makes the Secure Enclave the gate. The scaas-app Qt fork already stores its biometric item with
  `kSecAccessControlBiometryCurrentSet` and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (read at `31660a570c`).

### 2.2 The Secure Enclave

- "Works only with NIST P-256 elliptic curve keys", usable "for creating and verifying cryptographic signatures, or for elliptic
  curve Diffie-Hellman key exchange"; keys are made inside it, never imported or exported; "only the Secure Enclave that created
  the key can make use of the key" [A2]. CryptoKit offers `SecureEnclave.P256.KeyAgreement` (ECDH in the enclave, iOS 13) [A5].
- **It cannot hold or compute any SCaaS PQ key (ML-DSA, Falcon, SLH-DSA, ML-KEM) or Argon2id**, and offers no HMAC [A2]. The
  SDK's `create_se_key` (`p256`, 0x0101) remains the one hardware-signing path, classical.
- *(inference)* For `platform_secret` the enclave adds nothing over an ACL-protected Keychain item: an ECDH against a fixed peer
  gives a constant secret, exposed to the app's memory at each unlock exactly as the item's bytes are; both are released only after
  the enclave checks the biometric. The Keychain item is simpler and is what the Qt fork already does.

### 2.3 Files, backup, sync

- **File data protection** [A6]: Class A Complete (`NSFileProtectionComplete`; the class key is discarded about 10 seconds after lock
  with "Require Password: Immediately"), Class B Protected Unless Open, Class C Protected Until First User Authentication — "the
  default class for all third-party app data" — and Class D None.
- **Backup**: iCloud Backup excludes `tmp` and `Library/Caches`; other non-purgeable data is excluded by setting
  `isExcludedFromBackup` on a file or directory, set again after each save, and Apple warns it is "not a mechanism to guarantee
  those items never appear in a backup or on a restored device" [A8].
- **iCloud Keychain sync**: `WhenPasscodeSetThisDeviceOnly` and every `ThisDeviceOnly` item never sync [A1], [A4].

## 3. Consequences for SCaaS

### 3.1 What hardware does and does not do

*(inference throughout, from §1, §2 and the spec)* Neither Android's Keystore nor iOS's Secure Enclave can sign with a SCaaS PQ key,
decapsulate ML-KEM, or run Argon2id. Hardware therefore only **gates `K_plat`**: one HMAC (Android) or one ACL-released item
(iOS) per profile open, whose output goes through HKDF to `K_plat` and unwraps `DEK_p` (spec §7.1). The same pattern serves a seed's
platform unlock (`scaas.unlock.<seed>`, CLI-SDK-06) and PqVault's device-keystore-wrapped `P_k` (O7 (b)): three handles, one
adapter. The KDF is O8's and CLI-UPR-21's 64 MiB / 3 / 4, mobile bound 256 MiB, no timing run; this note measures nothing.

### 3.2 What an attacker gets

| Adversary | Gets | Bound |
|---|---|---|
| thief with a locked phone, no exploit | nothing readable: the app sandbox and file protection; the platform key needs a Class 3 biometric or the enclave's check | [M1], [M4], [A1], [A6] |
| a rooted or jailbroken device, profile locked | the profile root's files: the stolen-disk row of spec §14 (envelope, sealed items, names, sizes); one Argon2id per guess; the platform key **cannot be extracted** and **cannot be used without a fresh biometric** while the TEE, StrongBox or enclave holds | [M1], [M2], [A1]; a TEE or enclave exploit is out of scope |
| root or jailbreak **while the user opens the profile** | everything the process holds: `DEK_p` and the item keys until lock; the platform secret during the call (static, so reusable with a copy of the envelope); a seed's kept PRF key while that seed is open (CLI-SDK-06) | none on the device; seeds and imported keys not opened in that session stay behind their own passphrases (§7.4, O11) |
| holder of a cloud backup or device transfer, root **not** excluded | the stolen-disk row plus an older copy for a rollback; the `platform` wrap is dead (the key does not travel); a Google backup also needs the old device's screen-lock credential | [M1], [M6], [A1]; with §4's exclusion: nothing |
| someone with the phone **unlocked and the profile open** | spec §7.4's list (settings, public keystore fields, history, PqChat and Matrix stores, PqVault cache); no export and no weakening setting without the typed passphrase (§7.7); seeds only if open | the seeds' auto-lock on background (spec §13); the profile itself stays open by Q-UP6 (ruled), a stated residual |
| someone who enrolls their own finger or face | the platform key and the Keychain item are invalidated; the passphrase is needed | [M2], [A3] |
| a coerced biometric | opens the profile (O11's accepted risk), not a seed or key behind its own passphrase | spec §7.4, §14.1 |
| a Google or Apple account takeover, with a synced passkey | the passkey's PRF secret (§5); it opens a seed's PRF envelope only together with that seed's files, which sit inside the profile seal and outside backup | §4, §5 |
| a malicious app or an overlay reading the screen or clipboard | what the app shows or copies, unless §3.4's rules apply | [M7], [M8], [A7], [A9], [A10] |
| a buggy or boolean-only adapter (software key, no `CryptoObject`, passcode fallback) | platform unlock no stronger than the file next to it; the SDK cannot see it | §6 (contract, conformance test, security-level report) |

### 3.3 Memory hygiene

*(inference)* The Rust side is specified: every key and plaintext in `Zeroizing` buffers or the arena, locked pages where available
(spec §7.1, §7.3). The weak point on mobile is above Rust: a passphrase typed into a Dart `String`, a Qt `QString` or a WebView's JS
string (Dioxus and Tauri render in the system WebView [T9]) lives on a managed heap until collected and cannot be zeroed. The SDK's
copy calls already zero the buffer they read (review T26 C-5, decisions.md); the remaining rule is for the UI: read the field once
into `SecretBytes`, clear the field and its controller, and never put a secret into a view-model string, a log or a route
argument. A backgrounded app keeps its memory; Android may kill it, iOS may suspend it.

### 3.4 Screens, snapshots, clipboard

- **Android**: `FLAG_SECURE` makes screenshots blank and keeps the window off non-secure displays; it also covers background
  screenshots [M8]. Google notes it is not reliable against overlays and recommends the `HIDE_OVERLAY_WINDOWS` permission (Android
  12) against them [M8]. Proposal: `FLAG_SECURE` on every screen that shows words, a key, a PqVault item or a passphrase field, and
  `HIDE_OVERLAY_WINDOWS` app-wide.
- **iOS**: the system snapshots the window "immediately after your app moves to the background"; Apple's advice is to cover
  sensitive views before the snapshot, without animation, and scene-based apps do it in the scene delegate [A9]. `isCaptured`
  reports recording, mirroring and AirPlay, and is deprecated in iOS 27 for `UITraitCollection.sceneCaptureState` [A10]. No API
  read for this note blocks a screenshot on iOS. Proposal: a cover view at resign-active on every screen, and the secret screens
  hidden while the scene is captured.
- **Clipboard**: Android 13 previews every copy; a copy flagged `ClipDescription.EXTRA_IS_SENSITIVE` is not previewed, and Google
  says every app copying a password must set it [M7]. iOS offers an `expirationDate` for pasteboard items and `localOnly` to keep
  them off other devices through Handoff [A7]. Proposal: within the profile's clipboard opt-in (spec §7.7), every secret copy
  flagged sensitive on Android and cleared by the app after a short timer; on iOS `localOnly` plus `expirationDate`.

## 4. Backup and device change

*(inference)* Recommendation: **the profile root is never in a cloud backup or device transfer.** Android: put it under
`getNoBackupFilesDir()`, the one place that is excluded in every mode without per-file rules [M6], and add an explicit exclusion in
the `<cross-platform-transfer>` section, for which no statement on the no-backup directory was found [M6]. iOS: put it under
Application Support, set `isExcludedFromBackup` on the root directory at every start (Apple calls it guidance [A8]), and create it
with Complete protection (Class A [A6]); background writes while locked are then impossible, which a later push-driven chat sync must
take into account. Keychain items: `ThisDeviceOnly`, never synchronizable.

Why: a backup copy is the stolen-disk row plus rollback material (§3.2), the `platform` wrap cannot survive the move anyway, and
PqChat's store is a device-bound cache recovered from chain state (CLI-PQC-09). The cost is that a new phone starts without
profiles; the user imports the profile export (CLI-UPR-17) or restores seeds from their sealed backup or words. This is the owner's
trade-off; the alternative (back up the sealed root, keyed by the profile passphrase) is safe against everyone without the
passphrase and costs only the offline-guessing exposure of §3.2.

## 5. Passkeys and the PRF extension

- **Mechanism.** WebAuthn L3's `prf` extension evaluates CTAP2 `hmac-secret` and returns 32 bytes per salt (as recorded in
  [sdk-keys-and-derivation.md](sdk-keys-and-derivation.md) §5.2 and §8); a credential is "backup eligible" (BE), a "multi-device
  credential", when it may be synced, and BS gives its current backup state [W1].
- **Availability.** iOS 18, iPadOS 18, macOS 15 (`ASAuthorizationPublicKeyCredentialPRFAssertionInput`, with per-credential
  inputs keyed by credential id) [A7b]; an Apple engineer confirmed a bug where platform and hybrid PRF outputs differed for one
  credential, fixed in iOS 18.4 and macOS 15.4 betas [A7b]. Android: Credential Manager on Android 9 and later; passkeys in Google
  Password Manager are "synchronized and end-to-end encrypted"; other providers from Android 14 [M10]; Google Password Manager
  passkeys have supported PRF since 2023 by a WebAuthn-list post, and some Android 14 providers may not [M12] (no current Google
  document confirming it was found). Native apps must be associated with the RP ID's domain: Digital Asset Links on Android [M11],
  the `apple-app-site-association` `webcredentials` entry on iOS [A11]. The RP ID is the deployment's
  ([CLI-APP-14](../clients/app.md#CLI-APP-14)).
- **Sync means the cloud holds the secret.** *(inference)* A synced passkey's PRF output is reproducible by anyone who recovers the
  provider account; a device-bound credential (BE = 0) or a security key over NFC or USB is not. The SDK's PRF envelope
  (`prf.rs`: one credential and one per-seed salt open every vault of the seed; an all-zero output is `AuthenticatorRefused`)
  maps onto `Authenticator::get_assertion` with `prf_salt` unchanged on mobile.
- **Profiles have no passkey unlock** (`ProfileUnlock` is `Passphrase` or `Platform`, spec §11), and this note recommends keeping
  it so: the profile seal is what keeps a synced passkey alone from opening a seed. Proposal: show BE and BS at a seed's passkey
  enable, saying "this passkey is synced to your account" when BE is set.

## 6. Toolkits and the recommendation per platform

### 6.1 What each toolkit offers (2026-11-27)

| Toolkit | Item storage | Biometric | Fit for `K_plat` |
|---|---|---|---|
| Flutter | `flutter_secure_storage` 11.2.0: Android AES-GCM under a Keystore key, Jetpack `EncryptedSharedPreferences` "no longer recommended", an `AndroidOptions.biometric()` mode (strong-only from API 30); iOS accessibility `unlocked` (default), `first_unlock`, `first_unlock_this_device`; no `biometryCurrentSet` or passcode class documented [T1] | `local_auth` 3.0.2: `authenticate()` shown returning a `bool`, passcode fallback unless `biometricOnly` [T2]; `biometric_storage` 5.0.1, last release two years ago, parameters not documented [T3] | no plugin matches the contract; a small platform-channel adapter |
| Qt | QtKeychain (Qt 6 from 0.12): Android Keystore, iOS Keychain unlocked-only by default; no biometric or ACL documented [T8]; the scaas-app fork's own `Keychain` (Android AES-GCM key, `setUserAuthenticationRequired`, `setInvalidatedByBiometricEnrollment(true)`, `BIOMETRIC_STRONG`, `CryptoObject(Cipher)`, `KeyPermanentlyInvalidatedException` handled; iOS `biometryCurrentSet`), read at `31660a570c` | the fork's `Keychain` | closest existing code: crypto-bound on both OSes; it stores a value rather than computing an HMAC, so it needs the adapter's HMAC step |
| Dioxus 0.7 | renders in the platform WebView [T9]; `keyring-rs` is now `keyring-core` plus store crates, with `apple-native-keyring-store` (a `protected` module) and `android-native-keyring-store` [T7]; no biometric access control documented | `robius-authentication`: a prompt returning success or failure; repository archived 2025-07-07 [T6] | no; the native adapter through JNI and Swift glue |
| Tauri v2 | Stronghold: its own vault file with a caller-supplied password hash (argon2 option) [T5]; community `tauri-plugin-keyring-store`, `tauri-plugin-biometry` [T7], [T10] (unreviewed) | `biometric` 2.5.0 (2026-10-14): `authenticate()` returns success or failure; new `biometricCipher` "on Android with a key protected by strong biometric authentication", none on iOS [T4] | no; the native adapter as a Tauri mobile plugin (Kotlin and Swift) |

*(inference)* Stronghold would put a second vault engine and KDF outside `ua-rs`, against CLI-SDK-01 and CLI-SDK-02 (every KDF, AEAD
and MAC in `ua-rs`). scaas-app's §5 table names `robius-authentication` and `local_auth`; both are boolean gates, and the first is
archived.

### 6.2 Recommendation

| | Android | iOS |
|---|---|---|
| `platform_secret` | HMAC-SHA256 Keystore key per handle; `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`; `setInvalidatedByBiometricEnrollment(true)`; StrongBox first, TEE on `StrongBoxUnavailableException`; software refused; `BiometricPrompt` `BIOMETRIC_STRONG` with `CryptoObject(Mac)`, a negative button "Use passphrase" | 32 random bytes as a Keychain item per handle; `SecAccessControl` `.biometryCurrentSet`; `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`; not synchronizable; output HMAC-SHA256(item, salt) in the adapter, item bytes zeroed after |
| `ProfileKeychain` (anchors, marker, at most 2,560 B) | a small file under `getNoBackupFilesDir()` sealed under a Keystore AES-GCM key without user authentication | Keychain items, `WhenUnlockedThisDeviceOnly` (or `AfterFirstUnlockThisDeviceOnly` if background writes are later needed), not synchronizable |
| profile root | `getNoBackupFilesDir()` | Application Support, `isExcludedFromBackup`, Complete protection |
| screens | `FLAG_SECURE` on secret screens; `HIDE_OVERLAY_WINDOWS` | cover view at resign-active; secret screens hidden while captured |
| clipboard | `EXTRA_IS_SENSITIVE`; cleared by the app on a timer | `localOnly`; `expirationDate` |

Per toolkit: **all four call the same two native files** (Kotlin, Swift): Flutter through a platform channel behind its Dart
`Authenticator`; Qt through JNI and Objective-C++ (adapting the fork's `Keychain`, MPL per file); Dioxus through JNI and a Swift
bridge; Tauri as a mobile plugin. *(inference)* One adapter keeps the four builds from differing in the one place the SDK cannot
check (§3.2, last row).

*(inference)* On Android, `ProfileKeychain` protects the anchor against a restored backup or a copy put back by anyone without root,
not against root, who writes the app's files and the sealed item alike; spec §14's rollback row should say so for Android, as it
already does where the anchor is a file.

## 7. What the SDK and the user-profiles spec would add (proposals)

1. **An adapter contract per OS** in the SDK spec (§6.10) and CLI-UPR-12: §6.2's parameters, one table, with a conformance test on
   an emulator and a simulator (enroll a second finger: the next unlock must fail as "invalidated"; device credential only: must
   fail; a key below TEE: enable must fail).
2. **`AuthError::Invalidated`** beside `Refused`, `Cancelled`, `Unavailable`, `Unexpected` (`platform.rs`): the key is gone
   (`KeyPermanentlyInvalidatedException`, an item missing after an enrollment change or a passcode removal, a handle that does
   not exist on this device). After the next passphrase open the SDK drops the `platform` wrap and the key, and the client says
   why; it never re-prompts in a loop. The spec already says "an enrollment change invalidates the key; the passphrase remains"
   (§7.6) without naming this path.
3. **A security-level report** at `enable_platform_unlock`: the adapter returns `strongbox`, `tee` or `software` (Android
   `KeyInfo`), the SDK refuses `software` and records the level for the settings screen. *(inference)* This is not a kind
   disabled under [ARCH-POS-18](../decisions.md#ARCH-POS-18): the passphrase path always remains.
4. **No attestation policy** for `K_plat` (§1.3), stated with its reason.
5. **One `platform` wrap per profile and device is already enough** (the directory is per device and, with §4, never copied by
   the OS); the spec only needs item 2's clean-up for a copy made by hand.
6. **Backup placement** (§4) in CLI-UPR-16's mobile note, with the owner's choice on the trade-off.
7. **Mobile hygiene** (§3.3, §3.4) in CLI-UPR-16.
8. **scaas-app §5 table**: replace `robius-authentication` and `local_auth` as the "KEK behind a biometric gate" with the shared
   adapter.

## 8. Sources (all read 2026-11-27)

Android:

- [M1] Android Keystore system: <https://developer.android.com/privacy-and-security/keystore>
- [M2] `KeyGenParameterSpec.Builder` reference: <https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder>
- [M3] Show a biometric authentication dialog: <https://developer.android.com/identity/sign-in/biometric-auth>
- [M4] AOSP, Biometrics: <https://source.android.com/docs/security/features/biometric>
- [M5] Verify hardware-backed key pairs with key attestation: <https://developer.android.com/privacy-and-security/security-key-attestation>
- [M6] Back up user data with Auto Backup: <https://developer.android.com/identity/data/autobackup>
- [M7] Copy and paste: <https://developer.android.com/develop/ui/views/touch-and-input/copy-paste>
- [M8] Protect sensitive activities (`FLAG_SECURE`, `HIDE_OVERLAY_WINDOWS`): <https://developer.android.com/security/fraud-prevention/activities>
- [M9] `CryptoObject(KeyAgreement)` at API 36, from search results only (not opened): <https://developer.android.com/sdk/api_diff/b-1-beta1/changes/android.hardware.biometrics.BiometricPrompt.CryptoObject>, <https://developer.android.com/reference/kotlin/androidx/biometric/BiometricPrompt.CryptoObject>
- [M10] Passkey support on Android and Chrome: <https://developers.google.com/identity/passkeys/supported-environments>
- [M11] Create a passkey (prerequisite: Digital Asset Links): <https://developer.android.com/identity/passkeys/create-passkeys>
- [M12] Google Password Manager and PRF, from search results only (not opened): <https://lists.w3.org/Archives/Public/public-webauthn/2023Oct/0126.html>, <https://groups.google.com/a/chromium.org/g/blink-dev/c/iTNOgLwD2bI>

Apple:

- [A1] Apple Platform Security, Keychain data protection: <https://support.apple.com/guide/security/keychain-data-protection-secb0694df1a/web>
- [A2] Protecting keys with the Secure Enclave: <https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave>
- [A3] `biometryCurrentSet`: <https://developer.apple.com/documentation/security/secaccesscontrolcreateflags/biometrycurrentset>
- [A4] Accessing Keychain items with Face ID or Touch ID: <https://developer.apple.com/documentation/localauthentication/accessing-keychain-items-with-face-id-or-touch-id>
- [A5] `SecureEnclave.P256.KeyAgreement`: <https://developer.apple.com/documentation/cryptokit/secureenclave/p256/keyagreement>
- [A6] Apple Platform Security, Data Protection classes: <https://support.apple.com/guide/security/data-protection-classes-secb010e978a/web>
- [A7] `UIPasteboard.OptionsKey.expirationDate` (and `localOnly`): <https://developer.apple.com/documentation/uikit/uipasteboard/optionskey/expirationdate>
- [A7b] PRF assertion input and the PRF output bug, from search results only (not opened): <https://developer.apple.com/documentation/authenticationservices/asauthorizationpublickeycredentialprfassertioninput-swift.struct>, <https://developer.apple.com/forums/thread/764730>
- [A8] Optimizing your app's data for iCloud Backup: <https://developer.apple.com/documentation/foundation/optimizing-your-app-s-data-for-icloud-backup>
- [A9] Technical Q&A QA1838, sensitive information in the task switcher (2014, archived): <https://developer.apple.com/library/archive/qa/qa1838/_index.html>
- [A10] `UIScreen.isCaptured`: <https://developer.apple.com/documentation/uikit/uiscreen/iscaptured>
- [A11] Supporting associated domains: <https://developer.apple.com/documentation/xcode/supporting-associated-domains>

Specifications and toolkits:

- [W1] W3C Web Authentication Level 3 (BE, BS; the `prf` extension §10.1.4): <https://www.w3.org/TR/webauthn-3/>
- [T1] `flutter_secure_storage`: <https://pub.dev/packages/flutter_secure_storage>
- [T2] `local_auth`: <https://pub.dev/packages/local_auth>
- [T3] `biometric_storage`: <https://pub.dev/packages/biometric_storage>
- [T4] Tauri biometric plugin and changelog: <https://v2.tauri.app/plugin/biometric/>, <https://v2.tauri.app/release/biometric/all-versions/>
- [T5] Tauri Stronghold plugin: <https://v2.tauri.app/plugin/stronghold/>
- [T6] `robius-authentication`: <https://github.com/project-robius/robius-authentication>
- [T7] `keyring-rs` and its store crates (the store crates from search results only): <https://github.com/open-source-cooperative/keyring-rs>, <https://docs.rs/apple-native-keyring-store>, <https://docs.rs/android-native-keyring-store>, <https://docs.rs/crate/tauri-plugin-keyring-store/latest/source/Cargo.toml>
- [T8] QtKeychain: <https://github.com/frankosterfeld/qtkeychain>
- [T9] Dioxus 0.7, mobile: <https://dioxuslabs.com/learn/0.7/guides/platforms/mobile/>
- [T10] `tauri-plugin-biometry`, from search results only (not opened): <https://docs.rs/crate/tauri-plugin-biometry/latest>

Local reads: the scaas-app repository at `31660a570c` (`scaas-qt-wallet-client/mobile/android/qt6/AndroidManifest.xml` and its
`res/xml` rules, `SecureAndroidAuthentication.java`, `ui/StatusQ/src/keychain_apple.mm`); no code copied.
