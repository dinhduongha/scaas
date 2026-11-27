# User profiles: many protected local profiles in the SDK layer: design

**Status:** SPECIFIED, nothing built. A **frame**: the owner's rulings of 2026-11-27 (§1) are fixed; the means are controller
calls (`owner: no`) and the points the owner has not ruled are in §16. Branch `user-profiles-spec` (from `dev` `644ea61a8`),
worktree `.claude/worktrees/user-profiles-spec`. Rule ids introduced here (SPECIFIED, defined once in
[clients/scaas-sdk.md](../../clients/scaas-sdk.md) §12, recorded in [decisions.md](../../decisions.md) §41): CLI-UPR-01 to
CLI-UPR-16. No contract, signed byte format, vector, chain profile or node rule changes; no on-chain byte changes. The
cryptographic calls asked of `ua-rs` (§7) are new and need vectors before code. UNAUDITED.

**Reads** (as at `644ea61a8`): the SDK's vault and store code (`clients/scaas-sdk/src/vault/`: `store.rs` `SecureStore`,
`FileStore`, `MemoryStore`; `mod.rs` `KeystoreFile`; `seeds.rs`; `unlock.rs`; `roots.rs`), `Sdk::open` and `SdkConfig`
(`src/lib.rs`, `src/config.rs`), the CLI's data directory and chain-profile loading (`clients/scaas-cli/src/config.rs`); the SDK
spec §6 and rules CLI-SDK-02 to CLI-SDK-06, CLI-SDK-15, CLI-SDK-17; the TUI spec §10 and CLI-TUI-04, CLI-TUI-06, CLI-TUI-11;
hidden sets (SDK spec §6.5, CLI-UAL-18); PqVault's passphrase KDF (CLI-PQV-07, CLI-PQV-10 and its Change: O8, Argon2id 64 MiB / 3
passes / parallelism 4) and biometrics (pqvault spec §14 O7 (b), CLI-PQV-15 (3)); PqChat's recovery from state (CLI-PQC-09);
ARCH-POS-13 (no decryption oracle), ARCH-POS-15 (RPC lists). Order of sources: AGENTS.md "Which source wins".

## 1. Owner rulings this spec follows

| # | Date | Ruling | Rule |
|---|---|---|---|
| O1 | 2026-11-27 | The feature is named **"Profile"** in user-facing text and `UserProfile` / `user_profile` in code and docs. The existing per-chain "profile" (EVM and network profiles, the default profile, the TUI's pinned profiles, its caps) is called **"chain profile"** (`ChainProfile`) in docs and code; that rename touches no on-chain byte and is a later task, listed here, not done now. | CLI-UPR-01 |
| O2 | 2026-11-27 | User profiles live in the SDK layer and are used by every client: scaas-app desktop and mobile, `scaas-tui`, the CLI `scaas`. | CLI-UPR-02 |
| O3 | 2026-11-27 | A machine holds many profiles. Each profile is its own data directory: its encrypted store (many seeds, many native secret keys, hidden sets), its chat and vault state, its own settings including its chain-profile settings. | CLI-UPR-03 |
| O4 | 2026-11-27 | Each profile is protected separately: its own passphrase and KDF parameters, optional biometric unlock (the O7 (b) pattern of PqVault: opt-in). Opening one profile unlocks nothing of another. | CLI-UPR-04 |
| O5 | 2026-11-27 | On first run with no profile the client creates one named "default"; it asks for a passphrase when the profile's first secret (seed or key) is created. | CLI-UPR-05 |
| O6 | 2026-11-27 | A profile is open in at most one instance at a time (a lock file in its directory; a second instance opening it is refused by a named error). Instances with different profiles work together only over the normal network paths (PqChat, Matrix, the node), with no local side channel, so two-person chat can be tested on one machine. | CLI-UPR-06 |
| O7 | 2026-11-27 | Switching locks the current profile (its secrets forgotten exactly as a seed lock forgets them) and opens the other, on desktop and mobile. | CLI-UPR-07 |
| O8 | 2026-11-27 | The profile list shows only the user-given names; an option hides a profile from the list, after which it opens only by typing its name, as a hidden set opens only by typing its passphrase. | CLI-UPR-08 |
| O9 | 2026-11-27 | A profile's id is a UUIDv7. | CLI-UPR-09 |

Standing rules applied: secrets never leave the SDK and every KDF, AEAD and random draw runs in `ua-rs` (CLI-SDK-01, CLI-SDK-02);
fail closed with named errors; no decryption oracle (ARCH-POS-13); every RPC consumer takes a list of nodes (ARCH-POS-15); the node
is open and knows nothing of profiles.

## 2. Goals and non-goals (SPECIFIED)

**Goals.**

1. Several people, or one person with several roles (work, personal, a test identity), use one machine and one OS account, each
   profile with its own seeds, keys, chat, vault and settings.
2. Opening, locking and switching a profile are one SDK surface that every client calls the same way (CLI-UPR-02).
3. A stolen disk or another OS user learns at most the visible profiles' names, the number of profile directories and their
   creation times (§4, §14); every secret and every private record stays sealed under its own profile's passphrase.
4. Two instances of a client on one machine, on two profiles, talk to each other only as two machines would, so a two-person PqChat
   session runs and is tested on one machine (CLI-UPR-06).
5. Today's single store becomes the profile "default" by a one-time move (§12).

**Non-goals.**

- **Deniability.** A hidden profile is hidden from the list, not from the disk: its directory exists, its id (a UUIDv7) gives its
  creation time, its items have sizes and revisions (§8, §14). Nothing here makes a hidden profile deniable to someone who reads
  the disk; that would need a fixed-size container with decoys, which this spec does not offer (§16 Q-UP9).
- Separation from the OS account's own malware or administrator: a process of the same OS user can read the files and, while a
  profile is open, the process memory. Profiles separate people who share an OS account by passphrase, not by OS privilege.
- Anonymity between profiles on one machine: the RPC nodes, gateways, Matrix homeserver and any network observer see one IP
  address and one timing pattern for all profiles of a machine (§14).
- A server-side account: nothing about a profile leaves the device (CLI-UPR-10). No sync of profiles between devices beyond what
  exists per seed (sealed backup, device link; SDK spec §6.11).
- The chain-profile rename itself (CLI-UPR-01): a later task, §15.

## 3. Terms (SPECIFIED)

| Term | Meaning |
|---|---|
| **user profile** (`UserProfile`; "Profile" on screen) | one local identity: a directory under the profile root holding a store, app-core state and settings |
| **chain profile** (`ChainProfile`) | a chain's pinned data (CLI-SDK-15): chain key, family, `chain_uid`, RPC list, contracts, tokens, …; the build's data, never a user profile's |
| **profile root** | the directory that holds the profile index and every profile directory, one per OS user per platform (§5) |
| **instance** | one running process of a client (an app window process, a TUI session, one CLI command) |
| **open / locked** | open: an instance holds the profile's instance lock and its data key; locked: neither |
| **visible / hidden** | visible: a row in the index; hidden: no row, opened by typing its name (§8) |
| **protected / unprotected** | protected: the profile has a passphrase envelope (§7); unprotected: none yet, so it holds no secret (CLI-UPR-05) |

## 4. The profile id (CLI-UPR-09, CLI-UPR-10; SPECIFIED)

- Every profile has an id made once at creation: a **UUIDv7** (RFC 9562: 48-bit unix-millisecond timestamp, version and variant
  bits, 74 random bits from the OS RNG drawn in `ua-rs`), written in the canonical lower-case 36-character form. Owner ruling O9.
- The id is stable for the profile's life and **names its directory**. The user-given name is only a label in the index and in the
  sealed envelope; a rename changes the label and keeps the id and the directory.
- **The id never leaves the device**: never on chain, in a job, in a gateway request, in a chat message or Matrix event, in an
  RPC request, in a log line, in an error, an event or a `Debug` output, in a backup or a device link. It is not derived from any seed,
  key or name: a derived id would link the profile to its UAs and addresses.
- Keychain items of a profile are named with its id (§5); they stay on the device like the id.
- **Consequence, stated:** a UUIDv7 carries its creation time to the millisecond. Anyone who can list the profile root (a stolen
  disk, a backup of the home directory, an administrator) learns when each profile was made, hidden profiles included, and their
  order. The hidden-profile limit (§8: hidden from the list, not deniable on disk) already covers it.

## 5. Layout on disk (CLI-UPR-03, CLI-UPR-11; SPECIFIED; proposal for the file names)

One profile root per OS user and platform, shared by the CLI, the TUI and the desktop app of that user (as today's data directory
is shared):

| Platform | Profile root |
|---|---|
| Linux, BSD | `$XDG_DATA_HOME/scaas` (else `~/.local/share/scaas`), the CLI's `--data-dir` overriding it |
| macOS | `~/Library/Application Support/scaas` |
| Windows | `%APPDATA%\scaas` |
| Android, iOS | the app's private data directory (no other client shares it) |
| browser (wasm) | one IndexedDB database per profile, named by its id; the index in its own database (PLANNED, §13) |

```text
<root>/                          0700
  profiles.json                  the index (§6), written through FileStore (temp file, fsync, rename)
  profiles.json.lock             the index writers' lock (FileStore's lock of the item)
  p/<id>/                        0700, one per profile, <id> its UUIDv7
    instance.lock                held by the instance that has the profile open (§9)
    profile.envelope             the envelope (§7): unprotected marker, or KDF parameters, wrapped data key, sealed name
    keystore, keystore.prev      the SDK's keystore items (SDK spec §6.1, §6.3), sealed (§7)
    keystore.head                the rollback anchor where the platform has no keychain; else a keychain item named by the id
    sdk.state                    the SDK's operation state, sealed
    settings                     the profile's settings (below), sealed
    pqchat/                      pqchat-core's store (CLI-PQC-09), its items sealed
    pqvault/                     pqvault-core's offline ciphertext cache, its items sealed
    matrix/                      the matrix-rust-sdk store of this profile's Matrix login; its store key is a sealed item
    *.lock                       FileStore's per-item locks, as today
```

**What moves into a profile, from today's single store and config** (CLI-UPR-03):

| Today | In a profile |
|---|---|
| `$XDG_DATA_HOME/scaas/{keystore, keystore.prev, keystore.head, sdk.state}` | `p/<id>/` the same names, sealed |
| keychain items (`keystore.head`, the platform-secret key behind a seed's PRF envelope) | the same items, their names prefixed `scaas.profile.<id>.` by the app's `SecureStore` and `Authenticator` |
| `$XDG_CONFIG_HOME/scaas/overlay.json` (CLI) and the proposed `endpoints.toml` (TUI, Q-T8): named endpoints, credentials by file or variable name, a stronger RPC policy | `settings`, per chain-profile key, under CLI-TUI-06's rules unchanged |
| `tui.toml`'s idle lock, clipboard opt-in, default chain profile, lowered caps per chain profile (CLI-TUI-12, CLI-TUI-14) | `settings` |
| pqchat-core's store, its device anchor (CLI-PQC-09's Change), PqVault's cache, the Matrix store and login | `pqchat/`, `pqvault/`, `matrix/`; the device anchor a keychain item named by the id |

**What stays machine-wide** (`$XDG_CONFIG_HOME/scaas/`, read before any profile opens, never secret and never per person): the
TUI's colour, ASCII and key-map choices (CLI-TUI-07, CLI-TUI-18), the window geometry of the app. **What stays the build's:** the
release chain profiles, compiled in or digest-pinned (CLI-TUI-11, CLI-SDK-17); a user profile selects among them and overlays
them only as CLI-TUI-06 allows, never replaces one.

Each profile's seeds, native keys (EVM, Bitcoin, Solana, …, CLI-SDK-07), imported keys and hidden sets are exactly today's keystore
inside that profile's directory: the keystore format (CLI-SDK-03), its MAC, its rollback anchor and every seed's own vault
passphrase are unchanged. A hidden set (BIP-39 passphrase, SDK spec §6.5) belongs to the profile whose seed it opens; nothing about
it is written, as today.

## 6. The profile index (CLI-UPR-08, CLI-UPR-11; SPECIFIED; proposal for the format)

```json
{"format":"scaas.profiles","v":1,"rev":7,"last":"0193b2c4-6a1e-7c3d-9f20-5b8e1d2a4c6f","profiles":[{"id":"0193b2c4-6a1e-7c3d-9f20-5b8e1d2a4c6f","name":"default"}]}
```

- Rows hold the **id and the user-given name only**: no creation time, no seed count, no address, no protection flag, no avatar.
  The list on screen shows the names only (O8). A hidden profile has no row.
- `last` is the id of the last **visible** profile an instance opened, or `null`; opening a hidden profile never writes it, and
  hiding the profile named by `last` sets it to `null` in the same write.
- Bounded before parsing (64 KiB, depth 4, at most 32 rows), canonical JSON with unknown fields refused (`ProfileFormat`;
  another `format` or `v`: `ProfileVersion`), as the keystore container is read (SDK spec §6.1). A refusing reader writes nothing.
- Written with FileStore's `put_if` at the read `rev` under `profiles.json.lock` (SDK spec §6.3's rule; `StoreConflict` after three
  tries). **No previous copy** is kept: a `profiles.json.prev` would keep a hidden profile's row.
- Names: 1 to 64 bytes after NFC, no control or format characters (the account-name helper of SDK spec §7, one helper), unique among
  visible rows compared after NFKC case folding (`ProfileNameTaken`). A hidden profile's name is sealed and unknown to the index,
  so a visible and a hidden profile may share a name; opening by name in the hidden prompt finds only unlisted directories (§8).
- **The index is not trusted.** Before unlock it is only a label list: someone who can write it may rename a row or point it at
  another directory. After unlock the envelope's sealed name and id are compared with the row; a difference is
  `Event::ProfileIndexMismatch` (shown with the sealed name, not fatal) and the row is rewritten from the envelope.
- At most 32 profile directories under `p/` (`ProfileLimit` at create), which also bounds §8's search.

## 7. Protection (CLI-UPR-04, CLI-UPR-05, CLI-UPR-12; SPECIFIED; proposal for the envelope)

**The envelope.** A protected profile has a random 32-byte data key `DEK_p` (OS RNG, in `ua-rs`), held in `ua-rs`'s arena as a
handle while the profile is open (`mlock` where available, zeroized at lock and drop, never written in clear, never across the FFI),
exactly as a seed vault's data key is held (CLI-SDK-06). `profile.envelope` is canonical JSON holding public fields only:

| Field | Content |
|---|---|
| `format`, `v` | `scaas.profile`, 1 |
| `id` | the profile's id (bound into every associated data below) |
| `state` | `unprotected` or `protected` |
| `kdf` | `{alg: "argon2id", v: 1, m: 65536, t: 3, p: 4, salt: <16 random bytes>}` (memory in KiB) |
| `pass` | `DEK_p` wrapped under `KEK_pass = Argon2id(OpaqueString(passphrase), salt; m, t, p) → 32 bytes`, AEAD with associated data `scaas.profile.wrap.v1 ‖ id ‖ kdf` |
| `platform` | optional: `DEK_p` wrapped under `HKDF-SHA256(platform_secret(handle, salt))`, the handle a keychain / Keystore key named by the id |
| `name` | the user-given name sealed under `DEK_p` (associated data `scaas.profile.name.v1 ‖ id`) |

- **KDF parameters per profile.** The parameters are recorded in each profile's envelope, so profiles may differ and a profile's
  parameters may be raised at a passphrase change. The default is PqVault's pinned set (64 MiB / 3 / 4; CLI-PQV-10's Change, O8),
  reused here as a controller call (§16 Q-UP2). A reader refuses parameters below the default or above the bounds (m ≤ 1 GiB,
  t ≤ 16, p ≤ 8) as `ProfileFormat` before any KDF runs, so a tampered envelope can neither weaken nor stall an open. Every Argon2id
  run goes through `Limits::max_concurrent_heavy`.
- **The passphrase.** User-chosen, never generated (CLI-SDK-04); RFC 8265 OpaqueString before the KDF (CLI-PQV-07's Change, one
  form on every platform); vault v1's rule for a new envelope (at least 8 characters, not digits only; `ProfilePassphraseWeak`).
  Never stored, never kept after the wrap opens, never in an error or log. A wrong passphrase and an altered envelope are both
  `ProfileOpen`.
- **Sealed items.** While protected, every item of the profile's store is written as `{"rev":N,"sealed":"<base64 of nonce ‖
  ciphertext>"}`, AEAD under `DEK_p` with associated data `scaas.profile.item.v1 ‖ id ‖ item name ‖ be64(N)`. The outer `rev` is
  what `put_if` compares (unchanged rule, `store::rev_of`); binding it and the name into the associated data stops an item being
  swapped for another item or another revision of itself without detection. A sealed item that does not open is `VaultFormat` and
  the SDK writes nothing over it (SDK spec §6.1). The size bound of a sealed item is the base64 of the plain bound plus overhead.
  The sealing is a `SecureStore` adapter over the platform's store (`FileStore` on native, the app's own on mobile), so the
  keystore code (`KeystoreFile`, §6.3's lock, `rev`, `keystore.prev`, anchor) runs unchanged above it. App-core stores (`pqchat/`,
  `pqvault/`) seal through the same adapter; the Matrix store keeps its own encryption, its key a sealed item.
- **Two layers for seeds.** The seed vaults keep their own passphrases, envelopes and KDF (vault v2, scrypt, CLI-SDK-03, CLI-SDK-06)
  inside the sealed keystore: store encryption as today, under the profile's seal. Unlocking the profile does not unlock a seed;
  each seed unlocks as today. Whether one passphrase entry may serve both at the first secret is §16 Q-UP1.
- **Unprotected until the first secret** (O5). A new profile, "default" included, is `unprotected`: no passphrase, no `DEK_p`, its
  items (settings only) in plain form. Every call that would create a secret (`generate`, `import_words`, `derive_child`,
  `derive_from_signature`, `derive_from_key`, `import_key`, `create_passkey_key`, `create_se_key`, an app core's first key or record)
  on an unprotected profile is refused with `ProfilePassphraseRequired` before any work; the client asks for the profile passphrase,
  calls `set_passphrase`, which makes `DEK_p`, writes the envelope and re-writes every existing item sealed, then retries the call.
  A protected profile never returns to unprotected (`Argument`).
- **Biometric unlock, opt-in** (O4, the O7 (b) pattern). `enable_platform_unlock(passphrase, policy)` adds the `platform` wrap on
  this device: the Keychain / Android Keystore key under a biometric access policy (`biometryCurrentSet`, invalidated by an
  enrollment change), as for a seed (SDK spec §6.10). Off by default, per profile and per device; the client says, when it is turned
  on, that the device key alone then opens this profile on this device. An enrollment change invalidates the key and the passphrase
  remains. Nothing is derived from a biometric. Desktop Linux has passphrase only. `disable_platform_unlock` drops the wrap and the
  key; it revokes nothing from an earlier copy of the envelope (stated, as CLI-SDK-06 states for a seed).
- **Passphrase change** re-wraps the same `DEK_p` under the new passphrase (and new parameters if raised). Residual, stated as for
  a seed (SDK spec §6.3): it protects nothing against someone who copied the profile earlier and knows the old passphrase; the UI
  says so.
- **Opening one profile unlocks nothing of another** (O4): each profile has its own `DEK_p`, salt, keychain items and seed vaults;
  no key is shared, cached across profiles or derived from another profile's material.

## 8. Hidden profiles (CLI-UPR-08, CLI-UPR-13; SPECIFIED)

- `hide()` on an open, **protected** profile removes its row from the index (an unprotected profile cannot be hidden:
  `ProfilePassphraseRequired`); `show()` on an open hidden profile adds the row back with its sealed name.
- **Opening a hidden profile** takes its name and passphrase, both typed, both secret inputs (`SecretBytes`; the name never echoed,
  never on a command line, never in shell history, §13). The SDK:
  1. lists `p/` and takes every directory whose id is not in the index (unlisted), at most the §6 bound;
  2. for **every** unlisted directory, runs the envelope's KDF and tries the `pass` wrap, then compares the sealed name with the
     typed one (OpaqueString, constant time); it never stops at a match;
  3. pads to at least four attempts (dummy Argon2id runs at the default parameters when fewer directories are unlisted), so the time
     of a failed attempt is the same whether there are zero, one or four hidden profiles;
  4. returns the one match, or `ProfileOpen` for every failure: no such name, a wrong passphrase, no hidden profile at all, an
     unreadable envelope. A match whose directory another instance holds is `ProfileInUse`, which only someone who knew the name and
     passphrase can provoke.
- With more than four unlisted directories the time grows by one KDF run per directory; it then tells an observer of the screen
  how many unlisted directories exist, which the disk tells anyway. The name is a label, not key material: the passphrase is the
  protection (a name like "work" adds nothing to guess).
- The prompt "Open another profile" is always offered, whether or not hidden profiles exist.
- A hidden profile writes nothing that names it outside its directory: not `last`, not a recent-files list, not the OS's recent
  documents; its name is never drawn in a status line (the TUI and the app show "Hidden profile").
- **Limit, stated plainly:** hidden from the list, **not deniable on disk**. Its directory, its UUIDv7 (creation time), its item
  sizes and revisions, and its keychain items (named by the id) are visible to whoever reads the disk or lists the keychain.

## 9. One instance per profile (CLI-UPR-06, CLI-UPR-14; SPECIFIED)

- **The lock.** Opening a profile takes an exclusive, non-blocking OS advisory lock on `p/<id>/instance.lock` (the mechanism
  FileStore's item locks already use: `File::try_lock`, `flock` on Unix, `LockFileEx` on Windows) and holds it until the profile is
  locked or the process ends. A held lock is refused at once with **`ProfileInUse`**; the instance never waits for it.
- **No stale lock.** The OS releases an advisory lock when its process ends, by exit, crash or kill, so a crash leaves no lock to
  detect: the file stays and is free. Nothing is written into it (no PID, no time); there is no stale-lock rule, no timeout and no
  removal, and so no race between two instances deciding a lock is stale. The lock is taken before the envelope is read and before
  any item is written.
- **Local filesystems only.** Advisory locks over NFS and SMB are not reliable; a profile root on such a filesystem is outside the
  guarantee (stated; the SDK does not try to detect it).
- **Browser:** the Web Locks API (`navigator.locks.request(id, {ifAvailable: true})`), released when the tab closes (PLANNED with the
  wasm store).
- **Mobile:** one app process holds the lock; an app extension (iOS AutoFill, an Android autofill service) is a second instance
  (§16 Q-UP4).
- **Existing rule changed when built.** SDK spec §6.3 and CLI-SDK-17 say the CLI, `scaas-tui` and the app may share one data
  directory under the keystore's lock. With profiles they share the profile root and the index, never an open profile: a CLI
  command on a profile the TUI has open is `ProfileInUse` (§16 Q-UP3). The keystore's store lock, `rev` compare and `keystore.prev`
  stay, as defence in depth.
- **Instances of different profiles** share no memory, socket, pipe, D-Bus name, shared file or cache: each has its own `Sdk`, its
  own runtime, its own Matrix login and store, its own PqChat device id, its own RPC pools. They meet only where two machines would:
  the chains through the node lists (ARCH-POS-15), the gateways, the Matrix homeserver and PqChat's contract state. What they do
  share on the machine is read-only or separated by id: the build's chain profiles, the index (read; written under its lock), the OS
  keychain (items named by id). So two-person chat on one machine exercises the real paths and is a test (§17).

## 10. Lifecycle (CLI-UPR-15; SPECIFIED)

| Action | Needs | What happens |
|---|---|---|
| **first run** | a profile root with no index and no old store | the index and "default" (unprotected) are created and opened (O5) |
| **create** | a free visible name, fewer than 32 directories | a new id; the directory is built under a temporary name inside `p/` and renamed into place with its `unprotected` envelope, then the index row is added; a crash leaves either nothing or a complete unprotected profile |
| **open** (visible) | the instance lock; the passphrase or the platform unlock if protected | lock (§9), envelope read and bounded, `DEK_p` unwrapped in `ua-rs`, the index row checked (§6), `last` written, the profile's settings read, `Sdk::open` over its store |
| **open** (hidden) | name and passphrase | §8 |
| **lock** | — | the seed lock of CLI-SDK-06 for every seed (`vault.lock_all`: handles revoked in `ua-rs`, hidden sets dropped, `HiddenOpsAbandoned`), then `DEK_p` revoked, the `Sdk` dropped, the instance lock released; the client first closes its app cores and Matrix client (their handles are revoked by the seed lock anyway) and clears its view models |
| **switch** | — | lock, then open the other (O7); nothing is carried from one to the other |
| **rename** | open | the sealed name in the envelope and, if visible, the index row; the id and directory stay |
| **hide / show** | open, protected | §8 |
| **set / change passphrase, platform unlock** | open | §7 |
| **delete** | open (so its seeds' backup state can be read) and the profile's name typed again | `delete_preview()` lists the seeds and how many are `backup: pending`, and says that PqChat history recovers from state on another device (CLI-PQC-09) while seeds without a backup are lost; `delete(ConfirmDeleteProfile { typed_name })`, and with any seed `backup: pending` also `ConfirmDeleteUnbacked` (`ConfirmationMissing` without; the pattern of `ConfirmRemoveUnbacked`); order: the profile's keychain items, then `profile.envelope` (from then on the sealed items open with nothing), then the index row, then the directory; a crash part-way leaves a directory without an envelope, which the next start removes. Residual: a flash disk may keep old blocks; they are sealed |
| **export / import** | — | **gap:** the SDK has no profile-level sealed backup. What exists is per seed: `backup_seal` / `restore_backup` (`scaas/backup/v1`, CLI-UAL-12) and the device link (SDK spec §6.11). A profile moves to another device today as a new profile plus each seed's sealed backup restored, settings set again, PqChat recovered from contract state (new device id, CLI-PQC-09), PqVault read from chain. A one-file sealed profile backup is §16 Q-UP5 |

The last profile may be deleted; the next start creates "default" again (O5).

## 11. SDK surface (CLI-UPR-02; SPECIFIED; a sketch for the plan)

A module `user_profile` (feature `user-profile`, native and wasm stores), above `vault` and below every client:

```rust
pub struct UserProfiles { /* the profile root */ }
impl UserProfiles {
    pub fn at(root: String) -> Result<Arc<UserProfiles>, SdkError>;            // native FileStore root; migration (§12) once
    pub async fn list(&self) -> Result<Vec<UserProfileInfo>, SdkError>;       // visible rows: { id, name, protected }
    pub async fn create(&self, name: String) -> Result<UserProfileInfo, SdkError>;
    pub async fn open(&self, id: String, unlock: Option<ProfileUnlock>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn open_hidden(&self, name: Arc<SecretBytes>, passphrase: Arc<SecretBytes>) -> Result<Arc<UserProfile>, SdkError>;
}
pub enum ProfileUnlock { Passphrase(Arc<SecretBytes>), Platform }
impl UserProfile {
    pub fn store(&self) -> Arc<dyn SecureStore>;          // the sealed store: SdkConfig.store for Sdk::open
    pub fn app_dir(&self, part: ProfilePart) -> String;   // native: pqchat/, pqvault/, matrix/
    pub async fn settings(&self) -> Result<ProfileSettings, SdkError>;  pub async fn set_settings(&self, s: ProfileSettings) -> Result<(), SdkError>;
    pub async fn set_passphrase(&self, p: Arc<SecretBytes>, kdf: Option<KdfParams>) -> Result<(), SdkError>;
    pub async fn change_passphrase(&self, old: Arc<SecretBytes>, new: Arc<SecretBytes>, kdf: Option<KdfParams>) -> Result<(), SdkError>;
    pub async fn enable_platform_unlock(&self, p: Arc<SecretBytes>, policy: KeyPolicy) -> Result<(), SdkError>;
    pub async fn disable_platform_unlock(&self) -> Result<(), SdkError>;
    pub async fn rename(&self, name: String) -> Result<(), SdkError>;
    pub async fn hide(&self) -> Result<(), SdkError>;  pub async fn show(&self) -> Result<(), SdkError>;
    pub async fn delete_preview(&self) -> Result<DeletePreview, SdkError>;
    pub async fn delete(self: Arc<Self>, confirm: ConfirmDeleteProfile, unbacked: Option<ConfirmDeleteUnbacked>) -> Result<(), SdkError>;
    pub async fn lock(self: Arc<Self>) -> Vec<String>;    // the seed lock's abandoned hidden operations
}
```

New codes (CLI-SDK-13's naming): `ProfileInUse`, `ProfileOpen`, `ProfileNameTaken`, `ProfileNameInvalid`, `ProfileLimit`,
`ProfilePassphraseRequired`, `ProfilePassphraseWeak`, `ProfileFormat`, `ProfileVersion`, `ProfileLocked` (a call on a locked
profile's handle); event `ProfileIndexMismatch`. No code, event or `Debug` carries an id, a name, a passphrase or a path. The
`ua-rs` calls behind §7 (UUIDv7 draw, Argon2id wrap and unwrap, item seal and open, the arena handle of `DEK_p`, the dummy KDF run)
are new and need rows in `smartcontracts/vectors/` read by clientkeys and `ua-rs` before code (AGENTS.md: byte formats everywhere at
once).

## 12. Migration from today's single store (CLI-UPR-11; SPECIFIED)

Every chain is test-only and nothing of value is held, so **a one-time move into "default" is enough**; no old-layout reader, no
compatibility path and no second format are kept. At the first `UserProfiles::at(root)` that finds no `profiles.json` and finds
today's items (`keystore`, `keystore.prev`, `sdk.state`) at the root:

1. create "default" (a new id, `unprotected`), its directory built and renamed into place as at create;
2. move the items into it by `rename(2)` (same filesystem); the keychain anchor and any seed's platform-secret key are re-named under
   the id by the app's store, or, where that cannot be done, the anchor is rewritten from the moved container (as
   `accept_rollback` writes it); the CLI's `overlay.json` and the TUI's per-person `tui.toml` fields move into its `settings`;
3. write the index last; a crash before it repeats the move from where it stopped (each step is idempotent: an item already moved is
   absent at the root).

A migrated "default" holds secrets while unprotected, the one case of it: every `vault` and `app_core` call on it is refused with
`ProfilePassphraseRequired` until `set_passphrase` seals it. After mainnet launches a migration is a new owner question.

## 13. Per-client notes (CLI-UPR-16; SPECIFIED)

- **scaas-app desktop.** A start screen lists the visible names (`last` preselected) and always offers "Open another profile"
  (name and passphrase, the name field masked). A menu Profile → Lock, Switch, Rename, Hide / Show, Change passphrase, Delete. A
  second window or launch on an open profile shows "This profile is open in another window" (`ProfileInUse`). Several instances on
  different profiles may run side by side (O6).
- **scaas-app mobile.** One process; the profile switcher in settings; biometric unlock opt-in per profile on this device (§7); the
  seeds' auto-lock on background as today. App extensions: §16 Q-UP4.
- **scaas-tui.** `--profile <name>` opens a visible profile; `--profile-hidden` asks for the name and the passphrase on the terminal
  without echo (CLI-TUI-16's means); with neither, a picker screen when there are several, else the one profile. An action
  `profile` (lock and switch) on every screen; the status line shows the visible name, or "Hidden profile". The idle lock locks the
  seeds as today (§16 Q-UP6).
- **CLI `scaas`.** A global `--profile <name>`; `--profile-hidden` reads the name and the passphrase from the terminal without echo
  or from file descriptors, never from the command line or the environment (CLI-SDK-17's rule for secrets). Without either: `last`,
  else "default". Commands `scaas profile list | create | rename | hide | show | passphrase | platform-unlock | delete`, the last
  asking for the typed name. Each command is one instance: it takes the instance lock and releases it at exit (`ProfileInUse` while
  the TUI or the app has the profile open). **The chain-profile rename (§15) lands first**: today's `--profiles <file>` (a chain
  profile file in a `dev-profiles` build) and the new `--profile <name>` must never sit one letter apart.
- **Browser (wasm), PLANNED.** One IndexedDB database per profile named by its id, the index in its own database, the lock by Web
  Locks; the sealed-item adapter is the same.

## 14. Threat model (SPECIFIED)

| Adversary | Learns or can do | Bound |
|---|---|---|
| another OS user on the machine | nothing: the root and profile directories are `0700`, files `0600` (FileStore) | OS permissions; an administrator is out of scope |
| a stolen disk, a copied home directory, a backup | the visible names and `last` (index in clear); the number of profile directories; each id's creation time (UUIDv7, hidden ones included); item sizes and revisions; an unprotected profile's settings (endpoints, chain-profile picks; no secret, by O5) | every protected item sealed under `DEK_p` behind Argon2id 64 MiB / 3 / 4 per profile; seed vaults also behind their own scrypt (two layers); full-disk encryption recommended |
| an offline guesser of one profile's passphrase | one Argon2id run per guess at that profile's parameters; a success opens that profile's items and none of another's | passphrase strength (rule §7, meter in the UI); parameters raisable per profile |
| a second instance (the same user's other window or command) | refused: `ProfileInUse` | the OS lock (§9); a malicious process of the same user is out of scope (it can read the files and the memory) |
| someone watching the screen | the visible names only; no hidden name is drawn; the hidden prompt is always present; a failed hidden open takes the same time for zero to four hidden profiles | §8; names are labels the user picks |
| someone who edits the index | a wrong label or row before unlock | after unlock `ProfileIndexMismatch` and the row rewritten from the sealed envelope (§6) |
| someone who puts back an older copy of a profile | as today for the keystore: the anchor (`keystore.head`, keychain) raises `KeystoreRollback`; an item swapped across names or revisions fails its associated data | SDK spec §6.3; §7 |
| a network observer, an RPC node, a gateway, the Matrix homeserver | that several identities use one IP address and timing; never a profile id or name | non-goal (§2); profile ids never leave the device (§4) |
| a decryption-oracle attacker (ARCH-POS-13) | nothing: the profile layer opens only envelopes and items in the user's own directories with the user's own passphrase, and answers only the local user; it decrypts no ciphertext that arrives from the network and takes no action from a decrypted value | the hidden search opens only local directories, every failure one code |

The id's creation time (O9) is stated in §4: a reader of the root learns when each profile, hidden included, was made.

## 15. The chain-profile rename (CLI-UPR-01; a later task, PLANNED; nothing renamed here)

`ChainProfile` is already the code type (`clients/scaas-sdk/src/config.rs:65`, re-exported in `src/lib.rs`, generated as
`ChainProfile` in every binding) and SDK rules §10 is already titled "Chain profiles": the type stays. What changes, in one commit
across every place below (no on-chain byte, no vector, no EIP-712 domain, no node API changes):

| Kind | Today | After |
|---|---|---|
| SDK config field | `SdkConfig.profiles` (`config.rs:867`), `BindingConfig.profiles` (`binding.rs:926`), so every generated binding | `chain_profiles`; bindings regenerated |
| SDK error code | `ProfileMismatch` (stable code, CLI-SDK-13; about 50 lines in `src` and tests, every binding's error enum, docs) | `ChainProfileMismatch` (§16 Q-UP8) |
| SDK internals | `Chain.profile` and locals `profile` / `profiles` of `ChainProfile` type in `src/**` | `chain_profile` / `chain_profiles` |
| Cargo features | `dev-profiles` (`clients/scaas-sdk/Cargo.toml`, `clients/scaas-cli/Cargo.toml`) | `dev-chain-profiles` |
| SDK test file | `tests/evm_profiles.rs` (`[[test]] name = "evm_profiles"`) | `tests/evm_chain_profiles.rs` |
| CLI flag and field | `--profiles <file>` (`main.rs:575`), `Globals.profiles` (`main.rs:77`) | `--chain-profiles <file>`, `chain_profiles` |
| CLI codes | `ProfilesPinned`, `ProfilesRefused` | `ChainProfilesPinned`, `ChainProfilesRefused` |
| CLI code names | `parse_profiles`, `RELEASE_PROFILES`, private `Profiles` / `Profile` (`config.rs:16, 36, 67, 213`) | `parse_chain_profiles`, `RELEASE_CHAIN_PROFILES`, `ChainProfilesFile` / `ChainProfileRow` |
| CLI data | `clients/scaas-cli/profiles/release.json`, top-level key `"profiles"`; the overlay's credential field `"profile"` | `chain-profiles/release.json`, `"chain_profiles"`; `"chain_profile"` |
| TUI (docs only; no code yet) | `tui.toml` "the default profile", per-profile caps (spec §10), "release profiles" (CLI-TUI-11), `--profiles`, `dev-profiles` | `default_chain_profile`, caps per chain profile, "release chain profiles", `--chain-profiles`, `dev-chain-profiles` |
| prose | "profile" meaning a chain's pinned data | "chain profile" |

**Not renamed** (not a chain profile): Cargo `[profile.*]` build sections; "browser profile" (`signers-clientkeys.md`, `app.md:368`);
the node's own `profile` fields (`integration.md:93`, `:764`) and `pqz` job profile (`integration.md:176`), which are the node's
API and stay; "profiling".

**Where the word is used for chain profiles today** (lines matching "profile", the exclusions above removed; `git grep -ci` at
`644ea61a8`): 139 hand-written files, 1,424 lines, plus 117 generated binding files (1,886 lines) that follow by regeneration.

- `docs/clients/`: `scaas-sdk.md:23`, `scaas-tui.md:11`, `signers-clientkeys.md:11`, `scaas-rpc.md:6`, `app.md:1`,
  `ua-libraries.md:1`; `docs/integration.md:3` (lines 868, 1015, 1153; already "chain profile"); specs and plans:
  `specs/2026-11-17-scaas-sdk.md:87`, `specs/2026-11-17-scaas-tui.md:22`, `plans/2026-11-17-scaas-sdk.md:71`,
  `plans/2026-11-17-scaas-tui.md:10`. Beyond the list asked for: `docs/decisions.md` (141 lines) and `docs/networks/` (85).
- scaas-app's own repository (`app-common/`, `docs/`): no use of the word for chain profiles at its current head.
- `clients/scaas-cli`: `src/config.rs:66`, `tests/cli.rs:23`, `tests/e2e.rs:7`, `Cargo.toml:3`, `src/main.rs:2`, `src/calls.rs:1`,
  `profiles/release.json:1`.
- `clients/scaas-sdk/src`: `lib.rs:50`, `op/tests.rs:42`, `app_core.rs:40`, `op/quote.rs:36`, `dex.rs:29`, `config.rs:21`,
  `confidential/read.rs:18`, `account/register.rs:17`, `wallet/families/soroban_ops.rs:17`, `wallet/tokens.rs:16`,
  `confidential/pqz.rs:15`, `op/handoff.rs:15`, `wallet/families/mod.rs:15`, `op/bls_multi.rs:13`, `op/mod.rs:13`,
  `account/restore.rs:12`, `line.rs:12`, `op/gas.rs:11`, `op/submit.rs:10`, `wallet/history.rs:10`, `admin.rs:9`,
  `confidential/verdict.rs:9`, `wallet/balances.rs:9`, `account/register_tests.rs:7`, `admin/delay.rs:7`,
  `confidential/zether.rs:7`, `wallet/ops.rs:7`, `account/msig.rs:6`, `op/prepared.rs:6`, `binding.rs:5`, `account/msig_tests.rs:4`,
  `admin_tests.rs:4`, `confidential/pqz_debit.rs:4`, `error.rs:4`, `vault/tests.rs:4`, `wallet/families/aptos.rs:4`,
  `wallet/families/cosmos.rs:4`, `wallet/families/ton.rs:4`, `wasm/js.rs:4`, `watch.rs:4`, `account/line.rs:3`, `op/follow.rs:3`,
  `pqchat_keys.rs:3`, `wallet/families/solana.rs:3`, `wallet/families/soroban.rs:3`, `wallet/mod.rs:3`, `account/smart.rs:2`,
  `confidential/mod.rs:2`, `events.rs:2`, `wallet/families/algorand.rs:2`, `wallet/families/near.rs:2`, `wallet/families/sui.rs:2`,
  `op/state.rs:1`, `pqchat_records.rs:1`, `wallet/families/substrate.rs:1`, `wallet/handoff.rs:1`, `wallet/raw_tests.rs:1`;
  `Cargo.toml:5`; `ffi/src/api/mod.rs:4`.
- `clients/scaas-sdk/tests`: `e2e.rs:50`, `evm_profiles.rs:44`, `config.rs:30`, `confidential_pqz.rs:19`, `aptos.rs:18`,
  `evm_feature.rs:18`, `confidential.rs:16`, `cosmos.rs:15`, `soroban.rs:15`, `solana.rs:14`, `sui.rs:14`, `near.rs:13`,
  `substrate.rs:13`, `ton.rs:13`, `account.rs:12`, `algorand.rs:12`, `dex.rs:11`, `handoff.rs:11`, `soroban_ops.rs:11`,
  `wallet.rs:11`, `app_core.rs:10`, `l1_fee.rs:7`, `governance_delay.rs:6`, `wallet_ops.rs:5`, `account_ops.rs:4`,
  `app_core_vault_records.rs:4`, `arweave.rs:4`, `pqchat_keys.rs:4`, `history.rs:3`, `soroban_e2e.rs:3`, `passkey.rs:2`,
  `roots.rs:2`, `app_core_vault_rows.rs:1`, `binding.rs:1`, `children.rs:1`, `common/anvil.rs:1`, `common/fake_chain.rs:1`,
  `pqchat_records.rs:1`, `vault.rs:1`; binding tests `bindings/python/test_smoke.py:12`, `bindings/js/test/smoke.test.mjs:11`,
  `bindings/dart/test/e2e_test.dart:2`.
- `clients/pqchat-core`: `tests/common/chain.rs:14`, `tests/e2e/harness.rs:6`, `tests/common/sdk.rs:4`, `tests/vectors.rs:3`,
  `src/lib.rs:2`, `src/message.rs:1`, `src/net.rs:1`, `src/reads.rs:1`, `src/session.rs:1`, `src/stores.rs:1`, `src/topics.rs:1`,
  `tests/e2e.rs:1`.
- `clients/pqvault-core`: `tests/e2e.rs:13`, `tests/vectors.rs:4`, `src/keys.rs:1`, `src/lib.rs:1`, `src/vault.rs:1`,
  `tests/core.rs:1`, `tests/devices.rs:1`, `tests/exits.rs:1`.

The rename task re-runs the count at its own base and checks it to zero for the renamed identifiers (a grep gate in its commit).

## 16. Open questions

| # | Question | Options | Recommendation |
|---|---|---|---|
| Q-UP1 | At the first secret the client asks for the profile passphrase (O5) and the seed's vault passphrase (CLI-SDK-04): one entry or two? | (a) two entries; (b) one entry used for both; (c) the profile passphrase replaces seed vault passphrases in this profile | (a): the seed's own passphrase is the owner's rule of 2026-11-11 and protects the seed in every copy of the keystore; the client neither suggests nor refuses equal text |
| Q-UP2 | The profile envelope's KDF parameters | (a) PqVault's pinned set, 64 MiB / 3 / 4, as default, stronger allowed within the bounds of §7; (b) another set (low-memory phones, app extensions) | (a), no timing run without the owner's leave |
| Q-UP3 | A second instance only reading (the CLI's `balance` while the TUI has the profile open) | (a) refused (`ProfileInUse`), as O6 reads; (b) a read-only open beside the writer | (a): the ruling as stated; (b) would need a second lock class and every write path audited |
| Q-UP4 | An app extension (iOS AutoFill, Android autofill) reading PqVault entries while the app has the profile open | (a) refused as a second instance; (b) the extension asks the app over the platform's extension channel | (a) for now; (b) is a local side channel O6 excludes, so it is the owner's |
| Q-UP5 | Profile export / import as one sealed file | (a) none: per-seed sealed backups and the device link as today (§10); (b) a new `ua-rs` sealed profile backup holding each seed's `scaas/backup/v1` and the settings, with vectors | (a) now; (b) as a later task if the owner wants one-file moves |
| Q-UP6 | What the idle lock locks | (a) the seeds (today); (b) the whole profile | (a): (b) asks the profile and the seed passphrase after each idle period |
| Q-UP7 | Whether a hidden profile's name is key material (bound into the KDF) | (a) no, a label compared after unwrap (§8); (b) yes | (a): names are short and guessable; (b) changes nothing but forces a re-wrap at rename |
| Q-UP8 | Rename the stable code `ProfileMismatch` to `ChainProfileMismatch` in the rename task | (a) yes; (b) keep the code, rename prose only | (a): all chains are test-only, no compatibility is owed, and O1 says code too |
| Q-UP9 | Anything stronger than "hidden from the list" (decoy directories, a fixed-size container) | (a) no, a non-goal (§2); (b) yes | (a) |

## 17. Tests (SPECIFIED; for the plan)

Each negative test has its positive control and is run against a mutant (AGENTS.md):

- a second `open` of one profile in another process is `ProfileInUse`; a killed holder (SIGKILL) leaves a lock the next `open` takes
  at once; control: two different profiles open side by side;
- a wrong passphrase and an altered envelope, wrap or `kdf` are `ProfileOpen` / `ProfileFormat`; parameters above the bounds are
  refused before any KDF runs (a counter like `keystore::PARSED`); control: the right passphrase opens;
- a sealed item copied under another name or revision fails; control: the same item in place opens;
- a secret-creating call on an unprotected profile is `ProfilePassphraseRequired` and writes nothing; after `set_passphrase` every
  item on disk is sealed (no plain `keystore` byte left);
- opening profile A leaves profile B's items unopenable with A's key and B's seeds locked;
- the hidden search runs the same number of KDF calls for zero, one and four hidden profiles (counted, not timed) and returns one
  code for every failure; a hidden open never writes `last` or the index;
- the index edited to a wrong name raises `ProfileIndexMismatch` after unlock and is rewritten;
- lock revokes every handle (`WalletLocked` / `ProfileLocked` after) and zeroizes `DEK_p` in the arena (`ua-rs`'s existing arena
  test);
- migration: today's layout moves into "default", a crash at each step resumes, the old root holds no item after;
- no id, name or path in any error, event, log line or `Debug` (the existing redaction tests extended);
- end-to-end: two instances on one machine, two profiles, a PqChat 1:1 session over a local Matrix homeserver and a local chain.

## 18. Rule ids

| Id | Rule | Owner |
|---|---|---|
| CLI-UPR-01 | "Profile" on screen, `UserProfile` in code; "chain profile" / `ChainProfile` for a chain's data; the rename a later task | yes (O1) |
| CLI-UPR-02 | in the SDK layer, used by every client | yes (O2) |
| CLI-UPR-03 | many profiles per machine, each its own directory with its store, chat and vault state and settings | yes (O3) |
| CLI-UPR-04 | each protected separately, own passphrase and KDF parameters, biometric opt-in; one opens nothing of another | yes (O4) |
| CLI-UPR-05 | "default" on first run; the passphrase asked at the first secret | yes (O5) |
| CLI-UPR-06 | one instance per profile by a lock file and a named error; instances meet only over network paths | yes (O6) |
| CLI-UPR-07 | switching locks as a seed lock does, then opens the other | yes (O7) |
| CLI-UPR-08 | the list shows names only; a profile may be hidden and opened by typing its name | yes (O8) |
| CLI-UPR-09 | the profile id is a UUIDv7 | yes (O9) |
| CLI-UPR-10 | the id: stable, names the directory, the name a label, never leaves the device, not derived | no |
| CLI-UPR-11 | layout, index (names and ids only, no previous copy, untrusted), migration into "default" | no |
| CLI-UPR-12 | protection: `DEK_p`, the envelope, Argon2id per profile, sealed items, unprotected until the first secret, platform wrap | no |
| CLI-UPR-13 | the hidden search: every unlisted directory, padded, one error; not deniable on disk | no |
| CLI-UPR-14 | the instance lock: OS advisory lock, no stale state; the shared-directory sentence of SDK §6.3 changed when built | no |
| CLI-UPR-15 | lifecycle: create, rename, hide, delete with typed name and backup reminder; export a named gap | no |
| CLI-UPR-16 | client surfaces: `--profile`, `--profile-hidden`, pickers, the rename before `--profile` | no |
