# User profiles: many protected local profiles in the SDK layer: design

**Status:** SPECIFIED, nothing built. A **frame**: the owner's rulings of 2026-11-27 (§1, §16) are fixed; the means are controller
calls (`owner: no`). Fable reviewed the frame at `06d9843d5` on 2026-11-27 (three areas, all "approve with fixes", no
decryption-oracle path, no ruling reopened); every finding is applied as the controller's ruling of the same day (§19). Branch
`user-profiles-spec` (from `dev` `644ea61a8`), worktree `.claude/worktrees/user-profiles-spec`. Rule ids introduced here
(SPECIFIED, defined once in [clients/scaas-sdk.md](../../clients/scaas-sdk.md) §12, recorded in [decisions.md](../../decisions.md)
§41): CLI-UPR-01 to CLI-UPR-24. No contract, signed byte format, chain profile or node rule changes; no on-chain byte changes. The
`ua-rs` calls and the two file formats of §7 and §10.1, and the keystore's new vault label of §7.4, are new and need vector rows in
clientkeys and `ua-rs` before code. UNAUDITED.

**Reads** (as at `644ea61a8`): the SDK's vault and store code (`clients/scaas-sdk/src/vault/`: `store.rs` `SecureStore`,
`FileStore`, `MemoryStore`, `rev_of`; `mod.rs` `KeystoreFile`; `seeds.rs` (`import_key`); `unlock.rs`; `prf.rs`; `roots.rs`),
`src/platform.rs` (`KeyPolicy`), `Sdk::open` and `SdkConfig` (`src/lib.rs`, `src/config.rs`), the CLI's data directory and chain-profile
loading (`clients/scaas-cli/src/config.rs`); `ua-rs` `wallet/appkey.rs` (arena scopes, AES-256-GCM-SIV, Argon2id, OpaqueString) and
`wallet/vault.rs`; pqchat-core's store keys; the SDK spec §6 and rules CLI-SDK-01 to CLI-SDK-06, CLI-SDK-13, CLI-SDK-15, CLI-SDK-17;
the TUI spec §10 and CLI-TUI-04, CLI-TUI-06, CLI-TUI-11, CLI-TUI-12, CLI-TUI-14; hidden sets (SDK spec §6.5, CLI-UAL-18); PqVault's
passphrase KDF (CLI-PQV-07, CLI-PQV-10 and its Change) and biometrics (pqvault spec §14 O7 (b), CLI-PQV-15 (3)); PqChat's recovery
from state (CLI-PQC-09); ARCH-POS-13, ARCH-POS-15. Order of sources: AGENTS.md "Which source wins".

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
| O10 | 2026-11-27 | The spec's open points Q-UP1 to Q-UP9 (§16): Q-UP5, export and import of a whole profile as one sealed file, is in scope now with the content, seal, confirm and id rule of §10.1; the other eight as recommended. | CLI-UPR-17; §16 |
| O11 | 2026-11-27 | Platform (biometric) unlock on a shared OS account opens the profile to everyone enrolled on that account: an accepted risk. Mitigation: the user may lock each secret item separately with its own passphrase, optional per item: every seed (its own vault passphrase) and every imported native secret key; that per-item passphrase is never opened by platform or biometric unlock, only typed. | CLI-UPR-23; §7.4, §14.1 |

Standing rules applied: secrets never leave the SDK and every KDF, AEAD and MAC runs in `ua-rs` (CLI-SDK-01, CLI-SDK-02); fail closed
with named errors; no decryption oracle (ARCH-POS-13); every RPC consumer takes a list of nodes (ARCH-POS-15); the node is open and
knows nothing of profiles.

## 2. Goals and non-goals (SPECIFIED)

**Goals.**

1. Several people, or one person with several roles (work, personal, a test identity), use one machine and one OS account, each
   profile with its own seeds, keys, chat, vault and settings.
2. Opening, locking and switching a profile are one SDK surface that every client calls the same way (CLI-UPR-02).
3. A stolen disk or another OS user learns at most the visible profiles' names, the number of profile directories, their creation
   times, and the number and sizes of their items (§4, §14); every secret, every private record and every item name stays sealed under
   its own profile's passphrase.
4. Two instances of a client on one machine, on two profiles, talk to each other only as two machines would, so a two-person PqChat
   session runs and is tested on one machine (CLI-UPR-06).
5. Today's single store becomes the profile "default" by a one-time move (§12).
6. No crash, at any step of any action, loses a profile or leaves one that no rule opens, repairs or removes (§7.3, §10, §12).

**Non-goals.**

- **Deniability.** A hidden profile is hidden from the list, not from the disk: its directory exists, its id (a UUIDv7) gives its
  creation time, its items have count and sizes (§8, §14). Nothing stronger is offered (owner 2026-11-27, Q-UP9).
- Separation from the OS account's own malware or administrator: a process of the same OS user can read the files and, while a
  profile is open, the process memory. Profiles separate people who share an OS account by passphrase, not by OS privilege; platform
  unlock does not separate them at all (O11, §14.1).
- Anonymity between profiles on one machine: the RPC nodes, gateways, Matrix homeserver and any network observer see one IP
  address and one timing pattern for all profiles of a machine (§14).
- A server-side account: nothing about a profile leaves the device except a profile export the user makes (§10.1), and that holds
  no id (CLI-UPR-10). No live sync of profiles between devices.
- The chain-profile rename itself (CLI-UPR-01): a later task, §15.

## 3. Terms (SPECIFIED)

| Term | Meaning |
|---|---|
| **user profile** (`UserProfile`; "Profile" on screen) | one local identity: a directory under the profile root holding its envelope, its sealed store and app-core state |
| **chain profile** (`ChainProfile`) | a chain's pinned data (CLI-SDK-15); the build's data, never a user profile's |
| **profile root** | the directory that holds the index and every profile directory, one per OS user per platform (§5) |
| **instance** | one running process of a client (an app process, a TUI session, one CLI command) |
| **open / locked** | open: an instance holds the profile's instance lock and its data key; locked: neither |
| **visible / hidden** | visible: sealed as visible and listed by a row of the index; hidden: sealed as hidden, never listed, opened by typing its name (§8) |
| **unprotected / sealing / protected** | the envelope's states (§7): no passphrase yet and no secret; a re-seal in progress; sealed under the profile passphrase |
| **generation** | the directory `g<N>/` that holds the profile's items under one data key; a re-seal builds `g<N+1>/` and commits it in one rename (§7.3) |
| **tombstone** | `p/<id>.deleted`: a profile being deleted, removed at the next start (§10) |
| **key lock** | an imported native secret key sealed under its own passphrase, opened only by typing it (§7.4, O11) |

## 4. The profile id (CLI-UPR-09, CLI-UPR-10; SPECIFIED)

- Every profile has an id made once at creation: a **UUIDv7** (RFC 9562: 48-bit unix-millisecond timestamp, version and variant
  bits, 74 random bits from the OS RNG), written in the canonical lower-case 36-character form. Owner ruling O9. Drawn with the SDK's
  existing `uuid` 1 crate (its `v7` feature) and `getrandom`, as `uuid4` is drawn today; no new crate. Vector rows take the
  timestamp and the random bytes as inputs, so the encoding has known answers.
- The id is stable for the profile's life and **names its directory**. The user-given name is only a label in the envelope and, for
  a visible profile, in the index; a rename keeps the id and the directory. An envelope whose `id` differs from its directory's name
  is `ProfileFormat`.
- **The id never leaves the device**: never on chain, in a job, a gateway or RPC request, a chat message or Matrix event, a log
  line, an error, an event or a `Debug` output (`UserProfileInfo`'s `Debug` redacts it), a backup, an export or a device link. It is
  not derived from any seed, key or name. It crosses the FFI to the client in `UserProfileInfo`, because the app's keychain items are
  named by it (§5); the client must not log it, and must configure third-party stores it hands a profile path to (matrix-rust-sdk)
  not to log their paths: the SDK keeps the id out of every path and log it controls.
- **Consequence, stated:** a UUIDv7 carries its creation time to the millisecond. Anyone who can list the profile root (a stolen
  disk, a backup of the home directory, an administrator) learns when each profile was made, hidden profiles included, and their
  order. The hidden-profile limit (§8) covers it.

## 5. Layout on disk (CLI-UPR-03, CLI-UPR-11; SPECIFIED)

One profile root per OS user and platform, shared by the CLI, the TUI and the desktop app of that user:

| Platform | Profile root | Bound on another OS user |
|---|---|---|
| Linux, BSD | `$XDG_DATA_HOME/scaas` (else `~/.local/share/scaas`), the CLI's `--data-dir` overriding it | modes `0700` / `0600` |
| macOS | `~/Library/Application Support/scaas` | modes `0700` / `0600` |
| Windows | `%APPDATA%\scaas` | the default ACL of `%APPDATA%` (modes do not apply); FileStore's directory `fsync` is checked on Windows by a test before this row counts |
| Android, iOS | the app's private data directory, through the app's own store (§11) | the platform sandbox |
| browser (wasm) | one IndexedDB database per profile, named by its id; the index in its own database (PLANNED, §13) | the origin |

```text
<root>/                          0700; an existing root is tightened to 0700 at open; a root that is a symlink or not the user's is refused
  profiles.json                  the index (§6): a cache of visible names, rebuilt from the envelopes when lost
  profiles.json.lock             the root lock: first run, migration, create, import, delete's index step, rebuild, start-up clean-up
  p/.journal                     present only during a create or an import: {op, id} (§10)
  p/.tmp-<random>/               a profile being built; removed at start, never searched
  p/<id>.deleted/                a tombstone; removed at start
  p/<id>/                        0700, one per profile, <id> its UUIDv7
    instance.lock                held by the instance that has the profile open (§9)
    profile.envelope             the envelope (§7.1)
    profile.envelope.next        present only during a re-seal: the journal of §7.3
    profile.head                 the anchor of the sealed manifest where the platform has no keychain (§7.2)
    keystore.head                the keystore's anchor where the platform has no keychain (SDK spec §6.3), unsealed by contract
    g<N>/                        the current generation: every store item under an HMAC file name (§7.2), plus `manifest`
      <64 hex>, <64 hex>.lock    one sealed item and its FileStore lock; the name says nothing about the item
      manifest                   the sealed list of (part, item name, rev)
    matrix/                      the matrix-rust-sdk store of this profile's Matrix login, under its own key (a sealed item)
```

The store parts (`part` in §7.2) are `sdk` (`keystore`, `keystore.prev`, `sdk.state`, `settings`), `pqchat` (pqchat-core's store,
CLI-PQC-09) and `pqvault` (pqvault-core's offline ciphertext cache).

**What moves into a profile, from today's single store and config** (CLI-UPR-03):

| Today | In a profile |
|---|---|
| `{keystore, keystore.prev, sdk.state}` at the CLI's data directory | part `sdk` of the generation, sealed |
| `keystore.head` (file or keychain) | the same, the keychain item named `scaas.profile.<id>.keystore.head` by the app's store |
| a seed's platform-secret key behind its PRF envelope | the same key, named under the profile id by the app's `Authenticator` |
| the CLI's `overlay.json` (`$XDG_CONFIG_HOME/scaas/` or `~/.config/scaas/`), the TUI's proposed `endpoints.toml` (Q-T8) | `settings`, per chain-profile key, under CLI-TUI-06's rules; `--overlay` is withdrawn (§13) |
| `tui.toml`'s idle lock, clipboard opt-in, default chain profile, lowered caps per chain profile (CLI-TUI-12, CLI-TUI-14) | `settings` |
| pqchat-core's store and its device anchor, PqVault's cache, the Matrix store and login | parts `pqchat`, `pqvault`; `matrix/`; the device anchor a keychain item named by the id |

**What stays machine-wide** (`$XDG_CONFIG_HOME/scaas/`, read before any profile opens, never secret and never per person): the
TUI's colour, ASCII and key-map choices (CLI-TUI-07, CLI-TUI-18), the app's window geometry. **What stays the build's:** the release
chain profiles (CLI-TUI-11, CLI-SDK-17); a user profile selects among them and overlays them only as CLI-TUI-06 allows.

Each profile's seeds, native keys, imported keys and hidden sets are exactly today's keystore inside that profile's sealed store: the
keystore format (CLI-SDK-03), its MAC, its anchor and every seed's own vault passphrase are unchanged, plus the optional key lock of
§7.4.

## 6. The profile index (CLI-UPR-08, CLI-UPR-11; SPECIFIED)

```json
{"format":"scaas.profiles","v":1,"rev":7,"last":"0193b2c4-6a1e-7c3d-9f20-5b8e1d2a4c6f","profiles":[{"id":"0193b2c4-6a1e-7c3d-9f20-5b8e1d2a4c6f","name":"default"}]}
```

- **A cache, never the truth.** A profile's name and its hidden flag live in its envelope (§7.1): in clear for an unprotected
  profile, sealed for a protected one. The index only lets the picker show visible names before any passphrase; it is rebuilt from
  the envelopes whenever it is missing or does not parse while `p/` holds a profile directory, which is **never a first run**.
  Rebuild (under the root lock; also offered on demand with a typed confirm): a row for every unprotected directory from its clear
  name; no row for a protected directory, which is listed again at its first open if it is sealed as visible. The client says
  "profiles may be missing from the list after a repair; open them with 'Open another profile'". Rows whose directory is missing
  are dropped.
- Rows hold the **id and the name only**. A hidden profile never has a row, at any time (§8).
- `last` is the id of the last **visible** profile an app or TUI instance opened, or `null`; it is written only when it changes; a
  hidden open never writes it; the CLI never reads it (§13).
- Bounded before parsing (64 KiB, depth 4, at most 32 rows), canonical JSON, unknown fields refused; written with FileStore's
  `put_if` at the read `rev` under the root lock; **no previous copy** (it would keep stale rows).
- Names: 1 to 64 bytes after NFC, no control or format characters (the account-name helper of SDK spec §7); compared everywhere by
  **one helper**, `name_key(s)` = NFKC, then Unicode lower case (Rust's `str::to_lowercase`, JavaScript's `toLowerCase`, at the
  Unicode version the vectors pin), compared in constant time over equal-length padded buffers. Visible names are unique by
  `name_key` (`ProfileNameTaken`).
- **The index is not trusted.** After unlock the envelope's sealed name and hidden flag are compared with the row: a visible
  profile's row with another label is rewritten from the envelope (`Event::ProfileIndexMismatch`); **a row that points at a profile
  sealed as hidden is refused**: that open is `ProfileOpen`, the row is dropped and nothing else is written, so a planted row never
  draws a hidden name into the clear; the profile opens again through the hidden prompt.
- At most 32 profile directories under `p/` (`ProfileLimit` at create and import).

## 7. Protection (CLI-UPR-04, CLI-UPR-05, CLI-UPR-12, CLI-UPR-19 to CLI-UPR-21; SPECIFIED)

### 7.1 The envelope

A protected profile has a random 32-byte data key `DEK_p`, drawn and held in `ua-rs`. The existing arena scope (`AppKeys`) hangs off
a seed's `Wallet` (`appkey.rs:129`) and cannot hold a key before any seed exists or across seeds, so **a profile arena** is new: a
`ua-rs` `ProfileKeys` scope over its own secret store, with the arena's rules (locked pages where available, zeroized at lock and
drop, never written in clear, never across the FFI). `profile.envelope` is canonical JSON:

| Field | Content |
|---|---|
| `format`, `v` | `scaas.profile`, 1 |
| `id` | the profile's id, equal to its directory's name |
| `state` | `unprotected`, `sealing` (only in `profile.envelope.next`) or `protected` |
| `gen` | the current generation `N` |
| `migration` | `pending` while a migration fills this profile (§12), else absent |
| `name` | unprotected: the name in clear (NFC); protected: absent |
| `kdf` | `{alg: "argon2id", v: 1, m, t, p: 4, salt: <16 random bytes>}`, memory in KiB, the bounds of §7.5 |
| `pass` | `DEK_p` wrapped under `KEK_pass` (below) |
| `platform` | optional, never on a hidden profile: `{salt: <32 random bytes>, wrap}`, `DEK_p` wrapped under `K_plat` (below) |
| `label` | protected: `{name, hidden}` sealed under `K_label` |

**Keys, each separated by its HKDF-SHA256 label** (distinct from each other and from PqVault's `P_k`, which is a bare Argon2id output):

| Key | Derivation |
|---|---|
| `KEK_pass` | `HKDF(ikm = Argon2id(OpaqueString(passphrase), salt; m, t, 4) → 32 bytes, salt = none, info = "scaas.profile.wrap.v1")` |
| `K_plat` | `HKDF(ikm = platform_secret(handle, platform.salt), salt = none, info = "scaas.profile.platform.v1")`; handle `scaas.profile.<id>.unlock`, its own per profile, never a seed's (`scaas.unlock.<seed>`) |
| `K_label` | `HKDF(DEK_p, info = "scaas.profile.label.v1")` |
| `K_item` | `HKDF(DEK_p, info = "scaas.profile.item.v1")` |
| `K_name` | `HKDF(DEK_p, info = "scaas.profile.item-name.v1")` |
| `K_x` (export) | `HKDF(Argon2id(OpaqueString(export passphrase), file salt; m, t, 4), info = "scaas.profile-export.v1")` (§10.1) |

**The AEAD is AES-256-GCM-SIV** (already in `ua-rs`, `appkey.rs`), with a **96-bit nonce drawn from the OS RNG at every seal**,
never derived, never a counter (the export's chunks excepted, §10.1). Misuse resistance is chosen because `DEK_p` lives for the
profile's life between passphrase changes, and the pair (item, rev) does repeat: a `put_if` retry after `StoreConflict` re-seals new
content at the same `rev`, `accept_rollback` and a restored copy continue from an old `rev`, a copied directory on a second machine
writes the same revs under the same key. With GCM-SIV a repeated nonce reveals only that two equal plaintexts are equal; with GCM it
would give the authentication key. Every sealed value is `nonce ‖ ciphertext ‖ tag` (16-byte tag, last).

**Associated data is length-framed**: `lp(x) = be16(len(x)) ‖ x` for every variable field, fixed fields as written.

- `pass` and `platform.wrap` (a `seal_key` of `DEK_p`): AD = `lp("scaas.profile.wrap")` (or `"scaas.profile.platform"`) ‖ the canonical
  bytes of the envelope's public fields `format`, `v`, `id`, `state`, `gen`, `kdf` (salt included) as written in the file. A changed
  state, generation, parameter or salt fails the wrap. The hidden flag is not public: it is sealed in `label`.
- `label`: AD = `lp("scaas.profile.label") ‖ be16(1) ‖ lp(id)`.

**Refusals by state** (no item is read before these hold):

- a protected profile refuses any item not in sealed form and any file in `g<N>/` that is not an HMAC name or `manifest`
  (`VaultFormat`);
- an unprotected profile refuses a sealed item, a generation other than `g0`, and, unless `migration: pending`, a `keystore` item
  (`ProfileFormat`);
- where the OS has a keychain, `set_passphrase` writes the item `scaas.profile.<id>.protected`; an `unprotected` envelope beside it is
  `ProfileFormat`.
- **Residual, stated:** where there is no keychain (desktop Linux), someone who can write the directory may replace the whole
  envelope and generation with an unprotected one: the result is a different, empty profile under the same id (a deletion, not a
  disclosure); the sealed items it replaced are gone, not opened.

### 7.2 The sealed store (CLI-UPR-19)

- **Item.** `{"rev":N,"sealed":"<base64 of nonce ‖ ciphertext ‖ tag>"}`, AES-256-GCM-SIV under `K_item`, AD =
  `lp("scaas.profile.item") ‖ be16(1) ‖ lp(part) ‖ lp(item name) ‖ be64(N)` (domain, profile-format version, store part, the item's
  full name in its part, rev). An item cannot move between names or parts, or take another `rev`, without failing its tag.
- **File name.** `hex(HMAC-SHA256(K_name, lp(part) ‖ lp(item name)))`: 64 lower-case hex characters, which FileStore's name rule
  accepts. No item name (pqchat-core's keys hold UAs, session ids and Matrix room ids: `kem/{chain}/{ua}`, `mroom/{room}`, …) and no
  part name appears on disk. The real names live in the sealed `manifest`.
- **Manifest.** One sealed item at the fixed file name `manifest` (every profile has one, so the name says nothing), holding every
  `(part, item name, rev)` of the generation and its own `rev`. Every write is: the item (under the store lock, `put_if` as today),
  then the manifest with that item's new `rev`, then the anchor. The anchor is `{gen, manifest rev, the first 16 bytes of SHA-256 of
  the manifest's file}` in the keychain item `scaas.profile.<id>.head`, else the file `profile.head`, written as the keystore's
  anchor is (best effort after the write).
- **Rollback, exactly what holds.** On read: an item whose `rev` is **below** the manifest's is `Event::ProfileRollback` (shown, not
  fatal, writes refused for that item until the user accepts, as `KeystoreRollback`); an item above the manifest's is a crash between
  the two writes, and the manifest is brought forward; a manifest below the anchor is `ProfileRollback` for the profile. So an old
  copy of one item put back is seen, for every item, not only the keystore. Where the anchor is the file `profile.head` in the same
  directory (no keychain: desktop Linux), a rollback of the **whole directory** (envelope, generation and anchor together) is not
  seen: stated in §14. A passphrase change rotates `DEK_p` (§7.3), so an old envelope and the old passphrase open none of the state
  written after the change.
- **Size.** A sealed item's bound is the base64 of its plain bound (16 MiB for `keystore`, `keystore.prev`, `sdk.state`) plus
  1 KiB; `rev_of` reads the outer `rev` of a sealed item up to that bound instead of 16 MiB, and SDK spec §6.9's size contract says so
  (§15.2). `keystore.head` passes through unsealed: it is public by contract (`rev` and a hash, at most 64 bytes, for a keychain).
- **Errors.** `StoreError` gains `VaultFormat` (a sealed item that does not open; a plain item in a protected profile),
  `ProfileLocked` and `ProfilePassphraseRequired`, and `vault::io` maps each to the `SdkError` of the same name; this is a change to
  the keystore code (one mapping), which otherwise runs above the adapter as today (`KeystoreFile`, lock, `rev`, `keystore.prev`).
- **App cores.** pqchat-core's store is a `PqChatStore` (synchronous `load` / `replace`, revision 0 = absent then +1), not a
  `SecureStore`: the profile hands each app core a sealed store for its part and an adapter that maps its revision to the item `rev`
  (a plan task, before pqchat-core runs inside a profile). PqVault's cache uses the sealed `SecureStore` of part `pqvault`. The Matrix
  store keeps its own encryption; its store key is a sealed item, and it is **the one key that leaves the arena** (matrix-rust-sdk
  needs its bytes): it lives in the Matrix client until the profile locks, and the lock closes that client.
- **Zeroisation.** Every key above (`KEK_pass`, `K_plat` and the platform secret, `K_label`, `K_item`, `K_name`, `K_x`), every
  Argon2id output, dummy runs included, the OpaqueString bytes of a passphrase, a typed hidden name, and every plaintext buffer of an
  item, a label, an export or an import live in `Zeroizing` buffers or the arena and are dropped at the end of the call; `DEK_p` and
  the derived item keys stay in the profile arena until lock.

### 7.3 Re-seal, crash safety (CLI-UPR-20)

`set_passphrase` (unprotected → protected), `change_passphrase` (a new `DEK_p` under the new passphrase) and a raise of the KDF
parameters are one procedure:

1. under the instance lock, write `profile.envelope.next` with `state: "sealing"`, `gen: N+1`, the new `kdf`, the new wraps of a
   **new** `DEK_p` and its `label`: this file is the journal;
2. re-seal every item of `g<N>/` (read in plain form for `g0` of an unprotected profile, else opened under the old key) into
   `g<N+1>/` under the new keys, with a new manifest; `fsync` each file and the directory;
3. commit: rewrite `profile.envelope.next` with `state: "protected"` (its wraps re-sealed, since `state` is in their associated
   data; temporary file, `fsync`, rename), then rename it over `profile.envelope` and `fsync` the directory; write the keychain
   `protected` marker;
4. remove `g<N>/`.

At every open and at start-up (under the instance lock): a `profile.envelope.next` present means the commit did not happen, so it and
`g<N+1>/` are removed and the profile stays as it was (**roll back**; the user repeats the action); a generation other than the
envelope's `gen` is removed. A crash at any step therefore leaves either the old profile whole or the new one whole. The previous
plain `g0` of a migrated "default" is removed only after the commit.

### 7.4 Per-item passphrases; the key lock (CLI-UPR-23, CLI-UPR-24; owner O11)

- **Seeds.** Each seed already has its own vault passphrase (CLI-SDK-03, CLI-SDK-04; two entries at the first secret, Q-UP1). The
  profile's unlock, by passphrase or platform, **never** opens a seed: a seed opens by its own unlock only (CLI-SDK-06). A seed's own
  platform or passkey unlock is the seed's separate opt-in; on a shared OS account it carries O11's risk too, and the client says so
  when it is turned on. A seed kept on its passphrase alone is opened only by typing.
- **Imported native secret keys today** (ETH, BTC, Solana, … raw keys: `import_key`, SDK spec §6.7) are sealed as the label vault
  `native-import:<network>:<n>` **under the seed's own passphrase**, with the seed's PRF envelope when the seed has passkey or
  platform unlock (`vault/seeds.rs` `import_key`), and a passphrase unlock of the seed opens them all (CLI-SDK-06). So today an
  imported key has no passphrase of its own and is opened by the seed's platform unlock.
- **The key lock (new).** `ImportKey` gains `key_passphrase: Option<Arc<SecretBytes>>`. With it, the key's vault is sealed under that
  passphrase with a pin envelope only (no PRF envelope), as the label vault `native-import-locked:<network>:<n>` (a new label form in
  the keystore container: clientkeys and its vectors first, CLI-SDK-03). Such a vault is **never** opened by the seed's unlock of any
  kind, by a passkey, by a platform secret or by the profile's unlock; only `vault.unlock_key(seed, key, key_passphrase)` opens it,
  with the passphrase typed (`Unlock::Passkey` and `Unlock::Platform` are refused for it: `Argument`). It stays open until
  `lock_key`, the seed's lock or the profile's lock. A signature by a locked key is refused `KeyLocked` before anything is signed.
  The passphrase follows the vault passphrase rule; the client neither suggests nor refuses the seed's passphrase.
- **An existing import** may be moved under its own passphrase: `vault.lock_key_separately(seed, key, key_passphrase)` (seed
  unlocked) re-seals the key as a new `native-import-locked:` vault under a fresh data key and drops the old vault in the same write.
  Residual, stated: `keystore.prev`, an export made before and any earlier copy still hold the old vault under the seed's passphrase
  and PRF envelope; the UI says "move the funds to a new key if an earlier copy may be out".
- **What a platform unlock of the profile makes readable** (stated plainly, O11): the profile's settings and chain-profile settings;
  the keystore's public fields (seed labels, account rows with addresses and UA ids, backup states); `sdk.state` (operation history);
  the PqChat store (contacts and sessions, rooms, read positions, counters; CLI-PQC-09); the Matrix store and login (plain Matrix chat
  history included); PqVault's offline cache (ciphertexts and their metadata). **Not readable:** any seed's words and keys, any
  imported key, any key-locked key, PqVault items (each behind its own vault key and, by default, its passphrase, CLI-PQV-07), PqChat's
  local plaintext history where built (sealed under the account's app-scoped storage key, which needs the seed unlocked; CLI-PQC-09's
  Change).

### 7.5 KDF parameters, bounds, cost (CLI-UPR-21)

- Default **64 MiB / 3 / 4** (owner 2026-11-27, Q-UP2; PqVault's pinned set), stronger allowed within the bounds, no timing run.
- **Bounds, each field alone:** `m` from 65,536 KiB (64 MiB) to 1 GiB on desktop, to 256 MiB on mobile and in a browser; `t` from 3 to
  10; **`p` fixed at 4** (not a strength knob: at fixed `m`, a larger `p` is not stronger; `p = 4` computes the same on one thread,
  so wasm32 needs no threads). A value outside the general bounds (64 MiB to 1 GiB, 3 to 10, 4) is `ProfileFormat` before any KDF
  runs. A value inside them but above **this device's** maximum is **`ProfileKdfTooLarge`**, named, before any KDF runs (the
  parameters are public: the code leaks nothing), so a desktop export at 1 GiB on a phone says why it cannot open.
- **Out of memory** (argon2 returns `OutOfMemory`, it does not abort) is **`ProfileKdfOutOfMemory`**, never `ProfileOpen` or
  `ProfileImportOpen`.
- Every Argon2id run goes through the profile layer's own heavy limiter (§11), one at a time by default.
- **Tests** run a test-only parameter set (m 8 MiB, t 1) behind the feature `test-hooks` (never in a release build; the build check
  of CLI-SDK-01's feature tree refuses it there), so suites do not pay 64 MiB per CLI command.

### 7.6 The passphrase, the first secret, biometrics

- **The profile passphrase.** User-chosen, never generated (CLI-SDK-04); keyed in its RFC 8265 OpaqueString form (CLI-PQV-07's
  Change); the rule (at least 8 characters, not digits only; `ProfilePassphraseWeak`) is counted on that same form, the one that is
  keyed. Never stored, never kept after the wrap opens. A wrong passphrase and an altered wrap are both `ProfileOpen`.
- **Unprotected until the first secret** (O5). A new profile is `unprotected`, its `g0` holding settings only. Every call that would
  create a secret (`generate`, `import_words`, `derive_child`, `derive_from_signature`, `derive_from_key`, `import_key`,
  `create_passkey_key`, `create_se_key`, an app core's first key or record) on it is refused `ProfilePassphraseRequired` before any
  work; the client asks for the profile passphrase and, separately, the seed's vault passphrase (two entries, Q-UP1), calls
  `set_passphrase` (§7.3), then retries. A protected profile never returns to unprotected (`Argument`).
- **Biometric unlock, opt-in** (O4). `enable_platform_unlock(passphrase, policy)` on an open, visible, protected profile adds the
  `platform` wrap on this device: the Keychain / Android Keystore key `scaas.profile.<id>.unlock` under a policy that **must** have
  `biometry_current_set` and `invalidated_by_enrollment` both true (else `Argument`: no passcode fallback, no "no presence"); the
  secret is refused if the app left the lent buffer all zero (`prf.rs`'s `written` check, `AuthenticatorRefused`). Off by default, per
  profile and per device. The text at enable says: "every fingerprint or face enrolled in this OS account opens this profile on this
  device" (O11). An enrollment change invalidates the key; the passphrase remains. Desktop Linux has passphrase only.
  `disable_platform_unlock` drops the wrap and the key. **Platform unlock never reaches a hidden profile**: `enable_platform_unlock`
  on a hidden profile is `Argument`, and `hide()` drops an existing platform wrap and its key in the same re-write.

## 8. Hidden profiles (CLI-UPR-08, CLI-UPR-13; SPECIFIED)

- **`create_hidden(name, passphrase)`** makes a profile protected from its first write and sealed as hidden; **no index row is
  written, ever**. `hide()` on an open, protected, visible profile seals it as hidden and drops its row; residual, stated: the name
  was in the index before, and earlier copies of that file (old disk blocks, backups) and shell history may keep it; a rename after
  hiding is the remedy. `show()` seals it as visible and writes its row.
- **No duplicate.** Before `create_hidden`, an import as hidden, a hidden profile's rename or its passphrase change, the SDK runs the
  search below with the new (name, passphrase); a match is `ProfileNameTaken` (it tells nothing to someone who does not hold both).
- **Opening a hidden profile** takes its name and passphrase, both typed, both secret inputs (`SecretBytes`; the name never echoed,
  never on a command line, §13). The SDK, reading without any instance lock:
  1. lists `p/` and takes the **candidates**: every directory named by a UUID that has no row in the index (`.tmp-*`, tombstones and
     `.journal` are not candidates); more than **16** candidates is **`ProfileSearchTooLarge`** before any run (the count is public on
     disk);
  2. runs **max(candidates, 4)** KDF runs: each candidate with a usable envelope (protected, `id` equal to its directory, parameters
     within this device's maximum) at **its own** parameters, then the wrap, then `name_key` of the sealed name against the typed
     one; a candidate without one (missing, unreadable, unprotected, above this device's maximum, a mismatched id) costs one run at
     the default parameters and never stops the search; dummy runs at the default parameters fill up to four; **no early stop**;
  3. on exactly one match takes that directory's instance lock (`ProfileInUse` if held, which only a holder of the name and
     passphrase can provoke), re-reads its envelope under the lock and opens it; zero matches or **more than one** is `ProfileOpen`,
     as are every other failure: no such name, a wrong passphrase, no hidden profile at all.
- **The name is a label, not key material** (Q-UP7): not bound into the KDF; a rename re-wraps nothing.
- **Equal time, exactly what holds:** a failed open costs the same for zero to four candidates **when every candidate is at the
  default parameters**. A candidate at raised parameters makes every hidden open slower by its extra cost, and more than four
  candidates add one run each: a screen observer then learns that some unlisted directory exists or has raised parameters, which the
  disk tells anyway. The total work is bounded by 16 runs at this device's maximum.
- The prompt "Open another profile" is always offered. A hidden profile writes nothing that names it outside its directory (not
  `last`, not a recent list); its name is never drawn (the TUI and the app show "Hidden profile").
- **A planted row** that points at a hidden profile only makes the hidden prompt miss it (a denial, not a disclosure); the open
  through the row is refused and drops the row (§6), and the on-demand rebuild drops every protected row.
- **Limit, stated plainly:** hidden from the list, **not deniable on disk**: its directory, its UUIDv7, the count and sizes of its
  items, its keychain items (named by the id) are visible. Nothing stronger is offered (Q-UP9).

## 9. One instance per profile (CLI-UPR-06, CLI-UPR-14; SPECIFIED)

- **The lock.** Opening a profile by its id takes an exclusive **non-blocking** OS advisory lock on `p/<id>/instance.lock`
  (`File::try_lock`: `flock` on Unix, `LockFileEx` on Windows; FileStore's item locks use the blocking `File::lock` of the same
  family) before its envelope is read, and holds it until the profile is locked or the process ends. A held lock is **`ProfileInUse`**
  at once. The hidden search reads candidates without a lock and locks only the match (§8). `list()` reads no lock.
- **No stale lock.** The OS releases an advisory lock when its process ends, by exit, crash or kill; nothing is written into the
  file (no PID, no time), so there is no stale-lock rule and no race between instances deciding one is stale.
- **Local filesystems only** (NFS and SMB locks are not reliable; stated, not detected).
- **Browser:** Web Locks (`navigator.locks.request(id, {ifAvailable: true})`), PLANNED with the wasm store.
- **Mobile:** one app process holds the lock. An app extension (iOS AutoFill, an Android autofill service declared in its own
  process) is a second instance and is refused while the app has the profile open (Q-UP4, for now). (Not tested here: an iOS
  extension cannot reach the app's private directory at all, and Android runs an autofill service in the app's process unless it is
  declared otherwise.)
- **Existing rule changed when built.** SDK spec §6.3 and CLI-SDK-17 say the CLI, `scaas-tui` and the app may share one data
  directory under the keystore's lock. With profiles they share the root and the index, never an open profile: a CLI command on a
  profile the TUI has open is `ProfileInUse`, a command that only reads included (Q-UP3). The keystore's store lock, `rev` compare and
  `keystore.prev` stay, as defence in depth.
- **Instances of different profiles** share no memory, socket, pipe, D-Bus name, shared file or cache: each has its own `Sdk`, runtime,
  Matrix login and store, PqChat device id and RPC pools. They meet only where two machines would: the chains through the node lists
  (ARCH-POS-15), the gateways, the Matrix homeserver and PqChat's contract state. What they share on the machine is read-only or
  separated by id: the build's chain profiles, the index (written under the root lock), the OS keychain (items named by id).

## 10. Lifecycle (CLI-UPR-15, CLI-UPR-20; SPECIFIED)

Every step that touches the root runs under the root lock; every step inside a profile under its instance lock.

| Action | Needs | What happens |
|---|---|---|
| **start-up clean-up** | the root lock | remove `p/.tmp-*`; finish or undo `p/.journal` (below); remove tombstones and their keychain items; for each profile not open elsewhere (its instance lock taken with `try_lock`, skipped if held), roll back a `profile.envelope.next` and remove stale generations (§7.3); a profile directory without an envelope is **reported** (`Event::ProfileDamaged`, no name), **never removed** |
| **first run** | no index, `p/` empty or absent, no legacy items (§12) | "default" is created (unprotected) and opened (O5) |
| **create** | a free visible name, fewer than 32 directories | write `p/.journal` `{op: "create", id}`; build `p/.tmp-<random>/` with its unprotected envelope (clear name) and empty `g0/`; rename it to `p/<id>/`; add the row; remove the journal. Journal found at start: `p/<id>/` present and unprotected → add its row from the clear name; present and protected (an import) → leave it unlisted, listed at its first open if sealed visible; absent → nothing; then remove the journal |
| **create hidden** | name and passphrase, no duplicate (§8) | as create, protected and sealed hidden from the first write, no row |
| **open** (by id) | the instance lock; the passphrase, or the platform unlock if enabled | envelope bounded and refused by state (§7.1), `DEK_p` unwrapped, the row checked against the sealed label (§6), `last` written if it changed, settings read, the profile's `Sdk` opened (§11) |
| **open** (hidden) | name and passphrase | §8 |
| **lock** | — | `vault.lock_all()` on the profile's `Sdk` (every seed and hidden set; review A-8: today's `lock_all` misses a hidden set opened on a seed that is not unlocked, fixed in code on branch `fix-lock-all-hidden`, which this lock relies on), key-locked keys closed, then the profile's stores refuse every call (`ProfileLocked`), the profile arena is destroyed, the Matrix client is closed, the instance lock released; the client clears its view models and what it put on the clipboard (CLI-TUI-14). The `Sdk` object may outlive the lock in a binding's `Arc`; every call on it then fails |
| **switch** | — | lock, then open the other (O7); nothing is carried over |
| **rename** | open; for a hidden profile no duplicate (§8) | re-seal `label` (one envelope write, same `DEK_p`); a visible profile's row rewritten |
| **hide / show** | open, protected | §8 |
| **passphrase, parameters** | open | §7.3 |
| **delete** (open) | the name typed again; with any `backup: pending` seed also `ConfirmDeleteUnbacked` | `delete_preview()` lists the seeds and how many lack a backup; then: rename `p/<id>/` to the tombstone `p/<id>.deleted/` (one atomic step), drop the row, remove the keychain items, remove the tombstone. A crash at any step leaves a tombstone, which start-up finishes |
| **delete** (locked, visible; a lost passphrase) | the instance lock, the name typed again, and `ConfirmDeleteUnreadable` | the same steps without opening; the client says plainly: "this profile's data cannot be opened and will be lost; seeds return only from their words or their sealed backups" |
| **export / import** | §10.1 | §10.1 |

A lost profile passphrase loses the profile (stated): no recovery path exists; seeds return from their words or their sealed backups
(SDK spec §6.11). A **hidden** profile whose passphrase is lost cannot be named, so no call deletes it; it stays as an unlisted
directory, costs one run in every hidden search and counts toward 32; the user removes its directory by hand, and no call deletes unlisted directories (owner 2026-11-27, Q-UP10). The last profile may be deleted; the next start
creates "default" again (O5).

### 10.1 Export and import of a whole profile (CLI-UPR-17, CLI-UPR-18; SPECIFIED; owner Q-UP5)

**Inside the file** (all of it under the seal; the narrowing marked * is the owner's ruling of 2026-11-27, Q-UP11):

| Part | Content |
|---|---|
| the label | the profile's name and its hidden flag, **not its id** (CLI-UPR-10) |
| the store items | `keystore` (every seed vault and every key-locked vault sealed as today under its own passphrase, MAC and `rev` unchanged) and `sdk.state`, whose operations in flight are imported marked `imported` and followed only on the user's word |
| the settings | the chain-profile settings (named endpoints with their `first` marks, a stronger policy, lowered caps, the default chain profile), the idle lock and clipboard choices; **credential references are omitted** * (they name another machine's files and variables) |

**Never inside:** the instance lock and every `*.lock`; the envelope, `DEK_p` and the profile passphrase; keychain items (anchors,
platform keys, PqChat's device anchor); **`keystore.prev`** * (it may hold a seed removed in the last write); **the `pqchat` part** *
(CLI-PQC-09: a device-bound cache with no source of truth; after import PqChat recovers from contract state with a new device id,
so no counter, version floor, acceptance or pending envelope is ever imported); every cache (PqVault's offline cache, the Matrix store
and login); temporary files; the id; the release chain profiles.

**The file** (proposal for the bytes; vectors in clientkeys and `ua-rs` before code):

```text
magic "SCAASPX1" (8 bytes) ‖ be32 header length ‖ header (canonical JSON) ‖ chunk_0 ‖ … ‖ chunk_last
header = {"format":"scaas.profile-export","v":1,"kdf":{"alg":"argon2id","v":1,"m":65536,"t":3,"p":4,"salt":"<16 bytes, base64>"},"nonce_prefix":"<7 bytes, base64>","chunk":1048576}
chunk_i = AES-256-GCM-SIV(K_x, nonce = nonce_prefix ‖ be32(i) ‖ last_flag, AD = lp("scaas.profile-export") ‖ the header bytes ‖ be32(i), plaintext_i) ‖ tag
payload = be32 label length ‖ label JSON ‖ be32 settings length ‖ settings JSON ‖ for each item: lp(item name) ‖ be32 length ‖ bytes
```

- **Chunked seal (STREAM).** The payload is cut into 1 MiB chunks; chunk `i`'s nonce is the file's random 7-byte prefix, `be32(i)` and
  a last-chunk flag byte (`0x01` on the final chunk, `0x00` otherwise), so a truncated, reordered or extended file fails. The salt and
  the prefix are fresh per file. The header is in every chunk's associated data. Built in `ua-rs` (CLI-SDK-01).
- **Size.** The payload is at most **64 MiB** (a file of at most 64 MiB + 16 bytes per chunk + 4 KiB of header). Export refuses a
  larger profile with **`ProfileExportTooLarge`** rather than writing a file no device can import; import refuses a longer file before
  the KDF runs.
- **Verify, then parse.** No byte of a chunk is parsed before its tag verifies; parsed items go to the new profile's temporary
  directory only, and nothing is committed before the final chunk verified and every item validated.
- **Export** needs the profile open and protected, the profile's name typed again **and the profile passphrase** (checked against
  the `pass` wrap; `ProfileOpen` if wrong), and the export passphrase typed twice (the profile passphrase's rule; the client says the
  file is meant to leave the device, so a passphrase of its own is better). Native: written to a path the caller names, created new
  (`O_CREAT | O_EXCL`, mode `0600`), never through an existing file or a symlink (`Argument`); mobile and wasm: chunks handed to the
  platform's share sheet or file picker.
- **Import always makes a new profile with a new UUIDv7** (the file holds no id, so it neither overwrites nor matches an existing
  profile). Inputs: the file, the export passphrase, a new profile passphrase (protected from the first write, O5), a name if the
  file's is taken by a visible profile (`ProfileNameTaken`); a hidden file is imported hidden after the duplicate check (§8);
  `ProfileLimit` at 32. The client shows the file's name and hidden flag and asks the user to confirm before anything is written.
- **Settings at import keep only what cannot weaken:** a stronger RPC policy, lowered caps and the default chain profile are kept;
  **every named endpoint, every `first` mark, the idle lock and the clipboard choice are dropped unless the user confirms each one by
  itself** in the import review (an endpoint shown by label and host, CLI-RPC-11). CLI-TUI-06's refusals hold for what is kept.
- **Errors.** Everything after the header (a wrong passphrase, a changed byte, a truncated file, a refused item) is one error
  `ProfileImportOpen` to the user, with nothing written. Header refusals (magic, format, version, parameters outside the general
  bounds) are also `ProfileImportOpen` to the user, with a distinct reason in the local log; parameters above **this device's**
  maximum are `ProfileKdfTooLarge` and out of memory `ProfileKdfOutOfMemory` (§7.5). The new profile is built under `p/.tmp-*`, under
  the journal of §10; start-up removes what a crash left.
- **After import.** Seeds unlock with their own passphrases; key-locked keys with theirs; PqChat makes a new device id and recovers
  from contract state (CLI-PQC-09); PqVault rebuilds its cache from chain; the Matrix login is new.
- **Residual, stated.** Importing a profile that still exists elsewhere makes two profiles holding the same seeds; the client says
  so. A file is as strong as its export passphrase; the seed and key vaults inside keep their own. A file someone else made and
  handed over with its passphrase carries that person's seeds and accounts: the import review shows the name, and the client says
  "funds sent to addresses of an imported profile belong to whoever made its seeds".

## 11. SDK surface (CLI-UPR-02, CLI-UPR-22; SPECIFIED; a sketch for the plan)

A module `user_profile` (feature `user-profile`, which pulls `ua-rs`'s existing `argon2` 0.6.0 path; no new crate):

```rust
pub struct ProfilesConfig {
    pub root: ProfileRoot,                               // where profiles live
    pub authenticator: Option<Arc<dyn Authenticator>>,   // platform unlock before any Sdk exists
    pub limits: Limits,                                  // its own heavy limiter for Argon2id
}
pub enum ProfileRoot { Dir(String), Stores(Arc<dyn ProfileStores>) }   // native FileStore root, or the app's own stores (mobile)
#[async_trait]
pub trait ProfileStores: Send + Sync {                   // implemented by an app on mobile
    async fn index(&self) -> Result<Arc<dyn SecureStore>, StoreError>;
    async fn profile(&self, id: String, generation: u64, part: String) -> Result<Arc<dyn SecureStore>, StoreError>;
    async fn instance_lock(&self, id: String) -> Result<Arc<StoreLock>, StoreError>;  // non-blocking: Conflict when held
    async fn ids(&self) -> Result<Vec<String>, StoreError>;
    async fn remove(&self, id: String) -> Result<(), StoreError>;
}
impl UserProfiles {
    pub async fn new(config: ProfilesConfig) -> Result<Arc<UserProfiles>, SdkError>;  // start-up clean-up, rebuild, migration
    pub async fn list(&self) -> Result<Vec<UserProfileInfo>, SdkError>;          // visible: { id, name, protected }; Debug redacts id
    pub async fn create(&self, name: String) -> Result<UserProfileInfo, SdkError>;
    pub async fn create_hidden(&self, name: Arc<SecretBytes>, passphrase: Arc<SecretBytes>, kdf: Option<KdfParams>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn open(&self, id: String, unlock: Option<ProfileUnlock>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn open_hidden(&self, name: Arc<SecretBytes>, passphrase: Arc<SecretBytes>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn delete_locked(&self, id: String, confirm: ConfirmDeleteProfile, unreadable: ConfirmDeleteUnreadable) -> Result<(), SdkError>;
    pub async fn rebuild_index(&self, confirm: ConfirmRebuildIndex) -> Result<(), SdkError>;
    pub async fn import(&self, source: ImportSource, export_passphrase: Arc<SecretBytes>, profile_passphrase: Arc<SecretBytes>, name: Option<String>, keep: ImportChoices) -> Result<UserProfileInfo, SdkError>;
}
pub enum ProfileUnlock { Passphrase(Arc<SecretBytes>), Platform }
pub enum ImportSource { Path(String), Bytes(Vec<u8>) }   // Bytes: at most the 64 MiB bound
impl UserProfile {
    pub async fn sdk(&self, config: SdkConfig) -> Result<Arc<Sdk>, SdkError>;   // the profile opens and keeps its Sdk; `config.store` is ignored
    pub fn part_store(&self, part: ProfilePart) -> Result<Arc<dyn SecureStore>, SdkError>;  // pqvault; pqchat through its adapter
    pub fn matrix_store(&self) -> Result<MatrixStore, SdkError>;                // its directory and its store key (the one key that crosses)
    pub async fn settings(&self) -> Result<ProfileSettings, SdkError>;  pub async fn set_settings(&self, s: ProfileSettings) -> Result<(), SdkError>;
    pub async fn set_passphrase(&self, p: Arc<SecretBytes>, kdf: Option<KdfParams>) -> Result<(), SdkError>;
    pub async fn change_passphrase(&self, old: Arc<SecretBytes>, new: Arc<SecretBytes>, kdf: Option<KdfParams>) -> Result<(), SdkError>;
    pub async fn enable_platform_unlock(&self, p: Arc<SecretBytes>, policy: KeyPolicy) -> Result<(), SdkError>;
    pub async fn disable_platform_unlock(&self) -> Result<(), SdkError>;
    pub async fn rename(&self, name: Arc<SecretBytes>) -> Result<(), SdkError>;
    pub async fn hide(&self) -> Result<(), SdkError>;  pub async fn show(&self) -> Result<(), SdkError>;
    pub async fn delete_preview(&self) -> Result<DeletePreview, SdkError>;
    pub async fn delete(self: Arc<Self>, confirm: ConfirmDeleteProfile, unbacked: Option<ConfirmDeleteUnbacked>) -> Result<(), SdkError>;
    pub async fn export(&self, confirm: ConfirmExportProfile, profile_passphrase: Arc<SecretBytes>, export_passphrase: Arc<SecretBytes>, kdf: Option<KdfParams>, target: ExportTarget) -> Result<(), SdkError>;
    pub async fn lock(self: Arc<Self>) -> Vec<String>;   // the abandoned hidden operations of every seed
}
impl Vault {   // the key lock (§7.4); ImportKey gains key_passphrase: Option<Arc<SecretBytes>>
    pub async fn unlock_key(&self, seed: SeedId, key: ImportedKey, key_passphrase: Arc<SecretBytes>) -> Result<(), SdkError>;
    pub async fn lock_key(&self, seed: SeedId, key: ImportedKey);
    pub async fn lock_key_separately(&self, seed: SeedId, key: ImportedKey, key_passphrase: Arc<SecretBytes>) -> Result<(), SdkError>;
}
```

New codes (CLI-SDK-13's naming): `ProfileInUse`, `ProfileOpen`, `ProfileNameTaken`, `ProfileNameInvalid`, `ProfileLimit`,
`ProfilePassphraseRequired`, `ProfilePassphraseWeak`, `ProfileFormat`, `ProfileVersion`, `ProfileKdfTooLarge`,
`ProfileKdfOutOfMemory`, `ProfileSearchTooLarge`, `ProfileImportOpen`, `ProfileExportTooLarge`, `ProfileLocked`, `KeyLocked`; events
`ProfileIndexMismatch`, `ProfileRollback`, `ProfileDamaged`. No code, event or `Debug` carries an id, a name, a passphrase or a path.
The `ua-rs` calls (the profile arena, the Argon2id wraps, the item seal and HMAC name, the label seal, the export chunk seal, the
dummy run) and the two formats need vector rows in clientkeys and `ua-rs` before code (AGENTS.md: byte formats everywhere at once);
the dummy run has no known answer and is checked by a count test.

## 12. Migration from today's single store (CLI-UPR-11; SPECIFIED)

Every chain is test-only, so **a one-time move into "default" is enough**; no old-layout reader and no compatibility path are kept.

- **Source, exactly:** the CLI's data directory as today on every OS: `$XDG_DATA_HOME/scaas`, else `$HOME/.local/share/scaas`
  (`clients/scaas-cli/src/config.rs`; on Windows `HOME` is normally unset and there was no store), and its overlay at
  `$XDG_CONFIG_HOME/scaas/overlay.json`, else `~/.config/scaas/overlay.json`. On macOS and Windows the new root (§5) differs from
  that path; on Linux it is the same directory.
- **When:** at `UserProfiles::new`, under the root lock **and** the legacy `keystore.lock`, only when the legacy items (`keystore`,
  `keystore.prev`, `sdk.state`) exist at the source **and** `p/` holds no profile directory; once started, it resumes only into the
  profile whose envelope says `migration: pending`. A dropped `keystore` at the root of a root that already has profiles is ignored
  and reported, never migrated.
- **Steps:** (1) create "default" with `migration: pending` (unprotected, as at create, its row written); (2) move each legacy item
  into its `g0/` by `rename(2)` (same filesystem; copy, `fsync`, then remove across filesystems); re-name the keychain anchor and a
  seed's platform key under the id, or rewrite the anchor from the moved container (as `accept_rollback` writes it); move the overlay
  into `settings`; (3) clear `migration`. Each step is idempotent: an item already moved is absent at the source. A process of the old
  binary still running is held off by the legacy `keystore.lock`, and its later writes at the old path are reported at the next start.
- A migrated "default" holds secrets while unprotected, the one case: every `vault` and `app_core` call on it is refused
  `ProfilePassphraseRequired` until `set_passphrase` seals it (§7.3: the plain `g0` is removed only after the commit).

## 13. Per-client notes (CLI-UPR-16; SPECIFIED)

- **scaas-app desktop.** A start screen lists the visible names (`last` preselected) and always offers "Open another profile" (name
  and passphrase, the name field masked). A menu Profile → Lock, Switch, Rename, Hide / Show, Change passphrase, Export, Import,
  Delete. A second launch on an open profile shows "This profile is open in another window" (`ProfileInUse`).
- **scaas-app mobile.** One process; the switcher in settings; the app gives its own stores (`ProfileRoot::Stores`); biometric
  unlock opt-in per visible profile on this device; the seeds' auto-lock on background as today; app extensions refused while the app
  has the profile open (Q-UP4); export through the share sheet, import from a picked file.
- **scaas-tui.** `--profile <name>` opens a visible profile; `--profile-hidden` asks for the name and the passphrase on the terminal
  without echo (CLI-TUI-16's means); with neither, a picker, else the one profile. An action `profile` (lock and switch) on every
  screen; the status line shows the visible name or "Hidden profile". The idle lock locks the seeds, not the profile (Q-UP6). At lock
  and switch the TUI clears an OSC 52 clipboard value it set.
- **CLI `scaas`.** `--profile <name>`, else the profile named "default"; **the CLI never follows `last`** (the apps' choice), and it
  prints the profile it uses on stderr on every command (`profile: <name>`, or `profile: hidden`). `--profile-hidden` reads the name
  and the passphrase from the terminal without echo or from `--profile-name-fd` and `--profile-passphrase-fd`; **one descriptor per
  secret**: `--profile-passphrase-fd` (the profile), `--passphrase-fd` (a seed's vault passphrase, as today), `--key-passphrase-fd` (a
  key lock), `--export-passphrase-fd` (an export file); never the command line or the environment. Commands `scaas profile list |
  create | create-hidden | rename | hide | show | passphrase | platform-unlock | settings (show | set | import <file>) | export <file> |
  import <file> | delete | rebuild-index`; `settings import <file>` replaces the withdrawn `--overlay <file>` and applies CLI-TUI-06.
  Each command is one instance (`ProfileInUse` while the TUI or the app has the profile open). **Stated limit:** `--profile <name>`
  is visible in process listings to every local user, and `--profile-hidden` there tells that this user has a hidden profile. **The
  chain-profile rename (§15) lands first**, so `--profiles <file>` and `--profile <name>` never sit one letter apart.
- **Browser (wasm), PLANNED.** One IndexedDB database per profile named by its id, the index in its own database, Web Locks, the same
  sealed adapter and parameters up to 256 MiB.

## 14. Threat model (SPECIFIED)

| Adversary | Learns or can do | Bound |
|---|---|---|
| another OS user on the machine | nothing on Unix (root `0700`, tightened at open; files `0600`); on Windows the default ACL of `%APPDATA%`; a process listing shows a visible name given by `--profile <name>` and that `--profile-hidden` was used (§13) | OS permissions; an administrator is out of scope |
| a stolen disk, a copied home directory, a backup | the visible names and `last`; the number of profile directories; each id's creation time (UUIDv7, hidden ones included); per profile the number and sizes of its items and their outer revisions; an unprotected profile's settings and name; **no item name** (HMAC file names, §7.2) | every protected item and label sealed under `DEK_p` behind Argon2id per profile; seed and key vaults also behind their own passphrases; full-disk encryption recommended |
| an offline guesser of one profile's passphrase | one Argon2id run per guess at that profile's parameters; a success opens that profile's sealed store and none of another's, and no seed, imported key or key-locked key | passphrase strength (§7.6), parameters raisable per profile; per-item passphrases (§7.4) |
| someone at an unlocked OS session on a **shared OS account**, with platform unlock on | **opens the profile with any enrolled biometric** and reads what §7.4 lists (settings, chain-profile settings, keystore public fields, operation history, PqChat store, Matrix store, PqVault cache) | **accepted risk** (owner O11, §14.1); mitigation: seeds and imported keys behind their own typed passphrases, never opened by platform unlock; the text shown at enable |
| a second instance (the same user's other window or command) | refused: `ProfileInUse` | the OS lock (§9); a malicious process of the same user is out of scope |
| someone watching the screen | the visible names only; no hidden name drawn; the hidden prompt always present; a failed hidden open costs the same for zero to four candidates at the default parameters | §8 |
| someone who writes the root or a profile directory (the other person on a shared account, a restore) | may rename or plant index rows (a planted row on a hidden profile hides it from the prompt, never discloses it); may delete or corrupt files (a denial); may put back old copies; may replace a whole envelope with an unprotected one (a different, empty profile) | §6 (rows checked against the sealed label, hidden rows refused, rebuild); §7.1 (refusals by state; the keychain `protected` marker where there is one); §7.2 (manifest and anchor) |
| someone who puts back an older copy | one item or the manifest: `ProfileRollback` (per item, §7.2); the keystore: `KeystoreRollback` as today; **the whole directory at once on desktop Linux**, whose anchor file sits in the same directory: **not seen** (stated) | the keychain anchor where there is one; an old envelope with the old passphrase opens nothing written after a passphrase change (`DEK_p` rotated, §7.3) |
| a network observer, an RPC node, a gateway, the Matrix homeserver | that several identities use one IP address and timing; never a profile id or name | non-goal (§2); ids never leave the device (§4) |
| a holder of an export file | the format, the KDF parameters, the chunk count and the length; nothing else without the export passphrase | Argon2id at the file's parameters per guess; inside, the seed and key vaults behind their own passphrases; no id, no PqChat state, no credential reference (§10.1) |
| someone who alters an export file, or hands the user a crafted one with its passphrase | an altered file fails as one error, nothing written; a crafted file brings only its own seeds and accounts (said at import), and no endpoint, `first` mark, idle-lock or clipboard choice without the user's confirm of each, no credential reference, no PqChat state, no operation followed without the user's word | §10.1 |
| a decryption-oracle attacker (ARCH-POS-13) | nothing: the profile layer opens only the user's own envelopes and items, and export files the user picks, with passphrases the user types, and answers only the local user; it decrypts no ciphertext that arrives from the network, sends nothing before a whole import has opened, validated and been committed, follows no imported operation and processes no imported envelope without the user's word | every failure of an open, a hidden search or an import is one code to the user |

### 14.1 Accepted risks (owner)

- **Platform unlock on a shared OS account** (owner 2026-11-27, O11): everyone enrolled on that OS account opens the profile by
  biometrics, and reads what §7.4 lists. Accepted; mitigated by per-item passphrases (§7.4), never opened by platform unlock.
- **The profile id's creation time** (O9, §4).

## 15. The chain-profile rename (CLI-UPR-01; a later task, PLANNED; nothing renamed here)

`ChainProfile` is already the code type (`clients/scaas-sdk/src/config.rs:65`, generated as `ChainProfile` in every binding) and SDK
rules §10 is already titled "Chain profiles": the type stays. What changes, in one commit across every place below (no on-chain
byte, no EIP-712 domain, no node API changes; the text fields of one vector file are regenerated, below):

| Kind | Today | After |
|---|---|---|
| SDK config fields | `SdkConfig.profiles` (`config.rs:867`), `BindingConfig.profiles` (`binding.rs:926`), the JS config's `profiles` (`src/wasm/js.rs:792`, hand-written), so every generated binding | `chain_profiles`; bindings regenerated |
| SDK error code | `ProfileMismatch` (stable code, CLI-SDK-13; about 50 lines in `src` and tests, every binding's error enum, docs) | `ChainProfileMismatch` (Q-UP8) |
| SDK internals | `Chain.profile` and locals `profile` / `profiles` of `ChainProfile` type in `src/**` | `chain_profile` / `chain_profiles` |
| Cargo features | `dev-profiles` (`clients/scaas-sdk/Cargo.toml`, `clients/scaas-cli/Cargo.toml`); CI's `--features dev-profiles` (`.github/workflows/ci.yml` lines 132, 133, 1503, 1529, 1530, 1532); `scripts/check_test_features.py` | `dev-chain-profiles` everywhere at once (else the `scaas-cli` job fails on an unknown feature) |
| test files | `clients/scaas-sdk/tests/evm_profiles.rs` (`[[test]] name = "evm_profiles"`); `clients/scaas-rpc/tests/evm_profiles.rs` | `evm_chain_profiles.rs` |
| CLI flag and field | `--profiles <file>` (`main.rs:575`), `Globals.profiles` (`main.rs:77`) | `--chain-profiles <file>`, `chain_profiles` |
| CLI codes | `ProfilesPinned`, `ProfilesRefused` | `ChainProfilesPinned`, `ChainProfilesRefused` |
| CLI code names | `parse_profiles`, `RELEASE_PROFILES`, private `Profiles` / `Profile` (`config.rs:16, 36, 67, 213`) | `parse_chain_profiles`, `RELEASE_CHAIN_PROFILES`, `ChainProfilesFile` / `ChainProfileRow` |
| CLI data | `clients/scaas-cli/profiles/release.json`, top-level key `"profiles"`; the overlay's credential field `"profile"` | `chain-profiles/release.json`, `"chain_profiles"`; `"chain_profile"` |
| `scaas-rpc` runner | `runs/2026-11-22-evm-probes.py`'s own `--profile <key>` (a chain profile) | `--chain-profile <key>` |
| EVM chain data | `smartcontracts/evm/src/chains/<key>/profile.json` (18 files), `script/forkcheck.py` (29 lines), `script/test_forkcheck.py` (41), the README's "Chain profiles" row and "EVM profiles" heading | `chain-profile.json`; the scripts and prose follow |
| clients | `clients/clientkeys/src/evm.js` (8 lines), `clients/ua-rs/src/wallet/policy.rs` (3) | "chain profile" |
| vectors | `smartcontracts/vectors/ua/sign.json` (4 text fields, e.g. "a DEX off the profile") | regenerated by its generator from the renamed source text, never hand-edited |
| mutant runner | `clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t22-mutants.py` (matches source text holding `dev-profiles` and `--profiles`) | its patterns follow |
| TUI (docs only; no code yet) | `tui.toml` "the default profile", per-profile caps (spec §10), "release profiles" (CLI-TUI-11), `--profiles`, `dev-profiles` | `default_chain_profile`, caps per chain profile, "release chain profiles", `--chain-profiles`, `dev-chain-profiles` |
| prose | "profile" meaning a chain's pinned data | "chain profile" |

**Not renamed** (not a chain profile): Cargo `[profile.*]` build sections; Foundry's `[profile.*]` sections and `FOUNDRY_PROFILE`;
"browser profile" (`signers-clientkeys.md`, `app.md:368`); the node's own `profile` fields (`integration.md:93`, `:764`) and `pqz` job
profile (`integration.md:176`); "profiling"; `smartcontracts/evm/legacy/` (never edited).

**Where the word is used for chain profiles** (lines matching "profile", the exclusions removed; `git grep -ci` at `644ea61a8`):
139 hand-written files and 1,424 lines in the places first listed, plus 117 generated binding files (1,886 lines) that follow by
regeneration, plus the review's additions above (`ci.yml` 10 lines, `check_test_features.py` 1, `scaas-rpc` `tests/evm_profiles.rs`
25, `src/evm.rs` 4, `src/ton.rs` 2, `runs/2026-11-22-evm-probes.py` 9, the EVM chain data and scripts, `evm.js` 8, `policy.rs` 3,
`sign.json` 4, the T22 runner 4).

- `docs/clients/`: `scaas-sdk.md:23`, `scaas-tui.md:11`, `signers-clientkeys.md:11`, `scaas-rpc.md:6`, `app.md:1`,
  `ua-libraries.md:1`; `docs/integration.md:3` (868, 1015, 1153; already "chain profile"); specs and plans:
  `specs/2026-11-17-scaas-sdk.md:87`, `specs/2026-11-17-scaas-tui.md:22`, `plans/2026-11-17-scaas-sdk.md:71`,
  `plans/2026-11-17-scaas-tui.md:10`; also `docs/decisions.md` (141) and `docs/networks/` (85).
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

**The rename task's gate:** a grep over the **whole tree** (not the listed directories) for the renamed identifiers and for
"profile" outside the "Not renamed" list must reach zero at its commit.

### 15.2 Forward notes on rules this spec changes when built

- [CLI-SDK-17](../../clients/scaas-sdk.md#CLI-SDK-17) and SDK spec §6.3: the shared data directory becomes the shared root; an open
  profile is never shared (CLI-UPR-14).
- [CLI-TUI-06](../../clients/scaas-tui.md#CLI-TUI-06): the overlay "one file for the CLI and the TUI" becomes the profile's sealed
  `settings`; the CLI's `--overlay` is withdrawn for `scaas profile settings import`.
- [CLI-TUI-12](../../clients/scaas-tui.md#CLI-TUI-12) and [CLI-TUI-14](../../clients/scaas-tui.md#CLI-TUI-14): the lowered caps and
  the clipboard opt-in live in the profile's `settings`, not `tui.toml`; the clipboard value the TUI set is cleared at profile lock.
- SDK spec §6.9: a sealed item's size bound is the base64 of its plain bound plus 1 KiB, and `rev_of` reads it to that bound;
  `keystore.head` stays unsealed; `StoreError` gains `VaultFormat`, `ProfileLocked`, `ProfilePassphraseRequired`.
- SDK spec §6.7 and CLI-SDK-03: the key lock adds the label form `native-import-locked:<network>:<n>` (§7.4).

## 16. Owner rulings on the open points (owner 2026-11-27, O10)

Every point the frame left open was ruled on 2026-11-27: Q-UP5 in scope now (§10.1), the other eight as recommended.

| # | Question | Ruling | Where |
|---|---|---|---|
| Q-UP1 | At the first secret, the profile passphrase (O5) and the seed's vault passphrase (CLI-SDK-04): one entry or two? | two entries; the client neither suggests nor refuses equal text | §7.6; CLI-UPR-12 |
| Q-UP2 | The profile envelope's KDF parameters | 64 MiB / 3 / 4 as the default, stronger allowed within the bounds, no timing run | §7.5; CLI-UPR-12 |
| Q-UP3 | A second instance only reading (the CLI's `balance` while the TUI has the profile open) | refused (`ProfileInUse`), read-only too | §9; CLI-UPR-14 |
| Q-UP4 | An app extension (iOS AutoFill, Android autofill) while the app has the profile open | refused as a second instance, for now | §9, §13; CLI-UPR-14 |
| Q-UP5 | Profile export / import as one sealed file | in scope now: the profile's store items, its index entry and its settings (chain-profile settings included) in one file; never the OS lock or caches; sealed under a passphrase typed at export with the same Argon2id bounds; a typed confirm; import makes a new profile with a new UUIDv7 (the simplest safe rule, §10.1); a file never overwrites an existing profile; integrity bound in the seal; vectors in clientkeys and `ua-rs` before code | §10.1; CLI-UPR-15, CLI-UPR-17, CLI-UPR-18 |
| Q-UP6 | What the idle lock locks | the seeds, as today | §13; CLI-UPR-16 |
| Q-UP7 | Whether a hidden profile's name is key material | no: a label compared after unwrap | §8; CLI-UPR-13 |
| Q-UP8 | Rename the stable code `ProfileMismatch` | yes, to `ChainProfileMismatch`, in the rename task | §15; CLI-UPR-01 |
| Q-UP9 | Anything stronger than "hidden from the list" | nothing: a non-goal | §2, §8; CLI-UPR-13 |

### 16.1 Owner rulings after the review (owner 2026-11-27)

| # | Question | Ruling | Where |
|---|---|---|---|
| Q-UP10 | A hidden profile whose passphrase is lost can be neither named nor deleted (§10) | as recommended: the app neither names nor deletes it; the user removes its directory by hand; no call deletes unlisted directories (such a call would let anyone at the OS account delete another person's hidden profile without a passphrase) | §10; CLI-UPR-15 |
| Q-UP11 | The narrowing of Q-UP5's content (§10.1, marked *) | as recommended: a profile export leaves out `keystore.prev`, the PqChat store and credential references | §10.1; CLI-UPR-18 |

No open question remains.

## 17. Tests (SPECIFIED; for the plan)

Each negative test has its positive control and its named mutant, which must turn it red (AGENTS.md; runners through
`scripts/mutant_guard.py`). Suites use the `test-hooks` parameter set (§7.5) except the bound tests.

| Group | Test | Positive control | Mutant |
|---|---|---|---|
| lock (§9) | a second `open` in another process is `ProfileInUse`; a SIGKILLed holder leaves a lock the next `open` takes at once; the hidden search locks only the match | two different profiles open side by side | the instance lock dropped; lock taken before the search reads |
| G1 names | no item name and no part name appears in any file name or in any plain byte under `p/` (a pqchat key with a UA and a room id) | the manifest, opened, lists them | the HMAC name replaced by the item name |
| G2 AEAD | two seals of the same (part, name, rev, plaintext) differ; an item moved to another name, part or rev fails | the item in place opens | a fixed nonce; the part or the name left out of the AD |
| G3 state | an envelope's `state` flipped to `unprotected`, a plain item in a protected profile, a sealed item in an unprotected one: each refused by its code; with the keychain marker, an unprotected envelope beside it is `ProfileFormat` | the untouched profile opens | the state check removed; `state` left out of the wrap's AD |
| G4 crash | a crash at each step of `set_passphrase`, `change_passphrase`, create, import and migration leaves the old or the new profile whole, and the next start finishes or rolls back; two processes migrating at once make one "default" | the same actions without a crash | the journal ignored at start; the envelope renamed before the generation is complete; no root lock at migration |
| G5 rollback | an old copy of `settings` (or any item) put back is `ProfileRollback`; an old manifest under the anchor is `ProfileRollback`; after a passphrase change the old envelope with the old passphrase opens no item written after | the current copies open with no event | the manifest's rev not compared; `DEK_p` kept at a passphrase change |
| G6 platform | another profile's wrap, a wrong secret, an all-zero secret, a policy without `biometry_current_set` or `invalidated_by_enrollment`: each refused; enable on a hidden profile is `Argument`; `hide()` drops the wrap | the enabled wrap opens its own profile | the policy check removed; the profile id left out of the wrap's AD |
| G7 hidden | runs counted (not timed) equal max(candidates, 4) for 0, 1, 4 and 5 candidates, a corrupt and an unprotected candidate among them each one dummy run; two matches `ProfileOpen`; a duplicate at `create_hidden` and at import `ProfileNameTaken`; a planted row on a hidden profile: the open through it refused, the row dropped, no name written; `create_hidden` writes no index byte; more than 16 candidates `ProfileSearchTooLarge` | the one match opens | an early stop at the match; a corrupt candidate ending the search; the planted row repaired into the clear; `last` written on a hidden open |
| G8 KDF | parameters below the bounds and above them, each field alone, refused before any KDF (a counter); above this device's maximum `ProfileKdfTooLarge`; a forced allocation failure `ProfileKdfOutOfMemory`, never `ProfileOpen`; a release build refuses `test-hooks` | the default and a raised in-bounds set open | out-of-memory mapped to `ProfileOpen`; the per-device maximum not checked |
| G9 export | export without the profile passphrase refused; the file never holds an id, a lock, a keychain item, `keystore.prev`, a `pqchat` item, a credential reference or a cache (checked on the payload); a truncated, reordered, extended or one-byte-changed file (header included) is `ProfileImportOpen` with nothing written; a crafted file's endpoints, `first` marks, idle lock and clipboard choice are dropped without a confirm; its operations in flight are not followed; a payload above 64 MiB is `ProfileExportTooLarge`; an existing file or a symlink at the export path is refused | the unchanged file imports: a new id, the same seed fingerprints, a new PqChat device id | the last-chunk flag ignored; parse before verify; settings imported whole |
| G10 index, delete | a deleted and a corrupt index are rebuilt (never a first run): unprotected rows back, protected ones listed again at their first open; a crash at each step of delete leaves a tombstone that start-up finishes; a directory without an envelope is reported, never removed; a locked visible profile deletes with `ConfirmDeleteUnreadable` | an intact index lists as before | a missing index treated as a first run; the clean-up removing a directory without an envelope |
| G11 SDK fit | a sealed item at the plain 16 MiB bound reads its `rev` and is written at it; a sealed item that does not open is `VaultFormat` (not `VaultIo`); a call after lock is `ProfileLocked`; `lock` with a hidden set open on a seed that is not unlocked revokes it (A-8's fix) | a small item round-trips | `rev_of`'s 16 MiB cap kept for sealed items; `StoreError` collapsed to `Io` |
| G12 CLI, paths | the CLI ignores `last`; one descriptor per secret; an existing root at `0755` is tightened; a symlinked root is refused; migration reads `$HOME/.local/share/scaas` on macOS | `--profile` names the profile | the CLI following `last` |
| key lock (§7.4) | a key-locked import is not opened by the seed's passphrase unlock, the seed's passkey or platform unlock, or the profile's platform unlock; signing with it locked is `KeyLocked`; `unlock_key` with its passphrase opens it; `lock_key_separately` leaves no `native-import:` vault of that key in the new container | the same key without a key lock opens with the seed | the key vault sealed with the seed's PRF envelope; `unlock` opening every label vault |
| G15 zeroisation | after each call the derived keys and plaintext buffers are wiped (the arena's existing wipe test extended to the profile arena) | — | a key kept past its call |
| vectors | UUIDv7 rows with the timestamp and random bytes as inputs; envelope, item, name, label and export-chunk rows; `name_key` rows (NFC / NFD, a no-break space, case) | clientkeys and `ua-rs` read the same rows | — |
| end-to-end | two instances on one machine, two profiles, a PqChat 1:1 session over a local Matrix homeserver and a local chain | — | — |

## 18. Rule ids

| Id | Rule | Owner |
|---|---|---|
| CLI-UPR-01 | "Profile" on screen, `UserProfile` in code; "chain profile" / `ChainProfile` for a chain's data; the rename a later task, `ChainProfileMismatch` included | yes (O1, Q-UP8) |
| CLI-UPR-02 | in the SDK layer, used by every client | yes (O2) |
| CLI-UPR-03 | many profiles per machine, each its own directory with its store, chat and vault state and settings | yes (O3) |
| CLI-UPR-04 | each protected separately, own passphrase and KDF parameters, biometric opt-in; one opens nothing of another | yes (O4) |
| CLI-UPR-05 | "default" on first run; the passphrase asked at the first secret | yes (O5) |
| CLI-UPR-06 | one instance per profile by a lock file and a named error; instances meet only over network paths | yes (O6) |
| CLI-UPR-07 | switching locks as a seed lock does, then opens the other | yes (O7) |
| CLI-UPR-08 | the list shows names only; a profile may be hidden and opened by typing its name | yes (O8) |
| CLI-UPR-09 | the profile id is a UUIDv7 | yes (O9) |
| CLI-UPR-10 | the id: stable, names the directory, the name a label, never leaves the device, not derived | no |
| CLI-UPR-11 | layout, the index as a cache rebuilt from the envelopes, migration from the exact legacy path | no |
| CLI-UPR-12 | protection: `DEK_p`, the envelope, refusals by state, unprotected until the first secret, the platform wrap | no; Q-UP1, Q-UP2 yes |
| CLI-UPR-13 | the hidden search and `create_hidden`; not deniable on disk | no; Q-UP7, Q-UP9 yes |
| CLI-UPR-14 | the instance lock: non-blocking OS advisory lock, no stale state, the search locks only the match | no; Q-UP3, Q-UP4 yes |
| CLI-UPR-15 | lifecycle: create, rename, hide, delete by tombstone, delete of a locked profile; export and import by CLI-UPR-17 | no; Q-UP10 yes |
| CLI-UPR-16 | client surfaces: `--profile`, `--profile-hidden`, one descriptor per secret, the CLI never follows `last`, pickers | no; Q-UP6 yes |
| CLI-UPR-17 | a whole profile exports and imports as one sealed file | yes (O10, Q-UP5) |
| CLI-UPR-18 | the export file's means: no id, chunked seal, size bound, verify then parse, settings that cannot weaken, the profile passphrase | no; Q-UP11 yes |
| CLI-UPR-19 | the sealed store: AES-256-GCM-SIV with random nonces, framed associated data, HMAC file names, the anchored manifest, key labels, zeroisation | no |
| CLI-UPR-20 | crash safety: the re-seal journal and generations, the root lock, the create journal, tombstones, start-up clean-up | no |
| CLI-UPR-21 | KDF bounds per field and per device, `p` fixed, named refusals, the test parameter set | no |
| CLI-UPR-22 | SDK fit: the profiles config, the profile keeps its `Sdk`, store errors, the sealed size bound, app-core stores | no |
| CLI-UPR-23 | platform unlock on a shared OS account is an accepted risk; each seed and imported key may carry its own passphrase, never opened by platform unlock | yes (O11) |
| CLI-UPR-24 | the key lock's means: the label form, `unlock_key`, `lock_key_separately`, what a platform unlock leaves readable | no |

## 19. Review response (Fable, 2026-11-27: areas A, B, C; the controller's rulings, owner may veto)

| Group | Findings | Applied in |
|---|---|---|
| G1 item names leak | B-1 | §7.2 file names, §14 stolen disk; CLI-UPR-19 |
| G2 AEAD and nonce | B-2, B-13, C-14 | §7.1, §7.2; CLI-UPR-19 |
| G3 envelope state, plain items | B-3, C-5 | §7.1 refusals by state, the residual; CLI-UPR-12 |
| G4 crash safety | A-1, A-2, A-3, B-4 | §7.3, §10 journal, §12 locks; CLI-UPR-20 |
| G5 rollback claims | B-5, C-6 | §7.2 manifest and anchor, §7.3 rotation, §14; CLI-UPR-19, CLI-UPR-20 |
| G6 platform unlock | B-6, C-9 | §7.1 `K_plat`, §7.6 policy and hidden; C-9's residual ruled by the owner (O11, §14.1, §7.4); CLI-UPR-12, CLI-UPR-23, CLI-UPR-24 |
| G7 hidden profiles | B-7, B-8, B-10, B-14, C-3, C-4, C-11 | §6 one name helper, hidden rows refused; §8; §9 lock order; CLI-UPR-13, CLI-UPR-14 |
| G8 KDF bounds and cost | A-11, B-9, C-12 | §7.5; CLI-UPR-21 |
| G9 export and import | A-12, B-11, C-1, C-2, C-8, C-12 | §10.1 (B-11 asked for no streaming; the ruling chose the chunked seal); CLI-UPR-18 |
| G10 index, delete | A-4, A-5, C-7, C-10 | §6 cache and rebuild, §10 tombstones and delete of a locked profile, §12; CLI-UPR-11, CLI-UPR-15, CLI-UPR-20 |
| G11 SDK fit | A-6, A-7, A-14, A-15 | §7.2 size, errors, app cores; §9 `try_lock`; §11; CLI-UPR-22 |
| G12 CLI, paths, OS | A-9, A-10, C-13, C-15 | §4, §5, §12, §13, §14; CLI-UPR-11, CLI-UPR-16 |
| G13 rename list | A-13 | §15; CLI-UPR-01 (list only) |
| G14 forward notes, tests | A-16, A-17, B-16, C-16, C-17 | §15.2, §17, CLI-UPR-15's entry |
| G15 zeroisation | B-12, B-15 | §7.1 key labels, §7.2 zeroisation, the profile arena; CLI-UPR-19 |
| A-8 | `lock_all` misses a hidden set on a locked seed | a code fix on branch `fix-lock-all-hidden`; cross-referenced in §10's lock and §17 |
