# User profiles: many protected local profiles in the SDK layer: design

**Status:** wave 1 BUILT on branch `user-profiles` at `f9a599996` ([plan](../plans/2026-11-27-user-profiles.md) UP1 to UP11
and KH; UNAUDITED): the byte formats and their vectors, `ua-rs`'s `ProfileKeys` and `ExportKey` (feature `key-handles`), the
key-lock label in `ua-rs` and clientkeys, the crate `scaas-profile` and the SDK's `user_profile`. The rest SPECIFIED (wave 2):
platform unlock, the CLI, TUI and app surfaces, the pqchat-core and pqvault-core adapters, the SDK's key-lock calls, the browser
store, the bindings of the surface, the chain-profile rename, the Matrix client closed at lock; each rule's status in
[clients/scaas-sdk.md](../../clients/scaas-sdk.md) §12. A **frame**: the owner's rulings of 2026-11-27 (§1, §16) are fixed; the means are controller
calls (`owner: no`). Fable reviewed the frame twice on 2026-11-27: at `06d9843d5` (three areas, all "approve with fixes") and again
at `fa51e8275` (round 2: no P1, every round-1 finding fixed or partly fixed, new findings from the fixes), then a third time at
`9f2ee89b7` (round 3: area C approve, areas A and B approve with one P1 each, no P0); every finding of the three rounds is applied as the controller's ruling of the same day (§19). No decryption-oracle path was found in either round, and no owner
ruling was reopened. Branch `user-profiles-spec` (from `dev` `644ea61a8`), worktree `.claude/worktrees/user-profiles-spec`. Rule ids
(defined once in [clients/scaas-sdk.md](../../clients/scaas-sdk.md) §12, recorded in [decisions.md](../../decisions.md)
§41): CLI-UPR-01 to CLI-UPR-32. No contract, signed byte format, chain profile or node rule changes; no on-chain byte changes. The
`ua-rs` calls and the two file formats of §7 and §10.1, and the keystore's new vault label of §7.4, are new and need vector rows in
clientkeys and `ua-rs` before code. UNAUDITED.

**Reads** (as at `644ea61a8`): the SDK's vault and store code (`clients/scaas-sdk/src/vault/`: `store.rs` `SecureStore`,
`FileStore`, `MemoryStore`, `rev_of`; `mod.rs` `KeystoreFile`; `seeds.rs` (`import_key`); `unlock.rs`; `prf.rs`; `roots.rs`),
`src/platform.rs` (`KeyPolicy`), `Sdk::open` and `SdkConfig` (`src/lib.rs`, `src/config.rs`), the CLI's data directory and chain-profile
loading (`clients/scaas-cli/src/config.rs`); `ua-rs` `wallet/appkey.rs` (arena scopes, `seal_key`, AES-256-GCM-SIV, Argon2id,
OpaqueString), `wallet/vault.rs`, `wallet/manifest.rs` (label vaults, the backup payload); pqchat-core's `PqChatStore` and its keys;
the SDK spec §6 and rules CLI-SDK-01 to CLI-SDK-06, CLI-SDK-13, CLI-SDK-15, CLI-SDK-17; the TUI spec §10 and CLI-TUI-04, CLI-TUI-06,
CLI-TUI-11, CLI-TUI-12, CLI-TUI-14; hidden sets (SDK spec §6.5, CLI-UAL-18); PqVault's passphrase KDF (CLI-PQV-07, CLI-PQV-10 and its
Change) and biometrics (pqvault spec §14 O7 (b), CLI-PQV-15 (3)); PqChat's recovery from state (CLI-PQC-09); ARCH-POS-13,
ARCH-POS-15. Order of sources: AGENTS.md "Which source wins".

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
| O12 | 2026-11-27 | Q-UP10, Q-UP11 as recommended (§16.1): a hidden profile with a lost passphrase is removed by hand, no call deletes unlisted directories; an export leaves out `keystore.prev`, the PqChat store and credential references. | CLI-UPR-15, CLI-UPR-18 |
| O13 | 2026-11-27 | The user-profile store is its own crate, `scaas-profile`, over `ua-rs` only, so scaas-app's default build (no SDK) holds a profile (its Matrix session key, its settings) with `scaas-matrix`; the SDK depends on it and adds what needs the SDK (§11). | CLI-UPR-02 (Change) |
| O14 | 2026-11-27 | Each profile has its own Matrix: its own logins, session, store, crypto keys and device id, sealed in that profile (the Matrix store key a sealed item); nothing Matrix-side is shared between profiles; one `scaas-matrix` client per open profile; switching profiles closes the current client first. | CLI-UPR-29 |
| O15 | 2026-11-27 | scaas-app's default build links `ua-rs` only with the profile-crypto features; no signing code is compiled into it: `scaas-profile` takes `ua-rs`'s `user-profile` (the new feature `key-handles`: the arena, key handles, AEAD, HKDF, HMAC, Argon2id, `ProfileKeys`, `ExportKey`) and `json`, never `wallet`, `pq`, `signers`, `fam-*`, `zether` or `pqz` (§11). Source: "Owner ruling 2026-11-27 (chat): scaas-app's default build links ua-rs only with the profile-crypto features; no signing code is compiled into it." | CLI-UPR-32 |
| O16 | 2026-11-28 | The label's associated data binds the envelope's revision: `lp("scaas.profile.label") ‖ be16(1) ‖ lp(id) ‖ be64(rev)` (§7.1), and the label is re-sealed at every envelope write. An older envelope written back with its `rev` raised opens its wrap and fails its label at that `rev`: `ProfileRollback` (review F-2). A pinned-format change: clientkeys and the vectors first, then `ua-rs`, `scaas-profile` and the SDK; no old-format reader (test-only chains). | CLI-UPR-12, CLI-UPR-19 |
| O17 | 2026-11-28 | A deleted id keeps a permanent tombstone marker, `p/.tombstones/<id>` (an empty file), written by a delete before its rename and by start before it finishes a tombstone, kept until the user purges the markers (`purge_tombstones` with a confirm). A profile directory under a marked id is refused at start (`Event::ProfileRollback`) and at open (`ProfileRollback`): never listed, searched or opened, its keychain items never used. It closes the two-step put-back of review G-1 (the live directory renamed to its tombstone, start removes it with its keychain items, an old copy put back). | CLI-UPR-15, CLI-UPR-20 |
| O18 | 2026-11-28 | `set_passphrase` on a migrated "default" (`migration: pending`, a keystore moved in) shows the seeds being moved and needs the user's confirm: the SDK's `migrated_seeds()` gives their count and labels from the keystore's public fields, and `set_passphrase(…, Some(ConfirmMigratedSeeds { seeds }))` requires that count; without it, or with another count, `ConfirmationMissing`, nothing written (the crate takes `ConfirmMigratedKeystore` for the same refusal). It answers review G-3: `migration: pending` is not authenticated, so a keystore a root writer planted is never sealed unseen. | CLI-UPR-11, CLI-UPR-12 |
| O19 | 2026-11-28 | The reverse of a strengthening counts as weakening and needs the profile passphrase: a chain profile's `strict_majority` turned off, a lowered cap raised or removed (per chain profile and global), alongside the list's turning the idle lock off or lengthening it and turning the clipboard on (§7.7); the import's filter keeps only what strengthens the defaults (review G-5, A-15). | CLI-UPR-26 |
| O20 | 2026-11-28 | Two instances running `create_hidden` with one (name, passphrase) at once may both pass the duplicate search (no lock is held across a KDF): accepted. A hidden open never picks silently: two or more matches is **`ProfileHiddenAmbiguous`**; `hidden_matches(name, passphrase)` lists them as opaque choices (`HiddenMatch { index, created_ms }`: the place among the matches by id order and the creation time from the UUIDv7, never the id), and `open_hidden_match(name, passphrase, choice)` runs the search again and opens the choice that still holds by place and creation time, else `ProfileOpen` (§8). | CLI-UPR-13 |
| O21 | 2026-11-28 | `ProfileBusy` and `ProfilePartFull` become `StoreError` codes: the store face passes them through by name (they were `Unavailable`), `vault::io` maps each to the `SdkError` of the same name, a foreign or wasm store names them, and every SDK caller sees them (§7.2 "Errors"). | CLI-UPR-22 |
| O22 | 2026-11-28 | The migration's `migration: pending` is cleared at `set_passphrase`'s commit (the re-seal's new envelope carries none), not as a step of the move: an unprotected `g0` accepts the moved keystore only under `migration: pending`, so the flag stays until the seal (§12's step order fixed to the code). | CLI-UPR-11 |

Standing rules applied: secrets never leave the SDK and every KDF, AEAD and MAC runs in `ua-rs` (CLI-SDK-01, CLI-SDK-02); fail closed
with named errors; no decryption oracle (ARCH-POS-13); every RPC consumer takes a list of nodes (ARCH-POS-15); the node is open and
knows nothing of profiles.

## 2. Goals and non-goals (SPECIFIED)

**Goals.**

1. Several people, or one person with several roles (work, personal, a test identity), use one machine and one OS account, each
   profile with its own seeds, keys, chat, vault and settings.
2. Opening, locking and switching a profile are one SDK surface that every client calls the same way (CLI-UPR-02).
3. A stolen disk or another OS user learns at most the visible profiles' names, the number of profile directories and which of them
   are hidden, their creation times, and the number and sizes of their items (§4, §14); every secret, every private record and every
   item name stays sealed under its own profile's passphrase.
4. Two instances of a client on one machine, on two profiles, talk to each other only as two machines would, so a two-person PqChat
   session runs and is tested on one machine (CLI-UPR-06).
5. Today's single store becomes the profile "default" by a one-time move (§12).
6. No crash, at any step of any action, loses a profile or leaves one that no rule opens, repairs or removes; no write made while a
   profile is open is lost by a concurrent action of the same profile (§7.3, §10, §12).

**Non-goals.**

- **Deniability.** A hidden profile is hidden from the list, not from the disk: its directory exists, its envelope has no public
  name (so it reads as hidden), its id gives its creation time, its items have count and sizes (§8, §14). Nothing stronger is
  offered (owner 2026-11-27, Q-UP9).
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
| **visible / hidden** | visible: the envelope carries the name as a public field and the index lists it; hidden: the envelope has no public name, the name is sealed, the index never lists it, it opens by typing its name (§8) |
| **unprotected / protected** | the envelope's two states (§7): no passphrase yet and no secret; sealed under the profile passphrase. A re-seal in progress is shown by the journal file `profile.envelope.next`, never by a state value |
| **generation** | the directory `g<N>/` that holds the profile's items under one data key; a re-seal builds `g<N+1>/` and commits it in one rename (§7.3) |
| **part** | a store inside a profile: `sdk` (keystore, operation state, settings), `pqchat`, `pqvault`; `profile` is reserved for the manifests (§7.2) |
| **store write lock** | the profile's exclusive in-process lock that every writer of every part takes for a write and a re-seal takes for its whole run (§7.3) |
| **tombstone** | `p/<id>.deleted`: a profile being deleted, removed at the next start (§10) |
| **key lock** | an imported native secret key sealed under its own passphrase, opened only by typing it (§7.4, O11) |

## 4. The profile id (CLI-UPR-09, CLI-UPR-10; SPECIFIED)

- Every profile has an id made once at creation: a **UUIDv7** (RFC 9562: 48-bit unix-millisecond timestamp, version and variant
  bits, 74 random bits from the OS RNG), written in the canonical lower-case 36-character form. Owner ruling O9. Built with the SDK's
  existing `uuid` 1 crate by `uuid::Builder::from_unix_timestamp_millis(ms, &random_bytes)` (no crate feature is needed; `now_v7`
  is not used, since it takes no inputs and puts a counter in part of the random field); the 10 random bytes come from the OS RNG
  (`getrandom`, as `uuid4` draws today). Vector rows take the timestamp and the random bytes as inputs. No new crate.
- The id is stable for the profile's life and **names its directory**. The user-given name is a label in the envelope and, for
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

One profile root per OS user and platform, shared by the CLI, the TUI and the desktop app of that user. **Every platform uses a
directory** (`ProfileRoot::Dir`): on mobile it is the app's private data directory, where `FileStore` builds and runs as on desktop;
the app supplies only the keychain items (anchors, the `protected` marker, the unlock key) through one small interface (§11).

| Platform | Profile root | Bound on another OS user |
|---|---|---|
| Linux, BSD | `$XDG_DATA_HOME/scaas` (else `~/.local/share/scaas`), the CLI's `--data-dir` overriding it | modes `0700` / `0600` |
| macOS | `~/Library/Application Support/scaas` | modes `0700` / `0600` |
| Windows | `%APPDATA%\scaas` | the default ACL of `%APPDATA%` (modes do not apply); FileStore's directory `fsync` and a tombstone rename while the profile's files are open are checked on Windows by tests before this row counts (§17) |
| Android, iOS | the app's private data directory | the platform sandbox |
| browser (wasm) | one IndexedDB database per profile, named by its id; the index in its own database (PLANNED, §13) | the origin |

```text
<root>/                          0700 (§5 below on modes); a root that is a symlink or not the user's is refused
  profiles.json                  the index (§6): a cache of visible names, rebuilt from the envelopes when lost
  profiles.json.lock             the root lock: held only around short root steps (§10), never across a KDF run or a dialog
  p/.journal                     present only during the commit of a create or an import: {op, id} (§10)
  p/.tmp-<random>/               a profile being built; holds its own `build.lock`; removed at start only when that lock is free
  p/<id>.deleted/                a tombstone; removed at start when its instance lock is free
  p/.tombstones/<id>             an empty file per deleted id (O17): a directory under that id is never opened
  p/<id>/                        0700, one per profile, <id> its UUIDv7
    instance.lock                held by the instance that has the profile open (§9)
    profile.envelope             the envelope (§7.1)
    profile.envelope.next        present only during a re-seal: the journal of §7.3
    profile.head                 the anchor (§7.2) where the platform has no keychain
    keystore.head                the keystore's anchor where the platform has no keychain (SDK spec §6.3), unsealed by contract
    g<N>/                        the current generation of a protected profile
      <64 hex>                   one sealed item, or one part's sealed manifest; the name says nothing about either
      <64 hex>.lock              FileStore's lock of that item, kept as FileStore keeps it
      <64 hex>.tmp.<pid>.<n>     a FileStore temporary a crash left; removed at the next open under the instance lock
    g0/                          an unprotected profile's only generation: plain names, part `sdk` only (below)
    matrix/                      the matrix-rust-sdk store of this profile's Matrix logins, under its own key (a sealed item); never shared (CLI-UPR-29)
```

- **What a generation of a protected profile accepts:** `<64 hex>`, `<64 hex>.lock` and `<64 hex>.tmp.<pid>.<n>` (the last removed at
  open); any other file is `VaultFormat`.
- **The unprotected `g0/`** has no key, so plain names, no manifest and one part: `settings` (and its `settings.lock`), and in a
  migrated "default" only, `keystore`, `keystore.prev`, `sdk.state` (§12). An unprotected profile holds no app-core state (an app core
  needs a seed, so a protected profile).
- **Modes.** The SDK tightens a root to `0700` only when it already holds `profiles.json` or `p/`, or when the SDK made it; a wider
  mode on any other directory given as a root (`--data-dir ~`, a project directory) is refused (`ProfileRootUnsafe`), never changed.

**What moves into a profile, from today's single store and config** (CLI-UPR-03):

| Today | In a profile |
|---|---|
| `{keystore, keystore.prev, sdk.state}` at the CLI's data directory | `g0/` of "default" (§12), sealed into part `sdk` at `set_passphrase` |
| `keystore.head` (file or keychain) | the same, the keychain item named `scaas.profile.<id>.keystore.head` by the app's keychain interface |
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

- **A cache, never the truth.** A visible profile's name is a **public field of its envelope** (`name`), in clear: a **hint** for the
  list and the rebuild, outside the wraps' associated data; the authoritative name and hidden flag are the sealed `label` (§7.1),
  compared with the hint after unlock. A hidden profile's envelope has no public name. The index
  only spares the picker a read of every envelope. It is rebuilt from the envelopes whenever it is missing or does not parse while
  `p/` holds a profile directory, which is **never a first run**: one row per envelope with a public name, protected or not. A
  rebuild therefore lists **every visible profile**; only hidden ones are unlisted, as always. Also offered on demand with a typed
  confirm. Two envelopes with one visible `name_key` are both listed, marked, with `Event::ProfileIndexMismatch` (one of them was
  planted or copied; the client shows which one is protected).
- Rows hold the **id and the name only**. A hidden profile never has a row, at any time (§8).
- `last` is the id of the last **visible** profile an app or TUI instance opened, or `null`; written only when it changes; a hidden
  open never writes it; the CLI never reads it (§13).
- Bounded before parsing (64 KiB, depth 4, at most 32 rows), canonical JSON, unknown fields refused; written with FileStore's
  `put_if` at the read `rev` under the root lock; **no previous copy**.
- Names: 1 to 64 bytes after NFC, no control or format characters (the account-name helper of SDK spec §7); compared everywhere by
  **one helper**, `name_key(s)` = NFKC, then Unicode lower case (Rust's `str::to_lowercase`, JavaScript's `toLowerCase`, at the
  Unicode version the vectors pin), compared in constant time over equal-length padded buffers. Visible names are unique by
  `name_key` (`ProfileNameTaken`). A name from a file or an envelope passes the same helper before it is shown.
- **The index and the hint are not trusted.** At open the row is compared with the envelope, and after unlock the envelope's hint with
  the sealed `label`: a visible profile whose row or hint differs from its label has both rewritten from the label
  (`Event::ProfileIndexMismatch`); a row that points at an envelope with no public name, or an envelope whose label is sealed as
  hidden but which carries a planted public name, is refused: that open is `ProfileOpen`, the row is dropped and the planted hint
  removed, nothing else is written, and the profile opens again through the hidden prompt. A planted row cannot hide a hidden profile
  from the prompt, since the search reads envelopes, not rows (§8); a planted hint can (a denial, §14).
- At most **32** profile directories under `p/` (`ProfileLimit` at create and import), of which at most **16** hidden (§8).

## 7. Protection (CLI-UPR-04, CLI-UPR-05, CLI-UPR-12, CLI-UPR-19 to CLI-UPR-21; SPECIFIED)

### 7.1 The envelope

A protected profile has a random 32-byte data key `DEK_p`, drawn and held in `ua-rs`. The existing arena scope (`AppKeys`) hangs off
a seed's `Wallet` (`appkey.rs:129`) and cannot hold a key before any seed exists or across seeds, so **a profile arena** is new: a
`ua-rs` `ProfileKeys` scope over its own secret store, with the arena's rules (locked pages where available, zeroized at lock and
drop, never written in clear, never across the FFI). `profile.envelope` is canonical JSON, its fields in this order:

| Field | Content |
|---|---|
| `format`, `v` | `scaas.profile`, 1 |
| `id` | the profile's id, equal to its directory's name |
| `state` | `unprotected` or `protected` |
| `rev` | the envelope's own revision, raised at every envelope write (rename, `hide`, `show`, platform unlock, a re-seal's commit, a hint repaired); compared with the anchor (§7.2), outside the wraps' associated data, inside the label's (O16) |
| `gen` | the current generation `N` (0 while unprotected) |
| `migration` | `pending` while a migration fills this profile (§12), else absent |
| `name` | a visible profile's name (NFC), in clear: a hint, outside the wraps' associated data, checked against `label` after unlock; absent on a hidden profile |
| `kdf` | protected: `{alg: "argon2id", v: 1, m, t, p: 4, salt: <16 random bytes, base64>}`, memory in KiB, the bounds of §7.5 |
| `pass` | protected: `DEK_p` wrapped under `KEK_pass` (below) |
| `platform` | optional, never on a hidden profile: `{salt: <32 random bytes>, wrap}`, `DEK_p` wrapped under `K_plat` |
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

**Associated data, pinned for the vectors.** `lp(x) = be16(len(x)) ‖ x` for every variable field; domain strings are the ASCII bytes
shown, without a terminator; integers big-endian at the width shown.

- `pass` and `platform.wrap` are `ua-rs` `seal_key` wraps of `DEK_p` and keep its prefix (`"scaas/ua/v1/keywrap" ‖ u8(usage)`,
  `appkey.rs`), followed by the caller's AD: `lp("scaas.profile.wrap")` (or `lp("scaas.profile.platform")`) ‖ the canonical JSON
  object of **exactly** the public fields `format`, `v`, `id`, `state`, `gen` and `kdf`, in that order, with no other field (not
  `rev`, not `name`). A changed state, generation, parameter or salt fails the wrap; clientkeys produces the same bytes. So `rename`,
  `hide()` and `show()` re-seal only `label` under `DEK_p` and never touch the wraps: they need no passphrase and no biometric, and no
  key outlives its call (`hide()` still drops the platform wrap, §7.6).
- `label`: AD = `lp("scaas.profile.label") ‖ be16(1) ‖ lp(id) ‖ be64(rev)`, `rev` the envelope's own (owner O16, 2026-11-28):
  the domain, the profile-format version, the id, then the revision of the envelope that holds the label, last. Every envelope
  write (rename, `hide()`, `show()`, a re-seal's commit, a hint removed or repaired, anything that raises `rev`) re-seals the
  label at the new `rev` under `DEK_p`. At open, after the wrap opens, a label whose tag fails at the envelope's `id` and `rev`
  is **`ProfileRollback`** with `Event::ProfileRollback`, nothing written (an older envelope written back with its `rev` raised
  above the anchor's; a label damaged in place reads the same); a label that opens but is of no label form is `ProfileFormat`.
  The hidden search counts such a candidate as no match (one error for every hidden failure, §8).

**Refusals by state** (no item is read before these hold):

- a protected profile refuses any item not in sealed form and any file in `g<N>/` outside the pattern of §5 (`VaultFormat`);
- an unprotected profile refuses a sealed item, a generation other than `g0`, and, unless `migration: pending`, a `keystore` item
  (`ProfileFormat`);
- where the OS has a keychain, `set_passphrase` writes the item `scaas.profile.<id>.protected`, and every protected open writes it
  again if it is missing; an `unprotected` envelope beside it is `ProfileFormat`; a missing anchor (§7.2) beside it is
  `ProfileRollback`.
- **An unprotected profile is shown as such**: at every open the client says "this profile has no passphrase", and
  `set_passphrase` first shows the profile's endpoints and credential references (the import review's list, §10.1) for the user to
  keep or drop before they are sealed.
- **Residual, stated, every platform:** someone who can write the root may plant a new unprotected directory with a visible name and
  their own settings (endpoints, `first` marks, credential references), or replace a whole envelope and generation with an
  unprotected one. The keychain marker catches only the second, and only where there is a keychain. The user meets an unprotected
  profile announced as such, with someone else's settings shown before they are sealed, not a disclosure of any sealed item.

### 7.2 The sealed store (CLI-UPR-19)

- **Item.** `{"rev":N,"sealed":"<base64 of nonce ‖ ciphertext ‖ tag>"}`, AES-256-GCM-SIV under `K_item`, AD =
  `lp("scaas.profile.item") ‖ be16(1) ‖ lp(part) ‖ lp(item name) ‖ be64(N)` (domain, profile-format version, store part, the item's
  full name in its part, rev). An item cannot move between names or parts, or take another `rev`, without failing its tag. No store
  may use the part `profile`.
- **File name.** `hex(HMAC-SHA256(K_name, lp(part) ‖ lp(item name)))`: 64 lower-case hex characters. No item name (pqchat-core's keys
  hold UAs, session ids and Matrix room ids) and no part name appears on disk, and the profile layer never hands a part name to any
  other store: on every platform it names files itself (§5).
- **Manifests, one per part.** Each part's manifest is a sealed item of the reserved part `profile`, named `manifest:<part>` (so its
  AD and its HMAC file name are its own and no store item can take them), holding every `(item name, rev)` of the part and a
  **tombstone** `(item name, last rev)` for every item the part deleted, and its own `rev`. An item created again under a deleted
  name continues **above** its tombstone: the core stores `rev = tombstone rev + the caller's revision`, and the face shows the caller
  its own revision (pqchat-core's 0 = absent, then 1), so a re-created item is never a false rollback. **Tombstones are dropped at a
  re-seal**: the new generation's key opens no item of the old one, so nothing deleted can be put back. Bound: at most 65,536 entries
  per part, tombstones included (a write that would pass it is refused, `ProfilePartFull`; pqchat-core prunes what it no longer needs;
  a re-seal retires the tombstones) and the 16 MiB plain bound.
- **Writes.** Under the profile's **store write lock** (§7.3): the item (`put_if` as today), then the part's manifest with that item's
  new `rev` (`put_if` at the manifest's read `rev`, three tries, then `StoreConflict`), then the anchor. A delete writes the manifest
  first with the item's tombstone, then removes the file. Cost, stated (arithmetic, not a timing): one item write is three atomic file
  writes (item, manifest, anchor), each a temporary file, `fsync` and rename; a keystore update, which today writes `keystore.prev`,
  `keystore` and `keystore.head`, becomes seven.
- **The anchor** is `{gen, for each part its manifest's rev and the first 16 bytes of SHA-256 of its file, the envelope's rev and the
  first 16 bytes of SHA-256 of profile.envelope}`. Every client writes the file `profile.head`; a client whose store has a keychain
  also writes the keychain item `scaas.profile.<id>.head` and compares both by the same rule. It is written after every item write,
  after every envelope write and at every re-seal's commit.
- **The anchor is compared as the keystore's is** (`vault/mod.rs` `rolled_back`): for the generation, for each manifest and for the
  envelope, a value **ahead** of the anchor (a higher `gen`, a higher `rev`) is a crash between the write and the anchor's write, or a
  write by another client that could not reach this anchor, and **the anchor follows**; a value **below** the anchor, or **another
  hash at the same** `rev`, is `ProfileRollback`. So a kill between a manifest (or an envelope) and its anchor opens with no event,
  and the CLI (no keychain) and the desktop app (a keychain) taking turns on one profile open with no event.
- **Rollback, exactly what holds.** On read: an item whose `rev` is below its manifest's, or at or below its own tombstone's, is
  `Event::ProfileRollback` (shown, not fatal, writes refused for that item until the user accepts, as `KeystoreRollback`); an item
  above the manifest's is a crash between the two writes, and the manifest is brought forward; an item the manifest **lists but whose
  file is missing** is `Event::ProfileDamaged` (a removed `settings` does not silently fall back to defaults); a manifest, an
  envelope or a `gen` below the anchor, or another hash at the same rev, is `ProfileRollback` for the profile, so an envelope from
  before a `hide()` or a rename put back is seen, and one put back with its `rev` raised above the anchor's fails its label
  (§7.1, O16). Where the anchor is the file `profile.head` in the same directory (every client whose store
  has no keychain: the CLI and the TUI on every OS, the desktop app on Linux), **the anchor file and whatever it covers, put back
  together** (one item, its manifest and `profile.head`; or the whole directory), is not seen: stated in §14. A passphrase change
  rotates `DEK_p` (§7.3), so an old envelope and the old passphrase open nothing written after the change.
- **Restoring the previous keystore by hand** (SDK spec §6.3) is no longer a file copy under HMAC names: it is the call
  `vault.restore_previous()` (PLANNED), which writes `keystore.prev` over `keystore` through the store.
- **Size.** A sealed item's bound is the base64 of its plain bound (16 MiB for `keystore`, `keystore.prev`, `sdk.state`) plus
  1 KiB; `rev_of` reads the outer `rev` of a sealed item up to that bound instead of 16 MiB, and SDK spec §6.9's size contract says so
  (§15.2). `keystore.head` passes through unsealed: it is public by contract (`rev` and a hash, at most 64 bytes, for a keychain).
- **Errors.** `StoreError` gains `VaultFormat` (a sealed item that does not open; a plain item in a protected profile),
  `ProfileLocked`, `ProfilePassphraseRequired`, `ProfileRollback`, `ProfileDamaged`, and (owner O21, 2026-11-28) `ProfileBusy` and
  `ProfilePartFull`, and `vault::io` maps each to the `SdkError` of the same name; this is a change to the keystore code (one mapping), which otherwise runs above the adapter as today.
- **One store core, two faces.** The sealed store is one synchronous core (file I/O and AEAD are blocking work), holding the store
  write lock and the manifests for every part. The SDK's `SecureStore` face runs it on `spawn_blocking`; **pqchat-core's
  `PqChatStore` face is synchronous** and pqchat-core calls it from a blocking task: the one helper is pqchat-core's `Items`
  (`store.rs:91`), whose `get` and `update` become `async` and run the synchronous store call on `spawn_blocking`; its 33
  construction sites in 9 files (`chain_state.rs`, `chain_store.rs`, `consent.rs`, `device.rs`, `matrix.rs`, `message.rs`,
  `reads.rs`, `signed.rs`, `stores.rs`, counted at `9f2ee89b7`) gain an `.await` and nothing else.
  Chosen over an async adapter because a synchronous face never waits on a future, so it cannot deadlock or panic on a
  current-thread runtime, and pqchat-core's trait, its other stores and its tests stay as they are. pqchat-core's revision (0 =
  absent, then +1) is the item's `rev`. `StoreFault` **carries the code** (`ProfileLocked`, `VaultFormat`, `ProfileRollback`,
  `ProfileDamaged`, `Io`), so after a profile lock pqchat-core reports `ProfileLocked`, not `StoreIo`. pqvault-core has no store or
  cache in code today (its one trait is `Net`): its offline cache is a plan task of the app, written through the `SecureStore` face of
  part `pqvault`. The Matrix store keeps its own encryption; its store key is a sealed item, and it is **the one key that leaves the
  arena** (matrix-rust-sdk needs its bytes): it lives in the Matrix client until the profile locks, and the lock closes that client.
  Each profile has its own Matrix logins, session, store, crypto keys and device id (owner O14, CLI-UPR-29): nothing Matrix-side is
  shared between profiles, one `scaas-matrix` client runs per open profile, and a switch closes it before the other profile opens.
- **Zeroisation.** Every key above (`KEK_pass`, `K_plat` and the platform secret, `K_label`, `K_item`, `K_name`, `K_x`), every
  Argon2id output, dummy runs included, the OpaqueString bytes of a passphrase, a typed hidden name, and every plaintext buffer of an
  item, a label, an export or an import live in `Zeroizing` buffers or the arena and are dropped at the end of the call; `DEK_p` and
  the derived item keys stay in the profile arena until lock.
- **The browser** (PLANNED): IndexedDB has no synchronous form, so the synchronous core and pqchat-core's synchronous face do not
  carry to wasm32; the browser store needs an async core of its own, the same formats and rules, and is a later task.

### 7.3 Re-seal, crash safety, writes during a re-seal (CLI-UPR-20, CLI-UPR-25)

`set_passphrase` (unprotected → protected), `change_passphrase` (a new `DEK_p` under the new passphrase) and a raise of the KDF
parameters are one procedure, run under the instance lock **and the profile's store write lock, held for the whole run**:

1. take the store write lock: every writer of every part (the SDK, pqchat-core, pqvault-core) **waits** until the commit (never
   `StoreConflict`), then writes into the new generation under the new keys; no write lands in `g<N>/` once its items are being
   copied, so none is lost and a pqchat counter never goes backwards. A writer waits at most **120 s** (a re-seal of the largest
   profile, 64 MiB of items, is far below it); past that it fails **`ProfileBusy`** and writes nothing, and the caller retries;
2. write `profile.envelope.next` with `state: "protected"` and `gen: N+1` **from the start**, the new `kdf`, the `pass` wrap of a
   **new** `DEK_p` and its `label`; the file name is the journal (a reader never takes `.next` as the envelope), so no `sealing`
   value and no second wrap exist; a passphrase change or a parameter raise **drops the `platform` wrap and its key** (the user turns
   platform unlock on again), as `hide()` does;
3. re-seal every item of `g<N>/` (read in plain form for `g0` of an unprotected profile, else opened under the old key) into
   `g<N+1>/` under the new keys, with new manifests; `fsync` each file and the directory;
4. commit: rename `profile.envelope.next` over `profile.envelope`, `fsync` the directory; write the anchor for generation `N+1` and,
   on a first protection, the keychain `protected` marker; release the store write lock;
5. remove `g<N>/`.

At the profile's own open (under its instance lock; never at another profile's or another instance's start): a
`profile.envelope.next` present means the commit did not happen, so `g<N+1>/` is removed **first** and then the journal, and the
profile stays as it was (**roll back**; the user repeats the action); a generation **below** the envelope's `gen` is removed (a
crash between steps 4 and 5) **only when `g<gen>/` exists and the wrap has opened** (so after the passphrase and the anchor check);
otherwise it is `Event::ProfileDamaged` and nothing is removed, so an envelope with an edited or newer `gen` beside an older generation
never erases it; a generation **above** `gen` with no journal is `Event::ProfileDamaged` (and `ProfileRollback` where the
anchor says the envelope is old), **never removed**. A crash at any step therefore leaves either the old profile whole or the new
one whole, and an old envelope put back never erases the live generation. The previous plain `g0` of a migrated "default" is removed
only after the commit.

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
  passphrase with a pin envelope only, as the label vault `native-import-locked:<network>:<n>` (a new label form in the keystore
  container and in the seed's sealed manifest: clientkeys and its vectors first, CLI-SDK-03). Such a vault is **never** opened by the
  seed's unlock of any kind, by a passkey, by a platform secret or by the profile's unlock; only `vault.unlock_key(seed, key,
  key_passphrase)` opens it, with the passphrase typed (`Unlock::Passkey` and `Unlock::Platform` are refused for it: `Argument`). It
  stays open until `lock_key`, the seed's lock or the profile's lock. A signature by a locked key is refused `KeyLocked`.
- **Where it is enforced.** Every loop over a seed's vaults **skips** `native-import-locked:` labels: the passphrase change's re-wrap
  and the PRF enable and disable of `vault/prf.rs` (which today map over every vault of the seed with the seed's passphrase), the
  same-DEK re-seal (`reseal_label_vault`) and the retained-PRF open (`open_label_vault_retained`, `ua-rs` `wallet/manifest.rs`). So a
  seed's passphrase change, or its platform unlock turned on while the key is open, neither fails on the key-locked vault nor adds an
  envelope to it. **A reader refuses** a `native-import-locked:` vault that carries a `prf` envelope (`VaultFormat`), in `ua-rs` and
  clientkeys, with a vector row.
- **Backup and link.** A seed's sealed backup (`scaas/backup/v1`) and its device link carry imported keys as plain secrets inside
  their seal (`wallet/manifest.rs`'s payload); they **leave key-locked keys out**, since the payload has no key-locked form, and the
  backup screen says how many are left out. A key-locked key travels only in a profile export, still in its key-locked vault
  (§10.1), or by the user's own record of it.
- **An existing import** may be moved under its own passphrase: `vault.lock_key_separately(seed, key, key_passphrase)` (seed
  unlocked) re-seals the key as a new `native-import-locked:` vault under a fresh data key and drops the old vault, and **rewrites
  `keystore.prev` in the same procedure** (a second write of the new container), so neither the container nor its previous copy on
  this device holds the old vault. Residual, stated: old disk blocks, an export made before and any copy made elsewhere may keep it;
  the UI says "move the funds to a new key if an earlier copy may be out".
- **What a platform unlock of the profile makes readable** (stated plainly, O11): the profile's settings and chain-profile settings;
  the keystore's public fields (seed labels, account rows with addresses and UA ids, backup states); `sdk.state` (operation history);
  the PqChat store (contacts and sessions, rooms, read positions, counters; CLI-PQC-09); the Matrix store and login (plain Matrix chat
  history included); PqVault's offline cache (ciphertexts and their metadata). **Not readable:** any seed's words and keys, any
  imported key, any key-locked key, PqVault items (each behind its own vault key and, by default, its passphrase, CLI-PQV-07), PqChat's
  local plaintext history where built (sealed under the account's app-scoped storage key, which needs the seed unlocked; CLI-PQC-09's
  Change). **Not writable in a weakening way:** a settings change that could weaken the profile needs the typed passphrase (§7.7).

### 7.5 KDF parameters, bounds, cost (CLI-UPR-21)

- Default **64 MiB / 3 / 4** (owner 2026-11-27, Q-UP2; PqVault's pinned set), stronger allowed within the bounds, no timing run.
- **Bounds, each field alone:** `m` from 65,536 KiB (64 MiB) to 1 GiB on desktop, to 256 MiB on mobile and in a browser; `t` from 3 to
  10; **`p` fixed at 4** (not a strength knob: at fixed `m`, a larger `p` is not stronger; `p = 4` computes the same on one thread,
  so wasm32 needs no threads). A value outside the general bounds (64 MiB to 1 GiB, 3 to 10, 4) is `ProfileFormat` before any KDF
  runs. A value inside them but above **this device's** maximum is **`ProfileKdfTooLarge`**, named, before any KDF runs (the
  parameters are public: the code leaks nothing), so a desktop export at 1 GiB on a phone says why it cannot open.
- **Out of memory** (argon2 returns `OutOfMemory`, it does not abort) is **`ProfileKdfOutOfMemory`**, never `ProfileOpen` or
  `ProfileImportOpen`.
- Every Argon2id run goes through the profile layer's own heavy limiter (§11), one at a time by default, and **never under the root
  lock** (§10).
- **Tests** run a test-only parameter set (m 8 MiB, t 1) behind a **new feature `test-hooks`** in `ua-rs`, `scaas-sdk` and
  `scaas-cli`, with its row in `scripts/check_test_features.py` (never in a release build; that check refuses it there); the CLI's
  suites run a binary built with it.

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
  `disable_platform_unlock`, a passphrase change and a parameter raise drop the wrap and the key. **Platform unlock never reaches a
  hidden profile**: `enable_platform_unlock` on a hidden profile is `Argument`, and `hide()` drops an existing platform wrap and its
  key in the same envelope write.

### 7.7 Settings changes (CLI-UPR-26)

A settings change that **could weaken** the profile needs the **profile passphrase typed** (checked against the `pass` wrap; a
platform unlock does not count): adding an endpoint (a new label, list, chain profile or URL), marking one `first`, adding a
credential reference, turning the idle lock off or lengthening it, turning the clipboard opt-in on, and **the reverse of any
strengthening** (owner O19, 2026-11-28): turning a chain profile's `strict_majority` off (dropping that chain profile's settings
included), raising or removing a lowered cap, per chain profile or global (decimal values compared by value; one that is no
decimal counts as raised). A change that only strengthens (a stronger RPC policy, a cap lowered or lowered further, a shorter idle
lock, the clipboard off, removing an endpoint, a `first` mark or a credential reference) or picks the default chain profile needs
no passphrase. An import keeps without a confirm only what strengthens the defaults (§10.1). So a session left open, or
anyone enrolled on a shared OS account (O11), cannot plant an endpoint that decides the reads.

## 8. Hidden profiles (CLI-UPR-08, CLI-UPR-13; SPECIFIED)

- **At most 16 hidden profiles** per root. `create_hidden`, an import as hidden and `hide()` refuse at that cap
  (`ProfileHiddenLimit`). The search below accepts up to **32** candidates (the directory limit), so 16 hidden profiles and damaged
  directories together never lock the hidden prompt out.
- **`create_hidden(name, passphrase)`** makes a profile protected from its first write, with no public name and its label sealed as
  hidden; **no index row is written, ever**. `hide()` on an open, protected, visible profile removes the public name and re-seals
  the label as hidden (one envelope write under `DEK_p`, no passphrase; the platform wrap dropped; the anchor rewritten) and drops
  its row; residual, stated: the
  name was in the index and the envelope before, and earlier copies of those files (old disk blocks, backups) and shell history may
  keep it; a rename after hiding is the remedy. `show()` writes the public name and the row.
- **No duplicate.** Every path that makes a profile hidden or changes a hidden profile's name or passphrase (`create_hidden`, an import
  as hidden, `hide()`, a hidden rename, a hidden passphrase change) first runs the search below with the resulting (name,
  passphrase); a match other than the profile itself is `ProfileNameTaken` (it tells nothing to someone who does not hold both). So no
  two hidden profiles share a (name, passphrase), but for one race, accepted (owner O20, 2026-11-28): two instances running
  `create_hidden` with one (name, passphrase) at once may both pass the search, since no lock is held across a KDF; step 3
  below never picks between such twins.
- **Opening a hidden profile** takes its name and passphrase, both typed, both secret inputs (`SecretBytes`; the name never echoed,
  never on a command line, §13). The SDK, reading without any instance lock and without the root lock:
  1. lists `p/` and takes the **candidates**: every directory named by a UUID whose envelope has no public name, plus every
     UUID-named directory whose envelope is missing or does not parse (`.tmp-*`, tombstones and `.journal` are not candidates; the
     index is not read, so a planted row cannot hide a profile); more than 32 candidates is **`ProfileSearchTooLarge`** before any
     run, which only directories planted beyond the directory limit can cause;
  2. runs **max(candidates, 4)** KDF runs: each hidden envelope (protected, `id` equal to its directory, parameters within this
     device's maximum) at **its own** parameters, then the wrap, then `name_key` of the sealed name against the typed one; a candidate
     without a usable envelope (missing, unreadable, unprotected without a name, above this device's maximum, a mismatched id) costs
     one run at the default parameters and never stops the search; dummy runs at the default parameters fill up to four; **no early
     stop**; the total work is bounded by 32 runs at this device's maximum;
  3. on exactly one match takes that directory's instance lock (`ProfileInUse` if held, which only a holder of the name and
     passphrase can provoke), re-reads its envelope under the lock and opens it; zero matches is `ProfileOpen`, as is every other
     failure: no such name, a wrong passphrase, no hidden profile at all. Two or more matches is **`ProfileHiddenAmbiguous`**, none
     opened (owner O20): `hidden_matches(name, passphrase)` runs the same search and lists them as opaque choices, `HiddenMatch
     { index, created_ms }` (each match's place in id order and its creation time from its UUIDv7; no id, so its `Debug` shows
     none), and `open_hidden_match(name, passphrase, choice)` runs the search again and opens the match at that place whose
     creation time is the choice's, else `ProfileOpen`. Both cost a search's runs.
- **The name is a label, not key material** (Q-UP7): not bound into the KDF; a rename re-wraps nothing.
- **Equal time, exactly what holds:** a failed open costs the same for zero to four candidates **when every candidate is at the
  default parameters**. A candidate at raised parameters makes every hidden open slower by its extra cost, and more than four
  candidates add one run each: a screen observer then learns that some hidden or damaged directory exists or has raised parameters,
  which the disk tells anyway. The total work is bounded by 32 runs at this device's maximum.
- Unusable directories are also reported at the start (`Event::ProfileDamaged`, no name), so the user can remove them by hand.
- The prompt "Open another profile" is always offered. A hidden profile writes nothing that names it outside its directory (not
  `last`, not a recent list); its name is never drawn (the TUI and the app show "Hidden profile").
- **A hidden profile whose passphrase is lost** is neither named nor deleted by the app; the user removes its directory by hand; no
  call deletes unlisted directories (owner 2026-11-27, Q-UP10).
- **Limit, stated plainly:** hidden from the list, **not deniable on disk**: its directory, its envelope without a public name, its
  UUIDv7, the count and sizes of its items, its keychain items (named by the id) are visible. Nothing stronger is offered (Q-UP9).

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
  separated by id: the build's chain profiles, the index (written under the root lock), the OS keychain (items named by id). No
  instance takes another profile's instance lock at its start (§10).

## 10. Lifecycle (CLI-UPR-15, CLI-UPR-20; SPECIFIED)

The **root lock** is held only around short root steps (a journal, a rename, an index write, a removal), never across a KDF run, a
re-seal or a dialog; work inside a profile runs under its instance lock.

| Action | Needs | What happens |
|---|---|---|
| **start** (`UserProfiles::new`) | the root lock, briefly | finish or undo `p/.journal` (below); remove each `p/.tmp-*` whose `build.lock` it can take (one in use by a live import is left); remove each tombstone whose instance lock it can take, its id marked first (`p/.tombstones/<id>`, O17), then its keychain items; report a UUID-named directory under a marked id (`Event::ProfileRollback`), never open it; report a UUID-named directory without a usable envelope (`Event::ProfileDamaged`, no name), **never remove it**; migrate (§12). It takes no live profile's instance lock: a profile's own roll-back and generation clean-up run at that profile's open (§7.3) |
| **first run** | no index, `p/` empty or absent, no legacy items (§12) | "default" is created (unprotected) and opened (O5) |
| **create** | a free visible name, fewer than 32 directories | build `p/.tmp-<random>/` (its `build.lock` held) with its unprotected envelope (public name) and empty `g0/`; then, under the root lock, write `p/.journal` `{op: "create", id}`, rename the directory to `p/<id>/`, add the row, remove the journal. Journal found at start: `p/<id>/` present → add its row from its envelope's public name (none for a hidden import); absent → nothing; then remove the journal |
| **create hidden** | name and passphrase, no duplicate, fewer than 16 hidden (§8) | as create, protected and without a public name from the first write, no row |
| **open** (by id) | the instance lock; the passphrase, or the platform unlock if enabled | the profile's own clean-up (§7.3); `*.tmp.*` files of its generation removed; envelope bounded and refused by state (§7.1), `DEK_p` unwrapped, the anchor compared, the row checked against the envelope (§6), `last` written if it changed, settings read |
| **open** (hidden) | name and passphrase | §8 |
| **lock** | — | `vault.lock_all()` on the profile's `Sdk` (every seed and hidden set; it relies on review A-8's code fix, `lock_all` also walking hidden sets on seeds that are not unlocked, branch `fix-lock-all-hidden`), key-locked keys closed, then **`Sdk::close()`** (new: watchers, followers and operation trackers stopped, RPC and gateway pools dropped with the credential values they hold, a closed flag every later call meets), the profile's stores refuse every call (`ProfileLocked`), the profile arena destroyed, the Matrix client closed, the instance lock released; the client clears its view models and what it put on the clipboard (CLI-TUI-14). The `Sdk` object may outlive the lock in a binding's `Arc`; every call on it then fails `ProfileLocked` and no request leaves on it |
| **switch** | — | lock, then open the other (O7); nothing is carried over |
| **rename** | open; for a hidden profile no duplicate (§8); no passphrase | the sealed label re-sealed under `DEK_p`, and for a visible profile its public hint and row; the wraps untouched; the anchor rewritten |
| **hide / show** | open, protected | §8 |
| **passphrase, parameters** | open | §7.3 |
| **settings** | open; the profile passphrase for a weakening change | §7.7 |
| **delete** (open) | the name typed again; with any `backup: pending` seed also `ConfirmDeleteUnbacked` | `delete_preview()` lists the seeds and how many lack a backup; then: mark the id (`p/.tombstones/<id>`, O17) and rename `p/<id>/` to the tombstone `p/<id>.deleted/` (one atomic step, under the root lock), drop the row, remove the keychain items, remove the tombstone. A crash at any step leaves a tombstone, which start finishes |
| **delete** (locked, visible; a lost passphrase) | the instance lock, the name typed again, and `ConfirmDeleteUnreadable` | the same steps without opening; the client says plainly: "this profile's data cannot be opened and will be lost; seeds return only from their words or their sealed backups" |
| **export / import** | §10.1 | §10.1 |

A lost profile passphrase loses the profile (stated): no recovery path exists; seeds return from their words or their sealed backups
(SDK spec §6.11). A **hidden** profile whose passphrase is lost cannot be named, so no call deletes it: the user removes its directory
by hand, and no call deletes unlisted directories (owner 2026-11-27, Q-UP10). The last profile may be deleted; the next start creates
"default" again (O5).

### 10.1 Export and import of a whole profile (CLI-UPR-17, CLI-UPR-18, CLI-UPR-27; SPECIFIED; owner Q-UP5, Q-UP11)

**Inside the file** (all of it under the seal; the parts marked * are left out by the owner's ruling of 2026-11-27, Q-UP11):

| Part | Content |
|---|---|
| the label | the profile's name and its hidden flag, **not its id** (CLI-UPR-10) |
| the store items | `keystore` (every seed vault and every key-locked vault sealed as today under its own passphrase, MAC and `rev` unchanged) and `sdk.state`, whose operations in flight are imported marked `imported` and followed only on the user's word |
| the settings | the chain-profile settings (named endpoints with their `first` marks, a stronger policy, lowered caps, the default chain profile), the idle lock and clipboard choices; **credential references are omitted** * |

**Never inside:** the instance lock and every `*.lock`; the envelope, `DEK_p` and the profile passphrase; keychain items (anchors,
platform keys, PqChat's device anchor); **`keystore.prev`** *; **the PqChat store** * (CLI-PQC-09: a device-bound cache with no source
of truth; after import PqChat recovers from contract state with a new device id, so no counter, version floor, acceptance or pending
envelope is ever imported); every cache (PqVault's offline cache, the Matrix store and login); temporary files; the id; the release
chain profiles.

**The file** (pinned for the vectors; rows in clientkeys and `ua-rs` before code):

```text
file    = magic ‖ be32(header_len) ‖ header ‖ chunk_0 ‖ … ‖ chunk_last
magic   = the 8 ASCII bytes "SCAASPX1"
header  = canonical JSON, at most 4,096 bytes (a longer header_len is refused before any byte of it is parsed), fields in this order:
          {"format":"scaas.profile-export","v":1,"kdf":{"alg":"argon2id","v":1,"m":65536,"t":3,"p":4,"salt":"<16 bytes, base64>"},
           "nonce_prefix":"<7 bytes, base64>","chunk":1048576}
chunk_i = AES-256-GCM-SIV(K_x, nonce_i, AD_i, plaintext_i) as ciphertext_i ‖ tag_i (16 bytes)
nonce_i = nonce_prefix (7) ‖ be32(i) ‖ last_i (1 byte: 0x01 on the final chunk, else 0x00)
AD_i    = lp("scaas.profile-export") ‖ be32(header_len) ‖ header ‖ be32(i)
payload = be32(len) ‖ label JSON ‖ be32(len) ‖ settings JSON ‖ be16(item count) ‖ for each item: lp(item name) ‖ be32(len) ‖ bytes
```

- **Chunks.** `chunk` must equal 1,048,576 (any other value is a header refusal). Every chunk but the last holds exactly 1,048,576
  plaintext bytes; the last holds 1 to 1,048,576 (a payload that is a multiple of 1 MiB ends on a full chunk carrying the flag, never
  on an empty extra chunk; the payload is never empty, since the label is not). A truncated, reordered or extended file fails. The
  salt and the prefix are fresh per file. Vector rows at exactly 1 MiB and at 1 MiB + 1 of payload. Built in `ua-rs` (CLI-SDK-01).
- **Items.** An import accepts the item names `keystore` and `sdk.state`, each at most once, in that order; anything else is refused.
- **Size.** The payload is at most **64 MiB**. Export refuses a larger profile with **`ProfileExportTooLarge`**; import refuses a
  longer file before the KDF runs.
- **Verify, then parse.** No byte of a chunk is parsed before its tag verifies; parsed items go to the new profile's temporary
  directory only, and nothing is committed before the final chunk verified and every item validated.
- **Export** needs the profile open and protected, the profile's name typed again **and the profile passphrase** (checked against
  the `pass` wrap; `ProfileOpen` if wrong), and the export passphrase typed twice (the profile passphrase's rule; the client says the
  file is meant to leave the device, so a passphrase of its own is better). Native: written to a path the caller names, created new
  (`O_CREAT | O_EXCL`, mode `0600`), never through an existing file or a symlink (`Argument`); mobile and wasm: chunks handed to the
  platform's share sheet or file picker.
- **Import is two calls** (CLI-UPR-27). `import_preview(source, export_passphrase)` verifies and opens the whole file (no KDF under the
  root lock) and **keeps the decrypted payload in memory** (at most 64 MiB, in `Zeroizing` buffers held by the review handle):
  **nothing plain is written to disk**, and a crash during the review leaves nothing. It returns an `ImportReview`: the name and hidden flag, the seed and account counts, and **every setting**, each with an item id:
  endpoints by label and host with their `first` marks, the idle lock, the clipboard choice, and what would be kept without a confirm
  (a stronger policy, lowered caps, the default chain profile), so a file that sets caps to zero or picks another default chain is
  seen; every string passes the name helper before it is shown. `import(review, choices, profile_passphrase, name)` then seals the new
  profile under the new passphrase (a new UUIDv7, protected from the first write, O5), applies the choices by item id, writes the
  temporary directory `p/.tmp-<random>/` (its `build.lock` held), **sealed under the new profile's key from its first byte**, and
  commits under the root lock by one rename and the row (none for a hidden profile, after the duplicate check of §8; `ProfileHiddenLimit`,
  `ProfileLimit`, `ProfileNameTaken` as named). Dropping the review wipes its buffers.
- **Settings at import keep only what cannot weaken:** a stronger RPC policy, lowered caps and the default chain profile are kept;
  every named endpoint, every `first` mark, the idle lock and the clipboard choice are dropped unless the user confirms each one by
  itself; **a credential reference in a file is always dropped**, never offered for confirm (export never writes one, so a file that
  holds one was crafted). CLI-TUI-06's refusals hold for what is kept.
- **Errors.** Everything after the header (a wrong passphrase, a changed byte, a truncated file, a refused item) is one error
  `ProfileImportOpen` to the user, with nothing written. Header refusals (magic, format, version, `chunk`, header length, parameters
  outside the general bounds) are also `ProfileImportOpen` to the user, with a distinct reason in the local log; parameters above
  **this device's** maximum are `ProfileKdfTooLarge` and out of memory `ProfileKdfOutOfMemory` (§7.5).
- **After import.** Seeds unlock with their own passphrases; key-locked keys with theirs; PqChat makes a new device id and recovers
  from contract state (CLI-PQC-09); PqVault rebuilds its cache from chain; the Matrix login is new.
- **Residual, stated.** Importing a profile that still exists elsewhere makes two profiles holding the same seeds; the client says
  so. A file is as strong as its export passphrase; the seed and key vaults inside keep their own. A file someone else made and
  handed over with its passphrase carries that person's seeds and accounts: the review shows the name, and the client says "funds
  sent to addresses of an imported profile belong to whoever made its seeds".

## 11. SDK surface (CLI-UPR-02, CLI-UPR-22; SPECIFIED; a sketch for the plan)

Two layers (owner O13). **`scaas-profile`**, a crate over `ua-rs` only (`ua-rs`'s existing `argon2` 0.6.0 path; `ua-rs` without its
defaults, features `user-profile` and `json` only, so no signing code is compiled in: owner O15, CLI-UPR-32), synchronous (its
calls run on a blocking thread), with its own `Error` whose codes carry the SDK's names: the profile root, the index, the envelope,
the instance lock, the sealed store with its journal, generations, manifests and anchor, hidden profiles, delete, migration, export
and import, the storage of settings, and the `ProfileKeychain` interface. **The SDK**, module `user_profile` (feature `user-profile`:
the SDK's vault and `scaas-profile`): `UserProfile::sdk` (an `Sdk` opened on a profile), `Sdk::close()` at lock and switch, the
chain-profile meaning of the settings, the store keys handed to app cores (`part_store`, `pqchat_store`, `matrix_store`), and the
`SecureStore` face with the mapping of the store's codes to `StoreError` and `SdkError`. The sketch is the SDK's; a call that needs
no `Sdk` has its synchronous twin in `scaas-profile`, which scaas-app's default build calls directly.

```rust
pub struct ProfilesConfig {
    pub root: String,                                    // ProfileRoot::Dir on every platform: on mobile the app's private directory
    pub keychain: Option<Arc<dyn ProfileKeychain>>,      // anchors, the protected marker; None: files beside the profile (§7.2)
    pub authenticator: Option<Arc<dyn Authenticator>>,   // platform unlock before any Sdk exists
    pub limits: Limits,                                  // its own heavy limiter for Argon2id
}
pub trait ProfileKeychain: Send + Sync {                 // scaas-profile's, synchronous; small items only (<= 2,560 bytes), named by the store
    fn get(&self, name: &str) -> Result<Option<Vec<u8>>, scaas_profile::Error>;
    fn put(&self, name: &str, bytes: &[u8]) -> Result<(), scaas_profile::Error>;
    fn delete(&self, name: &str) -> Result<(), scaas_profile::Error>;
}
impl UserProfiles {
    pub async fn new(config: ProfilesConfig) -> Result<Arc<UserProfiles>, SdkError>;  // start (§10), rebuild, migration
    pub async fn list(&self) -> Result<Vec<UserProfileInfo>, SdkError>;          // visible: { id, name, protected }; Debug redacts id
    pub async fn create(&self, name: String) -> Result<UserProfileInfo, SdkError>;
    pub async fn create_hidden(&self, name: Arc<SecretBytes>, passphrase: Arc<SecretBytes>, kdf: Option<KdfParams>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn open(&self, id: String, unlock: Option<ProfileUnlock>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn open_hidden(&self, name: Arc<SecretBytes>, passphrase: Arc<SecretBytes>) -> Result<Arc<UserProfile>, SdkError>;
    pub async fn delete_locked(&self, id: String, confirm: ConfirmDeleteProfile, unreadable: ConfirmDeleteUnreadable) -> Result<(), SdkError>;
    pub async fn rebuild_index(&self, confirm: ConfirmRebuildIndex) -> Result<(), SdkError>;
    pub async fn import_preview(&self, source: ImportSource, export_passphrase: Arc<SecretBytes>) -> Result<Arc<ImportReview>, SdkError>;
    pub async fn import(&self, review: Arc<ImportReview>, choices: ImportChoices, profile_passphrase: Arc<SecretBytes>, name: Option<String>) -> Result<UserProfileInfo, SdkError>;
}
pub enum ProfileUnlock { Passphrase(Arc<SecretBytes>), Platform }
pub enum ImportSource { Path(String), Bytes(Vec<u8>) }   // Bytes: at most the 64 MiB bound
pub struct ProfileSdkConfig { pub chain_profiles: Vec<ChainProfile>, pub rp_id: Option<String>, pub runtime: RuntimeChoice, pub clock: Option<Clock>, pub gas_tables: Vec<GasTable> }
impl UserProfile {
    pub async fn sdk(&self, config: ProfileSdkConfig) -> Result<Arc<Sdk>, SdkError>;  // the store, authenticator and limits are the profile's; a second call returns the same Sdk
    pub fn part_store(&self, part: ProfilePart) -> Result<Arc<dyn SecureStore>, SdkError>;   // pqvault
    pub fn pqchat_store(&self) -> Result<Arc<dyn PqChatStore>, SdkError>;                   // the synchronous face (§7.2)
    pub fn matrix_store(&self) -> Result<MatrixStore, SdkError>;                            // its directory and its store key (the one key that crosses)
    pub async fn settings(&self) -> Result<ProfileSettings, SdkError>;
    pub async fn set_settings(&self, s: ProfileSettings, passphrase: Option<Arc<SecretBytes>>) -> Result<(), SdkError>;  // §7.7
    pub async fn set_passphrase(&self, p: Arc<SecretBytes>, kdf: Option<KdfParams>, keep: SettingsChoices) -> Result<(), SdkError>;
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
impl Sdk { pub async fn close(&self); }   // new (§10): tasks stopped, pools dropped, a closed flag every call checks
impl Vault {   // the key lock (§7.4); ImportKey gains key_passphrase: Option<Arc<SecretBytes>>; seed ids are Strings, as today
    pub async fn unlock_key(&self, seed: String, key: ImportedKey, key_passphrase: Arc<SecretBytes>) -> Result<(), SdkError>;
    pub async fn lock_key(&self, seed: String, key: ImportedKey);
    pub async fn lock_key_separately(&self, seed: String, key: ImportedKey, key_passphrase: Arc<SecretBytes>) -> Result<(), SdkError>;
    pub async fn restore_previous(&self, confirm: ConfirmRestorePrevious) -> Result<(), SdkError>;   // PLANNED (§7.2)
}
```

**Built (wave 1, `f9a599996`) where it differs from the sketch:** `hide(passphrase)` and `rename(name, Option<passphrase>)` (a
hidden profile's duplicate search; decisions CLI-UPR-13's Change); `set_passphrase`'s `keep` is `keep_settings: Option<Vec<u8>>`,
the settings bytes the user kept; `ImportChoices { confirm, kdf }` (the confirmed item ids and the new profile's KDF parameters);
`ProfilesConfig` adds `kdf_max_kib`, `legacy` and `legacy_overlay` (the migration's sources, computed by the caller; the SDK reads
no environment); `ProfileUnlock` has `Passphrase` only; `ProfileKeychain` is synchronous as sketched (decisions CLI-UPR-22's
Change); `pqchat_store`, platform unlock and the `Vault` key-lock calls are wave 2. Added by the owner's rulings of
2026-11-28 (§1 O16 to O23): `set_passphrase(…, migrated: Option<ConfirmMigratedSeeds>)` and `migrated_seeds()` (O18),
`UserProfiles::purge_tombstones(ConfirmPurgeTombstones)` (O17), `UserProfiles::hidden_matches` and `open_hidden_match` (O20). The
built API:
`clients/scaas-sdk/src/user_profile/mod.rs` and `clients/scaas-profile/src/lib.rs`.

New codes (CLI-SDK-13's naming): `ProfileInUse`, `ProfileOpen`, `ProfileUnknown` (a `--profile` name or id with no visible
profile), `ProfileNameTaken`, `ProfileNameInvalid`, `ProfileLimit`, `ProfileHiddenLimit`, `ProfilePartFull`, `ProfileRootUnsafe`,
`ProfilePassphraseRequired`, `ProfilePassphraseWeak`, `ProfileFormat`, `ProfileVersion`, `ProfileKdfTooLarge`,
`ProfileKdfOutOfMemory`, `ProfileSearchTooLarge`, `ProfileImportOpen`, `ProfileExportTooLarge`, `ProfileHiddenAmbiguous` (two or
more hidden matches, O20), `ProfileLocked`, `ProfileBusy` (a
writer that waited 120 s on a re-seal), `KeyLocked`; events
`ProfileIndexMismatch`, `ProfileRollback`, `ProfileDamaged`. No code, event or `Debug` carries an id, a name, a passphrase or a path.
The `ua-rs` calls (the profile arena, the Argon2id wraps, the item seal and HMAC name, the label seal, the export chunk seal, the
dummy run) and the two formats need vector rows in clientkeys and `ua-rs` before code (AGENTS.md: byte formats everywhere at once);
the dummy run has no known answer and is checked by a count test.

## 12. Migration from today's single store (CLI-UPR-11; SPECIFIED)

Every chain is test-only, so **a one-time move into "default" is enough**; no old-layout reader and no compatibility path are kept.

- **Source:** the CLI's data directory as today on every OS: `--data-dir <dir>` when the command gives one (every test and CI run),
  else `$XDG_DATA_HOME/scaas`, else `$HOME/.local/share/scaas` (`clients/scaas-cli/src/config.rs`; on Windows `HOME` is normally unset
  and there was no store), and its overlay at `$XDG_CONFIG_HOME/scaas/overlay.json`, else `~/.config/scaas/overlay.json`. On macOS and
  Windows the new root (§5) differs from that path; on Linux it is the same directory.
- **When:** at `UserProfiles::new`, under the root lock **and** the legacy `keystore.lock`, only when the legacy items (`keystore`,
  `keystore.prev`, `sdk.state`) exist at the source **and** `p/` holds no profile directory; once started, it resumes only into the
  profile whose envelope says `migration: pending`. Legacy items at a source whose root already has profiles are ignored **and
  reported** (`Event::ProfileDamaged` with no name, and a line on the CLI's stderr), never migrated.
- **Steps:** (1) create "default" with `migration: pending` (unprotected, as at create, its row written); (2) move each legacy item
  into its `g0/` by `rename(2)` (same filesystem; copy, `fsync`, then remove across filesystems); re-name the keychain anchor and a
  seed's platform key under the id, or rewrite the anchor from the moved container (as `accept_rollback` writes it); move the overlay
  into `settings`; (3) `migration: pending` is cleared by `set_passphrase`'s commit, whose new envelope carries none (owner O22,
  2026-11-28): an unprotected `g0` accepts the moved keystore only under `migration: pending`, so the flag stays from the move
  until the seal. Each step is idempotent: an item already moved is absent at the source. A process of the old
  binary still running is held off by the legacy `keystore.lock`, and its later writes at the old path are reported at the next start.
- A migrated "default" holds secrets while unprotected, the one case: every `vault` and `app_core` call on it is refused
  `ProfilePassphraseRequired` until `set_passphrase` seals it (§7.3: the plain `g0` is removed only after the commit).
- **The seeds moved are confirmed** (owner O18, 2026-11-28): `migration: pending` is not authenticated, so before sealing the
  client shows `migrated_seeds()` (the count and labels of the keystore's seeds, its public fields, no unlock) and
  `set_passphrase` takes `ConfirmMigratedSeeds { seeds }` with that count; without it, or with another count,
  `ConfirmationMissing`, nothing written.

## 13. Per-client notes (CLI-UPR-16; SPECIFIED)

- **scaas-app desktop.** A start screen lists the visible names (`last` preselected) and always offers "Open another profile" (name
  and passphrase, the name field masked). A menu Profile → Lock, Switch, Rename, Hide / Show, Change passphrase, Settings, Export,
  Import, Delete. A second launch on an open profile shows "This profile is open in another window" (`ProfileInUse`). An unprotected
  profile is announced at every open.
- **scaas-app mobile.** One process; the switcher in settings; the root in the app's private directory, the app supplying the keychain
  interface; biometric unlock opt-in per visible profile on this device; the seeds' auto-lock on background as today; app extensions
  refused while the app has the profile open (Q-UP4); export through the share sheet, import from a picked file.
- **scaas-tui.** `--profile <name>` opens a visible profile; `--profile-hidden` asks for the name and the passphrase on the terminal
  without echo (CLI-TUI-16's means); with neither, a picker, else the one profile. An action `profile` (lock and switch) on every
  screen; the status line shows the visible name or "Hidden profile". The idle lock locks the seeds, not the profile (Q-UP6). At lock
  and switch the TUI clears an OSC 52 clipboard value it set.
- **CLI `scaas`.**
  - **Which profile:** `--profile <name>`, or `--profile-name-fd <fd>` (a visible profile chosen without argv), else the profile named
    "default"; a name with no visible profile is **`ProfileUnknown`**, never a passphrase prompt. **The CLI never follows `last`** (the
    apps' choice), and it prints the profile it uses on stderr on every command (`profile: <name>`, or `profile: hidden`).
    `--profile-hidden` reads the name and the passphrase from the terminal without echo or from `--profile-name-fd` and
    `--profile-passphrase-fd`.
  - **One descriptor per secret:** `--profile-passphrase-fd` (the profile's, the old one for a change), `--new-profile-passphrase-fd`
    (the new one of a change, and of `set_passphrase`), `--passphrase-fd` (a seed's vault passphrase, as today), `--key-passphrase-fd`
    (a key lock), `--export-passphrase-fd` (an export file); never the command line or the environment; one descriptor is never read
    for two secrets.
  - **Commands:** `scaas profile list | create | create-hidden | rename | hide | show | passphrase | platform-unlock | settings (show |
    set | import <file>) | export <file> | import <file> | delete | rebuild-index`. `list`, `create`, `create-hidden`, `import` and
    `rebuild-index` **open no profile** (and so never meet `ProfileInUse` for "default"). `settings import <file>` replaces the
    withdrawn `--overlay <file>`, applies CLI-TUI-06 and §7.7 (a weakening change asks the profile passphrase).
  - Each command that opens a profile is one instance (`ProfileInUse` while the TUI or the app has it open).
  - **Stated limits:** `--profile <name>` is visible in process listings to every local user, and `--profile-hidden` there tells that
    this user has a hidden profile (`--profile-name-fd` avoids the first); the `profile: <name>` line on stderr lands in CI and job
    logs.
  - **The chain-profile rename (§15) lands first**, so `--profiles <file>` and `--profile <name>` never sit one letter apart.
- **Browser (wasm), PLANNED.** One IndexedDB database per profile named by its id, the index in its own database, Web Locks, the same
  formats and parameters up to 256 MiB, and an async store core of its own: the synchronous core and pqchat-core's synchronous face
  do not carry there (§7.2).

## 14. Threat model (SPECIFIED)

| Adversary | Learns or can do | Bound |
|---|---|---|
| another OS user on the machine | nothing on Unix (root `0700`; files `0600`); on Windows the default ACL of `%APPDATA%`; a process listing shows a visible name given by `--profile <name>` and that `--profile-hidden` was used (§13) | OS permissions; an administrator is out of scope |
| a stolen disk, a copied home directory, a backup | the visible names (index and envelopes) and `last`; the number of profile directories and which have no public name (hidden); each id's creation time (UUIDv7, hidden ones included); per profile the number and sizes of its items and their outer revisions; an unprotected profile's settings; **no item name** (HMAC file names, §7.2) | every protected item and label sealed under `DEK_p` behind Argon2id per profile; seed and key vaults also behind their own passphrases; full-disk encryption recommended |
| an offline guesser of one profile's passphrase | one Argon2id run per guess at that profile's parameters; a success opens that profile's sealed store and none of another's, and no seed, imported key or key-locked key | passphrase strength (§7.6), parameters raisable per profile; per-item passphrases (§7.4) |
| someone at an unlocked OS session on a **shared OS account**, with platform unlock on | **opens the profile with any enrolled biometric** and reads what §7.4 lists; cannot export (the profile passphrase), cannot make a weakening settings change (§7.7), cannot open a seed on its passphrase alone or a key-locked key | **accepted risk** (owner O11, §14.1); mitigation: seeds and imported keys behind their own typed passphrases, never opened by platform unlock |
| someone at a session left open (the idle lock locks the seeds, not the profile, Q-UP6) | the same as the row above, without a biometric | the same bounds |
| a second instance (the same user's other window or command) | refused: `ProfileInUse` | the OS lock (§9); a malicious process of the same user is out of scope |
| someone watching the screen | the visible names only; no hidden name drawn; the hidden prompt always present; a failed hidden open costs the same for zero to four candidates at the default parameters | §8 |
| someone who writes the root or a profile directory (the other person on a shared account, a restore) | **denials, a writer's power:** delete or corrupt files; plant UUID directories without a usable envelope until hidden opens are `ProfileSearchTooLarge` (reported at start as damaged, removed by hand); delete a visible profile by `delete_locked` with its name typed (no passphrase, as removing its directory by hand would do anyway). plant a public name on a hidden profile's envelope, which only takes it out of the hidden prompt (the open through the list is refused and removes the hint); change a visible profile's shown name before unlock (the hint is outside the wraps), detected at unlock against the sealed label (`ProfileIndexMismatch`) and rewritten. **No disclosure:** rename or plant index rows (checked against the envelopes and the sealed label; a row on a hidden profile refused; the search ignores rows); plant an unprotected directory with a visible name and settings (announced as unprotected, its settings shown before sealing, §7.1); put back old copies (next row) | §6, §7.1, §7.2, §8 |
| someone who puts back an older copy | one item, a manifest or the envelope (a pre-`hide()` or pre-rename envelope included, its `rev` raised or not): `ProfileRollback` (§7.2); a whole directory under a deleted id, after a delete or after a tombstone a writer made: `ProfileRollback`, never opened, until the user purges the markers (O17); a listed item removed: `ProfileDamaged`; the keystore: `KeystoreRollback` as today; an old envelope never erases the live generation (§7.3); **the anchor file and what it covers, put back together, where the anchor is a file** (the CLI and the TUI on every OS, the desktop app on Linux): **not seen** (stated) | the keychain anchor where there is one; an old envelope with the old passphrase opens nothing written after a passphrase change (`DEK_p` rotated) |
| a network observer, an RPC node, a gateway, the Matrix homeserver | that several identities use one IP address and timing; never a profile id or name; after a switch, nothing more from the locked profile (`Sdk::close`) | non-goal (§2); ids never leave the device (§4) |
| a holder of an export file | the format, the KDF parameters, the chunk count and the length; nothing else without the export passphrase | Argon2id at the file's parameters per guess; inside, the seed and key vaults behind their own passphrases; no id, no PqChat state, no credential reference (§10.1) |
| someone who alters an export file, or hands the user a crafted one with its passphrase | an altered file fails as one error, nothing written; a crafted file brings only its own seeds and accounts (said in the review), and no endpoint, `first` mark, idle-lock or clipboard choice without the user's confirm of each, **no credential reference at all**, no PqChat state, no operation followed without the user's word; every kept setting shown in the review | §10.1 |
| a decryption-oracle attacker (ARCH-POS-13) | nothing: the profile layer opens only the user's own envelopes and items, and export files the user picks, with passphrases the user types, and answers only the local user; it decrypts no ciphertext that arrives from the network, sends nothing before a whole import has opened, validated and been committed, follows no imported operation and processes no imported envelope without the user's word | every failure of an open, a hidden search or an import is one code to the user |

### 14.1 Accepted risks (owner)

- **Platform unlock on a shared OS account** (owner 2026-11-27, O11): everyone enrolled on that OS account opens the profile by
  biometrics, and reads what §7.4 lists. Accepted; mitigated by per-item passphrases (§7.4), never opened by platform unlock, and by
  §7.7 (no weakening settings change without the typed passphrase).
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
| `scaas-rpc` | `src/evm.rs`, `src/ton.rs` (prose); `runs/2026-11-22-evm-probes.py`'s own `--profile <key>` (a chain profile) | "chain profile"; `--chain-profile <key>` |
| EVM chain data | `smartcontracts/evm/src/chains/<key>/profile.json` (18 files) and the `README.md` in each `src/chains/<key>/`; `script/forkcheck.py` (29 lines), `script/test_forkcheck.py` (41), `script/deploy_pqchatstore.py` (10), `script/test_deploy_pqchatstore.py` (12), `script/onchain/{verify.sh, matrix.sh, README.md}`; the README's "Chain profiles" row and "EVM profiles" heading | `chain-profile.json`; the scripts and prose follow |
| run scripts that name the file | `runs/2026-11-21-avax-dot-arweave-review-mutants.py` (17 lines, `…/avalanche-testnet/profile.json`) and the other `runs/2026-11-21-avax-dot-arweave-*-mutants.py` | the new path |
| Solidity comments | `smartcontracts/evm/src/ua/{UARegistry.sol, UARegistryRegLib.sol, UARegistryAuxLib.sol, MlDsaVerifyOnly.sol}`, `test/ua/UARegistry.t.sol` | "chain profile" in comments; the commit runs the format-only check (every contract's runtime and init bytecode byte-identical, the size gate) |
| root docs | the root `README.md` (4 lines) and its anchor `docs/architecture.md#profiles` | "chain profile", the anchor renamed with its links |
| clients | `clients/clientkeys/src/evm.js` (8 lines), `clients/ua-rs/src/wallet/policy.rs` (3) | "chain profile" |
| vectors | `smartcontracts/vectors/ua/sign.json` (4 text fields, e.g. "a DEX off the profile") | regenerated by its generator from the renamed source text, never hand-edited |
| mutant runner | `clients/scaas-sdk/runs/2026-11-17-scaas-sdk-t22-mutants.py` (matches source text holding `dev-profiles` and `--profiles`) | its patterns follow |
| TUI (docs only; no code yet) | `tui.toml` "the default profile", per-profile caps (spec §10), "release profiles" (CLI-TUI-11), `--profiles`, `dev-profiles` | `default_chain_profile`, caps per chain profile, "release chain profiles", `--chain-profiles`, `dev-chain-profiles` |
| prose | "profile" meaning a chain's pinned data | "chain profile" |

**Not renamed** (not a chain profile), the gate's exemption list: Cargo `[profile.*]` build sections; Foundry's `[profile.*]` sections
and `FOUNDRY_PROFILE`; `WRAPLIMITS_PROFILE` and `script/onchain/WrapLimits.s.sol`'s two test profiles and `wraplimits.sh`; the Aptos
CLI's `--profile deployer` (`smartcontracts/move/aptos/scripts/`); the node's code and data (`scaas-node/src/config.rs`'s `profile`,
`node.example.toml`, `scaas-node/tests/`) and its own `profile` fields (`integration.md:93`, `:764`, the `pqz` job profile at
`integration.md:176`); `pqz-core/`; "browser profile" (`signers-clientkeys.md`, `app.md:368`); "profiling"; `TODO.md`, `COMPLETED.md`,
`docs/history/`, every `legacy/` (never edited). **A clash to keep, stated:** the node's mesh vectors carry a signed field
`"chain_profile": "public"` (`scaas-node/tests/vectors/mesh-envelope-v1.3.json`, 54 lines) meaning public or private, in signed bytes;
it stays as it is, so after the rename "chain profile" has two meanings across the SDK and the node, and the docs say which is meant
where both appear.

**Where the word is used for chain profiles** (lines matching "profile", the exclusions removed; `git grep -ci` at `644ea61a8`):
139 hand-written files and 1,424 lines in the places first listed, plus 117 generated binding files (1,886 lines) that follow by
regeneration, plus the review's additions in the table above.

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

**The rename task's gate:** a grep over the paths listed in this section (the table and the list above) for the renamed identifiers,
the renamed file names and the word "profile", with the exemption list above read by the gate as a path and pattern list, must reach
zero at its commit.

### 15.2 Forward notes on rules this spec changes when built

- [CLI-SDK-17](../../clients/scaas-cli.md#CLI-SDK-17) and SDK spec §6.3: the shared data directory becomes the shared root; an open
  profile is never shared (CLI-UPR-14); restoring `keystore.prev` by hand becomes `vault.restore_previous()`.
- [CLI-TUI-06](../../clients/scaas-tui.md#CLI-TUI-06): the overlay "one file for the CLI and the TUI" becomes the profile's sealed
  `settings`; the CLI's `--overlay` is withdrawn for `scaas profile settings import`; a weakening change needs the profile passphrase.
- [CLI-TUI-12](../../clients/scaas-tui.md#CLI-TUI-12) and [CLI-TUI-14](../../clients/scaas-tui.md#CLI-TUI-14): the lowered caps and
  the clipboard opt-in live in the profile's `settings`, not `tui.toml`; the clipboard value the TUI set is cleared at profile lock.
- SDK spec §6.9: a sealed item's size bound is the base64 of its plain bound plus 1 KiB, and `rev_of` reads it to that bound;
  `keystore.head` stays unsealed; `StoreError` gains `VaultFormat`, `ProfileLocked`, `ProfilePassphraseRequired`, `ProfileRollback`,
  `ProfileDamaged`.
- SDK spec §6.7, §6.10, §6.11 and CLI-SDK-03: the key lock adds the label form `native-import-locked:<network>:<n>`, skipped by every
  seed-wide loop, left out of the sealed backup and the device link (§7.4).
- pqchat-core (CLI-PQC-09): its store calls run on a blocking task over the profile's synchronous sealed face; `StoreFault` carries a
  code.

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

### 16.1 Owner rulings after the review (owner 2026-11-27, O12)

| # | Question | Ruling | Where |
|---|---|---|---|
| Q-UP10 | A hidden profile whose passphrase is lost can be neither named nor deleted (§10) | as recommended: the app neither names nor deletes it; the user removes its directory by hand; no call deletes unlisted directories (such a call would let anyone at the OS account delete another person's hidden profile without a passphrase) | §8, §10; CLI-UPR-15 |
| Q-UP11 | The narrowing of Q-UP5's content (§10.1, marked *) | as recommended: a profile export leaves out `keystore.prev`, the PqChat store and credential references | §10.1; CLI-UPR-18 |

No open question remains.

## 17. Tests (SPECIFIED; for the plan)

Each negative test has its positive control and its named mutant, which must turn it red (AGENTS.md; runners through
`scripts/mutant_guard.py`). Suites use the `test-hooks` parameter set (§7.5) except the bound tests.

| Group | Test | Positive control | Mutant |
|---|---|---|---|
| lock (§9) | a second `open` in another process is `ProfileInUse`; a SIGKILLed holder leaves a lock the next `open` takes at once; the hidden search locks only the match; a CLI command's start does not make an app's open of another profile `ProfileInUse` | two different profiles open side by side | the instance lock dropped; lock taken before the search reads; start taking every profile's lock |
| G1 names | no item or part name appears in any file name of a protected profile's generation, nor in any plain byte of it (a pqchat key with a UA and a room id); scope: the index, an unprotected envelope and `keystore.head` are plain by design | the manifest, opened, lists them | the HMAC name replaced by the item name |
| G2 AEAD | two seals of the same (part, name, rev, plaintext) differ; an item moved to another name, part or rev fails; the wrap's AD bytes equal the vector's (the `seal_key` prefix included) | the item in place opens | a fixed nonce; the part or the name left out of the AD; the AD over the whole envelope |
| G3 state | `state` flipped to `unprotected`, a plain item in a protected profile, a sealed item in an unprotected one: each refused; with the keychain marker, an unprotected envelope beside it is `ProfileFormat` and a missing anchor `ProfileRollback`; a missing marker is rewritten at a protected open; an unprotected profile's settings shown before `set_passphrase` seals them | the untouched profile opens | the state check removed; `state` or `name` left out of the wrap's AD |
| store files (R2-A-1) | a kill between a FileStore write and its rename leaves `*.tmp.*`; the next open removes it and opens; `.lock` files are accepted; any other file is `VaultFormat` | a clean generation opens | the pattern check refusing `.lock` or `.tmp.*`; no clean-up at open |
| G4 crash | a crash at each step of `set_passphrase`, `change_passphrase`, create, import and migration leaves the old or the new profile whole, and the next open or start finishes or rolls back; two processes migrating at once make one "default" | the same actions without a crash | the journal ignored; the envelope renamed before the generation is complete; no root lock at migration |
| re-seal writes (R2-A-2, R2-C-4) | a writer of every part (SDK, pqchat-core) running through a `change_passphrase`: every write issued during the re-seal waits (never `StoreConflict`) and is present after the commit, and a pqchat counter never goes backwards; a writer held past 120 s (a stalled re-seal under `test-hooks`) is `ProfileBusy` and writes nothing | a re-seal with no writer | the store write lock not held during the re-seal; a waiting writer answered `StoreConflict` |
| generations (R2-C-5, R3-C-1) | an older envelope put back beside the live `g<N>/`: `ProfileDamaged` / `ProfileRollback`, `g<N>/` kept; an envelope whose `gen` was edited upward beside the only generation: `ProfileDamaged`, nothing removed; a lower generation removed at open only after the wrap opened and `g<gen>/` exists; a journaled `g<N+1>/` removed before its journal; a passphrase change drops the platform wrap | a normal open after a commit | removing every generation other than `gen`; removing a lower generation before the wrap opens |
| G5 rollback | an old copy of `settings` (or any item) put back is `ProfileRollback`; a deleted item put back (at or below its tombstone) is `ProfileRollback`; a listed item removed is `ProfileDamaged`; an old manifest or a pre-`hide()` envelope under the anchor is `ProfileRollback`; after a passphrase change the old envelope with the old passphrase opens no item written after; two writers of different items of one part both land in its manifest | the current copies open with no event | the manifest's rev not compared; no tombstone at delete; the envelope not in the anchor; `DEK_p` kept at a passphrase change; the manifest written without `put_if` |
| anchor (R3-A-1) | a kill between a manifest write and its anchor, and between an envelope write and its anchor, opens with no event and the anchor follows; the CLI (no keychain) and the desktop app (a keychain) taking turns on one profile on macOS open with no event; a manifest or envelope below the anchor, or another hash at the same rev, is `ProfileRollback` | an untouched profile opens | "differs from the anchor" as the rule; the envelope's `rev` not compared |
| name hint (R3-B-1) | `rename`, `hide()`, `show()` need no passphrase and leave `pass` and `platform.wrap` byte-identical; after `rename` a platform open still works; a hint changed on disk opens, raises `ProfileIndexMismatch` and is rewritten from the label; a hint planted on a hidden envelope: the open through the list refused, the hint removed, the hidden prompt finds the profile again | the hint unchanged opens with no event | `name` kept in the wraps' AD; the hint trusted over the label |
| re-created items, tombstones (N-2, N-3) | an item deleted then created again opens with no event (its rev above the tombstone); after a re-seal the new manifests hold no tombstone | an item never deleted | the stored rev restarting at the caller's revision; tombstones carried into the new generation |
| G6 platform | another profile's wrap, a wrong secret, an all-zero secret, a policy without `biometry_current_set` or `invalidated_by_enrollment`: each refused; enable on a hidden profile is `Argument`; `hide()` and a passphrase change drop the wrap | the enabled wrap opens its own profile | the policy check removed; the profile id left out of the wrap's AD |
| G7 hidden | runs counted (not timed) equal max(candidates, 4) for 0, 1, 4 and 5 candidates, a corrupt candidate among them one dummy run; the 17th `create_hidden`, hidden import and `hide()` are `ProfileHiddenLimit`; at 16 hidden profiles plus damaged directories (up to 32 candidates) each still opens; 33 candidates are `ProfileSearchTooLarge`; a duplicate (name, passphrase) at `create_hidden`, hidden import, `hide()`, a hidden rename and a hidden passphrase change is `ProfileNameTaken`; a planted row on a hidden profile: the open through it refused, the row dropped, the prompt still finds the profile; `create_hidden` writes no index byte | the one match opens | an early stop at the match; a corrupt candidate ending the search; candidates read from the index; `hide()` without the duplicate check; `last` written on a hidden open |
| G8 KDF | parameters below and above the bounds, each field alone, refused before any KDF (a counter); above this device's maximum `ProfileKdfTooLarge`; a forced allocation failure `ProfileKdfOutOfMemory`; a release build refuses `test-hooks`; no KDF runs under the root lock (a second instance's start completes during a hidden search) | the default and a raised in-bounds set open | out-of-memory mapped to `ProfileOpen`; the per-device maximum not checked; a KDF under the root lock |
| G9 export, import | export without the profile passphrase refused; the file never holds an id, a lock, a keychain item, `keystore.prev`, a PqChat item, a credential reference or a cache (checked on the payload); a truncated, reordered, extended or one-byte-changed file (header included) is `ProfileImportOpen` with nothing written; a `chunk` other than 1,048,576, a header above 4 KiB, an item name other than `keystore` / `sdk.state` or one twice: refused; payloads of exactly 1 MiB and 1 MiB + 1 round-trip; a crafted file's credential reference is dropped even when every endpoint is confirmed; its endpoints, `first` marks, idle lock and clipboard choice are dropped without a confirm; `import_preview` lists every setting, kept ones included, and writes nothing to disk (a crash during the review leaves no file); the temporary directory `import` writes holds only sealed items; its operations in flight are not followed; a payload above 64 MiB is `ProfileExportTooLarge`; an existing file or a symlink at the export path is refused; another instance's start during a preview leaves its temporary directory | the unchanged file imports: a new id, the same seed fingerprints, a new PqChat device id | the last-chunk flag ignored; parse before verify; settings imported whole; a filter that forgets credential references; start removing a temporary directory whose `build.lock` is held; a preview written to disk in plain form |
| settings (R2-C-3) | an added endpoint, a `first` mark, a credential reference, the idle lock off and the clipboard on, each without the typed profile passphrase: refused; with a platform unlock only: refused | a lowered cap and a stronger policy pass without it | the passphrase check removed |
| G10 index, delete | a deleted and a corrupt index are rebuilt (never a first run) and list every visible profile, protected ones included; two envelopes with one visible name are both listed and marked; a crash at each step of delete leaves a tombstone that start finishes; a directory without an envelope is reported, never removed; a locked visible profile deletes with `ConfirmDeleteUnreadable`; legacy items beside existing profiles are reported | an intact index lists as before | a missing index treated as a first run; the clean-up removing a directory without an envelope; a rebuild listing only unprotected profiles |
| G11 SDK fit | a sealed item at the plain 16 MiB bound reads its `rev` and is written at it; a sealed item that does not open is `VaultFormat` (not `VaultIo`); a call after lock is `ProfileLocked`, from the SDK and from pqchat-core (`StoreFault` with its code); after lock no request leaves on the old `Sdk` (`Sdk::close`); `lock` with a hidden set open on a seed that is not unlocked revokes it (A-8's fix); `sdk()` twice returns the same `Sdk` | a small item round-trips | `rev_of`'s 16 MiB cap kept for sealed items; `StoreError` collapsed to `Io`; the lock leaving the stores open; `close` not called at lock |
| G12 CLI, paths | the CLI ignores `last`; a `--profile` name with no visible profile is `ProfileUnknown`; one descriptor per secret (`passphrase` reads two descriptors); `list`, `create`, `import`, `rebuild-index` open no profile; an existing root at `0755` holding `p/` is tightened; a wider foreign directory given as a root is `ProfileRootUnsafe`; a symlinked root is refused; migration reads `--data-dir` and `$HOME/.local/share/scaas` on macOS; the Windows directory `fsync` and a tombstone rename while files are open (one run each settles them) | `--profile` names the profile | the CLI following `last`; the root's mode not tightened; a symlinked root accepted; one descriptor read for two secrets |
| key lock (§7.4) | a key-locked import is not opened by the seed's passphrase unlock, the seed's passkey or platform unlock, or the profile's platform unlock; signing with it locked is `KeyLocked`; `unlock_key` with its passphrase opens it; the seed's passphrase change with a key-locked key present succeeds and leaves that vault byte-identical; enabling the seed's platform unlock while the key is open adds no envelope to it; a `native-import-locked:` vault with a `prf` envelope is `VaultFormat` (vector); `lock_key_separately` leaves no `native-import:` vault of that key in the new container **or in `keystore.prev`**; a seed backup and a device link leave key-locked keys out and say how many | the same key without a key lock opens with the seed | the key vault sealed with the seed's PRF envelope; a seed-wide loop not skipping `native-import-locked:`; `keystore.prev` not rewritten |
| G15 zeroisation | the profile arena is wiped at lock (the arena's existing wipe test extended); heap buffers are `Zeroizing` by type, which a test cannot observe: only the arena part is tested, stated | an open profile's arena holds its keys | a key kept in the arena past lock |
| vectors | UUIDv7 rows built by `uuid::Builder::from_unix_timestamp_millis` from a timestamp and random bytes; envelope wrap AD, item, HMAC name, manifest, label and export-chunk rows (the pinned bytes of §7.1, §7.2 and §10.1); `name_key` rows (NFC / NFD, a no-break space, case) | clientkeys and `ua-rs` read the same rows | — |
| end-to-end | two instances on one machine, two profiles, a PqChat 1:1 session over a local Matrix homeserver and a local chain | — | — |
| Matrix per profile (CLI-UPR-29; wave 2) | two profiles, two Matrix sessions over a local homeserver: two logins, two device ids, two stores under two store keys, each key a sealed item of its own profile; no file, key or session of one is read by the other; a switch closes the first client before the second opens | one profile's session survives its lock and reopen | one `matrix/` store or device id shared by two profiles; the store key kept outside the profile's sealed store; the client left open at a switch |

## 18. Rule ids

| Id | Rule | Owner |
|---|---|---|
| CLI-UPR-01 | "Profile" on screen, `UserProfile` in code; "chain profile" / `ChainProfile` for a chain's data; the rename a later task, `ChainProfileMismatch` included | yes (O1, Q-UP8) |
| CLI-UPR-02 | in the SDK layer, used by every client; Change 2026-11-27: the store lives in `scaas-profile`, used by the SDK and by scaas-app's default build | yes (O2, O13) |
| CLI-UPR-03 | many profiles per machine, each its own directory with its store, chat and vault state and settings | yes (O3) |
| CLI-UPR-04 | each protected separately, own passphrase and KDF parameters, biometric opt-in; one opens nothing of another | yes (O4) |
| CLI-UPR-05 | "default" on first run; the passphrase asked at the first secret | yes (O5) |
| CLI-UPR-06 | one instance per profile by a lock file and a named error; instances meet only over network paths | yes (O6) |
| CLI-UPR-07 | switching locks as a seed lock does, then opens the other | yes (O7) |
| CLI-UPR-08 | the list shows names only; a profile may be hidden and opened by typing its name | yes (O8) |
| CLI-UPR-09 | the profile id is a UUIDv7 | yes (O9) |
| CLI-UPR-10 | the id: stable, names the directory, the name a label, never leaves the device, not derived | no |
| CLI-UPR-11 | layout on a directory on every platform, the index as a cache rebuilt from public names, migration from the CLI's data directory | no |
| CLI-UPR-12 | protection: `DEK_p`, the envelope and its public name, refusals by state, unprotected until the first secret, the platform wrap | no; Q-UP1, Q-UP2 yes |
| CLI-UPR-13 | hidden profiles: at most 16, `create_hidden`, duplicates refused on every path, the bounded search over envelopes; not deniable on disk | no; Q-UP7, Q-UP9 yes |
| CLI-UPR-14 | the instance lock: non-blocking OS advisory lock, no stale state, the search locks only the match | no; Q-UP3, Q-UP4 yes |
| CLI-UPR-15 | lifecycle: create, rename, hide, delete by tombstone, delete of a locked profile; export and import by CLI-UPR-17 | no; Q-UP10 yes |
| CLI-UPR-16 | client surfaces: `--profile`, `--profile-name-fd`, `--profile-hidden`, one descriptor per secret, `ProfileUnknown`, the CLI never follows `last`, pickers | no; Q-UP6 yes |
| CLI-UPR-17 | a whole profile exports and imports as one sealed file | yes (O10, Q-UP5) |
| CLI-UPR-18 | the export file's means: no id, chunked seal pinned, size bound, verify then parse, credential references always dropped, the profile passphrase | no; Q-UP11 yes |
| CLI-UPR-19 | the sealed store: AES-256-GCM-SIV with random nonces, pinned framed AD, HMAC file names, one manifest per part with tombstones, the anchor over generation, manifests and envelope | no |
| CLI-UPR-20 | crash safety: the re-seal journal written as protected, generations removed only below or when journaled, the root lock held briefly, the create journal, tombstones | no |
| CLI-UPR-21 | KDF bounds per field and per device, `p` fixed, named refusals, the `test-hooks` feature | no |
| CLI-UPR-22 | SDK fit: the profiles config with a keychain interface, the profile's own `Sdk` and `Sdk::close`, store errors, the sealed size bound, the synchronous pqchat face | no |
| CLI-UPR-23 | platform unlock on a shared OS account is an accepted risk; each seed and imported key may carry its own passphrase, never opened by platform unlock | yes (O11) |
| CLI-UPR-24 | the key lock's means: the label form, skipped by every seed-wide loop, refused with a `prf` envelope, out of backups and links, `keystore.prev` rewritten | no |
| CLI-UPR-25 | writes during a re-seal: the store write lock held for the whole run, every writer waits, no write lost | no |
| CLI-UPR-26 | a settings change that could weaken the profile needs the typed profile passphrase | no |
| CLI-UPR-27 | import in two calls: a preview of every setting held in memory, then the import of the user's choices, sealed from its first byte | no |
| CLI-UPR-28 | the anchor is compared as the keystore's: ahead is a crash and the anchor follows; below, or another hash at the same rev, is a rollback; the envelope has a `rev` | no |
| CLI-UPR-29 | each profile has its own Matrix (logins, session, store, crypto keys, device id) sealed in it; nothing shared; one `scaas-matrix` client per open profile, closed first at a switch | yes (O14) |
| CLI-UPR-32 | scaas-app's default build links `ua-rs` with the profile-crypto features only (`user-profile` = `key-handles`, and `json`); no signing code compiled in; checked on the rlib's symbols | yes (O15) |

## 19. Review response (Fable, 2026-11-27; the controller's rulings, owner may veto)

**Round 1** (at `06d9843d5`):

| Group | Findings | Applied in |
|---|---|---|
| G1 item names leak | B-1 | §7.2 file names, §14 stolen disk; CLI-UPR-19 |
| G2 AEAD and nonce | B-2, B-13, C-14 | §7.1, §7.2; CLI-UPR-19 |
| G3 envelope state, plain items | B-3, C-5 | §7.1 refusals by state, the residual; CLI-UPR-12 |
| G4 crash safety | A-1, A-2, A-3, B-4 | §7.3, §10 journal, §12 locks; CLI-UPR-20 |
| G5 rollback claims | B-5, C-6 | §7.2 manifest and anchor, §7.3 rotation, §14; CLI-UPR-19, CLI-UPR-20 |
| G6 platform unlock | B-6, C-9 | §7.1 `K_plat`, §7.6 policy and hidden; C-9 ruled by the owner (O11, §14.1, §7.4); CLI-UPR-12, CLI-UPR-23, CLI-UPR-24 |
| G7 hidden profiles | B-7, B-8, B-10, B-14, C-3, C-4, C-11 | §6, §8, §9; CLI-UPR-13, CLI-UPR-14 |
| G8 KDF bounds and cost | A-11, B-9, C-12 | §7.5; CLI-UPR-21 |
| G9 export and import | A-12, B-11, C-1, C-2, C-8, C-12 | §10.1 (B-11 asked for no streaming; the ruling chose the chunked seal); CLI-UPR-18 |
| G10 index, delete | A-4, A-5, C-7, C-10 | §6, §10, §12; CLI-UPR-11, CLI-UPR-15, CLI-UPR-20 |
| G11 SDK fit | A-6, A-7, A-14, A-15 | §7.2, §9, §11; CLI-UPR-22 |
| G12 CLI, paths, OS | A-9, A-10, C-13, C-15 | §4, §5, §12, §13, §14; CLI-UPR-11, CLI-UPR-16 |
| G13 rename list | A-13 | §15; CLI-UPR-01 (list only) |
| G14 forward notes, tests | A-16, A-17, B-16, C-16, C-17 | §15.2, §17, CLI-UPR-15's entry |
| G15 zeroisation | B-12, B-15 | §7.1, §7.2; CLI-UPR-19 |
| A-8 | `lock_all` misses a hidden set on a locked seed | fixed in code on branch `fix-lock-all-hidden` (`e3b58fba3`); cross-referenced in §10 and §17 |

**Round 2** (at `fa51e8275`):

| Topic | Findings | Applied in |
|---|---|---|
| store files | R2-A-1, R2-B-9 | §5 the generation's accepted names and the unprotected `g0`, §7.1, §7.2 (no part name handed to another store); CLI-UPR-11, CLI-UPR-19 |
| writes during a re-seal | R2-A-2, R2-C-4 | §7.3 step 1; CLI-UPR-25 |
| generations, journal, anchor | R2-B-5, R2-B-6, R2-C-5 | §7.2 anchor, §7.3 (journal written as protected, platform wrap dropped, removal rules); CLI-UPR-20 |
| manifests | R2-A-10, R2-B-2, R2-C-10 | §7.2 (per part, reserved identity, tombstones, missing items, bound, cost, `restore_previous`, every client without a keychain); CLI-UPR-19 |
| hidden cap, rebuild, duplicates, old envelopes | R2-B-1, R2-C-7, R2-C-8, R2-C-9 | §6 public visible names and the rebuild, §8 the cap of 16 and duplicates on every path, §7.2 the envelope in the anchor, §14 the writer's denials; CLI-UPR-11, CLI-UPR-12, CLI-UPR-13 |
| key lock | R2-B-3, R2-B-4 | §7.4 (loops skip, reader refusal, backups and links, `keystore.prev`); CLI-UPR-24 |
| import and settings | R2-A-4, R2-C-1, R2-C-2, R2-C-3 | §10.1 (two calls, every setting shown, credential references always dropped, the root lock around the commit only), §7.7; CLI-UPR-18, CLI-UPR-26, CLI-UPR-27 |
| SDK and app cores | R2-A-3, R2-A-5, R2-A-6 | §5, §7.2, §10, §11 (a directory on every platform with a keychain interface; the synchronous pqchat face, chosen because it never waits on a future; `StoreFault` codes; `Sdk::close`); CLI-UPR-22 |
| rename list | R2-A-7 | §15 (the places added, the exemption list, the mesh vectors' clash kept, the gate over listed paths); CLI-UPR-01 (list only) |
| smaller | R2-A-8, R2-A-9, R2-A-11, R2-B-7, R2-B-8, R2-C-6, R2-C-11, R2-C-12 | §4 `Builder::from_unix_timestamp_millis`; §5 modes; §7.1 the pinned AD and the unprotected-profile residual; §7.5 `test-hooks` in three crates; §10 start without other profiles' locks; §10.1 the pinned chunk encoding and item names; §11 `ProfileSdkConfig`, String seed ids, `ProfileUnknown`; §13 descriptors, commands without a profile, `--profile-name-fd`, logs; §14 `delete_locked` among a writer's denials; §17; CLI-UPR-18's title |

**Round 3** (at `9f2ee89b7`; area C approve, areas A and B approve with one P1 each, no P0):

| Topic | Findings | Applied in |
|---|---|---|
| the anchor's comparison | R3-A-1, B N-1 | §7.1 the envelope's `rev`, §7.2 the keystore's rule (ahead follows; below or another hash at the same rev is a rollback), every client writing `profile.head`; CLI-UPR-28 |
| the visible name in the wraps' associated data | R3-B-1 | §6, §7.1 (`name` a hint outside the AD, checked against the sealed label after unlock), §8, §10 (`rename`, `hide()`, `show()` without a passphrase, the wraps untouched), §14; CLI-UPR-12, CLI-UPR-13 |
| a lower generation removed before authentication | R3-C-1 | §7.3 (only when `g<gen>/` exists and the wrap opened; else `ProfileDamaged`); CLI-UPR-20 |
| re-created items, tombstones, the search cap | B N-2, N-3, N-4 | §7.2 (rev above the tombstone; tombstones dropped at a re-seal), §8 (the search accepts 32 candidates; hidden profiles stay capped at 16); CLI-UPR-13, CLI-UPR-19 |
| the import preview on disk | R3-C-2, A P2 | §10.1 (the payload held in memory; the temporary directory written only by `import`, sealed); CLI-UPR-27 |
| a planted public name on a hidden envelope | R3-C-3 | §6, §14 (a denial); CLI-UPR-13 |
| pqchat-core's face, waiting writers, the browser | A P2, P3 | §7.2 (`Items` the one helper, 33 sites in 9 files; the browser needs an async core), §7.3 (writers wait at most 120 s, then `ProfileBusy`), §13; CLI-UPR-22, CLI-UPR-25 |
