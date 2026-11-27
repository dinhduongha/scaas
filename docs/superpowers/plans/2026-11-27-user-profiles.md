# User profiles: many protected local profiles in the SDK layer: build plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or
> superpowers:executing-plans to implement this plan task by task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Status (2026-11-27):** PLANNED; wave 1 runs now, wave 2 later. Spec:
[`2026-11-27-user-profiles.md`](../specs/2026-11-27-user-profiles.md) (SPECIFIED, a frame; Fable reviewed it in three rounds, every
finding applied, spec §19). Rules: [clients/scaas-sdk.md](../../clients/scaas-sdk.md) §12, CLI-UPR-01 to CLI-UPR-32, recorded in
[decisions.md](../../decisions.md) §41. Owner rulings O1 to O15 and Q-UP1 to Q-UP11 (spec §1, §16) are fixed and not reopened here.
UNAUDITED: every line this plan builds stays UNAUDITED.

**Owner rulings 2026-11-27 after UP5:** (O13, CLI-UPR-02's Change) the store is its own crate `clients/scaas-profile` over `ua-rs`
only, used by the SDK and by scaas-app's default build; UP5's core moved there (`74b860488`), and UP6 to UP10 build their store
parts there, the SDK keeping what needs an `Sdk` (each task's **Files** below). (O14, CLI-UPR-31) each profile has its own Matrix
logins, session, store, crypto keys and device id, sealed in it; wave 1 builds only the Matrix store key as a sealed item. (O15,
CLI-UPR-32) `scaas-profile` links `ua-rs` with `user-profile` (= the new feature `key-handles`) and `json` only, no signing code;
`app-core` = `key-handles` + `wallet`; task KH, checked by `clients/ua-rs/runs/2026-11-27-key-handles-nm.py`.

**Branch:** `user-profiles` from `dev` at `a739cee1f` (it holds `fix-lock-all-hidden`, review A-8, which the lock of spec §10
relies on), worktree `.claude/worktrees/user-profiles`. Commits local, staged by explicit path; **no push, no merge**.

**Goal of wave 1:** every new byte format of the spec has a generator in clientkeys and rows that clientkeys and `ua-rs` (and the
SDK, for the UUIDv7 and `name_key` rows) read; `ua-rs` holds the profile arena and every KDF, AEAD and MAC of the spec; the crate
`scaas-profile` builds the profile root, the index cache, the instance lock, the sealed store with its manifests, tombstones and
anchor, the re-seal, hidden profiles, delete, migration, export and import and the storage of settings; the SDK module
`user_profile` (feature `user-profile`) builds the `SecureStore` face, the code mapping, `UserProfile::sdk`, `Sdk::close()` and the
settings' chain-profile meaning; each under its §17 tests with a positive control and a named mutant.

**Wave 2** (after the path-less TreeKEM and TUI branches land on `dev`): the chain-profile rename (spec §15), the CLI's
`--profile` and `scaas profile …` commands, the pqchat-core and pqvault-core store adapters (the synchronous `PqChatStore` face
over the wave-1 core, `Items` made `async`), platform unlock (`enable_platform_unlock`, `disable_platform_unlock`, the SDK's use of
`K_plat`), the SDK's key-lock calls (`ImportKey.key_passphrase`, `unlock_key`, `lock_key`, `lock_key_separately`, `KeyLocked`, the
skips in `vault/prf.rs` and `vault/seeds.rs`, the backup and device-link counts), TUI T15, scaas-app's pickers, the bindings of
the `user_profile` surface, the two-instance PqChat e2e (§17 "end-to-end"), and the per-profile Matrix e2e (CLI-UPR-31, §17
"Matrix per profile": two profiles, two Matrix sessions, no shared state, a switch closing the first client).

## Global constraints (read before every task)

- AGENTS.md in full. Heavy commands (`cargo`, `npm`, `node` generators at 64 MiB Argon2id) through `scripts/capped`,
  **foreground**, never inside `timeout`, never in the background; `CARGO_INCREMENTAL=0`, `-j2`; MemAvailable at least 4 GB before
  a heavy step (`grep MemAvailable /proc/meminfo`); a `[capped] waiting for a free slot` line means wait, never raise
  `CAPPED_SLOTS` or `CAPPED_MEM`. No docker. No `sleep` / `until` / `pgrep -f` loops; no background shell left. Stop at a
  controller "pause".
- Durable notes in the main checkout's `scratchpad/user-profiles/`, never this worktree's `scratchpad/`. Never print
  `scratchpad/testnet-wallet.txt`.
- **TDD.** The test first; run it; see it fail for the stated reason; paste that red line into the commit body (`red: …`); then
  the code; green. Every negative test has its positive control in the same test. Each task's mutants (listed) go through one
  runner per task, `clients/scaas-sdk/runs/2026-11-27-user-profiles-<task>-mutants.py` (the pattern of
  `clients/scaas-sdk/runs/2026-11-17-scaas-sdk-lockall-mutants.py`: `mutants_lib.main`, which goes through
  `scripts/mutant_guard.py`), `check` then `run`; its record `…-<task>-mutants.txt` committed (last line `N mutants, N killed, 0
  survived, 0 not loaded, 0 other failure`). A JavaScript mutant uses the same runner with an `npm test` command.
- **Byte formats change everywhere at once.** A format exists first as a generator row in clientkeys
  (`clients/clientkeys/scripts/profile-vectors.mjs` → `smartcontracts/vectors/profile/*.json`); `ua-rs` and the SDK read the same
  rows; no reproducer edited alone; vectors never edited by hand (regenerate, then `git diff` reads the change).
- **Not touched in wave 1:** the chain-profile names (spec §15: `SdkConfig.profiles`, `ProfileMismatch`, `dev-profiles`, …),
  `clients/scaas-sdk/src/pqchat_tree.rs`, `clients/ua-rs/src/wallet/tree.rs`, the TUI crate (other branches edit them).
- Secrets: every KDF, AEAD and MAC runs in `ua-rs` (CLI-SDK-01, CLI-SDK-02); the SDK holds handles and public bytes only. Key
  material in the profile arena or `Zeroizing`; no id, name, passphrase or path in a `Debug`, error, event, log line or panic.
  `clippy::{unwrap_used, expect_used, panic, indexing_slicing}` stay denied in `src/` as the crates have them.
- New files carry `SPDX-License-Identifier: LicenseRef-Vegan-Community-1.0`. English. No machine or temp path in a committed file
  (tests use `tempfile` / `std::env::temp_dir()` plus a random suffix at run time).
- A red pin, bound or test is reported with its output, never edited to green. Generated bindings change only by
  `clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh` (UP4).
- Docs: status tags BUILT only where code and tests exist (UP12); the spec's and rules' text otherwise stays.

Abbreviations: `W` = the worktree root; `cap` = `"$W/scripts/capped"`; `C` = `--locked --offline -j2`; `UPF` =
`--features user-profile,test-hooks`; `T` = a `mktemp -d` directory.

**Gate commands** (each task names the ones it runs; results as rows `task | step | commit | rc | counts` in
`clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt`, full output in git-ignored `.log` files beside it):

| Step | Command (from `W`) |
|---|---|
| `ck` | `cd clients/clientkeys && $cap npm test` |
| `ck-gen` | `cd clients/clientkeys && $cap node scripts/profile-vectors.mjs "$T" && diff -r "$T" ../../smartcontracts/vectors/profile` |
| `ua-profile` | `cd clients/ua-rs && $cap cargo test C --features user-profile,test-hooks,vectors --test profile --test app_core` |
| `ua-clippy` | `cd clients/ua-rs && $cap cargo clippy C --all-targets -- -D warnings && $cap cargo clippy C --all-targets --features user-profile,test-hooks,vectors -- -D warnings` |
| `ua-vault` | `cd clients/ua-rs && $cap cargo test C --test wallet_vault --test wallet_custody --test retained_key --test wallet_import_ua` |
| `prof` | `cd clients/scaas-profile && $cap cargo test C && $cap cargo test C --features test-hooks && $cap cargo clippy C --all-targets -- -D warnings && $cap cargo clippy C --all-targets --features test-hooks -- -D warnings` |
| `kh-nm` | `python3 clients/ua-rs/runs/2026-11-27-key-handles-nm.py` (CLI-UPR-32: no signing symbol in the `user-profile` rlib, the `wallet` build's as control; `scaas-profile`'s graph) |
| `sdk-up` | `cd clients/scaas-sdk && $cap cargo test C UPF --test user_profile && $cap cargo test C UPF --lib user_profile` |
| `sdk-reg` | `cd clients/scaas-sdk && $cap cargo test C --test vault --test keystore_vectors && $cap cargo test C --lib vault` |
| `sdk-clippy` | `cd clients/scaas-sdk && $cap cargo clippy C --all-targets UPF -- -D warnings && $cap cargo clippy C --all-targets -- -D warnings` |
| `features` | `python3 scripts/check_test_features.py && cd clients/scaas-sdk && $cap cargo test C --test feature_tree` |
| `bind-gen` | `bash clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh --check` (UP4 only) |
| `fmt` | `scripts/format.sh --check rust js toml` with the main checkout's `scratchpad/tools/bin` on `PATH` |
| `docs` | `python3 scripts/docs_check.py check && python3 scripts/test_docs_check.py` |

## Pinned formats (controller calls, 2026-11-27, where the spec leaves the encoding open)

These fill only what spec §7 and §10.1 leave open; everything the spec pins stays as pinned. Each is a row of the generator.

1. **base64** everywhere in the profile formats (salts, wraps, `sealed`, `label`, `nonce_prefix`): RFC 4648 §4, standard
   alphabet, padded.
2. **Canonical JSON**: no whitespace, fields in the order the spec lists them (else as below), integers in decimal, strings as
   `JSON.stringify` / `serde_json` write them (the same escapes for the ASCII and NFC text these formats hold).
3. **`DEK_p`** is a `Derive` handle (usage byte 1 in the `seal_key` prefix); `KEK_pass`, `K_plat` are `KeyWrap` handles;
   `K_label`, `K_item`, `K_x` are `Data` handles; `K_name` is a `Derive` handle whose HMAC output is public (the file name).
   HKDF salt is empty for every key of spec §7.1.
4. **Wraps** (`pass`, `platform.wrap`): `seal_key` output, `nonce ‖ ct ‖ tag` (60 bytes), AD = `"scaas/ua/v1/keywrap" ‖ 0x01 ‖
   lp("scaas.profile.wrap" | "scaas.profile.platform") ‖ public JSON`, public JSON =
   `{"format":"scaas.profile","v":1,"id":"<id>","state":"protected","gen":N,"kdf":{"alg":"argon2id","v":1,"m":M,"t":T,"p":4,"salt":"<b64>"}}`.
5. **Label** plaintext: `{"name":"<NFC>","hidden":false|true}`; sealed `nonce ‖ ct ‖ tag`, AD spec §7.1.
6. **Item on disk**: `{"rev":N,"sealed":"<b64 of nonce ‖ ct ‖ tag>"}`; AD and file name spec §7.2; `N` = the item's stored rev.
7. **Manifest** (the item `manifest:<part>` of part `profile`, plaintext):
   `{"format":"scaas.profile-manifest","v":1,"part":"<part>","rev":M,"items":[["<name>",rev],…],"tombstones":[["<name>",rev],…]}`,
   each list sorted by the name's UTF-8 bytes, a name in at most one list; `M` equals the manifest item's stored rev.
8. **Anchor** (`profile.head` and the keychain item `scaas.profile.<id>.head`):
   `{"gen":N,"envelope":{"rev":R,"sha256":"<32 hex>"},"parts":{"<part>":{"rev":M,"sha256":"<32 hex>"},…}}`, parts sorted by
   name; `sha256` is the first 16 bytes of SHA-256 of the file's bytes (the envelope file; the manifest item's file), lower-case
   hex. **Compare** (CLI-UPR-28), per component (gen, envelope, each part the anchor names): stored above the anchor → `follow`;
   below, or the same rev with another hash, or a part the anchor names whose manifest is missing → `rollback`; a part on disk the
   anchor does not name → `follow`. The verdict: `rollback` if any component says so, else `follow` if any does, else `same`.
9. **Export payload** spec §10.1; its label JSON is item 5's; its settings JSON is the SDK's `ProfileSettings` serialisation
   (opaque bytes to the format rows).
10. **UUIDv7** as `uuid` 1.23.0's `Builder::from_unix_timestamp_millis(ms, &r)` builds it: bytes 0–5 `be48(ms)`, byte 6 `0x70 |
    (r[0] & 0x0f)`, byte 7 `r[1]`, byte 8 `0x80 | (r[2] & 0x3f)`, bytes 9–15 `r[3..10]`; canonical lower-case 36-character form.
11. **The test KDF set** (spec §7.5): `m = 8192` KiB, `t = 1`, `p = 4`, accepted only under feature `test-hooks`.

## Tasks and order (wave 1)

| Task | What | Depends on |
|---|---|---|
| UP0 | baseline: the summary file, the touched crates green before any change | — |
| UP1 | clientkeys `src/profile.js` + generator + vectors for every new format; clientkeys reads them | UP0 |
| UP2 | `ua-rs` `ProfileKeys` (profile arena), the Argon2id envelope with bounds, item seal, HMAC names, label seal, export chunk seal, the dummy run, `test-hooks`; reads UP1's rows | UP1 |
| UP3 | the key-lock vault label `native-import-locked:` in `ua-rs` and clientkeys: accepted, skipped by seed-wide loops, refused with a `prf` envelope, out of the backup payload; vector row | UP0 |
| UP4 | SDK foundations: `StoreError` and `SdkError` codes, `Event` variants, `vault::io` mapping, `rev_of`'s sealed bound, features `user-profile` / `test-hooks`, `check_test_features.py`, the bindings regenerated | UP2 |
| UP5 | sealed store core (in `scaas-profile` since O13): generations, manifests, tombstones, anchor, store write lock with `ProfileBusy`, the `SecureStore` face, the unprotected `g0` | UP4 |
| UP6 | profile root, index cache and rebuild, UUIDv7, `name_key`, envelope, instance lock, start, create, open, list, lock, `UserProfile::sdk()`, `Sdk::close()` | UP5 |
| UP7 | re-seal: `set_passphrase`, `change_passphrase`, KDF raise; journal and generation rules; `ProfilePassphraseRequired` on an unprotected profile | UP6 |
| UP8 | hidden profiles: `create_hidden`, `open_hidden` (counted search), `hide`, `show`, `rename`, duplicates, limits | UP7 |
| UP9 | delete by tombstone, `delete_locked`, `rebuild_index`, migration of the CLI's legacy store into "default" | UP7 |
| UP10 | `ProfileSettings`, `set_settings` with the §7.7 rule, export, `import_preview`, `import` | UP8, UP9 |
| UP11 | wave-1 closing gates on the final tree (every step above once), the summary | UP1–UP10 |
| UP12 | docs: status tags of what is built, decisions §41 statuses, the spec's status line | UP11 |

## Spec §17 → tasks

| §17 group | Wave 1 task | Left for wave 2 |
|---|---|---|
| lock (§9) | UP6 (second open, SIGKILLed holder, two profiles side by side, start takes no live lock); UP8 (search locks only the match) | the CLI command beside an app's open (CLI) |
| G1 names | UP5 | — |
| G2 AEAD | UP1 + UP2 (AD bytes, two seals differ, moved item fails), UP5 (in the store) | — |
| G3 state | UP6 (state flip, plain / sealed refusals, keychain marker), UP7 (settings shown before `set_passphrase`: the call's `keep` input) | the client's announcement |
| store files (R2-A-1) | UP5 | — |
| G4 crash | UP7 (re-seal), UP6 (create journal), UP9 (migration, delete), UP10 (import) | — |
| re-seal writes (R2-A-2, R2-C-4) | UP5 (the lock, `ProfileBusy`), UP7 (a writer through `change_passphrase`) | the pqchat-core writer |
| generations (R2-C-5, R3-C-1) | UP7 | the platform wrap drop (with platform unlock) |
| G5 rollback | UP5 | — |
| anchor (R3-A-1) | UP1 (compare rows), UP5 | the CLI / desktop turns on macOS |
| name hint (R3-B-1) | UP8 | platform open after `rename` |
| re-created items, tombstones (N-2, N-3) | UP5, UP7 | — |
| G6 platform | UP2 (the `K_plat` wrap's AD row, another profile's wrap fails) | the SDK's enable / disable, policy checks |
| G7 hidden | UP8 | — |
| G8 KDF | UP2 (bounds in `ua-rs`, OOM code), UP6 (bounds before any KDF, per-device maximum, no KDF under the root lock), UP4 (`test-hooks` refused in a release build) | — |
| G9 export, import | UP1 (format rows), UP2 (chunk seal), UP10 | — |
| settings (R2-C-3) | UP10 | platform-unlock-only case |
| G10 index, delete | UP6 (rebuild), UP9 | — |
| G11 SDK fit | UP4 (`rev_of` bound, codes), UP5 (`VaultFormat`), UP6 (`ProfileLocked`, `Sdk::close`, A-8 lock, `sdk()` twice) | pqchat-core's `StoreFault` code |
| G12 CLI, paths | UP6 (root modes, symlinked root, foreign directory), UP9 (migration source paths) | the CLI's flags and descriptors; the Windows row |
| key lock (§7.4) | UP3 (the label, the refusals, loops, backup payload) | the SDK calls and their tests |
| G15 zeroisation | UP2 | — |
| vectors | UP1, UP2, UP6 (UUIDv7 and `name_key` read by `scaas-profile`) | — |
| end-to-end | — | two instances, PqChat 1:1 |
| Matrix per profile (CLI-UPR-31) | UP6 (the Matrix store key, a sealed item of the profile; two profiles, two keys) | two profiles, two Matrix sessions, no shared state; a switch closes the client |

## UP0 — Baseline

**Files:** `clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt` (new).

- [ ] Fresh-worktree inputs: `scripts/vendor.sh link <dev worktree> core kat research`, then `check`; `clients/clientkeys/node_modules`
      copied (`cp -a`) from the dev worktree.
- [ ] Run `ck`, `ua-vault`, `sdk-reg`, `features`, `docs` on the untouched tree: the baseline rows.
- [ ] Commit the summary with this plan's first execution commit (not alone).

## UP1 — clientkeys reference and vectors

**Files:** `clients/clientkeys/src/profile.js` (new), `clients/clientkeys/scripts/profile-vectors.mjs` (new),
`clients/clientkeys/test/profile.test.js` (new), `smartcontracts/vectors/profile/{ids,envelope,items,export}.json` (new,
generated), `smartcontracts/vectors/README.md` (a row).

`profile.js` (noble / scure only, as `pqvault.js`): `uuid7(ms, r10)`; `nameKey(s)` (NFKC, `toLowerCase`) and `checkName(s)` (NFC,
1–64 bytes, no Cc / Cf: `ProfileNameInvalid`); `lp`; `publicJson(env)`; `wrapAd(domain, publicJson)` (with the `seal_key` prefix);
`kekPass(pass, salt, kdf)` (OpaqueString as `ua-rs` `passphrase_bytes`, Argon2id, HKDF); `kPlat(secret, salt)`; `subKeys(dek)`
(`K_label`, `K_item`, `K_name`); `sealWrap` / `openWrap`; `labelAd(id)`, `sealLabel` / `openLabel`; `itemAd(part, name, rev)`,
`itemFile(kName, part, name)`, `sealItem` / `openItem`, `itemJson`; `manifestJson(part, rev, items, tombstones)`;
`anchorJson(...)`, `anchorCompare(stored, anchor)`; export: `exportHeader(kdf, salt, prefix)`, `exportKey`, `payload(label,
settings, items)`, `exportFile(...)`, `importFile(...)` with its refusals; every seal takes its nonce as an input (the generator
fixes them; the SDK draws them).

Rows (`rnd(name, n)` as `pqvault-vectors.mjs`, prefix `scaas/profile/vectors/`):

- `ids.json`: UUIDv7 rows (`ms` 0, a 2026 time, `2^48 − 1`; random bytes all zero, all `ff`, `rnd`); `nameKey` rows (NFC vs NFD
  "é", a no-break space, "ǅ"/"Ǆ" case, "ß", "İ", full-width "Ａ"), `checkName` refusals (empty, 65 bytes, a Cc, a Cf (U+200B),
  64 bytes accepted).
- `envelope.json`: at the default set (one row: 64 MiB / 3 / 4) and the test set (rows): passphrase, OpaqueString bytes, salt,
  Argon2id output, `KEK_pass`, `DEK_p`, nonce, public JSON, wrap AD, `pass`; the platform wrap (secret, 32-byte salt, `K_plat`,
  AD, wrap); `K_label`, `K_item`, `K_name`; label rows (visible, hidden) with AD and sealed bytes; the whole envelope file of a
  protected profile and of an unprotected one; refusals: `state` flipped, `gen` changed, a salt changed, a wrap moved to another
  id, all failing the wrap (`Aead`); a `name` hint changed: the wrap still opens (name outside the AD).
- `items.json`: item rows (part, name, rev, plaintext, nonce, AD, sealed, file JSON, file name) for `sdk`/`keystore`, a pqchat key
  holding a UA and a room id, `manifest:sdk` of part `profile`; refusals: another name, part, rev (`Aead`); two seals of one item
  with two nonces differ; manifest rows (with tombstones; a re-created item above its tombstone); anchor rows and every
  `anchorCompare` case of pinned format 8.
- `export.json`: header bytes; small payload: the whole file in hex; payloads of exactly 1 MiB and 1 MiB + 1 by a pinned filler
  (`rnd` stream): the file's SHA-256, its length, chunk count, its first and last 64 bytes; refusals (truncated, a chunk dropped,
  two chunks swapped, a chunk appended, the last flag cleared, a header byte changed, `chunk` ≠ 1,048,576, `header_len` > 4,096, an
  item name other than `keystore` / `sdk.state`, `keystore` twice, `sdk.state` before `keystore`, payload > 64 MiB by length
  only): each `ProfileImportOpen` with its local reason.

- [ ] Tests first (`profile.test.js`): every row recomputed from its inputs and equal; every refusal refused with its code; red
      before `profile.js` exists (`ERR_MODULE_NOT_FOUND`), then each function red until written.
- [ ] Write `profile.js`, the generator; generate; read the diff.
- [ ] Mutants (`up1`, `npm test` command): the HMAC name over the item name only (no part); the last-chunk flag ignored at import;
      `rev` left out of the item AD; `name` inside the wrap's public JSON; `anchorCompare` "differs" as rollback (ahead not
      followed).
- [ ] Gates: `ck`, `ck-gen`, `fmt` (js), `docs`. Commit `user-profiles UP1: clientkeys profile formats and vectors`.

## UP2 — `ua-rs` profile primitives

**Files:** `clients/ua-rs/src/wallet/profile.rs` (new), `clients/ua-rs/src/wallet/mod.rs` (module, error codes),
`clients/ua-rs/src/wallet/appkey.rs` (only what `ProfileKeys` reuses: visibility, an explicit-nonce seal), `clients/ua-rs/Cargo.toml`
(features `user-profile = ["app-core"]`, since task KH `["key-handles"]` (O15), `test-hooks = ["user-profile"]`), `clients/ua-rs/tests/profile.rs` (new).

`ProfileKeys`: an `AppKeys` scope over a `SecretStore` of its own (an empty arena, no seed: the arena's locked pages and wipe),
holding `DEK_p` and its sub-keys after `create` or an open; `lock()` wipes it (every later call `WalletLocked`), drop wipes it.
Calls (names may follow the code's style; the bytes are UP1's):

- `ProfileKeys::new()`, `create_dek()`; `kdf_check(kdf)` (general bounds: `m` 65,536–1,048,576 KiB, `t` 3–10, `p` = 4; under
  `test-hooks` also exactly the test set; else `Argument`); `wrap_pass(passphrase, salt, kdf, public)`, `open_pass(passphrase,
  salt, kdf, public, wrap)` (`Aead` for a wrong passphrase or an altered wrap), `check_pass(...)` (the typed passphrase opens the
  wrap to the held `DEK_p`, constant time; for export and §7.7); `wrap_platform(secret, salt, public)`, `open_platform(...)`
  (refuses an all-zero secret: `Argument`); `seal_label(id, json)`, `open_label(id, sealed)`; `item_file(part, name)` (64 hex);
  `seal_item(part, name, rev, pt)`, `open_item(part, name, rev, sealed)` (random nonce; `Aead`); `dummy_kdf(kdf)`.
- `ExportKey::derive(passphrase, salt, kdf)`; `seal_chunk(prefix, i, last, header, pt)`, `open_chunk(...)`.
- Argon2id's `OutOfMemory` is the new error `KdfOutOfMemory` (code `KdfOutOfMemory`), never `Argument`; under `test-hooks` a hook
  forces it, and a counter counts every Argon2id run (`kdf_runs()`), dummy runs included.
- Fixed-nonce twins under `vectors` only (as `vectors_seal`).

- [ ] Tests first (`tests/profile.rs`, reading `smartcontracts/vectors/profile/*.json`): every envelope, label, item, file-name and
      export row reproduced byte for byte; the refusals; two `seal_item` of one input differ (G2); a moved item fails (G2); the
      bounds, each field alone below and above, refused before any KDF (`kdf_runs()` unchanged, G8); the test set refused without
      `test-hooks` (a compile-time branch: the test asserts it under `cfg(not(feature = "test-hooks"))` in a second run of the
      lib tests without the feature); OOM forced → `KdfOutOfMemory`; G15: the arena holds keys while open and none after `lock()`
      (the arena's wipe test pattern, `store::vectors`), every call after `lock()` `WalletLocked`.
- [ ] Mutants (`up2`): a fixed nonce in `seal_item`; the part left out of the item AD; `KdfOutOfMemory` mapped to `Argument`; the
      `m` lower bound not checked; `lock()` not wiping the arena.
- [ ] Gates: `ua-profile`, `ua-clippy`, `ua-vault` (regression), `fmt` (rust), `docs`. Commit `user-profiles UP2: ua-rs profile
      arena and seals`.

## UP3 — The key-lock vault label

**Files:** `clients/ua-rs/src/wallet/{manifest.rs,vault.rs}`, `clients/ua-rs/tests/wallet_vault.rs` (rows), clientkeys
`src/vault.js` / `src/keystore.js` (whichever reads label vaults), the keystore vector generator and its rows in
`smartcontracts/vectors/keystore/keystore.json`.

- [ ] Tests first: a `native-import-locked:<network>:<n>` label is a canonical label form (sealed with a pin envelope only; the
      same parse rules as `native-import:`); sealing it with a `prf` envelope is refused, and **reading** a vault of that label that
      carries a `prf` envelope is `VaultFormat` in `ua-rs` and clientkeys (a vector row both read); `reseal_label_vault` and
      `open_label_vault_retained` refuse or skip it (never open it with the seed's key); the backup payload (`scaas/backup/v1`)
      and the device link leave it out and return how many were left out; the positive twin: the same key as `native-import:`
      opens with the seed and travels in the backup.
- [ ] Mutants (`up3`): the reader not refusing a `prf` envelope on a locked label; `reseal_label_vault` not skipping the locked
      label; the backup payload keeping the locked key.
- [ ] Gates: `ua-vault`, `ua-clippy`, `ck`, the keystore generator's check, `fmt`, `docs`. Commit `user-profiles UP3: key-lock
      vault label`.

## UP4 — SDK foundations

**Files:** `clients/scaas-sdk/src/vault/{store.rs,mod.rs}`, `src/error.rs`, `src/events.rs`, `src/lib.rs` (feature bits),
`src/wasm/js.rs` (the store error names), `clients/scaas-sdk/Cargo.toml` (features `user-profile = ["vault", "file-store",
"scaas-ua/user-profile"]`, `test-hooks = ["user-profile", "scaas-ua/test-hooks"]`, each with its feature bit appended),
`scripts/check_test_features.py` (`test-hooks` a test feature), the generated bindings (by the generator only).

- [ ] Tests first: `StoreError` gains `VaultFormat`, `ProfileLocked`, `ProfilePassphraseRequired`, `ProfileRollback`,
      `ProfileDamaged`, each mapped by `vault::io` to the `SdkError` of the same name (a table test; `Io` still `VaultIo`);
      `SdkError` gains the codes of spec §11 (`ProfileInUse` … `KeyLocked`, appended; `OWN_CODES` test); `Event` gains
      `ProfileIndexMismatch`, `ProfileRollback`, `ProfileDamaged` (no field carries an id, name or path); `rev_of` reads a sealed
      item's outer `rev` up to the base64 of 16 MiB plus 1 KiB (a sealed item at the plain bound reads its rev; one byte above
      reads `u64::MAX`), the plain bound unchanged for plain items; `check_test_features.py` refuses `test-hooks` in a production
      graph (its positive control as the script's others).
- [ ] Regenerate the bindings (`…-gen.sh`), read the diff (only the new variants).
- [ ] Mutants (`up4`): `vault::io` collapsing every new code to `VaultIo`; `rev_of` keeping the 16 MiB cap for sealed items;
      `test-hooks` missing from the script's test features.
- [ ] Gates: `sdk-reg`, `sdk-clippy`, `features`, `bind-gen`, `fmt`, `docs`. Commit `user-profiles UP4: SDK store codes, features`.

## UP5 — The sealed store core

**Files:** `clients/scaas-profile/src/{lib.rs,store.rs,anchor.rs,file.rs}`, `clients/scaas-profile/tests/store.rs` (the core's
tests; moved from the SDK by O13, `74b860488`); in the SDK `src/user_profile/mod.rs` (the `SecureStore` face, the code mapping) and
`tests/user_profile.rs` (`required-features = ["user-profile", "test-hooks"]`: the face, the codes).

One synchronous core per open profile (file I/O and AEAD blocking): the generation directory `g<N>/`, the parts' manifests, the
store write lock (`std::sync::Mutex` or a fair lock; a writer waits at most 120 s, then `ProfileBusy`; `test-hooks` shortens the
wait and can stall a re-seal), the anchor (`profile.head`, and the optional `ProfileKeychain` of spec §11). The `SecureStore`
face for part `sdk` (`spawn_blocking`), `keystore.head` passed through to the profile directory unsealed. Writes as spec §7.2
(item `put_if`, manifest `put_if` at its read rev, three tries, `StoreConflict`; then the anchor); delete writes the tombstone
first; a re-created item continues above its tombstone and the face shows the caller's revision. Reads: §7.2's rollback and
damage rules. Open-time clean-up of `*.tmp.<pid>.<n>`; any other name in `g<N>/` `VaultFormat`. The unprotected `g0` face: plain
names, part `sdk`, `settings` only (and `keystore`, `keystore.prev`, `sdk.state` only under `migration: pending`), a sealed item
refused (`ProfileFormat`). Bounds: 65,536 entries per part (`ProfilePartFull`), the 16 MiB plain bound.

- [ ] Tests first (G1, store files, G5, anchor, re-created items): no item or part name in any file name or plain byte of a
      generation (control: the opened manifest lists them); a kill between a FileStore write and its rename leaves `*.tmp.*`,
      the next open removes it; `.lock` accepted, any other file `VaultFormat`; an old item put back `ProfileRollback`; a deleted
      item put back `ProfileRollback`; a listed item removed `ProfileDamaged`; an old manifest under the anchor `ProfileRollback`;
      two writers of two items of one part both land in the manifest; a kill between a manifest write and its anchor opens with no
      event and the anchor follows; a manifest below the anchor or another hash at its rev `ProfileRollback`; an item deleted then
      created again opens with no event; a writer blocked past the (shortened) wait is `ProfileBusy` and writes nothing; a sealed
      item that does not open is `VaultFormat` (not `VaultIo`); the anchor compare also checked against UP1's rows.
- [ ] Mutants (`up5`): the HMAC name replaced by the item name; the manifest's rev not compared; no tombstone at delete; the
      manifest written without `put_if`; "differs from the anchor" as the rule; the `.lock` / `.tmp.*` pattern refused; no clean-up
      at open; a waiting writer answered `StoreConflict`.
- [ ] Gates: `prof`, `sdk-up`, `sdk-reg`, `sdk-clippy`, `fmt`, `docs`. Commit `user-profiles UP5: sealed store core`.

## UP6 — Root, index, envelope, open and lock

**Files:** `clients/scaas-profile/src/{root.rs,index.rs,envelope.rs,names.rs,profile.rs}` (new: root, index, envelope, instance
lock, start, create, open, list, lock, the keychain marker, the KDF bounds and the per-device maximum, the Matrix store key item),
`clients/scaas-profile/tests/`; in the SDK `src/user_profile/mod.rs` (`UserProfiles` over the crate, `UserProfile::sdk`, the heavy
limiter around the crate's KDF calls, `ProfileKdfOutOfMemory` from `scaas-ua`'s `KdfOutOfMemory`), `src/lib.rs` (`Sdk::close()`,
the closed flag), `tests/user_profile.rs`.

`ProfilesConfig`, `ProfileKeychain`, `UserProfiles::{new, list, create, open}`, `UserProfile::{sdk, lock}`, `UserProfileInfo` (its
`Debug` redacts the id), `ProfileUnlock::Passphrase` (platform in wave 2), `KdfParams` with the per-device maximum (desktop 1 GiB;
a config field lowers it), the heavy limiter of the profiles (`Limits.max_concurrent_heavy`), Argon2id never under the root lock.
Root: `Dir` only; a symlinked root refused; mode tightened to `0700` only when it holds `profiles.json` or `p/` or was made by the
SDK, else a wider mode `ProfileRootUnsafe`. Index: bounded (64 KiB, depth 4, 32 rows), canonical, unknown fields refused,
`put_if` at its rev under the root lock (`profiles.json.lock`), rebuilt from envelopes' public names whenever missing or
unparsable while `p/` holds a profile (never a first run). Start: the journal finished or undone, `.tmp-*` removed when its
`build.lock` is free, tombstones removed when their instance lock is free, damaged directories reported (`Event::ProfileDamaged`,
never removed), no live profile's lock taken. First run: "default" created unprotected and listed. Open: `instance.lock` by
`File::try_lock` before the envelope is read (`ProfileInUse`), the envelope bounded and refused by state (§7.1), the row and the
hint checked against the sealed label (`ProfileIndexMismatch`, rewrite), `last` written when it changes. Lock: `vault.lock_all()`,
`Sdk::close()` (watchers, followers, trackers stopped; pools dropped; every later call `ProfileLocked`), the stores refusing
(`ProfileLocked`), the arena destroyed, the lock released. `sdk()` twice returns the same `Sdk`. UUIDv7 and `name_key` read UP1's
rows.

- [ ] Tests first: lock group (a second `open` in another process `ProfileInUse`, by a child process of the test binary; a
      SIGKILLed holder's lock taken at once; two profiles open side by side; start takes no live profile's lock); G3 (state flipped,
      plain item in a protected profile, sealed item in an unprotected one, the keychain marker rules with a test keychain); G8 (an
      out-of-bounds envelope `ProfileFormat` and an above-device one `ProfileKdfTooLarge`, before any KDF: `kdf_runs()`; a second
      instance's start completes during a held KDF); G10 rebuild (deleted and corrupt index list every visible profile, protected
      ones included; two envelopes with one visible name both listed with the event); G11 (`ProfileLocked` after lock from the
      `Sdk` and the store face; after lock no request leaves on the old `Sdk`; `lock` with a hidden set open on a locked seed
      revokes it; `sdk()` twice the same); G12 paths (a `0755` root holding `p/` tightened; a wider foreign directory
      `ProfileRootUnsafe`; a symlinked root refused); the UUIDv7 and `name_key` rows.
- [ ] Mutants (`up6`): the instance lock dropped; start taking every profile's lock; the state check removed; a missing index treated
      as a first run; a rebuild listing only unprotected profiles; `close` not called at lock; the root's mode not tightened; a
      symlinked root accepted; the per-device maximum not checked; a KDF under the root lock.
- [ ] Gates: `prof`, `sdk-up`, `sdk-reg`, `sdk-clippy`, `fmt`, `docs`. Commit `user-profiles UP6: profile root, index, open and lock`.

## UP7 — Re-seal

**Files:** `clients/scaas-profile/src/{reseal.rs,profile.rs}`, `clients/scaas-profile/tests/`; in the SDK `src/user_profile/mod.rs`,
`tests/user_profile.rs`, and the vault's secret-creating calls
(`generate`, `import_words`, `derive_child`, `derive_from_signature`, `derive_from_key`, `import_key`, `create_passkey_key`,
`create_se_key`, the app core's first key) refused `ProfilePassphraseRequired` before any work on an unprotected profile's `Sdk`.

`set_passphrase(p, kdf, keep)` (the passphrase rule `ProfilePassphraseWeak` on the OpaqueString form; `keep` = the settings items
the user keeps, the rest dropped before sealing), `change_passphrase(old, new, kdf)` (a new `DEK_p`), a raise of the parameters:
one procedure under the instance lock and the store write lock for the whole run, spec §7.3 steps 1–5; the open-time rules
(journal → roll back, `g<N+1>/` removed first; a lower generation removed only when `g<gen>/` exists and the wrap opened; a
higher one with no journal `ProfileDamaged`, never removed); tombstones dropped at the re-seal; the plain `g0` of a migrated
"default" removed only after the commit; crash points injected under `test-hooks` after each step.

- [ ] Tests first: G4 (a crash at each step of `set_passphrase` and `change_passphrase` leaves the old or the new profile whole, the
      next open finishes or rolls back); re-seal writes (a writer of part `sdk` through a `change_passphrase` waits, is present after
      the commit, never `StoreConflict`; held past the wait `ProfileBusy`); generations (an older envelope beside the live `g<N>/`:
      `ProfileDamaged` / `ProfileRollback`, `g<N>/` kept; an edited-upward `gen` beside the only generation: `ProfileDamaged`,
      nothing removed; a journaled `g<N+1>/` removed before its journal); G5 (after a passphrase change the old envelope with the
      old passphrase opens no item written after); tombstones gone after a re-seal; `ProfilePassphraseRequired` before any work (a
      call counter) and the positive twin after `set_passphrase`; the settings kept or dropped by `keep`.
- [ ] Mutants (`up7`): the journal ignored at open; the envelope renamed before the generation is complete; removing every
      generation other than `gen`; removing a lower generation before the wrap opens; `DEK_p` kept at a passphrase change;
      tombstones carried into the new generation; the store write lock not held during the re-seal.
- [ ] Gates: `prof`, `sdk-up`, `sdk-reg`, `sdk-clippy`, `fmt`, `docs`. Commit `user-profiles UP7: re-seal`.

## UP8 — Hidden profiles

**Files:** `clients/scaas-profile/src/{hidden.rs,profile.rs,index.rs}`, `clients/scaas-profile/tests/`; the SDK's
`src/user_profile/mod.rs` and `tests/user_profile.rs` for the async calls over them.

`create_hidden`, `open_hidden` (spec §8 steps 1–3: candidates from `p/` only, ≤ 32 else `ProfileSearchTooLarge`, `max(candidates,
4)` runs, each at its own parameters, damaged candidates one default run, dummy runs to four, no early stop, the match's lock taken
after the search, re-read under it), `hide`, `show`, `rename` (no passphrase; wraps byte-identical), the duplicate search on every
hidden path, at most 16 hidden (`ProfileHiddenLimit`), `last` never written by a hidden open, `create_hidden` writes no index byte.

- [ ] Tests first: G7 (runs counted for 0, 1, 4, 5 candidates, a corrupt one costs one run; the 17th `create_hidden` and `hide()`
      `ProfileHiddenLimit`; 16 hidden plus damaged directories up to 32 candidates still open; 33 `ProfileSearchTooLarge`; duplicates
      at `create_hidden`, `hide()`, a hidden rename, a hidden passphrase change `ProfileNameTaken`; a planted row on a hidden
      profile refused, dropped, the prompt still finds it; no index byte at `create_hidden`); name hint (R3-B-1: `rename`, `hide`,
      `show` leave `pass` byte-identical; a hint changed on disk raises `ProfileIndexMismatch` and is rewritten; a planted hint on a
      hidden envelope: the open through the list refused, the hint removed, the hidden prompt finds it); the lock group's "the
      search locks only the match".
- [ ] Mutants (`up8`): an early stop at the match; a corrupt candidate ending the search; candidates read from the index; `hide()`
      without the duplicate check; `last` written on a hidden open; `name` in the wraps' AD (the hint trusted over the label); the
      lock taken before the search reads.
- [ ] Gates: `prof`, `sdk-up`, `sdk-clippy`, `fmt`, `docs`. Commit `user-profiles UP8: hidden profiles`.

## UP9 — Delete, rebuild, migration

**Files:** `clients/scaas-profile/src/{lifecycle.rs,migrate.rs,root.rs}`, `clients/scaas-profile/tests/`; the SDK's
`src/user_profile/mod.rs` (the vault calls refused on a migrated "default", the `backup: pending` check of `delete`) and
`tests/user_profile.rs`.

`delete_preview`, `delete` (the name typed again as `ConfirmDeleteProfile`; `ConfirmDeleteUnbacked` with a `backup: pending` seed;
tombstone rename under the root lock, the row dropped, the keychain items removed, the tombstone removed), `delete_locked` (the
instance lock, the name, `ConfirmDeleteUnreadable`), `rebuild_index(ConfirmRebuildIndex)`. Migration (spec §12): a `legacy`
config input (the CLI's data directory path and its overlay path; the SDK reads no environment), under the root lock and the
legacy `keystore.lock`, only when legacy items exist and `p/` holds no profile; steps 1–3 idempotent; legacy items beside existing
profiles reported (`Event::ProfileDamaged`), never migrated.

- [ ] Tests first: G10 (a crash at each delete step leaves a tombstone that start finishes; a directory without an envelope
      reported, never removed; a locked visible profile deletes with `ConfirmDeleteUnreadable`; legacy items beside profiles
      reported); G4 (a crash at each migration step resumes into the same "default"; two processes migrating at once make one
      "default"); a migrated "default" refuses vault calls `ProfilePassphraseRequired` until `set_passphrase`, which removes the plain
      `g0` only after the commit; the migrated keystore opens with its seed afterwards (the positive control).
- [ ] Mutants (`up9`): the clean-up removing a directory without an envelope; no root lock at migration; migration ignoring
      `migration: pending` on resume.
- [ ] Gates: `prof`, `sdk-up`, `sdk-clippy`, `fmt`, `docs`. Commit `user-profiles UP9: delete and migration`.

## UP10 — Settings, export, import

**Files:** `clients/scaas-profile/src/{settings.rs,export.rs}` (the `settings` item's storage, export, `import_preview`, `import`),
`clients/scaas-profile/tests/`; the SDK's `src/user_profile/settings.rs` (`ProfileSettings` per chain-profile key, the §7.7 rule)
and `tests/user_profile.rs`.

`ProfileSettings` (per chain-profile key: named endpoints with `first` marks, the RPC policy, lowered caps; the default chain
profile; the idle lock; the clipboard opt-in; credential references): the item `settings` of part `sdk`. `set_settings(s,
passphrase)`: a weakening change (spec §7.7) needs the typed profile passphrase (`check_pass`), else refused. `export(confirm,
profile_passphrase, export_passphrase, kdf, ExportTarget::Path)`: the file of spec §10.1 (`O_CREAT | O_EXCL`, `0600`, no symlink),
`ProfileExportTooLarge` above 64 MiB; never an id, a lock, a keychain item, `keystore.prev`, a PqChat item, a credential reference or
a cache. `import_preview` (verify and open the whole file in memory, nothing written; `ImportReview` lists every setting by item
id); `import(review, choices, passphrase, name)` (a new UUIDv7, protected from the first write, the temporary directory sealed from
its first byte under its `build.lock`, committed under the root lock by one rename and the row, `sdk.state`'s operations marked
`imported`).

- [ ] Tests first: settings (R2-C-3: each weakening change without the passphrase refused; a lowered cap and a stronger policy
      pass); G9 (export without the profile passphrase refused; the payload holds none of the left-out items; every refusal row of
      UP1's `export.json` read by the SDK as `ProfileImportOpen` with nothing written; 1 MiB and 1 MiB + 1 round-trip; a crafted
      file's credential reference dropped even when every endpoint is confirmed; endpoints, `first`, idle lock and clipboard
      dropped without a confirm; `import_preview` writes nothing to disk; the temporary directory holds only sealed items;
      operations in flight not followed; above 64 MiB `ProfileExportTooLarge`; an existing file or a symlink at the export path
      refused; another instance's start during a preview leaves its temporary directory); the positive control: an unchanged file
      imports with a new id and the same seed fingerprints.
- [ ] Mutants (`up10`): the passphrase check of `set_settings` removed; parse before verify; settings imported whole; a filter that
      forgets credential references; start removing a temporary directory whose `build.lock` is held; a preview written to disk in
      plain form.
- [ ] Gates: `prof`, `sdk-up`, `sdk-clippy`, `fmt`, `docs`. Commit `user-profiles UP10: settings, export, import`.

## UP11 — Wave-1 closing gates

- [ ] On the final tree, once: `ck`, `ck-gen`, `ua-profile`, `ua-clippy`, `ua-vault`, `prof`, `sdk-up`, `sdk-reg`, `sdk-clippy`, `features`,
      `bind-gen`, `fmt` (rust js toml), `docs`, and every task's mutants `check`. Rows into the summary; commit it.

## UP12 — Docs

- [ ] `docs/clients/scaas-sdk.md` §12: a status line per rule built in wave 1 (BUILT where code and tests exist, with the test
      names; SPECIFIED where wave 2 remains); `docs/decisions.md` §41's entries' statuses; the spec's status line (wave 1 built at
      `<commit>`, UNAUDITED); `smartcontracts/vectors/README.md` row for `profile/`. `docs` gate. Commit `user-profiles UP12: docs`.
