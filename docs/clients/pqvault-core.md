# `pqvault-core`: the PqVault client core

`pqvault-core` is the Rust crate that holds PqVault's client logic: vault, epoch, item and batch records, the key schedule on
the SDK's key handles, the state read from the contract's views alone and its signature chain verified before anything is
trusted, unlocking, rekeys, removals and leaves, items, edits and their merge, batches sized by the chain's limits, recovery
from state, the replica check and the migration plan. It is an **app core above `scaas-sdk`**: every signature, verification,
KEM, KDF, Argon2id and AEAD runs in `ua-rs` behind the SDK's handles, and every chain read goes through the SDK's node lists.
The protocol it implements is normative elsewhere: the contract [pqvault.md](../contracts/pqvault.md) and the spec
[`2026-11-17-pqvault.md`](../superpowers/specs/2026-11-17-pqvault.md) (its §6 cryptography, §6.8 the item plaintext and the
secret table, §7 the crate, §8 the app-facing API); this page holds what the crate adds and the rules every PqVault client
follows. Status: **BUILT** in `clients/pqvault-core` (plan V10, V10e; the owner rulings of 2026-11-27 for the UI,
[CLI-PQV-16](../decisions.md#CLI-PQV-16) H1–H3 and [CLI-SDK-36](../decisions.md#CLI-SDK-36), on branch `pqvault-ui-rules`),
except where a section says otherwise. UNAUDITED: test data only ([CLI-PQV-08](#CLI-PQV-08)).

**Contents**

1. [Place and scope](#1-place-and-scope)
2. [The API surface](#2-the-api-surface)
3. [Items and the secret table](#3-items-and-the-secret-table)
4. [Sign after confirm](#4-sign-after-confirm)
5. [Stores](#5-stores)
6. [Vectors and tests](#6-vectors-and-tests)
7. [The client rules](#7-the-client-rules)

## 1. Place and scope

Status: **BUILT** (`tests/core.rs`: the dependency check, P1 before any call, no key byte in the public surface).

The crate depends on `scaas-sdk` (features `app-core`, `mlock`) and on no other SCaaS crate: no `scaas-ua`, no `scaas-rpc`
(`tests/core.rs` reads `cargo tree`). Its modules: `records` (the seven records, their ids, the wrap hash, the item AAD and
the typed data), `keys` (the key schedule on handles), `content` (canonical JSON, padding, the item bounds), `item` (the
redacting item layer, §3), `vault` (state, verification, unlock, every write, recovery). One trait, `Net`, is the seam to
the SDK: the reads that feed a decryption (`read_app`), the PqVault signing and verifying calls, the KEM wrap, the quote
before the signature (`quote_app_call`) and the signed record's call (`prepare_app_call`); `SdkNet` is the SDK's, a test
puts its own. It opens no connection and holds no key byte. [CLI-PQV-01](#CLI-PQV-01) is the rule.

## 2. The API surface

Status: **BUILT** (`src/lib.rs`, `src/vault.rs`, `src/item.rs`).

| Group | Calls |
|---|---|
| Scope | `PqVault::new(sdk)`, `PqVault::with_net(sdk, core, net)`, `p1(account)`, `ua(account)`, `PqVault::vault_key(seed, index)`, `generate_passphrase(seed)` |
| Reads | `chain_uid(at)`, `member_key(at, ua)`, `vaults_of(at, ua)`, `fetch(at, vault, me)`, `verify(state)`, `load(at, vault, me)`, `replica_agrees(home, replica)`, `recover(account, at)` |
| Unlock | `unlock(account, state, pass) -> Unlocked`, `lock(unlocked)`, `check_not_reused(pass, personal)`, `share_box(vaults, recipients)` |
| Items read | `open_latest(v) -> [ItemVersion]`, `history(v, item) -> [ItemVersion]`, `newest_readable(history)`; `ItemVersion.value: Result<Item>` |
| Writes (unsigned, §4) | `create_vault(account, info, members, at, mode, pass, payer) -> Prepared<VaultCreate>`; `rekey(v, members, admins, pass, link, payer)` and `rekey_by(v, signer, author, members, admins, pass, link, payer) -> (Prepared<VaultEpoch>, Exposure)`; `leave(v, payer) -> Prepared<VaultLeave>`; `remove(v, members, payer) -> (Prepared<VaultRemove>, [AffectedItem])`; `create_item(v, item, payer) -> Prepared<ItemRecord>`; `edit_item(v, base, item, payer) -> Prepared<EditRecord>` (a tombstone: `Item::deleted()`); `resolve(v, base, ours, item, payer) -> (Prepared<EditRecord>, Merge)`; `create_items(v, items, limits, payer) -> [Prepared<BatchRecord>]`; `accept(index, vault, accept, personal, payer) -> Prepared<ItemRecord>` |
| Confirm | `confirm(prepared) -> (Signed<R>, AppCall)`: the one signing call, then the call for `Wallet::submit_native_send` |
| A signed record | `prepare_signed(at, signed, wraps, payer) -> AppCall` (anyone may submit a signed record, a replica's copy included) |
| Plans | `migration_plan(from) -> MigrationPlan` |

Change of 2026-11-27 (CLI-SDK-36, CLI-PQV-16), for a front-end that used the earlier calls: every write took no payer and
returned `Signed<R>` (with the wraps beside it for a create or a rekey), and `prepare_create`, `prepare_rekey`,
`prepare_leave`, `prepare_remove`, `prepare_item`, `prepare_edit` and `prepare_batch` made its call; now every write takes
the payer, returns `Prepared<R>` (the wraps in it) and is signed and called by `confirm`; `prepare_signed` replaces the seven
for a record signed elsewhere. Items cross as `Item`, never as `serde_json::Value`: `create_item`, `edit_item`,
`create_items` and `resolve` take `Item`s, `ItemVersion.value` and `Merge` hold them.

## 3. Items and the secret table

Status: **BUILT** (`src/item.rs`; `tests/vectors.rs`), except the TOTP code (H4), `ItemSummary` and `reveal` / `copy` as
calls, **SPECIFIED** ([CLI-PQV-16](../decisions.md#CLI-PQV-16) H4 to H10).

An `Item` is `{ ty, fields, history }`: each field a `Field` of the kind one table gives it, `Plain(value)`,
`Secret(SecretBytes)` (a text), `Custom([...])` (the custom fields, each declaring itself secret) or `Opaque(SecretBytes)` (a
field this client does not know, its canonical JSON kept byte for byte, never shown); `history` holds the merge's losing
values, typed as their field is, so a secret's earlier value stays a secret. The table, the `card` and `identity` fields,
`hideBody` and the custom fields are pinned in [spec §6.8](../superpowers/specs/2026-11-17-pqvault.md#68-the-item-plaintext)
and in `item::TABLE`, the one place every front-end reads them from. A draft is built with `Item::new(type)` and
`set(name, Field)`; `Item::check` refuses a field of another kind than the table's (`Shape`), before anything is built. The
canonical JSON is written into a zeroizing buffer of 16,384 B that never reallocates and read from the decrypted plaintext's
secret buffer in place (a secret's text goes into its `SecretBytes` without a `String` between); `Debug` names fields and
kinds only. The stored bytes are unchanged: `smartcontracts/vectors/pqvault/items.json`'s plaintexts are read and written
back byte for byte.

## 4. Sign after confirm

Status: **BUILT** (`src/vault.rs` `Prepared`, `confirm`; the SDK's `AppCore::quote_app_call`; `tests/devices.rs`
`nothing_is_signed_before_the_confirm`).

Every write returns a `Prepared<R>`: the unsigned record, its wraps, and the SDK's quote of its call before the signature
(`AppQuote`: the call's review with the signature empty, and the payer's quote from the gas rows `(entry, "app", signer
kind)`, `None` when no row is measured). Nothing is signed until `confirm`; a `Prepared` dropped signed nothing and holds no
key (the record's ciphertexts, its typed data and the key references only). `confirm` makes the one signing call
(`prepare_pqvault_record`, `AppPrepared::sign`), then `prepare_app_call`, whose simulation follows the signature: a refusal
there (another device's newer version, `PqVaultVersion`) drops the signed record and sends nothing; the front-end then
offers `resolve`. The rule is [CLI-SDK-36](../decisions.md#CLI-SDK-36); the SDK's side is
[scaas-sdk.md](scaas-sdk.md) ("Sign after confirm").

## 5. Stores

Status: the crate holds **no store** (BUILT): a vault's state is read whole from the contract's views each time
([CLI-PQV-11](#CLI-PQV-11)), the epoch keys live as SDK handles in `Unlocked` until `lock`, and the highest version and epoch
seen this session sit in memory (the rollback check). **SPECIFIED**: offline reads from a cache of verified records and
ciphertexts inside the profile's sealed store, no offline writes ([CLI-PQV-16](../decisions.md#CLI-PQV-16) H9); the local
search index in memory or the device's encrypted store, dropped at the lock (spec §7 "Local index").

## 6. Vectors and tests

Status: **BUILT** locally, UNAUDITED. `tests/vectors.rs` (feature `vectors`) reproduces `smartcontracts/vectors/pqvault/`
(`records.json`, `keys.json`, `items.json`, `pass.json`) through the SDK's vectors build; `tests/core.rs`, `tests/devices.rs`,
`tests/exits.rs` and the unit tests run offline on seams; `tests/e2e.rs` runs the real client on a local `anvil`
(`runs/2026-11-22-pqvault-e2e.sh`, capped, foreground). Mutants: `runs/*-mutants.py` through `scripts/mutant_guard.py`, their
records beside them.

## 7. The client rules

Status: per rule (each states BUILT, SPECIFIED or PLANNED).

**PqVault** (`pqvault-core` BUILT, UNAUDITED, [CLI-PQV-01](#CLI-PQV-01); the contract is [pqvault.md](../contracts/pqvault.md), the design
the spec [`2026-11-17-pqvault.md`](../superpowers/specs/2026-11-17-pqvault.md)). The rules every PqVault client follows; the
first seven state owner rulings, CLI-PQV-04 and CLI-PQV-08 to CLI-PQV-12 controller calls (owner may override):

<a id="CLI-PQV-01"></a>**CLI-PQV-01** — **`pqvault-core`, a Rust crate of its own, builds, encrypts, opens and merges vault
records as an app core above `scaas-sdk`: it depends on the SDK, the SDK holds no PqVault logic beyond its two signing calls
`sign_pqvault_record` / `verify_pqvault_record` (all vault logic stays in `pqvault-core`; owner 2026-11-22,
[CLI-PQV-13](../decisions.md#CLI-PQV-13)), and every signature,
KEM, KDF and AEAD still runs in `ua-rs`, reached through the SDK ([CLI-UAL-01](ua-libraries.md#CLI-UAL-01)); scaas-app links it in its one
Rust library `app-core-rust` with the feature `pqvault` (which implies `scaas`; scaas-app's contract section 12)** (owner
2026-11-17, N2: the dependency reversed, which replaced V11's SDK module `pqvault` the same day). BUILT, UNAUDITED
(plan V10, V10e: `clients/pqvault-core`; its controller calls [CLI-PQV-14](../decisions.md#CLI-PQV-14)): the records, ids
and typed data of both modes, the key schedule on the SDK's handles, the state read from the views alone and the signature
chain of spec §6.9 verified before an unlock, unlock with the unopenable-epoch and history rules, rekey, leave, remove with
the affected list, items, edits, merge, batches sized by the chain's limits, recovery from the index vault and the scan,
the replica check, the migration plan; `tests/vectors.rs` reproduces `smartcontracts/vectors/pqvault/`, `tests/e2e.rs`
runs the real client on a local `anvil`, a KEM key rotation and an `msig` admin with a native member in both modes included
(owner 2026-11-22, [CLI-PQV-15](../decisions.md#CLI-PQV-15)); the generated passphrase is 6 BIP-39 words drawn in `ua-rs`,
the share box is found among the unlocked vaults; every write built for the review and signed only on the confirm
([CLI-SDK-36](../decisions.md#CLI-SDK-36)), items typed by one secret table ([CLI-PQV-16](../decisions.md#CLI-PQV-16) H1–H3).
Not built yet: the members' kind flags, the migration's run; reads spread
over the node list (a `scaas-rpc` / SDK follow-up) and the biometric `P_k` (CLI-PQV-07, scaas-app's) are not this crate's. The SDK's `vault` stays the seed vault; `pqvault-core`'s
calls are the spec's [§8](../superpowers/specs/2026-11-17-pqvault.md#8-the-app-facing-api-of-pqvault-core).

<a id="CLI-PQV-02"></a>**CLI-PQV-02** — **A personal vault uses the same path as a shared one: a random 32-byte epoch key
wrapped once to its own UA KEM key (ML-KEM-1024 + X25519); no seed-derived vault key exists; a personal vault is never
rekeyed to add a member: sharing from it is a new shared vault and a copy of the chosen live items** (owner 2026-11-17,
ruling "(a)", its sharing clause replaced by O1 (c) the same day). SPECIFIED. The bytes are [CLI-PQV-09](#CLI-PQV-09)'s.
Single notes are shared through a share box: one shared vault per recipient set, created on the first share and reused,
each later share one `createItems` copy (controller call 2026-11-21, within O1 (c)). SPECIFIED.

<a id="CLI-PQV-03"></a>**CLI-PQV-03** — **Metadata reduction: titles, usernames, URLs, folders, tags, item types, vault names
and settings only inside ciphertexts and `sealedInfo`; padding buckets always; batch writes for imports and migrations;
relayed submission; a personal vault held by a per-vault UA derived from the seed** (owner 2026-11-17, V8; PqChat's D10).
SPECIFIED. The derivation and the node-side linkage are [CLI-PQV-09](#CLI-PQV-09) and [CLI-PQV-11](#CLI-PQV-11).

<a id="CLI-PQV-04"></a>**CLI-PQV-04** — **Client hardening: secrets hidden until an explicit reveal and hidden again after
30 s or on leaving the foreground, no screenshots of a revealed secret where the platform allows, copy only on an explicit
action with the clipboard marked sensitive and cleared after 30 s, autofill on the exact host and scheme by default and from
accepted vaults only, auto-lock after 5 min idle and at once on screen lock (keys and plaintexts zeroized), never a secret in
a log, crash report, notification, URL or error** (controller call, owner may override). SPECIFIED.

<a id="CLI-PQV-05"></a>**CLI-PQV-05** — **No decryption oracle, honest limits, files off chain: a client sends nothing that
depends on whether a version or a passphrase check opened; it reads through an RPC list keeping the highest version seen per
item; it tells its user that a removed member keeps what it read (and lists the secrets to change) and that a deleted
item's bytes stay; files go off chain with their key and hashes inside an item, fetched only on the user's action** (owner
2026-11-17, V5, V7; [ARCH-POS-13](../decisions.md#ARCH-POS-13), [ARCH-POS-15](../decisions.md#ARCH-POS-15)). SPECIFIED.

<a id="CLI-PQV-06"></a>**CLI-PQV-06** — **Only a PQ-rooted 24-word (256-bit) seed owns a vault: `pqvault-core` refuses (from the
seed set's `class` and warnings the SDK reports from its authenticated index), with `SeedNotPqRooted` and before any other work, a classical-rooted seed set (the EOA-signature root, the
private-key root and their BIP-85 children), a phrase below 24 words and an imported raw key; the vault UA, a per-vault UA
included, derives from such a seed** (owner 2026-11-17, P1). SPECIFIED. The check binds what a client does for its own user;
the chain cannot show another member's seed class, so a shared vault is only as quantum-safe as its weakest member's seed.

<a id="CLI-PQV-07"></a>**CLI-PQV-07** — **The vault passphrase is an option, on by default: the epoch key that opens items
combines the KEM-unwrapped `K_e` with `Argon2id(passphrase, salt)`, the salt random per vault and stored in the vault's
record with its parameter set's id; neither the seed nor the passphrase alone opens anything; a change re-encrypts no item;
a wrong passphrase is detected by an AEAD check before any item is opened; the passphrase is never stored or sent;
forgetting it loses the vault; the choice is a flag in state with no value and no hint; versions written before a change
stay under the old passphrase** (owner 2026-11-17, P2, changing V9). SPECIFIED. The mechanics are
[CLI-PQV-10](#CLI-PQV-10)'s. **Biometric unlock per device, opt-in** (owner 2026-11-21, O7 (b)): a client may keep
`Argon2id`'s output `P_k`, never the passphrase, wrapped by a device-keystore key behind a biometric access policy; it is
off by default, turned on per device, and on that device the device key and the seed then open the vault (the client says
so when it is turned on); `passKdf = 1` is Argon2id 64 MiB / 3 / 4 (owner 2026-11-21, O8). SPECIFIED. **The passphrase's
bytes** (controller call 2026-11-21, the Fable code review F4): RFC 8265's OpaqueString before Argon2id: non-ASCII spaces to
U+0020, Unicode NFC, UTF-8; empty or a control character refused (`PassphraseInvalid`). BUILT in clientkeys (`passphraseBytes`)
and reproduced by `ua-rs` (`tests/pqvault_pass.rs`), pinned by `smartcontracts/vectors/pqvault/pass.json` `normalization`.

<a id="CLI-PQV-08"></a>**CLI-PQV-08** — **A migration tool moves the live items to vaults under a new seed and says that the
old ciphertexts stay on chain and every secret must be changed at its service; until the audit round that covers the
contract, `pqvault-core` and the `ua-rs` paths it uses, with its reviewers named, the app labels PqVault UNAUDITED and test
data only** (controller call, owner may override). SPECIFIED.

<a id="CLI-PQV-09"></a>**CLI-PQV-09** — **The key schedule's bytes: wraps under the label `scaas/pqvault/v1/wrap`; `K_v =
HKDF(K_e ‖ P_k)` with the vault, epoch and parameter id in its info; per version a fresh 16-byte salt and one HKDF giving key
and nonce, AES-256-GCM-SIV over the padded canonical JSON with the AAD (vault, epoch, item, version, author, home);
`sealedInfo` under `K_v` with an optional `prev = {epochId, keyWrap}`, the earlier key sealed under a `KeyWrap` key derived
from `K_v` with the key-wrap constant and its usage in the AAD, and a `file` item's key sealed under a derived `kFile`, never
under `K_v`; every key handle has one usage, `Derive`, `Data` or `KeyWrap`; a personal vault held by `ua_secret(seed, FN-DSA-512 by
default, PQV_ACCOUNT, i)`, index 0 the index vault listing the user's vaults** (controller call, owner may override).
SPECIFIED. Exact bytes: [spec §6](../superpowers/specs/2026-11-17-pqvault.md#6-cryptography); every client reproduces
`smartcontracts/vectors/pqvault/`. **`sealedInfo`'s padding** (owner 2026-11-21, the Fable
code review F12): to 1,024 B, the smallest bucket, so its size does not show `prev` or a longer name; past 1,024 B the next power
of two, at most 16,384 B; 1,052 B sealed, about 1.18 M state gas more than a 256-B bucket per vault or epoch record. The chain
does not enforce it. BUILT in clientkeys (`padInfo`), reproduced by `ua-rs`.

<a id="CLI-PQV-10"></a>**CLI-PQV-10** — **The passphrase's mechanics: a change, or turning it on or off, is an admin's rekey
of the same members with a fresh salt; the history is as strong as the weakest epoch that links to it, so before a rekey
that weakens it (passphrase off or weaker, a member added) the client shows what it would expose and offers the rekey
without `prev`; a downgrade is accepted only from a verified admin record; Argon2id without associated data at a parameter
set pinned after a measured run; a generated passphrase offered (6 BIP-39 words, owner 2026-11-22), a user-chosen one at least 16 characters with a
strength meter, nothing more enforced; a shared vault's passphrase never equal to the user's personal one** (controller
call, owner may override). SPECIFIED. The generated passphrase is 6 BIP-39 English words (about 66 bits) drawn in `ua-rs`
(owner 2026-11-22, [CLI-PQV-15](../decisions.md#CLI-PQV-15)); BUILT. Design: [spec §6.5](../superpowers/specs/2026-11-17-pqvault.md#65-the-vault-passphrase-p2).

<a id="CLI-PQV-12"></a>**CLI-PQV-12** — **`pqvault-core` holds key handles only and signs only under PqVault's app purpose:
the KEM-unwrapped epoch key, the passphrase output, the effective key and every key derived from them stay in `ua-rs`
behind handles of one usage each (`Derive`, `Data`, `KeyWrap`), and wrap, unwrap, HKDF, Argon2id, AEAD and key sealing
run there on those handles; the only bytes that come out are plaintexts it asks to decrypt for the user, which hold no
key (earlier and file keys are sealed); it signs its records only through the SDK's PqVault signing call
(`sign_pqvault_record`, over `ua-rs`'s dedicated path `wallet::pqvault`, which accepts the domain "SCaaS PqVault" and
PqVault's structs only), while the SDK's generic app signing call refuses every SCaaS purpose (PqVault's `P_V` included) and
every SCaaS contract's or the registry's domain by name (PqVault's included); if either cannot be met, the task stops and the
owner decides** (coordinator conditions, controller calls, owner may override; the dedicated path is the owner's ruling of
2026-11-22, [CLI-PQV-13](../decisions.md#CLI-PQV-13), BUILT, UNAUDITED). App scoping avoids
collisions among the cores an app links; it does not isolate: an app holding the user's unlocked seed set acts for that UA
in every app namespace, PqVault's included, so only reviewed app cores are linked. SPECIFIED. Design: the spec's
[§7](../superpowers/specs/2026-11-17-pqvault.md#7-pqvault-core).

<a id="CLI-PQV-11"></a>**CLI-PQV-11** — **Trust what is verified and accepted: a vault the user did not create stays pending
until the user accepts it after seeing its creator and members, and the accepted set is kept as `vaultRef` items in the
user's index vault; before encrypting under an epoch a client verifies the signature chain from the vault record through
every epoch to its own wrap; members and admins with a classical UA kind are flagged; reads for different vault UAs are
spread over the RPC list and over time so one node does not link them** (controller call, owner may override). SPECIFIED.
Details: [spec §6.9](../superpowers/specs/2026-11-17-pqvault.md#69-what-a-client-verifies-before-it-trusts-state-vc15) and §9.
The chain check holds [CTR-UA-74](../contracts/accounts.md#msig-reader-rule)'s step 6 along the vault: oldest first (the create
record, each epoch, then the removals kept under it, judged order-free against the versions after it), no `msig` names a
structure version below the highest one an earlier record named, a signing `msig` member's tag included (the SDK's
`verify_pqvault_record_versions` gives the versions); else `ChainUnverified` (C-3, R-2). A replica's epoch agrees with the
home's when its signature equals the home's with the `msig` version tags stripped (`epoch_agrees`, A-1: a copy carries the tag of
the replica registry's current version, every other byte the home's). Controller calls 2026-11-26, BUILT in `pqvault-core`
`vault.rs`, `tests/exits.rs`, UNAUDITED.

**The PqVault UI** (owner 2026-11-27; [CLI-PQV-16](../decisions.md#CLI-PQV-16)): the redacting item
layer lives in `pqvault-core` (fields typed `Plain`, `Secret(SecretBytes)`, `Custom` or `Opaque`, the canonical JSON in
zeroizing buffers; BUILT, UNAUDITED: `item.rs`), with the `card` and `identity` fields and the secret table per type pinned
there and in [spec §6.8](../superpowers/specs/2026-11-17-pqvault.md#68-the-item-plaintext) (BUILT); a note's body plain by default
with a per-item "hide body" (`hideBody`, BUILT); custom fields declaring themselves secret (BUILT); a secret's earlier values in
`history` secret too (BUILT). SPECIFIED, not built: the rest of this paragraph; a TOTP code reveal-gated, copyable with the 30-s clear except in the TUI; breach checks only on the
user's action over the user's own latest versions, padded k-anonymity; "decide later" writes nothing; autofill after v1 (Android
in-process first, then the extension on the user's action, iOS later); no passkeys in vaults; offline reads from the profile's
sealed cache, no offline writes; the web build and the extension after the core runs on wasm32 and after the native front-ends.
Every record is signed only after the user's confirm ([CLI-SDK-36](../decisions.md#CLI-SDK-36); BUILT in `pqvault-core`,
UNAUDITED: every write a `Prepared` with the SDK's quote before the signature, `PqVault::confirm` its one signing call).

The rules [CLI-PQV-13](../decisions.md#CLI-PQV-13) to [CLI-PQV-16](../decisions.md#CLI-PQV-16) are owner rulings and
controller calls recorded in `decisions.md`; the paragraphs above link them where they apply.
