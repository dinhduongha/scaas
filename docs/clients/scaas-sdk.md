# `scaas-sdk`: the one API apps call

`scaas-sdk` is the one Rust crate through which an app (scaas-app's `scaas` build, `scaas-tui`, the CLI `scaas`, an integrator's
service) reaches every SCaaS feature: seeds and keys, Universal Accounts, tokens and payments, Zether and PQZ, the DEX, governance,
and the generic surface that app cores above it use (`pqchat-core`, `pqvault-core`, a third party's). Every signature comes from `ua-rs` ([CLI-UAL-01](ua-libraries.md#CLI-UAL-01)), every chain read and send goes through
`scaas-rpc` ([CLI-RPC-01](scaas-rpc.md#CLI-RPC-01)), and the bindings are generated from its one API. Status: **BUILT** in
`clients/scaas-sdk` and `clients/scaas-cli` (plan T0–T24, T38, T40, T41.evm, T41.soroban, T41.arweave; each rule below states its
own status and what stays PLANNED): `vault`, `account`, `wallet`, `confidential`, `dex`, `admin`, `app_core`, the EVM and Soroban
operations with self-relay, the non-EVM families' reads, Arweave files, the CLI and the Dart binding (`flutter_rust_bridge`, plan
T20). PLANNED: the other bindings (plan T20b–T20h), the other families' operations, self-relay and native sends (after the freeze,
owner 2026-11-22), the native DOT and BTC sends (spec `docs/superpowers/specs/2026-11-17-scaas-sdk.md`, reviewed
by Fable on 2026-11-17 with every finding applied; plan `docs/superpowers/plans/2026-11-17-scaas-sdk.md`). UNAUDITED.

**Contents**

1. [Scope](#1-scope)
2. [Secrets and references](#2-secrets-and-references)
3. [The vault](#3-the-vault)
4. [Accounts](#4-accounts)
5. [Operations](#5-operations)
6. [Confidential tokens](#6-confidential-tokens)
7. [App cores above the SDK](#7-app-cores-above-the-sdk)
8. [Runtime, events, errors](#8-runtime-events-errors)
9. [Bindings](#9-bindings)
10. [Chain profiles and native chains](#10-chain-profiles-and-native-chains)
11. [The CLI](#11-the-cli)
12. [User profiles](#12-user-profiles)

## 1. Scope

<a id="CLI-SDK-01"></a>**CLI-SDK-01** — **One crate is the only API apps call; it signs through `ua-rs`, talks through `scaas-rpc`,
and holds no cryptography of its own** (owner 2026-11-11, 2026-11-17; BUILT: plan T1, T21, T41.evm step 0, T42,
`tests/feature_tree.rs`, `evm_feature.rs`). Modules: `vault` (several seeds), `account` (UA,
key references, `msig`, passkey and `SmartKeyAccount`, recovery), `wallet` (balances, tokens, history, the token and mandate-wallet
`mtx*` entries, native keys), `confidential` (Zether and PQZ provers, verdicts, disclosure), `dex`, `admin`, and `app_core`, the
generic surface for app cores above it ([CLI-SDK-19](#CLI-SDK-19)); each module and each guarded entry a compile-time feature,
so a build without it has none of its calls. Key
derivation, AEAD, KDFs, MACs, signatures and every hash a byte format fixes stay in `ua-rs`; HTTP, RPC, retries and node calls stay in
`scaas-rpc`. `scaas-ua` is taken without its default features, so one build carries one PQZ parameter set. No module is
named after an app: `pqchat-core` and `pqvault-core` depend on the SDK, not the reverse (owner 2026-11-17). The research's and earlier rulings' name "scaas-wallet" means
this crate (the library) and its `wallet` module; the end-user app is scaas-app.

## 2. Secrets and references

<a id="CLI-SDK-02"></a>**CLI-SDK-02** — **Secrets never leave the SDK; apps hold references** (owner 2026-11-11, 2026-11-17;
BUILT: plan T2a, T4, T9, T20, `tests/vault.rs`, `tests/config.rs` `credentials_never_in_debug`, the Dart `binding_test.dart`;
UNAUDITED). An app names keys by plain records with string ids (a seed id and a kind, account and index; a network and index; a
passkey's credential and key data; a watch-only id), never by key objects; each resolves inside the SDK to a `ua-rs` handle of an
unlocked seed (`WalletLocked` otherwise, `KeyRevoked` after a lock). A hidden set has its own session id, so no reference names both
sets. A secret crosses the API only as an explicit input (a vault, BIP-39 or derivation passphrase, an imported mnemonic or private
key, root (c)'s two signatures, a PRF output or platform secret written by the app's `Authenticator`) or as the one reveal of a new
seed's words (`SeedBackup`: shown once, three-word check, [CLI-SGN-11](signers-clientkeys.md#CLI-SGN-11),
[CLI-SGN-20](signers-clientkeys.md#CLI-SGN-20)), and always as `SecretBytes`: one implementation in `ua-rs`, Rust-owned, zeroed on
drop, neither `Clone` nor `Debug`, which a binding reaches by an id and two copy calls under a lock with an explicit dispose, never
through its generator's codec and never by a pointer handed to a garbage-collected language ([CLI-UAL-05](ua-libraries.md#CLI-UAL-05)'s
rule). Sealed exits only otherwise: the sealed backup and the device link ([CLI-UAL-12](ua-libraries.md#CLI-UAL-12)). No call exports
a raw key. No error, event, log line or `Debug` output carries a secret, an input, a URL, a request body, a ciphertext, a formatted
`ua-rs` vault, or an address of a hidden set ([CLI-UAL-04](ua-libraries.md#CLI-UAL-04), [CLI-RPC-11](scaas-rpc.md#CLI-RPC-11)).

## 3. The vault

<a id="CLI-SDK-03"></a>**CLI-SDK-03** — **The keystore holds several seeds, each as clientkeys / `ua-rs` vault v2 objects byte for
byte, in one authenticated `scaas.keystore` container** (owner 2026-11-11, 2026-11-17; container and integrity controller calls;
BUILT: plan T2a, T2b, T2c, T4, `tests/vault.rs`, `tests/keystore_vectors.rs`, `src/vault/tests.rs`; UNAUDITED; vault v2 and
container v 2 BUILT, owner 2026-11-19, T13b ruling 3: every vault's AAD binds its seed's id, the index MAC
covers the vault texts, v 1 refused by name, no migration; the entry checked again on every read that trusts its rows and before
every write that signs it again, review T26 A-1, A-2, `an_entry_changed_after_unlock_is_never_trusted_nor_signed_again`: its rows
read `verified` only when the entry as read verifies under the open wallet, a key row signs only from such an entry
(`KeystoreMismatch`), and a write of an entry that does not verify is `KeystoreMismatch` and locks the seed; PLANNED: the
`AccountUnverified` refusal, which no call returns yet, while the rows' unverified mark is built). The container is one item `{format: "scaas.keystore", v: 2, rev, seeds:
[...]}`. Each seed entry has a UUID `id`, the
user's `label` (1 to 64 scalar values, NFC, unique), `words`, the main set's BIP-32 master `fingerprint`, `origin`, `class` (`full` or
`classical-rooted`), `warnings` (`short_seed`, `imported_key`), `backup` (`pending` or `verified`), `vaults` (label → the exact vault
v2 JSON text, its `id` the seed's of [CLI-SGN-02](signers-clientkeys.md#CLI-SGN-02): `seed`, and `manifest`, `native-import:…`, `pqz-held:…` as `ua-rs`
seals them; [CLI-UAL-18](ua-libraries.md#CLI-UAL-18)), the `accounts` the user named, and `indexMac`. It records no parent seed, no
child index, no origin address and no hidden set. Bounds: 16 MiB, depth 5, 64 seeds, 64 vaults and 1,024 accounts per seed; an unknown
field or a broken rule is `VaultFormat`, another `format` or `v` `VaultVersion`, and a reader that refuses a container never writes
one. **Integrity:** `indexMac` is an HMAC-SHA256 over the entry's public fields under a key derived from the seed's entropy, computed
and checked in `ua-rs` at every unlock (`KeystoreMismatch`, the seed then stays locked for signing) and rewritten on every change of
those fields (so they change only while the seed is unlocked); it binds `id`, `label` and `words` to the vault the entropy came from.
Rows of a locked seed are **unverified**: shown with that mark, never used as a receive address or a destination
(`AccountUnverified`). **Writers:** every read-modify-write runs under the store's lock and replaces the item only at the expected
`rev` (`StoreConflict` after three tries); the replaced container is kept as `keystore.prev`; where a keychain exists a small anchor
`{rev, sha256}` detects an older container put back (`KeystoreRollback`, shown, not fatal; while it holds every keystore write is `KeystoreRollback` and writes nothing, until the user accepts the copy with `Vault::accept_rollback`, which rewrites the anchor over it: review T26 A-6, BUILT, UNAUDITED). The container is a file (or IndexedDB)
through the app's `SecureStore`, whose small keychain items hold only the anchor and the platform unlock secret; it receives vault
ciphertext and public fields only, and a failed write keeps the old item (`VaultIo`). clientkeys writes the container's vectors first
(`smartcontracts/vectors/keystore/`); scaas-app's default build, which has no `ua-rs`, reads and writes the same container.

<a id="CLI-SDK-04"></a>**CLI-SDK-04** — **Seeds are made with 24 words; shorter imports carry a warning; passphrases are the
user's** (owner 2026-11-11; the child index and hidden-set rules controller calls; BUILT: plan T4, T5, T23, `tests/vault.rs`,
`children.rs`, `confidential.rs` `short_seed_zether_key_is_the_provers`; UNAUDITED). Every seed the SDK makes is 24 words
from 32 bytes of the OS generator inside `ua-rs`, written with `backup: pending` until the three-word check passes. BIP-85 children
(`m/83696968'/39'/0'/24'/i'`, 24 words only) come from the parent's main set at its high-water mark `bip85Next`, kept in the parent's
sealed manifest and never lowered, so a removed child's words never return. An imported phrase of 12 to 24 valid English words is
accepted (NFKD, lower case, single spaces, checksum checked; otherwise `MnemonicInvalid`); 12 to 21 words carries `short_seed`, shown
wherever the seed is listed, with the advice to move funds to a 24-word seed, and every child inherits it. No passphrase is ever
generated: the vault passphrase follows vault v1's rule for a new envelope ([CLI-SGN-21](signers-clientkeys.md#CLI-SGN-21);
`VaultPassphraseWeak`), and the BIP-39 passphrase is never stored and reaches `ua-rs` as entered. A non-empty BIP-39 passphrase opens a
session-only hidden set: nothing about it is written, emitted or logged; its operations still in flight are listed when it is locked.
Removing a seed whose backup is `pending` needs a second confirmation. A seed import may check one word at a time against the BIP-39 list inside `ua-rs` (`word_in_list`, the word as `SecretBytes`); no list leaves the SDK (owner 2026-11-17).

<a id="CLI-SDK-05"></a>**CLI-SDK-05** — **A seed set derived from a classical key is marked classical-rooted and may carry every
kind** (owner 2026-11-11; BUILT in plan T6). Root (c), an external EVM wallet's EIP-712 signature over typed data `ua-rs` builds: signed twice
and required byte-equal, 65 bytes (a 64-byte compact form converted explicitly), `r` and `s` in range, recovering to the named account,
low-s, `r ‖ s` only, with a user-chosen derivation passphrase of at least 10 code points after NFKC, mandatory; no RPC call names the
origin. Root (d), a secp256k1 EVM private key: `KDF(privkey, passphrase, label, index)`, the passphrase empty or at least 10 code
points, `index` the seed-set number. Both are built in `ua-rs`; a failed check is `OriginSignature`, a short passphrase
`DerivationPassphraseShort`. The new seed is 24 words shown once, `class: classical-rooted` (authenticated by the index MAC and
inherited by its children); it may hold PQ, PQZ and KEM keys (the owner accepted the risk that they are only as strong as the
passphrase against a quantum attacker), and the UI says so when such a key is made. The mark is advisory across devices: the same
words imported elsewhere carry none. The exact constructions follow the owner's answers of 2026-11-17 (spec §25 Q-K4: Argon2id `0x13`,
`m = 128 MiB`, `t = 3`, `p = 4`; Q-K5; Q-K18), with the labels `scaas.sdk.root.eoa-sig.v1` / `scaas.sdk.root.raw-key.v1`, root (d)'s
empty-passphrase HKDF salt SHA-256 of its label and the numbers as 4-byte big-endian (plan T6, pinned by
`smartcontracts/vectors/keys/roots.json`); both calls are in the feature `classical-roots` (bit 24, off by default; BUILT, UNAUDITED).

<a id="CLI-SDK-06"></a>**CLI-SDK-06** — **Seeds unlock and lock one by one; changes are re-sealed under the same data key;
biometrics only gate** (BUILT: plan T4, T7, `tests/vault.rs`, `passkey.rs`; UNAUDITED). A seed unlocks with its vault passphrase, its passkey's PRF output or a platform secret (the
HMAC of a Keychain or Android Keystore key under a biometric access policy), the last two through vault v1's `prf` envelope. At unlock
no public key of the unlock credential exists, so user verification is enforced by the authenticator (separate secrets with and
without it) and by the AEAD (a wrong output is `VaultOpen`); an answer without an output, or with the 32 zero bytes the SDK lent
(an output the app never wrote: a forgotten write, a copy call's refused write whose status was dropped; review T26 C-1,
`an_output_never_written_is_refused`), is `AuthenticatorRefused`, nothing is sealed under it, and the passphrase remains. Signing keys' assertions are checked in full by `ua-rs` ([CLI-UAL-16](ua-libraries.md#CLI-UAL-16)); the app's `Authenticator`
and `SecureStore` are never trusted for policy. The passkey RP ID is the deployment's, never a SCaaS constant
([CLI-APP-14](app.md#CLI-APP-14)): `SdkConfig.rp_id`, which `create_passkey_key(seed, name)` and every passkey signing read, never a
parameter (owner 2026-11-19, T4; none configured: `AuthenticatorRefused`). Every change of a sealed record after unlock (the manifest, a backup generation) is re-sealed by
`ua-rs` under the vault's same data key, both envelopes kept, so a passkey session persists its changes; a new vault (an imported
key) takes the vault passphrase and, with a passkey set, its PRF output. A biometric is a platform gate; nothing is derived from it. A
passphrase change keeps the data key and removing the passkey unlock revokes nothing from an earlier copy of the container: the UI
says to move the funds if the old passphrase may have leaked. A passkey or platform unlock keeps the PRF key-encryption key, derived once, in `ua-rs`'s locked memory until lock (zeroed at lock, drop and `disable_prf_unlock`; never written, never across the FFI) and opens the seed's other vaults with it on first use, the unlock not asked again (owner 2026-11-18): the kept key opens every vault of the seed, so a memory read in the session exposes as much as opening them all, with fewer plaintext secrets resident. The exception (owner 2026-11-18): a passphrase unlock opens every vault at unlock and never keeps the passphrase, since
vault v1 derives a key per vault salt (no single key to keep) and keeping the passphrase would be worse. Scrypt, Argon2id and proofs run one at a time by default. `lock` calls
`ua-rs` `lock()`, which revokes every handle of that seed for good ([CLI-UAL-09](ua-libraries.md#CLI-UAL-09)), refusing new calls at
once and waiting at most for the calls in flight. Export between devices is the sealed backup or the device link only; the container
is not an export and the words are never shown again.

## 4. Accounts

<a id="CLI-SDK-07"></a>**CLI-SDK-07** — **Every account names its seed; keys are derived as clientkeys derives them; passkeys sit
beside seeds** (owner 2026-11-11; the index rule a controller call; BUILT: plan T9, T13, T13b, T19, `tests/account.rs`,
`account_ops.rs`, the parts named PLANNED below excepted; UNAUDITED). A UA key is `(seed, kind, account, index)`, a native
key `(seed, network, index)` (plus Bitcoin's change chain and Polkadot's path and SS58 prefix, BUILT in plan T19), derived byte for
byte as clientkeys `seed.js` and the vectors fix ([signers-clientkeys §9](signers-clientkeys.md#9-derivation-and-role-keys)). A passkey
(`webauthn-p256`) or a secure-element P-256 key is not derived: it is held by the platform and signs through the app's
`Authenticator`, the SDK building every message and verifying every answer ([CLI-UAL-07](ua-libraries.md#CLI-UAL-07)). An imported
classical key is a leaf of a seed, tagged with its network, never exported. Every attribute a wallet registers (signing kinds, PQZ
key, KEM key, Zether key) uses that wallet's own account index, so no two wallets share one. An EVM account whose code is an EIP-7702
designator carries a delegation mark and a warning; the SDK builds no type-4 transaction, so it cannot offer to clear the delegation
([CLI-SGN-40](signers-clientkeys.md#CLI-SGN-40) rule 3's offer: a recorded exception). A derived UA has no recovery
([CTR-ACC-09](../contracts/accounts.md#CTR-ACC-09)); guardian recovery is `SmartKeyAccount`'s ([CTR-ACC-03](../contracts/accounts.md#CTR-ACC-03)). Registration of a seed's UA key is BUILT (plan T13, `clients/scaas-sdk/src/account/register.rs`, `tests/account_ops.rs`, the `sdk-e2e` PQ registration): the arguments and the PoP by `ua-rs` (`registration_args`, `pop` v2), the calldata by `ua-rs` `registry_call` (the node's registry rows, both ways), each registry write an opaque value quoted and self-relayed by the user's payer, landed by its record (`isRegistered`, `pqzPopOf(…)` non-empty: the proof stored, proven or not (owner 2026-11-19, S2), `kemKeyAt`), a registration carrying its PQZ key's proof in one transaction or two (owner 2026-11-20; BUILT, `account::register::tests` `pq_registration_*`): quoted in one transaction first, in two steps (without `pqzPop`, then `storePqzPop`) when its whole gas is above half the chain's block gas limit or its regular gas above `tx_gas_cap`, each step quoted on its own and held to the same, else `GasAboveTxCap` / `GasAboveBlockShare`, nothing sent; `RegistryWrite::registration_gas` states the transactions, each step's gas and the total; the split keeps its `pqzPop` in `sdk.state` until `storePqzPop` lands, and a later prepare gives the second part only with the proof whose hash the registration committed, else `RegistrationPopInvalid` (merged-tree review M1); each registry write's gas from the gas table's rows where it has them (controller call, owner auto-run 2026-11-19; spec §13.3 "Registry writes": the regular bound the rows', the gas limit max(the estimate, the rows'); a form without a row the estimate, whole), the KEM commit's fill and repair, an ML-DSA key's expanded-key cache first where the registry caches it (owner 2026-11-19, T1: `cacheExpandedKey(kind, pk, 0)` simulated tells the cache path; each part `expandedKeyOf(ua)` shows missing its own write, landed by its pointer; `tests/account_ops.rs` `mldsa_cache_then_register`, the `sdk-e2e` `e2e_register_mldsa_cached_on_anvil`), the PQZ key attribute (feature `pqz`: the wallet's PQZ key of the same account and index, its `R_REG` proof by `ua-rs` `proveRegister` under the build set's PQZL `proofSystemId`, the PoP over both; without `pqz` `FeatureMissing`); `SmartKeyAccount` and guardian recovery are BUILT (plan T13 part 2; `clients/scaas-sdk/src/account/smart.rs`, `tests/wallet_ops.rs` `smart_execute_decoded_only`, the `sdk-e2e` `smart_account_add_key_self_relay` and `guardian_recovery_via_execute`): the counterfactual address by `ua-rs` (`smart_account_address`), one prepare per entry (`AddKey`, `RemoveKey`, `RotateKey`, `SetGuardian`, `CancelRecovery`, `CancelNonce`, `Execute`), `from` the account, signed as `AccountSig{keyIndex, …}` with the signing key's index given by the caller or read from the account (`nextKeyIndex()`, `keyAt(i)`), a signer the account does not hold `SignerNotAccountKey` (owner 2026-11-19, S3, P2); `Execute` with a decoded call only (`transfer`, `initiateRecovery`), signed under `ua-rs` `Expect::Execute`; the guardian's `initiateRecovery` is its own account's `Execute` (`prepare_initiate_recovery`); `completeRecovery` (anyone, after two days; `prepare_complete_recovery`) and the deploy (`factory.deploy`; `prepare_smart_deploy`) are native sends of the caller's EVM key (spec §8.5), quoted for review and sent by `submit_native_send` (the `sdk-e2e` tests above deploy and recover through them). Passkey and secure-element keys are BUILT (owner 2026-11-19, S1, P1; `clients/scaas-sdk/src/op/external.rs`, `src/op/tests.rs` `passkey_signs_through_the_authenticator`, `se_key_message_mode`): `create_passkey_key` and `create_se_key` store a key row (`AccountRow::Key`) beside the seed and return `KeyRef::Key{seed, id}`; an operation it signs first runs `ua-rs` `sign_scaas` through an `ExternalKey` that only refuses (the policy check passes before the user is asked; a refusal asks no device, owner 2026-11-19, T3: `src/op/tests.rs` `policy_refusal_asks_no_device`), then the SDK computes the passkey's challenge (`webauthn_challenge`) or the secure element's `ua_msg` (`ua_message`, MESSAGE mode) from `scaas_purpose(td)` and the digest, asks the `Authenticator`, and signs through an `ExternalKey` whose answer `ua-rs` verifies (`ExternalSignature` otherwise); a passkey's assertion is built and verified by `webauthn_assertion` first (`AuthenticatorRefused` for another key or UV clear). Such a row registers through `prepare_register` (owner 2026-11-19, T2): a passkey as `registerWebAuthn`, a secure element as `register` (`p256`), the PoP answered by the `Authenticator` and verified by `ua-rs` (`src/op/tests.rs` `key_rows_register`, the `sdk-e2e` `e2e_register_passkey_row_on_anvil`); it holds no KEM or PQZ key and never pays (a payer is a native key, spec §13.3). `msig` is BUILT (plan T13 part 4; `clients/scaas-sdk/src/account/msig.rs`, its tests `msig_minimal_sets` (`ua/nested.json`), `update_msig_current` (`ua/portable.json` `msigUpdates`, `msigUpdated`) and `msig_writes_landed_by_record`, the `sdk-e2e` `e2e_msig_register_accept_transfer_update_on_anvil`): `msig_structure` (members sorted by id, threshold and weights checked) and `MsigStructureArgs::ua`; `msig_state` reads the first structure (`registrationOf`), the current one (`msigOf`), `msigStateOf` and each accepted slot's `memberSigHashOf`, and shows listed, enabled and accepted apart and whether the accepted weight reaches the threshold ([CTR-UA-37](../contracts/accounts.md#CTR-UA-37)); `prepare_msig_register` (`registerMsig`, the `pop` by the named slots or empty, landed by `isRegistered`), `prepare_accept_membership` (landed by the slot's bit in `msigStateOf(ua).accepted`; nothing when set) and `prepare_update_msig` (`ua-rs` `plan_msig_update`, signed by slots of the stored structure, landed when `msigStateOf(ua).version` reaches the update's, [CTR-UA-44](../contracts/accounts.md#CTR-UA-44)) are `RegistryWrite`s; an operation signs as an `msig` through `KeyRef::Msig{ua, slots}`: the entry's check first, then every record read ahead (the `msig`'s and its `msig` members' first and current structures and bits), then `ua-rs` `msig_sig_current` (a set not minimal at either level `UAPoP`, a disabled slot refused); a slot or inner leaf not enabled and accepted on the registry is refused before anything is signed (`MsigSlotInactive`). The owner's M1–M5 of 2026-11-19 are BUILT (`ua-rs` `msig_slot_sig_current`, `msig_combine`, `registration_typed_data`; SDK `Op::member_sign`, `MsigSlot::Signed`, `msig_members_apart`): one slot signed on its own device and combined on the submitting one, a native member's `pop` slot at registration over the registration's typed data, an update landed only with its own structure, `holds_pqz_key` read, and a passkey or secure-element row as a slot through the external flow. A slot signed on another device names the operation it signed (`ua`, `purpose`, `digest`), and the submitting device combines
it only over its own preparation (`PreparedStale` otherwise; review 2026-11-20, F1). Not built: a native member on a gen-2
registry, collecting a `registerMsig` PoP slot from another device, and the local check of a slot's signatures (the registry
checks them; PLANNED). PLANNED (review 2026-11-20, F26): SDK calls for the registry entries `setPqzKey` (a new PQZ key version),
`setPqzScopedKey`, `storePqzScopedPop`, `registerMuSig2` and `registerFrost`; their rows exist in `ua-rs`
(`wallet/entries/registry.rs`). F2, registry records on a line of generations: BUILT (owner 2026-11-23; controller call (120) of CLI-SDK-33's T26 area A entry, UNAUDITED): every SDK registry read that chooses a domain, a signer set or a write target goes through one line reader (`line::read_line`: the bound registry's line walked and checked, every call by one endpoint at one block; a holder off the line, a broken line or a revert is an error, never a fallback): a record is read at the generation that holds it (`holderOf`), its PQZ attachment at its home; a native member of an `msig` signs `UAAuth` in the holder's domain, a native signer in the profile's registry's own, each at its generation; on the generic app-record entries, PqVault's and PqChat's paths, `msig` signing and writes, the write targets and `registration_of`; tested on a two-generation anvil (`clients/pqvault-core/tests/e2e.rs` `pqvault_records_on_a_two_generation_line`). A chain with `pinnedReads` false (Moonbeam, Moonbase) reads them by the sticky read (owner 2026-11-23, decisions CLI-SDK-33 (160), [scaas-rpc CLI-RPC-04](scaas-rpc.md#CLI-RPC-04); BUILT, `line::read_one`): every call of one read by one endpoint at its latest block, its head read before and after, a moved head retried at most 3 times, then `HeadMoving`; so signing and the `msig` writes work there, while a read that feeds a decryption (app-record verification) stays `PinnedReadsUntrusted`. **Sponsored registration** (owner 2026-11-17): a payment to an unregistered derived UA is `ReceiverUnregistered`; the receiver's app makes its portable registration blob (the `register` arguments with the PoP, which binds no caller, and the KEM record when set), the sender's app checks it (the UA equals the intended receiver and its key data, the kind is enabled on the chain, the PoP verifies locally, the KEM record is present and verifies when `kemPkHash` is set) before anything is sent, submits it paying the gas, adds the KEM key by `setKemKey`, and pays only after the registration lands. BUILT (plan T13b; `clients/scaas-sdk/src/account/sponsor.rs`, clientkeys `registrationBlob` and `smartcontracts/vectors/ua/registration_blobs.json`, `tests/account_ops.rs`, the `sdk-e2e` sponsored registration then pay): `registration_blob` and `prepare_submit_registration` for the single-key entries (`register`, `registerWebAuthn`); a blob is the typed `RegistrationBlob` (`from_json` / `to_json`, the named-field JSON text), at most 768 KiB, the largest registration any parameter set allows with headroom (spec §7.1 gives the derivation), depth 4, so a registration carrying a PQZ key's proof fits one and is split by the sender as §7's; `prepare_submit_registration` takes the payer and returns `RegistryWrite` values; `wallet`'s `prepare_pay` answers `ReceiverUnregistered` for a derived UA the profile's registry does not hold, and for any derived UA on a profile naming no registry (fail closed); a registry write whose payer transaction fails to sign stays submittable (owner 2026-11-19, the four rulings recorded under CLI-SDK-30 in decisions.md).

## 5. Operations

<a id="CLI-SDK-08"></a>**CLI-SDK-08** — **One entry point per signed struct and domain; the user reviews every field before it is
signed; calls are decoded** (explicit parameters, every `mtx*` relayable, no EIP-7702: owner rules; the rest controller calls;
BUILT: plan T10, T12, T13, T17, T18, `tests/completeness.rs`, `wallet_ops.rs`, `src/op/tests.rs`; PLANNED (review 2026-11-20, F20):
`sign_rescue_vault`, the two auditor consents and `cancel_all` sign without a prepared value and its review). Each `(struct, domain kind)` pair of `smartcontracts/vectors/typed/typed_ops.json` (and the transfer on ids, `PayMeta`
pays, trade and liquidity orders, registry writes) has exactly one SDK entry point whose request carries the struct's named fields; an
entry point's pairs lie in one module and one feature (`PqzAuth`, attached by the PQZ facade, is the one exclusion). A call prepares
first and returns an opaque prepared value kept by the SDK (a value rebuilt outside it is `PreparedUnknown`) whose review lists every
field with its source: signed (decoded: `payNo` as UUID text, `save`, the fee, the relayer), request (for a confidential operation the
plaintext amount and recipient the SDK encrypted), derived. Submitting signs exactly that value under the matching `ua-rs` check, which
refuses a non-zero unbound `relayer` or `feeRecipient` ([CLI-UAL-13](ua-libraries.md#CLI-UAL-13)); a value past its time or whose nonce
moved is `PreparedStale`. `Execute` and `UAExecute` take a decoded call, built by `ua-rs` from named fields and signed under its
allow-list; an undecoded call exists only behind its own feature and marker, flagged opaque in the review, and is otherwise
`OpaqueCallRefused`. A fee of 0 is accepted everywhere and never replaced. No call signs a caller's digest with a UA key
([CLI-SGN-29](signers-clientkeys.md#CLI-SGN-29)); no EIP-7702 authorization or type-4 transaction is built
([CLI-SGN-40](signers-clientkeys.md#CLI-SGN-40); `TxTypeRefused`). The review lists every token or market the operation touches, with its address and its listed or unlisted mark (owner 2026-11-17).

**The `SignReview` model** (owner 2026-11-27; SPECIFIED, nothing built): the review above becomes the raw section (rows still
`ReviewField`) of one `SignReview` the
SDK emits for every operation, record and app call, built from descriptors compiled into the SDK (one per `(struct, domain kind)`,
keyed by the pinned typehash, none fetched at run time), with typed rows, steps, the payer, warnings by severity and stable code, a
third party's descriptor only as hash-pinned release data under a Caution, and a pre-sign simulation of opaque and app calls as
supporting evidence with its basis shown; every front-end renders it and passes one review vector set:
[CLI-SDK-35](../decisions.md#CLI-SDK-35).

<a id="CLI-SDK-09"></a>**CLI-SDK-09** — **An operation is quoted and confirmed, written ahead, then sent to a gateway that takes it
or relayed by the holder** (BUILT on EVM: plan T10, T10b, T12, T13, T38, T41.evm, `src/op/tests.rs`, `tests/wallet_ops.rs`,
`handoff.rs`, `l1_fee.rs`, the `sdk-e2e` tests; on Soroban: plan T41.soroban, `tests/soroban_ops.rs`; the other families after the
freeze, owner 2026-11-22). Paths: a scaas-node gateway, for the entries the gateway takes
([NODE-GW-03](../node/gateway.md#NODE-GW-03): a registered token's `mtx*` entries, the transfer on ids, the DEX routes, and UA
registration once served), with the same body to the gateways chosen ([CLI-RPC-08](scaas-rpc.md#CLI-RPC-08)): those that announce the
profile's `chain_uid`, one that cannot be read or announces another left out and none left refused (review T26 B-7,
`a_gateway_down_or_of_another_chain_is_left_out`); or self-relay, for any
entry, as a transaction (type 2 where the chain has a base fee, else 0) from the holder's own native account, which pays the gas, with the
entry's calldata from `ua-rs`. A signed operation handed off to its payee is self-relayed by the payee's key after the import's checks (`Op::hand_off`,
`Op::import_signed`; spec §27.5 (c), decisions CLI-SDK-33 (49); BUILT on EVM, plan T41.evm). The quote never makes or sends a signature (owner 2026-11-18, ruling 1); its gas comes from the gas table (execution gas: regular plus EIP-8037 state gas,
so the gas limit covers both; owner 2026-11-19; measured with the registry, the router and the release envs as a real deploy configures
them, G4): a base row for (entry, domain kind, fresh lane), with an optional per-byte part for an input that grows (ruling B), a saved record's `save`, a fee's `fee_extra` (owner 2026-11-19, rulings 1 and 3; a wrap-in entry's measured against a signer who already holds units, A6) and, once when either party the entry debits is a derived UA (the signer, or the attached signature's owner: `mtxPayWithPayeeFee`'s payer), the row's `ua_extra` (A1, G1; measured on every variant a derived signer can sign, else the largest measured for the entry, G2), plus a verify row for the signer kind with 64 gas a byte of its `sig_bytes` (ruling 2; every verify row carries it, a row without it is refused as `GasSigBytesMissing`, A4; a variable-length kind's longest or worst case, A5; every kind's verify gas at its worst case, or where that cannot be determined the most expensive of many measurements plus its `margin`, added) and, for `mtxPayWithPayeeFee`'s attached signature (the payer's, A2), its kind's verify gas without its bytes (they are in the unsigned calldata already, A3) or the dearest accepted kind's (ruling 4), each rounded up to 1,000 and each looked up on its
own in the order the chain's measured rows, the module tables and the SCaaS reference table the profile opts in to; without
both, the app's own figure, one total (at most `max_gas`); then a margin; the quote carries the figure and names both
sources on every path (owner 2026-11-19, ruling B, the gas-table rulings and part 3b; BUILT in the SDK; the forge measurement, the generator and
the reference table BUILT for the entries and signer kinds spec §13.3 lists (the confidential, order, `account`, `dex` and
router entries since item 8), the entries it names unmeasured PLANNED;
EVM only today, the same principle per family PLANNED; spec §13.3). `mtxExecute`'s figure is the wallet's rows plus the app's figure for the inner call (`quote_with_gas`; ruling 5). After signing and before anything is written, a self-relay's gas is recomputed from the signed calldata, for every signer kind: the signature's bytes beyond what the quote counted, at 64 gas a byte with the margin, never below the quote's figure; above `max_gas` `SignedGasAboveCap`, nothing written or sent (owner 2026-11-19, G3; `ua-rs` caps a WebAuthn assertion at 1,024 bytes of `authData` and `clientDataJSON`, `WebAuthnTooLong`, in every `UASig` builder too, Q3; clientkeys the same on `SmartKeyAccount` and NEAR / Algorand passkey assertions, Q4); a gateway operation's self-relay `resend` recomputes its gas the same way from the row's stored signed calldata (Q5), from the larger of the payer's quote and the row's own figure (its entry, kind, signer kind, lane state, stored message and arguments: PR A review, finding 2); the signed gas is held to the chain's per-transaction cap and block gas limit, `GasAboveTxCap` (finding 3). FN-DSA's verify `margin` of 1,000 is the owner's figure (G5). A row whose cost grows with a count names it (`item`: `legs`, `accounts`, `entries`, `members`, `env_items`, `orders`) with its `per_item` gas (1 to 2^24); the row's figure is at a count of 0 (`base_count` 0, any other refused), the quote adds `per_item × count`, the count read from the operation and at most 65,536 (a PQZ rollover's `entries` = min(`n`, the set's `ROLL_MAX`) + its `skip` marks, K1, P1; `env_items` the four `Env` arrays' elements together, P1; `legs` of `mtxCreateToken` its `extra.config.legs`, K2; `orders` the DEX cancel's one order, K2); a count the SDK cannot read refuses the operation, `GasCountUnknown`, on every path; the parse refuses `GasItemUnpaired` and `GasItemUnknown` by name (owner 2026-11-19, I1), and a key outside the format, at the top, on a row or in a row's part, `GasFieldUnknown` (PR A review, finding 1). A third party the entry debits counts for `ua_extra` like the signer (`mtxOperatorTransfer`'s `account`; `mtxForceTransfer`'s record holder, counted as derived: finding 4). The counted rows are measured at several counts, at the entry's bound where feasible (I1 part 2, P3; BUILT: the router's lists, wrap limits, env publishes and Wrapped creation, the DEX cancel, Zether's multi transfers to 16 legs and `mtxRollOverBatch`, PQZ `mtxRollOver` to `ROLL_MAX`); the figure is the line's intercept and `per_item` its slope: the chord from the first to the last measured point where that chord is at or above every point (P4), else the worst slope between two points; the line is at or above every measured point, and where it overshoots the largest count (P1, P2, P4) the table's assumptions state by how much. PQZ `mtxConfidentialTransfer` / `…Compact` and PQZ `mtxRollOverSigned` have no row yet (U1, owner 2026-11-19: a follow-up after this round; the multi transfers need the PQZ precompile's stand-in per auditor-group count, the signed rollover an opening token and the holder's ML-DSA authorization): such an operation is `GasUnquoted` on self-relay. `mtxSetAuditorUA`'s new auditor's consent is an attached signature like the payee fee's (I3): its row has no consent verify, the quote adds the consent's verify row by the auditor's kind (read from `extra.consent` and `newAuditor`; a stored kind's: the worst accepted kind). The PQZ single debits are measured with stand-ins for the PQZ precompile (the set's calibrated row) and the holder's ML-DSA-65, their rows marked `stand_in` (I2). Without a figure a self-relay is `GasUnquoted`; a gateway
quote reports the gas as unquoted and is not refused, the figure is for the user and the app only, never sent to the gateway,
and the SDK never converts a token fee to or from gas. `submit` signs once, writes the row, then simulates the signed calldata
(owner 2026-11-19, ruling A). A send nothing accepted leaves the row `signed` for the next `resume` (review T26 B-6: an error
before any post, a simulation that failed in transport, every gateway unreachable; only a revert or more gas than the quote is
`SimRefused`, every gateway refusing is `GivenUpByEveryNode`); `resume` sends EVM rows only (B-8); a row's path decides how it is
sent, so a self-relayed row `resend` to the gateways is posted to them (B-5). Before
`submit` a quote shows the payer, the gas limit, the maximum fee per gas and the maximum cost; the user confirms it; above the profile's
caps it is `FeeAboveCap`, and the caps come from the SDK's configuration, never from the answering endpoint. A gas limit above the
chain's per-transaction cap (its regular part: EIP-8037; the quote's `regular_gas`, from the rows' `regular` figures, else the
whole) or the block limit is `GasAboveTxCap` (a registration carrying its PQZ key's proof goes in two steps when one does not fit, each
step also held to half the block gas limit, `GasAboveBlockShare`; owner 2026-11-20); a payer that is an
EIP-7702 designator is `PayerDelegated`; the payer's address is linked on chain to the subject, and a holder without a native key has no
self-relay path. The job API is server-side only, never in an end-user build ([NODE-ADM-06](../node/admin-auth.md#NODE-ADM-06)). With no
gateway for the entry and no payer: `SubmitPathNone`. **Write ahead:** sign, write the operation with its signed body (public data) to
the SDK's state, then simulate and send (a refused simulation is tracked as `SimRefused`, never an error); from the signature on the send completes whatever happens to the caller; a row written but not sent is sent
at restart, a row sent is never sent again automatically, only by the user's `resend` of the same bytes. **`submit` returns the operation's id once its row is written; every send result after that is an event, never an error of `submit`** (owner 2026-11-17), so no caller reads a send error as "not paid".

<a id="sdk-bls-multi"></a>**`bls12381-multi` groups (`0x0121`; BUILT `6e16ea8d3`, `ed0b3ab37`; UNAUDITED).** A group is a signer
`KeyRef::BlsMulti {seed, account, index, key_data}`: one member key of an open seed (`ua_key(0x0121, account, 0)`,
[CTR-UA-55](../contracts/accounts.md#CTR-UA-55)) and the group's key data `d`; an operation prepared with it has `from` = the group's
UA. Each member signs its partial of the prepared operation under the operation's check (`Op::bls_multi_part`; a member on
another device prepares the same request, the same named fields and `validUntil`, and gets the same digest); the coordinator
checks each partial on receipt and names a bad one (`bls_multi_part_ok`), then `submit_bls_multi(prepared, quote, parts,
surplus)` aggregates (invalid partials dropped, a minimal set unless `surplus`; below the threshold `BlsMultiBelowThreshold`,
nothing written) and submits as `submit` does, the job's `UASig` by name `{signature, signers}` ([job-api](../node/job-api.md#bls-multi-sig-shape)).
Plain `submit` refuses a group signer, and so do the calls that sign with one key: a DEX order, `cancel_all`, an auditor's consent and an `msig` slot refuse a group at prepare (`Argument`; merged-tree review M16, 2026-11-20); an aggregate never carries an owner statement (`ownerSig`, `pqzAuth`: `Argument`, M15). PLANNED: a group as an order's signer, as an auditor and as an `msig` slot. The quote reads the group's n as the `members` count of signer 289's verify row (`gas +
per_item × n`). Registration: every member's PoP part (`bls_multi_pop_part`, checked by `bls_multi_pop_part_ok`); the cost by n
before the parts exist (`quote_register_bls_multi`: the reference table's `registerBlsMulti` row, `gas + per_item × n`,
regular and state gas, no verify part); `register_bls_multi` aggregates the PoP (`RegistrationPopInvalid` for a bad or missing
part), simulates, raises the gas to the simulation's with the margin where it needs more (G3's rule; the PoP check's gas
pre-check asks the verifier's whole `POP_GAS` up front), and self-relays (no operation row: a registration holds no lane). An
attached signature of unknown kind counts a group's `members` at the cap 64. Rules: [CTR-UA-50](../contracts/accounts.md#CTR-UA-50),
[CTR-UA-52](../contracts/accounts.md#CTR-UA-52), [CTR-UA-56](../contracts/accounts.md#CTR-UA-56). The per-transaction cap holds the
registration's regular gas only (EIP-8037; the row's `regular` and `per_item.regular`, controller call, owner auto-run
2026-11-19): a group of 64 members quotes a gas limit above 2^24 (about 30 M, regular about 9.5 M: a registry write's fixed-cost
row takes no margin, owner 2026-11-20; it was about 45 M with the margin), so it needs
a block gas limit above that and an app `Limits::max_gas` above its default 2^24. Measured (merged-tree review M20,
2026-11-20, `clients/scaas-sdk/runs/2026-11-20-m20-nethermind-summary.txt`, before the margin was lowered): on a local Nethermind copy with Amsterdam
(EIP-8037, EIP-7825 enforced) the SDK's 64-member registration, quoted 44,983,452 gas with a regular bound of 14,240,076,
was included (`gasUsed` 28,600,373), and a call whose regular gas has no bound stopped at exactly 2^24 under a 30 M gas
limit; a PQZ debit (`mtxConfidentialTransferSingle`, quoted 46,445,076 with a regular bound of
13,733,076) was included (`gasUsed` 27,049,355) after two ML-DSA-65 + PQZ-key registrations sent in two steps each (the
one-transaction form quoted above half the block and above 2^24 regular).
**The group limit on a chain capping the regular gas at 2^24** (owner 2026-11-22, kept as it is, decisions CLI-SDK-32's
Change of that date; BUILT, `tests/e2e.rs` `e2e_bls_multi_group_limit_on_a_node`): `register_bls_multi` counts the whole raise
of the gas limit above the table's quote (to the node's estimate with the margin) as regular gas, so on such a chain a group
of at most **45 members** registers in one transaction (an unweighted group, threshold n / 2 + 1, measured on the local
Nethermind copy, `runs/2026-11-20-m20-nethermind-summary.txt`: 45 landed in every run, 46 on the edge, landed in one run and
refused in another as the node's estimate moved with the chain's state, 47, 48 and 64 refused). A larger group is refused
`GasAboveTxCap` before anything is signed or sent, and the app splits it into smaller groups (a group is one UA; there is no
two-step `registerBlsMulti`). The contract's cap stays 64 ([CTR-UA-52](../contracts/accounts.md#CTR-UA-52)); a chain without
that per-transaction cap holds the registration to half its block gas limit and `Limits::max_gas` only, up to the 64.

<a id="CLI-SDK-18"></a>**CLI-SDK-18** — **An operation ends only on a chain fact** (follows [CLI-RPC-09](scaas-rpc.md#CLI-RPC-09);
BUILT: plan T10, T11b, `src/op/follow.rs`, `src/op/tests.rs`, `tests/wallet.rs`, `soroban_ops.rs`; PLANNED (review 2026-11-20,
F12): DEX order and cancel rows ending without their event). Terminal, from a decisive read at the profile's final block only: `Landed` (the executed event of the operation's digest,
`UAMetaTransactionExecuted` on tokens, mandate wallets and the governance router, `MetaTransactionExecuted` on `SmartKeyAccount`; for a
registry write, its record present), `Consumed` (the lane nonce spent without that event; a `GovernanceRouter` op of a derived id reads
the map the router checks it on, `mtxNonceFor(target, …)`, as prepare and submit do: review D-1, BUILT on branch `router-cancel`,
`a_router_ops_follow_reads_the_target_keyed_nonce`), `Expired` (`validUntil` passed with the nonce
unspent), each with its `basis` (`Majority`: the strict majority's agreed read at `finalized`; `OneEndpoint`: endpoint 0's alone
under `failover`; CLI-RPC-09's "their text says they rest on one endpoint", review T26 B-14), and for an EVM native send `Reverted` (final and reverted; owner 2026-11-18, ruling 4). Everything else is `InFlight` with its detail: queued or sent, the gateways' merged state (never terminal, every node `dead`
included), a self-relay transaction that failed or was replaced (not a failed operation: the signed operation is public and may still
land). While in flight the user may wait, resend the same bytes, or cancel the lane's nonce, which makes the operation `Consumed`; a
router op of a derived id on a target of another registry generation is cancelled in that target's keyed map by
`admin_ua_cancel_nonce_for` (`UACancelNonceFor`, [CTR-GOV-33](../contracts/token-wrappers.md#CTR-GOV-33); the router's `mtxCancelNonce`
reaches only its own map). `mtxNonceFor` answers for the target as it is: a client reads it for an op on a new instance only once
the instance exists (review G-6).
After a restart every operation resumes from the chain. On Soroban (review T26 B-1 to B-3, `soroban_follow`) one endpoint answers
every fact of a step, the op's spent entries before its transaction's status, and decides only when the read is decisive (agreed;
under `failover` endpoint 0, not `discovered`); every bound is the chain's: a transfer's or burn's auth entry ends only past its
expiry ledger (it signs no time), a pay also when the read ledger's close time is past its `valid_until`, a native send's
transaction when the close time its status names is past its `max_time` and that endpoint still keeps the ledger it was sent at;
never the SDK's clock (`a_transfer_ends_on_its_expiry_ledger_not_on_the_clock`, `a_pay_expires_on_the_chains_time`,
`a_native_send_expires_on_the_chains_time_within_its_history`, `a_discovered_endpoint_decides_nothing`,
`an_own_landing_between_the_reads_is_never_consumed`).

## 6. Confidential tokens

<a id="CLI-SDK-10"></a>**CLI-SDK-10** — **The SDK is a reading layer under the seven requirements; a decryption failure never reaches
a source; a verdict comes before a send** (ARCH-POS-13 and ARCH-POS-15 as stated; BUILT: plan T15, T16, as the two paragraphs
below state, with their PLANNED parts; UNAUDITED). Zether and PQZ operations run their proofs
inside the `ua-rs` facades, whose requests carry no key. Every read that feeds a decryption is marked so in `scaas-rpc`
([CLI-RPC-06](scaas-rpc.md#CLI-RPC-06)) and meets [CLI-UAL-31](ua-libraries.md#CLI-UAL-31) to [CLI-UAL-37](ua-libraries.md#CLI-UAL-37):
the profile's sources; the pinned chain pair; one block final by the profile's finality rule, by number and hash; storage words and code
hashes, never views; the token catalogued by the factory, read as storage with `ua-rs`'s layout constants; the leg's registered key
equal to the handle's. The read fetches a fixed set of words chosen by the operation, the token and the handle, and returns before any
secret-dependent parsing; decryption and word checks run after it, so a failure never triggers a read of another source, and the
result goes to the holder only. A watched confidential token is read on a fixed schedule. A proof is built against the same final
block's words; a state change after it makes the contract refuse the proof and the operation stays in flight. A PQZ token in verifier
mode gets its inline verdict ([CTR-PQZ-29](../contracts/pq-zero-knowledge.md#CTR-PQZ-29)) from a verifier its chain profile lists,
through `scaas-rpc`'s verifier client, checked before it is attached; refused or unreachable is `VerdictRefused` and nothing is sent. A
PQZ token of another parameter set than the build's is `PqzSetMismatch`. The SDK builds no operation that drops a ciphertext from
contract state.
The Zether reading layer and part of the Zether operations are BUILT (plan T15; `clients/scaas-sdk/src/confidential/`,
`tests/confidential.rs`; UNAUDITED): one read at the profile's final block through `Purpose::FeedsDecryption` fetches a fixed set of
storage words and code (the factory's `_rec[token]`, the token's clone code and `ChainEnv`, `psid`, modes, auditor key, the account's
six slots and every point's four data words, each named UA's registry record and key pointer code) and checks it only after the pool
returned; `zether_balance` decrypts it in the facade; every Zether entry of spec §9.1 is a prepared operation, the Zether UA signing
through `sign_scaas`: the multi-recipient transfers draw their decoys uniformly from the registry's `0x0141` list read as a second
fixed word set (CTR-UA-29: the list's length, then a uniform sample of decoys + excluded entries at indexes drawn before the
read, the whole list when it holds at most twice that; no upper bound on the list, review 2026-11-20 F19) and shuffle every leg; the owner statements sign under `zether-owner`, their relayed forms carrying that
signature as `ownerSig` (owner 2026-11-19, C3). A failed check is a named error (`TokenUncatalogued`, `LegKeyMismatch`, C4; `ReceiverUnregistered` for a recipient with no
registry record, P2). The Zether UA's verify gas of a multi-recipient proof is the gas table's `0x0141` verify row, else the
request's `ua_signer_gas` (P1). The
watch loop reads a watched Zether UA's words on its fixed schedule, nothing decrypted. The anvil e2e (shield → roll-over →
transfer → balances, the token made through the factory, the Zether UAs registered first) is BUILT (gate `sdk-e2e`).
The PQZ reading layer, the balance, the verdicts and the PQZ rows without a proof are BUILT (plan T16 parts 1 and 2;
`clients/scaas-sdk/src/confidential/{pqz.rs,verdict.rs}`, `tests/confidential_pqz.rs`; UNAUDITED): the factory record, the clone's
code and `psid` first, a token of another set `PqzSetMismatch` with no account word read; then the account's slots, `sendCounter`,
`pqzKey` / `pqzVersions`, `accWords` or `accBlob`, the window and the blobs, `proofStore` a storage word (owner 2026-11-19, T16-b);
the registry's proven key the handle's. A verdict comes from `ChainProfile.verifiers` under its own policy (T16-a), its signer checked
against the verifier UA's registry record read at the same final block (T16-c). The six PQZ debits are BUILT (plan T16 part 3,
`src/confidential/pqz_debit.rs`, UNAUDITED; spec §9.2): the recipients' and the auditor's keys as a second fixed word set, the
envelope binding folded by the form, the facade's proof off the async workers, `PqzAuth` signed by the holder under `zether-auth`
and attached, relayed by a gateway (its job submission cap, NODE-GW-08) or self-relayed. The verdict path of an `OFFCHAIN`
debit (asked, checked, attached) is SPECIFIED for a real holder: its tests run on a fake chain state whose scoped record holds
the facade's registry key, and no real `OFFCHAIN` holder reaches it before P-T16-7 below (review 2026-11-20, F30). Under
`strict_majority` verifiers agree on the verdict apart from `validUntil` (each sets it from its own clock), and of the agreeing answers
the one with the median `validUntil` is taken, so no one replica decides (F14, M3). `pqz_balance_all` reads every key version at one final block (F3). An opening token
is `PqzOpeningUnsupported`. A native-id verifier is checked (P-T16-3, `verdict_native_verifier`); `pqz_balance_all` sums the key
versions (P-T16-5, `pqz_balance_all_versions`). PLANNED (P-T16-7): an `OFFCHAIN` holder's
debits, once `ua-rs`'s `PqzKeyHandle` can prove a debit with its scoped secret (today it opens one and proves its own
registration only; until then such a holder is `LegKeyMismatch`), and `PqzRollOver` with the opening-token support it belongs to.
The PQZ debit e2e (`tests/e2e.rs` `e2e_pqz_debit_on_a_node`, ignored by default) ran on a local Nethermind copy with the
precompile (review 2026-11-20, M20, `clients/scaas-sdk/runs/2026-11-20-m20-nethermind-summary.txt`); anvil has no precompile.

## 7. App cores above the SDK

<a id="CLI-SDK-14"></a>**CLI-SDK-14** — **The SDK has no `chat` module: `pqchat-core` is an app core above the SDK and takes
the app's live Matrix client itself** (owner 2026-11-17: one Matrix stack below both chat paths, then the dependency reversed for pqchat-core too; PLANNED until
`pqchat-core` exists; the SDK's side BUILT: no `chat` module and no Matrix SDK below it, `tests/app_core.rs`
`no_app_core_below_the_sdk`, the `PqChat` record and key entries of plan T21 and pqchat-core T1). The app's one Matrix
client (one matrix-rust-sdk stack, one login, one sync loop) lives in the app's one library and is `pqchat-core`'s to use; the
SDK starts no Matrix client, links no Matrix SDK, holds no Matrix store and requires no particular runtime. The attachment and
its release before logout, envelopes kept while a seed is locked, and the runtime shared with the Matrix client are
`pqchat-core`'s rules ([CTR-CHAT-01](../contracts/pqchat.md#CTR-CHAT-01)). `pqchat-core` reaches every signature, KEM operation,
container opening and chain read through the SDK under [CLI-SDK-19](#CLI-SDK-19) and [CLI-SDK-20](#CLI-SDK-20): it signs
`PqChat`'s records through the SDK's named `PqChat` record entries, never through the app signing call, and its ratchet
needs the HMAC, explicit-destroy, storage-root and ephemeral-wrap calls the spec's §12.2 lists, which the `pqchat-core`
spec confirms.

<a id="CLI-SDK-19"></a>**CLI-SDK-19** — **App cores sit above the SDK: they depend on it, it names none of them, and an app links
the SDK and its app cores in one Rust library** (owner 2026-11-17: the dependency reversed, then reversed for pqchat-core too; BUILT on the SDK's side: plan T21, features `app-core`
and `pqchat-records`, `tests/app_core.rs` `no_app_core_below_the_sdk`; `app-core-rust` is scaas-app's).
An app core (`pqchat-core`, `pqvault-core`, a third party's) depends on `scaas-sdk` with the feature `app-core` and on nothing
below it that touches a key or a node; the SDK names no app core and holds no app logic, while the record types of SCaaS
contracts (`PqChat`'s among them, behind the feature `pqchat-records`) are named, typed SDK entries as every SCaaS
contract's are under [CLI-SDK-08](#CLI-SDK-08); `PqVault`'s records have two signing calls, `prepare_pqvault_record` and
`verify_pqvault_record`, and no other PqVault logic (owner 2026-11-22, [CLI-PQV-13](../decisions.md#CLI-PQV-13)). scaas-app's one
library is `app-core-rust` (scaas-app's contract section 12), with the features `native-core` (on by default), `scaas`,
`pqchat` and `pqvault` (each implying `scaas`); the SDK defines no aggregating crate.
**`PqChat`'s tree mode** (BUILT, plan 2026-11-23-pqchat-treekem T5, `src/pqchat_tree.rs`, feature `pqchat-records`; spec
§8, §10, §13, §15; UNAUDITED): thin calls over `ua-rs`'s tree, each a function of the reads it is given (`PqTreeReads`: the
home's views by `ua-rs`'s names and the registry's records) that names every read it missed (`PqTreeStep::Need`):
`pqchat_tree_genesis` (creation in order, each member key authenticated by its registry record) with
`prepare_pqchat_tree_session`; `pqchat_tree_prepare_commit` (built, reviewed, then signed once: the record, its pieces and
`K_e`'s handle); `prepare_pqchat_tree_leave` / `_remove`; `pqchat_tree_replay` / `_resume` (the epochs' states, `K` handles,
rosters, warnings and the pin; the node keys held inside `ua-rs`); `pqchat_tree_registry` (the registry's records a call
missed, `kemKeyAt` with its kept signature, read at the final block as reads that feed a decryption; codex-1); the plan of a
commit in C37's order and of a creation in one transaction from the chain's gas rows (`plan_commit`, `next_send`,
`create_cap`, `pqchat_tree_limits`; rows as data, `gas/pqchat-tree.json` the forge reference; [CTR-CHAT-27](../decisions.md#ctr-chat-27--the-tree-modes-checks-and-bounds-controller-calls)'s Change of 2026-11-26).
No tree logic, no key byte and no "rejoin" call in the SDK.

<a id="CLI-SDK-20"></a>**CLI-SDK-20** — **The `app_core` surface gives an app core account handles, app record signing on
both paths, record verification, key handles, random bytes, reads and relayed submission, under two conditions: secrets
stay below the SDK, and nothing SCaaS is signed blind for an app; if either cannot be met for an app core, the task stops
and the owner decides** (coordinator conditions, controller calls, owner may override; BUILT: plan T21, `src/app_core.rs`,
`tests/app_core.rs`, the `sdk-e2e` `e2e_app_records_on_anvil`; PLANNED: `seal_to` / `open_sealed`, an `msig` or native signer of
the generic app records and of `PqChat` records (PqVault's `msig` signing BUILT, below, CLI-PQV-15); UNAUDITED). (1) Key handles only: a
KEM-unwrapped key, a derived key, an Argon2id output stay in `ua-rs` behind handles of one usage each (`Derive`, `Data`,
`KeyWrap`, refused for any other use) without `Clone`, `Debug` or a byte accessor, scoped to their app core and released
by `destroy` or at the seed's lock; wrap, unwrap, HKDF, HMAC, Argon2id, AEAD and key sealing (under a key-wrap constant no
data seal produces) run in `ua-rs` on them; the only bytes that leave are plaintexts the app core asks to decrypt for the
user; the app root key and every key derived from it never leave, by any path: `seal_key` and every KEM wrap (`kem_wrap`,
`kem_wrap_to_key`, their vectors twins, `pqchat_wrap`) refuse them (`AppKeyRooted`; owner ruling A-3, 2026-11-23,
"Restrict (1) only", BUILT, review T26 A-3 (b), `the_app_root_and_its_derivations_are_never_sealed_out`,
`the_app_root_and_its_derivations_are_never_kem_wrapped`, `the_app_root_never_leaves_by_a_kem_wrap`): sealed under a key
the caller can compute, or wrapped to a KEM key it chose, the root would leave as bytes; the wraps a format pins
seal drawn keys and keys derived from them (PqVault's `keyWrap` of an earlier epoch key, [pqvault spec §6.x
`sealedInfo.prev`](../superpowers/specs/2026-11-17-pqvault.md), VC24; its `file` item's key under `kFile`, the same spec's
item types), so none is refused. The limit kept by the same ruling: `kem_wrap_to_key` wraps a **drawn** key (an epoch, vault or file
key, or a key derived from one) towards a KEM public key the app core chose (an offline recipient not yet on chain), so an
app core can export such a key to a key pair of its own; never the root or a key derived from it; labels stay under the core's own declared prefixes, no two cores' prefixes overlapping. Scoping avoids collisions; it
does not isolate: an app holding the user's unlocked seed set acts for that UA in every app namespace, so only reviewed app
cores are linked. (2) The app signing call takes typed data, never a digest, and signs only a portable record under
`appPurpose(appId)` whose domain is exactly `name, version, salt` with `salt = appId`, or a chain-bound record under the
app's own purpose with the profile's `chainId` and the app's `verifyingContract`; it refuses by name every `UAKinds`
purpose constant (the guard on the chain-bound path) and every domain of a SCaaS contract or of the registry (by name, by
address, by chain), each refusal tested with a positive control and a mutant. Reads of ciphertexts the app core decrypts are decryption reads under
[CLI-SDK-10](#CLI-SDK-10); writes are operations under [CLI-SDK-08](#CLI-SDK-08). Design: spec §12.

Built additions (pqchat-core T1, 2026-11-21; BUILT, UNAUDITED): `read_app(chain, contract, entry, args)` reads a
`view` or `pure` entry of any contract by its JSON ABI item and named arguments at the profile's final block and answers
named JSON (outputs and tuple components by name, integers as decimal strings, bytes and addresses as `0x` hex), bounded
(entry 64 KiB, arguments 128 KiB, answer 1 MiB, output types nesting at most 16 levels: `Argument`), as a read that feeds a
decryption by default (`read_app`; `read_app_plain` for a read that never feeds one, T26 B-17); `read_app_agreed`, the same
read as an agreed read (CLI-RPC-05) whatever the chain's list policy, an app core's explicit option, also a read that feeds a
decryption (CTR-CHAT-23 (d), owner 2026-11-23; `src/app_core/agreed.rs`, BUILT on `pqchat-sigs`). `read_app_agreed_named`
is that agreed read over the chain's named endpoints only (scaas-rpc `read_at_block_agreed_named`: at least 3 named, else
`AgreementNeedsThree`), the read the TreeKEM ruling 13 asks for; `read_app_latest` is `read_app` at the latest block instead of
the final one, for what a sender already landed (C37); both BUILT, UNAUDITED (the TreeKEM T4-T9 review's D-4, D-14). PqChat's key entries
(`pqchat_*`, feature `pqchat-records`) are thin calls of `ua-rs`
`pqchat_keys` on the scope's handles, only in a scope that declared `scaas/pqchat/v1/` (`AppLabelRefused`); the signing ones
take the sender, creator or author from the account and never a digest or a ciphertext of the caller's. PqChat's record
entries (`prepare_pqchat_*`, `prepare_pqchat_card`) also work only in that scope (T26 A-9); they take the record's signer field as
given, and the contract refuses a record whose signer is not that field. Every PqChat signature but S5's is prepared, then
signed (T26 A-5, decisions (125), (135)): `prepare_pqchat_*`, `prepare_pqchat_card`, `pqchat_prepare_session` / `_epoch`
return the review and the typed digest (`PqChatPrepared`, `PqCardPrepared`), and nothing is signed until their `sign()`;
`pqchat_seal_message` (S5) signs without a per-signature review (CLI-PQC-04). The feature
`vectors` (bit 28) adds test-only entries (key bytes in and out, fixed randomness): a release build refuses it
(`compile_error!`), `scripts/check_test_features.py` keeps it out of every shipped artifact and the bind-gen check out of
every binding. It runs alone, in its own test (`--test pqchat_keys`): a `vectors` build of `ua-rs` refuses key handles until
a test unlocks them (no-decryption-oracle §4.8), so the whole suite runs without it and clippy builds it. Four
pure PqChat hashes join them (pqchat-core T3 to T5, 2026-11-22; BUILT, UNAUDITED): `pqchat_wrap_hash` (V2's `hashStruct(Wrap)` of a
wrap read from state, checked by the app core against `wrapHashes[i]` before it enters a decapsulation),
`pqchat_message_id` (a received message's `typed(PqChatMessage)`, its dedupe id), `pqchat_session_id` and
`pqchat_epoch_id` (S4: the ids the wraps' AAD binds, before signing); no key, no network. `SecretBytes` is re-exported so
an app core holds its plaintexts without a `scaas-ua` dependency of its own.
Three more `vectors` entries are pqchat-core T11's hostile harness (2026-11-23; BUILT, UNAUDITED), each sealing what an
honest client never seals: `pqchat_vectors_envelope` (the envelope of a record and a signature given apart, such as a
record signed through the generic `prepare_pqchat_message` by a UA other than its sender), `pqchat_vectors_seal_padded` (S5 from
a given padded plaintext: a non-zero fill stays) and `pqchat_vectors_seal_info_raw` (a `sealedInfo` of a given plaintext,
neither canonicalised nor padded); `tests/pqchat_keys.rs` `hostile_seals_for_the_e2e` reproduces the `envelope` and
`sealedInfo` rows through them and shows K5 and the content check refuse the hostile forms.
The signed contact card (UA-7 §14 O7, owner 2026-11-22; BUILT, UNAUDITED): `prepare_pqchat_card(account, kem_version,
matrix_id)`, then `sign()`, signs `PqChatCard(bytes32 ua, uint64 kemVersion, string matrixId)` in `DS_C` under `PURPOSE_PQCHAT`, the UA from
the account, the Matrix id empty or well formed (`Argument`); `verify_pqchat_card(chain, ua, card, sig)` is V1's check of a
card for `ua` (its `ua` that UA, its Matrix id well formed, the signature the UA's on the registry's records read at the final
block as a read that feeds a decryption), `false` with no detail. Rows: `smartcontracts/vectors/pqchat/cards.json`.
`prepare_app_record` and `verify_app_record` refuse a scope of PqChat's app id `keccak256("scaas.pqchat.v1")` on both paths
(`AppPurposeRefused`: its `appPurpose` is in `ua-rs`'s generated SCaaS list, owner 2026-11-23; BUILT, UNAUDITED); PqChat's
named entries, the card calls and `seal_for_arweave` under its scope still sign.
`argon2id_passphrase` (PqVault V9, 2026-11-21; BUILT, UNAUDITED) is `argon2id` of a typed passphrase after RFC 8265's
OpaqueString (every non-ASCII space to U+0020, then NFC; empty, a control character or bytes that are not UTF-8: `Argument`), so
a composed and a decomposed form of one passphrase give one key; the normalisation runs in `ua-rs`. PqVault's V1 vectors
(`smartcontracts/vectors/pqvault/`) run through this surface only (BUILT, UNAUDITED; `tests/app_core_vault_rows.rs` under
`vectors`, `tests/app_core_vault_records.rs` in the main suite: typed digests in both domains, both signing paths,
the verification); what they leave out: the 2026-11-21 Changes of [CLI-PQV-12](pqvault-core.md#CLI-PQV-12) in decisions.md.
PqVault's records are signed and verified by `prepare_pqvault_record` and `verify_pqvault_record` (owner 2026-11-22,
[CLI-PQV-13](../decisions.md#CLI-PQV-13); BUILT, UNAUDITED): thin calls of `ua-rs`'s `wallet::pqvault` with the generic
calls' profile checks, accepting PqVault's domains `DS_V` / `DS_B` and its seven structs only; `prepare_app_record` and
`verify_app_record` refuse every PqVault record (its domain name, its app id, its purpose `P_V`). `prepare_pqvault_record`
signs as an `msig` too (`KeyRef::Msig`; owner 2026-11-22, [CLI-PQV-15](../decisions.md#CLI-PQV-15); BUILT, UNAUDITED):
the `msig`'s records read as the generic `msig` path reads them, local key slots only, `ua-rs`'s `pqvault::sign_msig`;
`AppSigned.members` carries the slots; an `msig` signer's records chain is the explicit `records` argument (required on the
portable path). One key handle twice in one app-core call is `Argument`, before any lock (CLI-SDK-33's Change of
2026-11-22). `AppCore::generate_passphrase` gives 6 BIP-39 words drawn in `ua-rs`; the generic
KEM key rotation is `Account::prepare_set_kem_key` (`setKemKey` at a version ≥ 1, checked by `ua-rs`'s `check_kem_record`
first). Same entry: BUILT, UNAUDITED.

**Sign after confirm** (owner 2026-11-27): an app core builds the typed record and its quote for the review and calls the
SDK's signing entry only on the user's confirm; a review left makes no signing call: [CLI-SDK-36](../decisions.md#CLI-SDK-36).
The quote before the signature is `AppCore::quote_app_call(chain, contract, entry, args, payer, signer)` (BUILT, UNAUDITED;
the payer checked first, an app row's `per_item` counting the one argument array of its name, the record's `sig` not
counted, [CLI-PQV-17](../decisions.md#CLI-PQV-17) (7)):
`prepare_app_call`'s review and contract checks over the arguments with the record's `UASig` empty, and the payer's quote from
the gas tables alone, never a simulation: the base row `(entry's name, "app", not fresh)` and the signer kind's verify row (its
`sig_bytes` at the calldata price), the transaction row with the unsigned calldata, in the lookup order chain → module →
reference, with the margin; `AppQuote.quote` none (unquoted) without the rows. It is no transaction: the signed record's call
is still `prepare_app_call`'s, whose simulation follows the signature. `AppCore::seal` wipes the plaintext it is given.
`pqvault-core` BUILT, UNAUDITED; BUILT-gap in `pqchat-core`, which still signs when it builds a record (it changes after the
path-less branch lands).

<a id="CLI-SDK-21"></a>**CLI-SDK-21** — **`seal_for_arweave`, `upload_file`, `fetch_file` and `open_file` put an app core's
file on Arweave and read it back; the upload key signs only the item `ua-rs` built; the client keeps the signed bytes until
the item is settled; the free tier carries the smallest bucket, the operator payer the rest, and the client never holds an
operator credential** (owner 2026-11-21, [ARCH-POS-19](../decisions.md#ARCH-POS-19) Q4 (`ar://`) and Q5 (operator payer, free
tier, no credential in the client); the calls, the bucket split, settlement and the re-post schedule controller calls of
[ARCH-POS-20](../decisions.md#ARCH-POS-20), owner: no; BUILT in the SDK, as the "As built" line below states, its tests
against fake bundlers, gateways and payer; the node's payer ([NODE-SPN-05](../node/sponsorship.md#NODE-SPN-05)) SPECIFIED, nothing
built; UNAUDITED; design in the
[spec](../superpowers/specs/2026-11-21-avax-polkadot-arweave.md) part D). Beside the file seal calls of `pqchat-core`'s O9 (b):
`seal_for_arweave(app, file) -> ArweaveFile {url, ct_sha256, sha256, size, key, item}` runs in one `ua-rs` call: a fresh file key
handle, the frame and the object of [CLI-UAL-65](ua-libraries.md#CLI-UAL-65), `ctSha256` computed there, the upload key derived
and the item built, signed and verified ([CLI-UAL-64](ua-libraries.md#CLI-UAL-64)); `key` comes out as `seal_file` gives it
(PqChat: in the `file` content; PqVault: sealed under `kFile`), and `url` = `ar://<id>` is known before any upload.
`upload_file(app, item)` takes only an item `ua-rs` built (a kept item is reloaded by a parser that verifies its signature and
the no-tag shape) and posts it through `scaas-rpc` ([CLI-RPC-14](scaas-rpc.md#CLI-RPC-14)) to the release's bundler list, only on
the user's send; an object in the 2^16-B bucket goes on the free tier, best effort; a larger one, or a free-tier refusal, carries
`x-paid-by` with the operator payer's address after the node's payer ([NODE-SPN-05](../node/sponsorship.md#NODE-SPN-05)) approved
that upload address, and while no payer is configured that is `PayerUnavailable` (until the payer runs, objects above 2^16 B
serve tests only). **Settlement and re-posts.** The app core keeps the signed bytes until [CLI-RPC-13](scaas-rpc.md#CLI-RPC-13)
reports the item settled. If it is not settled, the SDK re-posts the same bytes (same id, never re-signed, never under another
key) at 24 h, 72 h and 7 days after the send, asking the payer for a new approval of the same upload address when a re-post is
refused for payment; this bounded schedule is the one exception to [CLI-RPC-08](scaas-rpc.md#CLI-RPC-08)'s "no automatic
re-send", allowed because the bytes and the id are the same. After the last re-post the file is `UploadUnsettled`, shown to the
user, who may re-post the same bytes by hand; the bytes are kept until settlement or the user's deletion. A PqVault item that
names an `ar://` object is written only after one gateway read of the object has passed the check. `fetch_file(app, url, size,
ct_sha256) -> FileObject` refuses a malformed `url`, and a `size` whose bucket is above the platform's cap, before any request;
reads through CLI-RPC-13 with the exact length `bucket(size) + 16`, marked as feeding a decryption, with SHA-256 equal to
`ct_sha256` as the gateway's acceptance check. `open_file(app, object, key, size, sha256, ct_sha256) -> Plaintext` checks the
exact length and SHA-256 of the object against `ct_sha256` before any decryption, whoever fetched the bytes (pqchat-core T10b),
then the tag, the frame, the zero pad, `size` and `sha256` in `ua-rs` before any plaintext leaves it; a failure is `FileHashMismatch` (or the read's
error), shown on the device only, and nothing the client sends depends on it ([ARCH-POS-13](../decisions.md#ARCH-POS-13)). It
runs on the user's action, or for the 2^16-B bucket automatically if the app allows it. The gateway and bundler lists are the
release's pinned data, with `named` entries from the operator or holder. The user is told, before the first upload, that the
object is public and permanent: a `redact` hides the message, never the object. The metadata cost is stated: the payer's
approvals and the receipt's `payer` link every funded upload key to the operator's payer address, and the bundler sees the
uploader's IP. **Three payment paths** (owner 2026-11-22, decisions CLI-SDK-32; Arweave never depends on the node): the free
tier; the user's **self-pay** (Turbo credits from the user's own wallet, or a per-upload payment: the uploader's own item, a 402
`PaymentRequired`; the paying wallet links the user's upload keys at the bundler, and the client shows `SELF_PAY_NOTICE`); the
operator's payer (NODE-SPN-05, optional, an operator convenience). **As built** (BUILT, UNAUDITED; feature `arweave`, without the
EVM part: `src/arweave.rs` `ArweaveFiles` (`upload_file`, `keep_up`, `fetch_file`), `ArweaveConfig` with `Payer::{None,
SelfPay, Operator}`; with `app-core`: `AppCore::seal_file`, `open_file` (every store) and `seal_for_arweave`; tests
`tests/arweave.rs`; decisions CLI-SDK-33 (66)). PqChat's `file` content (pqchat-core T10b, owner 2026-11-22; feature
`pqchat-records`; [CLI-PQC-02](pqchat-core.md#CLI-PQC-02)): `pqchat_seal_file_message(account, k, pos,
header, fields_json, file_key)` seals a `file` content given without its key, the key entered from the `File` handle inside
`ua-rs`; `pqchat_open_file(content, object)` opens the object a received content names, its length and `ctSha256` checked
before any decryption, the key read inside `ua-rs` (BUILT, UNAUDITED; CLI `app-core pqchat-seal-file-message`, `app-core
pqchat-open-file`; tests `tests/pqchat_keys.rs`). The kept bytes are the app core's (`KeptUpload`); `keep_up(kept, now)` takes the
app's clock.

<a id="CLI-SDK-34"></a>**CLI-SDK-34** — **Before signing, the SDK checks that the target contract's registry generation knows every
derived UA the operation names** (owner 2026-11-24; SPECIFIED).
- **What is checked:** the signer, the receivers and the role holders, by `kindOf` on the registry in the target's env
  ([CTR-UA-73](../contracts/accounts.md#CTR-UA-73)).
- **An unknown UA is refused before signing,** with a named error that says which UA, which generation, and the way out:
  - when the kind exists in that generation, the UA registers there too, with the same bytes and the same id;
  - when it does not, the user uses another UA or a native address.
- **Wallets:** a wallet creating a UA registers it in the oldest generation still in use that supports its kind.

## 8. Runtime, events, errors

<a id="CLI-SDK-11"></a>**CLI-SDK-11** — **The SDK is async on tokio and reports by subscription** (BUILT: plan T1, T14, `tests/history.rs`). The API is `async`;
the SDK adopts the app's tokio runtime or starts its own for a binding, and every exported async call runs its body on that runtime, so a
generator that polls from a foreign executor never runs I/O outside a reactor. Scrypt, Argon2id, proofs and slow key generation run off
the async workers, bounded (one at a time by default). A dropped call means: a read is abandoned, a store write completes or leaves the
old item, a submission completes to its written state. Events (seed locked and unlocked, keystore changes, mismatches and rollbacks,
abandoned hidden-set operations, operation states, balances, history items, dropped endpoints) go to each subscriber's bounded
queue; a slow subscriber gets `Lagged` with the count missed and re-reads state, and the SDK never waits for it. Watching is bounded per
poll. No event callback crosses a binding: the only interfaces an app implements are `SecureStore` and `Authenticator`, whose errors
include an unexpected-callback case, so a host exception never panics the SDK. A change of the SDK's state by another process is the event `StateChanged` (found by a cheap read of the state's revision on each poll, or at once where the store reports changes) (owner 2026-11-17).
History and watching are BUILT (plan T14; `clients/scaas-sdk/src/wallet/history.rs`, `src/watch.rs`, `tests/history.rs`): history
pages backwards from the profile's final block, one log window per request with both bounds, newest first, the account's operations
on the first page; `watch` takes only an account a keystore row names (a hidden set's account is never written, so no event or
cursor names it), reads at most `max_watch` (account, chain, token) triples per poll in turn, and keeps each triple's cursor in the
SDK's state; `StateChanged` and `state_rev` are built as stated.

<a id="CLI-SDK-13"></a>**CLI-SDK-13** — **Errors are named, stable codes; the layers below keep their names** (BUILT: plan T1, `src/error.rs`,
`tests/config.rs` `error_codes_are_names`). An error
answers `code()`, the variant's name, appended and never reused. `ua-rs`'s and `scaas-rpc`'s codes pass through by their own names (a
scaas-node refusal keeps its node `code`, [CLI-RPC-10](scaas-rpc.md#CLI-RPC-10)); `ua-rs`'s `Argument` is named per call where
scaas-app's contract has a name; no code name has two meanings across the layers. A name scaas-app's contract also uses means the same
thing in both (`VaultOpen`, `VaultParams`, `VaultVersion`, `VaultFormat`, `VaultIo`, `MnemonicInvalid`, `ChainUnknown`,
`EndpointScheme`, `EndpointAllFailed`, `EndpointNoMajority`, `AbiMismatch`, `Internal`). `BroadcastRejected` is not an error: it is the
code of a send outcome, never final ([CLI-RPC-08](scaas-rpc.md#CLI-RPC-08)). A node's `detail` text is untrusted: a UI shows a message
by `code`. The SDK's own names include `StoreConflict`, `KeystoreMismatch`, `KeystoreRollback`, `AccountUnverified`, `SeedUnknown`,
`SeedExists`, `AccountExists`, `LabelTaken`, `ConfirmationMissing`, `VaultPassphraseWeak`, `DerivationPassphraseShort`, `OriginSignature`,
`AuthenticatorRefused`, `ProfileMismatch`, `FeatureMissing`, `PreparedStale`, `PreparedUnknown`, `OpaqueCallRefused`, `FeeAboveCap`,
`GasAboveTxCap`, `GasUnquoted`, `PayerDelegated`, `SubmitPathNone`, `VerdictRefused`, `TxTypeRefused`, `RawDigestRefused`, `AppDomainRefused`,
`AppPurposeRefused`, `AppSaltMismatch`, `AppHandleForeign`, `AppLabelRefused`, `AppKeyUsage`, `AppArenaFull`, `KemKeyGone`,
`ReceiverUnregistered`, `RegistrationUaMismatch`, `RegistrationKindDisabled`, `RegistrationPopInvalid`, `RegistrationKemMissing`,
`GasAboveBlockShare`, `RegistrationVerifyOnly` (the kind's home, `kindHome(kind)`, is another generation of the line), `UaUnregistered`
(no generation of the bound registry's line holds the UA), `PqzHomeNone` (no PQZ home on the walk), and for Arweave
(CLI-SDK-21) `PayerUnavailable`, `PaymentRequired`, `UploadRejected`, `UploadUnsettled`, with `ArweaveItem`, `FileTooLarge` and
`FileHashMismatch` shared with `scaas-ua`
([CTR-UA-65](../contracts/accounts.md#CTR-UA-65), [off-chain readers](../contracts/accounts.md#off-chain-readers)). A
warning (`short_seed`, `imported_key`) comes beside a success, never as an error.

## 9. Bindings

<a id="CLI-SDK-12"></a>**CLI-SDK-12** — **Bindings are generated from the SDK's one API; an app links one Rust library** (owner
2026-11-11; generators and the C point controller calls; BUILT for Dart: `clients/scaas-sdk/bindings/dart`, generated
by `clients/scaas-sdk/runs/2026-11-17-scaas-sdk-gen.sh` with its drift check, plan T20, decisions CLI-SDK-30; the sync C++ surface BUILT: `clients/scaas-sdk/bindings/cpp`, plan T20b; the C# binding BUILT over the async API, its spike having shown `uniffi-bindgen-cs` carrying async: `clients/scaas-sdk/bindings/cs`, plan T20c; the Python binding BUILT: `clients/scaas-sdk/bindings/python`, plan T20d; the Kotlin binding BUILT: `clients/scaas-sdk/bindings/kotlin`, plan T20e; the Swift binding BUILT: `clients/scaas-sdk/bindings/swift`, plan T20f; the JS / TS binding BUILT over wasm-bindgen: `clients/scaas-sdk/bindings/js`, plan T20g; the Java binding BUILT over the async API: `clients/scaas-sdk/bindings/java`, plan T20e2; the Go binding BUILT over the async API: `clients/scaas-sdk/bindings/go`, plan T20h; each language switched on and off in
`clients/scaas-sdk/bindings/langs`, decisions CLI-SDK-33 (102)). The public Rust API is the binding surface: module objects
shared by reference, owned strings, byte vectors, integers, records and enums, string ids, no fixed-size arrays, lifetimes or generics,
secrets only as `SecretBytes`, every async call on the SDK's runtime. Generators: `flutter_rust_bridge` 2 for Dart and Flutter (the
two platform interfaces as one generated record of async closures); official UniFFI for Python, Kotlin and Swift over the async API;
`wasm-bindgen` for JS / TS in the browser over the async API; `uniffi-bindgen-go` for Go, `uniffi-bindgen-cs` for C# and `uniffi-bindgen-java` for Java
(fallback: a Java facade over the Kotlin binding) after a spike each (async if the generator carries it, else `sync-api`); all in this round (owner 2026-11-18). **C++ / Qt** (owner 2026-11-18, Q-B1 (b), after the spike showed `uniffi-bindgen-cpp`
refusing every async item): no C++ binding is generated from the SDK; Qt reaches it through the app's one library's own C ABI
(scaas-app's `app-core-rust`, cbindgen, as `app-matrix`), whose Rust side owns the one tokio runtime and returns each async call
through a completion callback that the Qt side posts to its GUI thread. **Third-party C++ apps, and every UniFFI generator without async** (owner 2026-11-18, (a′): C++, C#, maybe Go; Kotlin, Swift and
Python use the async API): a sync surface behind the feature `sync-api` (off by default), generated to C++ by UniFFI with
`uniffi-bindgen-cpp` (C# after its own generator spike): each exported async call has a `*_blocking` twin over the same
body (one macro, a test that none is missing), cancellation by an explicit cancel token, the platform interfaces sync, events
the same pull subscription. The SDK has no C ABI of its own in this round, and `ua-c` stays the signer's C surface. No binding is
written by hand per language, and no app-facing binding wraps `ua-rs` directly. No panic crosses the boundary (unwinding builds, every
call caught, a failed task `Internal`). An app links one Rust static library that holds the SDK and its app cores (scaas-app's
`app-core-rust`, [CLI-SDK-19](#CLI-SDK-19)); two Rust libraries in one process are not allowed. Each generated binding refuses, at load, a library
whose API version or feature bits differ from what it was generated against, or a test-only `vectors` build of `ua-rs`
(`AbiMismatch`), in Rust at the library's opening on every binding, FRB's `sdk_open` included (review T26 C-2,
`the_opening_runs_the_load_check`). `ua-rs`'s existing wrappers stay as they
are for clients that use the signer without the SDK ([the wallet surface](ua-libraries.md#the-wallet-surface-of-ua-rs-built)).

**In the browser** (owner 2026-11-27; PLANNED): scaas-app's web build and extension sign only through the SDK, a native EOA signs a
dApp's typed EIP-712 data only (never `eth_sign` or `personal_sign`), the provider sits in the top frame only, bridge mode to the
native app comes before a wasm key host, Firefox and Safari re-open from a session key in `storage.session`, and the passkey
residual of a `webauthn-p256` key under another extension's host permissions is an accepted risk:
[CLI-SDK-37](../decisions.md#CLI-SDK-37).

## 10. Chain profiles and native chains

<a id="CLI-SDK-15"></a>**CLI-SDK-15** — **Chain profiles are the app's pinned data; the chain is asked, never assumed** (BUILT: plan T1,
T11, T24, T40, `tests/config.rs`, `wallet.rs`, `evm_profiles.rs`).
A profile names its chain key (`<chain>-mainnet`, `<chain>-testnet`, `scaas-testnet`), family, chain id, `chain_uid`
([NET-ALL-24](../networks/README.md#NET-ALL-24)), the RPC node list and the gateways with a credential per endpoint where one is
needed ([CLI-RPC-02](scaas-rpc.md#CLI-RPC-02); an end-user app uses none, and no credential is ever stored in the keystore or the SDK's
state), the finality rule of its decisive and decryption reads, the chain's per-transaction gas cap where it has one, the SCaaS
contracts, the reviewed tokens and DEX list and the PQZ verifiers. Every chain connection pins its `chain_uid`. A gateway's or a
contract's `chain_uid` that differs from the profile is `ProfileMismatch` and that source is not used
([CLI-SGN-33](signers-clientkeys.md#CLI-SGN-33)); a token found through the factory's index
([CTR-TOK-27](../contracts/token-wrappers.md#CTR-TOK-27)) but not on the profile's list is shown as unlisted, its name and symbol
bounded and stripped of control and direction-override characters. Fees, gas limits and block gas come from the chain, under the
profile's caps; a gas price of 0 is a value like any other; no block limit is configured.

<a id="CLI-SDK-16"></a>**CLI-SDK-16** — **EVM keys sign only built transactions; other native chains sign through one guarded entry**
(owner 2026-11-17; BUILT: plan T11, T11b, T19, `tests/wallet.rs`, `src/wallet/raw_tests.rs`; UNAUDITED). EVM native sends (`evm`, `hedera_ecdsa`) are transactions of type 0, 1 or 2 built and signed in `ua-rs`
(3 and 4 refused; 0 by default where the chain has no base fee; owner 2026-11-18, ruling 3), quoted and capped, a delegated sender's
quote carrying the delegation mark (ruling 5); no EVM key signs a raw digest. Soroban's native XLM send is built by the SDK from named fields and signed by `ua-rs`'s transaction builder (plan
T41.soroban, `soroban_prepare_native_send`, `tests/soroban_ops.rs`). For another chain an app's own encoder builds the transaction and the SDK signs it through
one entry that exists only behind its own feature and marker and is absent from the default generated surface. The entry, not
`ua-rs`'s existing calls, enforces the restrictions (`ua-rs` keeps its native-key digest signing for other uses): native keys only,
never a UA key or a SCaaS kind, never an EVM-address key; NEAR, Sui, Stellar and Hedera Ed25519 through `ua-rs`'s envelope-building
calls (the transaction bytes in, the chain's envelope built and hashed in `ua-rs`), never as a bare digest; GRAM, whose native key is its
SCaaS identity and whose signed value has its SCaaS payload's form, kept off the entry; a refused off-chain envelope (Solana OCMS, Aptos `APTOS\n`) refused by the SDK itself
(and by `ua-rs`), with no first-byte rule (a `0x05` / `0x19 0x01` refusal was withdrawn: it refused real Polkadot and Solana
transactions and protected no payload); a bare 32-byte digest only for the Bitcoin sighash. All refusals are `RawDigestRefused`. The preimage is built in the app's
process from the transaction the user reviewed, decoded. **Residual:** a Bitcoin sighash is opaque to
`ua-rs`, and a Bitcoin key's secret also controls an unfunded EVM address; the defence is the caller's obligation. The Bitcoin, NEAR and
Polkadot keys and addresses are BUILT (plan T19, feature `native-networks`); their native sends are PLANNED (NEAR and Bitcoin after
the freeze, DOT deferred; owner 2026-11-22).

## 11. The CLI

The CLI: [scaas-cli.md](scaas-cli.md#CLI-SDK-17).

The interactive terminal front-end over the SDK is `scaas-tui`, a separate program with its own rules
([CLI-TUI-01](scaas-tui.md#CLI-TUI-01)): a session that follows events and reviews every operation on screen, where the CLI runs one
call per command.

## 12. User profiles

Status: **BUILT** in part, wave 1 ([plan](../superpowers/plans/2026-11-27-user-profiles.md) UP1 to UP11, KH; branch
`user-profiles` at `f9a599996`): the byte formats and their vectors, `ua-rs`'s `ProfileKeys` and `ExportKey` (feature
`key-handles`), the key-lock label in `ua-rs` and clientkeys, the crate `scaas-profile` and the SDK's `user_profile` (`UserProfiles`,
`UserProfile`, `Sdk::close`); each rule below names what of it is built. **SPECIFIED** (wave 2): platform unlock, the CLI, TUI and
app surfaces, the pqchat-core and pqvault-core store adapters, the SDK's key-lock calls, the browser store, the bindings of the
surface, the chain-profile rename, the Matrix client closed at lock. The design is the [user-profiles spec](../superpowers/specs/2026-11-27-user-profiles.md)
(a frame; the owner's rulings on its open points, 2026-11-27, in its §16; Fable's review of the same day applied, its §19). A **user profile** ("Profile" on screen, `UserProfile` / `user_profile` in code) is one local
identity with its own keystore, app-core state and settings; a **chain profile** (`ChainProfile`, §10) is a chain's pinned data.
UNAUDITED.

<a id="CLI-UPR-01"></a>**CLI-UPR-01** — **"Profile" on screen, `UserProfile` in code; a chain's pinned data is a "chain profile"**
(owner 2026-11-27; BUILT: the names `UserProfile` / `user_profile`, the SDK module and the crate `scaas-profile`; SPECIFIED: the
chain-profile rename, wave 2). The per-chain profile of §10, the CLI's and the TUI's profile files and their default, caps and
features are called chain profiles (`ChainProfile`) in docs and code. The rename touches no on-chain byte and is a later task,
listed in the spec §15, the stable code `ProfileMismatch` becoming `ChainProfileMismatch` with it (owner 2026-11-27); it lands
before the CLI's `--profile` flag.

<a id="CLI-UPR-02"></a>**CLI-UPR-02** — **User profiles live in the SDK layer and every client uses them** (owner 2026-11-27;
BUILT: the one surface, `scaas-profile` and the SDK's `user_profile`, plan UP5 to UP10, `scaas-profile` `tests/*.rs` and the SDK's
`tests/user_profile.rs`; SPECIFIED: its use by the CLI, `scaas-tui` and scaas-app, and its bindings, wave 2): scaas-app desktop and mobile, `scaas-tui` and the CLI `scaas` open, lock and switch profiles through one SDK surface
(spec §11), with no profile logic of their own. **Change (owner 2026-11-27, decisions CLI-UPR-02's Change of that date;
BUILT, `74b860488` and plan UP6 to UP10):** the store lives in `scaas-profile`, used by the SDK and by scaas-app's default build: a crate of its own over `ua-rs`
only (the profile root, the index, the envelope, the instance lock, the sealed store with its journal, generations, manifests and
anchor, hidden profiles, delete, migration, export and import, the storage of settings), with its own error codes named as the
SDK's. The SDK depends on it and adds what needs the SDK: an `Sdk` opened on a profile, `Sdk::close()` at lock and switch, the
chain-profile meaning of the settings, the store keys handed to app cores, and the `SecureStore` face with the mapping of the
store's codes to `StoreError` and `SdkError`.

<a id="CLI-UPR-03"></a>**CLI-UPR-03** — **A machine holds many profiles, each its own data directory** (owner 2026-11-27;
BUILT: one directory `p/<id>/` per profile with its keystore, `sdk.state`, settings and the parts `pqchat` and `pqvault`,
`scaas-profile` `tests/profiles.rs`, `tests/settings.rs`; SPECIFIED: the pqchat-core and pqvault-core store adapters, wave 2): its encrypted store (many seeds, many native secret keys, hidden sets: the keystore of §3 unchanged), its chat and vault
state, and its own settings, its chain-profile settings included. The release chain profiles stay the build's (CLI-TUI-11); a
profile only selects and overlays them under CLI-TUI-06.

<a id="CLI-UPR-04"></a>**CLI-UPR-04** — **Each profile is protected separately; opening one unlocks nothing of another** (owner
2026-11-27; BUILT: each profile's own data key, passphrase wrap and KDF parameters, `ua-rs` `ProfileKeys` (`tests/profile.rs`),
`scaas-profile` `tests/profiles.rs`, `tests/reseal.rs`; SPECIFIED: the biometric unlock, wave 2): its own passphrase and KDF parameters, an optional biometric unlock, opt-in (the pattern of PqVault's
O7 (b)). Each seed keeps its own vault passphrase inside (CLI-SDK-03).

<a id="CLI-UPR-05"></a>**CLI-UPR-05** — **A first run with no profile creates "default"; its passphrase is asked when its first
secret is created** (owner 2026-11-27; BUILT: `scaas-profile` `first_run_default`, the SDK's `passphrase_required_before_any_work`
(every secret-creating call refused until `set_passphrase`); SPECIFIED: the clients' prompt, wave 2).

<a id="CLI-UPR-06"></a>**CLI-UPR-06** — **A profile is open in at most one instance; instances meet only over the network** (owner
2026-11-27; BUILT: the instance lock, `scaas-profile` `tests/lock.rs`; SPECIFIED: the two-instance PqChat end-to-end test, wave 2). A lock file in the profile's directory; a second instance opening the same profile is refused with
`ProfileInUse`. Instances with different profiles work together only over PqChat, Matrix and the node, with no local side channel,
so two-person chat is tested on one machine.

<a id="CLI-UPR-07"></a>**CLI-UPR-07** — **Switching locks the current profile, forgetting its secrets exactly as a seed lock does
(CLI-SDK-06), then opens the other** (owner 2026-11-27; BUILT: the lock, `UserProfile::lock` (`lock_all`, `Sdk::close`, the arena wiped, the
instance lock released), the SDK's `g11_sdk_twice_and_locked`, `g11_no_request_after_lock`,
`g11_lock_revokes_hidden_set_of_a_locked_seed`; SPECIFIED: the clients' switch and the Matrix client closed at lock, wave 2), on
desktop and mobile.

<a id="CLI-UPR-08"></a>**CLI-UPR-08** — **The profile list shows the user-given names only; a profile may be hidden from it and is
then opened only by typing its name** (owner 2026-11-27; BUILT: `list`, `open_hidden`, `scaas-profile` `tests/hidden.rs`, the
SDK's `hidden_calls_route`; SPECIFIED: the clients' pickers and prompts, wave 2), as a hidden set opens only by its passphrase.

<a id="CLI-UPR-09"></a>**CLI-UPR-09** — **A profile's id is a UUIDv7** (owner 2026-11-27; BUILT: `vectors/profile/ids.json` read by clientkeys and `scaas-profile`
`ids_rows`). Its timestamp gives each
profile's creation time, hidden ones included, to anyone who can list the profile root (spec §4, §14).

<a id="CLI-UPR-10"></a>**CLI-UPR-10** — **The id is stable, names the profile's directory, and never leaves the device** (controller
call; BUILT: `scaas-profile` `envelope_rows` (an envelope under another id is `ProfileFormat`), `export_refusals_and_payload`
(no id in an export)). The name is a label only; a rename keeps the id; an envelope whose id differs from its directory is refused. The
id is never on chain, in a job, a request, a message, a log, an error, an event, a backup or an export, and is not derived from any
seed, key or name; it reaches the client only to name keychain items, and `UserProfileInfo`'s `Debug` redacts it.

<a id="CLI-UPR-11"></a>**CLI-UPR-11** — **One profile root, a directory on every platform; the index is a cache of the envelopes'
public names; a one-time move from the CLI's data directory into "default"** (controller call; BUILT: `scaas-profile`
`g12_root_modes_and_symlink`, `g10_rebuild_lists_every_visible`, `tests/lifecycle.rs` `migration_moves_into_default`,
`g4_crash_at_each_migration_step`, `legacy_beside_profiles_reported`, the sources given as `ProfilesConfig.legacy` and
`legacy_overlay`; migration's step (3) at `set_passphrase`'s commit, owner 2026-11-28 (decisions);
SPECIFIED: the CLI computing the source paths, wave 2). Profiles sit in `p/<id>/`
under a root the SDK tightens to `0700` only when it holds profiles or was made by the SDK (another wider directory refused, a
symlinked root refused); on mobile the root is the app's private directory and the app supplies only keychain items. A visible
profile's name is a public field of its envelope, so a rebuilt index (never a first run while profiles exist) lists every visible
profile; a row that points at a hidden envelope is refused and dropped. The generation of a protected profile accepts only HMAC
names, their `.lock` files and FileStore's crash-left temporaries (removed at open); the unprotected `g0` holds plain items of part
`sdk` only. The migration reads `--data-dir` or the default data directory on every OS, under the root lock and the legacy keystore
lock, only when no profile directory exists; legacy items beside existing profiles are reported. **Change (owner 2026-11-28; BUILT,
`scaas-profile` `migrated_default_sealed_after_commit`, the SDK's `migrated_default_refused_until_sealed`):** `set_passphrase` on a
migrated "default" holding a keystore needs the user's confirm of the seeds moved: the SDK's `migrated_seeds()` shows their count
and labels (the keystore's public fields), `set_passphrase` takes `ConfirmMigratedSeeds { seeds }` with that count (the crate
`ConfirmMigratedKeystore`); without it, or with another count, `ConfirmationMissing`, before any KDF, nothing written.

<a id="CLI-UPR-12"></a>**CLI-UPR-12** — **A profile's items are sealed under its own random data key, wrapped by Argon2id of its
passphrase; every state refuses what does not belong to it** (controller call; BUILT: `vectors/profile/envelope.json`, `ua-rs`
`tests/profile.rs`, `scaas-profile` `g3_state_flipped_and_marker`, `g3_unprotected_refuses_sealed`, `name_hint`,
`set_passphrase_seals_and_keeps`; hide and a hidden rename take the passphrase ([CLI-UPR-13](#CLI-UPR-13)); SPECIFIED: the biometric
wrap's use (its associated-data row built) and the clients' announcement, wave 2). An envelope with per-profile parameters
(default 64 MiB / 3 / 4); the wraps' associated data the canonical object of exactly its public fields format, version, id, state,
generation and parameters with their salt, after `ua-rs`'s `seal_key` prefix; the visible name a clear hint outside it, checked
against the sealed label after unlock (`ProfileIndexMismatch`, the hint rewritten from the label), so rename, hide and show need no
passphrase and never touch the wraps; the hidden flag sealed in the label; a protected
profile refuses any plain item, an unprotected one any sealed item and (outside a migration) a keystore, and a keychain marker, where
there is one, refuses an unprotected envelope after protection and is rewritten when missing; an unprotected profile is announced at
every open and its settings shown before they are sealed; the passphrase in OpaqueString form, its length rule counted on that form,
never kept; an unprotected profile holds no secret (`ProfilePassphraseRequired`); the biometric wrap per device, off by default, under
a policy that requires the current biometric enrollment, never on a hidden profile, dropped at a passphrase change. Owner 2026-11-27:
the default is 64 MiB / 3 / 4, stronger allowed within the bounds, no timing run; at the first secret the profile passphrase and the
seed's vault passphrase are two entries. **Change (owner 2026-11-28; BUILT, vectors first):** the label's associated data
binds the envelope's revision, `lp("scaas.profile.label") ‖ be16(1) ‖ lp(id) ‖ be64(rev)`; every envelope write re-seals the label
at its new revision; an older envelope written back with its revision raised opens its wrap and fails its label:
`ProfileRollback` with its event, nothing written.

<a id="CLI-UPR-13"></a>**CLI-UPR-13** — **At most 16 hidden profiles, created without ever being listed, never two with one name and
passphrase, found by a bounded search over the envelopes with no early stop and one error; hidden from the list, not deniable on
disk** (controller call; BUILT: `scaas-profile` `tests/hidden.rs`, `hidden_import`; `hide` and a hidden `rename` take the typed passphrase
for the duplicate search, a controller call in decisions). `create_hidden`, a hidden import and `hide()` refuse at the cap (`ProfileHiddenLimit`); every
path that makes a profile hidden or changes a hidden one's name or passphrase runs the duplicate check; the search takes the
envelopes without a public name and the unusable directories (not the index), at most 32 (`ProfileSearchTooLarge`), runs max(count,
4) KDFs at each envelope's own parameters, compares names by one helper (NFKC, then lower case), and opens only a single match;
`ProfileOpen` for every failure. Owner 2026-11-27: the name is a label, not key material; nothing stronger than hidden from the list
is offered. **Change (owner 2026-11-28; BUILT, `scaas-profile` `hidden_duplicates_listed_never_picked`, the SDK's
`hidden_duplicates_through_sdk`):** two instances' concurrent `create_hidden` of one (name, passphrase) may both pass the duplicate
check (accepted); a hidden open with two or more matches is `ProfileHiddenAmbiguous`, never a silent pick; `hidden_matches` lists
them as opaque choices (place and creation time, no id) and `open_hidden_match` opens the chosen one after a fresh search.

<a id="CLI-UPR-14"></a>**CLI-UPR-14** — **The instance lock is a non-blocking OS advisory lock held for the open profile's life**
(controller call; BUILT: `scaas-profile` `tests/lock.rs`, `search_locks_only_the_match`; SPECIFIED: the CLI's side, wave 2; Web Locks
with the browser store, PLANNED). `try_lock` before the envelope is read, released by the OS at any process end, nothing written into
it, so no stale lock exists; the hidden search reads without a lock and locks only its match; local filesystems only; Web Locks in a
browser. When built it replaces, for a profile, the shared-directory sentence of [CLI-SDK-17](scaas-cli.md#CLI-SDK-17) and the SDK spec §6.3:
clients share the root and the index, never an open profile. Owner 2026-11-27: a second instance is refused even when it only reads,
and an app extension is refused while the app has the profile open.

<a id="CLI-UPR-15"></a>**CLI-UPR-15** — **Create, rename, hide and delete are atomic and confirmed; a profile with a lost passphrase
can still be deleted** (controller call; BUILT: `scaas-profile` `tests/lifecycle.rs` (`delete_open_profile`,
`delete_locked_visible`, `g10_crash_at_each_delete_step`, `damaged_directory_reported_never_removed`, `hidden_not_deleted_by_id`),
`create_names_and_limit`, the SDK's `delete_through_sdk`). Create is journaled with its index row; delete needs the name typed, shows how
many seeds lack a backup and asks a second confirmation for them, and starts by renaming the directory to a tombstone, which start-up
finishes; a directory without an envelope is reported, never removed; a locked visible profile is deleted with the name typed and a
confirmation that its data is lost. A whole profile exports and imports by [CLI-UPR-17](#CLI-UPR-17). Owner 2026-11-27: a hidden
profile whose passphrase is lost is neither named nor deleted by the app; the user removes its directory by hand; no call deletes
unlisted directories. **Change (owner 2026-11-28; BUILT, `scaas-profile` `g1_two_step_old_copy_after_a_tombstone_refused`, the
SDK's `g1_purge_tombstones_through_sdk`):** a deleted id keeps a permanent marker, `p/.tombstones/<id>`, written by a delete before
its rename and by start before it finishes a tombstone; a directory under a marked id is refused at start (`ProfileRollback`
reported) and at open (`ProfileRollback`), never listed, searched or opened, its keychain items never used, until the user calls
`purge_tombstones` with its confirm.

<a id="CLI-UPR-16"></a>**CLI-UPR-16** — **Clients open a profile by name, a hidden one only through a prompt; the CLI never follows
the last profile an app opened** (controller call; SPECIFIED, nothing built: the CLI's flags and commands, the apps' pickers,
wave 2). `--profile <name>` or `--profile-name-fd` (else "default"; an unknown
name `ProfileUnknown`) and `--profile-hidden`, the hidden name and every passphrase from the terminal without echo or one file
descriptor per secret, never the command line or the environment; commands that need no profile open none; the CLI names the profile
on stderr (a line that lands in CI logs, stated); `scaas profile settings` replaces `--overlay`; the apps' pickers always offer
"Open another profile"; a hidden profile's name is never drawn; the clipboard value a client set is cleared at lock. Owner
2026-11-27: the idle lock locks the seeds, as today, not the profile.

<a id="CLI-UPR-17"></a>**CLI-UPR-17** — **A whole profile exports and imports as one sealed file** (owner 2026-11-27; BUILT:
`vectors/profile/export.json`, `ua-rs` `ExportKey`, `scaas-profile` `tests/export.rs`, the SDK's `g9_export_import_through_sdk`).
Inside: the profile's store items (seed vaults sealed as today), its index entry and its settings, its chain-profile settings
included. Never inside: the OS lock, caches. Sealed under a passphrase the user types at export, with the profile envelope's
Argon2id bounds; a typed confirm; the integrity of the whole file bound in the seal. Import makes a new profile with a new UUIDv7; a
file never overwrites an existing profile. Vectors in clientkeys and `ua-rs` before code (spec §10, export and import).

<a id="CLI-UPR-18"></a>**CLI-UPR-18** — **The export file holds no id, so an import is always a new profile; it is sealed in pinned
chunks, bounded, verified before it is parsed, and brings no setting that could weaken the profile** (controller call; BUILT: `scaas-profile` `tests/export.rs`, `tests/settings.rs` `import_filter`, the
SDK's `g9_every_refusal_row_is_import_open`; the imported operations in flight marked `imported`; SPECIFIED: the call that follows
one on the user's word, wave 2).
The file holds the label (name, hidden flag), the keystore and the operation state (operations in flight followed only on the user's
word), and the settings without credential references; never `keystore.prev`, the PqChat store, caches, locks, the envelope or
keychain items (owner 2026-11-27 for `keystore.prev`, the PqChat store and credential references). Export needs the name typed and
the profile passphrase, writes a new `0600` file never through a symlink; the seal is AES-256-GCM-SIV in chunks of exactly 1 MiB (the
last 1 byte to 1 MiB) with a last-chunk flag, a header of at most 4 KiB, the items `keystore` and `sdk.state` only, the payload at most
64 MiB (`ProfileExportTooLarge`); import keeps a stronger policy, lowered caps and the default chain profile, every endpoint, `first`
mark, idle-lock and clipboard choice only on the user's confirm of each, and always drops a credential reference; one error
`ProfileImportOpen`, header reasons in the local log, a new profile passphrase and a new PqChat device id.

<a id="CLI-UPR-19"></a>**CLI-UPR-19** — **The sealed store: AES-256-GCM-SIV with a random nonce per seal, pinned length-framed
associated data, HMAC file names, one manifest per part with tombstones, and an anchor over generation, manifests and envelope**
(controller call; BUILT: `vectors/profile/items.json`, `ua-rs` `tests/profile.rs`, `scaas-profile` `tests/store.rs`; the encodings
the spec leaves open as the plan's "Pinned formats"). Associated data: domain, profile-format version, store part, item name, rev; file names HMAC-SHA-256 of
part and name under a key derived from `DEK_p`, no part name handed to another store; each part's manifest a sealed item of the
reserved part `profile`, holding every item's rev and a tombstone per deleted item (a re-created item continuing above it; tombstones
dropped at a re-seal), at most 65,536 entries (`ProfilePartFull`), written under the store write lock with `put_if`; an item below its manifest or at its tombstone is `ProfileRollback`, a listed item
missing `ProfileDamaged`; the anchor compared as the keystore's ([CLI-UPR-28](#CLI-UPR-28)); the anchor a file every client
writes, and also a keychain item where there is one; a covered set put back together with the file is not seen (stated); every derived key separated by its own HKDF label, distinct from PqVault's; every
key and plaintext buffer zeroized at the end of its call; `DEK_p` in a new profile arena of `ua-rs`.

<a id="CLI-UPR-20"></a>**CLI-UPR-20** — **No crash loses a profile: re-seals by a journal written as protected and a new generation,
generations removed only when lower or journaled, root work under a briefly held root lock, deletes by tombstone** (controller call;
BUILT: `scaas-profile` `tests/reseal.rs`, `tests/lifecycle.rs` `g10_crash_at_each_delete_step`, `g4_crash_at_each_migration_step`,
`import_temporary_directory`, `start_cleans_up`; SPECIFIED: the platform wrap's drop, with platform unlock, wave 2). Setting or changing the passphrase writes `profile.envelope.next` (protected, `gen + 1`, a new data key; the platform wrap
dropped), re-seals into `g<N+1>/`, then commits by one rename and writes the anchor; an uncommitted journal is rolled back at the
profile's own open, its generation first; a lower generation is removed only when `g<gen>/` exists and the wrap has opened, else
`ProfileDamaged`; a higher one without a journal is `ProfileDamaged`; nothing is removed before authentication; the root lock covers only short root steps, never a KDF run, a re-seal or a dialog; create and import are journaled with
their row; start removes only the temporary directories and tombstones whose locks it can take and takes no live profile's lock.

<a id="CLI-UPR-21"></a>**CLI-UPR-21** — **KDF bounds per field and per device; `p` is fixed; a cost the device cannot pay is named**
(controller call; BUILT: `ua-rs` `kdf_bound_rows`, `kdf_out_of_memory`; `scaas-profile` `g8_bounds_before_any_kdf`,
`g8_start_during_held_kdf`; the device's maximum `ProfilesConfig.kdf_max_kib`). `m` 64 MiB to 1 GiB on desktop and to 256 MiB on mobile and in a browser, `t` 3 to 10, `p` 4; outside
the general bounds `ProfileFormat`, above this device's maximum `ProfileKdfTooLarge`, both before any KDF runs; out of memory
`ProfileKdfOutOfMemory`, never "wrong passphrase"; a test-only parameter set behind `test-hooks`, refused in a release build.

<a id="CLI-UPR-22"></a>**CLI-UPR-22** — **The profile layer fits the SDK: its own config, its own `Sdk` closed at lock, named store
errors, a sealed size bound and a synchronous store face for pqchat-core** (controller call; BUILT: `ProfilesConfig`, `UserProfile::sdk`, `Sdk::close`, the
`StoreError` codes, `rev_of`'s sealed bound, the synchronous core in `scaas-profile`, the SDK's face, the SDK's `secure_store_face`,
`store_codes_are_the_sdks`, `g11_*`; SPECIFIED: pqchat-core's `PqChatStore` face and `StoreFault`, wave 2; the browser's core
PLANNED; the crate is CLI-UPR-02's Change). `UserProfiles` takes a root
directory, the app's keychain interface, an authenticator and its own heavy limiter; a profile opens and keeps its `Sdk` (a second
call returns it), and its lock calls the new `Sdk::close` (tasks stopped, pools dropped, a closed flag) and leaves a state every later
call meets (`ProfileLocked`); `StoreError` gains `VaultFormat`, `ProfileLocked`, `ProfilePassphraseRequired`, `ProfileRollback`,
`ProfileDamaged`, `ProfileBusy` and `ProfilePartFull` (the last two: owner 2026-11-28, below); `rev_of` reads a sealed item up to the base64 of its plain bound; `keystore.head` stays unsealed; one synchronous
sealed core, the SDK's `SecureStore` over it on `spawn_blocking`, pqchat-core's `PqChatStore` over it directly from a blocking task (a
synchronous face never waits on a future; the one helper is pqchat-core's `Items`, made async over `spawn_blocking`), `StoreFault`
carrying the code; the browser needs an async core of its own (PLANNED); no new crate. **Change (owner 2026-11-28; BUILT, the SDK's
`store_codes_map_by_name`, `store_codes_by_name`, `secure_store_face`):** `ProfileBusy` and `ProfilePartFull` are `StoreError`
codes: the store face passes them through by name (they were `Unavailable`), `vault::io` maps each to the `SdkError` of the same
name, and the wasm store's JS names and the bindings carry them.

<a id="CLI-UPR-23"></a>**CLI-UPR-23** — **Platform unlock on a shared OS account is an accepted risk; each seed and each imported
secret key may carry its own passphrase, never opened by platform unlock** (owner 2026-11-27; SPECIFIED: platform unlock and the SDK's key-lock calls, wave 2; the key-lock
vault label BUILT in `ua-rs` and clientkeys, [CLI-UPR-24](#CLI-UPR-24)). Everyone enrolled on the
OS account opens a profile whose platform unlock is on. The user may lock each secret item with its own passphrase, optional per
item: every seed (its own vault passphrase) and every imported native secret key; that passphrase is only typed, never opened by
platform or biometric unlock.

<a id="CLI-UPR-24"></a>**CLI-UPR-24** — **The key lock: an imported key under its own passphrase, opened only by typing it, untouched
by every seed-wide operation; what a platform unlock leaves readable is stated** (controller call; BUILT in `ua-rs` and clientkeys: the label, the `prf`
refusal, the loops' skips, the backup and link left out, `ua-rs` `tests/wallet_vault.rs` `key_lock_*`,
`keystore_json_key_lock_rows`, clientkeys `test/vault.test.js`, `test/keystore.test.js`; SPECIFIED: the SDK's calls (`import_key`'s
key passphrase, `unlock_key`, `lock_key`, `lock_key_separately`, `KeyLocked`, the skips in `vault/prf.rs` and `vault/seeds.rs`), wave 2). `import_key` takes an
optional key passphrase; such a key is the vault `native-import-locked:<network>:<n>` with a pin envelope only, opened by
`unlock_key` alone, never by the seed's unlock of any kind, a passkey, a platform secret or the profile's unlock; every seed-wide loop
(re-wrap, PRF enable and disable, same-DEK re-seal, retained-PRF open) skips it, and a reader refuses one that carries a `prf`
envelope; the seed's sealed backup and device link leave it out and say so; a signature while it is locked is `KeyLocked`;
`lock_key_separately` moves an existing import under its own passphrase and rewrites `keystore.prev` in the same procedure. A
platform unlock of the profile leaves readable its settings, the keystore's public fields, the operation history, the PqChat and
Matrix stores and PqVault's cache; no seed, imported key, key-locked key, PqVault item or sealed PqChat history.

<a id="CLI-UPR-25"></a>**CLI-UPR-25** — **A re-seal holds the profile's exclusive store write lock for its whole run; no write is
lost** (controller call; BUILT: `scaas-profile` `writer_waits_then_busy`, `writer_through_change_waits_and_lands`; SPECIFIED: the
pqchat-core and pqvault-core writers through their adapters, wave 2). Every writer of every part (the SDK, pqchat-core, pqvault-core) takes the store write lock for a
write; a re-seal takes it from before its journal to its commit, so writers wait (never `StoreConflict`), at most 120 s, then
`ProfileBusy` with nothing written, and otherwise write into the new generation; a pqchat counter never goes backwards.

<a id="CLI-UPR-26"></a>**CLI-UPR-26** — **A settings change that could weaken the profile needs the profile passphrase typed**
(controller call; BUILT: `scaas-profile` `weakening_rule`, `set_settings_needs_the_passphrase_to_weaken`, the SDK's
`settings_weakening_needs_the_passphrase`). Adding an endpoint, a `first` mark or a credential reference, turning the idle lock off or lengthening
it, and turning the clipboard opt-in on need the passphrase, checked against the envelope (a platform unlock does not count); a change
that only strengthens, or picks the default chain profile, does not. **Change (owner 2026-11-28; BUILT, `scaas-profile`
`reverse_of_a_strengthening_weakens`):** the reverse of a strengthening counts as weakening: a chain profile's `strict_majority`
turned off, a lowered cap raised or removed, per chain profile and global.

<a id="CLI-UPR-27"></a>**CLI-UPR-27** — **An import is two calls: a preview of everything in the file, then the import of the user's
choices** (controller call; BUILT: `scaas-profile` `preview_then_import`, `import_temporary_directory`, the SDK's
`g9_export_import_through_sdk`; `ImportChoices` also carries the new profile's KDF parameters). `import_preview(source, export_passphrase)` verifies and opens the whole file, keeps the decrypted
payload in memory (at most 64 MiB; nothing plain on disk) and returns the name, the hidden flag, the counts and every setting with an item
id, kept ones included, each string through the name helper; `import(review, choices, profile_passphrase, name)` writes the new
profile into a temporary directory under its own lock, sealed under its key from the first byte, and commits it under the root lock
by one rename and the row.

<a id="CLI-UPR-28"></a>**CLI-UPR-28** — **The anchor is compared as the keystore's: ahead is a crash and the anchor follows; below, or
another hash at the same revision, is a rollback** (controller call; BUILT: the anchor rows of
`vectors/profile/items.json`, `scaas-profile` `anchor_follows_a_crash_refuses_a_rollback`, `keychain_anchor`, `anchor_rows`;
SPECIFIED: the CLI and the desktop app taking turns on macOS, wave 2). The anchor holds the generation, each part
manifest's revision and hash, and the envelope's revision (a new envelope field) and hash; a value ahead of it (a kill between a write
and the anchor's, or a write by a client that could not reach this anchor) moves the anchor forward; a value below it, or another
hash at the same revision, is `ProfileRollback`. Every client writes the anchor file; a client with a keychain also writes the
keychain item, and both are compared by this rule, so the CLI and the desktop app taking turns raise no event.

**The Matrix store key** (owner 2026-11-27; BUILT: the sealed item, `matrix_store()`, `scaas-profile`
`matrix_store_key_per_profile`; SPECIFIED: one `scaas-matrix` client per profile, closed at lock and switch, wave 2): a sealed item of the profile that owns the Matrix client, not an OS
secret-storage item; `scaas-matrix` holds it until the profile locks: [CLI-UPR-29](../decisions.md#CLI-UPR-29). Each profile has its
own Matrix (logins, session, store, keys, device id), one `scaas-matrix` client per open profile, closed at a switch before the
other opens ([CLI-PQC-20](../decisions.md#CLI-PQC-20)).

**Mobile backup** (owner 2026-11-27; SPECIFIED, nothing built: app code, wave 2): the profile root is excluded from every cloud backup and device-to-device transfer
(Android `getNoBackupFilesDir()` plus a `<cross-platform-transfer>` exclusion; iOS `isExcludedFromBackup` on the root at every start,
Complete protection, keychain items `ThisDeviceOnly`); the export ([CLI-UPR-17](#CLI-UPR-17)) is the only way to move a profile:
[CLI-UPR-30](../decisions.md#CLI-UPR-30).

<a id="CLI-UPR-32"></a>**CLI-UPR-32** — **scaas-app's default build links `ua-rs` only with the profile-crypto features; no signing
code is compiled into it** (owner 2026-11-27; BUILT, plan KH, `bb00216d6`). `scaas-profile` takes `ua-rs` without its defaults and with `user-profile` and
`json` only; `user-profile` is `key-handles` (the arena, `KeyHandle`, `KeyUsage`, `AppKeys` over an arena of its own, AEAD, HKDF,
HMAC, Argon2id, `seal_key`, the OS RNG, `passphrase_bytes`, `Nonce`, `ProfileKeys`, `ExportKey`; [ua-libraries.md](ua-libraries.md)
"Features"), which enables no `wallet`, `pq`, `signers`, `fam-*`, `zether` or `pqz`. What needs a seed or a UA kind (`Wallet::app_keys`,
the app root key, the KEM wrap, the PqChat keys, the tree) stays in `app-core`. `clients/ua-rs/runs/2026-11-27-key-handles-nm.py`
checks it: the `user-profile` rlib defines no signing symbol (`nm`), a `wallet` build does (the control), and `scaas-profile`'s
graph enables no signing feature. Verify-only code (classical kind verification, FROST/MuSig2 key-data and PoP checks)
stays; revisit only for a measured size need (owner 2026-11-27).
