# `scaas-sdk`: the one API apps call

`scaas-sdk` is the one Rust crate through which an app (scaas-app's `scaas` build, `scaas-tui`, the CLI `scaas`, an integrator's
service) reaches every SCaaS feature: seeds and keys, Universal Accounts, tokens and payments, Zether and PQZ, the DEX, governance,
and the generic surface that app cores above it use (`pqchat-core`, `pqvault-core`, a third party's). Every signature comes from `ua-rs` ([CLI-UAL-01](ua-libraries.md#CLI-UAL-01)), every chain read and send goes through
`scaas-rpc` ([CLI-RPC-01](scaas-rpc.md#CLI-RPC-01)), and the bindings are generated from its one API. Status: **SPECIFIED**, partly
built: `vault`, `account` (rows, restore, marks, registration), `wallet` (tokens, balances, native sends, the token and mandate-wallet operations)
and the operations core in `clients/scaas-sdk` on branch `sdk-code` (plan tasks T0–T12 and the T13 fix round of the closing review);
the Dart binding is still the plan's T3 spike, so no binding is BUILT (spec `docs/superpowers/specs/2026-11-17-scaas-sdk.md`, reviewed
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

## 1. Scope

<a id="CLI-SDK-01"></a>**CLI-SDK-01** — **One crate is the only API apps call; it signs through `ua-rs`, talks through `scaas-rpc`,
and holds no cryptography of its own** (owner 2026-11-11, 2026-11-17; SPECIFIED). Modules: `vault` (several seeds), `account` (UA,
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
SPECIFIED). An app names keys by plain records with string ids (a seed id and a kind, account and index; a network and index; a
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
SPECIFIED; vault v2 and container v 2 BUILT, owner 2026-11-19, T13b ruling 3: every vault's AAD binds its seed's id, the index MAC
covers the vault texts, v 1 refused by name, no migration). The container is one item `{format: "scaas.keystore", v: 2, rev, seeds:
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
`{rev, sha256}` detects an older container put back (`KeystoreRollback`, shown, not fatal). The container is a file (or IndexedDB)
through the app's `SecureStore`, whose small keychain items hold only the anchor and the platform unlock secret; it receives vault
ciphertext and public fields only, and a failed write keeps the old item (`VaultIo`). clientkeys writes the container's vectors first
(`smartcontracts/vectors/keystore/`); scaas-app's default build, which has no `ua-rs`, reads and writes the same container.

<a id="CLI-SDK-04"></a>**CLI-SDK-04** — **Seeds are made with 24 words; shorter imports carry a warning; passphrases are the
user's** (owner 2026-11-11; the child index and hidden-set rules controller calls; SPECIFIED). Every seed the SDK makes is 24 words
from 32 bytes of the OS generator inside `ua-rs`, written with `backup: pending` until the three-word check passes. BIP-85 children
(`m/83696968'/39'/0'/24'/i'`, 24 words only) come from the parent's main set at its high-water mark `bip85Next`, kept in the parent's
sealed manifest and never lowered, so a removed child's words never return. An imported phrase of 12 to 24 valid English words is
accepted (NFKD, lower case, single spaces, checksum checked; otherwise `MnemonicInvalid`); 12 to 21 words carries `short_seed`, shown
wherever the seed is listed, with the advice to move funds to a 24-word seed, and every child inherits it. No passphrase is ever
generated: the vault passphrase follows vault v1's rule for a new envelope ([CLI-SGN-21](signers-clientkeys.md#CLI-SGN-21);
`VaultPassphraseWeak`), and the BIP-39 passphrase is never stored and reaches `ua-rs` as entered. A non-empty BIP-39 passphrase opens a
session-only hidden set: nothing about it is written, emitted or logged; its operations still in flight are listed when it is locked.
Removing a seed whose backup is `pending` needs a second confirmation. A seed import may check one word at a time against the BIP-39 list inside `ua-rs` (`word_in_list`, the word as `SecretBytes`); no list leaves the SDK (owner 2026-11-17, "OK, all four points as proposed").

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
biometrics only gate** (SPECIFIED). A seed unlocks with its vault passphrase, its passkey's PRF output or a platform secret (the
HMAC of a Keychain or Android Keystore key under a biometric access policy), the last two through vault v1's `prf` envelope. At unlock
no public key of the unlock credential exists, so user verification is enforced by the authenticator (separate secrets with and
without it) and by the AEAD (a wrong output is `VaultOpen`); an answer without an output is `AuthenticatorRefused` and the passphrase
remains. Signing keys' assertions are checked in full by `ua-rs` ([CLI-UAL-16](ua-libraries.md#CLI-UAL-16)); the app's `Authenticator`
and `SecureStore` are never trusted for policy. The passkey RP ID is the deployment's, never a SCaaS constant
([CLI-APP-14](app.md#CLI-APP-14)). Every change of a sealed record after unlock (the manifest, a backup generation) is re-sealed by
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
beside seeds** (owner 2026-11-11; the index rule a controller call; SPECIFIED). A UA key is `(seed, kind, account, index)`, a native
key `(seed, network, index)` (plus Bitcoin's change chain and Polkadot's path and SS58 prefix once `ua-rs` has them), derived byte for
byte as clientkeys `seed.js` and the vectors fix ([signers-clientkeys §9](signers-clientkeys.md#9-derivation-and-role-keys)). A passkey
(`webauthn-p256`) or a secure-element P-256 key is not derived: it is held by the platform and signs through the app's
`Authenticator`, the SDK building every message and verifying every answer ([CLI-UAL-07](ua-libraries.md#CLI-UAL-07)). An imported
classical key is a leaf of a seed, tagged with its network, never exported. Every attribute a wallet registers (signing kinds, PQZ
key, KEM key, Zether key) uses that wallet's own account index, so no two wallets share one. An EVM account whose code is an EIP-7702
designator carries a delegation mark and a warning; the SDK builds no type-4 transaction, so it cannot offer to clear the delegation
([CLI-SGN-40](signers-clientkeys.md#CLI-SGN-40) rule 3's offer: a recorded exception). A derived UA has no recovery
([CTR-ACC-09](../contracts/accounts.md#CTR-ACC-09)); guardian recovery is `SmartKeyAccount`'s ([CTR-ACC-03](../contracts/accounts.md#CTR-ACC-03)). Registration of a seed's UA key is BUILT (plan T13, `clients/scaas-sdk/src/account/register.rs`, `tests/account_ops.rs`, the `sdk-e2e` PQ registration): the arguments and the PoP by `ua-rs` (`registration_args`, `pop` v2), the calldata by `ua-rs` `registry_call` (the node's registry rows, both ways), each registry write an opaque value quoted and self-relayed by the user's payer, landed by its record (`isRegistered`, `pqzPopOf(…)` non-empty: the proof stored, proven or not (owner 2026-11-19, S2), `kemKeyAt`), the node's split (a registration with a `pqzPop` above the cap: without it, then `storePqzPop`), the KEM commit's fill and repair, an ML-DSA key's expanded-key cache first where the registry caches it (owner 2026-11-19, T1: `cacheExpandedKey(kind, pk, 0)` simulated tells the cache path; each part `expandedKeyOf(ua)` shows missing its own write, landed by its pointer; `tests/account_ops.rs` `mldsa_cache_then_register`, the `sdk-e2e` `e2e_register_mldsa_cached_on_anvil`), the PQZ key attribute (feature `pqz`: the wallet's PQZ key of the same account and index, its `R_REG` proof by `ua-rs` `proveRegister` under the build set's PQZL `proofSystemId`, the PoP over both; without `pqz` `FeatureMissing`); `SmartKeyAccount` and guardian recovery are BUILT (plan T13 part 2; `clients/scaas-sdk/src/account/smart.rs`, `tests/wallet_ops.rs` `smart_execute_decoded_only`, the `sdk-e2e` `smart_account_add_key_self_relay` and `guardian_recovery_via_execute`): the counterfactual address by `ua-rs` (`smart_account_address`), one prepare per entry (`AddKey`, `RemoveKey`, `RotateKey`, `SetGuardian`, `CancelRecovery`, `CancelNonce`, `Execute`), `from` the account, signed as `AccountSig{keyIndex, …}` with the signing key's index given by the caller or read from the account (`nextKeyIndex()`, `keyAt(i)`), a signer the account does not hold `SignerNotAccountKey` (owner 2026-11-19, S3, P2); `Execute` with a decoded call only (`transfer`, `initiateRecovery`), signed under `ua-rs` `Expect::Execute`; the guardian's `initiateRecovery` is its own account's `Execute` (`prepare_initiate_recovery`); `completeRecovery` (anyone, after two days; `prepare_complete_recovery`) and the deploy (`factory.deploy`; `prepare_smart_deploy`) are native sends of the caller's EVM key (spec §8.5), quoted for review and sent by `submit_native_send` (the `sdk-e2e` tests above deploy and recover through them). Passkey and secure-element keys are BUILT (owner 2026-11-19, S1, P1; `clients/scaas-sdk/src/op/external.rs`, `src/op/tests.rs` `passkey_signs_through_the_authenticator`, `se_key_message_mode`): `create_passkey_key` and `create_se_key` store a key row (`AccountRow::Key`) beside the seed and return `KeyRef::Key{seed, id}`; an operation it signs first runs `ua-rs` `sign_scaas` through an `ExternalKey` that only refuses (the policy check passes before the user is asked; a refusal asks no device, owner 2026-11-19, T3: `src/op/tests.rs` `policy_refusal_asks_no_device`), then the SDK computes the passkey's challenge (`webauthn_challenge`) or the secure element's `ua_msg` (`ua_message`, MESSAGE mode) from `scaas_purpose(td)` and the digest, asks the `Authenticator`, and signs through an `ExternalKey` whose answer `ua-rs` verifies (`ExternalSignature` otherwise); a passkey's assertion is built and verified by `webauthn_assertion` first (`AuthenticatorRefused` for another key or UV clear). Such a row registers through `prepare_register` (owner 2026-11-19, T2): a passkey as `registerWebAuthn`, a secure element as `register` (`p256`), the PoP answered by the `Authenticator` and verified by `ua-rs` (`src/op/tests.rs` `key_rows_register`, the `sdk-e2e` `e2e_register_passkey_row_on_anvil`); it holds no KEM or PQZ key and never pays (a payer is a native key, spec §13.3). `msig` is BUILT (plan T13 part 4; `clients/scaas-sdk/src/account/msig.rs`, its tests `msig_minimal_sets` (`ua/nested.json`), `update_msig_current` (`ua/portable.json` `msigUpdates`, `msigUpdated`) and `msig_writes_landed_by_record`, the `sdk-e2e` `e2e_msig_register_accept_transfer_update_on_anvil`): `msig_structure` (members sorted by id, threshold and weights checked) and `MsigStructureArgs::ua`; `msig_state` reads the first structure (`registrationOf`), the current one (`msigOf`), `msigStateOf` and each accepted slot's `memberSigHashOf`, and shows listed, enabled and accepted apart and whether the accepted weight reaches the threshold ([CTR-UA-37](../contracts/accounts.md#CTR-UA-37)); `prepare_msig_register` (`registerMsig`, the `pop` by the named slots or empty, landed by `isRegistered`), `prepare_accept_membership` (landed by the slot's bit in `msigStateOf(ua).accepted`; nothing when set) and `prepare_update_msig` (`ua-rs` `plan_msig_update`, signed by slots of the stored structure, landed when `msigStateOf(ua).version` reaches the update's, [CTR-UA-44](../contracts/accounts.md#CTR-UA-44)) are `RegistryWrite`s; an operation signs as an `msig` through `KeyRef::Msig{ua, slots}`: the entry's check first, then every record read ahead (the `msig`'s and its `msig` members' first and current structures and bits), then `ua-rs` `msig_sig_current` (a set not minimal at either level `UAPoP`, a disabled slot refused); a slot or inner leaf not enabled and accepted on the registry is refused before anything is signed. Not built: a native member's `pop` slot at registration, a native member on a gen-2 registry, and `member_sign` (one member's signature collected from another device). **Sponsored registration** (owner 2026-11-17, "OK, all four points as proposed"): a payment to an unregistered derived UA is `ReceiverUnregistered`; the receiver's app makes its portable registration blob (the `register` arguments with the PoP, which binds no caller, and the KEM record when set), the sender's app checks it (the UA equals the intended receiver and its key data, the kind is enabled on the chain, the PoP verifies locally, the KEM record is present and verifies when `kemPkHash` is set) before anything is sent, submits it paying the gas, adds the KEM key by `setKemKey`, and pays only after the registration lands. BUILT (plan T13b; `clients/scaas-sdk/src/account/sponsor.rs`, clientkeys `registrationBlob` and `smartcontracts/vectors/ua/registration_blobs.json`, `tests/account_ops.rs`, the `sdk-e2e` sponsored registration then pay): `registration_blob` and `prepare_submit_registration` for the single-key entries (`register`, `registerWebAuthn`); a blob is the typed `RegistrationBlob` (`from_json` / `to_json`, the named-field JSON text), at most 768 KiB, the largest registration any parameter set allows with headroom (spec §7.1 gives the derivation), depth 4, so a registration carrying a PQZ key's proof fits one and is split by the sender as §7's; `prepare_submit_registration` takes the payer and returns `RegistryWrite` values; `wallet`'s `prepare_pay` answers `ReceiverUnregistered` for a derived UA the profile's registry does not hold, and for any derived UA on a profile naming no registry (fail closed); a registry write whose payer transaction fails to sign stays submittable (owner 2026-11-19, the four rulings recorded under CLI-SDK-30 in decisions.md).

## 5. Operations

<a id="CLI-SDK-08"></a>**CLI-SDK-08** — **One entry point per signed struct and domain; the user reviews every field before it is
signed; calls are decoded** (explicit parameters, every `mtx*` relayable, no EIP-7702: owner rules; the rest controller calls;
SPECIFIED). Each `(struct, domain kind)` pair of `smartcontracts/vectors/typed/typed_ops.json` (and the transfer on ids, `PayMeta`
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
([CLI-SGN-40](signers-clientkeys.md#CLI-SGN-40); `TxTypeRefused`). The review lists every token or market the operation touches, with its address and its listed or unlisted mark (owner 2026-11-17, "OK, all four points as proposed").

<a id="CLI-SDK-09"></a>**CLI-SDK-09** — **An operation is quoted and confirmed, written ahead, then sent to a gateway that takes it
or relayed by the holder** (SPECIFIED). Paths: a scaas-node gateway, for the entries the gateway takes
([NODE-GW-03](../node/gateway.md#NODE-GW-03): a registered token's `mtx*` entries, the transfer on ids, the DEX routes, and UA
registration once served), with the same body to the gateways chosen ([CLI-RPC-08](scaas-rpc.md#CLI-RPC-08)); or self-relay, for any
entry, as a transaction (type 2 where the chain has a base fee, else 0) from the holder's own native account, which pays the gas, with the
entry's calldata from `ua-rs`. The quote never makes or sends a signature (owner 2026-11-18, ruling 1); its gas comes from the gas table (execution gas: regular plus EIP-8037 state gas,
so the gas limit covers both; owner 2026-11-19): a base row for (entry, domain kind, fresh lane) plus a verify row for the signer kind, each rounded up to 1,000 and each looked up on its
own in the order the chain's measured rows, the module tables and the SCaaS reference table the profile opts in to; without
both, the app's own figure, one total (at most `max_gas`); then a margin; the quote carries the figure and names both
sources on every path (owner 2026-11-19, ruling B, the gas-table rulings and part 3b; BUILT in the SDK, the forge generator PLANNED;
EVM only today, the same principle per family PLANNED; spec §13.3). Without a figure a self-relay is `GasUnquoted`; a gateway
quote reports the gas as unquoted and is not refused, the figure is for the user and the app only, never sent to the gateway,
and the SDK never converts a token fee to or from gas. `submit` signs once, writes the row, then simulates the signed calldata
(owner 2026-11-19, ruling A). Before
`submit` a quote shows the payer, the gas limit, the maximum fee per gas and the maximum cost; the user confirms it; above the profile's
caps it is `FeeAboveCap`, and the caps come from the SDK's configuration, never from the answering endpoint. A gas limit above the
chain's per-transaction cap or the block limit is `GasAboveTxCap` (a PQ registration is split as the node splits it); a payer that is an
EIP-7702 designator is `PayerDelegated`; the payer's address is linked on chain to the subject, and a holder without a native key has no
self-relay path. The job API is server-side only, never in an end-user build ([NODE-ADM-06](../node/admin-auth.md#NODE-ADM-06)). With no
gateway for the entry and no payer: `SubmitPathNone`. **Write ahead:** sign, write the operation with its signed body (public data) to
the SDK's state, then simulate and send (a refused simulation is tracked as `SimRefused`, never an error); from the signature on the send completes whatever happens to the caller; a row written but not sent is sent
at restart, a row sent is never sent again automatically, only by the user's `resend` of the same bytes. **`submit` returns the operation's id once its row is written; every send result after that is an event, never an error of `submit`** (owner 2026-11-17, "OK, all four points as proposed"), so no caller reads a send error as "not paid".

<a id="CLI-SDK-18"></a>**CLI-SDK-18** — **An operation ends only on a chain fact** (follows [CLI-RPC-09](scaas-rpc.md#CLI-RPC-09);
SPECIFIED). Terminal, from a decisive read at the profile's final block only: `Landed` (the executed event of the operation's digest,
`UAMetaTransactionExecuted` on tokens, mandate wallets and the governance router, `MetaTransactionExecuted` on `SmartKeyAccount`; for a
registry write, its record present), `Consumed` (the lane nonce spent without that event), `Expired` (`validUntil` passed with the nonce
unspent), and for an EVM native send `Reverted` (final and reverted; owner 2026-11-18, ruling 4). Everything else is `InFlight` with its detail: queued or sent, the gateways' merged state (never terminal, every node `dead`
included), a self-relay transaction that failed or was replaced (not a failed operation: the signed operation is public and may still
land). While in flight the user may wait, resend the same bytes, or cancel the lane's nonce, which makes the operation `Consumed`.
After a restart every operation resumes from the chain.

## 6. Confidential tokens

<a id="CLI-SDK-10"></a>**CLI-SDK-10** — **The SDK is a reading layer under the seven requirements; a decryption failure never reaches
a source; a verdict comes before a send** (ARCH-POS-13 and ARCH-POS-15 as stated; SPECIFIED). Zether and PQZ operations run their proofs
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
fixed word set (CTR-UA-29) and shuffle every leg; the owner statements sign under `zether-owner`, their relayed forms carrying that
signature as `ownerSig` (owner 2026-11-19, C3). A failed check is a named error (`TokenUncatalogued`, `LegKeyMismatch`, C4; `ReceiverUnregistered` for a recipient with no
registry record, P2). The Zether UA's verify gas of a multi-recipient proof is the gas table's `0x0141` verify row, else the
request's `ua_signer_gas` (P1). The
watch loop reads a watched Zether UA's words on its fixed schedule, nothing decrypted. The anvil e2e (shield → roll-over →
transfer → balances, the token made through the factory, the Zether UAs registered first) is BUILT (gate `sdk-e2e`).

## 7. App cores above the SDK

<a id="CLI-SDK-14"></a>**CLI-SDK-14** — **The SDK has no `chat` module: `pqchat-core` is an app core above the SDK and takes
the app's live Matrix client itself** (owner 2026-11-17: one Matrix stack below both chat paths, then "OK, reverse pqchat-core too"; PLANNED until
`pqchat-core` exists). The app's one Matrix
client (one matrix-rust-sdk stack, one login, one sync loop) lives in the app's one library and is `pqchat-core`'s to use; the
SDK starts no Matrix client, links no Matrix SDK, holds no Matrix store and requires no particular runtime. The attachment and
its release before logout, envelopes kept while a seed is locked, and the runtime shared with the Matrix client are
`pqchat-core`'s rules ([CTR-CHAT-01](../contracts/pqchat.md#CTR-CHAT-01)). `pqchat-core` reaches every signature, KEM operation,
container opening and chain read through the SDK under [CLI-SDK-19](#CLI-SDK-19) and [CLI-SDK-20](#CLI-SDK-20): it signs
`PqChat`'s records through the SDK's named `PqChat` record entries, never through the app signing call, and its ratchet
needs the HMAC, explicit-destroy, storage-root and ephemeral-wrap calls the spec's §12.2 lists, which the `pqchat-core`
spec confirms.

<a id="CLI-SDK-19"></a>**CLI-SDK-19** — **App cores sit above the SDK: they depend on it, it names none of them, and an app links
the SDK and its app cores in one Rust library** (owner 2026-11-17: "agreed to reverse the dependency", then "OK, reverse pqchat-core too"; SPECIFIED).
An app core (`pqchat-core`, `pqvault-core`, a third party's) depends on `scaas-sdk` with the feature `app-core` and on nothing
below it that touches a key or a node; the SDK names no app core and holds no app logic, while the record types of SCaaS
contracts (`PqChat`'s among them, behind the feature `pqchat-records`) are named, typed SDK entries as every SCaaS
contract's are under [CLI-SDK-08](#CLI-SDK-08). scaas-app's one
library is `app-core-rust` (scaas-app's contract section 12), with the features `native-core` (on by default), `scaas`,
`pqchat` and `pqvault` (each implying `scaas`); the SDK defines no aggregating crate.

<a id="CLI-SDK-20"></a>**CLI-SDK-20** — **The `app_core` surface gives an app core account handles, app record signing on
both paths, record verification, key handles, random bytes, reads and relayed submission, under two conditions: secrets
stay below the SDK, and nothing SCaaS is signed blind for an app; if either cannot be met for an app core, the task stops
and the owner decides** (coordinator conditions, controller calls, owner may override; SPECIFIED). (1) Key handles only: a
KEM-unwrapped key, a derived key, an Argon2id output stay in `ua-rs` behind handles of one usage each (`Derive`, `Data`,
`KeyWrap`, refused for any other use) without `Clone`, `Debug` or a byte accessor, scoped to their app core and released
by `destroy` or at the seed's lock; wrap, unwrap, HKDF, HMAC, Argon2id, AEAD and key sealing (under a key-wrap constant no
data seal produces) run in `ua-rs` on them; the only bytes that leave are plaintexts the app core asks to decrypt for the
user; labels stay under the core's own declared prefixes, no two cores' prefixes overlapping. Scoping avoids collisions; it
does not isolate: an app holding the user's unlocked seed set acts for that UA in every app namespace, so only reviewed app
cores are linked. (2) The app signing call takes typed data, never a digest, and signs only a portable record under
`appPurpose(appId)` whose domain is exactly `name, version, salt` with `salt = appId`, or a chain-bound record under the
app's own purpose with the profile's `chainId` and the app's `verifyingContract`; it refuses by name every `UAKinds`
purpose constant (the guard on the chain-bound path) and every domain of a SCaaS contract or of the registry (by name, by
address, by chain), each refusal tested with a positive control and a mutant. Reads of ciphertexts the app core decrypts are decryption reads under
[CLI-SDK-10](#CLI-SDK-10); writes are operations under [CLI-SDK-08](#CLI-SDK-08). Design: spec §12.

## 8. Runtime, events, errors

<a id="CLI-SDK-11"></a>**CLI-SDK-11** — **The SDK is async on tokio and reports by subscription** (SPECIFIED). The API is `async`;
the SDK adopts the app's tokio runtime or starts its own for a binding, and every exported async call runs its body on that runtime, so a
generator that polls from a foreign executor never runs I/O outside a reactor. Scrypt, Argon2id, proofs and slow key generation run off
the async workers, bounded (one at a time by default). A dropped call means: a read is abandoned, a store write completes or leaves the
old item, a submission completes to its written state. Events (seed locked and unlocked, keystore changes, mismatches and rollbacks,
abandoned hidden-set operations, operation states, balances, history items, dropped endpoints) go to each subscriber's bounded
queue; a slow subscriber gets `Lagged` with the count missed and re-reads state, and the SDK never waits for it. Watching is bounded per
poll. No event callback crosses a binding: the only interfaces an app implements are `SecureStore` and `Authenticator`, whose errors
include an unexpected-callback case, so a host exception never panics the SDK. A change of the SDK's state by another process is the event `StateChanged` (found by a cheap read of the state's revision on each poll, or at once where the store reports changes) (owner 2026-11-17, "OK, all four points as proposed").
History and watching are BUILT (plan T14; `clients/scaas-sdk/src/wallet/history.rs`, `src/watch.rs`, `tests/history.rs`): history
pages backwards from the profile's final block, one log window per request with both bounds, newest first, the account's operations
on the first page; `watch` takes only an account a keystore row names (a hidden set's account is never written, so no event or
cursor names it), reads at most `max_watch` (account, chain, token) triples per poll in turn, and keeps each triple's cursor in the
SDK's state; `StateChanged` and `state_rev` are built as stated.

<a id="CLI-SDK-13"></a>**CLI-SDK-13** — **Errors are named, stable codes; the layers below keep their names** (SPECIFIED). An error
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
`ReceiverUnregistered`, `RegistrationUaMismatch`, `RegistrationKindDisabled`, `RegistrationPopInvalid`, `RegistrationKemMissing`. A
warning (`short_seed`, `imported_key`) comes beside a success, never as an error.

## 9. Bindings

<a id="CLI-SDK-12"></a>**CLI-SDK-12** — **Bindings are generated from the SDK's one API; an app links one Rust library** (owner
2026-11-11; generators and the C point controller calls; SPECIFIED). The public Rust API is the binding surface: module objects
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
whose API version or feature bits differ from what it was generated against (`AbiMismatch`). `ua-rs`'s existing wrappers stay as they
are for clients that use the signer without the SDK ([the wallet surface](ua-libraries.md#the-wallet-surface-of-ua-rs-built)).

## 10. Chain profiles and native chains

<a id="CLI-SDK-15"></a>**CLI-SDK-15** — **Chain profiles are the app's pinned data; the chain is asked, never assumed** (SPECIFIED).
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
(owner 2026-11-17; SPECIFIED). EVM native sends (`evm`, `hedera_ecdsa`) are transactions of type 0, 1 or 2 built and signed in `ua-rs`
(3 and 4 refused; 0 by default where the chain has no base fee; owner 2026-11-18, ruling 3), quoted and capped, a delegated sender's
quote carrying the delegation mark (ruling 5); no EVM key signs a raw digest. For another chain an app's own encoder builds the transaction and the SDK signs it through
one entry that exists only behind its own feature and marker and is absent from the default generated surface. The entry, not
`ua-rs`'s existing calls, enforces the restrictions (`ua-rs` keeps its native-key digest signing for other uses): native keys only,
never a UA key or a SCaaS kind, never an EVM-address key; NEAR, Sui, Stellar and Hedera Ed25519 through `ua-rs`'s envelope-building
calls (the transaction bytes in, the chain's envelope built and hashed in `ua-rs`), never as a bare digest; GRAM, whose native key is its
SCaaS identity and whose signed value has its SCaaS payload's form, kept off the entry; a refused off-chain envelope (Solana OCMS, Aptos `APTOS\n`) refused by the SDK itself
(and by `ua-rs`), with no first-byte rule (a `0x05` / `0x19 0x01` refusal was withdrawn: it refused real Polkadot and Solana
transactions and protected no payload); a bare 32-byte digest only for the Bitcoin sighash. All refusals are `RawDigestRefused`. The preimage is built in the app's
process from the transaction the user reviewed, decoded. **Residual:** a Bitcoin sighash is opaque to
`ua-rs`, and a Bitcoin key's secret also controls an unfunded EVM address; the defence is the caller's obligation. The Bitcoin, NEAR and
Polkadot networks join when `ua-rs` has them (PLANNED).

## 11. The CLI

<a id="CLI-SDK-17"></a>**CLI-SDK-17** — **The CLI `scaas` is a thin client of the SDK** (PLANNED). One subcommand per SDK call, named
flags, JSON or a table; it shows the review and the quote and asks before submitting. Passphrases, words and keys come from the
terminal without echo or from a file descriptor, never from the command line or the environment; nothing secret is printed except a
new seed's one reveal. It shares its data directory with the TUI and the app under the keystore's lock, holds no logic of its own and
serves as the reference client of the SDK's end-to-end tests. Its profiles are pinned (owner 2026-11-17, "OK, all four points as proposed"): compiled in or digest-pinned in a release build; a profile file only in a development build that says so on every run; an overlay may add a credential by file and lower caps, never change a `chain_uid`, a contract or an RPC list. It shares its call and action names with `scaas-tui`; neither calls the other.

The interactive terminal front-end over the SDK is `scaas-tui`, a separate program with its own rules
([CLI-TUI-01](scaas-tui.md#CLI-TUI-01)): a session that follows events and reviews every operation on screen, where the CLI runs one
call per command.
