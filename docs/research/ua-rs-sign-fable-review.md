> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

Fable counter-review of the `ua-rs-sign` spec draft, 2026-11-05 (kept verbatim; the spec's review-response section says what was applied, planned, noted or rejected).

# Counter-review of `docs/superpowers/specs/2026-11-05-ua-rs-sign.md` (branch `ua-rs-sign`, `d6de3b7a`)

Reviewer: Claude Fable 5.1, 2026-11-05. Scratch note, not committed. UNAUDITED, like everything it reviews.

Read: the spec; `AGENTS.md`; `clients/ua-rs` (`Cargo.toml`, `lib.rs`, `pq.rs`, `verify.rs`, `ua8.rs`, `keydata.rs`,
`musig2.rs`); `clients/clientkeys/src/{seed,pq,vault,backup,zether,zether-keys,seed-signer}.js` and `test/vault.test.js`;
`clients/ua-c/include/scaas_ua.h`, `src/lib.rs`; `docs/clients/signers-clientkeys.md` §7, §9; `docs/contracts/accounts.md`
CTR-UA-32; `smartcontracts/vectors/ua/*.json` (shapes); `smartcontracts/evm/src/common/MetaTxLib.sol` (`canon`);
`pqz-core/ffi` (`Cargo.toml` features, `lib.rs`), `pqz-core/rust-toolchain.toml`; `clients/zether-prover/src/{keys,api}.rs`;
UA-7 spec §3, §6, §12 on `ua7-research`; the pinned crates in the local registry (`ml-kem` 0.3.4, `ml-dsa` 0.1.1,
`slh-dsa` 0.2.0-rc.5, `pqcrypto-falcon` 0.4.1, `bip39` 2.2.2, `x25519-dalek` 2.0.1, `scrypt` 0.11.0).

Owner rulings (§1) are taken as settled; where a ruling creates a risk, the risk is named, not the ruling reopened.

## Counts

| Severity | Count |
|---|---|
| P0 (wrong / unsafe) | 3 |
| P1 (must add before build) | 15 |
| P2 (should add) | 27 |
| P3 (nice) | 7 |

Items F-01 … F-52 (52 in all). "Missing entirely" items are F-42 onward; the top ten are listed at the end.

## A. Cryptographic soundness

**F-01 · P0 · §9.1, §6.2, §6.3, §3** — Every randomized call takes `rng: &mut impl CryptoRngCore` from the caller in the
release API. The spec's own safety argument for `nonce = 0^96` ("every key encrypts once") rests on fresh `m` and `e` per
seal. A caller (or a binding) that passes a seeded, cloned or re-used RNG produces the same `ss`, the same AES key and the
same zero nonce for two plaintexts: full keystream reuse and tag forgery on AES-GCM. The same parameter also makes
BIP-340 `aux`, ML-DSA `rnd`, Falcon and PQZ `rnd32` caller-controlled. On top, the pins span three `rand_core`
generations (`frost-core` 3.0 → 0.6; `ml-dsa` 0.1.1 → 0.9 `TryCryptoRng`; `ml-kem` 0.3.4 → 0.10), so one trait bound cannot
even be written. **Fix:** no RNG parameter in any release signature; `OsRng` (per crate generation) inside `ua-rs`; the
deterministic entry points (`aux`, `m`, `e`, `rnd`) exist only under feature `vectors`, as §9.1 already says for them.
Mutant: "release build exposes an RNG parameter" must not compile.

**F-02 · P0 · §8** — The vault opens with the scrypt parameters read from the untrusted JSON (`N, r, p`) and the spec says
"old ones open". CLI-SGN-21 rules the opposite: on open, a pin envelope outside `N ∈ {2^15, 2^16, 2^17}, r = 8, p = 1` is
**refused** (`dekFrom` bounds check). Honouring stored parameters unbounded is a memory bomb (`N = 2^30` → 128 GiB) that
kills the app, and on this machine the terminal (`systemd-oomd`). The mutant list only has "stored parameters ignored",
the opposite failure. **Fix:** bounds check as CLI-SGN-21, `N` a power of two (scrypt 0.11 takes `log_n: u8`), named
error `VaultParams`; mutant "bounds check removed"; a `vault.json` row with `N = 2^31`, with `r = 16`, with `N = 3`.

**F-03 · P0 · §14 Q7, §3 (`0x0104`, `0x0105`)** — The nonce rule is written `k = hashToScalar(keccak256("…" ‖ sk ‖ ua_msg ‖
aux))`: a 256-bit value into a 254-bit (bn254 `r`) or 255-bit (BLS12-381 `r`) field. If `hashToScalar` is read as "mod r"
(as `fe()` / `from_be_bytes_mod_order` elsewhere in `verify.rs` and `keydata.rs`), the nonce has about 2.4 bits (bn254) and
1.1 bits (BLS) of bias: Bleichenbacher / lattice key recovery from a few thousand signatures. `verify.rs:199` defines the
challenge map as `(keccak(s ‖ 0x02) · 2^256 + keccak(s ‖ 0x03)) mod r`, 512 bits, which is fine. The spec must say so
explicitly for the nonce, and the signer must use the same function. Also: serialise `sk` fixed-width 32 B BE; include
the public key `Y` in the hash (BIP-340 does, against related-key and fault attacks); the mutant "nonce reduced from 256
bits" must be killed by a statistical test on the vector signer (not by the vectors, which cannot see bias).

**F-04 · P1 · §6.2 / §6.3** — Decapsulation has no stated checks. Encaps checks `ek` and refuses `ss_X == 0`; `decaps` must
mirror what it can: `mlkem_ct` exactly 1,568 B, `x25519_eph` 32 B, the all-zero / small-order `ss_X` refusal
(`SharedSecret::was_contributory`), and FIPS 203 implicit rejection kept (never a distinguishable error on a bad `ct`).
`open` then fails only at the AEAD tag. **Fix:** write the decaps check list; `kem.json` decaps refusal rows (short `ct`,
`ct` flipped byte → different `ss`, small-order `E`); mutant "decaps length check removed".

**F-05 · P1 · §6.1** — The KEM key is bound to one `ua`. For an **`msig` UA** (a structure, several seeds) no member's
seed yields "the" KEM key: each member derives a different one, and the registry stores one per version. The spec is
silent. **Fix:** state the rule: an `msig` UA's KEM key is a random key (`kem:<ua>:<version>` in the vault, Q2's opt-out)
held by whoever operates the structure, or a designated member's seed-derived key named in the spec; either way it rides
in the backup and link payloads (F-31).

**F-06 · P2 · §6.1** — The FIPS 203 §7.3 decapsulation-key check "at generation" is redundant for a key derived by
`KeyGen_internal` from the seed (it always passes) and runs on every `kem_key()` call if keys are re-derived per call
(F-27). Keep it (cheap, P14 says so) but say it is a self-test, and run it once per process per `(ua, version)`.

**F-07 · P2 · §6.3** — Seal authenticates nothing about the sender: anyone can seal to an organisation's recovery UA or to
a device's ephemeral key. Consumers will assume otherwise. **Fix:** one sentence in §6.3 and in the C header; for
`scaas/backup/v1` and `scaas/link/v1` the Sealed is signed by a UA key of the sender (`UASig` over `keccak256` of the
wire form) or the protocol binds the short code (F-31).

**F-08 · P2 · §6.3** — Unspecified: `aad` of `scaas/backup/v1` (what the backup is bound to), empty plaintext allowed or
not, a maximum plaintext size (`ct_len` over the ABI), no length hiding (padding is the caller's). Write the four rules.

**F-09 · P1 · §3, §11** — "Byte-equal" for ECDSA (`evm-eoa`, `p256`, `secp256k1`) holds only if both sides run RFC 6979
without extra entropy. clientkeys is on `@noble/curves` 2.4.0; `seed.js` calls `secp256k1.sign(digest, sk, {prehash:false,
format:'recovered'})` with no `extraEntropy` option, and the UA kinds `0x0101` / `0x0108` have no signer yet (T1). **Fix:**
the generator pins `extraEntropy: false` on every deterministic row and says so in the file's `note`; `sign.json` carries
the RFC 6979 A.2.5 (secp256k1) and A.2.5/P-256 published vectors so the Rust and the JS signer are each checked against
the RFC, not only against each other (`signatures.json` already does this for ed25519 RFC 8032 and BIP-340; RFC 6979 is
missing).

**F-10 · P1 · §11** — External known answers for the **signer** side are missing for ML-KEM. `pq_external.json` holds ACVP
ML-DSA, ACVP SLH-DSA and Falcon KATs (verifier side); nothing for ML-KEM-1024 and X25519. **Fix:** add ACVP ML-KEM-1024
`keyGen` (d, z → ek, dk), `encapDecap` (m → c, K; decaps of the given `c`), and RFC 7748 §6.1 X25519 vectors, read by
`ua-rs` and by clientkeys; use the existing ACVP ML-DSA `sigGen` deterministic cases and SLH-DSA `sigGen` cases for the
signers too, not only the verifiers.

**F-11 · P1 · §8, §13** — Zeroize claims per crate, checked against the registry: `pqcrypto-falcon` 0.4.1 `SecretKey` has no
`zeroize` at all (confirmed: no `zeroize` in its `Cargo.toml`); `ml-dsa`, `ml-kem`, `slh-dsa` zeroize only with their
`zeroize` feature on (off in `ua-rs`'s `pq` feature today); `bip39::Mnemonic` holds the words as a `String`. **Fix:** enable
the features; wrap Falcon's key bytes in `Zeroizing<Vec<u8>>` and re-create the crate type per call; never keep a
`Mnemonic` beyond `from_mnemonic`; §8 lists the residuals per crate (today it names only arkworks and `frost-core`), plus
PQClean Falcon's and `scrypt`'s large unzeroized work buffers.

**F-12 · P2 · §12** — "Written constant time" is asserted for `ml-dsa` and `ml-kem`; their READMEs (0.1.1, 0.3.4) make no
such claim (grep: none). `aes-gcm`'s `ghash`/`polyval` soft path and `scrypt` are not relevant to secrets in the same
way but should be listed. **Fix:** quote each crate's own statement in T0; where none exists, write "no claim by the
crate" in the residuals, and keep `subtle` for comparisons.

**F-13 · P2 · §3 (`0x0133`), Q10** — `slh-dsa` RC pin is fine for agreement, but FIPS 205 deterministic signing takes
`opt_rand = PK.seed`; the crate's `slh_sign_internal(msg, opt_rand: Option<&[u8]>)` takes `None` for that. Write which
call and which `M'` (`0x00 ‖ 0x00 ‖ pq_msg`, as `pq.rs` verifies) the signer uses, so a later crate release that changes the
default (`sign` hedged) is caught by the vector, not by the chain.

**F-14 · P2 · §3 (`0x0130`…)** — Hedged ML-DSA in production is right; add that the `rnd` is 32 B from the OS RNG and that
`sign_internal` is the call (so `ctx` stays empty by construction and the `M' = 0x00 ‖ 0x00 ‖ pq_msg` form is shared with
`pq.rs`); mutant "ctx non-empty" exists, add "rnd fixed in release" (killed by two signatures differing).

**F-15 · P2 · §4** — BIP-39 normalisation: `bip39` 2.2.2 does NFKD only with its `unicode-normalization` feature (pulled by
`alloc`); without it a non-ASCII passphrase or a Japanese/Spanish-looking input diverges from `@scure/bip39`. State the
feature and add a `keys.json` row with a non-ASCII BIP-39 passphrase.

**F-16 · P2 · §3 table** — `kind_tag` in the HKDF `info` is the **ASCII tag string** (`utf8("scaas.ua.mldsa65.v1")`, `pq.js`
`pqSeed`), not `TAG(kind) = keccak256(tag)`. The table uses the symbol `kind_tag` right after using `TAG(kind)` for the
hash; a reader builds the wrong `info`. Write `utf8(tag)`. Same in §10.2 (`"scaas.ua.pqz-mlwe.v1"`).

**F-17 · P2 · §4** — `account` and `index`: BIP-32 / SLIP-10 hardened indices are `< 2^31`, the HKDF kinds accept any
`u32`. Rule once: `account, index < 2^31` for every kind, refused otherwise (`Argument`); a `keys.json` refusal row.

## B. Consistency with clientkeys and the vectors

**F-18 · P1 · §8, §9.1** — The vault payload under label `seed` in clientkeys is the **32-byte entropy**
(`SeedBackup.take()` → `createVault(entropy, {label:'seed'})`), not the 64-byte seed the spec stores; the BIP-39 passphrase
is not in the vault. `open_vault → Wallet` as written cannot be byte-compatible, and `vault.json` "byte-equal plaintext"
would compare different objects. **Fix:** payload = entropy; define how a BIP-39 passphrase is handled (asked at every
unlock, or stored in a named field of the `data` plaintext as a v1-compatible extension — pick one, write it in
CLI-SGN-02); `Wallet` derives the seed on open.

**F-19 · P1 · §8** — Passphrase normalisation: `vault.js` runs `String(pin).normalize('NFKC')` before scrypt. Not in the
spec; without it a JS-sealed vault with a non-ASCII passphrase never opens in Rust (`unicode-normalization` NFKC). Add
the rule and a `vault.json` row with a composed/decomposed passphrase pair.

**F-20 · P2 · §8** — clientkeys has **vault v2** (CLI-SGN-17: an outer AES-GCM layer under a browser device key around the
v1 JSON). `ua-rs` must recognise `v: 2` and refuse it with a named error (`VaultVersion`, "open in the browser and export
v1"), not fail as "wrong passphrase". Also missing from §9.1: `rewrap_pin`, `needs_rewrap`, `enable_prf` (keep the DEK,
replace one envelope), and the new-passphrase policy (≥ 8 chars, not digits only) — all BUILT in clientkeys.

**F-21 · P2 · §8 "the hook"** — The `prf` envelope fields `credentialId`, `salt` are passkey-specific. For an Android
Keystore / iOS Keychain HMAC secret, define what goes there (a key alias as `credentialId`, the HMAC input as `salt`) or
the "no new format" claim is a format with undefined fields.

**F-22 · P1 · §5.3, §11** — `canon` is not a property of the hasher; it is a per-struct step on every struct with a `mode`
field: `MetaTxLib.canon` exists for `MetaTransaction` **and** `MetaTransfer` (and the UA forms carry the same bits). The
spec names only `MetaTransaction` / `UAMetaTransaction`. **Fix:** enumerate the structs from the Solidity, apply canon in
the typed record builder (keyed on struct name and `MODE_RESTRICT_*`), keep the EIP-712 hasher pure, and give **each**
struct its non-zero-unbound row in `sign.json`.

**F-23 · P2 · §5.3** — The generic hasher needs its JSON value encoding written: `uint`/`int` as decimal strings and
`0x` hex, two's complement for `int`, `bytes`/`string` keccak of the content, `bytesN` exact length, `address` 20 B
left-padded, `bool`, fixed and dynamic arrays (`T[]`, `T[k]`), nested structs, `EIP712Domain` type built from the fields
**present** in `domain` in EIP-712 order, unknown or missing fields refused. Vectors: `typed_ops.json` and `portable.json`
already; add rows for arrays and a negative `int`.

**F-24 · P2 · §3, §11** — Randomized rows are "verify-only" with the Rust verifier. The Rust signer and verifier share one
crate, so a shared bug passes. **Fix:** the cross-check runs both ways: JS verifies the Rust signatures (a fixture the Rust
test writes to a git-ignored file read by `npm test`, or a committed small set), Rust verifies the JS ones; for Falcon,
ML-DSA hedged, SLH-DSA randomized, BIP-340 with OS `aux`.

**F-25 · P3 · §3 row `0x0001`/`0x0003`** — `hedera-native` lumps ECDSA and ed25519 (HIP-632 raw ed25519 over the EIP-712
digest, `seed.js` `sign`). Split the row.

## C. API design, ABI, misuse

**F-26 · P1 · §5.1, §9** — `sign_typed(td)` signs any typed data under any domain: a hostile app page (or a bug in the
app) obtains a `Permit`, a `MetaTransfer` to a drain, or a router order, with no check. clientkeys keeps the signing
policy (`checkPayment`, `checkOp`, `checkCall`, …, signers-clientkeys §3, §5) in front of `signTyped`; the spec moves the
signer to Rust and leaves the policy nowhere. **Fix:** either an allow-list of `(domain name, primaryType)` pairs for the
SCaaS structs (from the vectors) with an explicit `AllowAnyTypedData` marker (its own ABI name) for the general-EVM
wallet, or the `check*` ports in `ua-rs` as the gate before `sign_typed`. State it.

**F-27 · P1 · §2, §9** — `scaas-wallet` is "general EVM via alloy": it needs **transaction** signing. The only path in the
spec is `sign_digest(raw, AllowRawDigest)` over a tx hash, which is exactly the class CLI-SGN-40 fences off (a type-4
EIP-7702 tx or an authorization is a raw digest too). **Fix:** `sign_transaction(tx: TypedTx)` with named fields
(EIP-2718 types 0, 1, 2, 3 only; type 4 refused by construction), RLP built inside `ua-rs` (alloy types are fine as the
input), `ChainId` explicit; the raw-digest path stays for Merkle roots and `check*` digests.

**F-28 · P1 · §3 (`0x0100`), §9** — WebAuthn is "the authenticator signs; `ua-rs` builds the challenge and the assertion
encoding", but neither call is in §9.1/§9.2. Add `webauthn_challenge(kind, purpose, digest) -> ua_msg` and
`webauthn_assertion(authData, clientDataJSON, r, s) -> key data / signature bytes` with the clientDataJSON challenge
check and the low-s normalisation `ua-verify.js` applies; vectors: the existing webauthn rows.

**F-29 · P1 · §9.2, §12** — Kind availability differs per build (Falcon refused on wasm32 without clang; `zether`/`pqz`
off with `--no-default-features`). The ABI has no way to tell: a binding gets `KIND_UNKNOWN` or `INTERNAL`. **Fix:** status
`SCAAS_UA_ERR_KIND_UNAVAILABLE` (distinct from unknown), `scaas_ua_features() -> uint64_t` bitmask (`wallet`, `pq`,
`falcon`, `zether`, `pqz`, `pqz-set-*`), and every binding checks `abi_version` and `features` at load.

**F-30 · P2 · §9.2** — `catch_unwind` is a no-op with `panic = "abort"` (common in mobile staticlibs) and on
`wasm32-unknown-unknown` (no unwinding). The rule "every export in `catch_unwind`" needs its companion: no panic path in
`ua-rs` on any untrusted input (every decode bounded, no `unwrap`, `clippy::panic`/`unwrap_used` denied), and a
`profile.release` without `panic = "abort"` for the shared library.

**F-31 · P2 · §9.2** — The header's own rules change and the spec does not say so: "no allocation crosses the ABI and
nothing is freed" and "pure computation over immutable static tables" become false with handles. Write the new rules:
`_free(NULL)` is a no-op; a handle is not reference-counted; use after free is UB; a handle may be used from any thread
concurrently (so `Wallet` holds no interior mutability without a lock); the last-error detail stays per thread.

**F-32 · P2 · §9.2** — Nullability and secret ownership over the C boundary: `passphrase` may be NULL when `prf32` is given
and the reverse; which envelope wins when both are given (clientkeys: PRF first); the mnemonic, passphrase, `ss32`,
decrypted `pt` and the exported PQZ leaf live in **caller** memory that Rust cannot wipe — the header says the caller
zeroizes them (`explicit_bzero` / `SecureZeroMemory`), and each binding does (Python `bytearray`, Go `[]byte`, C#
`CryptographicOperations.ZeroMemory`).

**F-33 · P2 · §9.2** — `scaas_ua_sign_typed(w, network, index, …)` lacks `coin_type` (the Rust API has it, Pi Network
needs it). Mirror the Rust signature; `0` or a flag for "default".

**F-34 · P2 · §8** — `export_pqz_leaf` returns a 32-byte secret in the clear, the only such call. Give it the raw-digest
treatment: its own ABI name ending `_raw`, a marker type in Rust, a header warning, and a log-free path.

**F-35 · P2 · §10.1** — Refusing `x`, `mnemonic`, `seed` **keys in the JSON input** is a denylist over an attacker-shaped
document (nested objects, other spellings, future fields). Invert it: the facade never parses a `key` object; it builds
the zether-prover command struct itself from `{coin, account}` and the handle, and passes typed values, so there is no
slot a secret could arrive in.

**F-36 · P3 · §9.1** — Per-call re-derivation (`scaas_ua_sign_ua(w, kind, account, index, …)`) costs a Falcon-1024 or
SLH-DSA keygen per signature (tens to hundreds of ms on a phone). Fine for v1; note a bounded per-`Wallet` key cache
(`Mutex<LruCache>`, zeroized on evict) as the upgrade path.

**F-37 · P3 · §9.1** — `Wallet::generate() -> (Wallet, SeedBackup)` holds the secret twice; `SeedBackup.take()` semantics
("this object forgets it") must be stated for the Rust pair. Also name the two passphrases apart in the API (`bip39_passphrase`
vs `vault_passphrase`): the same word for both will be misused.

## D. Facades

**F-38 · P2 · §10.2, §12** — Rust 1.97.1 by default (consequence of ruling 5): every binding's default build, every CI job
and the `ua-c` consumers move to 1.97.1; `ua-rs` cannot honestly keep `rust-version = 1.90` as a crate field when its
default features need 1.97.1 (`cargo` checks MSRV against the resolved graph). Write `rust-version = "1.97.1"` for the
crate and say 1.90 is "what a `--no-default-features` build happens to need", or split the facades into a sibling crate
`scaas-ua-facade` that depends on `scaas-ua`.

**F-39 · P2 · §10.1** — Zether balance reading needs the **balance cache** clientkeys has (`sealBalanceCache`,
`openBalanceCache`, `cacheAfterDebit`, `cacheAfterRollOver`, zether-limits §5): a BSGS decrypt from scratch is seconds per
account. The facade table omits it. Add the cache box (AES-GCM, device-bound bits) as a facade call with the same AAD
labels as clientkeys, or state that `scaas-wallet` owns it.

**F-40 · P2 · §10.2** — What a PQZ client also needs and the table omits: the current balance ciphertext → plaintext path
(`dec` with the `dec_win` window and a cache like F-39), the `R_REG` **witness** shape, and the random `rnd32` rule's
mutant ("rnd32 fixed" killed by two differing proofs). Also note the size consequence of `pqzh` on by default for every set
but `n2816` (Ligero prover in every mobile build) and gate it in T9 as a ratchet.

**F-41 · P3 · §10, §12** — wasm32: `getrandom` needs its `js`/`wasm_js` feature for `OsRng` on `wasm32-unknown-unknown`
across the three `rand_core` generations (0.6 → `getrandom` 0.2 `js`; 0.9/0.10 → `getrandom` 0.3 `wasm_js` + rustflags).
T0 item.

## E. Missing entirely

**F-42 · P1 · (new §) Key inventory and discovery.** The vault stores a seed; nothing records which `(kind, account,
index)`, which native networks, which KEM versions and which random (non-derived) keys a user actually uses. After a
restore from the phrase the wallet must scan 25 kinds × accounts × indices against every registry through the node, or the
user loses accounts. **Fix:** a `Manifest` (named fields: entries of `{kind, account, index, ua, label, created}`,
native `{network, coinType, index}`, KEM `{ua, version, derived|random}`, FROST shares, random KEM keys) kept in the vault
as its own label, included in `backup_seal` and `scaas/link/v1`; a `discover(kind, account, gap)` helper with a gap limit
(BIP-44 style) over a registry reader the caller supplies. Say which lives in `ua-rs` (the manifest and its envelope) and
which in `scaas-wallet` (the chain scan).

**F-43 · P1 · §6.3, §8 Device linking and the backup container.** `scaas/link/v1` seals "the UA's secrets to the new
device's ephemeral key", but the API has no `KemKeyPair::generate()` (ephemeral, not from a seed — the new device has
none), the `Sealed` wire form carries no recipient identifier, and the backup payload is undefined. A device cannot know
which `(ua, version)` or which ephemeral key opens a blob. **Fix:** `KemKeyPair::generate_ephemeral()`; a self-describing
container (JSON, base64url, named fields like the vault): `{v, purpose, recipient: {ua, version} | {kemPkHash}, aad,
sealed: {mlkemCt, x25519Eph, ciphertext}}`; `BackupPayload {v, entropy, bip39PassphraseHint?, vaults: [...], manifest}`;
the link protocol's short code enters the `aad` (F-07) so a swapped QR fails.

**F-44 · P1 · (new §) Untrusted-input bounds and fuzzing.** The node rule applies here too: bound every decode by length
**and depth**. Typed-data JSON with recursive or cyclic `types` recurses without end; vault JSON, `Sealed`, `kemPk`,
mnemonic text, zether / PQZ command JSON all come from outside. **Fix:** depth ≤ 8 and size caps per decoder; `cargo fuzz`
targets for each (typed data, vault, Sealed, kemPk, mnemonic, command JSON) in `clients/ua-rs/fuzz/`, a short run in the
T10 gate as `pqz-core` does.

**F-45 · P2 · (new §) External signers: hardware wallets, Secure Enclave, Android Keystore, Ledger.** The spec has one
external signer (WebAuthn) and no abstraction. A P-256 key in the iOS Secure Enclave / Android StrongBox is a valid
`p256` (`0x0101`) UA key that never enters `ua-rs`; a Ledger signs EIP-712 for `evm-eoa`. **Fix:** an `ExternalKey {kind,
key_data}` that only builds `ua_msg` / the EIP-712 digest and **verifies** the returned signature (the verifier exists),
so bindings have one path for "the key is elsewhere"; the enclave's key is also the natural PRF-like unlock secret for
the vault (F-21).

**F-46 · P2 · (new §) Memory protection beyond zeroize.** No `mlock` / `VirtualLock` on the seed and keys, no
`madvise(MADV_DONTDUMP)` / `PR_SET_DUMPABLE(0)`, no rule for iOS/Android backgrounding (the OS snapshots the heap), no
`Wallet::lock()` that drops the seed while keeping the public manifest. **Fix:** best-effort `mlock` on the `Wallet`
allocation (a feature, off on wasm32), dump exclusion on Linux, a `lock()`/`unlock()` pair, and a stated residual for
browsers.

**F-47 · P2 · (new §) Error and log hygiene.** `scaas_ua_last_error` and `Display` of errors must never carry an input:
the BIP-39 error must not echo the unknown word, the vault error not the label's plaintext, the typed-data error not the
message values. No `log`/`tracing` in `ua-rs`; bindings never print arguments on error paths. One test: every error string
of a run over secret inputs contains no substring of the inputs.

**F-48 · P2 · (new §) Supply chain.** Beyond the `=` pins: `cargo deny` (advisories, licences, duplicate versions —
replaces the T0 `cargo tree -d` spike as a permanent gate), `cargo audit` in CI, `Cargo.lock` committed for `ua-c` and every
binding's Rust side, `--locked` in every build script, `cargo vet` or at least a recorded review note for the new crates
(`ml-kem`, `x25519-dalek`, `aes-gcm-siv`, `scrypt`, `bip39`, `bip32`).

**F-49 · P2 · (new §) Key import.** clientkeys tags an imported key with its family (CLI-SGN-11). `ua-rs` has no import of
a raw native key (an existing EOA, a Stellar `S…` seed, a Solana keypair, a Hedera ed25519 key). Users arrive with keys.
**Fix:** `import_native_key(network, bytes)` stored in the vault under `native-import:<network>:<n>`, tagged, refused for
UA kinds (one key, one purpose), in the manifest and the backup.

**F-50 · P3 · (new §) Key rotation, stated.** A UA id is the hash of its key: there is no signing-key rotation, only a new
UA (and `msig` membership moves, CTR-UA-37); KEM keys rotate by version; the vault DEK by `rewrap`; FROST by a new DKG.
One paragraph that says this, so wallet UIs do not promise "rotate key".

**F-51 · P3 · (new §) Recovery beyond the phrase.** `backup_seal` to an organisation's UA and `msig` cover institutional
recovery; a consumer path (SLIP-39 Shamir shares of the entropy, or a seal to several recovery UAs with a threshold) is
not here. Name it as later work.

**F-52 · P3 · (new §) Reproducible builds and `no_std`.** No binaries go to GitHub, so reproducibility is for the apps'
own stores: `--locked`, `SOURCE_DATE_EPOCH`, `cargo auditable`. `no_std` is not needed by any listed target; say so once.

## Smaller notes (no severity)

- §6.2 combiner: X-Wing-style without `ct_M` in the hash is sound because ML-KEM's `K` already binds `c`; say so in one
  line, since a reader will ask why `ct_M` is absent while `E` is present.
- §6.1: deriving the KEM key from the seed makes CTR-UA-32's client rule ("one key per version, the `register` key
  included, on every chain") hold by construction; worth stating as the gain of Q2.
- §3: `0x0010` is a native kind at the native path; the row sits among UA-tree rows and reads as one.
- §8 `Why scrypt`: 128 MiB on wasm32 means the module's memory grows to ≥ 160 MiB; T9 should measure it on a phone browser.
- §12: BLS / bn254 / Zether signing through arkworks is variable-time with the **secret scalar** in the exponent, which is
  more than a "residual" on a shared host; a blinded scalar multiplication (`k·G` with `k = k' + r·n`) is cheap.
- §9.2 `scaas_ua_kem_decaps` returns `ss` to any holder of the handle: a decapsulation oracle by design (Q6); say it, so a
  binding never exposes the handle to page scripts (wasm32).

## Top 10 "missing entirely"

1. F-42 key inventory / manifest and gap-limit discovery after restore.
2. F-43 ephemeral KEM key generation + a self-describing Sealed/backup container (device linking is impossible as written).
3. F-26 a signing policy in front of `sign_typed` (allow-list or `check*` ports).
4. F-27 `sign_transaction` with named fields for the general-EVM wallet (type 4 refused by construction).
5. F-44 depth/size bounds and fuzz targets for every untrusted decoder.
6. F-45 external-signer path (Secure Enclave / Keystore / Ledger / WebAuthn through one `ExternalKey`).
7. F-28 WebAuthn challenge and assertion builders in the API.
8. F-46 memory protection beyond zeroize (`mlock`, dump exclusion, `lock()`).
9. F-49 raw native key import, tagged by family.
10. F-48 supply-chain gates (`cargo deny` / `audit` / `vet`, `--locked`).

## P0 / P1 in one line each

- **P0 F-01** caller-supplied RNG in the release API breaks the "nonce 0, single-use key" argument (keystream reuse); use `OsRng` inside, inject only under `vectors`.
- **P0 F-02** unbounded stored scrypt parameters on vault open = memory bomb and contradicts CLI-SGN-21; bounds check + `VaultParams`.
- **P0 F-03** Q7 nonce must use the 512-bit `hashToScalar` of `verify.rs`, not a 256-bit mod-r map (nonce bias → key recovery); say it, hash `Y` too.
- **P1 F-04** decaps-side checks (ct length, `E`, contributory `ss_X`, implicit rejection) and their `kem.json` rows.
- **P1 F-05** who holds an `msig` UA's KEM key (seed-binding to `ua` gives each member a different key).
- **P1 F-09** RFC 6979 published vectors + `extraEntropy: false` pinned in the generator for every ECDSA "byte-equal" claim.
- **P1 F-10** ACVP ML-KEM-1024 and RFC 7748 vectors for the signer/KEM side; ACVP `sigGen` reused for the signers.
- **P1 F-11** zeroize per crate: Falcon has none, `ml-*`/`slh-dsa` need the feature, `bip39::Mnemonic` is a `String`.
- **P1 F-18** vault payload is the 32-byte entropy, not the 64-byte seed; define the BIP-39 passphrase handling.
- **P1 F-19** NFKC-normalise the vault passphrase as `vault.js` does, or JS vaults never open in Rust.
- **P1 F-22** `canon` is per struct (`MetaTransaction`, `MetaTransfer`, the UA forms), in the record builder, one vector row each.
- **P1 F-26** a signing policy in front of `sign_typed`.
- **P1 F-27** `sign_transaction` with named fields; no tx via the raw-digest path.
- **P1 F-28** WebAuthn challenge / assertion builders in §9.
- **P1 F-29** `KIND_UNAVAILABLE` status and `scaas_ua_features()`; bindings check both at load.
- **P1 F-42** key inventory / manifest and discovery.
- **P1 F-43** ephemeral KEM key + self-describing Sealed/backup container.
- **P1 F-44** decoder bounds (length and depth) and fuzz targets.
