# AI audit prompt, unit `app-cores` (DRAFT, 2026-11-22)

**Final (2026-11-24); amended 2026-11-28: pqchat-core's TreeKEM layer and pqvault-core's sign-after-confirm landed on `dev`;
pqchat-core's sign-after-confirm landed too (branch `pqchat-core-confirm`); FRAME only for the biometric unlock
(section 8).**

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed -n` /
`cat`; `python3 scripts/docs_check.py resolve <id>` (it only prints). Not allowed: any build, test, fuzz, benchmark, gas or timing
run (`forge`, `cargo`, `npm`, `dotnet`, `anvil`, `docker`, `gate.sh`, `at-set.sh`, which rewrites `PqzSet.sol` in place); any
edit, file creation (except the one result file below), deletion, commit, checkout, stash or push; any network access to a
chain or RPC. The machine runs other heavy jobs: a large build here gets the terminal killed.

## 2. Target

- Run from the root of the main checkout of the SCaaS repository (public).
- Code under audit: the detached worktree `.claude/worktrees/audit-<TAG>` at tag `<TAG>`, commit `<SHA>`. Below, `T/` means that
  directory. Read code and docs **only** under `T/`; the main checkout's own tree may be on another branch.
- First step: `git -C .claude/worktrees/audit-<TAG> rev-parse HEAD` must print `<SHA>`. If it does not, stop and write only that.
- Prior reports named below live in the main checkout's `scratchpad/` (git-ignored, local; not under `T/`).
- The whole unit is in scope, including code that did not change since an earlier review.

## 3. Result file

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-app-cores.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-app-cores.md`, `20261120-09-agy-gemini-4-argon-high-app-cores.md`). Use the tool's
  configured model and effort (read from its config at run time; the owner may change any reviewer's model); do not
  override them. Name that model in the report's title line; the ledger records it. The unit name is always last.
- If your sandbox cannot write files, print the whole report as your final message; the runner saves it under that name.

## 4. Which source wins

1. Owner rulings: entries in `T/docs/decisions.md` with `owner: yes`, and their dated `Change` lines. They override code that has
   not caught up: **a difference between code and an owner ruling is a finding against the code.**
2. Component docs: `T/docs/contracts/`, `T/docs/clients/`, `T/docs/node/`, `T/docs/networks/`, `T/docs/integration.md`.
3. Code, for pinned byte formats only; `T/smartcontracts/vectors/` is the authority for bytes.
4. `T/docs/history/`; 5. `T/docs/research/`: background only.

`T/docs/decisions.md` is about 1.8 MB: search it by rule id (`### CTR-UA-37`, `<a id="...">`), never read it whole. An old id in a
comment resolves with `python3 scripts/docs_check.py resolve <id>`. Follow a stated rule as stated; do not propose reopening it.

## 5. Absolute rules (a break of any one is at least P1)

1. **Never lose ciphertext.** PQZ and Zether ciphertexts stay in contract state, never only a hash plus calldata or events (logs
   and history expire; state does not).
2. **No decryption oracle** (ARCH-POS-13). Nothing decrypts a ciphertext someone else chose and leaks anything about the result
   (a revert, a status, an error code, a timing, a signed verdict). Scoped exceptions are under section 7.
3. **Explicit parameters** (CTR-MTX-28, CTR-MTX-29, CTR-UA-36). Named, typed parameters and typed EIP-712, one entry point per
   operation; no packed `bytes` holding several fields, no hex bundles. Only a single crypto object stays `bytes` (a proof, a
   ciphertext, a key, a signature). Node JSON uses named fields; the old hex forms are refused (`HEX_ARGS_REFUSED`,
   `HEX_DATA_REFUSED`).
4. **Every state-changing `mtx*` is relayable**, with a fee of 0 too. A relayer can refuse or delay, never forge or alter.
5. **No EIP-7702.** An EOA signs with its own key and runs no code; a 7702 delegate never authorises (no ERC-1271 through it) and
   a delegated caller is refused (CTR-UA-24 and its Change of 2026-10-30, NET-EVM-07).
6. **No assumption about a chain:** no gas price 0, no block gas limit of ours; the PQZ / ML-DSA precompiles may ship to customer
   chains. **One rule on every chain:** never a rule split by L1, L2 or chain kind.
7. **EIP-8037 inclusion:** a transaction fits only if its regular gas plus its state gas fit the block gas limit;
   `gas_used = max(...)` is accounting, not inclusion. Do not conclude from it that a large deploy or call fits.
8. **EIP-7825 cap:** regular gas per transaction is at most 2^24 = 16,777,216 on Osaka and later (Nethermind enforces it, in
   `eth_call` too). forge / anvil 1.8.5 do not enforce it by default, so a path that is green in `forge test` above 2^24 fails on
   a chain (example found 2026-11-15: pure-Solidity ML-DSA-65 verify on an uncached key, about 19.0 M).
9. **Nothing deployed is upgraded.** Contracts are immutable; versions live in the factory's catalogue.
10. **Authorization lives in contracts.** Off-chain checks are extra, never the only guard. Fail closed: a refusal, a named error,
    zero sends.
11. **Zether is not PQZ** (separate systems, separate rules); **NEAR is not Algorand**.

A green gate is not evidence of soundness: three P0s in this repository sat behind green tests. Do not trust a test because it
passes; check that a negative test can fail. When you find a transcript, statement, digest or signature bug, check the same class
everywhere it can recur (C, Rust, wasm32, generic and specialised verifiers, Solidity, clients) and list each place.

## 6. Threat model

`pqchat-core` and `pqvault-core` are app cores **above** `scaas-sdk` (CLI-SDK-19, CLI-PQC-01, CLI-PQV-01): they depend on
the SDK, the SDK names neither, and every key, KEM, HKDF, AEAD, padding, canonical JSON, typed record and signature check
runs in `ua-rs` through the SDK. Attackers: another member of a session or vault (a malicious admin, a removed or departed
member, an `msig` member); a sender of spam, of a crafted envelope, wrap, `sealedInfo` or item; a malicious RPC endpoint,
node, Matrix homeserver, Arweave gateway or bundler; a contract on another chain or a replica that names the same home; a
local attacker who reads the app's store, caches, logs, crash reports or a backup; a thief of an unlocked or a locked
device. Goals: a key or plaintext outside a handle; a record shown or used before it is verified and accepted; a wrong
recipient, epoch or key chosen from a lying read; a message or item read by someone removed; a decryption failure on
attacker-chosen data that becomes observable (an error, a reply, a read receipt, a timing, a fetch, a later write); history
lost because recovery relied on local state or events; a passphrase tested offline faster than the pinned Argon2id allows; a
biometric path that opens a vault on a device where the user did not turn it on; an attachment whose size or bytes leak
through the padding or the Arweave path.

## 7. Do not report (accepted by the owner; skip unless the code does something worse than the accepted behaviour)

- **Hybrid wrapped tokens:** a minter may mint unbacked units and unwrap them against the reserve users deposited (CTR-GOV-30,
  CTR-TOK-05 "not claimed on a hybrid"; owner 2026-11-13, USDC -> VND CBDC).
- **`BURNER`:** holders cannot stop a user sending to an unspendable address (not a burn; CTR-GOV-29).
- **Own-key `OFFCHAIN` PQZ token** (`pqzOwnKey = true`, `pqzOpening = false`): whoever can make that token's verifier sign can
  recover that token's key; the risk lies in that token only (ARCH-POS-13 Change 2026-11-13, CTR-PQZ-37).
- **The hybrid KEM** (ML-KEM-1024 + X25519, IND-CCA by its combiner): a decapsulation of a sender-chosen ciphertext and its
  one-shot AEAD are outside ARCH-POS-13 (Change 2026-11-13). Still report any PQZ or Zether key applied to a value that was
  not first shown well formed by re-encryption and byte comparison.
- **Shared-key `OFFCHAIN` class (class 2):** `msig` refused and op 7 unsupported at first; the auditor guarantee as ruled (an
  honest recipient cannot spend an unreadable credit; collusion leaves a named unreadable leg) (three-key spec, Q8 / Q9).
- **CTR-DEX-19:** `dex` must be a contract, nothing more; a contract made to look like a DEX can report any fill and take the
  signed amount (owner-accepted residual risk).
- **CTR-TOK-31:** R10 Sybil on the net wrap / unwrap rule; Q17 (a) the shielded id of a confidential kind is not always the
  public id (disclosed).
- **Classical Zether:** handing `s` over opens every leg, decoys included (CTR-ZTH-37); the sender may leave the auditor out of
  one transfer (CTR-ZTH-42); `fund` burns public Zether units from the caller (CTR-ZTH-35).
- **`msig`:** one with no `pop` is unusable until enough weight accepted, on each registry (CTR-UA-37).
- **`fndsa1024`:** built on the Falcon round-3 specification v1.2, the FIPS 206 risk accepted (CTR-UA-40 Q1).
- **`PqChat`:** a member can take the slot first and make the admin rekey again (CTR-CHAT-09, O2); what an open topic accepts
  cannot be removed, and its state-gas cost per KiB is accepted (CTR-CHAT-16, D20).
- **`OPERATOR_TRANSFER` / grants:** a `WHOLE` holder is unbounded by design (CTR-GOV-20).
- **PQZ rollover floor C0-6** of the 2026-10-26 review: accepted, spec corrected (CTR-PQZ-08 (a)).
- **Sizes and deploy gas:** the code-size ceiling is 64 KiB (Amsterdam / Glamsterdam is required on every chain, NET-EVM-06):
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 / 70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `app-cores`

**Finalized 2026-11-24 against `origin/ua-rs-sign`:** both crates are built there (`pqchat-core` T1-T12 with review rounds
2 and 3, `pqvault-core` V10), and the pre-freeze tag carries them. **Still FRAME:** the biometric unlock of invariant (h) (scaas-app, after the pre-freeze tag, TODO 8b-3: audit only what a core already
claims). The component doc `T/docs/clients/pqchat-core.md` still tags most sections **SPECIFIED** although the code is built:
a status tag that disagrees with the code is a dimension 1 finding.

**Amendment 2026-11-28** (controller call under the owner's auto-run grant of 2026-11-25; the owner may veto). (1)
`pqchat-core`'s TreeKEM layer (CLI-PQC-17), FRAME until now, landed on `dev` with the TreeKEM client round (plan T4-T10),
the path-less Adds round and F-1: audit it in full (invariant l). (2) `pqvault-core`'s sign-after-confirm and redacting
item layer (CLI-SDK-36, CLI-PQV-16 H1-H3, CLI-PQV-17, CLI-PQV-18) landed on `dev` (invariant m). (3) `pqchat-core`'s
sign-after-confirm, relayed topic writes, window sorts and pinned `contentHash` (CLI-PQC-18, CLI-PQC-21) landed on
`dev` from branch `pqchat-core-confirm` (invariant n).

The two client cores: `pqchat-core` (the PqChat client: sessions, epochs, ratchet, envelopes, the Matrix and chain message
stores, topics, recovery) and `pqvault-core` (the PqVault client: vaults, epochs, the passphrase, items, versions and merge,
sharing, migration).

**Scope (paths under `T/`; to be confirmed when the crates land):**
- `clients/pqchat-core/` (built; finalized 2026-11-24): `src/lib.rs` (the crate surface, `#![forbid(unsafe_code)]`, the
  `deny` of `unwrap` / `expect` / `panic` / indexing), `src/session.rs` (sessions, epochs, rekeys, wraps in chunks, leave,
  remove), `src/message.rs` (envelopes, the ratchet positions through the SDK, `PqChatTooFar`), `src/signed.rs` (the
  `require_signed_records` check, CLI-PQC-15, on `sstore2` homes), `src/check.rs`, `src/consent.rs` (pending sessions until
  accepted, CLI-PQC-08), `src/drops.rs` (records dropped, never answered, CLI-PQC-07), `src/reads.rs` (every chain read and its
  purpose, CLI-PQC-13, CLI-PQC-16), `src/recovery.rs` and `src/chain_state.rs` (state-only recovery, CLI-PQC-09),
  `src/chain_store.rs`, `src/store.rs`, `src/stores.rs` (the chain and Matrix message stores, the local cache), `src/matrix.rs`
  (the Matrix transport trait), `src/topics.rs`, `src/file.rs` (attachments through the Arweave seal, T10b), `src/device.rs`
  (several keys per member, CTR-CHAT-24), `src/content.rs`, `src/order.rs`, `src/model.rs`, `src/net.rs`, `src/error.rs`,
  `src/abi.json` (generated by `runs/gen_abi.py`); the Dart binding `ffi/` (`ffi/src/api/mod.rs`: `pqchat_open`, the
  `SecretBytes` handles, `pqchat_error_code`; `ffi/dart/`); tests `tests/` (incl. `hostile/`, `e2e/`, `matrix_conformance.rs`,
  `vectors.rs`, `devices.rs`, `signed.rs`); `runs/check_reads.py` (the reads gate `pqc-reads`), `runs/bind_surface.py`,
  `runs/pqc_mutants.py`, the mutant records `runs/2026-11-17-pqchat-core-t1-mutants.txt` to `-t12-`, `-r2-`, `-r3-`,
  `-e2e-`, `-sigs-mutants.txt`, the summary `runs/2026-11-17-pqchat-core-summary.txt`; `Cargo.toml`, `Cargo.lock`, `deny.toml`,
  `.cargo/audit.toml`
- `clients/pqchat-core/` additions (2026-11-28): `src/tree.rs` (the TreeKEM layer: replay, the walk, path and path-less
  commits, `tree_commit_plan`, the batch split, the exits; landed), `tests/tree_scenarios.rs` and the tree tests (landed);
  landed from `pqchat-core-confirm`: `src/confirm.rs` (`Prepared<W>`, `review()`, `quote()`, `confirm`), the
  changes to `src/session.rs`, `src/topics.rs` (relayed topic writes, the window sorts, the pinned `contentHash` check in
  `resolve_ref`), `src/tree.rs`, `src/net.rs`, `src/matrix.rs`, `src/error.rs`, the mutant record
  `runs/2026-11-28-pqchat-core-confirm-mutants.txt`, `tests/sign_sites.rs` (every signing call site behind a confirm)
- `clients/pqvault-core/` additions (landed 2026-11-27): `src/item.rs` (the redacting item layer: `Item`, `Field`, the
  secret table `item::TABLE`, `Item::check`, the merge by canonical JSON, the 64-secret and 16,384 B bounds),
  `src/vault.rs` `Prepared`, `confirm`, `Confirmed`, `Confirmed::within_review`, `prepare_signed`; tests
  `tests/devices.rs`; `runs/2026-11-27-pqvault-ui-rules-summary.txt` and its mutant records (`-mutants.txt`, `-r2-`, `-r3-`)
- `clients/pqvault-core/` (finalized 2026-11-22, branch `pqvault-core`): `src/lib.rs` (the `Net` seam over the SDK, `SdkNet`,
  `Error`, P1 `PqVault::p1`, `entry`'s JSON ABI items), `src/records.rs` (records, typed JSON of both domains, ids, scopes,
  `wrap_hash`, `item_aad`, `sig_hash`, `sig_of`'s bounded decode), `src/keys.rs` (the key schedule on handles: wrap, unwrap,
  `pass_key`, `vault_key`, `seal_info` / `open_info`, `seal_prev` / `open_prev`, `encrypt_item` / `decrypt_item`, `kFile`),
  `src/content.rs` (canonical JSON, padding, item bounds, merge), `src/vault.rs` (`fetch` / `verify` (spec §6.9) / `load`,
  `unlock` and the history walk, `create_vault`, `rekey` / `rekey_by`, `leave`, `remove`, items, `create_items`,
  `open_latest`, `history`, `replica_agrees`, `recover`, `accept`, `member_key`, `share_box`, `generate_passphrase`,
  `migration_plan`, the `prepare_*` calls); tests `tests/{vectors,core,e2e}.rs`; `runs/2026-11-22-pqvault-core-mutants.py`,
  `runs/2026-11-22-pqvault-e2e.sh`, `runs/2026-11-22-pqvault-core-summary.txt`, the mutant records `-v10-mutants.txt`,
  `-v10-r2-mutants.txt`, `-v10-r3-mutants.txt`
- the SDK and `ua-rs` rows pqvault-core rests on (read for the calls it makes): `T/clients/scaas-sdk/src/app_core.rs`
  (`sign_pqvault_record` with its `msig` branch `sign_pqvault_msig`, `verify_pqvault_record`, `generate_passphrase`,
  `read_app`, `kem_wrap`, `kem_unwrap`, `prepare_app_call`), `src/account/msig.rs` `app_msig`, `src/account/register.rs`
  `set_kem_key_args` / `prepare_set_kem_key` (CLI-PQV-15); `T/clients/ua-rs/src/wallet/pqvault.rs` (`digest`, `sign`,
  `sign_msig`, `verify`), `src/wallet/uasig.rs` `msig_sig_app_chain`, `src/wallet/appkey.rs` `generated_passphrase`
- the controller calls of 2026-11-22 (CLI-PQV-15 (5)-(8), CLI-SDK-33's Change): `sign_pqvault_record`'s explicit `records`
  argument; `AppCore::with`'s refusal of a repeated handle; F2 on the dedicated path, `src/account/msig.rs` `line_domain`
  (the holder generation's `UAAuth` domain at its `generation()`), its `line` flag through `ua_path` and `with_records`;
  tests `clients/scaas-sdk/tests/app_core.rs` `a_handle_twice_in_one_call_is_refused`, `tests/app_core_vault_records.rs`
  `pqvault_records_chain_is_explicit`, pqvault-core e2e `pqvault_records_on_a_two_generation_line` (chain 31930); mutant
  record `clients/pqvault-core/runs/2026-11-22-pqvault-core-v10-r3-mutants.txt
- their SDK rows: `T/clients/scaas-sdk/src/{pqchat_keys,pqchat_records,app_core}.rs`, `src/vault/` (read for the calls the
  cores make; the SDK itself is unit `scaas-sdk`), and the `ua-rs` rows `wallet::pqchat_keys`, `wallet::pqchat::verify`,
  the PqVault key schedule (read only; `ua-rs` is the `ua-rs-*` units)
- the vectors: `T/smartcontracts/vectors/pqchat/`, `T/smartcontracts/vectors/pqvault/`, clientkeys
  `scripts/pqchat-vectors.mjs` and `src/pqvault.js` (the reference rows the cores reproduce, CLI-PQC-11)
- bindings of the cores, if any (CLI-PQC spec §11)

**Specifications and rules to read first:**
- pqchat-core: `T/docs/clients/pqchat-core.md` (CLI-PQC-01 to -14), spec `T/docs/superpowers/specs/2026-11-17-pqchat-core.md`
  (§1 rulings, §5 the SDK surface, §7 the store, §9 threat model, §10 vectors, §13 open points with the owner's answers, §14
  the Fable review), `T/docs/contracts/pqchat.md` and the UA-7 decisions (CTR-CHAT-*); the T1 hand-off note
  `scratchpad/pqchat-core/t1-sdk-rows.md` in the main checkout (local, git-ignored: the SDK calls K1-K6, S1 / S2 / S5, V1 / V2,
  R1 / R2 and the controller calls on canonical JSON and decoder bounds)
- pqvault-core: the PqVault spec `T/docs/superpowers/specs/2026-11-17-pqvault.md` §6 (cryptography), §7 (`pqvault-core`),
  §8 (the app-facing API), §9 (client obligations), §10 (threat model), §11 (tests), §14 (O1-O9 with the owner's rulings);
  `T/docs/clients/ua-libraries.md` (CLI-PQV-01 to -12, the share box); the V10 rows of the spec (a V10 test per verified
  record, spec §6.9)
- decisions ARCH-POS-13, ARCH-POS-15, CLI-SDK-19 to -21 (app cores, the `app_core` surface, the Arweave calls), the PqVault
  rulings O7 (b) and O8 (2026-11-21), the PqChat state-only recovery ruling (CTR-CHAT, CLI-PQC-09)

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **Keys only through SDK and `ua-rs` handles, never raw** (CLI-PQC-03, CLI-PQV-12, CLI-SDK-02, CLI-SDK-20): epoch keys,
   chain keys, message keys, `K_v`, `P_k`, file keys and the passphrase cross into the cores as handles only; only decrypted
   content the user reads leaves the SDK; no core calls `ua-rs` directly, and `pqchat-core` never calls T21's
   `sign_pqchat_session` / `sign_pqchat_message` with a caller-made ciphertext (t1-sdk-rows.md call 4). No blind signing:
   records are signed only through the SDK's named, typed entries (CLI-PQC-04).
b. **The ratchet and epoch rules** (CLI-PQC-14 and the UA-7 rules): no skipped message key is kept; a verified message is
   read at any counter up to 2^20 (`PqChatTooFar` above); a chain position is its own handle kind (chain + counter) and the
   hint and public MAC refuse it; epochs `parent + 1`, the home slot and the removal rule as the contract states; a removed
   or departed member reads no later epoch; PqVault: `K_v` as CLI-PQV-09 (wraps under `scaas/pqvault/v1/wrap`, HKDF info
   binding `vaultId`, `epochId`, `passKdf`), a passphrase change or toggle is an admin's rekey (CLI-PQV-10).
c. **Padding and canonical JSON bounds**: canonical JSON with integers within ±(2^53 − 1) only (checked by re-serialising,
   in `ua-rs` and clientkeys alike); bounded decoders: `parents` ≤ 8, `UASig` members ≤ 16 per level, padded plaintext ≤
   65,536 B; PqVault `sealedInfo` padded to 1,024 B then the next power of two (CLI-PQV-09; the chain takes 28 to 16,412 B),
   item ciphertexts within 32 to 16,416 B; padding buckets always (CLI-PQV-03, metadata reduction). Every decode bounded by
   length and depth (Matrix events, RFC 4648 §4 base64 with padding exactly, the chain reads, the store's own rows).
d. **Every read that feeds a decryption, or chooses an encryption key, a recipient or an epoch, is `FeedsDecryption` with
   the majority option** (CLI-PQC-13, ARCH-POS-15, CLI-RPC-06): `read_app(..., trusted = true)` at the final block for
   `kemKeyOf`, `kemKeyAt`, `checkedOf`, `memberAccepted`, `latestEpoch`, `epochsOf`, `childOf`, `removedIn`, the wraps,
   `sealedInfo`, `messageAt`, `storedRange`, the topic pages, and PqVault's `vaultsOf`, `vaultOf`, `epochOf`, `wrapAt`, the
   item reads. List every read the cores make and its purpose.
e. **No decryption oracle (ARCH-POS-13, CLI-PQV-05):** a record that fails a check is dropped, shown on the device at most,
   and nothing the client sends depends on it (CLI-PQC-07): no reply, receipt, error, fetch, Matrix event or later write. Spam
   is filtered by the clients without leaking (a session stays pending until its user accepts it, with no network call and
   no write before, CLI-PQC-08). An envelope that arrives while the seed is locked is kept and processed at unlock, never
   answered differently (CLI-PQC-10).
f. **State-only recovery for PqChat** (CLI-PQC-09; owner 2026-11-10): no client session list, no events; recovery from
   `sessionsOf` / `latestEpoch` / `storedRange` and the other contract views alone; the local store is a cache with no secret
   and no state that recovery needs. PqVault the same (CTR-PQV-10: no vault list kept, no event read).
g. **The vault passphrase:** Argon2id (RFC 9106, version 0x13), `passKdf = 1` pinned at 64 MiB / 3 passes / parallelism 4,
   32-byte output, no associated data (owner O8, 2026-11-21); the passphrase's bytes RFC 8265 OpaqueString (NFC) before
   Argon2id (non-ASCII spaces to U+0020, then NFC, then UTF-8; an empty result or a control character refused
   `PassphraseInvalid`), the same in clientkeys and `ua-rs` (spec §6.5, the Fable code review F4; the `pass.json`
   `normalization` rows); `passSalt` 32 random bytes per vault;
   a shared vault's passphrase refused when it equals an unlocked personal vault's (spec §6.5); an unknown `passKdf` refused.
h. **Biometric unlock is an opt-in per device** (owner O7 (b), 2026-11-21; spec §6.5): a device-keystore-wrapped `P_k`
   behind biometrics only on a device where the user turned it on, off by default, the client saying so when it is turned
   on; on that device the device key and the seed then open the vault without the passphrase, and nowhere else. Check that
   the wrapped copy is bound to that device's keystore, and that `P_k` and `K_v` otherwise live only in `ua-rs` key memory
   (zeroized, `mlock` where the platform allows) until the auto-lock or the app's exit ("never stored, never sent").
i. **Attachments through the Arweave seal** (plan T10b; CLI-SDK-21, CLI-UAL-64, CLI-UAL-65): the file sealed under a fresh
   key by the SDK call, padding inside the AEAD (the size bucket only is visible), `ctSha256` checked before opening,
   `fetch_file` / `open_file` as unit `scaas-sdk` invariant (d) states; a PqVault item that names an `ar://` object is
   written only after one gateway read of it passed the check.
j. Reproduction: the cores' bytes equal clientkeys' rows (CLI-PQC-11) and the real-crypto end-to-end run is a gate
   (CLI-PQC-12); a vector row that only a canonical input exercises does not prove a canonicalization (section 5's note on
   tests that cannot fail).
k. **The review-fix round's reader rules** (added 2026-11-26; CLI-PQC-15 and the pqchat-core / pqvault-core Changes of
   2026-11-25 / -26; CTR-UA-74): pqchat-core's walk (`reads.rs` `walk`): an epoch counts only through its chain down to the
   signed session record, each link judged against its parent with the parent's exits, ids recomputed, session and number
   checked, the remover in the parent's admins (U-1, E-4); each remembered id bound to the hash of the record verified under
   it (C-1); a record that is its own parent ends the walk, no underflow (C-2); "plain" computed as the contract's `_keeps`
   (E-1, `check.rs`); a replica's exits read under the epoch named (E-5), a replica record compared with the home's with the
   `msig` tags stripped (A-1); step 6 along a session's epochs and along pqvault-core's vault (`vault.rs` `verify`,
   `epoch_agrees`: oldest first, no `msig` version below the highest seen; C-3 / R-2, `tests/exits.rs`); the leave and remove
   builders checked at the head with the lag and the named epoch's lists (D2-4, C-5), refused by the new code `ExitLag` (29
   codes).
l. **The TreeKEM layer** (added 2026-11-28; CLI-PQC-17, CTR-CHAT-26 / -27 and their Changes of 2026-11-26 to -28; the
   path-less delta spec `T/docs/superpowers/specs/2026-11-25-treekem-pathless-add.md` R17-R20, C45-C47; F-1 of 2026-11-28):
   tree epoch keys only from a verified replay (the registry's records for every KEM key a path secret goes to, epochs from
   verified data, `joinEpoch` from the walk, served counts bounded); a path-less Add never sent while the device's own path
   commit is staged on the head (F-5); a path-less record of the device's own `(ua, keyId)` with a reproduced nonce and a
   foreign tag is the compromise warning (R10), after which the device takes no key and drops the chain until the next path
   commit reaches it (F-1, C-11 / G-4); a batch of Adds over the per-transaction cap split, never refused (the owner's
   ruling of 2026-11-27); the admins' warning when a path commit is due (R18).
m. **pqvault-core: sign after confirm and the item layer** (added 2026-11-28; CLI-SDK-36, CLI-PQV-16 H1-H3, -17, -18):
   nothing signed before `confirm`; a `Prepared` read-only, keyless, and what `confirm` signs is what `review` / `quote`
   showed; `confirm` returns the signed record whatever the call did, and `prepare_signed` re-sends it with no second
   signature; `Confirmed::within_review` sends on the first confirm only with the same payer and a `max_cost` at most the
   reviewed one, every other case asks a second confirm (CLI-PQV-18). The item layer: every field typed by `item::TABLE`,
   a secret only as `SecretBytes` (history included), unknown fields and `null`s written back byte for byte, the merge by
   canonical JSON that never un-hides, at most 64 secrets per item, the canonical JSON in a 16,384 B zeroizing buffer that
   never reallocates, `Debug` printing counts only; `items.json`'s plaintexts read and written back byte for byte.
n. **pqchat-core: sign after confirm** (landed from `pqchat-core-confirm`) (CLI-PQC-21, CLI-PQC-18, CLI-SDK-36):
   `create`, `rekey`, `leave`, `remove`, `create_tree`, `tree_commit` (path and path-less), `tree_leave`, `tree_remove` and
   the six topic writes return `Prepared<W>`, nothing signed before `confirm`; a topic write relayed by default through the
   node's door A (NODE-GW-09) with fee 0 allowed; feeds ranked over a window by one deterministic arithmetic; a `ref`'s
   pinned `contentHash` rebuilt from the version's nonce (CTR-CHAT-31) and checked, `HashUnchecked` only where the view
   cannot give it.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- the pqchat-core spec's §14 (Fable, 2026-11-17) and the PqVault spec's §16-§17 (reviews r1 / r2)
- `scratchpad/pqvault-review/20261121-fable-code-review-v1-v8.md` (local; its client findings, F4 and others)
- the cores' build review rounds as recorded in `T/docs/decisions.md` (CLI-PQC-15 to -17 and the pqchat-core Changes) and in
  the round-2 / round-3 mutant records (`clients/pqchat-core/runs/2026-11-17-pqchat-core-r2-mutants.txt`, `-r3-mutants.txt`);
  the T26 SDK review's app-core rows (`scratchpad/sdk-review-20261123-0621/`: A-5 part b, A-9, B-17)
- the review-fix round (2026-11-24 to -26, local; the cores: E-1, E-4, E-5, U-1, D2-*, C-1 to C-5): the TreeKEM and G1 code review
  `scratchpad/treekem-g1-review-20261124-1550/` (`BRIEF.md`, Fable areas A-G at `8cac68125`; its fixes, red tests and
  mutants in `T/smartcontracts/evm/runs/2026-11-24-review-fix-contract-summary.txt`), the re-review
  `scratchpad/review-fix-review-20261125-1959/` (`STATUS.md`: verdict, branch, fix commit, red test and mutant per finding;
  `fable-{A..G}.md`) and the fix check `scratchpad/review-fix-check-20261126-0429/` (`STATUS.md`, `fable-{A,R,C}.md`)
- added 2026-11-28 (local, `STATUS.md` in each): the TreeKEM client round's review
  `scratchpad/treekem-t4-t9-review-20261126-1808/` and re-check `scratchpad/treekem-t4-t9-recheck-20261126-2332/`; the
  path-less review `scratchpad/treekem-pathless-review-20261127-1527/` and the F-1 notes `scratchpad/treekem-f1/`; the PqVault
  UI rules review `scratchpad/pqvault-ui-rules-review-20261127-1556/` and re-check
  `scratchpad/pqvault-ui-rules-recheck-20261127-1918/`; `scratchpad/pqchat-core-confirm-review-20261128-0133/`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the cores' gate summaries under `T/clients/pqchat-core/runs/` and `T/clients/pqvault-core/runs/` (mutants included:
  `T/clients/pqchat-core/runs/2026-11-17-pqchat-core-summary.txt` with its `pqc-reads` rows, the T1-T12, r2, r3, e2e and sigs
  mutant records, e.g. T1 10 of 10 killed; `T/clients/pqvault-core/runs/2026-11-22-pqvault-core-summary.txt` and the V10
  records), and the tag's own client gate summary
- the review-fix round's client rows: `T/clients/runs/2026-11-25-review-fix-client-summary.txt`,
  `2026-11-26-review-fix3-client-summary.txt`, `2026-11-26-review-fix4-client-summary.txt` (with their `-mutants.py`
  runners), and the round's closing matrix (`T/smartcontracts/evm/runs/2026-11-26-round-matrix.sh` and its summary)
- added 2026-11-28: `T/clients/pqvault-core/runs/2026-11-27-pqvault-ui-rules-summary.txt` and its mutant records;
  `T/runs/2026-11-27-treekem-pathless-combined-summary.txt`, `-matrix-summary.txt`, the path-less mutant records `-p3-` to
  `-p9-`, `-trace-`, `T/runs/2026-11-27-pqchat-treekem-split-mutants.txt`, `T/runs/2026-11-28-treekem-f1-f1-mutants.txt`;
  `T/clients/pqchat-core/runs/2026-11-28-pqchat-core-confirm-mutants.txt` and the confirm rows of
  `T/clients/pqchat-core/runs/2026-11-17-pqchat-core-summary.txt`

**Also accepted for this unit (do not report):**
- What the specs leave for later rounds: groups beyond what CLI-PQC-02 scopes, attachments in the app's first version
  beyond T10b, PqVault's other families (spec §12).
- The PqVault owner rulings O1-O9 as ruled (O7 (b) and O8 above; O1 (c) the share box), and the accepted PqChat risks of
  section 7.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CLI-PQC-01 to -17, CLI-PQV-01 to -18, CLI-SDK-19 to -21, CLI-SDK-36 CLI-PQC-18, CLI-PQC-21, the PqVault owner rulings O1-O9 and the PqChat state-only recovery ruling against `clients/pqchat-core/` and `clients/pqvault-core/` (the TreeKEM layer in scope since 2026-11-28, invariant l); the doc status tags against the built code; the reader rules of invariant k. |
| 2 | Cryptography | The key schedules on handles (pqvault-core `keys.rs`: wrap, unwrap, `pass_key`, `vault_key`, `seal_info`, `encrypt_item`; pqchat-core's epoch, chain and message keys through the SDK); HKDF info binding `vaultId`, `epochId`, `passKdf`; Argon2id parameters and RFC 8265 normalisation (invariant g); the ratchet rules (invariant b); padding inside the AEAD. |
| 3 | Security | Records signed only through the SDK's typed entries (no blind signing, invariant a); a removed or departed member reads no later epoch; biometric unlock bound to one device (invariant h); a shared vault's passphrase equal to a personal one refused. |
| 4 | Rules that do not bend | No decryption oracle (invariant e); every read that feeds a decryption or chooses a key `FeedsDecryption` (invariant d); state-only recovery (invariant f); no ciphertext kept only off chain. |
| 5 | Secrets and privacy | Leads within the unit: keys only as handles (invariant a); no plaintext or key on disk; the local store a cache with no secret; padding buckets always. |
| 6 | Robustness and denial of service | Bounded decoders (`parents` <= 8, `UASig` <= 16 per level, padded plaintext <= 65,536 B, Matrix events, base64 exactly, the store's rows; invariant c). |
| 7 | Failure handling | A record that fails a check is dropped, nothing sent in answer; an envelope that arrives while locked kept and processed at unlock. |
| 8 | Consistency across languages and layers | The cores' bytes equal clientkeys rows (`pqchat.js`, `pqvault.js`, `scripts/pqchat-vectors.mjs`) and `T/smartcontracts/vectors/{pqchat,pqvault}/` (CLI-PQC-11, invariant j). |
| 9 | Contract specifics | N/A: no contract code (the contracts are units `evm-pqchat`, `evm-pqvault`). |
| 10 | Performance and cost | Argon2id at 64 MiB / 3 / 4 on mobile (no timing runs); RPC reads per unlock and per history walk. |
| 11 | Interfaces and misuse | The app-facing API (pqvault-core `entry` JSON ABI, `Net` seam) hard to misuse; prepare and sign in one step as decided (T26 A-5 part b). |
| 12 | Tests | Mutant records (`runs/2026-11-22-pqvault-core-v10*-mutants.txt`, the pqchat-core mutants); the real-crypto e2e as a gate (CLI-PQC-12); the review-fix round's client mutants (`T/clients/runs/2026-11-2[56]-review-fix*-client-*`). |
| 13 | Operations and the supply chain | `Cargo.lock` and `cargo deny` / `cargo audit` of both crates; SPDX headers. |

## 9. Report format (Markdown, English)

```
# app-cores: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### APC-1 [P1] <short title>
- Where: T/<path>:<line>[-<line>] (every place, if the class recurs)
- Rule or invariant: <rule id or invariant from section 8>
- Dimension: <number and name, from the dimension table of section 8 (`docs/review.md` §1)>
- Claim: <one or two sentences>
- Failure scenario: <concrete inputs or call sequence -> wrong outcome (forgery, loss, leak, lock, crash, divergence)>
- Evidence: <quoted code, doc or standard clause, and the reasoning>
- Fix: <concrete change>
- Confidence: CONFIRMED (traced end to end) | PLAUSIBLE (say what is not traced)

## Earlier findings in this unit
<for each finding of the prior reports in section 8 that touches this unit: closed / open / regressed, with file:line>

## Checked and sound
<what you checked and found holding, with file:line, so a reader knows the coverage>

## Not covered
<what you did not reach>
```

Severity: **P0** forgery, theft or loss of funds, an unbacked mint, a break of privacy of amounts, balances or keys, a permanent
lock, a decryption oracle, a lost ciphertext, a consensus split; **P1** a break of a section-5 rule or an owner ruling with a
real path, a relayer able to alter an intent, a DoS of a whole contract or node; **P2** a bounded loss, griefing, a wrong
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
