# AI audit prompt, unit `crypto-kem-seal` (DRAFT, 2026-11-24)

Contracts audit at the pre-freeze target (owner rulings 2026-11-12: pre-freeze -> audit -> audit fixes -> freeze). This file is
self-contained: run it as it is, with any tool (Codex, agy, a Claude workflow, Fable, ...). Placeholders the controller fills
before the run: `<TAG>`, `<SHA>`.

## 1. Role and limits

You are one AI reviewer of the SCaaS contracts audit. The audit is an AI audit (decision ARCH-POS-14): reports name the tool and
model that wrote them. Everything under audit is `UNAUDITED`. Nothing is live with value; every chain is test-only.

**STRICTLY READ-ONLY.** Allowed: reading files; `git -C T log | show | diff | grep | blame | rev-parse`; `grep` / `rg` / `sed
 -n` /
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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-crypto-kem-seal.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-crypto-kem-seal.md`, `20261120-09-agy-gemini-4-argon-high-crypto-kem-seal.md`). Use the tool's
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

The whole system, read across its layers: the contracts (EVM, and the Soroban registry where a rule claims one rule on every
chain), `pqz-core` and the Nethermind precompiles, the signers (`ua-rs`, clientkeys and every `ua-*` wrapper), the SDK and its
bindings, the app cores, and the open node. Attackers: any EOA or contract; a relayer (may refuse, delay or reorder, never
forge or alter); a front-runner; a malicious subject, holder or group member; a malicious admin or role holder exceeding its
grant; a colluding key holder or `msig` member; a party that left or was removed; a malicious token, DEX, executor, verifier,
gateway, bundler or node; an RPC endpoint that lies, lags or forks, alone or with others; a malicious app calling the SDK or a
binding out of order; a local reader of logs, errors, metrics, stores or backups; a replayer across chain id, `chainUid`,
registry generation, token, release, kind, operation, purpose or nonce lane; a chain whose gas, block limit, precompiles or
host functions differ from the SCaaS testnet. Goals: forgery, theft, an unbacked mint, a leak of amounts, balances, keys or
plaintext, a permanent lock, replay, griefing that blocks others, a call that cannot fit a block (EIP-8037, EIP-7825), a
decryption oracle through any layer, a secret out of its place, and **a fork between layers**: a record the contract accepts
that clients cannot follow, a record clients build that the contract refuses, or a check that one path makes and its sibling
skips. Prefer a concrete call sequence to a pattern match. Across units: every optimisation that replaced code with shared code,
a library or a module (DELEGATECALL) must keep behaviour; say so when it does not.

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
  never report the old 24 KiB limit. `WrappedToken`, `WrappedRegulatedToken` and the confidential regulated releases miss 60 /
  70 M
  public blocks and deploy where the block takes them (owner 2026-11-05). Report a size only if it breaks EIP-8037 / EIP-7825 on
  a path a user must take.
- **Gas prices:** the schedule's provisional rows and calibration figures are the owner's (no timing runs here).
- The `UNAUDITED` label itself, Vietnamese source comments, style, naming, gas opinions that break no rule.
- Findings an earlier report below lists as fixed: report them only if the fix is wrong, incomplete or undone since; findings a
  triage marked REJECT or accepted (the ledgers named below): skip unless you have new evidence.

## 8. Your unit: `crypto-kem-seal`

KEM scheme 1 and everything sealed with it or beside it: seal and open, vault derivation, the wraps of PqVault and PqChat, the
file seal and the sealed PQZ leaf, read vertically through `ua-rs`, clientkeys, the wrappers, the SDK, the app cores and the
contracts that keep the bytes.

**How to read (dimension 2, read vertically, `T/docs/review.md` §1-§2).** One primitive at a time, through every
implementation and layer listed below: C, Rust, wasm32, JS, Solidity, C#, the generic and the specialised verifier, the
signer and every verifier. First read the standard or the spec's mathematics; then each implementation against it; then the
implementations against each other on the shared vectors. **A bug class found once is checked everywhere it can recur**, and
the finding lists every place. Where a primitive comes from a library (`ml-dsa`, `@noble/post-quantum`, .NET `MLDsa`, a
Soroban host function), audit our use of it (parameters, encodings, context, lengths, error handling), not the library
itself, and name its pinned version.

This unit leads dimension 2 for KEM and seals; units `ua-rs-custody`, `app-cores`, `evm-pqchat` and `evm-pqvault` audit each
layer alone.

**Primitives and every implementation (paths under `T/`; find any implementation this list misses and name it):**
- **KEM scheme 1** (ML-KEM-1024 + X25519, the combiner; small-order X25519 points, implicit rejection, canonical `pk_X`):
  `ua-rs` `clients/ua-rs/src/wallet/kem.rs` (`ml-kem` =0.3.4, `curve25519-dalek` 4), `src/ua_portable.rs` (the KEM record);
  clientkeys `src/kem.js` (`@noble/post-quantum`, `@noble/curves`), `src/ua.js`; the registry's KEM record and its hash
  `smartcontracts/evm/src/ua/UAKinds.sol`, `UARegistry*.sol` (`setKemKey`, `kemKeyOf`, `kemKeyAt`); the tree's admission check
  (`src/pqgroup/PqGroupTree.sol`, built); the C ABI and wrappers that expose it (`clients/ua-c/src/lib.rs`,
  `scaas_ua.h`, `ua-cxx`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart-frb`)
- **Seal and open** (labels, AAD bound into the key derivation, single use): `ua-rs` `src/wallet/seal.rs`, `src/wallet/aead.rs`;
  clientkeys `src/seal.js`; the file seal `ua-rs` `src/wallet/file.rs`, `src/file.rs`, `src/wallet/pqchat_file.rs`,
  `src/wallet/arweave.rs`, clientkeys `src/arweave.js`
- **Vault derivation** (BIP-39 seed, HKDF labels, scrypt / Argon2id, NFKC / RFC 8265): `ua-rs` `src/wallet/derive.rs`,
  `vault.rs`, `store.rs`, `roots.rs`, `appkey.rs` (`generated_passphrase`, `kem_wrap`, `kem_unwrap`), `secret.rs`; clientkeys
  `src/seed.js`, `src/vault.js`, `src/keystore.js`, `src/keystore-mac.js`
- **Wraps in PqVault**: `ua-rs` `src/wallet/pqvault.rs`, `appkey.rs`; clientkeys `src/pqvault.js`, `src/appcore.js`; the SDK
  `clients/scaas-sdk/src/app_core.rs`, `src/vault/`; `clients/pqvault-core/src/keys.rs` (wrap, unwrap, `pass_key`, `vault_key`,
  `seal_info`, `seal_prev`, `encrypt_item`); the contract keeps them opaque (`src/pqvault/`)
- **Wraps in PqChat**: `ua-rs` `src/wallet/pqchat_keys.rs`, `src/wallet/pqchat.rs`; clientkeys `src/pqchat.js`; the SDK
  `src/pqchat_keys.rs`, `src/pqchat_records.rs`; `clients/pqchat-core/src/`; the contract keeps them opaque (`src/pqchat/`)
- **The sealed PQZ leaf** (`sealPqKey` / `openPqKey`, P6h (3), CLI-SGN-55; vault v2 under `pqz:registry:<account>:<index>:<version>`): clientkeys
  `src/pq.js`, generator `scripts/pqz-leaf-vectors.mjs` (rows `smartcontracts/vectors/ua/pqz_leaf.json`), test `test/pqz-leaf.test.js`; `ua-rs` `src/facade/pqz.rs` (`PqzKey::open_leaf`, `pqz_leaf_label`),
  `src/wallet/mod.rs`, tests `tests/pqz_leaf.rs`, `tests/vectors_marker.rs`; the wrappers (`ua-c`, `ua-cxx`, `ua-cs`, `ua-py`,
  `ua-go`, `ua-dart-frb`); the Zether confidential key's `sealConfKey` pattern (`src/zether-keys.js`, `src/zether.js`)
- **The PQZ sealed opening's KEM use** (three-key model): `pqz-core/ffi/src/opening.rs`, `pqz-core/ffi/src/bin/pqz-vectors.rs`
- **PENDING LANDING (`user-profiles`, added 2026-11-28): the user profile's seals** (CLI-UPR-12, -17 to -21): the data key
  wrapped by Argon2id of the passphrase (per-field bounds, `p` fixed), the sealed store's AES-256-GCM-SIV with a random nonce
  and length-framed associated data, the export seal under `ExportKey`, the Matrix store key as a sealed item (CLI-UPR-29):
  `ua-rs` `src/wallet/profile.rs`, `appkey.rs` (`key-handles`); clientkeys `src/profile.js`; `clients/scaas-profile/src/`
  (how it calls the arena); rows `smartcontracts/vectors/profile/`. Hunt nonce reuse under one key, associated data that
  does not bind an item to its profile and name, a KDF floor a file can lower, and the same bytes in Rust and JS.

**Specifications and standards to read first:**
- FIPS 203, RFC 7748, RFC 5869, RFC 9106, RFC 8265, BIP-39, NIST SP 800-38D (AES-GCM)
- `T/docs/clients/signers-clientkeys.md` (CLI-SGN-02, -30, the seed vault, the PQ Zether keys), `T/docs/clients/ua-libraries.md`
  (CLI-UAL-64, -65, CLI-PQV-01 to -15, the share box), `T/docs/clients/pqchat-core.md`, spec
  `T/docs/superpowers/specs/2026-11-17-pqvault.md` §6, `2026-11-17-pqchat-core.md`; decisions ARCH-POS-13 (Change
  2026-11-13 on the hybrid KEM), the owner rulings O7 (b), O8

**Invariants to check (beyond section 5; each a finding when it fails):**
1. One KEM, one combiner, one encoding in every implementation: key generation from the seed under its own label, the
   combiner's inputs and order, the X25519 checks (small-order and non-canonical points refused or handled as specified),
   ML-KEM's implicit rejection kept (never turned into an explicit error).
2. Every seal binds its context in the AAD and the key derivation: the label, the account and index, the vault or session,
   epoch and member `(ua, keyId)`; no two seals share a label; a blob of one kind never opens as another kind's.
3. Vault derivation equal in `ua-rs` and clientkeys: BIP-39 (NFKC), HKDF salts and infos, scrypt and Argon2id parameters
   (`passKdf = 1`: 64 MiB, 3, 4), RFC 8265 OpaqueString before Argon2id; generated seeds 24 words.
4. Wraps: each wrap hashes to its signed hash; `K_v` and the epoch keys bound to `vaultId` / `sessionId`, `epochId` and
   `passKdf`; a removed member gets no wrap of a later epoch.
5. The sealed PQZ leaf: exact lengths and version byte refused before any AEAD call; the opened leaf and `seed32` only in the
   arena; clientkeys and `ua-rs` byte-equal both ways on the shared rows, every wrapper reading them.
6. No decryption oracle: a wrong key, version or truncated blob refused with one error class and no distinguishing timing or
   later action; the hybrid KEM's decapsulation of a sender-chosen ciphertext is accepted (section 7), any PQZ or Zether key
   applied to a value not shown well formed is not.
7. Zeroize and `mlock` for every key, seed and shared secret; no secret in errors, logs, `Debug` or binding exceptions.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/docs/research/security-review-record.md` (index of every review, and what no review covered)
- `T/pqz-core/research/code-review-2026-10-26/README.md`, `code-review-2026-10-19/README.md`
- `scratchpad/review-ua-mtx-merge/` (A to E, recheck-*, recheck2-*), `scratchpad/review-3w/` (`triage.md`),
  `scratchpad/review-3zh/`, `scratchpad/review-t21/` (`ledger.md`, O1-O8), `scratchpad/sdk-complete-review/`,
  `scratchpad/sdk-review-20261123-0621/` (T26, `STATUS.md`), `scratchpad/pqvault-review/`,
  `scratchpad/treekem-review-20261123-1426/`
- the reports of the layer units of this round under `scratchpad/ai-audit/results/` when they exist: read them for leads,
  do not repeat their findings; a finding of yours that a layer unit already reported names that unit's id
- `T/docs/research/zether-msm-crypto-review.md`, `T/docs/research/pqz-specialised-verifier.md` §7,
  `docs/reviews/specs/2026-10-13-pqz-sv-review.md` in the main checkout (git-ignored, local), the Fable crypto reviews named in
  `T/docs/research/security-review-record.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/smartcontracts/evm/runs/2026-11-18-prefreeze-matrix-summary.txt`, `2026-11-19-pr-a-matrix-summary.txt`, and the tag's own
  closing matrix (every forge directory at the default set, the set-sensitive tests at the other three sets, node and e2e,
  clients, vectors)
- `T/pqz-core/runs/gate/3zh-g2-<set>-summary.txt` for the four sets

**Also accepted for this unit (do not report):** the hybrid KEM's decapsulation of a sender-chosen ciphertext and its one-shot
 AEAD (ARCH-POS-13 Change 2026-11-13); T21 ledger rows REJECT or LATER and O1-O8 (O2: the link key over an authenticated
 channel).

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CLI-SGN-02, -30, CLI-PQV-09, -10, -12, CLI-UAL-64, -65 for each implementation. |
| 2 | Cryptography | **Leads this dimension for its family, read vertically.** Section 8's invariants 1-7 through every implementation and layer listed. |
| 3 | Security | A wrap or seal that opens under another context; a removed member wrapped into a later epoch; a foreign vault accepted; the link window (O3). |
| 4 | Rules that do not bend | No decryption oracle (invariant 6); never lose ciphertext (wraps and sealed info in state). |
| 5 | Secrets and privacy | **Leads this dimension within the family.** Keys, seeds, shared secrets and opened leaves only in the arena, zeroized and `mlock`ed; no secret across the FFI as raw bytes. |
| 6 | Robustness and denial of service | Bounded decode of every sealed blob, wrap and KEM record; exact lengths before AEAD. |
| 7 | Failure handling | One error class for every open failure; no partial vault write after a failed open. |
| 8 | Consistency across languages and layers | clientkeys = `ua-rs` = every wrapper = the SDK = the app cores on the shared rows (`vectors/keys/`, `keystore/`, `pqchat/`, `pqvault/`, `appcore/`, `arweave/`, the PQZ leaf rows), both ways. |
| 9 | Contract specifics | The contracts keep wraps and sealed blobs opaque and in full (never only a hash); size bounds as `evm-pqchat` / `evm-pqvault` state. |
| 10 | Performance and cost | Argon2id and scrypt cost on mobile against the rulings (no timing runs). |
| 11 | Interfaces and misuse | Seal APIs that take a label or AAD from the caller where the spec fixes it; handles from another vault refused. |
| 12 | Tests | Negative rows (wrong key, version, truncation, small-order point) read by every implementation; mutants of each label and AAD. |
| 13 | Operations and the supply chain | `ml-kem` =0.3.4, `aes-gcm` =0.11.1, `aes-gcm-siv` =0.12.1, `argon2` =0.6.0, `scrypt` =0.12.0, `bip39` =2.2.2, `@noble/*` pins and advisories. |

## 9. Report format (Markdown, English)

```
# crypto-kem-seal: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### CKS-1 [P1] <short title>
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
refusal that blocks a legitimate user, a missing check with a defence elsewhere; **P3** low impact; **info** a note with a
security
angle. No padding: no style findings, no generic advice. A claim that something is sound is a result too: say what you checked.
Say "no findings" explicitly if there are none.

Every finding names its dimension number (ARCH-POS-22, `T/docs/review.md` §3); a finding that touches several names
the main one first. Under "Not covered", name each row of the dimension table you did not reach.
