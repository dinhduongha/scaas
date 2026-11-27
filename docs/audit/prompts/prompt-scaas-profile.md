# AI audit prompt, unit `scaas-profile` (2026-11-28)

**PENDING LANDING: branch `user-profiles` (section 8).** The round pins its commit at the tag.

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-scaas-profile.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-scaas-profile.md`, `20261120-09-agy-gemini-4-argon-high-scaas-profile.md`). Use the tool's
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

`scaas-profile` is the local store of a machine's user profiles (CLI-UPR-02 and its Change of 2026-11-27): many profiles, each
its own directory, each sealed under its own data key wrapped by Argon2id of its passphrase; hidden profiles; re-seal,
export and import, delete, the index, the instance lock. It has no SDK; every KDF, AEAD and MAC runs in `ua-rs`'s profile
arena (`ProfileKeys`, `ExportKey`, feature `key-handles`), and the crate holds handles, public bytes and files. Attackers: a
local attacker who reads or rewrites the profile root (the envelopes, the index, the anchors, the journal, the sealed items)
while the app is closed or open, including one who rolls a directory back to an older copy; a thief of the device or of a
backup; someone who sees the screen or the profile list and wants to learn whether a hidden profile exists; a crafted export
file; a second instance of an app; a crash or power loss at any step. Goals: a profile's items, a seed or a key readable
without its passphrase; one profile's passphrase opening another (CLI-UPR-04); a KDF cost lowered so the passphrase is
tested offline faster than the pinned bounds allow (CLI-UPR-21); a rollback accepted silently (CLI-UPR-28); a profile lost by
a crash during a re-seal, rename or delete (CLI-UPR-20); the existence, count or name of a hidden profile learnt from the
index, the directory layout, timing or an error (CLI-UPR-13); an import that applies a setting the user did not see or
confirm (CLI-UPR-27); a settings change that weakens the profile without its passphrase (CLI-UPR-26); two instances writing
one profile (CLI-UPR-06, -14); a profile id leaving the device (CLI-UPR-10).

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

## 8. Your unit: `scaas-profile`

**Added 2026-11-28 (controller call under the owner's auto-run grant of 2026-11-25; the owner may veto). PENDING LANDING:
branch `user-profiles`, not on `dev` when this prompt was written.** The round's commit pin is set at the tag, as for every
unit. Before the run the controller checks that the branch landed in the tag; if it did not, this unit is not run and the
round's summary lists it as not covered. The file list below is the branch's; confirm each path under `T/` and list a
missing one under "Not covered".

**Scope (paths under `T/`):**
- `clients/scaas-profile/`: `src/lib.rs` (the crate surface, the `deny` of `unwrap` / `expect` / `panic` / indexing, the
  `test-hooks` `compile_error!` outside debug builds), `src/profile.rs` (`Profiles`, `OpenProfile`: start, create, open, list,
  lock), `src/store.rs` (the sealed store core `Core`, the manifests, the store write lock), `src/envelope.rs` (`Envelope`,
  `Kdf`, `KdfParams`, `State`), `src/anchor.rs` (`Anchor`, `Head`, `Verdict`, CLI-UPR-28), `src/index.rs` (the index as a
  cache, CLI-UPR-11), `src/names.rs` (name checks, NFKC / NFC, `name_key`), `src/hidden.rs` (`create_hidden`, `open_hidden`,
  `hide`, `show`, `rename`, CLI-UPR-13), `src/reseal.rs` (`set_passphrase`, `change_passphrase`, the journal, CLI-UPR-20,
  -25), `src/lifecycle.rs` (delete, `delete_locked`, `rebuild_index`, the typed confirmations), `src/migrate.rs` (the CLI's
  single store into "default"), `src/settings.rs` (the settings' storage and rules, CLI-UPR-26), `src/export.rs` (export,
  `ImportReview`, `ImportSource`, `FILE_MAX`, CLI-UPR-17, -18, -27), `src/file.rs` (`rev_of`, atomic writes); tests
  `tests/{export,hidden,lifecycle,lock,profiles,reseal,review,settings,store}.rs`; `Cargo.toml` (`scaas-ua` with
  `user-profile` and `json` only, no signing code), `Cargo.lock`, `deny.toml`
- read only (each audited in its own unit): `ua-rs`'s profile arena `src/wallet/profile.rs` and the `key-handles` feature
  (unit `ua-rs-custody`), the SDK's `src/user_profile/` and `Sdk::close` (unit `scaas-sdk`), clientkeys `src/profile.js`,
  `scripts/profile-vectors.mjs` and `smartcontracts/vectors/profile/` (unit `clientkeys-vectors`)

**Specifications and rules to read first:** `T/docs/clients/scaas-sdk.md` §12 (CLI-UPR-01 to -32); decisions CLI-UPR-01 to -32
with their Changes (the owner's rulings of 2026-11-27 among them, O15: the profile arena without signing code); spec
`T/docs/superpowers/specs/2026-11-27-user-profiles.md`, plan `T/docs/superpowers/plans/2026-11-27-user-profiles.md`;
`T/docs/clients/ua-libraries.md` (the profile arena's rows).

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **Keys only as handles** (CLI-UPR-02, -12, CLI-UPR-32): no KDF, AEAD or MAC in this crate; the data key, the passphrase key
   and the export key never leave `ua-rs`'s arena as bytes; plaintext items zeroized after use; the crate links no signing
   code (`clients/ua-rs/runs/2026-11-27-key-handles-nm.py`).
b. **One profile, one protection** (CLI-UPR-04, -07): opening one profile unlocks nothing of another; a switch locks the
   current profile and forgets its secrets as a seed lock does; the SDK of the closed profile is closed (`Sdk::close`).
c. **KDF bounds** (CLI-UPR-21): every `KdfParams` field bounded on read and on write, `p` fixed, a cost the device cannot pay
   refused by name; an envelope cannot lower the cost below the pinned floor, and no read path accepts one that does.
d. **The sealed store** (CLI-UPR-19): AES-256-GCM-SIV with a random nonce per seal, the length-framed associated data binding
   each item to its profile, kind and name as the spec pins; a swapped, truncated or replayed item refused with one error
   class.
e. **No crash loses a profile** (CLI-UPR-20, -25, -15): re-seals by a journal and a new generation under the exclusive store
   write lock; create, rename, hide and delete atomic and confirmed; every crash point between two writes leaves a profile
   that opens with the old or the new passphrase, never neither.
f. **Rollback** (CLI-UPR-28): the anchor compared as the keystore's (ahead is a crash and the anchor follows; below, or
   another hash at the same revision, is refused by name).
g. **Hidden profiles** (CLI-UPR-08, -13, -16): at most 16, never listed, never two with one name; found only by trying the
   unlisted directories with a typed passphrase; nothing in the index, the directory names, the file sizes, the error
   classes or the time an open takes tells whether one exists (state what holds and what the spec accepts).
h. **The instance lock** (CLI-UPR-06, -14): a non-blocking OS advisory lock held for the open profile's life; a second open
   refused by name; released on every exit path.
i. **Export and import** (CLI-UPR-17, -18, -27): one sealed file under pinned parameters, no profile id inside (an import is
   always a new profile), `FILE_MAX` checked before reading; the import is a preview of everything in the file, then the
   import of the user's choices only, each setting confirmed by item id; a crafted file decoded within bounds of length and
   depth.
j. **Settings** (CLI-UPR-26): a change that could weaken the profile needs the passphrase typed; list every setting and
   whether it is gated.
k. **Ids and names** (CLI-UPR-09, -10): the id a UUIDv7 that names the directory and never leaves the device (not in an
   export, a log or a network call); names checked and normalised one way everywhere.
l. **Migration** (`migrate.rs`): the CLI's single store moved into "default" without a window where neither copy opens.

**Prior reports (do not re-report what they list as fixed; give the closure table):** the spec review
`scratchpad/user-profiles-review-20261127-0819/` and the code review `scratchpad/user-profiles-code-review-20261128-0230/`
(local; `STATUS.md` in each); the Changes under CLI-UPR-01 to -32.

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
`T/clients/scaas-sdk/runs/2026-11-27-user-profiles-summary.txt` with the mutant records `2026-11-27-user-profiles-up1-` to
`-up10-mutants.txt`, `-kh-mutants.txt` and `2026-11-28-user-profiles-r1-` to `-r3-mutants.txt`;
`T/clients/ua-rs/runs/2026-11-27-key-handles-nm.py`; the tag's own client gate summary.

**Areas** (ARCH-POS-22, `T/docs/review.md` §2). This unit is one layer; it names the other areas so its findings land
where they belong.

| Area | Scope here |
|---|---|
| Layer | `clients/scaas-profile/` |
| Cross-layer | the envelope, item, label, file-name and export-chunk bytes against `T/smartcontracts/vectors/profile/` as `ua-rs` and clientkeys build them; the calls into the arena (`ua-rs-custody`) and the SDK's profile layer (`scaas-sdk`); end to end: unit `cross-layer` |
| Cryptography | the arena's Argon2id, AES-256-GCM-SIV, HKDF and HMAC are `ua-rs`'s; read here only for how they are called (parameters, associated data, nonce origin); read vertically by `crypto-kem-seal` |
| Adversarial | the local reader and rewriter, the device or backup thief, the shoulder surfer, a crafted export, a second instance, a crash (section 6); across the system: unit `adversarial` |

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1 and the brief template of §5). Apply every dimension within this
unit's scope; each row says what to hunt here and which area leads it. A row marked `N/A` gives its reason and stays. Every
finding names its dimension number (section 9).

| # | Dimension | Lead area | What to hunt in this unit |
|---|---|---|---|
| 1 | Conformance | Layer | CLI-UPR-01 to -32 one by one against the crate; the doc's status tags against the built code. |
| 2 | Cryptography | Cryptography | How the arena is called: KDF parameters and their bounds (invariant c), the associated data and nonces of the sealed store (invariant d), the export seal (invariant i). |
| 3 | Security | Adversarial | Rollback (invariant f), hidden-profile deniability (invariant g), settings that weaken a profile (invariant j), one profile opening another (invariant b). |
| 4 | Rules that do not bend | Layer | Fail closed by name; no secret leaves the arena; nothing a client must trust from an unverified file. |
| 5 | Secrets and privacy | Layer | Keys as handles only (invariant a); the id never leaves the device (invariant k); no secret or hidden-profile hint in errors, logs or `Debug`. |
| 6 | Robustness and denial of service | Layer | Bounded decodes of envelopes, the index, the journal and an import (`FILE_MAX`, depth); a KDF cost the device cannot pay refused, not run. |
| 7 | Failure handling | Layer | Crash safety of every multi-write step (invariant e); a held lock (invariant h); a migration interrupted (invariant l). |
| 8 | Consistency across languages and layers | Cross-layer | The profile vectors read alike by this crate, `ua-rs` and clientkeys; the index a cache of the envelopes, never the authority. |
| 9 | Contract specifics | N/A | No contract code. |
| 10 | Performance and cost | Layer | Argon2id per open and per hidden-profile probe (16 at most); no timing runs. |
| 11 | Interfaces and misuse | Layer | Typed confirmations (`ConfirmDeleteUnbacked`, `ConfirmDeleteUnreadable`, `ConfirmRebuildIndex`); the import as two calls; no call that writes without the lock. |
| 12 | Tests | Layer | The mutant records above kill each check; crash-point tests that can fail; the `test-hooks` KDF set never in a release (`scripts/check_test_features.py`). |
| 13 | Operations and the supply chain | Layer | `Cargo.lock`, `cargo deny` (`deny.toml`), the pins (`uuid`, `unicode-normalization`, `zeroize`); the profile root excluded from cloud backup on mobile (CLI-UPR-30, where the code claims it); SPDX headers. |

## 9. Report format (Markdown, English)

```
# scaas-profile: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### PRF-1 [P1] <short title>
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
