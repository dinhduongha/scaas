# AI audit prompt, unit `vendor-falcon-rs` (2026-11-26)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-vendor-falcon-rs.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-vendor-falcon-rs.md`, `20261120-09-agy-gemini-4-argon-high-vendor-falcon-rs.md`). Use the tool's
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

Attackers: a malicious counterparty, relayer, node or RPC feeding data to the library; a malicious caller of the JSON, C ABI or
binding boundary; a local attacker who reads memory, swap, logs, errors or a backup; a lost or reinstalled device. Goals: the
user signs something other than what it sees, or a digest valid elsewhere (another chain, `chainUid`, token, kind, op, nonce
lane); a key, seed, nonce or share leaks; a nonce is reused; a decode crashes or exhausts memory (bounded by length AND depth);
a secret reaches an error, a log or a `Debug` print; a decryption oracle on the client. ua-rs is the only signer every client
uses (owner 2026-11-05).

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

## 8. Your unit: `vendor-falcon-rs`

falcon-rs 0.3.1, the third-party round-3 Falcon port that keys, signs and verifies both Falcon kinds (`fndsa512` 0x0132,
`fndsa1024` 0x0135) in `ua-rs` on `wasm32-unknown-unknown` (CLI-UAL-66), and the `ua-rs` glue over it. Unlike the other
libraries of this audit, **this unit audits the library's own code** (owner 2026-11-26: nobody had audited falcon-rs),
function by function against the reference C, besides our use of it. Unit `crypto-signatures` reads the Falcon kinds
vertically (verdict and key parity across the layers), `ua-rs-sign` the native signer; a defect in the glue's routing
belongs here. Added 2026-11-26 (controller call; the owner may veto).

**Before you read.** `vendor/` is git-ignored (ARCH-POS-24): the controller installs it in the frozen worktree with
`scripts/vendor.sh install` and checks it with `scripts/vendor.sh check` before the run. If `T/vendor/falcon-rs-0.3.1/` is
missing, stop and write only that. Its pinned tree id is in `T/scripts/vendor.sh` (`315fb462…` at the time of writing).

**Scope (paths under `T/`):**
- `vendor/falcon-rs-0.3.1/` (crates.io `falcon-rs` 0.3.1, MIT; `default-features = false, features = ["fpemu"]`):
  `src/falcon.rs` (the API the glue calls, `sv_buf`, the padded signer), `src/sign.rs` (`gaussian0_sampler`, `ber_exp`,
  `sampler`, `ff_sampling_fft_dyntree`, `do_sign_dyn`, `sign_dyn`), `src/keygen.rs`, `src/vrfy.rs` (verification,
  `complete_private`), `src/codec.rs`, `src/fft.rs`, `src/fpr/emu.rs` (integer floating point; `fpr/native.rs` must not
  compile under `fpemu`), `src/rng.rs`, `src/shake.rs`, `src/common.rs` (`hash_to_point_vartime`), `src/lib.rs`, `Cargo.toml`;
  `src/safe_api.rs` only to confirm that the glue does not reach it
- its records: `vendor/falcon-rs-0.3.1.VENDORED.md` (source, crate sha256, upstream commit, licence, audit status),
  `vendor/README.md`, the pins in `scripts/vendor.sh` (the script's own logic is unit `bindings-cli-ci`)
- the `ua-rs` glue: `clients/ua-rs/src/falcon/soft.rs`, `src/falcon.rs` (routing), `build.rs` and `Cargo.toml` (wasm32 to
  falcon-rs, native to PQClean), `src/wallet/pqsign.rs` (the Falcon signing calls), `Cargo.lock` (the `path` entry); tests
  `tests/fndsa_vrfy.rs`, `tests/fndsa/` (`rows.rs`, `sign.rs`, `wasm/run.sh`)
- the reference, read as the other side: `vendor/pqclean-falcon-seeded/` (PQClean `falcon-padded-512` / `-1024`, clean) and
  `vendor/pqclean-falcon-seeded.local/seeded.c` (PQClean's `pqclean.c` with the randomness passed in)

**Specifications and rules to read first:**
- the Falcon round-3 specification v1.2; PQClean's `falcon-padded-*`; the padded encoding as `T/docs/contracts/accounts.md`
  and `T/smartcontracts/evm/src/ua/FnDsa.sol` take it
- `T/docs/clients/ua-libraries.md` CLI-UAL-66 (normative); decisions CLI-UAL-66, ARCH-POS-18 (why wasm32 must sign),
  ARCH-POS-24 (the vendor rule), CTR-UA-40 (the kinds; the FIPS 206 risk accepted)
- `T/docs/audit/audited/vendor-falcon-rs.md` (the first audit: FR-1 to FR-12 and the timing-test list)

**Invariants to check (beyond section 5):**
1. **A faithful port.** Under `fpemu` each function equals the round-3 C PQClean ships, function by function: the integer
   tables (`PRIMES`, `REV10`, the key-generation Gaussian table, `GMb`, `iGMb`), NTT and FFT, the sampler, key generation with
   its restarts, encoding and decoding, the norm bound, verification. Name every difference and whether it changes a key, a
   signature or a verdict.
2. **No hardware float.** No `f64` operation or `libm` call on any path the glue reaches (`fpr/native.rs` not compiled);
   the known differences FR-1 (`fpr_expm_p63` in emulated Horner form: another, equally valid signature with probability
   about 2^-39 per signature) and FR-2 (signed-zero semantics, unreachable with hashed targets) and nothing larger.
3. **Determinism and parity.** A seed gives PQClean's key pair byte for byte; `rnd = nonce || sampler seed` as `seeded.c`
   `do_sign`; the padded retry continues on the same stream; the glue takes no caller RNG where the spec forbids it.
4. **Verify path.** Every FN-DSA vector row (`tests/fndsa/rows.rs` and the rows under `T/smartcontracts/vectors/`: 220, 48
   accept and 172 refuse) gives PQClean's verdict; header byte, lengths, padding and the norm checked before use; no panic
   reachable from an untrusted key, signature or message.
5. **Secrets and timing.** The secret key, the expanded key, the sampler state and a rejected padded candidate (FR-6) wiped;
   constant time by reading on the signing path (the record's timing-test list: the `fpr::emu` operations, the sampler, FFT,
   the key load, `prng`); `hash_to_point_vartime` only ever on the public `ua_msg` (FR-7).
6. **The glue's boundary.** Only `falcon::falcon::*` used (FR-8); named errors for the sampler's panic and key generation's
   give-up after 1,000 tries (FR-9); the dependency gated to wasm32 (FR-12); verify after sign (FR-12); the routing cannot
   pick falcon-rs natively or PQClean on wasm32; refusals equal on both paths.
7. **The tree is the published package.** The pins in `scripts/vendor.sh`, `VENDORED.md`'s provenance, nothing edited after
   unpacking; the audit's tree id recomputed as stated (FR-3).

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/docs/audit/audited/vendor-falcon-rs.md` (Fable, 2026-11-26, at `5120ac3c5`, tree `57a1aa39…`: FR-1 to FR-12; give each
  one's state at the tag)
- `T/vendor/pqclean-falcon-seeded.VENDORED.md` and the T0 seeded-keygen comparison (Q1 of the `ua-rs` signing entry in
  `T/docs/decisions.md`)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/clients/runs/2026-11-26-ua-rs-wasm-fndsa-summary.txt` (220 rows equal to PQClean natively and in wasm32, 48 wallet
  cases byte-equal, 12 glue mutants killed), `T/clients/ua-rs/runs/2026-11-26-ua-rs-wasm-fndsa-mutants.py`,
  `T/clients/ua-rs/tests/fndsa/wasm/run.sh` (by hand: FR-4), the CI `scripts/vendor.sh check` rows of the tag's PR, and the
  tag's own client gate summary

**Also accepted for this unit (do not report):**
- `fndsa1024` on the Falcon round-3 specification v1.2, the FIPS 206 risk accepted (CTR-UA-40 Q1)
- key generation is variable time by design (restarts); the parts the record lists as not covered, unless the glue reaches
  them

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-26). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CLI-UAL-66 and ARCH-POS-24 against the glue and the tree; `VENDORED.md` and the audit record's states against the code at the tag. |
| 2 | Cryptography | Leads within the unit: invariants 1-4, the port against the round-3 C function by function; the sampler, key generation, the norm bound and the padded encoding. |
| 3 | Security | A wasm32 key or signature that differs from the native one (another UA for the same seed, or signatures the contracts refuse); a signature valid for another message; the routing choosing the wrong path. |
| 4 | Rules that do not bend | Maximal support (ARCH-POS-18): both Falcon kinds key, sign and verify on wasm32; fail closed; no decryption oracle (none applies: say so). |
| 5 | Secrets and privacy | Invariant 5: wipes of every secret buffer, no secret in an error or `Debug`, constant time on the signing path by reading. |
| 6 | Robustness and denial of service | Untrusted keys and signatures: lengths before parsing, no panic, no unbounded loop; key generation's give-up. |
| 7 | Failure handling | Named errors from the glue for every failure of the library (FR-9); a failed signing leaves no partial state. |
| 8 | Consistency across languages and layers | The same keys, signatures and verdicts as PQClean (native `ua-rs`), clientkeys `pq.js` and `FnDsa.sol` on the shared rows. |
| 9 | Contract specifics | N/A: no contract code (the contract's verifier is unit `evm-ua-verifiers`). |
| 10 | Performance and cost | Sign and key-generation time on wasm32 with emulated floats, by reading only (no timing run). |
| 11 | Interfaces and misuse | The glue's API: no caller RNG, no secret message on the variable-time path (FR-7), the hidden `pub` functions not reachable (FR-8). |
| 12 | Tests | The 220 rows and their refusal edges (FR-11), the native / wasm32 parity over many seeds (FR-5), the wasm32 gate in CI (FR-4), the 12 glue mutants. |
| 13 | Operations and the supply chain | Leads within the unit: the crate sha256 and tree pins, the upstream commit, the MIT licence, nothing edited; `scripts/vendor.sh check` in CI; the vendored `SECURITY.md` contact (FR-12). |

## 9. Report format (Markdown, English)

```
# vendor-falcon-rs: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### VFR-1 [P1] <short title>
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
