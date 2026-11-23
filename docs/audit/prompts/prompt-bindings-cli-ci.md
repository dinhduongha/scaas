# AI audit prompt, unit `bindings-cli-ci` (DRAFT, 2026-11-24)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-bindings-cli-ci.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.1-sol-high-bindings-cli-ci.md`, `20261120-09-agy-gemini-4-argon-high-bindings-cli-ci.md`). Use the tool's
  configured model and effort; do not override them. The unit name is always last.
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

The `ua-*` bindings run inside apps of every language over `libscaas_ua_c`; `scaas-cli` is a tool that prepares and signs; CI
and the supply chain decide what is tested, built and pushed. Attackers and failure modes: a host app that misuses a binding
(lifetimes, threads, the garbage collector, finalizers, callbacks); an input that crosses a language boundary (strings,
lengths, encodings, exceptions); a malicious or compromised dependency, or a lockfile update that pulls one; a pull request
that steers CI (an untrusted input in a `run:` step, a job that `ci_changes.py` skips for a path it should cover, a check that
always passes); a secret, a key or a temp path that reaches a commit or a push. Goals: memory unsafety, a secret in a
host-language string, log or exception, a signature the user did not review in the CLI, a binding that diverges from the C
ABI, a job skipped for a change it should test, an unpinned or advisory-ridden dependency in a release signer, a secret pushed.
Prefer a concrete call sequence to a pattern match. Across units: every optimisation that replaced code with shared code, a
library or a module (DELEGATECALL) must keep behaviour; say so when it does not.

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

## 8. Your unit: `bindings-cli-ci`

The `ua-*` bindings beyond their FFI edge, `scaas-cli`, and CI with the supply chain (owner 2026-11-24). Unit `ua-rs-boundary`
audits the C ABI and each wrapper **at its FFI boundary**; this unit audits the rest of each binding (its own logic, types,
errors, memory and thread rules as the host language sees them), the CLI, and the checks that guard every push.

**Scope (paths under `T/`):**
- the bindings over `libscaas_ua_c`: `clients/ua-c/` (beyond the ABI: `include/scaas_ua.h` against the Rust exports, the
  C tests), `clients/ua-cxx/` (C++: RAII, `include/scaas_ua.hpp`, `src/wallet.cpp`, `src/wallet.rs`), `clients/ua-qt/`,
  `clients/ua-cs/` (`Scaas.Ua/`: `SafeHandle`s, `Wallet.cs`, `Registry.cs`, `KeyData.cs`, `Ua.cs`), `clients/ua-py/`
  (`scaas_ua/__init__.py`, `wallet.py`), `clients/ua-go/` (`ua.go`, `keydata.go`, `registry.go`, `wallet/`, cgo),
  `clients/ua-dart/`
  (the pure-Dart reader: `lib/src/{ua,keydata,keccak,table}.dart`), `clients/ua-dart-frb/` (flutter_rust_bridge: `rust/src/api/`,
  `lib/src/`); each binding's tests and vector readers
- `clients/scaas-cli/src/` (`main.rs`, `calls.rs`, `config.rs`, `flex.rs`), its tests, `Cargo.toml`, `Cargo.lock`
- CI: `.github/workflows/ci.yml` (every job, its triggers, permissions and the header that lists the commands),
  `.github/ci_changes.py` (which job runs for which path)
- the supply chain: `clients/*/deny.toml`, `clients/*/.cargo/audit.toml`, every `Cargo.lock` and `package-lock.json`, the
  `cargo deny` / `cargo audit` / `npm audit` jobs, `rust-toolchain.toml`, the pinned tool versions in CI
- the scripts: `scripts/evm_libs.sh` (the `smartcontracts/evm/lib/` commit and sha256 pins), `scripts/format.sh`,
  `scripts/capped`, `scripts/check_test_features.py`, `scripts/docs_check.py` (the parts that refuse consumer names, machine
  paths and temp paths), `scripts/size_gate.py`; the CI steps "no machine paths in tracked files" and "no temp paths in
  tracked files"
- not in scope: the C ABI's own contract (`ua-rs-boundary`), the SDK's uniffi bindings (`scaas-sdk`), `*/legacy/`

**Specifications and rules to read first:**
- `T/docs/clients/ua-libraries.md` (CLI-UAL-*: the wrappers, handles, errors), `T/docs/clients/scaas-sdk.md` (the CLI rows of
  CLI-SDK-*), `T/AGENTS.md` "Security", "Machine" and "Traps"; decisions ARCH-POS-16 (no machine path), the T26 decision (137)
  (the C ABI stays version 7)

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **Memory and handles in each host language.** A handle freed exactly once (RAII, `SafeHandle`, Go finalizers with
   `runtime.KeepAlive`, Python `__del__` / context managers, Dart `Finalizer` / frb opaque types); no use after free when the
   host's GC runs early; thread rules as documented; a callback or exception never unwinds across the C ABI.
b. **Secrets in host strings.** No key, seed, passphrase or plaintext copied into an immutable host string (`System.String`,
   Python `str` / `bytes` kept, Go `string`, Dart `String`), a log, an exception message or a `toString`; buffers zeroed where
   the host allows.
c. **The same surface and the same bytes.** Each binding exposes what `scaas_ua.h` exposes, maps every error code, and reads
   the same vector rows (`T/smartcontracts/vectors/`); the pure-Dart `ua-dart` reader equals `ua-rs` on its rows.
d. **The CLI asks first.** Every signing command shows the review of what it signs before signing (prepare -> review -> sign,
   `every_signing_command_asks_first`); `dev-profiles` (chain 31337, `Depth(0)`, B-22) never on by default; config
   (`config.rs`) holds names of keys or env variables, never a secret; no secret in its output or errors.
e. **CI covers what it claims.** `ci_changes.py` runs every job whose inputs changed (a path a job reads that does not trigger
   it is a finding); no `pull_request_target` or untrusted input interpolated into a `run:` step; least `permissions:`; tool
   versions pinned; the header's command list equals the jobs.
f. **The supply chain.** Every dependency pinned (lockfiles committed and resolved with `--locked`), `cargo deny` and
   `cargo audit` over every lockfile that reaches a release signer, `npm ci --ignore-scripts` and `npm audit`; each ignored
   advisory with a recorded reason (`crypto-bigint` RUSTSEC-2026-0387 known); `scripts/evm_libs.sh` commit and sha256 pins
   checked; no build-time network fetch of code; no built binary published (repo rule).
g. **Secret and path checks.** The temp-path and machine-path steps match what `AGENTS.md` refuses and cannot match
   themselves away; `docs_check.py` refuses consumer names; there is no gitleaks in CI by design, so say what does guard a push
   (the pre-push scan is local) and whether any CI step prints a secret.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `scratchpad/review-t21/` (part 5, the boundary and wrappers), `scratchpad/sdk-binding-review/`, `scratchpad/pr-a-review/`
- `scratchpad/sdk-review-20261123-0621/` (the CLI rows of T26: A-5, A-6, B-22)

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- the tag's client gate summary: `ua-c`, `ua-cxx`, `ua-qt`, `ua-cs`, `ua-py`, `ua-go`, `ua-dart`, `ua-dart-frb` rows, `cli` rows,
  `cargo deny` / `cargo audit` rows; `format.sh --check`; the CI run of the tag's PR

**Also accepted for this unit (do not report):** no gitleaks in CI (`AGENTS.md`: the scan before a push is local and
separate); `crypto-bigint` RUSTSEC-2026-0387 through `frost-secp256k1` =3.0.0 (report only a new path from a release signer);
T21 ledger rows REJECT or LATER and O1-O8.

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | CLI-UAL-* for each binding, the CLI rows of CLI-SDK-*, `AGENTS.md` Security and Machine rules for the scripts and CI; the CI header's command list against the jobs. |
| 2 | Cryptography | N/A for primitives (none in the bindings, CLI or CI); check only that no binding re-encodes or truncates a crypto object, and that the CLI signs only through `ua-rs` / the SDK. |
| 3 | Security | The CLI's signing commands (review before sign); CI permissions and untrusted inputs (invariant e); a binding that lets a host caller pass a handle from another vault. |
| 4 | Rules that do not bend | Explicit parameters in each binding's API (named fields, no packed blobs); no machine path committed (ARCH-POS-16); nothing the bindings or CLI do that the C ABI forbids. |
| 5 | Secrets and privacy | **Leads within the unit.** Invariants b and d: secrets in host strings, exceptions, logs; CLI config and output. |
| 6 | Robustness and denial of service | Bounded input in each binding before it reaches the C ABI; a CI job that can hang or be starved. |
| 7 | Failure handling | Every error code mapped; no exception or panic across the boundary; a failed CLI command leaves no signed artifact behind. |
| 8 | Consistency across languages and layers | Each binding's surface and vector rows equal the C ABI's and `ua-rs`'s (invariant c); the C ABI version 7 in every binding. |
| 9 | Contract specifics | N/A: no contract code (CI's `contract-evm` job is checked as CI: that it runs the per-set and size gates `AGENTS.md` requires). |
| 10 | Performance and cost | N/A except CI cost: a job that runs the full matrix on every path change, or skips one it should run. |
| 11 | Interfaces and misuse | **Leads within the unit.** Each binding idiomatic and hard to misuse (ownership, threads, disposal); the CLI's defaults safe. |
| 12 | Tests | Each binding's tests can fail; `check_test_features.py`; CI steps that always pass (a `|| true`, a grep that matches itself). |
| 13 | Operations and the supply chain | **Leads this dimension for the repository.** Invariants e, f, g: pins, `cargo deny` / `cargo audit` / `npm audit`, `evm_libs.sh`, `format.sh`, the temp-path and machine-path checks, SPDX headers, licences of new dependencies. |

## 9. Report format (Markdown, English)

```
# bindings-cli-ci: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### BCC-1 [P1] <short title>
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
