# AI audit prompt, unit `scaas-matrix` (2026-11-28)

**Landed on `dev`; the whole unit is at the tag.**

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-scaas-matrix.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-scaas-matrix.md`, `20261120-09-agy-gemini-4-argon-high-scaas-matrix.md`). Use the tool's
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

`scaas-matrix` is the one Matrix client crate of the repository (CLI-PQC-20, CLI-MTX-01): matrix-sdk, opened once per user
profile directory, with the store key the caller gives it, and the PqChat transport riding the same client. `pqchat-transport`
is the trait-only crate between it and `pqchat-core`, so neither depends on the other. Matrix end-to-end encryption itself is
matrix-sdk's (a third-party dependency, read for how this crate configures and calls it, not audited line by line).
Attackers: a malicious or compromised homeserver (it sees metadata, serves, delays, drops, replays or reorders any event,
forges unencrypted room state, redirects); another Matrix user (an invite, a crafted or oversized event, room state that tries
to turn a PqChat room into a chat room or the reverse, a flood); a push gateway; a local attacker who reads the profile
directory, matrix-sdk's store, logs, crash reports or a backup; a second instance of an app on the same profile. Goals: the
store key or the session token on disk in clear, in a log or in an error; a Matrix room and a PqChat room mixed, so a PqChat
event is shown as chat or a chat event reaches `pqchat-core`; an ephemeral signal (read receipt, typing, presence) or a push
content leaking against the defaults; a plain `http` homeserver or a downgrade by redirect; an unbounded decode or queue that
exhausts memory; two clients writing one store; anything sent in answer to a PqChat event (a receipt, a reply, a typing
notice) that tells its sender whether it decrypted (ARCH-POS-13, CLI-PQC-07).

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

## 8. Your unit: `scaas-matrix`

**Added 2026-11-28 (controller call under the owner's auto-run grant of 2026-11-25; the owner may veto). Landed on `dev`:
the whole unit is at the tag.** The Matrix client crate and the PqChat transport trait (CLI-PQC-19, CLI-PQC-20).

**Scope (paths under `T/`):**
- `clients/scaas-matrix/`: `src/lib.rs` (the client: one per profile directory under the OS file lock, the store key from the
  caller, the session in the encrypted store, the `https` check, the two room kinds, encrypted direct rooms, SAS
  verification, backup off, pushers, the named errors), `src/policy.rs` (the private defaults, push rules, the bounds),
  `src/transport.rs` (the PqChat transport over the same client, CLI-MTX-10); tests `tests/e2e.rs`, `tests/profile.rs`,
  `tests/deps.rs` (the dependency rule); `runs/2026-11-27-scaas-matrix-summary.txt`, `runs/2026-11-27-scaas-matrix-mutants.py`
  and its records `-r1-mutants.txt`, `-t9-mutants.txt`; `Cargo.toml`, `Cargo.lock`, `deny.toml`, `.cargo/audit.toml`
- `clients/pqchat-transport/`: `src/lib.rs` (the trait `pqchat-core` sends and reads through, `EVENT_TYPE`
  `net.scaas.pqchat.v1`, the content bound, the conformance test every implementation passes), `Cargo.toml`, `Cargo.lock`
- read only: `clients/pqchat-core/src/matrix.rs` (the re-export and the event codec; unit `app-cores`), the user profile's
  Matrix store key (CLI-UPR-29; its sealing is unit `scaas-profile`, pending landing)

**Specifications and rules to read first:** `T/docs/clients/scaas-matrix.md` (CLI-MTX-01 to -12); decisions CLI-PQC-19,
CLI-PQC-20, CLI-MTX-01 to -06 with their Changes, CLI-UPR-29; spec `T/docs/superpowers/specs/2026-11-27-scaas-matrix.md`, plan
`T/docs/superpowers/plans/2026-11-27-scaas-matrix.md`; `T/docs/clients/pqchat-core.md` (CLI-PQC-05 the transport, -07 drops,
-10 envelopes while locked); `T/docs/clients/stack.md` (which crate depends on which).

**Invariants to check (beyond section 5; each a finding when it fails):**

a. **The dependency rule** (CLI-MTX-01): `scaas-matrix` depends on matrix-sdk and `pqchat-transport`, never on `scaas-sdk`,
   `pqchat-core` or `ua-rs`; `pqchat-transport` holds no Matrix crate; `tests/deps.rs` can fail.
b. **One client per profile directory** (CLI-MTX-02): an OS advisory lock held while the client is open, a second open
   refused by name, the lock released on every exit path, a stale lock never stealing a live one.
c. **The store key and the session** (CLI-MTX-03, -04): the key comes from the caller, stays in memory, is zeroized, and is
   never derived, written, logged or put in an error here; a wrong key is a named error with the store untouched; the
   session token lives only in the encrypted store; the homeserver URL is `https`, and no redirect or discovery step
   downgrades it.
d. **Private defaults** (CLI-MTX-05, -08): read receipts private (`m.read.private`), no typing, no presence; nothing
   ephemeral in a PqChat room; no pusher by default, `event_id_only` when one is set, none for a hidden profile; PqChat
   pushes only on opt-in. Check each default where it is set and every path that could send the signal anyway.
e. **Two room kinds that never mix** (CLI-MTX-06): how a room is classified, whether a homeserver or another user can flip
   the class (room state, tags, invites, a direct-room flag), what each kind accepts and drops.
f. **Encrypted direct rooms, SAS verification, key backup off** (CLI-MTX-07).
g. **Bounded decodes and queues** (CLI-MTX-09): event content above `pqchat-transport`'s bound dropped before it is parsed,
   JSON depth bounded, every queue bounded with a stated overflow rule; a homeserver flood cannot exhaust memory.
h. **The transport** (CLI-MTX-10): PqChat events ride the same client and match the conformance test of
   `pqchat-transport`; nothing is sent in answer to a PqChat event (no receipt, reply or typing notice), so the transport
   adds no decryption oracle (ARCH-POS-13, CLI-PQC-07).
i. **Errors** (CLI-MTX-12): named, with nothing secret; native first (CLI-MTX-11): report wasm32 only where code claims it.

**Prior reports (do not re-report what they list as fixed; give the closure table):** the crate's review
`scratchpad/scaas-matrix-review-20261127-1552/` and its re-checks `scratchpad/scaas-matrix-recheck-20261127-1928/`,
`scratchpad/scaas-matrix-recheck2-20261127-2200/` (local; `STATUS.md` in each); the Changes under CLI-MTX-01 to -06.

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
`T/clients/scaas-matrix/runs/2026-11-27-scaas-matrix-summary.txt` and its mutant records; the tag's own client gate summary.

**Areas** (ARCH-POS-22, `T/docs/review.md` §2). This unit is one layer; it names the other areas so its findings land
where they belong.

| Area | Scope here |
|---|---|
| Layer | `clients/scaas-matrix/`, `clients/pqchat-transport/` |
| Cross-layer | the event codec in `pqchat-core` (`matrix.rs`) against `pqchat-transport`'s type and bound; the store key the user profile seals (CLI-UPR-29) against what this crate assumes of it; end to end: unit `cross-layer` |
| Cryptography | none of its own: matrix-sdk's encryption is configured, not implemented, here; the store key's sealing is read vertically by `crypto-kem-seal` |
| Adversarial | the homeserver, another Matrix user, a push gateway, a local reader, a second instance (section 6); across the system: unit `adversarial` |

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1 and the brief template of §5). Apply every dimension within this
unit's scope; each row says what to hunt here and which area leads it. A row marked `N/A` gives its reason and stays. Every
finding names its dimension number (section 9).

| # | Dimension | Lead area | What to hunt in this unit |
|---|---|---|---|
| 1 | Conformance | Layer | CLI-MTX-01 to -12, CLI-PQC-19, CLI-PQC-20, CLI-UPR-29 against the code; the doc's status tags against the built code. |
| 2 | Cryptography | Cryptography | N/A as a primitive: matrix-sdk implements Matrix encryption; hunt only its configuration (encrypted direct rooms, SAS, backup off, invariant f) and the store key's handling (invariant c). |
| 3 | Security | Adversarial | Room classes that an outsider can flip (invariant e); the instance lock (invariant b); the `https` check and redirects (invariant c). |
| 4 | Rules that do not bend | Layer | No decryption oracle at the transport (invariant h); every chat stays recoverable without this crate's local state for PqChat (state-only recovery belongs to `pqchat-core`). |
| 5 | Secrets and privacy | Layer | The store key and the session token (invariant c); receipts, typing, presence, pushers (invariant d); no secret in logs, errors or `Debug`. |
| 6 | Robustness and denial of service | Layer | Bounded decodes and queues (invariant g); a homeserver that floods, stalls or serves huge events. |
| 7 | Failure handling | Layer | A wrong store key, a held lock, a lost session: named errors, nothing half-written, the lock released. |
| 8 | Consistency across languages and layers | Cross-layer | `EVENT_TYPE`, the content bound and the conformance test equal in `pqchat-transport`, `scaas-matrix` and `pqchat-core`'s codec. |
| 9 | Contract specifics | N/A | No contract code. |
| 10 | Performance and cost | Layer | Sync and queue sizes on mobile; no unbounded store growth (no timing runs). |
| 11 | Interfaces and misuse | Layer | The client API hard to misuse: no call that opens a client without the lock or the caller's key, no call that sends an ephemeral signal into a PqChat room. |
| 12 | Tests | Layer | `tests/deps.rs` and the e2e can fail; the mutant records (`-r1-`, `-t9-`) cover each check; the conformance test run against this implementation. |
| 13 | Operations and the supply chain | Layer | matrix-sdk's version and features, `Cargo.lock`, `cargo deny` / `cargo audit` (`deny.toml`, `.cargo/audit.toml`), its licence and size; SPDX headers. |

## 9. Report format (Markdown, English)

```
# scaas-matrix: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### SMX-1 [P1] <short title>
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
