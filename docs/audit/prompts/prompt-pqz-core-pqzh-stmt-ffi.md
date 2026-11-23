# AI audit prompt, unit `pqz-core-pqzh-stmt-ffi` (DRAFT, 2026-11-16)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-pqz-core-pqzh-stmt-ffi.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-pqz-core-pqzh-stmt-ffi.md`, `20261120-09-agy-gemini-4-argon-high-pqz-core-pqzh-stmt-ffi.md`). Use the tool's
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

Attackers: a malicious prover (soundness: a false statement accepted, money printed); a malicious input to a verifier (DoS by
length or depth, a panic, an abort, a stack overflow); a side channel on the prover's secrets (constant time, zeroize); a
divergence between implementations (C oracle, Rust production, wasm32, generic and specialised verifiers, the Solidity statement
builder) that one side accepts and another refuses; a public input not bound into Fiat-Shamir; a zero-knowledge leak; a holder
tool that becomes a decryption oracle. The C core is an oracle, not production; `pqz-ffi` defaults to Rust.

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

## 8. Your unit: `pqz-core-pqzh-stmt-ffi`

The Ligero-based proof system `pqzh`, the statement builder `stmt`, and `pqz-ffi` (dispatch on `proofSystemId`, the opening and seal code, wasm32 and the wallet wasm crate).

**Scope (paths under `T/`):**
- `pqz-core/pqzh/ligero/src/`, `pqz-core/pqzh/ligero_params.py`, `pqz-core/pqzh/evm_model.py` (read)
- `pqz-core/stmt/src/`
- `pqz-core/ffi/src/` (incl. `opening.rs`, `pqzl.rs`, `pqzl/`, `memo.rs`, `fixture.rs`, `selftest.rs`), `pqz-core/ffi/wasm/`, `ffi/wallet-wasm/`, `ffi/offchain/`, `ffi/pqz_ffi.h`, `ffi/build.rs`

**Specifications and rules to read first:**
- `T/pqz-core/pqzh/README.md`, `T/pqz-core/ffi/README.md`, `T/docs/contracts/pq-zero-knowledge.md`, spec `2026-11-13-pqz-three-keys.md` (sealed opening, holder checks), decisions ARCH-POS-13 with its Changes; CLI-SGN-51 (the sealed-opening check)

**Invariants to check (beyond section 5):**
1. Ligero soundness: field, rate, queries, Merkle commitments, the role tags (PQZH v4); every public input in the transcript; zero knowledge as claimed.
2. `stmt` builds the same statement bytes as the Solidity side (`T/smartcontracts/evm/src/pqz/PqzLayer.sol`, `PqzCore.sol`) at all four sets.
3. `pqz-ffi` dispatch: each `proofSystemId` to exactly one verifier; Rust by default, C only as oracle; error mapping fails closed.
4. `opening.rs`: re-encrypt and compare, never decrypt a credit with `s`; `check_recipient` / `check_auditor`; zeroize of `m`, `e`, `ss_x`, `exp.vs`; the seal-side guard against a repeated `seed_enc`; malformed KEM and truncated openings refused.
5. Bounds on proof, ciphertext and opening lengths at the boundary; wasm32 = native.

**Prior reports (do not re-report what they list as fixed; give the closure table):**
- `T/pqz-core/research/code-review-2026-10-19/`, `code-review-2026-10-25/`, `code-review-2026-10-26/` (README and per-unit files)
- `T/pqz-core/research/code-review-2026-11-13/fix-round.md`, `code-review-2026-11-15/fix-round.md`
- `T/docs/research/security-review-record.md` sections 3.1-3.2
- `scratchpad/review-3w/` (u1-u5, three-keys u1-u4, `triage.md`, `spec-pqz-three-keys.md`); `scratchpad/review-3zh/20261115-15-fable-fable5.2-high-3zh-core-g1.md`

**Gate evidence at the tag (read for what was run; a green gate proves nothing by itself):**
- `T/pqz-core/runs/gate/3zh-g2-n2048-kmax1024-summary.txt`, `3zh-g2-n2304-kmax4096-summary.txt`, `3zh-g2-n2560-kmax16384-summary.txt`, `3zh-g2-n2816-kmax65536-summary.txt` (the full gate at four sets on the final core tree), `3zh-core-g1*-summary.txt`
- `T/pqz-core/ffi/runs/2026-11-15-wallet-wasm.txt`, `T/pqz-core/ffi/vectors/runs/2026-11-13-three-keys-vectors.txt`, `T/pqz-core/fuzz/runs/2026-11-13-three-keys-regress-valid.txt`

**Dimension table** (ARCH-POS-22, `T/docs/review.md` §1; added 2026-11-24). Apply every dimension within this unit's
scope; each row says what to hunt here. A row marked `N/A` gives its reason and stays. Every finding names its dimension
number (section 9).

| # | Dimension | What to hunt in this unit |
|---|---|---|
| 1 | Conformance | `pqzh/README.md`, `ffi/README.md`, `pq-zero-knowledge.md`, the three-key spec (sealed opening, holder checks), ARCH-POS-13 and its Changes, CLI-SGN-51 against `pqzh/ligero/src/`, `stmt/src/`, `ffi/src/`. |
| 2 | Cryptography | Leads within the unit (with `crypto-pqz` and `crypto-kem-seal`): Ligero soundness (field, rate, queries, Merkle commitments, role tags PQZH v4, every public input in the transcript, zero knowledge as claimed); `stmt` bytes equal the Solidity side; `opening.rs` re-encrypt and compare (never decrypt a credit with `s`), `check_recipient` / `check_auditor`; the seal-side guard against a repeated `seed_enc`; the KEM inputs of the sealed opening. |
| 3 | Security | `pqz-ffi` dispatch: each `proofSystemId` to exactly one verifier (Rust by default, C only as oracle); a malformed KEM or truncated opening accepted. |
| 4 | Rules that do not bend | No decryption oracle in `opening.rs` or the offchain crate (`ffi/offchain`): no error, timing or output depends on decrypting an attacker-chosen value; explicit parameters at the C ABI (`pqz_ffi.h`). |
| 5 | Secrets and privacy | Zeroize of `m`, `e`, `ss_x`, `exp.vs`; no secret in an error string across the FFI or wasm boundary. |
| 6 | Robustness and denial of service | Bounds on proof, ciphertext and opening lengths at the boundary; depth of any decode; no panic across `extern "C"` or wasm. |
| 7 | Failure handling | Error mapping fails closed; the C ABI's error codes stable. |
| 8 | Consistency across languages and layers | wasm32 = native; `stmt` = `PqzLayer.sol` / `PqzCore.sol` at all four sets; the wallet wasm (`ffi/wallet-wasm`) = clientkeys `pqzopenWasm.js`; `pqz-vectors` output = `T/smartcontracts/vectors/pqz/`. |
| 9 | Contract specifics | N/A: no contract code (the statement layout it mirrors is audited in `evm-tokens-pqz`). |
| 10 | Performance and cost | Ligero prove and verify time per set from the gate logs; wasm memory. |
| 11 | Interfaces and misuse | The C ABI (`pqz_ffi.h`) and wasm exports hard to misuse: lengths passed with pointers, no implicit set. |
| 12 | Tests | Vectors checked by every reader (`pqz-vectors --check`, `pqz_kat.py --check`, `ffi/vectors/tamper.py`); opening negative rows. |
| 13 | Operations and the supply chain | `ffi/build.rs` fetches nothing at build time; pinned dependencies; SPDX headers. |

## 9. Report format (Markdown, English)

```
# pqz-core-pqzh-stmt-ffi: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### PQH-1 [P1] <short title>
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
