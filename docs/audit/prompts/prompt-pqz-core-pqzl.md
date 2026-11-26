# AI audit prompt, unit `pqz-core-pqzl` (DRAFT, 2026-11-16)

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

Write exactly one file: `scratchpad/ai-audit/results/<YYYYMMDD-HH>-<tool>-<model>-<effort>-pqz-core-pqzl.md`

- `<YYYYMMDD-HH>`: local date and hour at which you start; `<tool>`, `<model>`, `<effort>`: what actually runs, lower case, no
  spaces (e.g. `20261120-09-codex-gpt-6.2-astra-high-pqz-core-pqzl.md`, `20261120-09-agy-gemini-4-argon-high-pqz-core-pqzl.md`). Use the tool's
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

## 8. Your unit: `pqz-core-pqzl`

The lattice proof system `pqzl`: the Rust production core and the C oracle.

**Scope (paths under `T/`):**
- `pqz-core/pqzl/rust/src/` (production; `bin/` and `testkit.rs` are tools), `pqz-core/pqzl/rust/tests/`
- `pqz-core/pqzl/src/*.c`, `*.h` (the C oracle)
- read-only: `pqz-core/params/sets/<set>/set.toml` for the bounds the code relies on (unit `pqz-core-params-vectors` audits the generator)

**Specifications and rules to read first:**
- `T/pqz-core/pqzl/README.md` and `T/docs/contracts/pq-zero-knowledge.md` (the relations, CTR-PQZ-03 parameters at or above Kyber-512 core-SVP, the `R_TXM` e2 bound per vector <= 64 in l2, beta 446 for the shared-randomness hints)
- spec `T/docs/superpowers/specs/2026-11-13-pqz-three-keys.md` (split relation `R_TXS`, the `v_f` randomness group, `proofSystemId`)

**Invariants to check (beyond section 5):**
1. Each relation (`R_REG`, the split `R_TXS`, `R_TXM` for op 7 with its randomness groups, `v_f`, `R_BURN`, refresh, disclosure with the kind byte tied to the form, PQZL v6) proves what the statement claims; every public input is bound into Fiat-Shamir.
2. Rejection sampling, challenge sets, norm bounds and the NTT / CRT arithmetic as specified; no overflow at the largest set `n2816-kmax65536`.
3. Constant time and zeroize wherever the prover touches secrets (the review fix E, `ct.rs`).
4. C oracle = Rust = wasm32 byte for byte; the `test-hooks` feature never in a production build.
5. Verifier decode bounded by length and depth; no panic or abort on any input.
6. **The specialised verifier's norm checks equal the general verifier's, line by line** (added 2026-11-22, owner approval
   of that day). `pqz-ffi` dispatches PQZL to the specialised verifier (`T/pqz-core/ffi/src/lib.rs`, `pqzl::verify_fast`), so a
   bound it applies more loosely than the general verifier is a forgery. `T/docs/research/pqz-specialised-verifier.md` §7 says
   the norm-check review is "still due"; the one review so far, `docs/reviews/specs/2026-10-13-pqz-sv-review.md` in the main
   checkout (git-ignored, local), read the C code only, at `dde1fa6`, before `proofSystemId` v2, `sv.rs`, the four sets and
   the three-key relations: read it, and give its findings in the closure table.
   - Compare C `T/pqz-core/pqzl/src/pqz_sv.c` (the setup constants and the verify body) with `pqzl/lazer/lnp-tbox.c`
     (`lnp_tbox_verify`, `_lnp_tbox_check_z34`), `pqzl/lazer/lnp-quad.c` (`lnp_quad_verify`), `lnp-quad-many.c` and
     `dcompress.c`; Rust `T/pqz-core/pqzl/rust/src/sv.rs` (`setup`, `verify_body`) with `rust/src/proof/{tbox,quad,abdlop}.rs`;
     and C `pqz_sv.c` with Rust `sv.rs`.
   - Every bound, each with its counterpart or "none": ‖z1‖² ≤ ⌊2·m1·d·962·2^(2·log2stdev1) / 400⌋ (the specialised form
     `z1bnd` = ⌊t·2^(2·log2stdev1 − 4) / 25⌋: check the identity, and the general verifier's `int_div` with aliased operands);
     ‖z3‖² ≤ `Bz3sqr`; ‖z4‖∞ ≤ `Bz4`; h's coefficients 0 and d/2 zero, on centred values; ‖hint‖∞ ≤ m (LaZer's comment says
     2·linf, both codes use linf: say which one the extractor needs); ‖(z21, w − γ·w1)‖² ≤ `Bsqr` (P6-Z21, lazer#26) with
     UseHint and the centring identical; each exact-ℓ2 bound `l2Bsqr[i]` as it enters (the o(2^j) powers, P6-L2); c ∈ [−8, 8];
     and any other bound or range check the general verifier applies. Same representative (centred or [0, q)), same ≤ or <,
     each check reached; a `setup` refusal makes init fail, never accept.
   - At all four sets, `n2048-kmax1024`, `n2304-kmax4096`, `n2560-kmax16384`, `n2816-kmax65536`, for every relation and shape
     a set builds (`R_REG`, `R_TX`, `R_TX0`, `R_TXS`, `R_TXS0`, the `R_TXM` shapes of `pqz_txm*_params.h`, `R_BURN`, `R_DS`,
     `R_DR`), in C and in Rust.
   - Each bound's source: the bounds are derived, not written in `set.toml`. Trace each from
     `T/pqz-core/params/sets/<set>/set.toml` through `gen_set.py` and the codegen (`pqzl/params/codegen/lnp-tbox-codegen.sage`,
     the set's `codegen.txt`) to the generated `pqz_*_params.h` and the Rust params (`pqzl/rust/src/params/`), and say that the
     C and Rust specialised and general verifiers all read the same value.
   - Overflow and width of each comparison: `l2_sum` / `l2_le` (the 2^31 coefficient cut-off, the running sum below 2^62),
     `uabs64` of `INT64_MIN`, the `int_u64` conversions, `z1bnd` < 2^62 up to log2stdev1 = 20, the four-prime CRT range
     (P/2 ≈ 2^119) against every sum the code bounds, and in Rust every `unsigned_abs`, `as` cast and shift.
   - A proof that fails only one norm must be refused by both verifiers, in C and in Rust. Use the cheating fixtures in
     `T/pqz-core/pqzl/rust/tests/fixtures/cheating/` (`n2048-kmax1024` at the top, the other three sets in `<set>/`;
     `export.sh` makes them): `norm_z1_over`, `norm_w_over`, `norm_z21_big`, `norm_z3_over`, `norm_z4_over`, `l2dom_s_over_A`,
     `l2dom_s_over_B`, `tx_over`, with `norm_honest` and `l2dom_honest` as controls. Tests: `rust/tests/sv_diff.rs`
     `cheating_rejected` (Rust specialised), `rust/tests/vectors.rs` `cheating_proofs_reject` (Rust general),
     `pqzl/sv/review/review.sh norm` and `zdiff` (C, proofs made at run time). Say which of the four verifiers (C / Rust ×
     specialised / general) at which set each case reaches, and name the fixtures to request where none exists: h with a
     non-zero coefficient 0 or d/2; one exact-ℓ2 bound broken alone, per equation (`R_TX`, `R_TXM`); z1, z3 and z4 at exactly
     the bound (accept) and one unit above (refuse); a C run of the committed fixtures against `pqz_verify_fast`. The hint
     bound is said to be unreachable by encoding (`sv.rs` `hint_bound_unreachable_by_encoding`): check the argument.

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
| 1 | Conformance | CTR-PQZ-03 (parameters at or above Kyber-512 core-SVP), the `R_TXM` e2 bound, beta 446, the three-key spec's split relation `R_TXS` and `v_f` group, PQZL v6, against `pqzl/rust/src/` and `pqzl/src/*.c`; `pqzl/README.md` claims each with code and a test. |
| 2 | Cryptography | Leads within the unit (with `crypto-pqz`): soundness of every relation (`R_REG`, `R_TX`, `R_TX0`, `R_TXS`, `R_TXS0`, `R_TXM`, `R_BURN`, `R_DS`, `R_DR`, refresh); Fiat-Shamir binding of every public input; rejection sampling, challenge sets, norm bounds, NTT / CRT; the specialised verifier's norm checks equal the general verifier's line by line (invariant 6), read vertically C `pqz_sv.c` / `lazer/` against Rust `sv.rs` / `proof/{tbox,quad,abdlop}.rs`; constant time and zeroize in the prover (`ct.rs`). |
| 3 | Security | A proof that passes one verifier and fails the other (a forgery through the dispatched `verify_fast`); a statement field the transcript omits; `test-hooks` code reachable in a production build. |
| 4 | Rules that do not bend | N/A for on-chain rules except the oracle rule: nothing in the core decrypts; the PQZ ciphertext format kept intact (never only a hash) is the contracts'. |
| 5 | Secrets and privacy | Secrets in the prover (witness, randomness) zeroized and not logged; timing of secret-dependent code (`ct.rs`). |
| 6 | Robustness and denial of service | Verifier decode bounded by length and depth; no panic or abort on any input; overflow at `n2816-kmax65536` (the widths of invariant 6). |
| 7 | Failure handling | Every verify error fails closed (reject, never accept on an internal error); a `setup` refusal makes init fail. |
| 8 | Consistency across languages and layers | C oracle = Rust = wasm32 byte for byte (proofs, verdicts, transcripts) at all four sets; the bounds read from the same generated params in C and Rust. |
| 9 | Contract specifics | N/A: no contract code in this unit (the Solidity verifier path is the precompile's; `evm-tokens-pqz` reads its answer). |
| 10 | Performance and cost | Prove and verify time and memory per set (read from the gate logs, no runs); the wasm32 prover's budget (CTR-PQZ-18, measured elsewhere). |
| 11 | Interfaces and misuse | N/A beyond the FFI (unit `pqz-core-pqzh-stmt-ffi`). |
| 12 | Tests | The cheating fixtures per norm at four sets (invariant 6), each refused by all four verifiers; KATs; the fuzz corpora; tests that cannot fail (a fixture the verifier refuses for another reason). |
| 13 | Operations and the supply chain | Pinned dependencies of the Rust crate; SPDX headers; no machine path in `runs/` summaries. |

## 9. Report format (Markdown, English)

```
# pqz-core-pqzl: <tool> <model> <effort> at <SHA>
Summary: counts P0 / P1 / P2 / P3 / info; one line per P0 and P1.

## Findings
### PQL-1 [P1] <short title>
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
