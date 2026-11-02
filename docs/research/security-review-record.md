> **Research note — background and rationale only, not normative; the current rules are in docs/ (see decisions.md).**

# Security and cryptographic review record

Status 2026-11-02. Every cryptographic and security review of this repository, what each one covered, what it found, what
became of it, and what no review has covered. Reviews are listed from their records, not from memory. The raw reports stay
where they are; this file is the index. Rows marked *local* point to `docs/reviews/`, which is git-ignored: those reports exist
only on the owner's machine.

**No part of this system has had an independent external audit.** Every review below was done by AI models or by the
project itself. PQZ, classical Zether and the PQ signature verifiers carry the label `UNAUDITED`. The label and a chain's
own decision are what remain: since the owner's rulings of 2026-10-31 an audit is not a deploy gate. The SCaaS mainnet 22776
still launches only after the cryptographic audit and G-LIC.

"Contracts audit" in the pre-freeze order keeps its name (owner 2026-11-02): it is an audit by AI reviewers, Codex, agy and the
Claude workflow. "Independent" and "external" in this file mean outside the project and its models.

## 1. Coverage at a glance

| Area | Latest dedicated review | Result | Changed since that review? | Gap |
|---|---|---|---|---|
| PQZL proof system, relations, parameters | 2026-10-25 at `008e196c` | fixed, then re-reviewed (r01a, r01b) | no core change on `typed-signing`; `pqz-core-m16` was a bench bug only | no external audit; G-LIC unanswered |
| PQZH (Ligero) | 2026-10-25 unit R3 | no P0 / P1 in the live path | no | external review of the Ligero ZK argument owed |
| Precompile surface (`stmt`, `ffi`, Nethermind plugin) | 2026-10-25 unit R4 | P3 items, fixed in r01b | no core change | no external audit; fuzzing is local only |
| PQ signature verifiers on chain | 2026-10-26 unit C1 | checked sound by three reviewers, hardening only | moved or edited by later rounds | P6c audit of the verifiers and the expanded-key cache owed |
| Classical Zether verifier | 2026-11-01 at `6fed9881` | sound and complete, highest finding low | `typed-signing` edits the token side | Claude models only; see §6 |
| Zether token | 2026-10-26 units C0, C3 | 1 P0, fixed | **yes**, `typed-signing`, CRV read it 2026-11-02 | Claude model only since 2026-10-26; contracts audit after the freeze |
| PQZ token | 2026-10-26 units C0, C2 | 2 P1, fixed | **yes**, later rounds, CRV read `typed-signing` 2026-11-02 | contracts audit after the freeze |
| UA registry, accounts, wallets | 2026-10-26 unit C4 | fixed | **yes**: UA-8, R2 split, typed entries | contracts audit after the freeze |
| Meta-tx, token base, factory | 2026-10-26 unit C5 | fixed | **yes**: metatx split, typed entries | contracts audit after the freeze |
| DEX and trade | 2026-10-26 unit C6 | fixed | **yes**: DEX round | contracts audit after the freeze |
| Node, relay, gateway, mesh | none dedicated | round reviews only | continuous | **part 3 of the three-part review not done** |
| `pqz-prover`, clients, wallets | none dedicated for PQZ; Zether prover seen in 2026-10-26 | round reviews only | continuous | **part 3 not done**, waits for P6h / P6i |
| Non-EVM contracts | none dedicated | round reviews, per family | continuous | add-on audit per family after each UA round |
| Chain and infrastructure | none | not reviewed | | to do before 22776 |

## 2. Register of reviews

### 2.1 Dedicated security and cryptographic reviews

| Date | Target | Scope | Reviewers and method | Result | Outcome | Record |
|---|---|---|---|---|---|---|
| 2026-08-31 | 22 specification files | design documents: architecture, Zether, meta-tx, threat model | spec audit, no code | report | input to the specs | [AUDIT_SPEC_REPORT](AUDIT_SPEC_REPORT_20260831_021000.md) |
| 2026-10-03 | per-network and design specs | design documents | Claude, one review per spec | verdicts, mostly FIX-THEN-GO; `net-ton` BLOCK | spec fixes; `NET-TON-FIX1` still open | *local:* `docs/reviews/specs/` |
| 2026-10-13 | LaZer tbox proof | soundness of the Schwartz-Zippel checks | found in project work, reported upstream | 2 soundness bugs: P6-SZ ([lazer#24](https://github.com/lazer-crypto/lazer/issues/24)), P6-L2 ([lazer#25](https://github.com/lazer-crypto/lazer/issues/25)) | fixed, `proofSystemId` v2, `98695de` | [STATUS.md](../../pqz-core/STATUS.md) |
| 2026-10-15 | `p6-anon-l` `1732d00`, `p6-anon-h` `6506fb6` | P6-ANON tracks against the plan | read-only pre-review | 0 blocker, 3 major, 9 minor | handled in the P6-ANON round | *local:* `docs/reviews/2026-10-15-p6-anon-lh-prereview.md` |
| 2026-10-19 | `main` `4c20032` | PQZH Ligero, STARK backup, PQZL C, LaZer fork | 4 Claude reviewers, static; Codex aborted, out of credits | **2 P0**, 1 P1 in the backup | §3.1 | [code-review-2026-10-19](../../pqz-core/research/code-review-2026-10-19/README.md) A-D |
| 2026-10-19 | `0dc869d` | PQZL Rust | Codex, agy | P1: secret-dependent branches in the prover | fix E, constant-time work | same, G, H, E |
| 2026-10-19 | `e9cabd1` | second round: PQZH Rust, PQZL C | Codex, agy, Claude on each | no P0 / P1 in the live path | triage P-A..P-I, Q-A..Q-I fixed on `rev2-*`; O for constant time | same, I-O |
| 2026-10-19 | `7aab1fe`, `fe2faf0` | on-chain: plugin and all Solidity | agy, Claude in 3 parts; Codex aborted, then re-run at `fe2faf0` | no P0 / P1; P2 W-A, W-B, W-C, CHAIN-01 | W-A..W-S fixed on `rev2-chain`; CHAIN-02, -03 fixed | same, T-V |
| 2026-10-20 | `a61d221` | the transcript fix, PQZL Rust | reviews A and B | **P0 B-1**, confirmed by a cheating prover | §3.1 | same, W, X |
| 2026-10-25 | `008e196c` | whole core: design, transcript, parameters, Ligero, precompile | Codex, agy, Claude UltraCode (350 agents, three-vote refutation), Fable adjudicating R0 | 1 P1, 1 P2, P3s | §3.2 | [code-review-2026-10-25](../../pqz-core/research/code-review-2026-10-25/README.md) |
| 2026-10-26 | `64549aa4` | all EVM contracts, units C0-C6 | Codex C0-C2 only, agy, Claude UltraCode (465 agents), Fable C0 and consolidation | **1 P0, 2 P1, 5 P2, 57 P3**, 4 refuted | §3.3 | [code-review-2026-10-26](../../pqz-core/research/code-review-2026-10-26/README.md) |
| 2026-10-30 | `main` `2b162239` | EIP-7702 exposure | read-only audit | owner rulings D1-D5, EIP-7702 off | built on `ua8`, `no7702` | [eip7702-audit](eip7702-audit-2026-10-30.md) |
| 2026-11-01 | `zether-msm` `6fed9881` | merged-MSM Zether verifier | Claude Opus: 8 lenses, 3 verifiers per finding, about 95 executed attacks | sound and complete; highest finding low | §3.4 | [zether-msm-crypto-review](zether-msm-crypto-review.md) |
| 2026-11-02 | `typed-signing` `11eb80b5`, base `462edf66` | whole branch: EIP-712 across all reproducers, one accepted form per operation, allow-lists, interactions, cryptographic binding of the changed Zether, PQZ and UA code | Fable, read-only, nothing run | ready with fixes: no Critical, 1 Important, 2 Minor | §3.6 | *local:* `.superpowers/sdd/2026-10-31-typed-signing/review-CRV.md` |

### 2.2 Reviews inside feature rounds

Each of these rounds ran a review per task and a whole-branch review. They check the change against its spec and its security
rules. They are not independent audits, and they do not re-review what the change leaves alone. Their reports are in
git-ignored workspaces (`.superpowers/sdd/<round>/`), so they are not public and are not preserved by the repository; what
matters is copied into `docs/decisions.md`, `TODO.md` or the branch's run logs.

`pqzl-rust` port, `pqzl-fs3`, `rev2`, r01a, r01b, `review2-fix`, `metatx-split`, `near-algorand`, `dex-round`, `ua-soroban`,
`ua8` (portable registrations), `kem-scheme`, `msig-pophash`, `webauthn-clients`, `soroban-router-fix`, `zether-ungate`,
`node-ua-jobs`, `zether-msm`, `typed-signing`, `ua8-soroban`.

Documentation reorganisation reviews (*local:* `docs/reviews/reorg/`) are not security reviews and are not counted.

## 3. Findings that changed the design

### 3.1 PQZL transcript, 2026-10-19 and 2026-10-20

| Id | Severity | Finding | Status |
|---|---|---|---|
| C review (`h`) | **P0** | `h` was not absorbed into the Fiat-Shamir transcript before `mu`: any PQZL statement forged by a linear solve, in all four implementations, inherited from LaZer | fixed, `proofSystemId` v3, merge `361a86b9`; [lazer#28](https://github.com/lazer-crypto/lazer/issues/28) filed |
| D review (`z3`, `z4`) | **P0** | `z3`, `z4` never absorbed before their Schwartz-Zippel challenges, same reach | fixed in the same bump |
| B-1 = A-1 | **P0** | V3 / V4 drawn before the commitment `tg` to `g`: the v3 fix did not fully close the class; a cheating prover was accepted on all 14 codes | fixed in the regeneration, CTR-PQZ-09; re-checked by unit R1 at `008e196c` |
| A-2 | P3 | β4 and υ shared a challenge | fixed in the same bump |
| B-F (backup) | P1 | the STARK backup's only preset is not zero knowledge and proves 71.9 bits | backup only, not live; P-I is a gate before it is ever promoted |
| G-1 | P1 | prover control flow on secret values | fix E, both cores; ctgrind check, limits in [E-constant-time](../../pqz-core/research/code-review-2026-10-19/E-constant-time.md) |

Owner rulings then: fix before anything else, report upstream at once, roll the SCaaS testnet back.

### 3.2 Core review, 2026-10-25

| Id | Severity | Finding | Status |
|---|---|---|---|
| R0-1 | **P1** | audited `R_TXM`: auditor copies of a group shared key, randomness and coefficient, so digit differences were public and decoys identifiable | fixed in r01a, r01b: `S_AUD` groups and windows, disclosure offset |
| R0-C2 | **P2** | `z4` rejection sized with `Bprime = 1`: slow leak of `s[0]` over many proofs of one key | fixed: `Bprime = 8` |
| R0-C3 | P3 | final challenge `c` not filtered to the stated set, no attack | handled in r01a (`8ee7f9e6`) |
| F-4 | P3 | the auditor UA as sender or leg collides masks | fixed: `AuditorAsParty` |

Tooling and robustness items (R0-2, R1-1, R3-1, R4-C3, R4-C7 and others) went to the r01 rounds. The SCaaS testnet reset onto
`2.2.0-pqz5` in `31af331e`. The review's own README has no per-finding closure table: the statuses here come from the code and
the commits, and P3 and P4 items not named above are not individually confirmed by this record.

### 3.3 Contract review, 2026-10-26

| Id | Severity | Finding | Status |
|---|---|---|---|
| C0-1 | **P0** | classical Zether, audited multi-recipient: one randomness across legs made `C_aud_j − C_aud_k` public, breaking receiver anonymity and amount confidentiality | fixed, option (ii) per-leg randomness, `4f4c5eec`, `15b9f451` |
| C0-2 | **P1** | PQZH calldata proposal measured with one signer: holders that register and cannot debit | owner option 2, PQZH value only at `n2048-kmax1024`, `1d5f24eb` |
| C2-1 | **P1** | a PQZH value token could be initialised at a set where no debit fits: value in, never out | fixed, `1d5f24eb` |
| C0-3 | P2 | Zether ciphertexts kept only as a hash on COMPACT, against the owner's rule | fixed: records in state, NONE retired, `41b798d9` |
| C0-4 | P2 | disclosure challenge weak Fiat-Shamir: a false amount opening with the key holder's help | fixed: strong Fiat-Shamir, `1d2e052a`, `87042b84` |
| C0-5 | P2 | `msig` PQZ holder with no debit allowance: every credit could lock | fixed: `PQZ_DEBIT_MIN_GAS` bound, `3485a756`, `bd7fe719` |
| C0-6 | P2 | rollover flood kills an in-flight debit: liveness only | **accepted** by the owner (option 3), spec corrected, regression test pins it |
| C2-3 | P2 | auditor key of zero bytes under FULL or OPTIONAL | fixed, `1d5f24eb` |

Merge `e2e7a01e`, gates green at four sets. About 40 minors deferred. C5-9 is deferred. The README's "Coverage" section lists
what no reviewer of this round covered, and it stands.

**Live consequence of C0-5:** the bound reads a pinned gas figure. At 2026-11-02 the figure is about 9.4 k below the measured
debit at all four sets, so an `msig` in that narrow window sits on the wrong side of the rule. The owner set the re-pin for
after CRV's fix wave.

### 3.4 Zether merged MSM, 2026-11-01

Soundness relative to the per-equation verifier proved, per attempt about `2^-248`; completeness proved except at `ρ = 0`; zero
knowledge unchanged; proof bytes unchanged. Knowledge soundness transfer is conditional on the per-equation extractor, which was
not re-derived. Findings F1 and F2 (low) fixed; the rest documented. A load-bearing precondition: G1MSM subgroup-checks every
input, so any other stack must be probed.

### 3.5 Current rounds, not merged

- **`typed-signing` N1:** two High findings fixed locally: `/v1/op` was open, and 64-byte Hedera signatures were refused. The
  fixes are not on the remote branch yet. The node was not deployed from it.
- **`ua8-soroban` N2 review:** XDR depth unbounded on job input, a stack overflow not executed; plain `signed_op` an open host
  call; closed type list on `ua_value`; no e2e of native `relay`. Fix round in progress, see §7.

### 3.6 `typed-signing` whole-branch review, 2026-11-02

| Id | Severity | Finding | Status |
|---|---|---|---|
| I1 | Important | the prover's typed digest did not zero an unbound `relayer` / `feeRecipient`, so a named Zether entry could be signed over a digest the contract never computes. Fail-closed, no funds; the vectors could not show it | fixed, `28fba50a`, test failed before the fix |
| M1 | Minor | a relay fee's inner call signed with a fee mode and no recipient bit pays its fee to `MtxRelayExecutor`, where it stays. The signer's own mistake, no theft | open, may wait |
| M2 | Minor | `PqzAuth` names header word 11 `recipient` while the contract writes `M` there. Display only, digests agree | open: a rename changes the type string across all vectors |

Contract seams and the cryptographic binding were clean as read. This was one model reading, not an audit: soundness of the proof
systems and the parameter sets was out of scope, and `e2e.py` sections 5b and 6b, `msig` `pqzAuth` on a real registry, flat wallet
jobs through a lane and the Hedera 64-byte path on a named entry remain unverified on a chain.

## 4. Standing verification

These run repeatedly, unlike a review. They catch regressions. They do not prove design security.

| Check | Where | Note |
|---|---|---|
| Gate A / B of the PQZ core | [gate.sh](../../pqz-core/gate.sh) | KAT against LaZer golden files, tbox and SV fix checks, SV vs generic differential, C = Rust = wasm32, vectors with tamper, FFI, fuzz, per set; run only when cores or set parameters change |
| Cheating provers and attack tests | `pqz-core/pqzh/ligero/tests/attacks.rs`, `pqzl/rust` fixtures, `pqz-core/pqzl/sv/review/` | negatives that must be refused |
| Parameter estimates | `params/sets/*/e-s0.txt`, `e-s1.txt`; [soundness](pqz-tbox-soundness.md), [E-S0](pqz-parameters-e-s0.md), [E-S1](pqz-core-e-s1.md), [anonymity](pqz-anonymity.md) | MSIS / MLWE target 450 in uSVP and dual_hybrid; exceptions recorded per set |
| Fuzzing | [pqz-core/fuzz](../../pqz-core/fuzz/README.md) | libFuzzer on the precompile boundary with ASan and UBSan; **local only, no CI job** |
| Constant time | `pqz-core/pqzl/test/ct.sh`, `pqz-core/pqzh/ligero/runs/ct.sh`, `pqzl/rust/runs/ct-timing/` | ctgrind and timing; limits stated in reports E and O |
| Known-answer vectors | `smartcontracts/vectors/`, ACVP and NIST KATs, RFC 8032 | cross-language byte equality across clients and contracts |
| Forge suites and invariants | `smartcontracts/evm/test/`, per set | wrapper, DEX, UA ledger and Zether invariants |
| Mutation runs | `smartcontracts/evm/runs/*mutations*` | negatives proven able to fail, per round |
| Differentials | `UARegistry` split, Zether merged vs per-equation | old and new code compared row by row |
| Reproducible build | `pqz-core/artifact/` | source only |

Not in CI: Slither, `cargo audit` or `cargo deny`, CodeQL, secret scanning (a regex scan is run by hand before a push), fuzzing. CI
on `main` is red in `docs` and `ua-c` as of 2026-11-01. Dependabot #46-#53 are open, including `wee_alloc` (critical) and
`follow-redirects` (high), not triaged.

## 5. How far these reviews can be trusted

- **Independence is limited.** Claude models wrote most of the code and reviewed it. Fresh context and refutation rounds reduce
  that; only Codex and agy are different models. Reviewers did disagree usefully: agy missed R0-1 and marked C0-1 sound, Codex
  found them; Claude alone found C0-4, C0-5, C0-6.
- **Codex is missing for C3-C6.** Credits ran out, and the owner chose no refill. The Zether token, UA registry, meta-tx and DEX
  units of 2026-10-26 had agy and Claude only.
- **The 2026-11-01 Zether review used Claude models only**, the same family as the implementer.
- **Static reviews ran nothing.** The 2026-10-19, -25 and -26 reviews read code. Gas and size figures in them come from logs.
- **Three P0s shipped past tests and survived review rounds.** B-1 was missed by the first fix for the same class, and the code
  was green throughout. A green gate is no evidence of soundness.

## 6. Not reviewed

**External**
- Cryptographic audit: not done. It is a production gate of 22776 (`TODO.md`), and `docs/contracts/pq-zero-knowledge.md` states the PQZ release gate as an **independent** cryptographic audit. Whether AI reviewers alone can meet it is the owner's decision; until the owner changes that text, it stands.
- G-LIC: the letter was sent; no reply.
- The Ligero ZK argument (P6-PQZH leftovers) and the PQ verifiers with the expanded-key cache (P6c).

**Three-part review**
- **Part 3, `clients/pqz-prover` and the node relay: not done.** Waits for P6h, P6i; P6j is the review.
- **Whole contracts since `64549aa4`: no dedicated review.** The metatx split, UA-8, the DEX round, merged MSM, `typed-signing`
  and the size levers have round reviews only. The contracts audit (pre-freeze order, step 8) is that review.

**Specific gaps**
- From the 2026-10-26 Coverage section: how the precompile binds `message` in `R_REG`; `STMT_*`, `multiLen`, `HALF_WORDS`
  at the other three sets; `mtxPrepareAcc` halves against 2^24; events and selector sets; op 7 blobs on chains with the code size
  limit.
- Independent review of `pqz_sv.c` against `lnp-tbox.c`: started 2026-10-13, result not recorded.
- Zether: RFC 9380 re-derivation of the 130 generators; the per-equation special-soundness proof; Nethermind's zkevm
  accelerator and Besu's Java result cache; token-level suites at `M = 16`; a `verifyRange` weak Fiat-Shamir forgery derived, not
  executed. Any stack other than those probed must be probed for G1MSM subgroup checks.
- `0x0105` and `0x0141` holding one key: left as a question for the audit.
- Non-EVM families: no dedicated cryptographic review of Soroban, Solana, NEAR, Algorand, Move, TON, Cosmos.
- Node: threat model exists ([threat-model](../node/threat-model.md)); it is a design document, not a review of the code.
- Infrastructure: chainspec, sealer key custody, node topology, image and dependency supply chain, Blockscout exposure.
- About 40 deferred minors from `review2-fix`, plus deferred minors of each round in `TODO.md`.

## 7. In progress at 2026-11-02

| Item | Scope | State |
|---|---|---|
| `typed-signing` | CRV done, §3.6; I1 fixed | waits for the owner's merge go and the `debit_min_gas` re-pin |
| N2 fix round | Soroban `signed_op` and job input | running from WIP `f47ed86a`; nothing verified yet |

## 8. Order from here

1. Re-pin of `debit_min_gas` at the final bytecode, then the owner's merge go on `typed-signing`.
2. `ua8-soroban` B9, whole-branch review RV, testnet B10.
3. Freeze contracts of EVM and Soroban.
4. Contracts audit, reviewers the owner's choice.
5. P6h, P6i, P6j: part 3.
6. The cryptographic audit before 22776, reviewers the owner's choice. Suggested packaging: cryptography (PQZ, Zether, signature
   verifiers); EVM contracts; each non-EVM family; node and clients; infrastructure.
